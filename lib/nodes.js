/**
 * @file lib/nodes.js
 * @brief Shared node/sysinfo access: sysinfo fetch, group and host-name resolution, the per-node software scan entry point and the WINDOWS-UPDATES finding.
 *
 * Part of the MeshCentral Inventory & Vulnerability Scanner plugin; see ../inventoryscanner.js
 * for the module list and the attach order. Every member is attached to the shared plugin
 * object, so cross-module calls go through obj.name(...) and stay replaceable at runtime.
 */

"use strict";

/**
 * @brief Attach this module's members to one plugin instance.
 * @param {object} obj - The plugin object created by the entry point.
 */
module.exports.attach = function (obj) {
    // ---- Shared node/sysinfo collection ----

    /**
     * @brief Fetch the sysinfo record for a node.
     * Sysinfo <code>_id</code> is <code>"si" + node._id</code>.
     * @param {object} node - The node record.
     * @param {function} callback - Called with <code>(err, sysinfoRecord|null)</code>.
     */
    obj.fetchSysinfo = function (node, callback) {
        if ((node == null) || (node._id == null)) { callback(null, null); return; }
        obj.db.Get('si' + node._id, function (err, docs) {
            if (err || !docs || docs.length === 0) { callback(null, null); return; }
            callback(null, docs[0]);
        });
    };

    /**
     * @brief Build a vulnerability finding for a node whose Windows is missing
     * pending updates. Used only for Windows devices with <code>count > 0</code>.
     * @param {number} count - The number of missing updates.
     * @returns {object} A critical finding record.
     */
    /**
     * @brief Scan the software of ONE node with its OS context (distro-managed rule needs the
     * OS release). Every report/scan/export path goes through here (v3.1.0).
     */
    obj.scanNodeSoftware = function (node, softwareList, callback) {
        obj.scanDeviceSoftware(softwareList, callback, { osDesc: (node && node.osdesc) || '' });
    };

    obj.windowsUpdatesFinding = function (count) {
        return {
            cve: 'WINDOWS-UPDATES',
            isWindowsUpdates: true,
            severity: 'CRITICAL',
            cvss: 10,
            description: 'Windows is not up to date: ' + count + ' critical/important update(s) pending.',
            software: 'Windows Updates',
            version: count + ' pending',
            published: '',
            references: []
        };
    };

    /**
     * @brief Resolve the human-readable device group (mesh) name for a node.
     * Prefers the live mesh record, falls back to the last segment of the mesh id.
     * @param {object} node - The node record.
     * @returns {string} The group name (may be empty).
     */
    obj.getGroupName = function (node) {
        try {
            if (node && node.meshid) {
                // Mesh records live on the webserver object, keyed by mesh _id
                // (mesh/<domain>/<name>), with a human-readable 'name' field.
                var meshes = null;
                try { meshes = obj.meshServer.webserver.meshes; } catch (e) { }
                if (!meshes) { try { meshes = obj.meshServer.meshes; } catch (e) { } }
                if (meshes && meshes[node.meshid] && meshes[node.meshid].name) {
                    return meshes[node.meshid].name;
                }
                // Fallback: derive the group name from the last segment of the mesh id.
                var parts = String(node.meshid).split('/');
                return parts[parts.length - 1] || '';
            }
        } catch (e) { }
        return '';
    };

    /**
     * @brief Return the device host name.
     * Uses the node "real name" (hostname), falling back to the display name.
     * @param {object} node - The node record.
     * @returns {string} The host name (may be empty).
     */
    obj.getHostName = function (node) {
        if (node == null) return '';
        if (node.rname) return node.rname;
        if (node.name) return node.name;
        return '';
    };

    /**
     * @brief THE one derivation of a device's hardware facts (v5.1.0). Every consumer - the hardware CSV,
     * the printable reports, the fleet index and the asset-management push - reads the SAME structure, so
     * the browser, the CSV and the push can no longer drift apart. Values are kept raw AND pre-formatted
     * (via obj.formatBytes) so no consumer formats them a second, slightly different way.
     * @param {object} hw - <code>doc.hardware</code> of the sysinfo record (may be empty).
     * @param {object} ident - <code>hw.identifiers</code> (SMBIOS/WMI identifiers, may be empty).
     * @param {object} node - the node record (for the IP address).
     * @returns {object} The canonical hardware summary.
     */
    obj.hardwareSummary = function (hw, ident, node) {
        hw = hw || {}; ident = ident || {};
        var gpus = [];
        if (ident.gpu_name) {
            var gl = Array.isArray(ident.gpu_name) ? ident.gpu_name : [ident.gpu_name];
            for (var gi = 0; gi < gl.length; gi++) { if (gl[gi]) { gpus.push(String(gl[gi])); } }
        }
        var banks = [], memTotal = 0;
        if (hw.windows && Array.isArray(hw.windows.memory)) {
            for (var mi = 0; mi < hw.windows.memory.length; mi++) {
                var m = hw.windows.memory[mi]; if (!m) continue;
                var cap = m.Capacity || 0;
                if (typeof cap === 'number') { memTotal += cap; }
                banks.push({
                    label: m.BankLabel || m.DeviceLocator || ('Bank ' + (mi + 1)),
                    capacityBytes: cap, capacityText: obj.formatBytes(cap),
                    speed: (m.Speed || 'N/A'), partNumber: (m.PartNumber || 'N/A'), manufacturer: (m.Manufacturer || '')
                });
            }
        }
        var storage = [];
        if (Array.isArray(ident.storage_devices)) {
            for (var si = 0; si < ident.storage_devices.length; si++) {
                var sd = ident.storage_devices[si]; if (!sd) continue;
                storage.push({
                    model: (sd.Model || sd.Caption || ('Disk ' + (si + 1))),
                    caption: (sd.Model || 'N/A'),
                    sizeBytes: (sd.Size || 0), sizeText: obj.formatBytes(sd.Size)
                });
            }
        }
        var tpm = null;
        if (hw.tpm) {
            var t = hw.tpm;
            tpm = {
                label: (t.SpecVersion != null) ? ('TPM ' + parseFloat(t.SpecVersion).toFixed(1)) : 'TPM',
                specVersion: (t.SpecVersion != null) ? parseFloat(t.SpecVersion) : null,
                isActivated: !!t.IsActivated, isEnabled: !!t.IsEnabled, isOwned: !!t.IsOwned,
                manufacturerId: (t.ManufacturerId || ''), manufacturerVersion: (t.ManufacturerVersion || ''),
                detail: 'Activated: ' + (t.IsActivated ? 'Yes' : 'No') + ', Enabled: ' + (t.IsEnabled ? 'Yes' : 'No') + ', Owned: ' + (t.IsOwned ? 'Yes' : 'No') +
                    (t.ManufacturerId ? (', Manufacturer: ' + t.ManufacturerId) : '') + (t.ManufacturerVersion ? (', Version: ' + t.ManufacturerVersion) : '')
            };
        }
        var dns = (hw.network && Array.isArray(hw.network.dns)) ? hw.network.dns.slice() : [];
        var ip = (node && (node.ip || node.networkAddresses)) || '';
        var bios = { vendor: (ident.bios_vendor || ''), version: (ident.bios_version || ''), serial: (ident.bios_serial || ''), mode: (ident.bios_mode || '') };
        var board = { vendor: (ident.board_vendor || ''), name: (ident.board_name || ''), serial: (ident.board_serial || ''), version: (ident.board_version || '') };
        var system = { product: (ident.product_name || ''), manufacturer: (ident.chassis_manufacturer || ''), serial: (ident.chassis_serial || ''), assetTag: (ident.chassis_assettag || '') };
        return {
            cpu: (ident.cpu_name || ''), gpus: gpus,
            memoryBanks: banks, memoryTotalBytes: memTotal, memoryTotalText: obj.formatBytes(memTotal),
            storage: storage, bios: bios, board: board, system: system, tpm: tpm,
            network: { ip: ip, dns: dns },
            // one best-effort serial for asset systems that have a single field
            serial: (system.serial || bios.serial || board.serial || ''),
            manufacturer: (system.manufacturer || ident.manufacturer || ''),
            model: (system.product || ident.model || ''),
            // the CSV/report/push all need to know whether ANY hardware fact was reported
            hasAny: !!(ident.cpu_name || gpus.length || banks.length || storage.length || bios.vendor || bios.version ||
                board.vendor || board.name || system.product || system.manufacturer || tpm || ip || dns.length)
        };
    };

    /**
     * @brief The display/export projection of the RAW inventory rows (name/version/publisher/location/date,
     * plus the curated licenseType since v5.6.0).
     * Derived FROM the raw rows and only ever used for output - never as matcher input (the matcher needs
     * location/installLocation to recognise distribution packages; see collectNodeInventory).
     * @param {Array<object>} raw - the raw stored software rows.
     * @returns {Array<object>} The projected list.
     */
    obj.softwareProjection = function (raw) {
        var out = [];
        for (var i = 0; i < (raw || []).length; i++) {
            var sw = raw[i]; if (!sw) continue;
            var nm = (sw.name || sw.displayName || sw.DisplayName || sw.Name || '');
            // v5.6.0: the license annotation travels with the projection, so the software CSV, the fleet
            // index, the device/software detail views and the asset push all report the SAME license type
            // without re-deriving it. It is the curated table value (obj.licenseTypeFor), never a guess:
            // '' means "no curated statement about this product".
            var lt = '';
            try { lt = (nm && obj.licenseTypeFor) ? obj.licenseTypeFor(nm) : ''; } catch (e) { lt = ''; }
            out.push({
                name: nm,
                version: (sw.version || sw.Version || ''),
                publisher: (sw.publisher || sw.vendor || sw.Publisher || ''),
                location: (sw.location || sw.installLocation || sw.path || ''),
                date: (sw.date || sw.installedDate || sw.installDate || ''),
                licenseType: lt
            });
        }
        return out;
    };

    /**
     * @brief THE one way to obtain a device's installed-software rows (v5.1.0): the sysinfo document is
     * fetched and handed to getStoredSoftware, so the plugin's own store AND the sysinfo fallback are both
     * seen. Every consumer (CSV, reports, fleet index, asset push, license rules) goes through here - before
     * this, the license path called getStoredSoftware(node, {}) and could therefore see FEWER programs than
     * the CSV listed for the same device.
     * @param {object} node - the node record.
     * @param {function} callback - <code>(err, {doc, rows})</code>; rows are the RAW inventory rows.
     */
    obj.fetchNodeSoftware = function (node, callback) {
        obj.fetchSysinfo(node, function (err, sysinfoRecord) {
            if (err) { return callback(err); }
            var doc = sysinfoRecord ? (sysinfoRecord.doc || sysinfoRecord) : {};
            callback(null, { doc: doc, rows: obj.getStoredSoftware(node, doc) });
        });
    };

    /**
     * @brief THE canonical per-device inventory collection (v5.1.0). One path, one result shape, used by
     * the hardware/software/vulnerability CSV, both printable reports, the fleet index and the external
     * asset-management push - so all of them see exactly the same device facts and the same findings.
     *
     * Before this, the same "fetchSysinfo -> getStoredSoftware -> scanNodeSoftware -> OS findings" chain was
     * copied into reports.js (twice), csv.js, fleetindex.js and assetmgmt.js; the copies had already drifted
     * (one dropped location/installLocation, one dropped the sysinfo doc, one dropped the OS/Windows-Update/
     * EOL findings entirely), which made the browser list, the CSV and the push disagree.
     *
     * @param {object} node - the node record.
     * @param {function} callback - <code>(err, inv)</code> where inv carries: identity (id/host/given/group/os/
     *   platform/online/ip), doc + hardwareRaw + identifiers + windowsBuild, hardware (obj.hardwareSummary),
     *   software (RAW rows - the matcher input), softwareList (obj.softwareProjection - for output),
     *   softwareFindings (the per-software scan rows, needed for the CPE-coverage categories),
     *   findings (the FULL list: software + OS CVEs + WINDOWS-UPDATES + OS-EOL - identical everywhere),
     *   windowsUpdates, osSupport and counts.
     */
    obj.collectNodeInventory = function (node, callback) {
        obj.fetchNodeSoftware(node, function (err, got) {
            if (err) { return callback(err); }
            var doc = got.doc;
            var hw = (doc && doc.hardware) ? doc.hardware : {};
            var ident = hw.identifiers || {};
            var windowsBuild = '';
            if (hw.windows && hw.windows.osinfo) { windowsBuild = hw.windows.osinfo.BuildRevision || hw.windows.osinfo.BuildNumber || ''; }
            // RAW rows go to the matcher - a projection here would break distro-package detection
            var software = got.rows;
            obj.scanNodeSoftware(node, software, function (softwareFindings) {
                var findings = (softwareFindings || []).concat(obj.scanDeviceOs((node && node.osdesc) || '', windowsBuild));
                var wu = obj.getWindowsUpdates(node);
                if (wu && wu.count > 0) { findings.push(obj.windowsUpdatesFinding(wu.count)); }
                var eol = obj.osEolFinding(node);
                if (eol != null) { findings.push(eol); }
                var cves = 0, findingIds = 0, maxSeverity = null, seenIds = {};
                for (var fi = 0; fi < findings.length; fi++) {
                    var f = findings[fi]; if (!f) continue;
                    if (f.isCve === true) { cves++; }
                    if (f.cve) { findingIds++; if (!seenIds[f.cve]) { seenIds[f.cve] = 1; } }
                    var sev = String(f.severity || '').toUpperCase();
                    var rank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 }[sev];
                    if (rank != null) {
                        var cur = maxSeverity ? ({ CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 }[String(maxSeverity).toUpperCase()] || -1) : -1;
                        if (rank > cur) { maxSeverity = sev; }
                    }
                }
                var ws = obj.meshServer.webserver;
                callback(null, {
                    node: node, doc: doc, hardwareRaw: hw, identifiers: ident, windowsBuild: windowsBuild,
                    id: node ? node._id : '',
                    group: obj.getGroupName(node), host: obj.getHostName(node),
                    given: (node && typeof node.name === 'string') ? node.name.trim() : '',
                    os: String((node && node.osdesc) || ''),
                    platform: obj.osPlatformOf ? (obj.osPlatformOf(node) || '') : '',
                    online: !!(node && ws && ws.wsagents && ws.wsagents[node._id]),
                    ip: (node && (node.ip || node.networkAddresses)) || '',
                    hardware: obj.hardwareSummary(hw, ident, node),
                    software: software,
                    softwareList: obj.softwareProjection(software),
                    softwareFindings: softwareFindings || [],
                    findings: findings,
                    windowsUpdates: wu,
                    osSupport: obj.osSupportState((node && node.osdesc) || ''),
                    counts: {
                        software: software.length, findings: findings.length,
                        cves: cves, findingIds: findingIds,
                        uniqueFindingIds: Object.keys(seenIds).length,
                        maxSeverity: maxSeverity
                    }
                });
            });
        });
    };
};
