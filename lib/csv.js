/**
 * @file lib/csv.js
 * @brief CSV formatting (RFC 4180 plus the formula-injection guard), the shared per-node CSV builder used by the toolbar AND the export route, and the whole-fleet export.
 *
 * Part of the MeshCentral Inventory & Vulnerability Scanner plugin; see ../inventoryscanner.js
 * for the module list and the attach order. Every member is attached to the shared plugin
 * object, so cross-module calls go through obj.name(...) and stay replaceable at runtime.
 */

"use strict";

const path = require('path');

/**
 * @brief Attach this module's members to one plugin instance.
 * @param {object} obj - The plugin object created by the entry point.
 */
module.exports.attach = function (obj) {
    // ---- CSV helpers ----

    /**
     * @brief Format a single CSV field per RFC 4180.
     * Neutralizes CSV formula injection (CWE-1236) by prefixing a <code>'</code>
     * when the value starts with <code>= + - @ tab CR</code>.
     * @param {*} value - The value to format.
     * @returns {string} The escaped CSV field.
     */
    obj.formatCsvField = function (value) {
        if ((value === null) || (value === undefined)) { return '""'; }
        var str = String(value);
        if ((str.charAt(0) === '=') || (str.charAt(0) === '+') || (str.charAt(0) === '-') || (str.charAt(0) === '@') || (str.charAt(0) === '\t') || (str.charAt(0) === '\r')) {
            str = "'" + str;
        }
        if (str.indexOf(',') >= 0 || str.indexOf('"') >= 0 || str.indexOf('\r') >= 0 || str.indexOf('\n') >= 0) {
            str = str.replace(/"/g, '""');
            str = '"' + str + '"';
        }
        return str;
    };

    /**
     * @brief Format a complete CSV row from the given field values.
     * @param {...*} arguments - The field values.
     * @returns {string} The CSV row (comma-joined escaped fields).
     */
    obj.formatCsvRow = function () {
        var fields = [];
        for (var i = 0; i < arguments.length; i++) { fields.push(obj.formatCsvField(arguments[i])); }
        return fields.join(',');
    };

    /**
     * @brief Format a byte count into a human-readable string.
     * @param {number} bytes - The number of bytes.
     * @returns {string} A human-readable size, or an empty string.
     */
    obj.formatBytes = function (bytes) {
        if ((bytes === null) || (bytes === undefined)) { return ''; }
        var b = Number(bytes);
        if (!isFinite(b) || (b === 0)) { return ''; }
        var sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        var i = parseInt(Math.floor(Math.log(Math.abs(b)) / Math.log(1024)), 10);
        if (i >= sizes.length) { i = sizes.length - 1; }
        return Math.round(b / Math.pow(1024, i), 2) + ' ' + sizes[i];
    };

    /**
     * @brief Build a filename timestamp.
     * @returns {string} The timestamp in <code>YYYYMMDD-HHMMSS</code> format.
     */
    obj.timestamp = function () {
        var now = new Date();
        return now.getFullYear() +
            ('0' + (now.getMonth() + 1)).slice(-2) + ('0' + now.getDate()).slice(-2) + '-' +
            ('0' + now.getHours()).slice(-2) + ('0' + now.getMinutes()).slice(-2) + ('0' + now.getSeconds()).slice(-2);
    };

    /**
     * @brief Stream a full-inventory CSV download for ALL non-deleted devices, intended for
     * direct links (panel navigation, bookmarks) where no device selection exists.
     * Same generator as the device-list toolbar export, so column layout and status semantics
     * are identical. Gated on full site admin by handleAdminReq.
     * @param {object} req - The Express request (<code>type=hardware|software|vulns</code>).
     * @param {object} res - The Express response (CSV attachment).
     * @param {object} user - The authenticated user.
     */
    obj.exportCsv = function (req, res, user) {
        var type = String(req.query.type || 'vulns');
        if (['hardware', 'software', 'vulns'].indexOf(type) < 0) { res.sendStatus(400); return; }
        var base = (type === 'vulns') ? 'Vulnerabilities' : ((type === 'hardware') ? 'HardwareInventory' : 'SoftwareInventory');
        obj.meshServer.db.GetAllType('node', function (err, nodes) {
            if (err) { res.sendStatus(500); return; }
            var liveNodes = [];
            if (nodes) {
                for (var i = 0; i < nodes.length; i++) {
                    var n = nodes[i];
                    if (n && (n._id != null) && (n.deleted == null)) { liveNodes.push(n); }
                }
            }
            obj.buildCsvForNodes(liveNodes, type, function (err2, csvContent) {
                if (err2) { res.sendStatus(500); return; }
                var filename = base + '_' + obj.timestamp() + '.csv';
                res.setHeader('Content-Disposition', 'attachment; filename="' + filename + '"');
                res.setHeader('Content-Type', 'text/csv; charset=utf-8');
                res.send('\uFEFF' + ((csvContent != null) ? csvContent : ''));
            });
        });
    };

    // ---- Individual-device exports (device-list toolbar) ----

    /**
     * @brief Build a CSV string for an arbitrary list of node records.
     * Supports types <code>hardware</code>, <code>software</code>, <code>patches</code>
     * and <code>vulns</code>. Used by the <code>uiCustomEvent</code> device-list toolbar path.
     * @param {Array<object>} nodes - Array of node records (<code>node/&lt;domain&gt;/&lt;id&gt;</code>).
     * @param {string} type - One of <code>hardware|software|patches|vulns</code>.
     * @param {function} callback - Called with <code>(err, csvContent, filenameBase)</code>.
     */
    obj.buildCsvForNodes = function (nodes, type, callback) {
        if (!nodes || nodes.length === 0) { callback(null, '', 'empty'); return; }

        var rows = [];
        if (type === 'hardware') {
            rows.push(obj.formatCsvField('Group') + ',' + obj.formatCsvField('Host Name') + ',' +
                obj.formatCsvField('OS') + ',' + obj.formatCsvField('Hardware Category') + ',' + obj.formatCsvField('Component') + ',' + obj.formatCsvField('Value') + ',' + obj.formatCsvField('Details') + ',' + obj.formatCsvField('Location'));
        } else if (type === 'software') {
            rows.push(obj.formatCsvField('Group') + ',' + obj.formatCsvField('Host Name') + ',' +
                obj.formatCsvField('Software Name') + ',' + obj.formatCsvField('Software Version') + ',' + obj.formatCsvField('Software Publisher') + ',' + obj.formatCsvField('Software Location') + ',' + obj.formatCsvField('Software Install Date'));
        } else { // vulns
            rows.push(obj.formatCsvField('Group') + ',' + obj.formatCsvField('Host Name') + ',' +
                obj.formatCsvField('Status') + ',' + obj.formatCsvField('CVE ID') + ',' + obj.formatCsvField('Severity') + ',' + obj.formatCsvField('CVSS Score') + ',' + obj.formatCsvField('Manual Rating') + ',' + obj.formatCsvField('Comment') + ',' +
                obj.formatCsvField('Software') + ',' + obj.formatCsvField('Version') + ',' + obj.formatCsvField('Description'));
        }

        var pending = nodes.length, errored = false;

        /**
         * @brief Finish building the CSV once every node has been processed.
         */
        function finish() {
            if (--pending > 0) { return; }
            if (errored) { callback(new Error('Database error while building CSV.'), '', ''); return; }
            var base = (type === 'vulns') ? 'Vulnerabilities' : (type.charAt(0).toUpperCase() + type.slice(1) + 'Inventory');
            callback(null, rows.join('\r\n') + '\r\n', base);
        }

        nodes.forEach(function (node) {
            var group = obj.getGroupName(node);
            var hostName = obj.getHostName(node);
            var osDesc = node.osdesc || '';
            var ipAddress = node.ip || node.networkAddresses || '';
            var commonPrefix = [group, hostName];

            obj.fetchSysinfo(node, function (err, sysinfoRecord) {
                if (err) { errored = true; finish(); return; }
                var doc = sysinfoRecord ? (sysinfoRecord.doc || sysinfoRecord) : {};

                if (type === 'hardware') {
                    var hasHardware = false;
                    var hw = (doc && doc.hardware) ? doc.hardware : {};
                    var ident = (hw && hw.identifiers) ? hw.identifiers : {};
                    var sysRow = function (cat, component, value, details, location) {
                        hasHardware = true;
                        rows.push(obj.formatCsvRow(group, hostName, osDesc, cat, component, value, details, location));
                    };

                    // CPU (from SMBIOS identifiers)
                    if (ident.cpu_name) {
                        sysRow('CPU', ident.cpu_name, ident.cpu_name || 'Unknown', '', 'Processor');
                    }
                    // GPU(s)
                    if (ident.gpu_name) {
                        var gpuList = Array.isArray(ident.gpu_name) ? ident.gpu_name : [ident.gpu_name];
                        for (var gi = 0; gi < gpuList.length; gi++) { if (gpuList[gi]) { sysRow('GPU', gpuList[gi], gpuList[gi], '', 'Graphics'); } }
                    }
                    // Memory (Windows banks)
                    if (hw.windows && Array.isArray(hw.windows.memory) && hw.windows.memory.length > 0) {
                        var memTotal = 0;
                        for (var mi = 0; mi < hw.windows.memory.length; mi++) {
                            var m = hw.windows.memory[mi]; if (!m) continue;
                            var cap = m.Capacity || 0;
                            if (typeof cap === 'number') { memTotal += cap; }
                            sysRow('Memory', m.BankLabel || m.DeviceLocator || ('Bank ' + (mi + 1)),
                                obj.formatBytes(cap), 'Speed: ' + (m.Speed || 'N/A') + ', Part: ' + (m.PartNumber || 'N/A'),
                                m.Manufacturer || '');
                        }
                    }
                    // Storage (SMBIOS storage devices)
                    if (Array.isArray(ident.storage_devices)) {
                        for (var si = 0; si < ident.storage_devices.length; si++) {
                            var sd = ident.storage_devices[si]; if (!sd) continue;
                            var sModel = sd.Model || sd.Caption || ('Disk ' + (si + 1));
                            sysRow('Storage', sModel, obj.formatBytes(sd.Size), 'Model: ' + (sd.Model || 'N/A'), '');
                        }
                    }
                    // BIOS
                    if (ident.bios_vendor || ident.bios_version) {
                        sysRow('BIOS/UEFI', ident.bios_version || 'Unknown', ident.bios_version || 'Unknown',
                            'Vendor: ' + (ident.bios_vendor || 'N/A') + ', Serial: ' + (ident.bios_serial || 'N/A') + ', Mode: ' + (ident.bios_mode || 'N/A'), '');
                    }
                    // Motherboard
                    if (ident.board_vendor || ident.board_name) {
                        sysRow('Motherboard', ident.board_name || 'Unknown', ident.board_name || 'Unknown',
                            'Vendor: ' + (ident.board_vendor || 'N/A') + ', Serial: ' + (ident.board_serial || 'N/A') + ', Version: ' + (ident.board_version || 'N/A'), '');
                    }
                    // System / chassis
                    if (ident.product_name || ident.chassis_manufacturer) {
                        sysRow('System', ident.product_name || 'Unknown', ident.product_name || 'Unknown',
                            'Manufacturer: ' + (ident.chassis_manufacturer || 'N/A') + ', Serial: ' + (ident.chassis_serial || 'N/A') + ', Asset Tag: ' + (ident.chassis_assettag || 'N/A'), '');
                    }
                    // TPM
                    if (hw.tpm) {
                        var tpm = hw.tpm;
                        var tpmDetail = 'Activated: ' + (tpm.IsActivated ? 'Yes' : 'No') + ', Enabled: ' + (tpm.IsEnabled ? 'Yes' : 'No') + ', Owned: ' + (tpm.IsOwned ? 'Yes' : 'No');
                        if (tpm.ManufacturerId) { tpmDetail += ', Manufacturer: ' + tpm.ManufacturerId; }
                        if (tpm.ManufacturerVersion) { tpmDetail += ', Version: ' + tpm.ManufacturerVersion; }
                        sysRow('TPM', (tpm.SpecVersion != null) ? 'TPM ' + parseFloat(tpm.SpecVersion).toFixed(1) : 'TPM', tpmDetail, '', '');
                    }
                    // Network (limited: node IP + DNS servers from sysinfo; full adapter
                    // details are fetched live by MeshCentral and are not in the sysinfo doc)
                    var netDetails = 'IP: ' + (ipAddress || 'N/A');
                    if (hw.network && Array.isArray(hw.network.dns) && hw.network.dns.length > 0) { netDetails += ', DNS: ' + hw.network.dns.join(', '); }
                    if (ipAddress || (hw.network && Array.isArray(hw.network.dns) && hw.network.dns.length > 0)) {
                        sysRow('Network', ipAddress || 'Unknown', netDetails, '', '');
                    }
                    if (!hasHardware) { rows.push(obj.formatCsvRow(group, hostName, osDesc, 'System', 'No Hardware Data', 'No hardware information available', '', '')); }
                    finish();
                } else if (type === 'software') {
                    var softwareList = obj.getStoredSoftware(node, doc);
                    if (softwareList.length === 0) {
                        rows.push(obj.formatCsvRow(group, hostName, '', '', '', '', ''));
                    } else {
                        for (var j = 0; j < softwareList.length; j++) {
                            var sw = softwareList[j]; if (!sw) continue;
                            rows.push(obj.formatCsvRow(group, hostName,
                                sw.name || sw.displayName || sw.DisplayName || '', sw.version || sw.Version || '',
                                sw.publisher || sw.vendor || sw.Publisher || '', sw.location || sw.installLocation || sw.path || '',
                                sw.date || sw.installedDate || sw.installDate || ''));
                        }
                    }
                    finish();
                } else { // vulns
                    var windowsBuild = '';
                    if (doc && doc.hardware && doc.hardware.windows && doc.hardware.windows.osinfo) { windowsBuild = doc.hardware.windows.osinfo.BuildRevision || doc.hardware.windows.osinfo.BuildNumber || ''; }
                    obj.scanNodeSoftware(node, obj.getStoredSoftware(node, doc), function (softwareVulns) {
                        var deviceVulns = softwareVulns.concat(obj.scanDeviceOs(osDesc, windowsBuild));
                        // Windows-only: missing updates are treated as a critical finding.
                        var wu = obj.getWindowsUpdates(node);
                        if (wu && wu.count > 0) { deviceVulns.push(obj.windowsUpdatesFinding(wu.count)); }
                        var eolF = obj.osEolFinding(node); if (eolF != null) { deviceVulns.push(eolF); }
                        for (var m = 0; m < deviceVulns.length; m++) {
                            var v = deviceVulns[m];
                            var status = v.status || ((v.isCve || v.cve) ? 'CVE' : '');
                            if (v.outOfScope === true) { status = (status === 'firmware' ? 'firmware is not covered by CVE data' : 'drivers are not covered by CVE data'); }
                            if (v.distro === 'supported') { status = 'patched by the distribution (OS supported)'; }
                            else if (v.distro === 'eol') { status = 'distribution package - OS end of life'; }
                            else if (v.distro === 'unknown') { status = 'distribution package - OS support unknown'; }
                            var assessment = obj.getMeshAssessment(node.meshid, v.cve);
                            var rating = assessment ? assessment.assessment : (v.severity || '');
                            var comment = assessment ? assessment.comment : '';
                            // A finding flagged as false positive is shown as such instead of a CVE.
                            if (assessment && assessment.flagged) {
                                status = 'false positive';
                                rating = 'UNKNOWN';
                            }
                            rows.push(obj.formatCsvRow(group, hostName, status, v.cve || '', v.severity || '', (v.cvss != null) ? v.cvss : '', rating, comment, v.software, v.version, v.description || ''));
                        }
                        finish();
                    });
                }
            });
        });
    };
};
