/**
 * @file lib/csv.js
 * @brief CSV formatting (RFC 4180 plus the formula-injection guard), the column-by-column ordering every export is delivered in, the shared per-node CSV builder used by the toolbar AND the export route, and the whole-fleet export.
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
     * @brief Compare two CSV cell values the way a spreadsheet would: empty first, then
     * case-insensitive NATURAL order (digit runs compare as numbers, so "Firefox 9" sorts before
     * "Firefox 121" and "Windows 10" before "Windows 11").
     * @param {*} a - Raw value of the first row.
     * @param {*} b - Raw value of the second row.
     * @returns {number} negative, 0 or positive.
     */
    obj.csvCellCompare = function (a, b) {
        var x = String((a == null) ? '' : a).trim();
        var y = String((b == null) ? '' : b).trim();
        if (x === y) return 0;
        if (x === '') return -1;
        if (y === '') return 1;
        try { var c = x.localeCompare(y, undefined, { numeric: true, sensitivity: 'base' }); if (c !== 0) return c; } catch (e) { }
        return 0;   // equal for the spreadsheet (Array.sort is stable, so such rows keep their order)
    };

    /**
     * @brief Row comparator used by every CSV export: column 1, then column 2, ... (left to right).
     * Without it the rows came out in database order, which nobody can read in a spreadsheet (v4.4.0).
     * @param {Array<string>} a - Raw values of the first row.
     * @param {Array<string>} b - Raw values of the second row.
     * @returns {number} negative, 0 or positive.
     */
    obj.csvRowCompare = function (a, b) {
        var n = Math.max(a.length, b.length);
        for (var i = 0; i < n; i++) {
            var c = obj.csvCellCompare(i < a.length ? a[i] : '', i < b.length ? b[i] : '');
            if (c !== 0) return c;
        }
        return 0;
    };

    /**
     * @brief Build a CSV string for an arbitrary list of node records.
     * Supports types <code>hardware</code>, <code>software</code>, <code>patches</code>
     * and <code>vulns</code>. Used by the <code>uiCustomEvent</code> device-list toolbar path.
     * The data rows are collected as raw value arrays, sorted column-by-column left to right and
     * only then escaped - so the formula guard still runs on every field and the sort sees the
     * real values, not the quoting (v4.4.0). Devices are read in paced batches so a large fleet
     * export cannot block the server.
     * @param {Array<object>} nodes - Array of node records (<code>node/&lt;domain&gt;/&lt;id&gt;</code>).
     * @param {string} type - One of <code>hardware|software|patches|vulns</code>.
     * @param {function} callback - Called with <code>(err, csvContent, filenameBase)</code>.
     */
    obj.buildCsvForNodes = function (nodes, type, callback) {
        if (!nodes || nodes.length === 0) { callback(null, '', 'empty'); return; }

        var header = [];
        if (type === 'hardware') {
            header = ['Group', 'Host Name', 'OS', 'Hardware Category', 'Component', 'Value', 'Details', 'Location'];
        } else if (type === 'software') {
            header = ['Group', 'Host Name', 'Software Name', 'Software Version', 'Software Publisher', 'Software Location', 'Software Install Date', 'License Type', 'License', 'License Source'];
        } else { // vulns
            header = ['Group', 'Host Name', 'Status', 'CVE ID', 'Severity', 'CVSS Score', 'Manual Rating', 'Comment', 'Software', 'Version', 'Description'];
        }
        var data = [];
        var errored = false;

        /**
         * @brief Finish once every node has been read: sort column by column (left to right) and
         * escape only then, so the spreadsheet opens in a readable order (v4.4.0).
         */
        function finish() {
            if (errored) { callback(new Error('Database error while building CSV.'), '', ''); return; }
            data.sort(obj.csvRowCompare);
            var lines = [header.map(function (h) { return obj.formatCsvField(h); }).join(',')];
            for (var r = 0; r < data.length; r++) {
                lines.push(data[r].map(function (cell) { return obj.formatCsvField(cell); }).join(','));
            }
            var base = (type === 'vulns') ? 'Vulnerabilities' : (type.charAt(0).toUpperCase() + type.slice(1) + 'Inventory');
            callback(null, lines.join('\r\n') + '\r\n', base);
        }

        obj.pacedEach(nodes, function (node, nodeDone) {
            // v5.1.0: ONE canonical collection path (obj.collectNodeInventory) for the CSV, the reports,
            // the fleet index and the asset push - the rows below are generated from that single record.
            obj.collectNodeInventory(node, function (err, inv) {
                if (err) { errored = true; nodeDone(); return; }
                var group = inv.group;
                var hostName = inv.host;
                var osDesc = inv.os;
                var ipAddress = inv.ip;

                if (type === 'hardware') {
                    var h = inv.hardware;
                    var sysRow = function (cat, component, value, details, location) {
                        data.push([group, hostName, osDesc, cat, component, value, details, location]);
                    };
                    // CPU (from SMBIOS identifiers)
                    if (h.cpu) { sysRow('CPU', h.cpu, h.cpu || 'Unknown', '', 'Processor'); }
                    // GPU(s)
                    for (var gi = 0; gi < h.gpus.length; gi++) { sysRow('GPU', h.gpus[gi], h.gpus[gi], '', 'Graphics'); }
                    // Memory (Windows banks)
                    for (var mi = 0; mi < h.memoryBanks.length; mi++) {
                        var mb = h.memoryBanks[mi];
                        sysRow('Memory', mb.label, mb.capacityText, 'Speed: ' + mb.speed + ', Part: ' + mb.partNumber, mb.manufacturer);
                    }
                    // Storage (SMBIOS storage devices)
                    for (var si = 0; si < h.storage.length; si++) {
                        var st = h.storage[si];
                        sysRow('Storage', st.model, st.sizeText, 'Model: ' + st.caption, '');
                    }
                    // BIOS
                    if (h.bios.vendor || h.bios.version) {
                        sysRow('BIOS/UEFI', h.bios.version || 'Unknown', h.bios.version || 'Unknown',
                            'Vendor: ' + (h.bios.vendor || 'N/A') + ', Serial: ' + (h.bios.serial || 'N/A') + ', Mode: ' + (h.bios.mode || 'N/A'), '');
                    }
                    // Motherboard
                    if (h.board.vendor || h.board.name) {
                        sysRow('Motherboard', h.board.name || 'Unknown', h.board.name || 'Unknown',
                            'Vendor: ' + (h.board.vendor || 'N/A') + ', Serial: ' + (h.board.serial || 'N/A') + ', Version: ' + (h.board.version || 'N/A'), '');
                    }
                    // System / chassis
                    if (h.system.product || h.system.manufacturer) {
                        sysRow('System', h.system.product || 'Unknown', h.system.product || 'Unknown',
                            'Manufacturer: ' + (h.system.manufacturer || 'N/A') + ', Serial: ' + (h.system.serial || 'N/A') + ', Asset Tag: ' + (h.system.assetTag || 'N/A'), '');
                    }
                    // TPM
                    if (h.tpm) { sysRow('TPM', h.tpm.label, h.tpm.detail, '', ''); }
                    // Network (limited: node IP + DNS servers from sysinfo; full adapter
                    // details are fetched live by MeshCentral and are not in the sysinfo doc)
                    var netDetails = 'IP: ' + (ipAddress || 'N/A');
                    if (h.network.dns.length > 0) { netDetails += ', DNS: ' + h.network.dns.join(', '); }
                    if (ipAddress || h.network.dns.length > 0) { sysRow('Network', ipAddress || 'Unknown', netDetails, '', ''); }
                    if (!h.hasAny) { data.push([group, hostName, osDesc, 'System', 'No Hardware Data', 'No hardware information available', '', '']); }
                    nodeDone();
                } else if (type === 'software') {
                    var licMap = (obj.licenseMapForNode != null) ? obj.licenseMapForNode(node._id) : {};
                    if (inv.softwareList.length === 0) {
                        data.push([group, hostName, '', '', '', '', '', '', '', '']);
                    } else {
                        for (var j = 0; j < inv.softwareList.length; j++) {
                            var sw = inv.softwareList[j];
                            var lic = licMap[String(sw.name).toLowerCase()] || { license: '', source: '' };
                            // v5.6.0: License Type is the curated annotation (SPDX id or Proprietary /
                            // Freeware / Freeware (non-commercial)) and is known WITHOUT any collection run;
                            // License / License Source still come from the opt-in on-device read.
                            data.push([group, hostName, sw.name, sw.version, sw.publisher, sw.location, sw.date, sw.licenseType || '', lic.license || '', lic.source || '']);
                        }
                    }
                    nodeDone();
                } else { // vulns
                    for (var m = 0; m < inv.findings.length; m++) {
                        var v = inv.findings[m];
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
                        data.push([group, hostName, status, v.cve || '', v.severity || '', (v.cvss != null) ? v.cvss : '', rating, comment, v.software, v.version, v.description || '']);
                    }
                    nodeDone();
                }
            });
        }, finish);
    };
};
