/**
 * @file lib/routes.js
 * @brief pluginadmin.ashx GET/POST dispatch, the site-admin gate, the X-InvScanner-Request cross-site guard, the panel render, the location list and the log tailing for the UI.
 *
 * Part of the MeshCentral Inventory & Vulnerability Scanner plugin; see ../inventoryscanner.js
 * for the module list and the attach order. Every member is attached to the shared plugin
 * object, so cross-module calls go through obj.name(...) and stay replaceable at runtime.
 */

"use strict";

const fs = require('fs');
const path = require('path');

/**
 * @brief Attach this module's members to one plugin instance.
 * @param {object} obj - The plugin object created by the entry point.
 */
module.exports.attach = function (obj) {
    /** @brief Tail the last lines of one whitelisted log file. */
    obj.tailLogFile = function (file) {
        try {
            if (!fs.existsSync(file)) { return { lines: [], note: 'No log file yet.' }; }
            var st = fs.statSync(file);
            var fd = fs.openSync(file, 'r');
            var len = Math.min(st.size, 256 * 1024);
            var buf = Buffer.alloc(len);
            fs.readSync(fd, buf, 0, len, Math.max(0, st.size - len));
            fs.closeSync(fd);
            var lines = buf.toString('utf8').split(String.fromCharCode(10));
            if (lines.length > 0 && lines[lines.length - 1] === '') { lines.pop(); }
            if (len < st.size) { lines.shift(); }
            return { lines: lines.slice(-300), size: st.size };
        } catch (ex) { return { lines: [], note: 'Could not read the log: ' + ex.message }; }
    };

    /**
     * @brief POST get_log: tail a plugin log for the UI. type is whitelisted.
     * @param {object} req - body.type: 'nvd' | 'winget' | 'os'.
     */
    obj.getLogHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        var t = String((req.body && req.body.type) || '');
        if (t === 'nvd') { var n = obj.tailLogFile(path.join(obj.nvdDataPath, 'nvd-download.log')); n.file = 'nvd/nvd-download.log'; return send(n); }
        if (t === 'winget') { var w = obj.tailLogFile(obj.wingetLogPath); w.file = 'plugins/inventoryscanner/winget-update.log'; return send(w); }
        if (t === 'os') { var o = obj.tailLogFile(obj.osLogPath); o.file = 'plugins/inventoryscanner/os-update.log'; return send(o); }
        if (t === 'deploy') { var s = obj.tailLogFile(obj.swLogPath); s.file = 'plugins/inventoryscanner/software-deploy.log'; return send(s); }
        send({ error: 'Unknown log type (nvd|winget|os|deploy).' });
    };

    /**
     * @brief Authorization rule for every route and the toolbar hook (OWASP A01).
     * The plugin works server-wide (all devices of all domains, one assessments file), so it is
     * restricted to full site administrators of the DEFAULT domain (user.domain === ''); in a
     * multi-domain (multi-tenant) server a sub-domain administrator must not see other tenants'
     * inventory (v3.0.1). Single-domain servers are unaffected.
     * @param {object} user - The authenticated MeshCentral user.
     * @returns {boolean} true when allowed.
     */
    obj.isAuthorizedAdmin = function (user) {
        return (user != null) && (user.siteadmin === 0xFFFFFFFF) && ((user.domain == null) || (user.domain === ''));
    };

    /**
     * @brief MeshCentral admin GET handler for the vulnerability assessment panel.
     * All routes are gated on full site admin.
     * <code>action=show</code> renders the assessment view;
     * <code>action=scan</code> returns the aggregated CVEs of a mesh as JSON.
     * @param {object} req - The Express request.
     * @param {object} res - The Express response.
     * @param {object} user - The authenticated user.
     */
    obj.handleAdminReq = function (req, res, user) {
        if (!obj.isAuthorizedAdmin(user)) { res.sendStatus(401); return; }
        // MeshCentral's plugin list (goPlugin) opens '/pluginadmin.ashx?pin=<name>' WITHOUT an
        // action - that is the panel, not a 404 (v4.3.2).
        var action = (req.query.action == null || req.query.action === '') ? 'show' : req.query.action;
        if (action === 'show') { return obj.showAssessmentPanel(req, res, user); }
        if (action === 'scan') { return obj.assessmentScan(req, res, user); }
        if (action === 'show_cpe') { return obj.showCustomCpe(req, res, user); }
        if (action === 'report') { return obj.vulnerabilityReport(req, res, user); }
        if (action === 'deviceReport') { return obj.deviceReport(req, res, user); }
        if (action === 'export') { return obj.exportCsv(req, res, user); }
        res.sendStatus(404);
    };

    /**
     * @brief Request-origin check for every state-changing POST (OWASP A01 / CWE-352).
     * MeshCentral authenticates pluginadmin.ashx by session cookie only (no CSRF token);
     * its default SameSite=lax already keeps the cookie off cross-site POSTs, but that is a
     * server setting (sessionsamesite) the plugin cannot rely on. Every POST must therefore
     * carry the custom header <code>X-InvScanner-Request: 1</code>: a cross-site page cannot
     * add a custom header without a CORS preflight, and MeshCentral never answers one with
     * Access-Control-Allow-* headers (OWASP "custom request header" defence). Origin/Host are
     * deliberately NOT compared - reverse proxies that rewrite Host would break the panel.
     * @param {object} req - The Express request.
     * @returns {boolean} true when the request may proceed.
     */
    obj.isSameOriginRequest = function (req) {
        var h = (req && req.headers) ? req.headers : {};
        return String(h['x-invscanner-request'] || '') === '1';
    };

    /**
     * @brief MeshCentral admin POST handler (urlencoded body): site-admin gate, request-origin
     * header check, then dispatch by <code>action</code> to the handler of the owning module
     * (assessments, CPE table, NVD, logs, winget, OS updates, software deploy, settings).
     * @param {object} req - The Express request.
     * @param {object} res - The Express response.
     * @param {object} user - The authenticated user.
     */
    obj.handleAdminPostReq = function (req, res, user) {
        if (!obj.isAuthorizedAdmin(user)) { res.sendStatus(401); return; }
        if (!obj.isSameOriginRequest(req)) { res.sendStatus(403); return; }
        if ((req.body == null) || (typeof req.body !== 'object')) { res.sendStatus(400); return; }
        if (req.body.action === 'save_assessment') { return obj.saveAssessmentHandler(req, res, user); }
        if (req.body.action === 'flag_false_positive') { return obj.flagFalsePositiveHandler(req, res, user); }
        if (req.body.action === 'unflag_false_positive') { return obj.unflagFalsePositiveHandler(req, res, user); }
        if (req.body.action === 'add_cpe') { return obj.addCpeHandler(req, res, user); }
        if (req.body.action === 'remove_cpe') { return obj.removeCpeHandler(req, res, user); }
        if (req.body.action === 'get_locations') { return obj.getLocationsHandler(req, res, user); }
        if (req.body.action === 'get_cpe_table') { return obj.getCpeTableHandler(req, res, user); }
        if (req.body.action === 'get_nvdlog') { return obj.getNvdLogHandler(req, res, user); }
        if (req.body.action === 'update_nvd') { return obj.updateNvdHandler(req, res, user); }
        if (req.body.action === 'get_log') { return obj.getLogHandler(req, res, user); }
        if (req.body.action === 'wg_get_config') { return obj.wgGetConfigHandler(req, res, user); }
        if (req.body.action === 'wg_save_config') { return obj.wgSaveConfigHandler(req, res, user); }
        if (req.body.action === 'wg_run') { return obj.wgRunHandler(req, res, user); }
        if (req.body.action === 'wg_status') { return obj.wgStatusHandler(req, res, user); }
        if (req.body.action === 'wg_programs') { return obj.wgProgramsHandler(req, res, user); }
        if (req.body.action === 'os_run') { return obj.osRunHandler(req, res, user); }
        if (req.body.action === 'os_status') { return obj.osStatusHandler(req, res, user); }
        if (req.body.action === 'sw_files') { return obj.swFilesHandler(req, res, user); }
        if (req.body.action === 'sw_upload') { return obj.swUploadHandler(req, res, user); }
        if (req.body.action === 'sw_delete_file') { return obj.swDeleteFileHandler(req, res, user); }
        if (req.body.action === 'sw_rescan_library') { return obj.swRescanLibraryHandler(req, res, user); }
        if (req.body.action === 'sw_serverfiles') { return obj.swServerFilesHandler(req, res, user); }
        if (req.body.action === 'sw_devices') { return obj.swDevicesHandler(req, res, user); }
        if (req.body.action === 'sw_create_task') { return obj.swCreateTaskHandler(req, res, user); }
        if (req.body.action === 'sw_status') { return obj.swStatusHandler(req, res, user); }
        if (req.body.action === 'sw_retry_task') { return obj.swRetryTaskHandler(req, res, user); }
        if (req.body.action === 'sw_cancel_task') { return obj.swCancelTaskHandler(req, res, user); }
        if (req.body.action === 'delete_cpe_table') { return obj.deleteCpeTableHandler(req, res, user); }
        if (req.body.action === 'get_settings') { return obj.getSettingsHandler(req, res, user); }
        if (req.body.action === 'save_settings') { return obj.saveSettingsHandler(req, res, user); }
        if (req.body.action === 'revert_setting') { return obj.revertSettingHandler(req, res, user); }
        res.sendStatus(404);
    };

    /**
     * @brief Render the vulnerability assessment panel view.
     * @param {object} req - The Express request.
     * @param {object} res - The Express response.
     * @param {object} user - The authenticated user.
     */
    obj.showAssessmentPanel = function (req, res, user) {
        obj.meshServer.db.GetAllType('mesh', function (err, meshes) {
            var meshList = [];
            if (!err && meshes) {
                for (var i = 0; i < meshes.length; i++) {
                    var m = meshes[i];
                    if ((m != null) && (m._id != null) && (m.deleted == null)) {
                        meshList.push({ id: m._id, name: (m.name != null) ? m.name : m._id });
                    }
                }
                meshList.sort(function (a, b) { return a.name.localeCompare(b.name); });
            }
            res.render('assessment', {
                shortName: obj.shortName,
                meshList: meshList,
                lastUpdate: obj.lastUpdate || '',
                lastScan: obj.lastScan || '',
                scanIntervalHours: obj.scannerConfig().intervalHours,
                totalCves: obj.allCves.length,
                version: obj.PLUGIN_VERSION
            });
        });
    };

    /**
     * @brief Get all unique locations (mesh groups) for the location filter.
     * @param {object} req - The Express request.
     * @param {object} res - The Express response.
     * @param {object} user - The authenticated user.
     */
    obj.getLocationsHandler = function (req, res, user) {
        obj.meshServer.db.GetAllType('mesh', function (err, meshes) {
            if (err) { res.type('json'); res.json({ error: err.message }); return; }
            var locations = [];
            if (meshes) {
                for (var i = 0; i < meshes.length; i++) {
                    var m = meshes[i];
                    if ((m != null) && (m._id != null) && (m.deleted == null)) {
                        locations.push({ id: m._id, name: (m.name != null) ? m.name : m._id });
                    }
                }
            }
            locations.sort(function (a, b) { return a.name.localeCompare(b.name); });
            res.type('json'); res.json({ locations: locations });
        });
    };

    /**
     * @brief Parse a comma-separated list of mesh ids from a request field.
     * @param {*} value - The raw field value (one or more comma-separated mesh ids).
     * @returns {Array<string>} The valid, unique mesh ids (<code>mesh/&lt;domain&gt;/&lt;name&gt;</code>).
     */
    obj.parseMeshIds = function (value) {
        var out = [];
        var parts = String(value || '').split(',');
        for (var i = 0; i < parts.length; i++) {
            var id = parts[i].trim();
            // Validate meshId format (prevents key-poisoning in assessments.json).
            if (id && /^mesh\/[^:]+$/.test(id) && (out.indexOf(id) < 0)) { out.push(id); }
        }
        return out;
    };
};
