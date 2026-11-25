/**
 * @file lib/assetmgmt.js
 * @brief Optional, opt-in connector that PUSHES the three lists this plugin already aggregates
 *        (hardware inventory, software inventory, vulnerabilities) OUT to an external asset-management
 *        system over its REST API - issue #5, v5.0.0.
 *
 * The plugin's data-protection model is unchanged: everything is still aggregated ON THIS SERVER; this
 * module only forwards that already-aggregated data when an administrator deliberately (a) configures a
 * target and (b) switches it on. Default is OFF and there is NO automatic push unless a sync interval is
 * set (also off by default). It is the one place the plugin can send data off-server, so:
 *   - the endpoint must be https (credentials never travel in the clear);
 *   - secrets (token / password / api-key value) are stored in scanner-settings.json and never returned
 *     to the browser in the clear (masked) and never written to any log;
 *   - request/response bodies are NOT logged - only the device, the HTTP status and an external id;
 *   - the sending runs entirely server-side from stored inventory: it issues NO agent command, so it does
 *     not touch the one-runcommands-session-per-agent rule and never reaches a device.
 *
 * Generic by design: a "generic" target maps fields of an aggregated record through an admin-authored
 * JSON body template with {{placeholders}} - which is how any REST system is reached. Two common systems
 * are also first-class presets that build the right request for you: Atlassian Jira (issue per device)
 * and Snipe-IT (open-source IT asset, hardware record per device).
 *
 * Part of the MeshCentral Inventory & Vulnerability Scanner plugin; see ../inventoryscanner.js for the
 * module list and attach order. All state hangs off obj.
 */

"use strict";

const fs = require('fs');
const path = require('path');
const https = require('https');

/**
 * @brief Attach this module's members to one plugin instance.
 * @param {object} obj - The plugin object created by the entry point.
 */
module.exports.attach = function (obj) {
    // ---------- config ----------

    /** @type {string} Sentinel typed (or sent) to erase a stored secret instead of keeping it. */
    obj.AS_CLEAR = '__AS_CLEAR__';
    /** @type {string} A masked placeholder shown where a secret is set (never the value). */
    obj.AS_MASK = '--------';

    /** @type {Array<string>} The supported connector kinds. */
    obj.AS_TARGET_TYPES = ['generic', 'jira', 'snipeit'];
    obj.AS_METHODS = ['POST', 'PUT', 'PATCH'];
    obj.AS_RESPONSE_MAX_BYTES = 64 * 1024;
    obj.AS_SWEEP_MS = 3600 * 1000; // re-check the schedule interval at most hourly

    /** @brief The effective asset-management config (plugin file wins over config.json; defaults fill gaps). */
    obj.assetConfig = function () {
        var c = obj.effectiveSectionConfig('assetManagement') || {};
        return {
            enabled: c.enabled === true,
            targetType: (obj.AS_TARGET_TYPES.indexOf(c.targetType) >= 0) ? c.targetType : 'generic',
            endpointUrl: String(c.endpointUrl || ''),
            authMode: (['none', 'bearer', 'basic', 'header'].indexOf(c.authMode) >= 0) ? c.authMode : 'none',
            username: String(c.username || ''),
            token: String(c.token || ''),
            password: String(c.password || ''),
            headerName: String(c.headerName || ''),
            headerValue: String(c.headerValue || ''),
            intervalHours: (typeof c.intervalHours === 'number' && c.intervalHours >= 0) ? c.intervalHours : 0,
            only: (c.only === 'vulnerable') ? 'vulnerable' : 'all',
            method: (obj.AS_METHODS.indexOf(c.method) >= 0) ? c.method : 'POST',
            headersJson: String(c.headersJson || '{}'),
            bodyTemplate: String(c.bodyTemplate || ''),
            externalIdPath: String(c.externalIdPath || ''),
            jiraProject: String(c.jiraProject || ''),
            jiraIssueType: String(c.jiraIssueType || 'Task'),
            jiraLabel: String(c.jiraLabel || 'inventory-scanner'),
            jiraSummary: String(c.jiraSummary || '[Inventory] {{device.given}}{{device.host}}'),
            jiraVulnIssues: c.jiraVulnIssues === true,
            snipeCategory: (typeof c.snipeCategory === 'number') ? c.snipeCategory : null,
            snipeNameTemplate: String(c.snipeNameTemplate || '{{device.given}}{{device.host}}'),
            // persisted (not from the browser):
            _hasToken: !!(c.token), _hasPassword: !!(c.password), _hasHeaderValue: !!(c.headerValue)
        };
    };

    // ---------- persisted last-push state ----------

    /** @type {object} last push result per device { id: {time,status,httpCode,externalId,error} }. */
    obj.asResults = {};

    obj.loadAssetResults = function () {
        obj.asResults = {};
        try {
            if (fs.existsSync(obj.asResultsPath)) {
                var d = JSON.parse(fs.readFileSync(obj.asResultsPath, 'utf8'));
                if (d && (typeof d === 'object')) obj.asResults = d;
            }
        } catch (e) { obj.asResults = {}; }
    };

    obj.saveAssetResults = function () {
        try {
            var dir = path.dirname(obj.asResultsPath);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            fs.writeFileSync(obj.asResultsPath, JSON.stringify(obj.asResults));
        } catch (e) { obj.debug('plugin:inventory_scanner', 'Could not save asset-sync results:', e.message); }
    };

    /** @brief Append a redacted line to the asset-sync log (rotated ~5 MB). Never a payload/secret. */
    obj.asLog = function (line) {
        try {
            var dir = path.dirname(obj.asLogPath);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            try { if (fs.existsSync(obj.asLogPath) && (fs.statSync(obj.asLogPath).size > 5 * 1024 * 1024)) fs.renameSync(obj.asLogPath, obj.asLogPath + '.old'); } catch (e) { }
            fs.appendFileSync(obj.asLogPath, new Date().toISOString() + ' ' + line + String.fromCharCode(10));
        } catch (e) { }
    };

    // ---------- generic template helpers ----------

    /** @brief Resolve a dotted {{path}} against a record; returns undefined when absent. */
    obj.asResolve = function (record, pth) {
        var parts = String(pth).trim().split('.');
        var v = record;
        for (var i = 0; i < parts.length && v != null; i++) { v = v[parts[i]]; }
        return v;
    };

    /** @brief Replace every {{path}} in a string with the value (kept as text). */
    obj.asFillString = function (str, record) {
        return String(str).replace(/\{\{\s*([\w.]+)\s*\}\}/g, function (_m, p) {
            var v = obj.asResolve(record, p);
            if (v == null) { return ''; }
            return (typeof v === 'object') ? JSON.stringify(v) : String(v);
        });
    };

    /**
     * @brief Recursively fill a parsed template. A string that is exactly one {{path}} is replaced by the
     * typed value (so an array or number injects whole); otherwise {{path}} tokens inside the text are
     * string-replaced. Values are JSON data only - this never evaluates code.
     */
    obj.asFill = function (node, record) {
        if (typeof node === 'string') {
            var only = node.match(/^\{\{\s*([\w.]+)\s*\}\}$/);
            if (only) { var v = obj.asResolve(record, only[1]); return (v === undefined) ? '' : v; }
            return obj.asFillString(node, record);
        }
        if (Array.isArray(node)) { return node.map(function (e) { return obj.asFill(e, record); }); }
        if (node && (typeof node === 'object')) {
            var o = {}; for (var k in node) { if (Object.prototype.hasOwnProperty.call(node, k)) o[k] = obj.asFill(node[k], record); } return o;
        }
        return node;
    };

    /** @brief Build the auth headers for a config (server-side only; never returned to the browser). */
    obj.asAuthHeaders = function (cfg) {
        var h = {};
        if (cfg.authMode === 'bearer' && cfg.token) { h['Authorization'] = 'Bearer ' + cfg.token; }
        else if (cfg.authMode === 'basic' && (cfg.username || cfg.password)) {
            h['Authorization'] = 'Basic ' + Buffer.from(cfg.username + ':' + cfg.password, 'utf8').toString('base64');
        } else if (cfg.authMode === 'header' && cfg.headerName && cfg.headerValue) { h[cfg.headerName] = cfg.headerValue; }
        return h;
    };

    /** @brief A minimal valid Atlassian Document Format doc from plain paragraph strings. */
    obj.asAdf = function (lines) {
        var content = [];
        for (var i = 0; i < lines.length; i++) {
            content.push({ type: 'paragraph', content: [{ type: 'text', text: String(lines[i]).substring(0, 30000) }] });
        }
        return { type: 'doc', version: 1, content: content };
    };

    /**
     * @brief Build the list of HTTP requests that represent ONE device record for the configured target.
     * Returns { error } or { requests: [{method,url,headers,body,externalKey}] }. Pure: no I/O.
     */
    obj.asBuildRequests = function (record, cfg, lastExternalId) {
        if (!/^https:\/\//i.test(cfg.endpointUrl)) { return { error: 'The asset endpoint URL must be https.' }; }
        var base = cfg.endpointUrl.replace(/\/+$/, '');
        var common = { 'Content-Type': 'application/json', 'Accept': 'application/json', 'User-Agent': 'meshcentral-inventoryscanner' };
        var auth = obj.asAuthHeaders(cfg);
        var h; for (var k in auth) { if (Object.prototype.hasOwnProperty.call(auth, k)) common[k] = auth[k]; }
        var d = record.device;
        if (cfg.targetType === 'jira') {
            var summary = obj.asFillString(cfg.jiraSummary || '[Inventory] ', record) || ('Inventory ' + (d.given || d.host || d.id));
            var body = JSON.stringify(record.software || []); var vbody = JSON.stringify(record.vulnerabilities || []);
            var desc = obj.asAdf([
                'Device ' + (d.given || '') + ' ' + (d.host || '') + ' (' + (d.id || '') + ')',
                'Group: ' + (d.group || '') + ' | OS: ' + (d.os || '') + ' | Online: ' + (d.online ? 'yes' : 'no'),
                'Hardware: ' + JSON.stringify(record.hardware || {}),
                'Installed software (' + (record.software || []).length + '): ' + body,
                'Vulnerabilities (' + (record.vulnerabilities || []).length + '): ' + vbody
            ]);
            var fields = { summary: summary.substring(0, 255), labels: [String(cfg.jiraLabel || 'inventory-scanner').substring(0, 100)], description: desc };
            var reqs = [];
            if (lastExternalId) {
                reqs.push({ method: 'PUT', url: base + '/rest/api/3/issue/' + encodeURIComponent(lastExternalId), headers: common, body: { fields: fields }, externalKey: lastExternalId });
            } else {
                fields.project = { key: cfg.jiraProject }; fields.issuetype = { name: cfg.jiraIssueType || 'Task' };
                reqs.push({ method: 'POST', url: base + '/rest/api/3/issue', headers: common, body: { fields: fields }, externalKey: null });
            }
            return { requests: reqs };
        }
        if (cfg.targetType === 'snipeit') {
            var name = obj.asFillString(cfg.snipeNameTemplate || '{{device.given}}{{device.host}}', record) || (d.host || d.id);
            var payload = {
                name: String(name).substring(0, 190),
                asset_tag: ('inv-' + String(d.id).replace(/[^A-Za-z0-9_-]/g, '')).substring(0, 100),
                serial: String((record.hardware && record.hardware.serial) || '').substring(0, 100),
                status_id: 1,
                notes: ('OS: ' + (d.os || '') + ' | software ' + (record.software || []).length + ' | vulns ' + (record.vulnerabilities || []).length).substring(0, 1000)
            };
            if (cfg.snipeCategory != null) payload.category_id = cfg.snipeCategory;
            var sreq = lastExternalId
                ? { method: 'PATCH', url: base + '/api/hardware/' + encodeURIComponent(lastExternalId), headers: common, body: payload, externalKey: lastExternalId }
                : { method: 'POST', url: base + '/api/hardware', headers: common, body: payload, externalKey: null };
            return { requests: [sreq] };
        }
        // generic: body from the admin JSON template
        var tpl = cfg.bodyTemplate;
        if (!tpl) { return { error: 'Set a JSON body template for the generic target.' }; }
        var parsed = null;
        try { parsed = JSON.parse(tpl); } catch (e) { return { error: 'Body template is not valid JSON: ' + e.message }; }
        var hdrs = {};
        try { var ej = JSON.parse(cfg.headersJson || '{}'); if (ej && typeof ej === 'object') { for (var hk in ej) { if (Object.prototype.hasOwnProperty.call(ej, hk)) hdrs[String(hk)] = obj.asFillString(String(ej[hk]), record); } } } catch (e) { return { error: 'Extra-headers field is not valid JSON.' }; }
        var gheaders = {}; for (var gk in common) { if (Object.prototype.hasOwnProperty.call(common, gk)) gheaders[gk] = common[gk]; }
        for (var xk in hdrs) { if (Object.prototype.hasOwnProperty.call(hdrs, xk)) gheaders[xk] = hdrs[xk]; }
        return { requests: [{ method: cfg.method, url: base, headers: gheaders, body: obj.asFill(parsed, record), externalKey: null }] };
    };

    /**
     * @brief Pull an external id out of a create response so the next push UPDATES instead of
     * duplicating. Jira answers {id,key}, Snipe-IT {payload:{id}} or {id}; for a generic target the
     * admin says where the id lives via externalIdPath (a dotted path, e.g. "id" or "data.asset.id").
     */
    obj.asExternalId = function (cfg, text) {
        try {
            var o = JSON.parse(text);
            if (cfg.targetType === 'jira') { return String(o.id || o.key || ''); }
            if (cfg.targetType === 'snipeit') { return String((o && o.payload && o.payload.id != null) ? o.payload.id : (o.id != null ? o.id : '')); }
            var p = String(cfg.externalIdPath || '').trim();
            if (p === '') { return ''; }
            var v = o;
            var parts = p.split('.');
            for (var i = 0; i < parts.length && v != null; i++) { v = v[parts[i]]; }
            return (v == null) ? '' : String(v);
        } catch (e) { }
        return '';
    };

    /**
     * @brief Outbound single https request (injectable indirection so tests run offline). opts
     * {method,url,headers,body(object)}. https-only; response text capped; never logs anything.
     */
    obj.assetHttp = function (opts, callback) {
        var u = null;
        try { u = new URL(opts.url); } catch (e) { return callback(new Error('Invalid URL')); }
        if (u.protocol !== 'https:') { return callback(new Error('Only https endpoints are allowed')); }
        var payload = (opts.body != null) ? JSON.stringify(opts.body) : null;
        var headers = Object.assign({}, opts.headers || {});
        if (payload != null) { headers['Content-Length'] = Buffer.byteLength(payload); }
        var req = https.request({
            method: opts.method, hostname: u.hostname, port: u.port || 443, path: u.pathname + (u.search || ''),
            headers: headers, timeout: 30000
        }, function (res) {
            var size = 0, parts = [];
            res.on('data', function (c) { size += c.length; if (size > obj.AS_RESPONSE_MAX_BYTES) { req.destroy(new Error('Response too large')); return; } parts.push(c); });
            res.on('end', function () { callback(null, { statusCode: res.statusCode, text: Buffer.concat(parts).toString('utf8').substring(0, obj.AS_RESPONSE_MAX_BYTES) }); });
        });
        req.on('error', function (e) { callback(e); });
        req.on('timeout', function () { req.destroy(new Error('Request timed out')); });
        if (payload != null) req.write(payload);
        req.end();
    };

    // ---------- record collection ----------

    /** @brief Build the aggregated record for one node from data already stored on this server. */
    obj.asCollectDeviceRecord = function (node, cb) {
        obj.fetchSysinfo(node, function (err, sr) {
            if (err) { cb(err); return; }
            var doc = sr ? (sr.doc || sr) : {};
            var hw = doc.hardware || {};
            var ident = hw.identifiers || {};
            var ws = obj.meshServer.webserver;
            var software = obj.getStoredSoftware(node, doc).map(function (a) {
                return { name: a.name || a.Name || a.displayName || '', version: a.version || a.Version || '', publisher: a.publisher || a.Publisher || a.vendor || '' };
            });
            obj.scanNodeSoftware(node, software, function (vulns) {
                var vlist = [];
                for (var i = 0; i < (vulns || []).length; i++) {
                    var v = vulns[i];
                    if (v && v.isCve === true) vlist.push({ cve: v.cve || '', severity: v.severity || 'UNKNOWN', cvss: (v.cvss != null ? v.cvss : ''), software: v.software || '', version: v.version || '' });
                }
                cb(null, {
                    device: {
                        id: node._id, host: obj.getHostName(node), given: (typeof node.name === 'string') ? node.name.trim() : '',
                        group: obj.getGroupName(node), os: String(node.osdesc || ''), platform: obj.osPlatformOf ? (obj.osPlatformOf(node) || '') : '',
                        online: !!(ws && ws.wsagents && ws.wsagents[node._id])
                    },
                    hardware: {
                        cpu: ident.cpu_name || '', manufacturer: ident.manufacturer || hw.manufacturer || '', model: ident.model || hw.model || '',
                        serial: ident.serial || hw.serial || '', bios: ident.bios_version || '', memoryBytes: (hw.totalMemory || 0),
                        os: String(node.osdesc || ''), ip: node.ip || ''
                    },
                    software: software,
                    vulnerabilities: vlist,
                    counts: { software: software.length, vulnerabilities: vlist.length }
                });
            });
        });
    };

    // ---------- push / test ----------

    obj.asPushing = false;

    /** @brief Send one device's aggregated record. cb(err, resultRecord). */
    obj.asSendDevice = function (nodeId, cb) {
        var cfg = obj.assetConfig();
        obj.db.Get(nodeId, function (gerr, docs) {
            if (gerr || !docs || !docs.length) { return cb(new Error('Device not found')); }
            var node = docs[0];
            if ((node == null) || (node.deleted != null)) { return cb(new Error('Device deleted')); }
            obj.asCollectDeviceRecord(node, function (cerr, record) {
                if (cerr) { return cb(cerr); }
                if (cfg.only === 'vulnerable' && (record.counts.vulnerabilities === 0)) {
                    // record the skip so the UI never shows a stale "ok" from an earlier push
                    var sk = { time: new Date().toISOString(), status: 'skipped', note: 'no vulnerabilities' };
                    obj.asResults[nodeId] = sk; obj.saveAssetResults();
                    obj.asLog((record.device.host || nodeId) + ' - push skipped (no vulnerabilities)');
                    return cb(null, sk);
                }
                var last = obj.asResults[nodeId]; var externalId = last ? last.externalId : null;
                var built = obj.asBuildRequests(record, cfg, externalId);
                if (built.error) { return cb(new Error(built.error)); }
                var reqs = built.requests; var sent = 0; var newId = externalId || ''; var fail = null; var code = 0;
                (function sendOne() {
                    if (sent >= reqs.length) {
                        var rec = { time: new Date().toISOString(), status: fail ? 'error' : 'ok', httpCode: code, externalId: newId };
                        if (fail) rec.error = fail;
                        obj.asResults[nodeId] = rec; obj.saveAssetResults();
                        obj.asLog((record.device.host || nodeId) + ' - push ' + rec.status + (code ? (' http ' + code) : '') + (fail ? (' (' + fail + ')') : ''));
                        return cb(null, rec);
                    }
                    var rq = reqs[sent++];
                    obj.assetHttp(rq, function (e, r) {
                        if (e) { fail = e.message; code = 0; return sendOne(); }
                        code = r ? r.statusCode : 0;
                        if (code >= 200 && code < 300) {
                            var id = obj.asExternalId(cfg, r.text);
                            if (id) newId = id;
                        } else { fail = 'HTTP ' + code; }
                        sendOne();
                    });
                })();
            });
        });
    };

    /** @brief POST as_push: push all (or the given) devices now. Uses stored data only - no agent command. */
    obj.asPushHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        var cfg = obj.assetConfig();
        if (!cfg.enabled) { return send({ error: 'Asset sync is disabled - enable it (and set a target) first.' }); }
        if (obj.asPushing) { return send({ started: false, busy: true }); }
        var ids = null;
        if (req.body && req.body.nodeIds) {
            var a = String(req.body.nodeIds).split(',').filter(function (x) { return /^node\/[^:]{1,100}$/.test(x.trim()); }).map(function (x) { return x.trim(); });
            if (a.length) ids = a.slice(0, 2000);
        }
        obj.asPushing = true;
        var finish = function (count, errs) { obj.asPushing = false; obj.asLog('push run: ' + count + ' device(s), ' + errs + ' error(s) by ' + ((user && user.name) || '?')); send({ started: true, devices: count, errors: errs }); };
        var pick = function (nodes) {
            var out = []; for (var i = 0; i < nodes.length; i++) { var n = nodes[i]; if (n && n._id && n.deleted == null && n.name != null && n._id.indexOf('node/') === 0) out.push(n._id); }
            if (ids) out = out.filter(function (x) { return ids.indexOf(x) >= 0; });
            return out;
        };
        obj.db.GetAllType('node', function (gerr, nodes) {
            if (gerr) { obj.asPushing = false; return send({ error: gerr.message }); }
            var list = pick(nodes || []);
            if (list.length === 0) { obj.asPushing = false; return finish(0, 0); }
            var done = 0, errs = 0;
            list.forEach(function (nid) {
                obj.asSendDevice(nid, function (e) { if (e) errs++; if (++done >= list.length) finish(list.length, errs); });
            });
        });
    };

    /** @brief POST as_test: send ONE synthetic record to verify the target + credentials. Status only. */
    obj.asTestHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        var cfg = obj.assetConfig();
        if (!cfg.endpointUrl) { return send({ error: 'Set the endpoint URL first.' }); }
        var sample = {
            device: { id: 'node//test', host: 'testhost', given: 'Test', group: 'Test group', os: 'TestOS', platform: 'windows', online: true },
            hardware: { cpu: 'test cpu', manufacturer: 'test', model: 'test', serial: 'TESTSERIAL', memoryBytes: 0, os: 'TestOS', ip: '' },
            software: [{ name: 'Test Software', version: '1.0', publisher: 'Test' }],
            vulnerabilities: [{ cve: 'CVE-0000-0000', severity: 'LOW', cvss: 0, software: 'Test Software', version: '1.0' }],
            counts: { software: 1, vulnerabilities: 1 }
        };
        var built = obj.asBuildRequests(sample, cfg, null);
        if (built.error) { return send({ error: built.error }); }
        obj.assetHttp(built.requests[0], function (e, r) {
            if (e) { obj.asLog('test - ' + e.message); return send({ ok: false, error: e.message }); }
            obj.asLog('test request -> HTTP ' + (r ? r.statusCode : '?'));
            send({ ok: r && r.statusCode >= 200 && r.statusCode < 300, httpCode: r ? r.statusCode : 0 });
        });
    };

    /** @brief POST as_status: the config summary (secrets masked) + last push per device. */
    obj.asStatusHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        obj.db.GetAllType('node', function (gerr, nodes) {
            var devices = [];
            if (!gerr && nodes) {
                for (var i = 0; i < nodes.length; i++) {
                    var n = nodes[i]; if (!n || !n._id || n.deleted != null || n.name == null || n._id.indexOf('node/') !== 0) continue;
                    var last = obj.asResults[n._id] || null;
                    devices.push({ id: n._id, host: obj.getHostName(n), given: (typeof n.name === 'string') ? n.name.trim() : '', group: obj.getGroupName(n), last: last });
                }
            }
            var cfg = obj.assetConfig();
            devices.sort(function (a, b) { return (a.group === b.group) ? String(a.given || a.host).localeCompare(String(b.given || b.host)) : String(a.group).localeCompare(String(b.group)); });
            send({
                devices: devices, running: !!obj.asPushing,
                config: {
                    enabled: cfg.enabled, targetType: cfg.targetType, endpointUrl: cfg.endpointUrl, authMode: cfg.authMode,
                    intervalHours: cfg.intervalHours, only: cfg.only, method: cfg.method, username: cfg.username, headerName: cfg.headerName,
                    externalIdPath: cfg.externalIdPath,
                    jiraProject: cfg.jiraProject, jiraIssueType: cfg.jiraIssueType, jiraLabel: cfg.jiraLabel, jiraSummary: cfg.jiraSummary, jiraVulnIssues: cfg.jiraVulnIssues,
                    snipeCategory: cfg.snipeCategory, snipeNameTemplate: cfg.snipeNameTemplate,
                    hasToken: !!cfg._hasToken, hasPassword: !!cfg._hasPassword, hasHeaderValue: !!cfg._hasHeaderValue
                }
            });
        });
    };

    /** @brief POST as_get_config: same as as_status.config without the device table. */
    obj.asGetConfigHandler = function (req, res, user) {
        var cfg = obj.assetConfig();
        res.type('json');
        res.json({ config: {
            enabled: cfg.enabled, targetType: cfg.targetType, endpointUrl: cfg.endpointUrl, authMode: cfg.authMode,
            intervalHours: cfg.intervalHours, only: cfg.only, method: cfg.method, headersJson: cfg.headersJson, bodyTemplate: cfg.bodyTemplate,
            externalIdPath: cfg.externalIdPath,
            username: cfg.username, headerName: cfg.headerName, jiraProject: cfg.jiraProject, jiraIssueType: cfg.jiraIssueType, jiraLabel: cfg.jiraLabel,
            jiraSummary: cfg.jiraSummary, jiraVulnIssues: cfg.jiraVulnIssues, snipeCategory: cfg.snipeCategory, snipeNameTemplate: cfg.snipeNameTemplate,
            tokenMask: cfg._hasToken ? obj.AS_MASK : '', passwordMask: cfg._hasPassword ? obj.AS_MASK : '', headerValueMask: cfg._hasHeaderValue ? obj.AS_MASK : '',
            hasToken: !!cfg._hasToken, hasPassword: !!cfg._hasPassword, hasHeaderValue: !!cfg._hasHeaderValue
        } });
    };

    /** @brief POST as_save_config: validate + store the assetManagement section; blank secret = keep. */
    obj.asSaveConfigHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        var b = req.body || {};
        var others = {};
        for (var sk in obj.pluginSettings) { if (Object.prototype.hasOwnProperty.call(obj.pluginSettings, sk) && sk !== 'assetManagement') others[sk] = obj.pluginSettings[sk]; }
        var prev = obj.pluginSettings.assetManagement || {};
        var targetType = (obj.AS_TARGET_TYPES.indexOf(b.targetType) >= 0) ? b.targetType : 'generic';
        var url = String(b.endpointUrl || '').trim();
        if (url !== '' && !/^https:\/\/[^\s"'<>]{5,300}$/.test(url)) { return send({ error: 'Endpoint must be a short https URL.' }); }
        var method = (obj.AS_METHODS.indexOf(b.method) >= 0) ? b.method : 'POST';
        var authMode = (['none', 'bearer', 'basic', 'header'].indexOf(b.authMode) >= 0) ? b.authMode : 'none';
        var ih = 0; if (b.intervalHours != null && String(b.intervalHours) !== '') { ih = parseInt(String(b.intervalHours), 10); if (isNaN(ih) || ih < 0 || ih > 8760) return send({ error: 'Invalid sync interval (0..8760 hours).' }); }
        var enabled = obj.boolSetting(b.enabled, false);
        if (enabled && url === '') { return send({ error: 'Enable needs an https endpoint URL.' }); }
        if (enabled && targetType === 'jira' && !String(b.jiraProject || '').trim()) { return send({ error: 'Jira needs a project key.' }); }
        // body/headers template validation (generic only)
        if (targetType === 'generic') {
            if (b.headersJson != null && String(b.headersJson).trim() !== '') { try { var hj = JSON.parse(b.headersJson); if (!hj || typeof hj !== 'object' || Array.isArray(hj)) return send({ error: 'Extra headers must be a JSON object.' }); } catch (e) { return send({ error: 'Extra headers are not valid JSON.' }); } }
            if (enabled && String(b.bodyTemplate || '').trim() === '') { return send({ error: 'The generic target needs a JSON body template.' }); }
            if (String(b.bodyTemplate || '').trim() !== '') { try { JSON.parse(b.bodyTemplate); } catch (e) { return send({ error: 'Body template is not valid JSON.' }); } }
        }
        var keep = function (name) { var v = (b[name] != null) ? String(b[name]) : null; if (v == null || v === '') return prev[name] || ''; if (v === obj.AS_CLEAR) return ''; return v; };
        others.assetManagement = {
            enabled: enabled, targetType: targetType, endpointUrl: url, authMode: authMode,
            username: String(b.username || '').trim(), headerName: String(b.headerName || '').trim(),
            token: keep('token'), password: keep('password'), headerValue: keep('headerValue'),
            intervalHours: ih, only: (b.only === 'vulnerable') ? 'vulnerable' : 'all',
            method: method, headersJson: String(b.headersJson || '{}'), bodyTemplate: String(b.bodyTemplate || ''),
            externalIdPath: String(b.externalIdPath || '').trim().substring(0, 120),
            jiraProject: String(b.jiraProject || '').trim(), jiraIssueType: String(b.jiraIssueType || 'Task').trim(),
            jiraLabel: String(b.jiraLabel || 'inventory-scanner').trim(), jiraSummary: String(b.jiraSummary || '').trim(),
            jiraVulnIssues: obj.boolSetting(b.jiraVulnIssues, false),
            snipeCategory: (b.snipeCategory != null && String(b.snipeCategory) !== '') ? (parseInt(String(b.snipeCategory), 10) || null) : null,
            snipeNameTemplate: String(b.snipeNameTemplate || '').trim()
        };
        var previous = obj.pluginSettings; obj.pluginSettings = others;
        obj.savePluginSettings(function (err) {
            if (err) { obj.pluginSettings = previous; return send({ error: err.message }); }
            obj.rescheduleAll();
            obj.asLog('configuration saved by ' + ((user && user.name) || '?') + ' - target ' + targetType + ', ' + (enabled ? 'ENABLED' : 'disabled') + ' (secrets not logged)');
            obj.asGetConfigHandler({}, res, user);
        });
    };

    /** @brief The optional scheduled push - runs ONLY when enabled AND intervalHours > 0. */
    obj.scheduleAssetSync = function () {
        var cfg = obj.assetConfig();
        if (!cfg.enabled || !(cfg.intervalHours > 0)) { return; }
        var gen = obj.timerGen;
        obj.longTimeout(function () {
            if (!obj.timerValid(gen)) return;
            obj.asPushHandler({ body: {}, headers: {} }, { type: function () { return this; }, json: function () { } }, { name: 'scheduler' });
            obj.scheduleAssetSync();
        }, cfg.intervalHours * 3600 * 1000);
    };
};
