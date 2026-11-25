/**
 * @file lib/license.js
 * @brief License keys / license info in the software inventory (issue #7, v4.8.0). Like the CPE table, the
 * core is a curated + downloadable + admin-editable mapping from a software name to one or more EXTRACTION
 * rules (Windows registry value, a file read with a regex / line / raw, or a WMI class property), so every
 * deployment can teach it which program stores its license where - not just Microsoft software. A read-only
 * PowerShell script runs those (trusted, admin-curated) rules on the device and returns the found values.
 * Collected per device on demand (never automatic, opt-in default off), stored under data/<node>/license.json,
 * and added as two columns to the software-inventory CSV for asset management. The rule strings travel
 * base64-embedded and are used ONLY as registry paths / file contents / CIM properties, never as code.
 * Transport is the OS engine's: invscanner-lic- sessions (runcommands type 1), marker @@INVLIC@@, on the
 * shared routeAgentCommand hook; a node with a license run is skipped by every other pump.
 *
 * Part of the MeshCentral Inventory & Vulnerability Scanner plugin; see ../inventoryscanner.js
 * for the module list and the attach order. Every member is attached to the shared plugin
 * object, so cross-module calls go through obj.name(...) and stay replaceable at runtime.
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
    /** @brief marker of the one-line JSON answer of a license collect script. */
    obj.LIC_MARKER = '@@INVLIC@@';

    /** @brief session/responseid prefix of a license collection command. */
    obj.LIC_SESSION_PREFIX = 'invscanner-lic-';

    /** @type {number} reading registry/files/WMI for many apps is bounded but can take a couple of minutes. */
    obj.LIC_TIMEOUT_MS = 6 * 60 * 1000;

    /** @type {string} default URL of the repository-maintained license table. */
    obj.LICENSE_TABLE_DEFAULT_URL = 'https://raw.githubusercontent.com/derStephan/meshcentral-inventoryscanner/main/license-table.json';

    /** @type {number} hard cap for the remote license table payload (2 MB). */
    obj.LICENSE_TABLE_MAX_BYTES = 2 * 1024 * 1024;

    /** @type {number} caps on the per-device extraction so the script stays small. */
    obj.LIC_MAX_APPS = 60;
    obj.LIC_MAX_RULES_PER_APP = 8;
    /** @type {number} Hard cap on the user profiles one per-user run considers (issue #10). */
    obj.LIC_MAX_USERS = 20;

    /** @type {Array<object>|null} compiled curated/remote table: { match:RegExp, label, rules:[...] }. */
    obj.remoteLicenseEntries = null;
    /** @type {string} origin of the applied table: '' | 'downloaded' | 'cache' | 'bundled'. */
    obj.licenseTableOrigin = '';
    /** @type {string|null} ISO time the table was loaded. */
    obj.licenseTableLoadedAt = null;
    /** @type {Array<object>} admin custom rules { match, label, rules:[...] }, consulted first. */
    obj.customLicenseEntries = [];

    /** @type {Object<string, object>} nodeid -> live { sid, since, timer }. */
    obj.licPending = {};
    /** @type {Object<string, object>} safeNodeDir -> { time, items:[{name,license,source,ok}], ms:[{name,key}], error }. */
    obj.licenseInventory = {};

    // ---- curated + remote + custom license table (mirrors lib/cpetable.js) ----

    /** @brief Load the license table from disk (cache, then the copy shipped in the plugin folder). */
    obj.loadLicenseTable = function () {
        var tryFiles = [obj.licenseCachePath, path.join(obj.pluginDir, 'license-table.json')];
        for (var f = 0; f < tryFiles.length; f++) {
            try {
                if (!fs.existsSync(tryFiles[f])) continue;
                var r = obj.applyLicenseTableText(fs.readFileSync(tryFiles[f], 'utf8'));
                if (r.ok) {
                    obj.licenseTableOrigin = (f === 0 ? 'cache' : 'bundled');
                    try { obj.licenseTableLoadedAt = new Date(fs.statSync(tryFiles[f]).mtimeMs).toISOString(); } catch (ex) { }
                    return;
                }
            } catch (ex) { }
        }
        obj.remoteLicenseEntries = [];
    };

    /**
     * @brief Validate + compile a license-table JSON ({ entries:[{match,label,rules:[...] }] }).
     * match uses the same regex-safety gate as the CPE table; rule fields are length-capped and their types
     * restricted. Invalid entries/rule fields are skipped, never fatal.
     * @returns {object} { ok, applied, skipped, error? }
     */
    obj.applyLicenseTableText = function (payload) {
        var data = null;
        try { data = (typeof payload === 'string') ? JSON.parse(payload) : payload; } catch (ex) { return { ok: false, applied: 0, skipped: 0, error: 'Invalid JSON: ' + ex.message }; }
        if (!data || !Array.isArray(data.entries)) { return { ok: false, applied: 0, skipped: 0, error: 'Missing entries array.' }; }
        if (data.entries.length > 5000) { return { ok: false, applied: 0, skipped: 0, error: 'Too many entries.' }; }
        var out = [], applied = 0, skipped = 0;
        for (var i = 0; i < data.entries.length; i++) {
            var en = data.entries[i];
            if (!en || (typeof en.match !== 'string') || (en.match.length === 0) || !obj.isSafeTableRegex(en.match)) { skipped++; continue; }
            var rules = obj.sanitizeLicenseRules(en.rules);
            if (rules == null) { skipped++; continue; }
            try { out.push({ match: new RegExp(en.match, 'i'), label: String(en.label || en.match).substring(0, 120), rules: rules }); applied++; }
            catch (ex) { skipped++; }
        }
        if (applied === 0 && skipped > 0 && out.length === 0) { return { ok: false, applied: 0, skipped: skipped, error: 'No valid entries.' }; }
        obj.remoteLicenseEntries = out;
        obj.licenseTableLoadedAt = new Date().toISOString();
        return { ok: true, applied: applied, skipped: skipped };
    };

    /**
     * @brief Validate the rule list of one entry; returns a clean array or null when unusable. Only three
     * rule types exist, each with only data fields - no command text can ever come from the table.
     * Since v5.5.0 (issue #10) three OPTIONAL extensions exist, all still data-only:
     *  - `perUser: true` on a registry rule: the path is written `HKCU:\...` and applied per loaded user hive
     *    (`Registry::HKEY_USERS\<SID>\...`); perUser on an HKLM path is refused (it would mean nothing).
     *  - `perUser: true` on a file rule with a `{{profile}}` placeholder: the placeholder becomes each user's
     *    profile directory; `{{profile}}` WITHOUT perUser is refused.
     *  - exactly ONE `*` wildcard: in a registry path it is one whole subkey segment (enumerated, at most 20
     *    matches); in a file path it is a leaf pattern (at most 5 candidate files). More than one is refused.
     * @returns {Array<object>|null}
     */
    obj.sanitizeLicenseRules = function (rules) {
        if (!Array.isArray(rules) || rules.length === 0 || rules.length > obj.LIC_MAX_RULES_PER_APP) { return null; }
        var wild = function (s) { return (String(s).match(/\*/g) || []).length; };
        var clean = [];
        for (var i = 0; i < rules.length; i++) {
            var r = rules[i];
            if (!r || typeof r !== 'object') { return null; }
            var t = String(r.type || '');
            var str = function (v, n) { return (typeof v === 'string') ? v.substring(0, n) : ''; };
            var pu = (r.perUser === true);
            if (t === 'registry') {
                var p = str(r.path, 1000), v = str(r.value, 200);
                if (!p || !v) { return null; }
                if (wild(p) > 1 || wild(v) > 0) { return null; }
                if (pu && !/^HKCU:\\/i.test(p)) { return null; }   // per-user registry only makes sense under HKCU
                var o1 = { type: 'registry', path: p, value: v };
                if (pu) { o1.perUser = true; }
                clean.push(o1);
            }
            else if (t === 'file') {
                var fp = str(r.path, 1000); if (!fp) { return null; }
                if (wild(fp) > 1) { return null; }
                if (fp.indexOf('{{profile}}') >= 0 && !pu) { return null; }   // placeholder without per-user = refused
                var o = { type: 'file', path: fp };
                if (pu) { o.perUser = true; }
                if (r.regex != null) { var rg = str(r.regex, 500); if (rg && !obj.isSafeTableRegex(rg)) { return null; } if (rg) { o.regex = rg; } }
                if (r.jsonfield != null) { o.jsonfield = str(r.jsonfield, 100); }
                if (typeof r.line === 'number' && r.line >= 1) { o.line = Math.floor(r.line); }
                clean.push(o);
            }
            else if (t === 'wmi') {
                if (pu) { return null; }   // WMI is machine-wide; a per-user flag would be a lie
                var cls = str(r.class, 120), pr = str(r.property, 120); if (!cls || !pr) { return null; }
                var w = { type: 'wmi', class: cls, property: pr }; if (r.filter != null) { w.filter = str(r.filter, 300); }
                clean.push(w);
            }
            else { return null; }
        }
        return clean.length ? clean : null;
    };

    /** @brief Custom license rules file (admin-edited) load/save. */
    obj.loadCustomLicense = function () {
        obj.customLicenseEntries = [];
        try {
            if (fs.existsSync(obj.customLicensePath)) {
                var d = JSON.parse(fs.readFileSync(obj.customLicensePath, 'utf8'));
                if (Array.isArray(d)) {
                    for (var i = 0; i < d.length; i++) {
                        var e = d[i];
                        if (e && typeof e.match === 'string' && obj.isSafeTableRegex(e.match)) {
                            var rules = obj.sanitizeLicenseRules(e.rules);
                            if (rules != null) { obj.customLicenseEntries.push({ match: e.match, label: String(e.label || e.match).substring(0, 120), rules: rules }); }
                        }
                    }
                }
            }
        } catch (err) { obj.customLicenseEntries = []; }
    };
    obj.saveCustomLicense = function (cb) {
        try { var d = path.dirname(obj.customLicensePath); if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); fs.writeFileSync(obj.customLicensePath, JSON.stringify(obj.customLicenseEntries, null, 2)); if (cb) cb(null); }
        catch (err) { if (cb) cb(err); }
    };

    /** @brief Compiled custom entries as regexes. */
    obj.compiledCustomLicense = function () {
        var out = [];
        for (var i = 0; i < obj.customLicenseEntries.length; i++) {
            var e = obj.customLicenseEntries[i];
            if (!obj.isSafeTableRegex(e.match)) { continue; }
            try { out.push({ match: new RegExp(e.match, 'i'), label: e.label, rules: e.rules }); } catch (err) { }
        }
        return out;
    };

    /**
     * @brief Resolve the license rules for one installed-software name: custom entries win, then the table.
     * @returns {object|null} { label, rules } or null.
     */
    obj.licenseRulesForApp = function (name) {
        var n = String(name || '');
        var custom = obj.compiledCustomLicense();
        for (var c = 0; c < custom.length; c++) { if (custom[c].match.test(n)) { return { label: custom[c].label, rules: custom[c].rules }; } }
        var table = obj.remoteLicenseEntries != null ? obj.remoteLicenseEntries : [];
        for (var i = 0; i < table.length; i++) { if (table[i].match.test(n)) { return { label: table[i].label, rules: table[i].rules }; } }
        return null;
    };

    obj.licenseTableStatus = function () {
        var lc = obj.licenseConfig();
        return {
            source: obj.remoteLicenseEntries != null ? 'remote' : 'none',
            origin: obj.remoteLicenseEntries != null ? (obj.licenseTableOrigin || 'cache') : '',
            updated: obj.licenseTableLoadedAt || '', url: lc.tableUrl, tableEnabled: lc.tableEnabled,
            entries: obj.remoteLicenseEntries != null ? obj.remoteLicenseEntries.length : 0,
            custom: obj.customLicenseEntries.length
        };
    };

    /**
     * @brief The license config (inventoryScanner section). Opt-in: collection is OFF by default.
     * Since v5.2.0 it can ALSO run on a schedule - but only when the master switch is on AND
     * collectIntervalHours > 0 (default 0 = on demand only, exactly as before).
     */
    obj.licenseConfig = function () {
        var cfg = null; try { cfg = obj.effectiveSectionConfig('inventoryScanner'); } catch (e) { }
        var out = { collectEnabled: false, msKeys: true, tableEnabled: true, tableUrl: obj.LICENSE_TABLE_DEFAULT_URL, collectIntervalHours: 0 };
        if (cfg && typeof cfg === 'object') {
            if (typeof cfg.licenseCollectionEnabled === 'boolean') { out.collectEnabled = cfg.licenseCollectionEnabled; }
            if (typeof cfg.licenseMsKeys === 'boolean') { out.msKeys = cfg.licenseMsKeys; }
            if (typeof cfg.licenseTableEnabled === 'boolean') { out.tableEnabled = cfg.licenseTableEnabled; }
            if (typeof cfg.licenseTableUrl === 'string' && cfg.licenseTableUrl.length > 0) { out.tableUrl = cfg.licenseTableUrl; }
            if (typeof cfg.licenseCollectIntervalHours === 'number' && cfg.licenseCollectIntervalHours >= 0) { out.collectIntervalHours = cfg.licenseCollectIntervalHours; }
        }
        return out;
    };

    /** @brief Fetch + cache the remote license table (https, size-capped). Test-overridable indirection. */
    obj.fetchLicenseTable = function (cb) {
        var lc = obj.licenseConfig();
        if (!/^https:\/\//i.test(lc.tableUrl)) { if (cb) cb(new Error('License table URL must be https')); return; }
        obj.licenseHttpGet(lc.tableUrl, function (err, text) {
            if (err) { if (cb) cb(err); return; }
            var r = obj.applyLicenseTableText(text);
            if (!r.ok) { if (cb) cb(new Error('License table rejected: ' + r.error)); return; }
            obj.licenseTableOrigin = 'downloaded';
            try { fs.mkdirSync(path.dirname(obj.licenseCachePath), { recursive: true }); fs.writeFileSync(obj.licenseCachePath, text); } catch (ex) { }
            if (cb) cb(null, r);
        });
    };
    obj.licenseHttpGet = function (url, cb) {
        var getIt = function (u, left) {
            var req = https.get(u, { headers: { 'User-Agent': 'meshcentral-inventoryscanner' }, timeout: 30000 }, function (res) {
                if ((res.statusCode >= 300) && (res.statusCode < 400) && res.headers.location && left > 0) {
                    res.resume(); var nu = null;
                    try { nu = new URL(String(res.headers.location), u).href; } catch (e) { cb(new Error('Invalid redirect')); return; }
                    if (!/^https:\/\//i.test(nu)) { cb(new Error('Redirect away from https blocked')); return; }
                    getIt(nu, left - 1); return;
                }
                if (res.statusCode !== 200) { res.resume(); cb(new Error('HTTP ' + res.statusCode)); return; }
                var size = 0, parts = [];
                res.on('data', function (ch) { size += ch.length; if (size > obj.LICENSE_TABLE_MAX_BYTES) { req.destroy(new Error('License table too large')); return; } parts.push(ch); });
                res.on('end', function () { cb(null, Buffer.concat(parts).toString('utf8')); });
            });
            req.on('error', function (e) { cb(e); });
            req.on('timeout', function () { req.destroy(new Error('License table fetch timeout')); });
        };
        getIt(url, 3);
    };

    /** @brief Refresh the remote license table if enabled and due (same NVD updateHours cycle as CPE). */
    obj.maybeFetchLicenseTable = function (cb) {
        var lc = obj.licenseConfig();
        if (!lc.tableEnabled) { if (cb) cb(null, { skipped: 'disabled' }); return; }
        var uh = 24 * 7;
        try { var ec = obj.effectiveSectionConfig('vulnerabilityScanner'); if (ec && (typeof ec.updateHours === 'number') && (ec.updateHours >= 1)) { uh = ec.updateHours; } } catch (ex) { }
        if (obj.remoteLicenseEntries != null) {
            var age = (obj.licenseTableLoadedAt != null) ? (Date.now() - Date.parse(obj.licenseTableLoadedAt)) : 0;
            if (age < uh * 3600 * 1000) { if (cb) cb(null, { skipped: 'fresh' }); return; }
        }
        obj.fetchLicenseTable(function (err, r) { if (err) { obj.licenseLog('table update failed (keeping current table): ' + err.message); } if (cb) cb(err, r); });
    };

    // ---- collected per-node storage (mirrors the software inventory files) ----

    obj.loadLicenseInventory = function () {
        obj.licenseInventory = {};
        try {
            if (!fs.existsSync(obj.inventoryDataPath)) return;
            var dirs = fs.readdirSync(obj.inventoryDataPath, { withFileTypes: true });
            for (var i = 0; i < dirs.length; i++) {
                if (!dirs[i].isDirectory()) continue;
                try {
                    var lf = path.join(obj.inventoryDataPath, dirs[i].name, 'license.json');
                    if (fs.existsSync(lf)) { var d = JSON.parse(fs.readFileSync(lf, 'utf8')); if (d && typeof d === 'object') { obj.licenseInventory[dirs[i].name] = d; } }
                } catch (e) { }
            }
        } catch (e) { }
    };
    obj.saveLicenseForNode = function (nodeid, entry) {
        try { var dir = path.join(obj.inventoryDataPath, obj.safeNodeDir(nodeid)); fs.mkdirSync(dir, { recursive: true }); fs.writeFileSync(path.join(dir, 'license.json'), JSON.stringify(entry, null, 2)); }
        catch (e) { obj.licenseLog(nodeid + ' - could not save: ' + e.message); }
    };
    /**
     * @brief name(lower) -> { license, source } map for one node's collected items.
     * v5.5.0 (issue #10): the FIRST successful read wins. Before this the LAST item per name always overwrote,
     * so a later failing rule could mask a value an earlier rule had found. A collected user name is part of the
     * source string ("registry (user: alice)") so the CSV shows where the value came from; the values themselves
     * stay on this server as before.
     */
    obj.licenseMapForNode = function (nodeid) {
        var m = {}; var e = obj.licenseInventory[obj.safeNodeDir(nodeid)];
        if (e && Array.isArray(e.items)) {
            for (var i = 0; i < e.items.length; i++) {
                var it = e.items[i];
                if (!it || !it.name) { continue; }
                var low = String(it.name).toLowerCase();
                var src = String(it.source || '');
                if (it.user) { src += ' (user: ' + String(it.user) + ')'; }
                var lic = String(it.license || '');
                var cur = m[low];
                if (it.ok === true && lic !== '') {
                    if (!cur || cur.license === '') { m[low] = { license: lic, source: src }; }
                } else if (!cur) {
                    m[low] = { license: lic, source: src };
                }
            }
        }
        return m;
    };

    /** @brief Append a line to the license collection log (rotated ~5 MB). */
    obj.licenseLog = function (line) {
        try {
            var dir = path.dirname(obj.licenseLogPath);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            try { if (fs.existsSync(obj.licenseLogPath) && (fs.statSync(obj.licenseLogPath).size > 5 * 1024 * 1024)) { fs.renameSync(obj.licenseLogPath, obj.licenseLogPath + '.old'); } } catch (e) { }
            fs.appendFileSync(obj.licenseLogPath, new Date().toISOString() + ' ' + line + String.fromCharCode(10));
        } catch (e) { }
    };

    /**
     * @brief The rule list to run on a node: for each installed program that has rules, { label, name, rules }.
     * @param {Array<object>} rows - the RAW inventory rows from obj.fetchNodeSoftware (v5.1.0: the same source
     *   the CSV/reports/push use, so a program listed in the CSV is also a program a license rule can match).
     */
    obj.licenseAppRules = function (rows) {
        var apps = Array.isArray(rows) ? rows : [];
        var out = [], seen = {};
        for (var i = 0; i < apps.length && out.length < obj.LIC_MAX_APPS; i++) {
            var a = apps[i]; if (!a) continue;
            var name = a.name || a.displayName || a.DisplayName || a.Name || '';
            if (!name) continue;
            var low = String(name).toLowerCase(); if (seen[low]) continue;
            var e = obj.licenseRulesForApp(name);
            if (e != null) { seen[low] = true; out.push({ label: e.label, name: name, rules: e.rules }); }
        }
        return out;
    };

    /**
     * @brief Build the read-only license extraction PowerShell. The per-app rules travel as one base64 JSON
     * blob and are used only as registry paths / file reads / CIM properties, never as code.
     *
     * Since v5.5.0 (issue #10) the script additionally understands, per rule:
     *  - `perUser` on registry rules: the HKCU path is applied to every ALREADY-LOADED user hive
     *    (`Registry::HKEY_USERS\<SID>\...`); offline hives are NEVER loaded (`reg load` would be a system
     *    modification - the read-only guarantee stands, and the issue rules it out explicitly);
     *  - `perUser` + `{{profile}}` on file rules: the placeholder becomes each existing profile directory;
     *  - one `*` wildcard: a registry subkey segment (enumerated, at most 20 matches, first non-empty value
     *    wins - the VMware `License.ws.*` case) or a file leaf pattern (at most 5 candidate files).
     * Users are discovered read-only from ProfileList (SID + profile dir), capped at LIC_MAX_USERS, and only
     * those with a loaded hive (registry rules) or an existing profile dir (file rules) take part. Every item
     * of the answer carries the `user` it came from.
     * @param {Array<object>} appRules - obj.licenseAppRules output.
     * @param {boolean} msKeys - also read Microsoft SoftwareLicensingProduct partial keys.
     * @returns {string}
     */
    obj.licenseBuildScript = function (appRules, msKeys) {
        var blob = obj.rbB64 ? obj.rbB64(JSON.stringify({ apps: appRules, ms: msKeys === true })) : Buffer.from(JSON.stringify({ apps: appRules, ms: msKeys === true }), 'utf8').toString('base64');
        return [
            "$ProgressPreference = 'SilentlyContinue'",
            "$ErrorActionPreference = 'SilentlyContinue'",
            "$invLic = @{ collect = $true; items = @(); ms = @(); error = '' }",
            "$invR = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + blob + "')) | ConvertFrom-Json",
            // read-only user discovery: SIDs + profile dirs from ProfileList, loaded hives / existing dirs only
            "$invUsers = @()",
            "try { foreach ($invPl in (Get-ChildItem -LiteralPath 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList' -ErrorAction Stop)) { if ($invUsers.Count -ge " + obj.LIC_MAX_USERS + ") { break }; $invSid = [string]$invPl.PSChildName; $invPip = [string](Get-ItemProperty -LiteralPath $invPl.PSPath -ErrorAction Stop).ProfileImagePath; if ($invPip.Contains('%')) { $invPip = [Environment]::ExpandEnvironmentStrings($invPip) }; $invLoaded = Test-Path ('Registry::HKEY_USERS\\' + $invSid); $invDirOk = Test-Path -LiteralPath $invPip -PathType Container; if ($invPip -and ($invLoaded -or $invDirOk)) { $invUsers += @{ sid = $invSid; name = [string](Split-Path -Leaf $invPip); profile = $invPip; loaded = $invLoaded } } } } catch { }",
            "if ($invR.ms) { try { foreach ($invP in (Get-CimInstance -ClassName SoftwareLicensingProduct -Filter 'PartialProductKey IS NOT NULL')) { $invLic.ms += @{ name = [string]$invP.Description; key = [string]$invP.PartialProductKey } } } catch { } }",
            // single-line read helpers: registry value at one path; file content via regex/jsonfield/line/raw
            "function invRegVal($p, $v) { $x = $null; try { $x = (Get-Item -LiteralPath $p -ErrorAction Stop).GetValue($v) } catch { }; if ($x -eq $null) { return $null }; return [string]$x }",
            "function invFileVal($p, $rx, $jf, $ln) { $c = Get-Content -LiteralPath $p -Raw -ErrorAction Stop; $v = [string]$c; if ($rx) { $m = [regex]::Match($c, $rx); if ($m.Success -eq $false) { return $null }; if ($m.Groups.Count -gt 1 -and $m.Groups[1].Value) { $v = $m.Groups[1].Value } else { $v = $m.Value } } elseif ($jf) { try { $v = [string](($c | ConvertFrom-Json).$jf) } catch { return $null } } elseif ($ln -gt 0) { $v = [string](($c -split \"`n\")[[int]$ln - 1]) }; $v = ($v -replace '[\\r\\n\\t]', ' ').Trim(); if ($v.Length -gt 512) { $v = $v.Substring(0, 512) }; if ($v.Length -eq 0) { return $null }; return $v }",
            // the per-rule loop: targets = one machine path, or one entry per user; wildcard = subkey/leaf scan
            "foreach ($invA in $invR.apps) { foreach ($invRule in $invA.rules) { $invVal = ''; $invSrc = [string]$invRule.type; $invOK = $false; $invUser = ''; try { if ($invRule.type -eq 'registry') { $invTg = @(); if ($invRule.perUser -eq $true) { foreach ($invU in $invUsers) { if ($invU.loaded -eq $true) { $invTg += @{ p = ('Registry::HKEY_USERS\\' + $invU.sid + '\\' + ([string]$invRule.path -replace '^HKCU:\\\\', '')); u = $invU.name } } } } else { $invTg += @{ p = [string]$invRule.path; u = '' } }; foreach ($invT in $invTg) { if ($invOK) { break }; $invP2 = [string]$invT.p; if ($invP2.Contains('*')) { $invSg = $invP2.Split('\\'); $invPre = ''; $invPat = ''; $invRest = ''; $invHit = 0; foreach ($invS in $invSg) { if ($invHit -eq 0 -and $invS.Contains('*')) { $invPat = $invS; $invHit = 1 } elseif ($invHit -eq 0) { if ($invPre) { $invPre = $invPre + '\\' + $invS } else { $invPre = $invS } } else { if ($invRest) { $invRest = $invRest + '\\' + $invS } else { $invRest = $invS } } }; $invKn = 0; foreach ($invK in (Get-ChildItem -Path ($invPre + '\\' + $invPat) -ErrorAction SilentlyContinue)) { if ($invOK -or $invKn -ge 20) { break }; $invKn = $invKn + 1; $invKp = [string]$invK.PSPath; if ($invRest) { $invKp = $invKp + '\\' + $invRest }; $invX = invRegVal $invKp $invRule.value; if ($invX) { $invVal = $invX; $invUser = [string]$invT.u; $invOK = $true } } } else { $invX = invRegVal $invP2 $invRule.value; if ($invX) { $invVal = $invX; $invUser = [string]$invT.u; $invOK = $true } } } } elseif ($invRule.type -eq 'file') { $invTg = @(); if ($invRule.perUser -eq $true) { foreach ($invU in $invUsers) { if ($invU.profile) { $invTg += @{ p = ([string]$invRule.path -replace '\\{\\{profile\\}\\}', $invU.profile); u = $invU.name } } } } else { $invTg += @{ p = [string]$invRule.path; u = '' } }; foreach ($invT in $invTg) { if ($invOK) { break }; $invP2 = [string]$invT.p; if ($invP2.Contains('*')) { $invKn = 0; foreach ($invF in (Get-ChildItem -Path $invP2 -File -ErrorAction SilentlyContinue)) { if ($invOK -or $invKn -ge 5) { break }; $invKn = $invKn + 1; $invX = invFileVal $invF.FullName $invRule.regex $invRule.jsonfield $invRule.line; if ($invX) { $invVal = $invX; $invUser = [string]$invT.u; $invOK = $true } } } else { if (Test-Path -LiteralPath $invP2) { $invX = invFileVal $invP2 $invRule.regex $invRule.jsonfield $invRule.line; if ($invX) { $invVal = $invX; $invUser = [string]$invT.u; $invOK = $true } } } } } elseif ($invRule.type -eq 'wmi') { $invQ = $null; if ($invRule.filter) { $invQ = Get-CimInstance -ClassName $invRule.class -Filter $invRule.filter -ErrorAction Stop } else { $invQ = Get-CimInstance -ClassName $invRule.class -ErrorAction Stop }; foreach ($invO in $invQ) { $invX = [string]$invO.($invRule.property); if ($invX) { $invVal = $invX; break } }; $invOK = ($invVal.Length -gt 0) } } catch { }; $invLic.items += @{ name = $invA.name; label = $invA.label; source = $invSrc; license = $invVal; ok = $invOK; user = $invUser } } }",
            "$invLic | ConvertTo-Json -Compress -Depth 6 | ForEach-Object { Write-Output ('" + obj.LIC_MARKER + "' + $_) }"
        ].join(String.fromCharCode(10));
    };

    /**
     * @brief Send the license extraction to a single online, idle Windows node.
     * @returns {object} { started } | { busy } | { error }
     */
    obj.licDispatch = function (nodeid, script) {
        try {
            var ws = obj.meshServer.webserver;
            if (!obj.routeHookInstalled) { try { obj.installRouteHook(); } catch (e) { } }
            var agent = (ws != null && ws.wsagents != null) ? ws.wsagents[nodeid] : null;
            if ((agent == null) || (typeof agent.send !== 'function')) return { error: 'offline' };
            if ((obj.licPending[nodeid] != null) || (obj.rbPending != null && obj.rbPending[nodeid] != null) ||
                (obj.wuPending != null && obj.wuPending[nodeid] != null) || (obj.devPending != null && obj.devPending[nodeid] != null) ||
                (obj.wgPending != null && obj.wgPending[nodeid] != null) || (obj.osPending != null && obj.osPending[nodeid] != null) ||
                (obj.swPending != null && obj.swPending[nodeid] != null)) { return { busy: true }; }
            var sid = obj.LIC_SESSION_PREFIX + obj.safeNodeDir(nodeid);
            var entry = { nodeid: nodeid, sid: sid, since: Date.now() };
            entry.timer = setTimeout(function () { obj.licTimeout(entry); }, obj.LIC_TIMEOUT_MS);
            obj.licPending[nodeid] = entry;
            try { agent.send(JSON.stringify({ action: 'runcommands', type: 1, cmds: obj.wgTransport(script), runAsUser: 0, reply: true, sessionid: sid, responseid: sid })); }
            catch (ex) { clearTimeout(entry.timer); delete obj.licPending[nodeid]; return { error: 'send-failed: ' + ex.message }; }
            return { started: true, sid: sid };
        } catch (e) { return { error: e.message }; }
    };

    /** @brief True when a node currently has a license collection in flight. */
    obj.licIsBusy = function (nodeid) { return (nodeid != null) && (obj.licPending != null) && (obj.licPending[nodeid] != null); };

    /** @brief Answer of a license collection session (consumed by lib/collector.js). */
    obj.licHandleResponse = function (nodeid, command) {
        var entry = obj.licPending[nodeid];
        if (entry == null) return;
        if (entry.timer) { clearTimeout(entry.timer); }
        delete obj.licPending[nodeid];
        var text = (typeof command.result === 'string') ? command.result : JSON.stringify(command.result || '');
        var data = obj.wgPayloadFromText(text, obj.LIC_MARKER);
        if ((data == null) && (typeof entry.cbuf === 'string')) { data = obj.wgPayloadFromText(entry.cbuf, obj.LIC_MARKER); }
        var s = function (v, n) { return String(v == null ? '' : v).substring(0, n); };
        var rec = { time: new Date().toISOString() };
        if (data == null) { rec.error = (text.indexOf(obj.LIC_MARKER) >= 0) ? 'unparsable' : 'no-marker'; rec.items = []; rec.ms = []; }
        else {
            rec.items = Array.isArray(data.items) ? data.items.slice(0, 500).map(function (x) { return { name: s(x && x.name, 200), label: s(x && x.label, 120), source: s(x && x.source, 20), license: s(x && x.license, 600), ok: (x && x.ok) === true, user: s(x && x.user, 100) }; }) : [];
            rec.ms = Array.isArray(data.ms) ? data.ms.slice(0, 40).map(function (x) { return { name: s(x && x.name, 200), key: s(x && x.key, 100) }; }) : [];
            if (data.error) { rec.error = s(data.error, 200); }
        }
        var found = rec.items.filter(function (x) { return x.ok; }).length;
        obj.licenseInventory[obj.safeNodeDir(nodeid)] = rec;
        obj.saveLicenseForNode(nodeid, rec);
        obj.licenseLog(nodeid + ' - collected: ' + found + '/' + rec.items.length + ' app license value(s), ' + rec.ms.length + ' MS key(s)' + (rec.error ? (' error=' + rec.error) : ''));
        obj.wgRaiseNodeEvent(nodeid, 'License collection: ' + found + ' software license value(s) and ' + rec.ms.length + ' Microsoft key(s) read (stored on this server only).');
    };

    /** @brief Watchdog for a license session that never answered. */
    obj.licTimeout = function (entry) {
        if ((entry == null) || (obj.licPending[entry.nodeid] !== entry)) return;
        delete obj.licPending[entry.nodeid];
        var rec = { time: new Date().toISOString(), items: [], ms: [], error: 'timeout' };
        obj.licenseInventory[obj.safeNodeDir(entry.nodeid)] = rec; obj.saveLicenseForNode(entry.nodeid, rec);
        obj.licenseLog(entry.nodeid + ' - no answer within the timeout');
    };

    /** @brief POST lic_status: Windows devices with their collected license summary + pending. */
    obj.licStatusHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        try {
            var lc = obj.licenseConfig();
            obj.db.GetAllType('mesh', function (merr, meshes) {
                var meshNames = {};
                if (!merr && meshes) { for (var mi = 0; mi < meshes.length; mi++) { var mm = meshes[mi]; if (mm && mm._id && mm.deleted == null) meshNames[mm._id] = mm.name || mm._id; } }
                obj.db.GetAllType('node', function (nerr, nodes) {
                    var ws = obj.meshServer.webserver, devices = [];
                    if (!nerr && nodes) {
                        for (var i = 0; i < nodes.length && devices.length < 2000; i++) {
                            var n = nodes[i];
                            if ((n == null) || (n._id == null) || (n.deleted != null)) continue;
                            if (!/windows/i.test(String(n.osdesc || ''))) continue;
                            var e = obj.licenseInventory[obj.safeNodeDir(n._id)];
                            var found = e && Array.isArray(e.items) ? e.items.filter(function (x) { return x.ok; }).length : 0;
                            devices.push({
                                id: n._id, host: obj.getHostName(n), given: (typeof n.name === 'string') ? n.name.trim() : '',
                                group: meshNames[n.meshid] || n.meshid || '', os: String(n.osdesc || '').substring(0, 120),
                                online: (ws != null && ws.wsagents != null && ws.wsagents[n._id] != null),
                                collected: e ? { time: e.time, found: found, ms: (e.ms || []).length, apps: (e.items || []).length, error: e.error || '' } : null,
                                pending: obj.licPending[n._id] ? { since: obj.licPending[n._id].since } : null
                            });
                        }
                    }
                    devices.sort(function (a, b) { return (a.group === b.group) ? String(a.given || a.host).localeCompare(String(b.given || b.host)) : String(a.group).localeCompare(String(b.group)); });
                    send({ devices: devices, enabled: lc.collectEnabled, running: (function () { for (var k in obj.licPending) { if (obj.licPending[k] != null) return true; } return false; })() });
                });
            });
        } catch (ex) { send({ error: ex.message }); }
    };

    /**
     * @brief One pass over all ONLINE Windows devices: build each device's read-only license script from the
     * canonical software rows (obj.fetchNodeSoftware) and dispatch it. Devices that already hold a
     * runcommands session are skipped, so the one-session-per-agent rule holds. Used by BOTH the
     * "collect all" route and the optional scheduler - one implementation, no copy (v5.2.0).
     * @param {string} by - who/what triggered the run (for the log; never a secret).
     * @param {function} cb - <code>(err, {candidates, started})</code>.
     */
    obj.licSweepOnce = function (by, cb) {
        var lc = obj.licenseConfig();
        var ws = obj.meshServer.webserver;
        obj.db.GetAllType('node', function (nerr, nodes) {
            if (nerr) { if (cb) cb(nerr); return; }
            var cands = [];
            if (nodes && ws && ws.wsagents) {
                for (var i = 0; i < nodes.length; i++) {
                    var n = nodes[i];
                    if ((n == null) || (n._id == null) || (n.deleted != null)) continue;
                    if (!/windows/i.test(String(n.osdesc || ''))) continue;   // license extraction is Windows-only
                    if (ws.wsagents[n._id] == null) continue;                  // offline devices keep their last result
                    if (obj.licPending[n._id] != null) continue;               // a collection is already in flight
                    cands.push(n);
                }
            }
            var started = 0;
            var finish = function () {
                obj.licenseLog('license collect (all online Windows) started on ' + started + ' of ' + cands.length + ' device(s) by ' + by);
                if (cb) cb(null, { candidates: cands.length, started: started });
            };
            if (cands.length === 0) { return finish(); }
            obj.pacedEach(cands, function (n, candDone) {
                obj.fetchNodeSoftware(n, function (ferr, got) {
                    if (!ferr && got) {
                        var script = obj.licenseBuildScript(obj.licenseAppRules(got.rows), lc.msKeys);
                        var r = obj.licDispatch(n._id, script);
                        if (r.started) started++;
                    }
                    candDone();
                });
            }, finish, 8);
        });
    };

    /**
     * @brief The OPTIONAL license collection schedule (v5.2.0). Runs only when the master switch is on AND
     * licenseCollectIntervalHours > 0 (default 0 = on demand only, the behaviour before v5.2.0). The run
     * itself is unchanged: a read-only script per online Windows device, values stored on this server,
     * never logged, never sent anywhere by this feature.
     */
    obj.scheduleLicenseCollection = function () {
        var lc = obj.licenseConfig();
        if (!lc.collectEnabled || !(lc.collectIntervalHours > 0)) { return; }
        var gen = obj.timerGen;
        obj.longTimeout(function () {
            if (!obj.timerValid(gen)) { return; }
            obj.licSweepOnce('the schedule (every ' + lc.collectIntervalHours + 'h)', function () {
                if (!obj.timerValid(gen)) { return; }
                obj.scheduleLicenseCollection();
            });
        }, lc.collectIntervalHours * 3600 * 1000);
    };

    /** @brief POST lic_collect: collect licenses on one device (nodeId) or all online Windows (all=true). */
    obj.licCollectHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        var body = req.body || {};
        var lc = obj.licenseConfig();
        if (!lc.collectEnabled) { return send({ error: 'License collection is switched off (Settings tab -> License keys).' }); }
        if (body.nodeId != null && String(body.nodeId) !== '') {
            var nodeid = String(body.nodeId);
            if (!/^node\/[^:]{1,100}$/.test(nodeid)) { return send({ error: 'Invalid node id.' }); }
            obj.db.Get(nodeid, function (err, docs) {
                if (err || !docs || !docs.length || docs[0] == null || docs[0].deleted != null) { return send({ error: 'Unknown device.' }); }
                if (!/windows/i.test(String(docs[0].osdesc || ''))) { return send({ error: 'License keys are read on Windows devices.' }); }
                // v5.1.0: the canonical software source (sysinfo doc included), so the rules match exactly
                // the programs the CSV and the reports list for this device.
                obj.fetchNodeSoftware(docs[0], function (ferr, got) {
                    if (ferr) { return send({ error: ferr.message }); }
                    var script = obj.licenseBuildScript(obj.licenseAppRules(got.rows), lc.msKeys);
                    var r = obj.licDispatch(nodeid, script);
                    if (r.error) { return send({ error: r.error === 'offline' ? 'The device is offline.' : r.error }); }
                    if (r.busy) { return send({ error: 'Another task is running on this device - try again later.' }); }
                    obj.licenseLog(nodeid + ' - license collect dispatched by ' + ((user && user.name) || '?'));
                    send({ started: true });
                });
            });
            return;
        }
        // all online Windows devices - the SAME sweep the optional scheduler runs (one implementation)
        obj.licSweepOnce(((user && user.name) || '?'), function (serr, r) {
            if (serr) { return send({ error: serr.message }); }
            send({ started: true, devices: r.started });
        });
    };

    // ---- custom-rule routes (mirror the CPE table handlers) ----

    obj.getLicenseTableHandler = function (req, res, user) {
        var entries = [];
        var table = obj.remoteLicenseEntries != null ? obj.remoteLicenseEntries : [];
        for (var i = 0; i < table.length; i++) { entries.push({ match: table[i].match.source, label: table[i].label, rules: table[i].rules, source: 'table' }); }
        for (var c = 0; c < obj.customLicenseEntries.length; c++) { var e = obj.customLicenseEntries[c]; entries.push({ match: e.match, label: e.label, rules: e.rules, source: 'custom' }); }
        res.type('json'); res.json({ entries: entries, licenseTable: obj.licenseTableStatus() });
    };

    obj.addLicenseHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        var body = req.body || {};
        var match = String(body.match || '').trim();
        var label = String(body.label || '').trim().substring(0, 120);
        if (!match) { return send({ error: 'A match regex is required.' }); }
        if (!obj.isSafeTableRegex(match)) { return send({ error: 'Regex rejected (empty, >500 chars, nested quantifier or backreference).' }); }
        try { new RegExp(match, 'i'); } catch (e) { return send({ error: 'Invalid regex: ' + e.message }); }
        var rules;
        try { rules = JSON.parse(String(body.rules || '[]')); } catch (e) { return send({ error: 'Rules must be a JSON array: ' + e.message }); }
        // v5.5.0: the editor's per-user checkbox stamps perUser onto every registry/file rule of the payload,
        // so the admin does not have to hand-write it into each rule object.
        if (obj.boolSetting(body.perUser, false) && Array.isArray(rules)) {
            for (var ri = 0; ri < rules.length; ri++) {
                var rr = rules[ri];
                if (rr && typeof rr === 'object' && (rr.type === 'registry' || rr.type === 'file')) { rr.perUser = true; }
            }
        }
        var clean = obj.sanitizeLicenseRules(rules);
        if (clean == null) { return send({ error: 'Rules must be 1-8 entries of type registry(path+value), file(path[+regex|jsonfield|line]) or wmi(class+property[+filter]); perUser needs HKCU:/{{profile}}, and at most one * wildcard per path.' }); }
        obj.customLicenseEntries.push({ match: match, label: label || match, rules: clean });
        obj.saveCustomLicense(function (err) { if (err) { return send({ error: err.message }); } return send({ success: true, count: obj.customLicenseEntries.length }); });
    };

    obj.removeLicenseHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        var idx = parseInt(String((req.body || {}).index || ''), 10);
        if (isNaN(idx) || idx < 0 || idx >= obj.customLicenseEntries.length) { return send({ error: 'Invalid index.' }); }
        obj.customLicenseEntries.splice(idx, 1);
        obj.saveCustomLicense(function (err) { if (err) { return send({ error: err.message }); } return send({ success: true, count: obj.customLicenseEntries.length }); });
    };
};
