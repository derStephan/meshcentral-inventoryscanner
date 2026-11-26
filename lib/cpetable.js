/**
 * @file lib/cpetable.js
 * @brief Software name -> CPE mapping tables and their management: the maintained cpe-table.json (the file the installer ships and every refresh rewrites - the ONLY curated table, no code copy since v4.2.0) and the custom entries added under Vulnerabilities > CPE table, which always win.
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
    /** @type {string} Default URL of the repository-maintained CPE mapping table. */
    obj.CPE_TABLE_DEFAULT_URL = 'https://raw.githubusercontent.com/derStephan/meshcentral-inventoryscanner/main/cpe-table.json';

    /** @type {number} Hard cap for remote table payloads (2 MB). */
    obj.CPE_TABLE_MAX_BYTES = 2 * 1024 * 1024;

    /** @type {Array<object>|null} Compiled remote table ({ match: RegExp, vendor, product }) or null. */
    obj.remoteCpeEntries = null;

    /** @type {string|null} Timestamp (ISO) of the last successfully applied remote table. */
    obj.cpeTableLoadedAt = null;

    /** @type {string} Where the applied table came from: '' | 'downloaded' | 'cache' | 'bundled'. */
    obj.cpeTableOrigin = '';

    /** @type {Array<object>} User-customized CPE entries: <code>{ match, vendor, product, licenseType? }</code>.
     * Consulted BEFORE the maintained table so an admin can override or extend mappings. */
    obj.customCpeEntries = [];

    // ---- Custom CPE mapping (admin-editable) ----

    /**
     * @brief Load user-customized CPE mapping entries from disk into memory.
     * Each entry is <code>{ match: string, vendor: string, product: string, licenseType?: string }</code> where
     * <code>match</code> is a regex source (matched case-insensitively against the display name).
     */
    obj.loadCustomCpe = function () {
        obj.customCpeEntries = [];
        try {
            if (fs.existsSync(obj.customCpePath)) {
                var data = JSON.parse(fs.readFileSync(obj.customCpePath, 'utf8'));
                if (Array.isArray(data)) {
                    obj.customCpeEntries = data.filter(function (e) {
                        return e && typeof e.match === 'string' && e.vendor && e.product;
                    }).map(function (e) {
                        var out = { match: e.match, vendor: e.vendor, product: e.product };
                        var lt = obj.sanitizeLicenseType(e.licenseType);   // v5.6.0: optional annotation
                        if (lt !== '') { out.licenseType = lt; }
                        return out;
                    });
                }
            }
        } catch (err) {
            obj.debug('plugin:inventory_scanner', 'Error loading custom CPE entries:', err.message);
            obj.customCpeEntries = [];
        }
    };

    /**
     * @brief Persist the user-customized CPE mapping entries to disk.
     * @param {function} [callback] - Called with <code>null</code> on success or an Error.
     */
    obj.saveCustomCpe = function (callback) {
        try {
            var dir = path.dirname(obj.customCpePath);
            if (!fs.existsSync(dir)) { fs.mkdirSync(dir, { recursive: true }); }
            fs.writeFileSync(obj.customCpePath, JSON.stringify(obj.customCpeEntries, null, 2));
            if (callback) callback(null);
        } catch (err) {
            obj.debug('plugin:inventory_scanner', 'Error saving custom CPE entries:', err.message);
            if (callback) callback(err);
        }
    };

    /**
     * @brief Add a custom CPE mapping entry and persist it.
     * @param {string} match - Regex source matched case-insensitively against the display name.
     * @param {string} vendor - The CPE vendor.
     * @param {string} product - The CPE product.
     * @param {function} [callback] - Called with <code>(err)</code>.
     * @param {string} [licenseType] - Optional license annotation (v5.6.0); an unusable value is dropped.
     */
    obj.addCustomCpe = function (match, vendor, product, callback, licenseType) {
        if (!obj.isSafeTableRegex(match)) { if (callback) callback(new Error('Regex rejected (empty, longer than 500 characters, nested quantifier or backreference).')); return; }
        if ((typeof vendor !== 'string') || (typeof product !== 'string') || (vendor.length > 200) || (product.length > 200)) { if (callback) callback(new Error('Vendor/product too long.')); return; }
        try {
            // Validate that the regex is valid before storing.
            new RegExp(match, 'i');
        } catch (err) {
            if (callback) callback(new Error('Invalid regex: ' + err.message));
            return;
        }
        var entry = { match: match, vendor: vendor, product: product };
        var lt = obj.sanitizeLicenseType(licenseType);
        if (lt !== '') { entry.licenseType = lt; }
        obj.customCpeEntries.push(entry);
        obj.saveCustomCpe(callback);
    };

    /**
     * @brief Remove a custom CPE mapping entry by index and persist it.
     * @param {number} index - The index in <code>customCpeEntries</code>.
     * @param {function} [callback] - Called with <code>(err)</code>.
     */
    obj.removeCustomCpe = function (index, callback) {
        if ((typeof index !== 'number') || (index < 0) || (index >= obj.customCpeEntries.length)) {
            if (callback) callback(new Error('Invalid index'));
            return;
        }
        obj.customCpeEntries.splice(index, 1);
        obj.saveCustomCpe(callback);
    };

    /**
     * @brief Return the compiled custom CPE entries as regex objects.
     * @returns {Array<object>} Entries with <code>{ match: RegExp, vendor, product, licenseType? }</code>.
     */
    obj.compiledCustomCpe = function () {
        var out = [];
        for (var i = 0; i < obj.customCpeEntries.length; i++) {
            var e = obj.customCpeEntries[i];
            if (!obj.isSafeTableRegex(e.match)) { continue; }
            try {
                var row = { match: new RegExp(e.match, 'i'), vendor: e.vendor, product: e.product };
                var lt = obj.sanitizeLicenseType(e.licenseType);
                if (lt !== '') { row.licenseType = lt; }
                out.push(row);
            }
            catch (err) { }
        }
        return out;
    };

    // The curated mappings live ONLY in cpe-table.json (shipped with the plugin, refreshed from
    // its URL) - v4.2.0 removed the old built-in seed copy, so there is exactly one table to
    // maintain. It is applied by obj.applyCpeTableText and served by obj.activeSoftwareTable.

    /**
     * @brief Validate and apply a CPE table JSON payload (string or object).
     * Entry regexes compile with the i flag only (same semantics as the custom entries);
     * invalid entries are skipped, not fatal. Two entry shapes are accepted:
     * <code>{match, vendor, product}</code> (maps to a NVD CPE) or
     * <code>{match, kind}</code> with kind "driver"/"firmware" (declares the matched
     * software out-of-NVD-scope - it is reported as such and excluded from coverage).
     * Since v5.6.0 a CPE row may additionally carry <code>licenseType</code> - an SPDX identifier
     * or one of the three descriptors documented in cpe-table.json's <code>_licenseNote</code> and
     * CONTRIBUTING.md. It is optional, sanitized (obj.sanitizeLicenseType), never lowercased and
     * has no effect on CVE matching; kind rows carry none.
     * @param {string|object} payload - Raw JSON text or parsed object.
     * @returns {object} { ok: boolean, applied: number, skipped: number, error?: string }
     */
    /**
     * @brief Reject regex sources with the classic catastrophic-backtracking shape (a quantified
     * group that itself contains a quantifier, e.g. (a+)+ or (x*)*). Table and custom regexes run
     * against every installed program name on the server's event loop, so one such pattern from a
     * tampered table could stall the whole MeshCentral process (OWASP A08 / CWE-1333, v3.0.1).
     * Heuristic by design: it blocks the known-dangerous form, plain patterns stay accepted.
     * @param {string} src - Regex source.
     * @returns {boolean} true when acceptable.
     */
    obj.isSafeTableRegex = function (src) {
        var s = String(src || '');
        if (s.length === 0 || s.length > 500) { return false; }
        if (/\\[1-9]/.test(s) || /\\k</.test(s)) { return false; } // backreferences (numbered + named)
        // v5.5.1 (audit 4): a real scanner instead of one flat regex. The old check only saw a quantifier
        // DIRECTLY inside the quantified group, so '((a+))+$' (45 s on 29 characters, measured) and
        // '(a|a)+$' (72 s) passed and could stall the event loop for every scan. Rule now: a group that is
        // repeated by + * or {..} must not contain - at ANY depth - a quantifier (+ * ? {..}) or an
        // alternation (|). Optional groups '(x64)?' and top-level alternation stay allowed; the shipped
        // tables need nothing else (all entries re-checked by the test suite).
        var stack = [], i = 0, inClass = false;
        while (i < s.length) {
            var c = s.charAt(i);
            if (c === '\\') { i += 2; continue; }
            if (inClass) { if (c === ']') { inClass = false; } i++; continue; }
            if (c === '[') { inClass = true; i++; continue; }
            if (c === '(') {
                stack.push({ risky: false }); i++;
                if (s.charAt(i) === '?') {
                    i++;
                    if (s.charAt(i) === '<' && (s.charAt(i + 1) === '=' || s.charAt(i + 1) === '!')) { i += 2; }
                    else if (s.charAt(i) === '<') { while (i < s.length && s.charAt(i) !== '>') { i++; } i++; }
                    else { i++; }
                }
                continue;
            }
            if (c === ')') {
                var g = stack.pop() || { risky: false };
                i++;
                var q = s.charAt(i);
                var repeated = (q === '+' || q === '*' || q === '{');
                if (repeated && g.risky) { return false; }
                if (stack.length > 0 && (g.risky || repeated || q === '?')) { stack[stack.length - 1].risky = true; }
                continue;
            }
            if (c === '|' || c === '+' || c === '*' || c === '?' || c === '{') { if (stack.length > 0) { stack[stack.length - 1].risky = true; } }
            i++;
        }
        return true;
    };

    /**
     * @brief Normalize the optional <code>licenseType</code> annotation of a table row (v5.6.0).
     * The value is an SPDX license identifier or one of three documented descriptors
     * (Proprietary / Freeware / Freeware (non-commercial)); it is display/report data only, so it is
     * capped, charset-restricted and NEVER lowercased (SPDX ids are case-sensitive). An unusable
     * value yields '' and the row simply carries no license type - it is never fatal, and a missing
     * value is the honest answer (CONTRIBUTING.md: omit rather than guess).
     * @param {*} v - The raw field value from a table payload.
     * @returns {string} The clean value or ''.
     */
    obj.sanitizeLicenseType = function (v) {
        if (typeof v !== 'string') { return ''; }
        var s = v.trim().substring(0, 80);
        if ((s.length === 0) || !/^[A-Za-z0-9.+()\- ]+$/.test(s)) { return ''; }
        return s;
    };

    obj.applyCpeTableText = function (payload) {
        var data = null;
        try { data = (typeof payload === 'string') ? JSON.parse(payload) : payload; } catch (ex) { return { ok: false, applied: 0, skipped: 0, error: 'Invalid JSON: ' + ex.message }; }
        if (!data || !Array.isArray(data.entries)) { return { ok: false, applied: 0, skipped: 0, error: 'Missing entries array.' }; }
        if (data.entries.length > 20000) { return { ok: false, applied: 0, skipped: 0, error: 'Too many entries.' }; }
        var applied = 0, skipped = 0, out = [];
        for (var i = 0; i < data.entries.length; i++) {
            var en = data.entries[i];
            if (!en || (typeof en.match !== 'string') || (en.match.length === 0) || (en.match.length > 500)) { skipped++; continue; }
            if (!obj.isSafeTableRegex(en.match)) { skipped++; continue; }
            var isKind = (en.kind === 'driver' || en.kind === 'firmware');
            if (isKind) {
                // kind rows are exclusion markers without a product identity - no license annotation.
                try { out.push({ match: new RegExp(en.match, 'i'), kind: en.kind }); applied++; } catch (ex) { skipped++; }
                continue;
            }
            if ((typeof en.vendor !== 'string') || (typeof en.product !== 'string') ||
                (en.vendor.length === 0) || (en.vendor.length > 200) || (en.product.length > 200)) { skipped++; continue; }
            try {
                var row = { match: new RegExp(en.match, 'i'), vendor: en.vendor.toLowerCase(), product: en.product.toLowerCase() };
                var lt = obj.sanitizeLicenseType(en.licenseType);
                if (lt !== '') { row.licenseType = lt; }
                out.push(row); applied++;
            }
            catch (ex) { skipped++; }
        }
        if (applied === 0) { return { ok: false, applied: 0, skipped: skipped, error: 'No valid entries.' }; }
        obj.remoteCpeEntries = out;
        obj.cpeTableLoadedAt = new Date().toISOString();
        return { ok: true, applied: applied, skipped: skipped };
    };

    /**
     * @brief Load the CPE mapping table from disk (silent).
     * Priority: the downloaded cache under the datapath, then the copy shipped
     * INSIDE the plugin folder (the installer unpacks the repository
     * cpe-table.json beside inventoryscanner.js) - so the maintained table is
     * live even on a first start without network. Since v4.2.0 this file is the
     * ONLY curated table (the built-in seed copy in this code was removed);
     * if neither file loads, matching runs on custom entries + auto matcher only.
     */
    obj.loadRemoteCpeTable = function () {
        var tryFiles = [obj.cpeTablePath, path.join(obj.pluginDir, 'cpe-table.json')];
        for (var f = 0; f < tryFiles.length; f++) {
            try {
                if (!fs.existsSync(tryFiles[f])) continue;
                var r = obj.applyCpeTableText(fs.readFileSync(tryFiles[f], 'utf8'));
                if (r.ok) {
                    obj.cpeTableOrigin = (f === 0 ? 'cache' : 'bundled');
                    try { obj.cpeTableLoadedAt = new Date(fs.statSync(tryFiles[f]).mtimeMs).toISOString(); } catch (ex) { }
                    obj.debug('plugin:inventory_scanner', 'Loaded CPE table from', (f === 0 ? 'cache' : 'plugin folder:'), r.applied, 'entries');
                    return;
                }
                obj.debug('plugin:inventory_scanner', 'CPE table invalid in', (f === 0 ? 'cache' : 'plugin folder'), '-', r.error);
            } catch (ex) { obj.debug('plugin:inventory_scanner', 'CPE table read failed:', ex.message); }
        }
        obj.debug('plugin:inventory_scanner', 'WARNING: no cpe-table.json found (cache and plugin folder both empty/unreadable) - curated mappings unavailable until one loads, custom entries and the auto matcher still work.');
    };

    /**
     * @brief Fetch the remote CPE mapping table (https only, size-capped) and cache it.
     * The HTTP layer is a separate indirection (obj.cpeTableHttpGet) so tests run offline.
     * @param {function} callback - Called with (err, result).
     */
    obj.fetchCpeTable = function (callback) {
        var url = obj.scannerConfig().cpeTableUrl;
        if (!/^https:\/\//i.test(url)) { if (callback) callback(new Error('CPE table URL must be https')); return; }
        obj.cpeTableHttpGet(url, function (err, text) {
            if (err) { if (callback) callback(err); return; }
            var r = obj.applyCpeTableText(text);
            if (!r.ok) { if (callback) callback(new Error('CPE table rejected: ' + r.error)); return; }
            obj.cpeTableOrigin = 'downloaded';
            try {
                fs.mkdirSync(path.dirname(obj.cpeTablePath), { recursive: true });
                fs.writeFileSync(obj.cpeTablePath, text);
            } catch (ex) { obj.debug('plugin:inventory_scanner', 'Could not cache CPE table:', ex.message); }
            if (callback) callback(null, r);
        });
    };

    /** @brief HTTP GET text with size cap and redirects (overridable indirection for tests).
     *  @param {number} [maxBytes] - payload cap, default CPE_TABLE_MAX_BYTES (the lifecycle fetch passes its own). */
    obj.cpeTableHttpGet = function (url, callback, maxBytes) {
        var cap = (typeof maxBytes === 'number' && maxBytes > 0) ? maxBytes : obj.CPE_TABLE_MAX_BYTES;
        var answered = false;
        var cbOnce = function (e, t) { if (answered) { return; } answered = true; callback(e, t); };
        var getIt = function (u, redirectsLeft) {
            var req = https.get(u, { headers: { 'User-Agent': 'meshcentral-inventoryscanner' }, timeout: 30000 }, function (res) {
                if (((res.statusCode == null) || (res.statusCode >= 300) && (res.statusCode < 400)) && res.headers.location && (redirectsLeft > 0)) {
                    res.resume();
                    var nu = null;
                    try { nu = new URL(String(res.headers.location), u).href; } catch (e) { cbOnce(new Error('Invalid redirect')); return; } // RFC 3986 resolution (v3.0.1)
                    if (!/^https:\/\//i.test(nu)) { cbOnce(new Error('Redirect away from https blocked')); return; }
                    getIt(nu, redirectsLeft - 1);
                    return;
                }
                if (res.statusCode !== 200) { res.resume(); cbOnce(new Error('HTTP ' + res.statusCode)); return; }
                var size = 0, parts = [];
                res.on('data', function (chunk) {
                    size += chunk.length;
                    if (size > cap) { req.destroy(new Error('payload too large (cap ' + cap + ' bytes)')); return; }
                    parts.push(chunk);
                });
                // v5.5.1: a destroyed request emits 'error' and may still emit 'end' - answer exactly once
                res.on('end', function () { if (size <= cap) { cbOnce(null, Buffer.concat(parts).toString('utf8')); } });
            });
            req.on('error', function (err) { cbOnce(err); });
            req.on('timeout', function () { req.destroy(new Error('fetch timeout')); });
        };
        getIt(url, 3);
    };

    /** @brief Refresh the remote table if enabled and due (age > NVD updateHours cycle). */
    obj.maybeFetchCpeTable = function (callback) {
        var scfg = obj.scannerConfig();
        if (!scfg.cpeTableEnabled) { if (callback) callback(null, { skipped: 'disabled' }); return; }
        var uh = 24 * 7;
        try { var ec = obj.effectiveSectionConfig('vulnerabilityScanner'); if (ec && (typeof ec.updateHours === 'number') && (ec.updateHours >= 1)) { uh = ec.updateHours; } } catch (ex) { }
        var ageLimit = uh * 3600 * 1000;
        if (obj.remoteCpeEntries != null) {
            var age = (obj.cpeTableLoadedAt != null) ? (Date.now() - Date.parse(obj.cpeTableLoadedAt)) : 0;
            if (age < ageLimit) { if (callback) callback(null, { skipped: 'fresh' }); return; }
        }
        obj.fetchCpeTable(function (err, r) {
            if (err) { obj.debug('plugin:inventory_scanner', 'CPE table update failed (keeping current table):', err.message); }
            if (callback) callback(err, r);
        });
    };

    /** @brief The software table in force: the maintained cpe-table.json when loaded, else empty (custom + auto matcher only). */
    obj.activeSoftwareTable = function () { return (obj.remoteCpeEntries != null) ? obj.remoteCpeEntries : []; };

    /** @brief Status info about the active CPE table for the UI. */
    obj.cpeTableStatus = function () {
        var scfg = obj.scannerConfig();
        return {
            source: (obj.remoteCpeEntries != null) ? 'remote' : 'none',
            origin: (obj.remoteCpeEntries != null) ? (obj.cpeTableOrigin || 'cache') : '',
            updated: obj.cpeTableLoadedAt || '',
            url: scfg.cpeTableUrl,
            enabled: scfg.cpeTableEnabled,
            entries: (obj.remoteCpeEntries != null) ? obj.remoteCpeEntries.length : 0
        };
    };

    /**
     * @brief Return the current custom CPE mapping entries as JSON for the admin UI.
     * @param {object} req - The Express request.
     * @param {object} res - The Express response.
     * @param {object} user - The authenticated user.
     */
    obj.showCustomCpe = function (req, res, user) {
        res.type('json');
        res.json({ entries: obj.customCpeEntries.map(function (e, i) { return { index: i, match: e.match, vendor: e.vendor, product: e.product, licenseType: (e.licenseType || '') }; }) });
    };

    /**
     * @brief Add a custom CPE mapping entry from the admin UI.
     * Validates and persists; returns the updated entry list.
     * @param {object} req - The Express request (urlencoded <code>match, vendor, product</code>, optional <code>licenseType</code>).
     * @param {object} res - The Express response.
     * @param {object} user - The authenticated user.
     */
    obj.addCpeHandler = function (req, res, user) {
        var match = String(req.body.match || '').trim();
        var vendor = String(req.body.vendor || '').trim().toLowerCase();
        var product = String(req.body.product || '').trim().toLowerCase();
        var licenseType = String(req.body.licenseType || '').trim();
        if (!match || !vendor || !product) {
            res.type('json'); res.json({ error: 'Regex, vendor and product are required.' }); return;
        }
        obj.addCustomCpe(match, vendor, product, function (err) {
            if (err) { res.type('json'); res.json({ error: err.message }); return; }
            res.type('json');
            res.json({ success: true, entries: obj.customCpeEntries.map(function (e, i) { return { index: i, match: e.match, vendor: e.vendor, product: e.product, licenseType: (e.licenseType || '') }; }) });
        }, licenseType);
    };

    /**
     * @brief Remove a custom CPE mapping entry from the admin UI.
     * @param {object} req - The Express request (urlencoded <code>index</code>).
     * @param {object} res - The Express response.
     * @param {object} user - The authenticated user.
     */
    obj.removeCpeHandler = function (req, res, user) {
        var index = parseInt(String(req.body.index || ''), 10);
        if (isNaN(index)) { res.type('json'); res.json({ error: 'Invalid index.' }); return; }
        obj.removeCustomCpe(index, function (err) {
            if (err) { res.type('json'); res.json({ error: err.message }); return; }
            res.type('json');
            res.json({ success: true, entries: obj.customCpeEntries.map(function (e, i) { return { index: i, match: e.match, vendor: e.vendor, product: e.product, licenseType: (e.licenseType || '') }; }) });
        });
    };

    /**
     * @brief Return the complete CPE mapping table (maintained table + custom entries).
     * @param {object} req - The Express request.
     * @param {object} res - The Express response.
     * @param {object} user - The authenticated user.
     */
    obj.getCpeTableHandler = function (req, res, user) {
        var entries = [];
        // Table in force: the loaded cpe-table.json (empty when no table file exists)
        var table = obj.activeSoftwareTable();
        var tblSource = 'remote';
        for (var i = 0; i < table.length; i++) {
            var e = table[i];
            entries.push({ match: e.match.source, vendor: (e.kind != null) ? '-' : e.vendor, product: (e.kind != null) ? ('excluded: ' + e.kind) : e.product, licenseType: (e.licenseType || ''), source: tblSource });
        }
        // Custom entries
        for (var i = 0; i < obj.customCpeEntries.length; i++) {
            var e = obj.customCpeEntries[i];
            entries.push({ match: e.match, vendor: e.vendor, product: e.product, licenseType: (e.licenseType || ''), source: 'custom' });
        }
        res.type('json'); res.json({ entries: entries, cpeTable: obj.cpeTableStatus() });
    };

    /**
     * @brief Delete a CPE mapping entry from the custom table.
     * @param {object} req - The Express request.
     * @param {object} res - The Express response.
     * @param {object} user - The authenticated user.
     */
    obj.deleteCpeTableHandler = function (req, res, user) {
        var match = String(req.body.match || '');
        var vendor = String(req.body.vendor || '');
        var product = String(req.body.product || '');
        if (!match || !vendor || !product) {
            res.type('json'); res.json({ error: 'Missing match, vendor, or product.' }); return;
        }
        var found = false;
        for (var i = 0; i < obj.customCpeEntries.length; i++) {
            var e = obj.customCpeEntries[i];
            if (e.match === match && e.vendor === vendor && e.product === product) {
                obj.customCpeEntries.splice(i, 1);
                found = true;
                break;
            }
        }
        if (!found) {
            res.type('json'); res.json({ error: 'Entry not found.' }); return;
        }
        obj.saveCustomCpe(function (err) {
            if (err) { res.type('json'); res.json({ error: err.message }); return; }
            res.type('json'); res.json({ success: true });
        });
    };
};
