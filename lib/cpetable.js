/**
 * @file lib/cpetable.js
 * @brief Software name -> CPE mapping tables and their management: the built-in seed (last resort), the remotely maintained cpe-table.json (the file the installer ships and every refresh rewrites) and the custom entries added in the CPE Mapping tab, which always win.
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

    /** @type {Array<object>} User-customized CPE entries: <code>{ match, vendor, product }</code>.
     * Consulted BEFORE the built-in SOFTWARE_CPE_TABLE so an admin can override or extend mappings. */
    obj.customCpeEntries = [];

    // ---- Custom CPE mapping (admin-editable) ----

    /**
     * @brief Load user-customized CPE mapping entries from disk into memory.
     * Each entry is <code>{ match: string, vendor: string, product: string }</code> where
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
     */
    obj.addCustomCpe = function (match, vendor, product, callback) {
        if (!obj.isSafeTableRegex(match)) { if (callback) callback(new Error('Regex rejected (empty, longer than 500 characters, nested quantifier or backreference).')); return; }
        if ((typeof vendor !== 'string') || (typeof product !== 'string') || (vendor.length > 200) || (product.length > 200)) { if (callback) callback(new Error('Vendor/product too long.')); return; }
        try {
            // Validate that the regex is valid before storing.
            new RegExp(match, 'i');
        } catch (err) {
            if (callback) callback(new Error('Invalid regex: ' + err.message));
            return;
        }
        obj.customCpeEntries.push({ match: match, vendor: vendor, product: product });
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
     * @returns {Array<object>} Entries with <code>{ match: RegExp, vendor, product }</code>.
     */
    obj.compiledCustomCpe = function () {
        var out = [];
        for (var i = 0; i < obj.customCpeEntries.length; i++) {
            var e = obj.customCpeEntries[i];
            if (!obj.isSafeTableRegex(e.match)) { continue; }
            try { out.push({ match: new RegExp(e.match, 'i'), vendor: e.vendor, product: e.product }); }
            catch (err) { }
        }
        return out;
    };

    /**
     * @brief Curated mapping of common Windows display names to CPE vendor/product.
     * Matched by substring/regex against the installed software display name.
     * @type {Array<object>}
     * Each entry: <code>{ match: RegExp, vendor, product }</code>.
     */
    // Curated mapping of Windows display name/publisher -> real CPE (vendor/product).
    // Vendor and product names are verified against the NVD CVE feed (2002-2026).
    // Each entry matches via regex on the display name. NO generic token matching.
    obj.SOFTWARE_CPE_TABLE = [
        // Browser / Messaging
        { match: /mozilla firefox/i, vendor: 'mozilla', product: 'firefox' },
        { match: /mozilla thunderbird/i, vendor: 'mozilla', product: 'thunderbird' },
        { match: /google chrome/i, vendor: 'google', product: 'chrome' },
        { match: /webview2/i, vendor: 'microsoft', product: 'edge_webview2' }, // before 'microsoft edge' - distinct runtime, not the browser
        { match: /microsoft edge/i, vendor: 'microsoft', product: 'edge' },
        { match: /microsoft teams/i, vendor: 'microsoft', product: 'teams' },
        // Adobe
        { match: /adobe acrobat reader/i, vendor: 'adobe', product: 'acrobat_reader' },
        { match: /adobe acrobat( \(64-bit\))?/i, vendor: 'adobe', product: 'acrobat' },
        { match: /^adobe acrobat/i, vendor: 'adobe', product: 'acrobat' },
        // Office / Microsoft products (via CPE; Windows Update / MSRC cover patches separately)
        { match: /microsoft 365|microsoft office|office 16|microsoft onenote/i, vendor: 'microsoft', product: 'office' },
        { match: /microsoft onedrive/i, vendor: 'microsoft', product: 'onedrive' },
        { match: /microsoft visual studio code/i, vendor: 'microsoft', product: 'visual_studio_code' },
        { match: /microsoft visual studio/i, vendor: 'microsoft', product: 'visual_studio' },
        { match: /microsoft sql server/i, vendor: 'microsoft', product: 'sql_server' },
        { match: /^copilot/i, vendor: 'microsoft', product: 'copilot' },
        // Java / Oracle
        { match: /oracle java|^java/i, vendor: 'oracle', product: 'jre' },
        { match: /java.*development kit/i, vendor: 'oracle', product: 'jdk' },
        { match: /virtualbox/i, vendor: 'oracle', product: 'vm_virtualbox' },
        // Apache
        { match: /apache netbeans/i, vendor: 'apache', product: 'netbeans' },
        { match: /openoffice/i, vendor: 'apache', product: 'openoffice' },
        // Open source / well-known tools
        { match: /^7-zip/i, vendor: '7-zip', product: '7-zip' },
        { match: /notepad\+\+/i, vendor: 'notepad-plus-plus', product: 'notepad\\+\\+' }, // NVD criteria escape '+'
        { match: /vlc media player/i, vendor: 'videolan', product: 'vlc_media_player' },
        { match: /^python/i, vendor: 'python', product: 'python' },
        { match: /node\.js/i, vendor: 'nodejs', product: 'node.js' },
        { match: /^libreoffice/i, vendor: 'libreoffice', product: 'libreoffice' },
        { match: /^irfanview/i, vendor: 'irfanview', product: 'irfanview' },
        { match: /tortoisesvn/i, vendor: 'tigris', product: 'tortoisesvn' },
        { match: /tortoisegit/i, vendor: 'tortoisegit', product: 'tortoisegit' },
        { match: /pdf-xchange/i, vendor: 'pdf-xchange', product: 'pdf-xchange_editor' },
        { match: /winscp/i, vendor: 'winscp', product: 'winscp' },
        { match: /foxit pdf editor/i, vendor: 'foxit', product: 'pdf_editor' },
        { match: /screentogif/i, vendor: 'screentogif', product: 'screentogif' },
        { match: /^gimp/i, vendor: 'gimp', product: 'gimp' },
        { match: /audacity/i, vendor: 'audacityteam', product: 'audacity' },
        { match: /^inkscape/i, vendor: 'inkscape', product: 'inkscape' },
        { match: /keepassxc/i, vendor: 'keepassxc', product: 'keepassxc' },
        { match: /keepass(?!xc)/i, vendor: 'keepass', product: 'keepass' },
        { match: /mremoteng/i, vendor: 'mremoteng', product: 'mremoteng' },
        { match: /forticlient/i, vendor: 'fortinet', product: 'forticlient' },
        { match: /teamviewer/i, vendor: 'teamviewer', product: 'teamviewer' },
        { match: /anydesk/i, vendor: 'anydesk', product: 'anydesk' },
        { match: /^putty/i, vendor: 'putty', product: 'putty' },
        { match: /filezilla server/i, vendor: 'filezilla-project', product: 'filezilla_server' },
        { match: /filezilla/i, vendor: 'filezilla-project', product: 'filezilla_client' },
        { match: /wireshark/i, vendor: 'wireshark', product: 'wireshark' },
        { match: /^curl/i, vendor: 'haxx', product: 'curl' },
        { match: /openssl/i, vendor: 'openssl', product: 'openssl' },
        { match: /^php /i, vendor: 'php', product: 'php' },
        // Nextcloud / collaboration
        { match: /^nextcloud talk/i, vendor: 'nextcloud', product: 'talk' },
        { match: /^nextcloud/i, vendor: 'nextcloud', product: 'nextcloud' },
        // Common software whose display name does not trivially reduce to its CPE product
        { match: /^git(?!hub)/i, vendor: 'git', product: 'git' },
        { match: /brave browser|brave \d/i, vendor: 'brave', product: 'brave' },
        { match: /docker desktop/i, vendor: 'docker', product: 'docker_desktop' },
        { match: /electron/i, vendor: 'electronjs', product: 'electron' },
        { match: /power bi report server/i, vendor: 'microsoft', product: 'power_bi_report_server' },
        { match: /globalprotect/i, vendor: 'paloaltonetworks', product: 'globalprotect' },
        { match: /sumatrapdf/i, vendor: 'sumatrapdfreader', product: 'sumatrapdf' },
        // VPN / Remote
        { match: /securepoint (ssl vpn|vpn client)/i, vendor: 'securepoint', product: 'openvpn-client' }
        // NOTE (v3.0.0): additions belong in cpe-table.json (the shipped + fetched table) -
        // do NOT mirror them here; this array is only the offline seed of last resort.
    ];

    /**
     * @brief Validate and apply a CPE table JSON payload (string or object).
     * Entry regexes compile with the i flag only (same semantics as the built-in table);
     * invalid entries are skipped, not fatal. Two entry shapes are accepted:
     * <code>{match, vendor, product}</code> (maps to a NVD CPE) or
     * <code>{match, kind}</code> with kind "driver"/"firmware" (declares the matched
     * software out-of-NVD-scope - it is reported as such and excluded from coverage).
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
        if (/\((?:[^()\\]|\\.)*(?:[+*]|\{\d+,\d*\})(?:[^()\\]|\\.)*\)(?:[+*]|\{\d+,\d*\})/.test(s)) { return false; }
        if (/\\[1-9]/.test(s)) { return false; } // backreferences
        return true;
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
                try { out.push({ match: new RegExp(en.match, 'i'), kind: en.kind }); applied++; } catch (ex) { skipped++; }
                continue;
            }
            if ((typeof en.vendor !== 'string') || (typeof en.product !== 'string') ||
                (en.vendor.length === 0) || (en.vendor.length > 200) || (en.product.length > 200)) { skipped++; continue; }
            try { out.push({ match: new RegExp(en.match, 'i'), vendor: en.vendor.toLowerCase(), product: en.product.toLowerCase() }); applied++; }
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
     * live even on a first start without network and contributions never need
     * a code change; SOFTWARE_CPE_TABLE stays as the last-resort seed only.
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

    /** @brief HTTP GET text with size cap and redirects (overridable indirection for tests). */
    obj.cpeTableHttpGet = function (url, callback) {
        var getIt = function (u, redirectsLeft) {
            var req = https.get(u, { headers: { 'User-Agent': 'meshcentral-inventoryscanner' }, timeout: 30000 }, function (res) {
                if (((res.statusCode == null) || (res.statusCode >= 300) && (res.statusCode < 400)) && res.headers.location && (redirectsLeft > 0)) {
                    res.resume();
                    var nu = null;
                    try { nu = new URL(String(res.headers.location), u).href; } catch (e) { callback(new Error('Invalid redirect')); return; } // RFC 3986 resolution (v3.0.1)
                    if (!/^https:\/\//i.test(nu)) { callback(new Error('Redirect away from https blocked')); return; }
                    getIt(nu, redirectsLeft - 1);
                    return;
                }
                if (res.statusCode !== 200) { res.resume(); callback(new Error('HTTP ' + res.statusCode)); return; }
                var size = 0, parts = [];
                res.on('data', function (chunk) {
                    size += chunk.length;
                    if (size > obj.CPE_TABLE_MAX_BYTES) { req.destroy(new Error('CPE table too large')); return; }
                    parts.push(chunk);
                });
                res.on('end', function () { callback(null, Buffer.concat(parts).toString('utf8')); });
            });
            req.on('error', function (err) { callback(err); });
            req.on('timeout', function () { req.destroy(new Error('CPE table fetch timeout')); });
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

    /** @brief The software table in force: validated remote table when loaded, else the built-in one. */
    obj.activeSoftwareTable = function () { return (obj.remoteCpeEntries != null) ? obj.remoteCpeEntries : obj.SOFTWARE_CPE_TABLE; };

    /** @brief Status info about the active CPE table for the UI. */
    obj.cpeTableStatus = function () {
        var scfg = obj.scannerConfig();
        return {
            source: (obj.remoteCpeEntries != null) ? 'remote' : 'builtin',
            origin: (obj.remoteCpeEntries != null) ? (obj.cpeTableOrigin || 'cache') : '',
            updated: obj.cpeTableLoadedAt || '',
            url: scfg.cpeTableUrl,
            enabled: scfg.cpeTableEnabled,
            entries: (obj.remoteCpeEntries != null) ? obj.remoteCpeEntries.length : obj.SOFTWARE_CPE_TABLE.length
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
        res.json({ entries: obj.customCpeEntries.map(function (e, i) { return { index: i, match: e.match, vendor: e.vendor, product: e.product }; }) });
    };

    /**
     * @brief Add a custom CPE mapping entry from the admin UI.
     * Validates and persists; returns the updated entry list.
     * @param {object} req - The Express request (urlencoded <code>match, vendor, product</code>).
     * @param {object} res - The Express response.
     * @param {object} user - The authenticated user.
     */
    obj.addCpeHandler = function (req, res, user) {
        var match = String(req.body.match || '').trim();
        var vendor = String(req.body.vendor || '').trim().toLowerCase();
        var product = String(req.body.product || '').trim().toLowerCase();
        if (!match || !vendor || !product) {
            res.type('json'); res.json({ error: 'Regex, vendor and product are required.' }); return;
        }
        obj.addCustomCpe(match, vendor, product, function (err) {
            if (err) { res.type('json'); res.json({ error: err.message }); return; }
            res.type('json');
            res.json({ success: true, entries: obj.customCpeEntries.map(function (e, i) { return { index: i, match: e.match, vendor: e.vendor, product: e.product }; }) });
        });
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
            res.json({ success: true, entries: obj.customCpeEntries.map(function (e, i) { return { index: i, match: e.match, vendor: e.vendor, product: e.product }; }) });
        });
    };

    /**
     * @brief Get the complete CPE mapping table (built-in + custom entries).
     * @param {object} req - The Express request.
     * @param {object} res - The Express response.
     * @param {object} user - The authenticated user.
     */
    obj.getCpeTableHandler = function (req, res, user) {
        var entries = [];
        // Table in force: remote when loaded and valid, else the built-in one
        var table = obj.activeSoftwareTable();
        var tblSource = (obj.remoteCpeEntries != null) ? 'remote' : 'built-in';
        for (var i = 0; i < table.length; i++) {
            var e = table[i];
            entries.push({ match: e.match.source, vendor: (e.kind != null) ? '-' : e.vendor, product: (e.kind != null) ? ('excluded: ' + e.kind) : e.product, source: tblSource });
        }
        // Custom entries
        for (var i = 0; i < obj.customCpeEntries.length; i++) {
            var e = obj.customCpeEntries[i];
            entries.push({ match: e.match, vendor: e.vendor, product: e.product, source: 'custom' });
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
