/**
 * @file inventoryscanner.js
 * @brief MeshCentral Inventory & Vulnerability Scanner plugin.
 *
 * Provides:
 *  - CSV exports of hardware, software and patch inventory via the device-list
 *    toolbar (Custom UI <code>devicesbarbuttons</code>) for the selected devices;
 *  - an offline NVD 2.0 CVE scanner;
 *  - a per-device-group vulnerability assessment admin panel
 *    (<code>pluginadmin.ashx?pin=inventoryscanner&action=show</code>) where the
 *    administrator rates every CVE found in a group. The rating is **group-wide**
 *    (applies to all devices in the group) and requires a mandatory comment.
 *
 * Only existing MeshCentral plugin/DB APIs are used. All actions are gated on a
 * full site administrator (<code>user.siteadmin === 0xFFFFFFFF</code>, i.e.
 * SITERIGHT_ADMIN). No inventory data ever leaves the server; only the public
 * NVD feed is downloaded.
 *
 * @author derStephan
 * @version 3.5.0
 *
 * Transparency: This plugin was created with the assistance of Qwen 3.6 27B and Qwen 3.8 Flash Next.
 * Audits: 2026-11-06 (NVIDIA Nemotron 3 550B A55B) and 2026-11-11 (Claude, v3.0.1) via opencode - see AUDIT.md.
 */

"use strict";

const fs = require('fs');
const path = require('path');
const https = require('https');
const zlib = require('zlib');
const crypto = require('crypto');

/**
 * Version of the CODE in this module, read ONCE when Node loads the module (v3.0.1).
 * pluginHandler.installPlugin re-requires the plugin after an upgrade, gets the CACHED old
 * module and creates a new instance from it; reading config.json per instance (pre-3.0.1)
 * made that instance report the new version, so the stale code was never noticed or reloaded.
 */
var MODULE_CODE_VERSION = 'unknown';
try { MODULE_CODE_VERSION = JSON.parse(fs.readFileSync(path.join(__dirname, 'config.json'), 'utf8')).version || 'unknown'; } catch (ex) { }

/**
 * @brief Plugin entry point.
 *
 * MeshCentral invokes this with the pluginHandler instance as <code>parent</code>.
 * <code>parent.parent</code> is the meshcentral server object.
 *
 * @param {object} parent - The pluginHandler instance.
 * @returns {object} The plugin object exposing MeshCentral hooks.
 */
module.exports.inventoryscanner = function (parent) {
    var obj = {};
    /** @type {object} Reference to the pluginHandler instance. */
    obj.parent = parent;
    /** @type {object} Reference to the meshcentral server object. */
    obj.meshServer = parent.parent;
    /** @type {object} Reference to the MeshCentral database. */
    obj.db = obj.meshServer.db;
    /** @type {function} MeshCentral debug logger. */
    obj.debug = obj.meshServer.debug;
    /** @type {string} Plugin short name used in the pluginadmin.ashx?pin= URL. */
    obj.shortName = 'inventoryscanner';
    /** @type {string} Version from the manifest beside this file - shown in the panel so stale
     *  deploys (new view, old server code) are visible at a glance. */
    obj.PLUGIN_VERSION = MODULE_CODE_VERSION;
    /** @type {number} Process-wide instance generation (shared across module reloads via global):
     *  only the newest instance may act on its timers - pluginHandler replaces instances on
     *  install/upgrade without telling the old one, whose timer chains would otherwise keep running. */
    global.__inventoryscannerInstanceGen = (global.__inventoryscannerInstanceGen || 0) + 1;
    obj.instanceGen = global.__inventoryscannerInstanceGen;
    /** @brief True while this object is the newest plugin instance in the process. */
    obj.isCurrentInstance = function () { return obj.instanceGen === global.__inventoryscannerInstanceGen; };
    /** @brief A chained timer started under generation <code>gen</code> may still run. */
    obj.timerValid = function (gen) { return (gen === obj.timerGen) && obj.isCurrentInstance(); };

    /**
     * @brief Functions exported to the web UI (serialized into /pluginHandler.js).
     * @type {Array<string>}
     */
    obj.exports = ['inventoryCsv', 'openAssessment', 'onWebUIStartupEnd'];

    /** @type {string} Directory for NVD data under the meshcentral datapath (survives restarts). */
    obj.nvdDataPath = path.join(obj.meshServer.datapath, 'nvd');
    /** @type {string} Path to the persisted group-wide assessment ratings file. */
    obj.assessmentsPath = path.join(obj.nvdDataPath, 'assessments.json');
    /** @type {string} Path to the persisted scheduled scan results file. */
    obj.scansPath = path.join(obj.nvdDataPath, 'scans.json');

    /**
     * @brief Directory for the plugin's own live-collected inventory database.
     * Installed software and patch lists are NOT part of the MeshCentral sysinfo
     * document (meshagent.js leaves "save software into database" as an open TODO),
     * so this plugin collects them directly from the agents and stores them here.
     * Lives under the plugin folder inside the datapath, so it survives MeshCentral
     * updates and is fully independent of the core server.
     * @type {string}
     */
    obj.inventoryDataPath = path.join(obj.meshServer.datapath, 'plugins', 'inventoryscanner', 'data');
    /** @type {string} Path to the user-customized CPE mapping entries (plugins/inventoryscanner/custom-cpe.json).
     * Entries added via the admin UI are persisted here and survive MeshCentral updates. */
    obj.customCpePath = path.join(obj.meshServer.datapath, 'plugins', 'inventoryscanner', 'custom-cpe.json');
    /** @type {string} Path to the UI-managed scanner settings (plugins/inventoryscanner/scanner-settings.json).
     * Keys saved from the panel's Settings tab are persisted here and OVERRIDE the same keys in the
     * server's config.json; they take effect without a restart. config.json is never written by the plugin. */
    obj.pluginSettingsPath = path.join(obj.meshServer.datapath, 'plugins', 'inventoryscanner', 'scanner-settings.json');
    /** @type {object} In-memory plugin settings overlay: <code>{ vulnerabilityScanner: {...}, inventoryScanner: {...} }</code>. */
    obj.pluginSettings = {};

    /** @type {string} Cache of the remotely maintained CPE mapping table (plugins/inventoryscanner/cpe-table.json). */
    obj.cpeTablePath = path.join(obj.meshServer.datapath, 'plugins', 'inventoryscanner', 'cpe-table.json');
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

    /** @type {number} Timer generation; incremented on every settings save so old chained timers stop themselves. */
    obj.timerGen = 0;
    /** @type {Array<object>} User-customized CPE entries: <code>{ match, vendor, product }</code>.
     * Consulted BEFORE the built-in SOFTWARE_CPE_TABLE so an admin can override or extend mappings. */
    obj.customCpeEntries = [];
    /** @type {Object<string, object>} In-memory software inventory per node id. */
    obj.softwareInventory = {};
    /** @type {Object<string, object>} In-memory Windows-updates state per node id.
     * <code>{ time, count, updates }</code> where <code>count</code> is the number of
     * missing (pending) Windows updates. */
    obj.windowsUpdates = {};
    /** @type {Object<string, boolean>} Set of pending live collection requests (nodeid -> true). */
    obj.pendingCollection = {};
    /** @type {Object<string, boolean>} Set of pending Windows-update collection requests (nodeid -> true). */
    obj.pendingWinUpdates = {};
    /** @type {boolean} True once the webserver.routeAgentCommand hook has been installed. */
    obj.routeHookInstalled = false;

    /**
     * @brief In-memory NVD product index.
     * @type {Object<string, Array<object>>}
     * Maps <code>"vendor|product"</code> (lower-cased) to an array of CPE match
     * definitions. Each definition has the shape
     * <code>{ part, kind:'any'|'exact'|'range', version, startInc, startExc, endInc, endExc, cves }</code>.
     */
    obj.productIndex = {};
    /** @type {Object<string, Array<object>>} Secondary index by product name only.
     * Maps <code>"product"</code> (lower-cased) to an array of
     * <code>{ vendor, defs }</code> so CVEs can be searched by product name alone,
     * independent of the (often unreliable) vendor guess. */
    obj.productIndexByProduct = {};
/** @type {Object<string, number>} Set of all real CPE product tokens present in the
     * loaded NVD index (lower-cased). Used to check whether a candidate product token
     * derived from an installed-software name actually exists before searching. */
    obj.cpeProductTokens = {};
    /** @type {Object<string, number>} CPE vendor tokens of APPLICATION entries in the loaded feeds (v3.1.0). */
    obj.cpeVendorTokens = {};
    /** @type {Array<object>} All CVE records loaded from the NVD feeds. */
    obj.allCves = [];
    /** @type {string|null} ISO timestamp of the last successful feed download. */
    obj.lastUpdate = null;
    /** @type {string|null} ISO timestamp of the last scheduled (or manual) group scan. */
    obj.lastScan = null;
    /** @type {Object} In-memory scheduled scan results: <code>meshId -> { time, cves }</code>. */
    obj.scanResults = {};
    /**
     * @brief Persisted group-wide assessment ratings.
     * @type {Object<string, object>}
     * Maps <code>"meshId:cveId"</code> (a rating applies to every device in the
     * group) to <code>{ meshId, cveId, assessment, comment, lastModified, assessedBy, assessedById }</code>.
     */
    obj.assessments = {};

    /** @type {number} First year of NVD coverage. */
    obj.FIRST_YEAR = 2002;

    /**
     * @brief MeshCentral startup hook.
     * Ensures the NVD directory exists, loads assessments, ensures the NVD feed
     * is present and schedules the weekly update.
     */
    obj.server_startup = function () {
        // MeshCentral's installPlugin ends with a plain require() which returns the
        // CACHED module after an upgrade - the old instance stays active and this hook
        // runs on it. Detect the newer manifest beside the file and hot-swap a fresh
        // instance into the pluginHandler (all dispatch is by reference, so one click
        // is enough; no server restart needed).
        try {
            var diskVer = null;
            try { diskVer = JSON.parse(fs.readFileSync(path.join(__dirname, 'config.json'), 'utf8')).version; } catch (e0) { }
            if (diskVer != null && obj.PLUGIN_VERSION !== 'unknown' && diskVer !== obj.PLUGIN_VERSION && obj.parent != null && obj.parent.plugins != null) {
                var sname = obj.shortName;
                obj.wgLog('upgrade detected on disk (' + obj.PLUGIN_VERSION + ' -> ' + diskVer + '), reloading without server restart');
                try {
                    Object.keys(require.cache).forEach(function (k) { if (k.indexOf(__dirname + path.sep) === 0) { delete require.cache[k]; } }); // path.sep: never touch a sibling folder such as inventoryscanner2
                    var fresh = require(path.join(__dirname, sname + '.js'))[sname](obj.parent);
                    obj.parent.plugins[sname] = fresh;
                    obj.parent.exports[sname] = fresh.exports;
                    obj.timerGen++;
                    obj.__superseded = true;
                    try { fresh.server_startup(); } catch (e1) { }
                    obj.wgLog('hot reload complete, version ' + fresh.PLUGIN_VERSION + ' active');
                    return;
                } catch (e2) { obj.wgLog('hot reload failed (' + e2.message + '); the next server restart applies the upgrade'); }
            }
        } catch (e) { }
        obj.debug('plugin:inventory_scanner', 'Starting inventory & vulnerability scanner plugin');
        try { fs.mkdirSync(obj.nvdDataPath, { recursive: true }); } catch (e) { }
        try { fs.mkdirSync(obj.inventoryDataPath, { recursive: true }); } catch (e) { }
        obj.loadAssessments();
        obj.loadScans();
        obj.loadCollectedInventory();
        obj.loadCustomCpe();
        obj.loadRemoteCpeTable();
        obj.loadOsLifecycle();
        obj.loadPluginSettings();
        obj.maybeFetchCpeTable();
        obj.maybeFetchOsLifecycle();
        obj.wgLoadResults();
        obj.osLoadResults();
        obj.installRouteHook();
        obj.ensureNvdData();
        // Self-heal: check if NVD timer is stale (> 1 week since last successful update)
        obj.checkAndRepairNvdTimer();
        obj.scheduleUpdate();
        obj.scheduleScans();
        obj.scheduleInventoryCollection();
        obj.scheduleWingetUpdates();
        obj.fixOwnPluginUrl();
    };

    /**
     * @brief MeshCentral's plugin list offers a generic configure link (viewmode 43)
     *   that 404s for this plugin; point the stored url at the real admin panel.
     */
    obj.fixOwnPluginUrl = function () {
        try {
            if (typeof obj.db.getPlugins !== 'function' || typeof obj.db.updatePlugin !== 'function') return;
            var want = '/pluginadmin.ashx?pin=' + obj.shortName + '&action=show';
            obj.db.getPlugins(function (err, docs) {
                if (err || !docs) return;
                for (var i = 0; i < docs.length; i++) {
                    if (docs[i] && docs[i].shortName === obj.shortName && docs[i].url !== want) {
                        try { obj.db.updatePlugin(docs[i]._id, { url: want }, function () { }); } catch (e) { }
                    }
                }
            });
        } catch (e) { }
    };

    /**
     * @brief Self-heal for NVD update timer. If last successful update is older than
     * updateHours (or missing), re-arm the scheduler and notify admins.
     */
    obj.checkAndRepairNvdTimer = function () {
        try {
            var cfg = obj.effectiveSectionConfig('vulnerabilityScanner');
            var hours = (cfg && typeof cfg.updateHours === 'number' && cfg.updateHours >= 1) ? cfg.updateHours : 168;
            var maxAge = hours * 3600 * 1000;
            var stale = false;
            if (!obj.lastUpdate) {
                obj.nvdLog('NVD timer self-heal: no lastUpdate recorded, scheduling update');
                stale = true;
            } else {
                var age = Date.now() - Date.parse(obj.lastUpdate);
                if (isNaN(age) || age > maxAge) {
                    obj.nvdLog('NVD timer self-heal: lastUpdate is ' + Math.round(age / 3600000) + 'h old (max ' + hours + 'h), scheduling update');
                    stale = true;
                }
            }
            if (stale) {
                obj.scheduleUpdate();
                // Notify admins if data is older than 1 week (7 days)
                var weekMs = 7 * 24 * 3600 * 1000;
                if (!obj.lastUpdate || (Date.now() - Date.parse(obj.lastUpdate) > weekMs)) {
                    obj.notifyAdminsNvdStale(obj.lastUpdate, hours);
                }
            }
        } catch (e) {
            obj.debug('plugin:inventory_scanner', 'NVD timer self-heal error:', e.message);
        }
    };

    /**
     * @brief Notify admins that NVD database is stale.
     * @param {string|null} lastUpdate - The lastUpdate timestamp or null.
     * @param {number} updateHours - Configured update interval in hours.
     */
    obj.notifyAdminsNvdStale = function (lastUpdate, updateHours) {
        var msg = 'NVD vulnerability database is stale';
        if (lastUpdate) {
            var ageHours = Math.round((Date.now() - Date.parse(lastUpdate)) / 3600000);
            msg += ' (last successful update ' + ageHours + ' hours ago, configured interval ' + updateHours + 'h)';
        } else {
            msg += ' (no successful update recorded)';
        }
        msg += '. Scheduled update has been re-triggered.';
        var event = {
            etype: 'server',
            action: 'msg',
            type: 'notify',
            id: Math.random(),
            tag: 'ServerNotify',
            value: msg,
            title: 'NVD Database Stale'
        };
        try { obj.meshServer.DispatchEvent(['*'], obj, event); }
        catch (e) { obj.debug('plugin:inventory_scanner', 'Error dispatching NVD stale notification:', e.message); }
    };

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

    // ---- Plugin settings (UI-managed, overrides config.json - which is never written) ----

    /**
     * @brief Load the UI-managed scanner settings from disk into memory.
     */
    obj.loadPluginSettings = function () {
        obj.pluginSettings = {};
        try {
            if (fs.existsSync(obj.pluginSettingsPath)) {
                var data = JSON.parse(fs.readFileSync(obj.pluginSettingsPath, 'utf8'));
                if (data && (typeof data === 'object')) { obj.pluginSettings = data; }
            }
        } catch (err) {
            obj.debug('plugin:inventory_scanner', 'Error loading plugin settings:', err.message);
            obj.pluginSettings = {};
        }
    };

    /**
     * @brief Persist the UI-managed scanner settings to disk.
     * @param {function} [callback] - Called with <code>(err)</code>.
     */
    obj.savePluginSettings = function (callback) {
        try {
            var dir = path.dirname(obj.pluginSettingsPath);
            if (!fs.existsSync(dir)) { fs.mkdirSync(dir, { recursive: true }); }
            fs.writeFileSync(obj.pluginSettingsPath, JSON.stringify(obj.pluginSettings, null, 2));
            if (callback) callback(null);
        } catch (err) {
            obj.debug('plugin:inventory_scanner', 'Error saving plugin settings:', err.message);
            if (callback) callback(err);
        }
    };

    /**
     * @brief Merge a settings section from the server config.json with the plugin's
     * own settings file. The plugin file wins per key; config.json stays the fallback.
     * @param {string} section - <code>'vulnerabilityScanner'</code> or <code>'inventoryScanner'</code>.
     * @returns {object|null} The effective section object (may be undefined-like when set nowhere).
     */
    obj.effectiveSectionConfig = function (section) {
        var base = null;
        try { base = obj.meshServer.config.settings[section]; } catch (e) { }
        var over = obj.pluginSettings[section];
        if ((over == null) || (typeof over !== 'object')) { return base; }
        var merged = {};
        if (base && (typeof base === 'object')) {
            for (var k in base) { if (Object.prototype.hasOwnProperty.call(base, k)) { merged[k] = base[k]; } }
        }
        for (var k2 in over) { if (Object.prototype.hasOwnProperty.call(over, k2)) { merged[k2] = over[k2]; } }
        return merged;
    };

    /**
     * @brief Restart all chained timers so settings saved in the UI take effect
     * immediately: bump the timer generation (old chained timers notice it and stop)
     * and schedule the scan + collection loops freshly from the effective config.
     */
    obj.rescheduleAll = function () {
        obj.timerGen++;
        obj.scheduleScans();
        obj.scheduleInventoryCollection();
        obj.scheduleWingetUpdates();
    };

    // ---- Assessment persistence ----

    /**
     * @brief Load manual assessments from disk into memory.
     * On parse error, resets the in-memory store to an empty object.
     */
    obj.loadAssessments = function () {
        try {
            if (fs.existsSync(obj.assessmentsPath)) {
                obj.assessments = JSON.parse(fs.readFileSync(obj.assessmentsPath, 'utf8'));
                obj.debug('plugin:inventory_scanner', 'Loaded', Object.keys(obj.assessments).length, 'assessments');
            } else { obj.assessments = {}; }
        } catch (err) {
            obj.debug('plugin:inventory_scanner', 'Error loading assessments:', err.message);
            obj.assessments = {};
        }
    };

    /**
     * @brief Persist the in-memory assessment overrides to disk.
     * @param {function} [callback] - Called with <code>null</code> on success or an Error.
     */
    obj.saveAssessments = function (callback) {
        try {
            fs.writeFileSync(obj.assessmentsPath, JSON.stringify(obj.assessments, null, 2));
            if (callback) callback(null);
        } catch (err) {
            obj.debug('plugin:inventory_scanner', 'Error saving assessments:', err.message);
            if (callback) callback(err);
        }
    };

    // ---- NVD feed management ----

    /**
     * @brief Return the current calendar year.
     * @returns {number} The current year.
     */
    obj.currentYear = function () { return new Date().getFullYear(); };

    /**
     * @brief Append a diagnostic line to <code>nvd/nvd-download.log</code>.
     * Used to diagnose the NVD feed download independent of the server/container
     * logs. Appends with a timestamp; never throws.
     * @param {string} msg - The message to log.
     */
    obj.nvdLog = function (msg) {
        try {
            var line = '[' + new Date().toISOString() + '] ' + msg + '\n';
            fs.appendFileSync(path.join(obj.nvdDataPath, 'nvd-download.log'), line);
        } catch (e) { }
        obj.debug('plugin:inventory_scanner', msg);
    };

    /**
     * @brief Ensure the NVD database is available at startup.
     * Loads existing feeds, or downloads all missing year feeds if none are present.
     */
    /** @type {boolean} True while an NVD download run (scheduled or manual) is in flight. */
    obj.nvdUpdateRunning = false;

    /**
     * @brief Single entry point for NVD downloads with a concurrency guard.
     * Concurrent callers get callback(null, "skipped") - the already running
     * download covers them (it refreshes the current year when asked to).
     * @param {boolean} force - Re-download the current year even if cached.
     * @param {function} [callback] - Called with (err, result).
     */
    obj.runNvdUpdate = function (force, callback) {
        if (obj.nvdUpdateRunning) { if (callback) callback(null, 'skipped'); return; }
        obj.nvdUpdateRunning = true;
        obj.downloadNvdDatabase(force, function (err) {
            obj.nvdUpdateRunning = false;
            if (callback) callback(err, err ? null : 'done');
        });
    };

    /**
     * @brief Manual "update now" trigger from the Settings tab.
     * Answers immediately (the download continues in the background); reports
     * alreadyRunning when a scheduled or manual run is in flight.
     * @param {object} req - The Express request (unused body).
     * @param {object} res - The Express response.
     * @param {object} user - The authenticated user.
     */
    obj.updateNvdHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        if (obj.nvdUpdateRunning) { return send({ started: false, alreadyRunning: true }); }
        obj.runNvdUpdate(true, function (err) {
            obj.debug('plugin:inventory_scanner', err ? ('NVD update run failed: ' + err.message) : 'NVD update run finished');
        });
        send({ started: true });
    };

    obj.ensureNvdData = function () {
        var latestYearFile = path.join(obj.nvdDataPath, 'nvdcve-2.0-' + obj.currentYear() + '.json');
        if (fs.existsSync(latestYearFile)) {
            obj.debug('plugin:inventory_scanner', 'Loading existing NVD database');
            obj.loadNvdFromAllFiles();
        } else {
            obj.debug('plugin:inventory_scanner', 'Downloading NVD database');
            obj.runNvdUpdate(false, null);
        }
    };

    /**
     * @brief Schedule periodic NVD feed updates.
     * Defaults to every 7 days; overridable via
     * <code>meshserver.config.settings.vulnerabilityScanner.updateHours</code>.
     */
    obj.scheduleUpdate = function () {
        var hours = 24 * 7; // weekly default
        try {
            var cfg = obj.effectiveSectionConfig('vulnerabilityScanner');
            if (cfg && (typeof cfg.updateHours === 'number') && (cfg.updateHours >= 1)) { hours = cfg.updateHours; }
        } catch (e) { }
        obj.debug('plugin:inventory_scanner', 'Next NVD update scheduled in', hours, 'hours');
        var gen = obj.timerGen;
        obj.longTimeout(function () {
            if (!obj.timerValid(gen)) { return; }
            obj.runNvdUpdate(true, function (err) {
                if (!obj.timerValid(gen)) { return; }
                if (!err) {
                    obj.updateTimerArmed = true;
                }
                obj.maybeFetchCpeTable();
                obj.maybeFetchOsLifecycle();
                obj.scheduleUpdate();
            });
        }, hours * 3600 * 1000);
    };

// ============================================================================
// winget automatic software updates (engine)
// ----------------------------------------------------------------------------
// Verified transport (meshcore.js): {action:'runcommands', type:1 (cmd.exe), cmds,
// runAsUser:0, reply:true, sessionid, responseid} -> the agent answers
// {action:'msg', type:'runcommands', result, sessionid, responseid}, captured
// by this plugin's routeAgentCommand hook. Verified winget CLI usage from the
// official docs (list --upgrade-available / upgrade --id --exact --silent /
// pin add --id --installed --exact, all with --accept-*-agreements and
// --disable-interactivity). One script per device does
// list -> filter(ignore) -> per-package upgrade -> pin sync and answers with a
// single @@INVWUP@@ marker line containing compressed JSON.
// ============================================================================

    /** @type {string} latest winget run results per node (state file). */
    obj.wingetResultsPath = path.join(obj.meshServer.datapath, 'plugins', 'inventoryscanner', 'winget-results.json');
    /** @type {string} append-only winget update log (shown in the UI, rotated at ~5 MB). */
    obj.wingetLogPath = path.join(obj.meshServer.datapath, 'plugins', 'inventoryscanner', 'winget-update.log');
    /** @type {Object<string, object>} nodeid -> in-flight run bookkeeping. */
    obj.wgPending = {};
    /** @type {Array<string>} queued node ids. */
    obj.wgQueue = [];
    /** @type {number} number of devices currently being updated. */
    obj.wgActive = 0;
    /** @type {Object} nodeid -> { time, winget, results[], error? } of the last run. */
    obj.wgResults = {};
    /** @type {boolean} true while a batch (scheduled or manual) occupies the queue. */
    obj.wgBatchRunning = false;
    /** @type {boolean} true while the running batch is a report-only dry run. */
    obj.wgBatchDry = false;
    /** @type {object|null} extra script options for the running batch: { mode, onlyId }. */
    obj.wgBatchOpts = null;

    obj.WINGET_MAX_PARALLEL = 2;
    /** @type {number} hard cap of devices per batch (pre-3.0.1 this constant was referenced but undefined). */
    obj.WINGET_MAX_DEVICES = 5000;
    obj.WINGET_RUN_TIMEOUT_MS = 2 * 60 * 60 * 1000;
    obj.WINGET_DRY_TIMEOUT_MS = 10 * 60 * 1000;
    obj.WINGET_MARKER = '@@INVWUP@@';
    obj.WINGET_ID_RE = /^[A-Za-z0-9._+-]{1,128}$/;

    /** @brief Unsigned hex of a signed win32 exit code (winget documents its codes in hex). */
    obj.wgExitHex = function (n) {
        try { return ((n | 0) >>> 0).toString(16).toUpperCase(); } catch (e) { return ''; }
    };

    /**
     * @brief Effective winget updater configuration (scanner-settings.json
     * overlay first, config.json settings.wingetUpdater second, defaults last).
     * @returns {object} <code>{ enabled, intervalHours, meshes, excludeNodes, ignorePackages, pinSync }</code>
     */
    obj.wingetConfig = function () {
        var cfg = null;
        try { cfg = obj.effectiveSectionConfig('wingetUpdater'); } catch (e) { }
        var out = { enabled: false, intervalHours: 168, meshes: null, excludeNodes: [], ignorePackages: [], pinSync: true };
        if (cfg && (typeof cfg === 'object')) {
            if (typeof cfg.enabled === 'boolean') { out.enabled = cfg.enabled; }
            if (typeof cfg.intervalHours === 'number' && cfg.intervalHours >= 1 && cfg.intervalHours <= 87600) { out.intervalHours = cfg.intervalHours; }
            if (Array.isArray(cfg.updateMeshes) && cfg.updateMeshes.length > 0) { out.meshes = cfg.updateMeshes.slice(); }
            if (Array.isArray(cfg.excludeNodes)) {
                out.excludeNodes = cfg.excludeNodes.filter(function (x) { return (typeof x === 'string') && /^node\/[^:]{1,100}$/.test(x); });
            }
            if (Array.isArray(cfg.ignorePackages)) {
                out.ignorePackages = cfg.ignorePackages.filter(function (x) { return x && (typeof x.id === 'string') && obj.WINGET_ID_RE.test(x.id); })
                    .map(function (x) { return { id: x.id, note: (typeof x.note === 'string') ? x.note.substring(0, 200) : '' }; });
            }
            if (typeof cfg.pinSync === 'boolean') { out.pinSync = cfg.pinSync; }
        }
        return out;
    };

    /**
     * @brief PowerShell lines that open the client transcript (shared by the winget and the
     * OS update scripts). Client transcript location (v3.0.1): only folders that standard users
     * cannot write to. 1) the agent folder (found via the process ancestors), 2) a dedicated
     * %ProgramData%\\InventoryScanner folder that is created with an ACL for SYSTEM +
     * Administrators only and refused when it already exists with another owner or as a
     * reparse point. Plain %ProgramData% / %TEMP% are not used (both allow file creation by
     * standard users). Without a safe folder the run continues without a transcript.
     * Sets $invTDir (safe folder or $null) and $invT (transcript file or $null).
     * @param {string} fileName - Transcript file name (fixed literal, never user input).
     * @returns {Array<string>} One statement per line.
     */
    obj.psTranscriptLines = function (fileName) {
        var fn = String(fileName).replace(/[^A-Za-z0-9._-]/g, '');
        return [
            "$invTDir = $null",
            "try { $invQ = $PID; for ($invHop = 0; $invHop -lt 4; $invHop++) { $invPP = 0; try { $invPP = (Get-CimInstance Win32_Process -Filter ('ProcessId={0}' -f $invQ) -ErrorAction Stop).ParentProcessId } catch { break }; if (-not $invPP) { break }; $invPX = $null; try { $invPX = (Get-Process -Id $invPP -ErrorAction Stop).Path } catch { break }; if ($invPX -and ((Split-Path $invPX -Leaf) -imatch '^(meshagent|meshcentral)[a-z0-9_-]*\\.exe$')) { $invTDir = Split-Path $invPX; break }; $invQ = $invPP } } catch { }",
            "if ($null -eq $invTDir) { try { $invLD = Join-Path $env:ProgramData 'InventoryScanner'; $invOK = @('S-1-5-18', 'S-1-5-32-544'); if (Test-Path -LiteralPath $invLD) { $invLI = Get-Item -LiteralPath $invLD -Force; $invOw = (Get-Acl -LiteralPath $invLD).GetOwner([System.Security.Principal.SecurityIdentifier]).Value; if (($invLI.Attributes -band [IO.FileAttributes]::ReparsePoint) -or ($invOK -notcontains $invOw)) { $invLD = $null } } else { $null = New-Item -ItemType Directory -Path $invLD -ErrorAction Stop; $invDS = New-Object System.Security.AccessControl.DirectorySecurity; $invDS.SetAccessRuleProtection($true, $false); foreach ($invS in $invOK) { $invDS.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object System.Security.Principal.SecurityIdentifier($invS)), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))) }; Set-Acl -LiteralPath $invLD -AclObject $invDS -ErrorAction Stop }; $invTDir = $invLD } catch { $invTDir = $null } }",
            "$invT = $null; if ($invTDir) { $invT = Join-Path $invTDir '" + fn + "' }",
            "if ($invT -and (Test-Path -LiteralPath $invT)) { try { $invFI = Get-Item -LiteralPath $invT -Force; if ($invFI.Attributes -band [IO.FileAttributes]::ReparsePoint) { $invT = $null } elseif ($invFI.Length -gt 5MB) { Move-Item -LiteralPath $invT ($invT + '.old') -Force } } catch { } }",
            "if ($invT) { try { '' | Out-File -FilePath $invT -Append -Encoding utf8 -ErrorAction Stop } catch { $invT = $null } }",
            "if ($invT) { try { Start-Transcript -Path $invT -Append | Out-Null } catch { } }"
        ];
    };

    /**
     * @brief Build the one-shot PowerShell script (runs as SYSTEM over the
     * agent's runcommands channel). Transport: wgTransport wraps the whole script
     * into ONE gzip+base64 line for cmd.exe, so PowerShell receives it atomically;
     * every statement is nevertheless kept on a single line (defense in depth,
     * guarded by a test).
     * @param {object} wcfg - The winget config section.
     * @param {boolean} [dry] - Dry run: list only, install/pin nothing.
     * @param {object} [opts] - { onlyId: winget id (already WINGET_ID_RE-validated) to
     *   touch exactly this package, mode: 'update' (default) | 'uninstall' }.
     *   Uninstall REQUIRES onlyId, probes existence with a case-insensitive id
     *   containment check on 'winget list --id <id> --exact' output (no reliance on
     *   exit-code or message localization) and then 'winget uninstall --id --exact
     *   --silent' (winget uninstall has NO --accept-package-agreements option - passing it
     *   aborts with "Argument name was not recognized", verified on winget 1.29),
     *   state ok/failed by exit code.
     * @returns {string} The script text.
     */
    obj.wgBuildScript = function (wcfg, dry, opts) {
        opts = opts || {};
        var mode = (opts.mode === 'uninstall') ? 'uninstall' : 'update';
        var onlyId = (typeof opts.onlyId === 'string' && obj.WINGET_ID_RE.test(opts.onlyId)) ? opts.onlyId : '';
        if (mode === 'uninstall' && onlyId === '') { throw new Error('wgBuildScript: uninstall requires a validated onlyId'); }
        var ids = [];
        for (var i = 0; i < wcfg.ignorePackages.length; i++) {
            var id = wcfg.ignorePackages[i].id;
            if (obj.WINGET_ID_RE.test(id) && (ids.indexOf(id) < 0)) { ids.push(id); }
        }
        var psList = ids.map(function (x) { return "'" + x.replace(/'/g, "''") + "'"; }).join(', ');
        var pinLines = (mode === 'update' && onlyId === '' && !dry && wcfg.pinSync && ids.length > 0) ? [
            "foreach ($pn in $invIgnore) { try { $null = (& $wg pin add --id $pn --installed --exact --accept-source-agreements --disable-interactivity) 2>&1 } catch { } }"
        ] : [];
        var dryGuard = dry
            ? "if ($invDry) { $results += @{ id = $p.id; name = $p.name; from = $p.from; to = $p.to; state = 'dry-run' }; continue };"
            : "";
        var onlyGuard = (mode === 'update' && onlyId !== '')
            ? "if ($p.id -ine $invOnly) { continue };"
            : "";
        var head = [
            "$ProgressPreference = 'SilentlyContinue'",
            "$invDry = " + (dry ? '$true' : '$false'),
            "$invMode = '" + (mode === 'uninstall' ? 'uninstall' : (dry ? 'scan' : 'update')) + "'",
            "$invOnly = '" + onlyId.replace(/'/g, "''") + "'"
        ].concat(obj.psTranscriptLines('invscanner-winget.log'), [
            "$wg = $null",
            "$invAP = $null; if (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\winget.exe') { $invAP = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\winget.exe' -ErrorAction SilentlyContinue).'(default)' }; if ($invAP -and (Test-Path $invAP)) { $wg = $invAP }",
            // Lookup order: App Paths, the admin-only WindowsApps package folder (newest first),
            // then PATH. Get-Command returns an ApplicationInfo whose location is in .Path
            // (.FullName is empty there - the pre-3.0.1 code therefore never used the PATH hit).
            "if (-not $wg) { foreach ($wc in @((Get-ChildItem ($env:ProgramFiles + \"\\WindowsApps\\Microsoft.DesktopAppInstaller_*\\winget.exe\") -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1), (Get-Command winget -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1))) { if ($null -ne $wc) { $invWP = $null; if ($wc.Path) { $invWP = [string]$wc.Path } elseif ($wc.FullName) { $invWP = [string]$wc.FullName }; if ($invWP) { $wg = $invWP; break } } } }",
            "if ($wg -eq $null) { Write-Output '" + obj.WINGET_MARKER + "{\"winget\":false}'; Stop-Transcript -ErrorAction SilentlyContinue | Out-Null; exit }",
            "$invIgnore = @(" + psList + ")",
            "$results = @()"
        ]);
        if (mode === 'uninstall') {
            // existence probe: case-insensitive containment of the id in 'winget list --id X --exact'
            // output - no exit-code mythology and no reliance on (localizable) message text.
            head.push(
                "$invProbe = ''",
                "try { $invProbe = ((& $wg list --id $invOnly --exact --accept-source-agreements --disable-interactivity) 2>&1) -join ' ' } catch { $invProbe = '' }",
                "if ($invProbe -inotmatch ([regex]::Escape($invOnly))) { $results += @{ id = $invOnly; name = ''; from = ''; to = ''; state = 'not-installed' } } else { $o = (& $wg uninstall --id $invOnly --exact --silent --accept-source-agreements --disable-interactivity) 2>&1; $code = $LASTEXITCODE; $tail = (($o | Select-Object -Last 3) -join ' '); if ($tail -isnot [string]) { $tail = [string]$tail }; if ($tail.Length -gt 400) { $tail = $tail.Substring(0,400) }; $st = 'failed'; if ($code -eq 0) { $st = 'ok' }; $results += @{ id = $invOnly; name = ''; from = ''; to = ''; state = $st; exit = $code; log = $tail } }"
            );
        } else {
            head.push(
                "$raw = ''",
                "try { $raw = ((& $wg list --upgrade-available --accept-source-agreements --disable-interactivity) 2>&1) -join [Environment]::NewLine } catch { }",
                "$rows = @()",
                // Table parser (v3.0.1): winget pads columns to a fixed width, so a full-width cell is
                // followed by ONE space only (long names, long ids, long versions, '< x.y' versions).
                // The column starts are therefore taken from the header line above the dash line
                // (language independent: only positions are used); every row is validated (dotted id,
                // non-empty versions/source) and falls back to the old two-space regex when the
                // column cut does not validate. Parsing stops at the table footer.
                "# invscanner:parse-begin",
                "$invLines = @($raw -split '[\\r\\n]+')",
                "$invH = -1; for ($invI = 1; $invI -lt $invLines.Count; $invI++) { if ($invLines[$invI] -match '^\\s*-{10,}\\s*$') { $invH = $invI - 1; break } }",
                "$invC = @(); if ($invH -ge 0) { $invC = @([regex]::Matches($invLines[$invH], '(?:^|(?<=\\s))\\S+') | ForEach-Object { $_.Index }) }",
                "$invEnd = $false; for ($invI = [Math]::Max(0, $invH + 2); ($invI -lt $invLines.Count) -and (-not $invEnd); $invI++) { $line = [string]$invLines[$invI]; $invR = $null; if (($invC.Count -eq 5) -and ($line.Length -gt $invC[4])) { $invR = @($line.Substring(0, $invC[1]).Trim(), $line.Substring($invC[1], $invC[2] - $invC[1]).Trim(), $line.Substring($invC[2], $invC[3] - $invC[2]).Trim(), $line.Substring($invC[3], $invC[4] - $invC[3]).Trim(), $line.Substring($invC[4]).Trim()) }; if (($null -eq $invR) -or ($invR[1] -notmatch '^[A-Za-z0-9._+-]+\\.[A-Za-z0-9._+-]+$') -or ($invR[2] -eq '') -or ($invR[3] -notmatch '^\\S+$') -or ($invR[4] -notmatch '^\\S+$')) { $invR = $null; if ($line -match '^(.+?)\\s{2,}([A-Za-z0-9._+-]+\\.[A-Za-z0-9._+-]+)\\s{2,}(\\S+)\\s{2,}(\\S+)\\s{2,}(\\S+)\\s*$') { $invR = @($matches[1].Trim(), $matches[2], $matches[3], $matches[4], $matches[5]) } }; if ($null -ne $invR) { $rows += [pscustomobject]@{ name = $invR[0]; id = $invR[1]; from = $invR[2]; to = $invR[3] } } elseif (($invH -ge 0) -and (($line -match '^\\s*-{10,}\\s*$') -or ($line -match '^\\s*\\d+\\s'))) { $invEnd = $true } }",
                "# invscanner:parse-end",
                "foreach ($p in $rows) { " + onlyGuard + "$skip = $false; foreach ($ig in $invIgnore) { if ($p.id -ieq $ig) { $skip = $true; break } }; if ($skip) { $results += @{ id = $p.id; name = $p.name; from = $p.from; to = $p.to; state = 'skipped-ignored' }; continue }; if ($p.to -ieq 'Unknown' -or $p.to -eq $p.from) { $results += @{ id = $p.id; name = $p.name; from = $p.from; to = $p.to; state = 'skipped-noversion' }; continue }; " + dryGuard + " $o = (& $wg upgrade --id $p.id --exact --silent --accept-package-agreements --accept-source-agreements --disable-interactivity) 2>&1; $code = $LASTEXITCODE; $tail = (($o | Select-Object -Last 3) -join ' '); if ($tail -isnot [string]) { $tail = [string]$tail }; if ($tail.Length -gt 400) { $tail = $tail.Substring(0,400) }; $st = 'failed'; if ($code -eq 0) { $st = 'ok' }; $results += @{ id = $p.id; name = $p.name; from = $p.from; to = $p.to; state = $st; exit = $code; log = $tail } }"
            );
        }
        return head.concat(pinLines, [
            "if ($null -eq $results) { $results = @() }",
            "@{ winget = $true; dry = $invDry; mode = $invMode; results = @($results) } | ConvertTo-Json -Compress -Depth 5 | ForEach-Object { Write-Output ('" + obj.WINGET_MARKER + "' + $_) }",
            "Stop-Transcript -ErrorAction SilentlyContinue | Out-Null"
        ]).join(String.fromCharCode(10));
    };

    /** @brief Append a line to the winget update log (rotated once at ~5 MB). */
    obj.wgLog = function (line) {
        try {
            var dir = path.dirname(obj.wingetLogPath);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            try { if (fs.existsSync(obj.wingetLogPath) && (fs.statSync(obj.wingetLogPath).size > 5 * 1024 * 1024)) { fs.renameSync(obj.wingetLogPath, obj.wingetLogPath + '.old'); } } catch (e) { }
            fs.appendFileSync(obj.wingetLogPath, new Date().toISOString() + ' ' + line + String.fromCharCode(10));
        } catch (e) { }
    };

    /**
     * @brief Raise a client-side event on the device's events page (MeshCentral
     *   persists DispatchEvent payloads via db.StoreEvent; visibility 'nodes' shows
     *   them to everyone with rights on that machine).
     * @param {string} nodeid - The device.
     * @param {string} msg - One-line summary.
     */
    obj.wgRaiseNodeEvent = function (nodeid, msg) {
        try {
            obj.db.Get(nodeid, function (err, nodes) {
                try {
                    if (err || !nodes || !nodes.length) return;
                    var node = nodes[0];
                    var targets = [nodeid];
                    if (node.meshid != null) { targets.push(node.meshid); }
                    obj.meshServer.DispatchEvent(targets, obj, {
                        etype: 'node', nodeid: nodeid, msg: msg, visibility: 'nodes'
                    });
                } catch (e) { }
            });
        } catch (e) { }
    };

    /** @brief Load persisted last-run results (survives restarts). */
    obj.wgLoadResults = function () {
        obj.wgResults = {};
        try {
            if (fs.existsSync(obj.wingetResultsPath)) {
                var d = JSON.parse(fs.readFileSync(obj.wingetResultsPath, 'utf8'));
                if (d && (typeof d === 'object')) { obj.wgResults = d; }
            }
        } catch (e) { obj.wgResults = {}; }
    };

    /** @brief Persist results (best-effort, non-blocking errors are logged only). */
    obj.wgSaveResults = function () {
        try {
            var dir = path.dirname(obj.wingetResultsPath);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            fs.writeFileSync(obj.wingetResultsPath, JSON.stringify(obj.wgResults));
        } catch (e) { obj.wgLog('could not save results: ' + e.message); }
    };

    /**
     * @brief winget only exists on Windows. A node counts as Windows once the agent
     *   reported an OS description; nodes that never reported stay visible (unknown OS -
     *   excluding them would hide fresh installs).
     * @param {object} node - The node record.
     * @returns {boolean} true unless the node is provably non-Windows.
     */
    obj.wgIsWindowsNode = function (node) {
        if (node == null) return false;
        var o = String(node.osdesc || '');
        if (o === '') return true;
        return /windows/i.test(o);
    };

    /**
     * @brief Resolve the device list for a batch.
     * @param {boolean} onlyMeshes - restrict to the configured meshes (scheduled runs).
     * @param {function} cb - (nodeids)
     */
    obj.wgTargetNodes = function (onlyMeshes, cb) {
        try {
            var wcfg = obj.wingetConfig();
            obj.db.GetAllType('node', function (err, nodes) {
                if (err || !nodes) { return cb([]); }
                var out = [];
                for (var i = 0; i < nodes.length; i++) {
                    var n = nodes[i];
                    if ((n == null) || (n._id == null) || (n.deleted != null)) continue;
                    if (!obj.wgIsWindowsNode(n)) continue;
                    if (onlyMeshes) {
                        if (wcfg.meshes == null) continue; // scheduled: require explicit group opt-in
                        if (wcfg.meshes.indexOf(n.meshid) < 0) continue;
                    }
                    if (wcfg.excludeNodes.indexOf(n._id) >= 0) continue;
                    out.push(n._id);
                }
                cb(out);
            });
        } catch (e) { cb([]); }
    };

    /**
     * @brief Start a batch of winget updates.
     * @param {string} reason - 'scheduled' | 'manual' (logged).
     * @param {function} [done] - optional callback when the batch queue drained.
     * @returns {object} { started, nodes, busy? }
     */
    /**
     * @brief Start a batch of winget updates.
     * @param {string} reason - 'scheduled' | 'sweep' | 'connect' | 'dry-run' | 'manual'.
     * @param {function} [done] - optional callback when the batch queue drained.
     * @param {Array<string>} [nodeids] - explicit device list (skips the scope
     *   filter; used by per-device runs and the dry-run test button).
     * @param {boolean} [dry] - report only: nothing is installed or pinned.
     * @returns {object} { started, nodes, busy? }
     */
    obj.wgStartBatch = function (reason, done, nodeids, dry, opts) {
        // One agent runs ONE runcommands session at a time (meshcore.js answers "already busy"),
        // so winget batches and OS update batches never overlap (v3.5.0).
        if (obj.wgBatchRunning || obj.osBatchRunning) { return { started: false, busy: true, nodes: 0 }; }
        var wcfg = obj.wingetConfig();
        var launch = function (ids) {
            var what = (dry === true) ? 'DRY-RUN' : ((opts != null && opts.mode === 'uninstall') ? 'uninstall batch' : 'update batch');
            if (ids.length === 0) {
                obj.wgLog(what + ' (' + reason + ') - no target devices');
                if (done) done();
                return;
            }
            obj.wgBatchRunning = true;
            obj.wgBatchDry = dry === true;
            obj.wgBatchOpts = opts || null;
            obj.wgLog(what + ' (' + reason + ') starting for ' + ids.length + ' device(s)');
            obj.wgQueue = ids.slice();
            obj.wgBatchDone = done || null;
            obj.wgPump();
        };
        if (Array.isArray(nodeids) && nodeids.length > 0) { launch(nodeids.slice(0, obj.WINGET_MAX_DEVICES)); return { started: true, nodes: 0 }; }
        obj.wgTargetNodes(reason === 'scheduled' || reason === 'sweep', function (ids) {
            launch(ids);
        });
        return { started: true, nodes: 0 };
    };

    /**
     * @brief Wrap the builder script for the agent's cmd.exe runcommands channel (type 1):
     * ONE powershell -Command line carrying the whole script as base64(gzip(UTF-8)); it is
     * decompressed and run in one piece (no per-line stdin parsing, no quoting issues, the
     * line stays far below cmd's 8191 character limit).
     * @param {string} script - The raw PowerShell text from wgBuildScript.
     * @returns {string} The single-line command.
     */
    obj.wgTransport = function (script) {
        var b64 = zlib.gzipSync(Buffer.from(String(script), 'utf8')).toString('base64');
        return 'powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$d=[Convert]::FromBase64String(\'' + b64 + '\');$m=New-Object IO.MemoryStream(,$d);$g=New-Object IO.Compression.GZipStream($m,[IO.Compression.CompressionMode]::Decompress);$s=(New-Object IO.StreamReader($g,[Text.Encoding]::UTF8)).ReadToEnd();Invoke-Expression $s"';
    };

    /** @brief Feed the queue up to WINGET_MAX_PARALLEL devices. */
    obj.wgPump = function () {
        try {
            while ((obj.wgActive < obj.WINGET_MAX_PARALLEL) && (obj.wgQueue.length > 0)) {
                var nodeid = obj.wgQueue.shift();
                if (obj.wgPending[nodeid] != null) continue; // already running there
                var ws = obj.meshServer.webserver;
                if (!obj.routeHookInstalled) { try { obj.installRouteHook(); } catch (e) { } }
                var agent = (ws != null && ws.wsagents != null) ? ws.wsagents[nodeid] : null;
                if ((agent == null) || (typeof agent.send !== 'function')) {
                    obj.wgResults[nodeid] = { time: new Date().toISOString(), error: 'offline', results: [] };
                    obj.wgLog(nodeid + ' - skipped, agent offline');
                    obj.wgRaiseNodeEvent(nodeid, 'Winget updater: skipped, the agent was offline');
                    continue;
                }
                var sid = 'invscanner-wg-' + safeNodeDir(nodeid);
                var entry = { nodeid: nodeid, sid: sid, since: Date.now() };
                entry.timer = setTimeout(function () { obj.wgTimeout(entry); }, obj.wgBatchDry === true ? obj.WINGET_DRY_TIMEOUT_MS : obj.WINGET_RUN_TIMEOUT_MS);
                obj.wgPending[nodeid] = entry;
                obj.wgActive++;
                try {
                    agent.send(JSON.stringify({ action: 'runcommands', type: 1, cmds: obj.wgTransport(obj.wgBuildScript(obj.wingetConfig(), obj.wgBatchDry === true, obj.wgBatchOpts)), runAsUser: 0, reply: true, sessionid: sid, responseid: sid }));
                    obj.wgLog(nodeid + ' - update script sent (client transcript: invscanner-winget.log next to meshagent.exe or in C:\\ProgramData)');
                } catch (ex) {
                    clearTimeout(entry.timer); delete obj.wgPending[nodeid]; obj.wgActive--;
                    obj.wgResults[nodeid] = { time: new Date().toISOString(), error: 'send-failed: ' + ex.message, results: [] };
                    obj.wgLog(nodeid + ' - send failed: ' + ex.message);
                }
            }
            if ((obj.wgActive === 0) && (obj.wgQueue.length === 0) && obj.wgBatchRunning) {
                obj.wgBatchRunning = false;
                obj.wgBatchDry = false;
                obj.wgBatchOpts = null;
                obj.wgSaveResults();
                obj.wgLog('update batch finished');
                var d = obj.wgBatchDone; obj.wgBatchDone = null;
                if (d) d();
            }
        } catch (e) { obj.wgLog('pump error: ' + e.message); }
    };

    /** @brief Watchdog for a device that never answered. */
    obj.wgTimeout = function (entry) {
        if ((entry == null) || (obj.wgPending[entry.nodeid] !== entry)) return;
        delete obj.wgPending[entry.nodeid];
        obj.wgActive--;
        obj.wgResults[entry.nodeid] = { time: new Date().toISOString(), error: 'timeout', results: [] };
        obj.wgLog(entry.nodeid + ' - no answer within the run timeout');
        obj.wgRaiseNodeEvent(entry.nodeid, 'Winget updater: the device did not answer within the timeout');
        obj.wgPump();
    };

    /**
     * @brief Extract the marker payload from an output text. The answer is ONE
     * ConvertTo-Json -Compress line, so the payload ends at the first line break
     * after the marker - anything printed afterwards (e.g. a cmd banner or a
     * transcript notice that was not silenced) cannot corrupt it, and anything
     * before it is ignored. Chunks split across packets are handled by the
     * caller feeding the accumulated buffer (wgPending entry .cbuf).
     * @param {string} text - raw agent output.
     * @returns {object|null} Parsed answer object, null when absent/unparsable.
     */
    obj.wgPayloadFromText = function (text, marker) {
        try {
            var mk = (typeof marker === 'string' && marker !== '') ? marker : obj.WINGET_MARKER;
            var idx = String(text).lastIndexOf(mk);
            if (idx < 0) return null;
            var payload = String(text).substring(idx + mk.length);
            var nl = payload.search(/[\r\n]/);
            if (nl >= 0) payload = payload.substring(0, nl);
            payload = payload.trim();
            if (payload === '' || payload.charAt(0) !== '{') return null;
            return JSON.parse(payload);
        } catch (e) { return null; }
    };

    /**
     * @brief Handle a runcommands response for one of our update sessions.
     * Extracts the marker JSON, normalizes single-element array unrolling that
     * ConvertTo-Json does, stores results and advances the queue.
     * @param {string} nodeid - device the answer came from.
     * @param {object} command - the agent message (result text).
     */
    obj.wgHandleResponse = function (nodeid, command) {
        var entry = obj.wgPending[nodeid];
        if (entry == null) return; // not ours (e.g. a browser-initiated runcommands session)
        if (entry.timer) { clearTimeout(entry.timer); }
        delete obj.wgPending[nodeid];
        obj.wgActive--;
        var text = (typeof command.result === 'string') ? command.result : JSON.stringify(command.result || '');
        var rec = { time: new Date().toISOString(), winget: false, dry: obj.wgBatchDry === true, mode: (obj.wgBatchOpts && obj.wgBatchOpts.mode) || '', results: [] };
        var data = obj.wgPayloadFromText(text);
        var hadMarker = (text.indexOf(obj.WINGET_MARKER) >= 0);
        if ((data == null) && (typeof entry.cbuf === 'string') && (entry.cbuf !== '')) { data = obj.wgPayloadFromText(entry.cbuf); hadMarker = hadMarker || (entry.cbuf.indexOf(obj.WINGET_MARKER) >= 0); } // answer line was chunk-split on the console channel
        if (data != null) {
            rec.winget = (data.winget === true);
            var rr = data.results;
            if (rr == null) { rr = []; } else if (!Array.isArray(rr)) { rr = [rr]; } // PS unwraps single-element arrays
            rec.results = rr.filter(function (x) { return x && (typeof x.id === 'string'); }).map(function (x) {
                return { id: x.id, name: (typeof x.name === 'string') ? x.name.substring(0, 200) : '', from: String(x.from == null ? '' : x.from).substring(0, 60), to: String(x.to == null ? '' : x.to).substring(0, 60), state: String(x.state || 'unknown').substring(0, 40), exit: (typeof x.exit === 'number') ? x.exit : null, log: String(x.log || '').substring(0, 500) };
            });
        } else { rec.error = hadMarker ? 'unparsable payload' : 'no marker in output'; }
        obj.wgResults[nodeid] = rec;
        var okN = 0, skipN = 0, failN = 0, wouldN = 0;
        for (var i = 0; i < rec.results.length; i++) {
            var s = rec.results[i].state;
            if (s === 'ok') okN++; else if (s === 'dry-run') wouldN++; else if (s.indexOf('skipped') === 0 || s === 'not-installed') skipN++; else failN++;
        }
        obj.wgLog(nodeid + ' - ' + (rec.dry ? '[dry-run] ' : '') + (rec.error || (rec.winget ? (rec.dry ? ('would update ' + wouldN + ', ' + skipN + ' skipped, ' + failN + ' failed') : (rec.mode === 'uninstall' ? ('done: ' + okN + ' uninstalled, ' + skipN + ' skipped/not-installed, ' + failN + ' failed') : ('done: ' + okN + ' updated, ' + skipN + ' skipped, ' + failN + ' failed'))) : 'winget not available')));
        // Per-package detail lines so failures never require opening the client transcript:
        // one FAILED line with exit code + winget's own (system) message per failed package,
        // and a WARNING when the client upgraded a package that was on the ignore list.
        var evMsg = 'Winget updater: ' + (rec.error || (rec.winget === false ? 'winget is not available on this device' : (rec.dry ? ('dry run - ' + wouldN + ' package(s) would be updated') : (rec.mode === 'uninstall' ? (okN + ' package(s) uninstalled, ' + failN + ' failed') : (okN + ' package(s) updated, ' + failN + ' failed')))));
        if (rec.error == null) {
            var ignIds = [];
            try { var igl = obj.wingetConfig().ignorePackages; for (var zi = 0; zi < igl.length; zi++) { ignIds.push({ raw: String(igl[zi].id), lc: String(igl[zi].id).toLowerCase() }); } } catch (e) { }
            var failIds = [];
            for (var fi = 0; fi < rec.results.length; fi++) {
                var fr = rec.results[fi];
                if (fr.state === 'failed') {
                    failIds.push(fr.id);
                    obj.wgLog(nodeid + ' - FAILED ' + fr.id + ' [' + fr.from + ' -> ' + fr.to + '] exit ' + (fr.exit == null ? '?' : (fr.exit + ' (0x' + obj.wgExitHex(fr.exit) + ')')) + ': ' + String(fr.log || '').replace(/[\r\n]+/g, ' ').replace(/\s+/g, ' ').trim());
                } else if (fr.state === 'ok' && rec.dry !== true && rec.mode !== 'uninstall') {
                    // An upgraded package that the ignore list should have covered is never silent:
                    // exact hits mean the script ran without the current list, near misses mean the
                    // stored id does not equal the id winget reports on this device.
                    var fid = String(fr.id).toLowerCase(), exact = false, near = null;
                    for (var qi = 0; qi < ignIds.length; qi++) {
                        var gi = ignIds[qi].lc;
                        if (gi === fid) { exact = true; break; }
                        if (gi.length > 4 && fid.length > 4 && (fid.indexOf(gi) >= 0 || gi.indexOf(fid) >= 0)) { near = ignIds[qi].raw; }
                    }
                    if (exact) { obj.wgLog(nodeid + ' - WARNING ' + fr.id + ' is on the ignore list but was upgraded anyway (it was missing from the script that ran)'); }
                    else if (near != null) { obj.wgLog(nodeid + ' - WARNING ' + fr.id + ' was upgraded although the similar ignore entry "' + near + '" exists - ids do not match exactly, fix it from the device list (+ ignore)'); }
                }
            }
            if ((!rec.dry) && failIds.length > 0) { evMsg += ' (' + failIds.slice(0, 3).join(', ') + (failIds.length > 3 ? ', ...' : '') + ')'; }
        }
        obj.wgRaiseNodeEvent(nodeid, evMsg);
        obj.wgSaveResults();
        obj.wgPump();
    };

    /**
     * @brief Superseded-row pruning for the software list. Two registry rows
     * that resolve to the SAME CPE product AND the SAME arch-aware display name
     * are one program with a leftover uninstall entry (classic: "Mozilla Firefox
     * 3.6.24 (x86 de-DE)" still listed next to "Firefox 121.0.1", or a chain of
     * "Java 8 Update NNN" rows); the newer version wins. Rows that merely share
     * a CPE product mapping but differ in display name or architecture are
     * DISTINCT installs and always coexist (verified on a real fleet:
     * "Microsoft Edge" vs "Microsoft Edge WebView2-Laufzeit", VC++ 2008 x64 vs
     * x86 - silently merging them drops inventory rows the agent really
     * reported and attributes CVEs to the wrong product). Python / .NET-style
     * products key on major(.minor) because they genuinely install side by
     * side. Rows with an unknown version are never treated as superseded.
     * @param {Array<object>} softwareList - raw rows ({ name, version, publisher }).
     * @returns {Array<object>} pruned list; input is not modified.
     */
    /**
     * @brief Architecture signature of a display name ('64' / '32' / '' when
     *   not stated or both mentioned). Kept out of the name token on purpose:
     *   the token strips arch noise, the sig restores the distinction for the
     *   supersede check so x86 and x64 installs never merge.
     * @param {string} name - Display name.
     * @returns {string} The signature.
     */
    obj.pruneArchSig = function (name) {
        var n = String(name).toLowerCase();
        var b64 = /(x64|amd64|arm64|aarch64|64[ -]?bit)/.test(n);
        var b32 = /(x86|i386|32[ -]?bit)/.test(n);
        return (b64 && !b32) ? '64' : ((b32 && !b64) ? '32' : '');
    };

    /** @brief Name token with the vendor's own leading name word stripped, so the
     *  same product labeled "Mozilla Firefox" / "Firefox" still compares equal. */
    obj.pruneNameKey = function (name, vendor) {
        var tok = obj.pruneNameToken(name);
        var words = String(vendor || '').toLowerCase().replace(/[_+]+/g, ' ').split(' ');
        var changed = true;
        while (changed) {
            changed = false;
            for (var wi = 0; wi < words.length; wi++) {
                var w = words[wi];
                if (w !== '' && tok.indexOf(w + ' ') === 0) { tok = tok.substring(w.length + 1); changed = true; }
            }
        }
        return tok;
    };
    /**
     * @brief Version/arch/locale-stripped lowercase name token for the prune
     *   grouping key when no CPE mapping resolves; needs no NVD index.
     * @param {string} name - Display name.
     * @returns {string} The token.
     */
    obj.pruneNameToken = function (name) {
        return String(name).toLowerCase()
            .replace(/\(.*?\)/g, ' ')
            .replace(/\b\d+(?:[._-]\d+)*\b/g, ' ')
            .replace(/\b(x86|x64|arm64?|arm|64[ -]?bit|32[ -]?bit|[a-z][a-z][-_][A-Za-z]{2,4}|update|edition|beta|rc)\b/gi, ' ')
            .replace(/[^a-z0-9+.#]+/g, ' ')
            .replace(/\s+/g, ' ').trim().toLowerCase();
    };

    obj.pruneSuperseded = function (softwareList) {
        if (!Array.isArray(softwareList)) return [];
        // Products that genuinely install side by side, keyed by the CPE product token the mapping
        // actually produces (v3.0.1: '.net', 'visual_c\\+\\+' and friends were missing, so VC++ 2008 /
        // 2015 and .NET 8 / 10 runtimes collapsed into one row and the older one was never scanned).
        var SIDE_BY_SIDE = { jre: 1, jdk: 1, java: 1, net_framework: 1, '.net_framework': 1, '.net': 1, '.net_core': 1, 'asp.net_core': 1, dotnet: 1, python: 2, visual_c: 1, 'visual_c\\+\\+': 1, 'visual_c++': 1, 'visual_c\\+\\+_redistributable': 1, 'visual_c++_redistributable': 1, vcredist: 1 };
        var groups = {}, drop = {};
        for (var i = 0; i < softwareList.length; i++) {
            var sw = softwareList[i];
            if (sw == null) { drop[i] = true; continue; }
            var name = String(sw.name || sw.Name || sw.displayName || sw.DisplayName || '');
            var version = String(sw.version != null ? sw.version : (sw.Version != null ? sw.Version : ''));
            var vm = String(obj.normalizeCveVersion(version) || version).trim().match(/^(?:0?v|v)?(\d+)(?:[._](\d+))?/);
            var key = null, tok = '', arch = '';
            if (name !== '' && vm != null) {
                var pub = String(sw.publisher || sw.Publisher || '');
                var mapped = null;
                try { mapped = obj.deriveCpeProduct(pub, name); } catch (e) { }
                var product, vendor;
                if (mapped != null) { product = mapped.product; vendor = mapped.vendor; tok = obj.pruneNameKey(name, mapped.vendor); }
                else {
                    product = obj.pruneNameToken(name);
                    vendor = null;
                    try { vendor = obj.deriveVendorFromPublisher(pub); } catch (e2) { }
                    if (vendor == null) { vendor = '?'; }
                    else if (product.indexOf(vendor + ' ') === 0) { product = product.substring(vendor.length + 1); }
                    // "Mozilla Firefox 3.6" (unmapped form) vs "Firefox 121" is ONE program:
                    // the coexistence token must ignore the vendor's own leading name word too.
                    tok = obj.pruneNameKey(name, vendor);
                }
                var mode = SIDE_BY_SIDE[String(product).toLowerCase()] || 0;
                var grp = mode === 1 ? vm[1] : (mode === 2 ? (vm[2] != null ? vm[1] + '.' + vm[2] : vm[1]) : 'all');
                key = (vendor || '?') + '|' + String(product).toLowerCase() + '@' + grp;
                arch = obj.pruneArchSig(name);
            }
            if (key == null) continue; // unversioned / nameless rows are never treated as superseded
            var g = groups[key] || (groups[key] = []);
            var keep = true;
            for (var gi = 0; gi < g.length; gi++) {
                var e3 = g[gi];
                if (e3.tok !== tok || e3.arch !== arch) continue; // different install variant - coexists
                var cv = 0;
                try { cv = obj.compareCpeVersions(version, e3.version); } catch (e4) { cv = 0; }
                if (cv > 0) { drop[e3.i] = true; g.splice(gi, 1); gi--; } // newer leftover-free row wins
                else { keep = false; break; } // an equal-or-newer row of the same program already survives
            }
            if (keep) { g.push({ i: i, version: version, tok: tok, arch: arch }); } else { drop[i] = true; }
        }
        var out = [];
        for (var oi = 0; oi < softwareList.length; oi++) { if (!drop[oi]) out.push(softwareList[oi]); }
        return out;
    };

    /** @type {string} what the UI shows instead of the removed interval setting. */
    obj.WINGET_SCHEDULING_DESC = 'daily - right after a device connects on a new calendar day, and at the latest 24 h after its previous automatic run';


    /** @type {number} sweep cadence for the due check (ms); not a user setting. */
    obj.WINGET_SWEEP_MS = 60 * 60 * 1000;
    /** @type {number} force a refresh after this much continuous uptime (ms). */
    obj.WINGET_MAX_AGE_MS = 24 * 60 * 60 * 1000;

    /**
     * @brief Two-stage automatic-update policy (replaces the old interval):
     * a device is due when it never ran, when its last run lies on an earlier
     * calendar day, or when that run is 24h+ old (long-lived connection).
     * @param {string} nodeid - Node id.
     * @param {object} [results] - override map for testing.
     * @param {number} [now] - override now (epoch ms).
     * @returns {boolean} true when an automatic batch should cover the device.
     */
    obj.wgNodeDue = function (nodeid, results, now) {
        var res = results || obj.wgResults || {};
        var t = (res[nodeid] && res[nodeid].time) ? Date.parse(res[nodeid].time) : 0;
        if (!t || isNaN(t)) return true;
        var n = now || Date.now();
        var d = new Date(t), e = new Date(n);
        if (d.getFullYear() !== e.getFullYear() || d.getMonth() !== e.getMonth() || d.getDate() !== e.getDate()) return true;
        return (n - t) >= obj.WINGET_MAX_AGE_MS;
    };

    /**
     * @brief Agent-connect / sweep entry for ONE device: runs it when enabled,
     * in scope, not excluded, due and no batch/pending run is in flight.
     * @param {string} nodeid - Node id.
     * @param {string} reason - 'connect' | 'sweep' (logged).
     */
    obj.wgQueueNode = function (nodeid, reason) {
        try {
            var wcfg = obj.wingetConfig();
            if (!wcfg.enabled) return false;
            if (wcfg.excludeNodes.indexOf(nodeid) >= 0) return false;
            if (obj.wgBatchRunning || obj.osBatchRunning || (obj.wgPending && obj.wgPending[nodeid] != null)) return false;
            if (!obj.wgNodeDue(nodeid)) return false;
            if (wcfg.meshes != null) {
                obj.db.Get(nodeid, function (err, node) {
                    try {
                        if (err || (node == null) || node.deleted != null) return;
                        if (wcfg.meshes.indexOf(node.meshid) < 0) return;
                        if (obj.wgBatchRunning) return;
                        obj.wgLog('auto-update (' + reason + ') for one device');
                        obj.wgStartBatch(reason, null, [nodeid], false);
                    } catch (e) { }
                });
                return true;
            }
            obj.wgLog('auto-update (' + reason + ') for one device');
            obj.wgStartBatch(reason, null, [nodeid], false);
            return true;
        } catch (e) { return false; }
    };

    /**
     * @brief One sweep pass over scheduled-scope devices: queue the ONLINE and
     * due ones as a batch. Scheduled by scheduleWingetUpdates hourly.
     */
    obj.wgSweepOnce = function (done) {
        var wcfg = obj.wingetConfig();
        if (!wcfg.enabled) { if (done) done(); return; }
        obj.wgTargetNodes(true, function (ids) {
            var ws = obj.meshServer.webserver;
            var due = [];
            for (var i = 0; i < ids.length; i++) {
                var online = (ws != null && ws.wsagents != null && ws.wsagents[ids[i]] != null);
                if (online && obj.wgNodeDue(ids[i])) due.push(ids[i]);
            }
            if (due.length === 0) { if (done) done(); return; }
            obj.wgLog('sweep: ' + due.length + ' due device(s)');
            obj.wgStartBatch('sweep', done, due, false);
        });
    };

    /**
     * @brief Hourly sweep loop (restart-proof gen guard). Devices that
     * reconnect are covered immediately by the agent-connect hook; this loop
     * catches devices whose connection simply outlives the day boundary.
     */
    obj.scheduleWingetUpdates = function () {
        var wcfg = obj.wingetConfig();
        if (!wcfg.enabled) { return; }
        var gen = obj.timerGen;
        obj.longTimeout(function () {
            if (!obj.timerValid(gen)) { return; }
            obj.wgSweepOnce(function () { obj.scheduleWingetUpdates(); });
        }, obj.WINGET_SWEEP_MS);
    };


    // ---- winget updater HTTP handlers ----

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
     * @param {object} req - body.type: 'nvd' | 'winget'.
     */
    obj.getLogHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        var t = String((req.body && req.body.type) || '');
        if (t === 'nvd') { var n = obj.tailLogFile(path.join(obj.nvdDataPath, 'nvd-download.log')); n.file = 'nvd/nvd-download.log'; return send(n); }
        if (t === 'winget') { var w = obj.tailLogFile(obj.wingetLogPath); w.file = 'plugins/inventoryscanner/winget-update.log'; return send(w); }
        if (t === 'os') { var o = obj.tailLogFile(obj.osLogPath); o.file = 'plugins/inventoryscanner/os-update.log'; return send(o); }
        send({ error: 'Unknown log type (nvd|winget|os).' });
    };

    /** @brief POST wg_get_config: effective winget-updater config + per-key source. */
    obj.wgGetConfigHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        var wcfg = obj.wingetConfig();
        var over = obj.pluginSettings.wingetUpdater || {};
        var b = null;
        try { b = obj.meshServer.config.settings.wingetUpdater; } catch (e) { }
        var srcOf = function (key) {
            if (Object.prototype.hasOwnProperty.call(over, key)) { return 'file'; }
            if (b && Object.prototype.hasOwnProperty.call(b, key)) { return 'config.json'; }
            return 'default';
        };
        send({
            config: {
                enabled: wcfg.enabled, scheduling: obj.WINGET_SCHEDULING_DESC,
                updateMeshes: wcfg.meshes || [], excludeNodes: wcfg.excludeNodes,
                ignorePackages: wcfg.ignorePackages, pinSync: wcfg.pinSync
            },
            sources: {
                enabled: srcOf('enabled'),
                updateMeshes: srcOf('updateMeshes'), excludeNodes: srcOf('excludeNodes'),
                ignorePackages: srcOf('ignorePackages'), pinSync: srcOf('pinSync')
            },
            running: obj.wgBatchRunning, active: obj.wgActive, queued: obj.wgQueue.length
        });
    };

    /** @brief POST wg_save_config: validate everything, store override, reschedule. */
    obj.wgSaveConfigHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        var body = (req.body || {});
        var meshes = parseMeshIds(body.updateMeshes);
        var excludes = [];
        if (typeof body.excludeNodes === 'string') {
            excludes = body.excludeNodes.split(',').map(function (x) { return x.trim(); }).filter(function (x) { return x !== ''; });
        } else if (Array.isArray(body.excludeNodes)) { excludes = body.excludeNodes; }
        for (var ei = 0; ei < excludes.length; ei++) {
            if (typeof excludes[ei] !== 'string' || !/^node\/[^:]{1,100}$/.test(excludes[ei])) { return send({ error: 'Invalid excluded node id.' }); }
        }
        var ignore = [];
        var ig = body.ignorePackages;
        if (typeof ig === 'string') { try { ig = JSON.parse(ig); } catch (e) { ig = null; } }
        if (ig == null) { ig = []; }
        if (!Array.isArray(ig) || ig.length > 500) { return send({ error: 'Invalid ignore list (max 500 entries).' }); }
        for (var ii = 0; ii < ig.length; ii++) {
            var ent = ig[ii];
            if ((ent == null) || (typeof ent.id !== 'string') || !obj.WINGET_ID_RE.test(ent.id.trim())) { return send({ error: 'Invalid package id in ignore list.' }); }
            var nid = ent.id.trim();
            if (!ignore.some(function (x) { return x.id === nid; })) {
                ignore.push({ id: nid, note: (typeof ent.note === 'string') ? ent.note.trim().substring(0, 200) : '' });
            }
        }
        obj.pluginSettings.wingetUpdater = {
            enabled: boolSetting(body.enabled, false),
            updateMeshes: meshes,
            excludeNodes: excludes,
            ignorePackages: ignore,
            pinSync: boolSetting(body.pinSync, true)
        };
        obj.savePluginSettings(function (err) {
            if (err) { return send({ error: err.message }); }
            obj.rescheduleAll();
            obj.wgGetConfigHandler({}, res, user);
        });
    };

    /**
     * @brief POST wg_run: manual batch; optional nodeIds (one or several
     *   devices, bypasses scope filters), dry=true (report only) and the
     *   per-package mode: pkgId (exact winget id, validated) limits the batch
     *   to that ONE package across all targeted devices, mode 'update'
     *   (default) upgrades it everywhere, 'uninstall' removes it everywhere
     *   (devices without the package report 'not-installed'). Uninstall never
     *   runs dry and always requires pkgId.
     */
    obj.wgRunHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        if (obj.wgBatchRunning || obj.osBatchRunning) { return send({ started: false, busy: true }); }
        var body = (req.body || {});
        var ids = null;
        if (body.nodeIds != null) {
            var arr = body.nodeIds;
            if (typeof arr === 'string') { try { arr = JSON.parse(arr); } catch (e) { arr = arr.split(','); } }
            if (!Array.isArray(arr)) arr = [arr];
            ids = [];
            for (var i = 0; i < arr.length && ids.length < 200; i++) {
                var x = String(arr[i] == null ? '' : arr[i]).trim();
                if (x !== '' && /^node\/[^:]{1,100}$/.test(x) && ids.indexOf(x) < 0) ids.push(x);
            }
            if (ids.length === 0) { return send({ error: 'Invalid nodeIds.' }); }
        }
        var dry = (body.dry === 'true' || body.dry === true);
        var pkgId = (typeof body.pkgId === 'string') ? body.pkgId.trim() : '';
        var mode = (body.mode === 'uninstall') ? 'uninstall' : (body.mode === 'update' ? 'update' : '');
        if (pkgId !== '' && !obj.WINGET_ID_RE.test(pkgId)) { return send({ error: 'Invalid package id.' }); }
        if (mode === 'uninstall') {
            if (pkgId === '') { return send({ error: 'Uninstall needs an exact package id.' }); }
            if (dry) { return send({ error: 'Uninstall does not support dry runs.' }); }
        }
        var opts = (pkgId !== '' || mode !== '') ? { onlyId: (pkgId !== '' ? pkgId : null), mode: (mode !== '' ? mode : 'update') } : null;
        if (opts != null && opts.onlyId == null) delete opts.onlyId;
        var reason = (mode === 'uninstall') ? 'pkg-uninstall' : (pkgId !== '' ? 'pkg-update' : (dry ? 'dry-run' : 'manual'));
        var r = obj.wgStartBatch(reason, null, ids, dry, opts);
        send({ started: !!r.started, busy: !!r.busy, dry: dry, pkgId: pkgId, mode: (mode !== '' ? mode : 'update'), devices: ids == null ? -1 : ids.length });
    };

    /**
     * @brief POST wg_programs: the per-program view across all devices.
     * Aggregates the stored per-device run results (last run per device, dry
     * or real) into one row per winget package id: which devices carry it,
     * from which version to which, and which state the last run produced -
     * the base for "update/uninstall this program on every device at once".
     * Stale device ids (deleted nodes) are dropped.
     */
    obj.wgProgramsHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        obj.db.GetAllType('node', function (nerr, nodes) {
            var labels = {};
            if (!nerr && nodes) {
                for (var i = 0; i < nodes.length; i++) {
                    var n = nodes[i];
                    if ((n == null) || (n._id == null) || (n.deleted != null)) continue;
                    labels[n._id] = ((typeof n.name === 'string' && n.name.trim() !== '') ? n.name.trim() : '') || obj.getHostName(n) || n._id;
                }
            }
            var byId = {}, order = [];
            var nodeids = Object.keys(obj.wgResults);
            for (var k = 0; k < nodeids.length; k++) {
                var rec = obj.wgResults[nodeids[k]];
                if ((rec == null) || (labels[nodeids[k]] == null)) continue; // deleted/unknown device
                var rl = Array.isArray(rec.results) ? rec.results : [];
                for (var ri = 0; ri < rl.length; ri++) {
                    var r2 = rl[ri];
                    if ((r2 == null) || (typeof r2.id !== 'string') || r2.id === '') continue;
                    var p = byId[r2.id];
                    if (p == null) { p = byId[r2.id] = { id: r2.id, name: '', devices: [], ready: 0, ok: 0, failed: 0, skipped: 0 }; order.push(r2.id); }
                    if ((p.name === '') && (typeof r2.name === 'string')) { p.name = r2.name; }
                    var st = String(r2.state || '');
                    if (st === 'dry-run') p.ready++;
                    else if (st === 'ok') p.ok++;
                    else if (st === 'failed') p.failed++;
                    else p.skipped++;
                    p.devices.push({ node: nodeids[k], label: labels[nodeids[k]], state: st || 'unknown', from: String(r2.from || '').substring(0, 60), to: String(r2.to || '').substring(0, 60), time: rec.time || '', dry: rec.dry === true });
                }
            }
            var pkgs = order.map(function (x) { return byId[x]; });
            pkgs.sort(function (a, b) { return (b.ready + b.failed) - (a.ready + a.failed) || String(a.id).localeCompare(String(b.id)); });
            if (pkgs.length > 400) pkgs = pkgs.slice(0, 400);
            for (var pi = 0; pi < pkgs.length; pi++) { if (pkgs[pi].devices.length > 200) pkgs[pi].devices = pkgs[pi].devices.slice(0, 200); }
            send({ packages: pkgs, note: (pkgs.length === 0) ? 'No stored run results yet - start a dry run to populate this table.' : '' });
        });
    };

    /**
     * @brief POST wg_status: per-device table for the Updates tab.
     * All desktop nodes with group, online flag, exclusion and the compact
     * summary of the last run (ok/skipped/failed counts, error state).
     */
    obj.wgStatusHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        var wcfg = obj.wingetConfig();
        obj.db.GetAllType('mesh', function (merr, meshes) {
            var meshNames = {};
            if (!merr && meshes) {
                for (var mi = 0; mi < meshes.length; mi++) {
                    var m = meshes[mi];
                    if ((m != null) && (m._id != null) && (m.deleted == null)) { meshNames[m._id] = (m.name != null) ? m.name : m._id; }
                }
            }
            obj.db.GetAllType('node', function (nerr, nodes) {
                var devices = [];
                var ws = obj.meshServer.webserver;
                if (!nerr && nodes) {
                    for (var i = 0; i < nodes.length; i++) {
                        var n = nodes[i];
                        if ((n == null) || (n._id == null) || (n.deleted != null)) continue;
                        if (!obj.wgIsWindowsNode(n)) continue;
                        var rec = obj.wgResults[n._id];
                        var sum = null;
                        if (rec != null) {
                            var okN = 0, skN = 0, faN = 0, wdN = 0;
                            var pkgRows = [];
                            var rl = Array.isArray(rec.results) ? rec.results : [];
                            for (var ri = 0; ri < rl.length; ri++) {
                                var s = (rl[ri] && rl[ri].state) ? rl[ri].state : '';
                                // Every package row of the last run (dry or real) goes into rows so the
                                // panel can list outcome, exit code and winget's message per package -
                                // nobody should need the client transcript to find out what failed.
                                if (s === 'ok') okN++;
                                else if (s === 'dry-run') wdN++;
                                else if (s.indexOf('skipped') === 0 || s === 'not-installed') skN++; else faN++;
                                if (rl[ri] != null && pkgRows.length < 200) {
                                    pkgRows.push({ id: String(rl[ri].id || '').substring(0, 128), name: String(rl[ri].name || '').substring(0, 200), from: String(rl[ri].from || '').substring(0, 60), to: String(rl[ri].to || '').substring(0, 60), state: s || 'unknown', exit: (typeof rl[ri].exit === 'number') ? rl[ri].exit : null, log: String(rl[ri].log || '').substring(0, 500) });
                                }
                            }
                            sum = { time: rec.time, winget: rec.winget === true, dry: rec.dry === true, ok: okN, would: wdN, skipped: skN, failed: faN, error: rec.error || '', rows: pkgRows };
                        }
                        devices.push({
                            id: n._id, host: obj.getHostName ? obj.getHostName(n) : (n.rname || n.name || n._id),
                            given: (typeof n.name === 'string' && n.name.trim() !== '') ? n.name.trim() : '',
                            group: meshNames[n.meshid] || n.meshid || '',
                            online: (ws != null && ws.wsagents != null && ws.wsagents[n._id] != null),
                            excluded: wcfg.excludeNodes.indexOf(n._id) >= 0,
                            inScope: (wcfg.meshes == null) ? false : (wcfg.meshes.indexOf(n.meshid) >= 0),
                            last: sum, pending: (obj.wgPending != null && obj.wgPending[n._id] != null) ? { since: (obj.wgPending[n._id].since || 0) } : null
                        });
                    }
                }
                devices.sort(function (a, b) { return (a.group === b.group) ? String(a.given || a.host).localeCompare(String(b.given || b.host)) : String(a.group).localeCompare(String(b.group)); });
                send({
                    devices: devices, running: obj.wgBatchRunning, active: obj.wgActive, queued: obj.wgQueue.length,
                    config: { enabled: wcfg.enabled, scheduling: obj.WINGET_SCHEDULING_DESC, updateMeshes: wcfg.meshes || [], excludeNodes: wcfg.excludeNodes, ignorePackages: wcfg.ignorePackages, pinSync: wcfg.pinSync }
                });
            });
        });
    };


    // ---- OS updates and OS upgrades (v3.5.0) ----
    // Two manual fleet actions next to the winget engine, same transport and answer pattern:
    //  - 'update':  Windows = search + download + install through the built-in Windows Update
    //               agent (COM Microsoft.Update.Session); Linux = the distribution's package
    //               manager (apt-get update + upgrade, dnf, yum, zypper, pacman, apk).
    //  - 'upgrade': only devices whose OS release is PROVABLY not current. "Current" comes only from
    //               fresh endoflife.date data (no hard-coded fallback release - it would go stale);
    //               without it the state is 'unknown', the reason is shown and nothing is upgraded.
    //               Windows 10/11 = the same
    //               Windows Update run with the documented TargetReleaseVersion policy set to the
    //               current release (restored afterwards); Ubuntu = apt-get dist-upgrade followed by
    //               do-release-upgrade (non-interactive). Other distributions have no supported
    //               in-place tool and are reported as unsupported, never guessed.
    // runcommands type 1 = cmd.exe (Windows), type 3 = /bin/sh (Linux) - verified in meshcore.js.
    // Nothing ever reboots a device; a pending reboot is reported per device.

    /** @type {string} last OS run per node (state file). */
    obj.osResultsPath = path.join(obj.meshServer.datapath, 'plugins', 'inventoryscanner', 'os-results.json');
    /** @type {string} OS update log (shown in the UI, rotated at ~5 MB). */
    obj.osLogPath = path.join(obj.meshServer.datapath, 'plugins', 'inventoryscanner', 'os-update.log');
    obj.osPending = {};
    obj.osQueue = [];
    obj.osActive = 0;
    obj.osResults = {};
    obj.osBatchRunning = false;
    obj.osBatchMode = '';
    obj.OS_MARKER = '@@INVOSU@@';
    obj.OS_MAX_PARALLEL = 2;
    /** @type {number} Windows Update scans/installs and release upgrades are slow. */
    obj.OS_RUN_TIMEOUT_MS = 4 * 60 * 60 * 1000;
    /** @type {number} lifecycle data older than this is not trusted to name the CURRENT release.
     *  There is deliberately NO hard-coded fallback release: any built-in value would silently go
     *  stale, so without fresh data the state is 'unknown' and nothing is upgraded. */
    obj.OS_REFERENCE_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;

    /** @brief Append a line to the OS update log (rotated once at ~5 MB). */
    obj.osLog = function (line) {
        try {
            var dir = path.dirname(obj.osLogPath);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            try { if (fs.existsSync(obj.osLogPath) && (fs.statSync(obj.osLogPath).size > 5 * 1024 * 1024)) { fs.renameSync(obj.osLogPath, obj.osLogPath + '.old'); } } catch (e) { }
            fs.appendFileSync(obj.osLogPath, new Date().toISOString() + ' ' + line + String.fromCharCode(10));
        } catch (e) { }
    };

    obj.osLoadResults = function () {
        obj.osResults = {};
        try { if (fs.existsSync(obj.osResultsPath)) { var d = JSON.parse(fs.readFileSync(obj.osResultsPath, 'utf8')); if (d && typeof d === 'object') { obj.osResults = d; } } } catch (e) { obj.osResults = {}; }
    };

    obj.osSaveResults = function () {
        try {
            var dir = path.dirname(obj.osResultsPath);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            fs.writeFileSync(obj.osResultsPath, JSON.stringify(obj.osResults));
        } catch (e) { obj.osLog('could not save results: ' + e.message); }
    };

    /**
     * @brief Shell family of a node. Unknown OS -> null: without a reported OS the right
     * shell cannot be chosen, so such devices are never touched.
     * @returns {string|null} 'windows' | 'linux' | null
     */
    obj.osPlatformOf = function (node) {
        var d = String((node && node.osdesc) || '');
        if (d === '') return null;
        if (/windows/i.test(d)) return 'windows';
        if (/android|\bios\b|ipados|mac\s?os|darwin/i.test(d)) return null;
        if (/linux|ubuntu|debian|fedora|centos|red hat|rhel|rocky|almalinux|suse|mint|alpine|arch|manjaro|raspbian|pop!_os/i.test(d)) return 'linux';
        return null;
    };

    /** @brief '23h2' -> 232 for ordering Windows releases. */
    function winRelNum(r) { var m = String(r || '').match(/^(\d{2})h([12])$/i); return m ? (parseInt(m[1], 10) * 10 + parseInt(m[2], 10)) : 0; }
    /** @brief '22.04' -> 2204 for ordering Ubuntu releases. */
    function ubuRelNum(r) { var m = String(r || '').match(/^(\d{2})\.(\d{2})$/); return m ? (parseInt(m[1], 10) * 100 + parseInt(m[2], 10)) : 0; }

    /**
     * @brief Check that the cached lifecycle data of one product can name the current release.
     * @returns {string} '' when usable, else the reason why not (shown to the admin).
     */
    obj.osReferenceProblem = function (slug, now) {
        var rec = obj.osLifecycle[slug];
        if (!obj.scannerConfig().osLifecycleEnabled) return 'fetching OS support dates is switched off (Settings tab)';
        if (!rec || !Array.isArray(rec.cycles) || rec.cycles.length === 0) return 'no endoflife.date data for "' + slug + '" yet (fetched with the next NVD refresh)';
        var t = Date.parse(rec.fetched || '');
        if (isNaN(t)) return 'endoflife.date data for "' + slug + '" has no fetch date';
        if (((now != null) ? now : Date.now()) - t > obj.OS_REFERENCE_MAX_AGE_MS) return 'endoflife.date data for "' + slug + '" is older than 30 days (last fetched ' + rec.fetched.substring(0, 10) + ')';
        return '';
    };

    /**
     * @brief Newest Windows 11 release according to the cached endoflife.date data.
     * @returns {object} { release: '25h2'-style or '', reason: '' or why it is unknown }
     */
    obj.osCurrentWindows11 = function (now) {
        var why = obj.osReferenceProblem('windows', now);
        if (why !== '') return { release: '', reason: why };
        var best = '', cy = obj.osLifecycle.windows.cycles;
        for (var i = 0; i < cy.length; i++) {
            var m = String(cy[i].cycle).toLowerCase().match(/^11-(\d{2}h[12])(?:-[we])?$/);
            if (m && winRelNum(m[1]) > winRelNum(best)) best = m[1];
        }
        return best ? { release: best, reason: '' } : { release: '', reason: 'the endoflife.date data lists no Windows 11 release' };
    };

    /**
     * @brief Newest Ubuntu LTS release according to the cached endoflife.date data.
     * @returns {object} { release: '24.04'-style or '', reason: '' or why it is unknown }
     */
    obj.osCurrentUbuntuLts = function (now) {
        var why = obj.osReferenceProblem('ubuntu', now);
        if (why !== '') return { release: '', reason: why };
        var best = '', cy = obj.osLifecycle.ubuntu.cycles;
        for (var i = 0; i < cy.length; i++) {
            if (cy[i].lts === true && ubuRelNum(cy[i].cycle) > ubuRelNum(best)) best = cy[i].cycle;
        }
        return best ? { release: best, reason: '' } : { release: '', reason: 'the endoflife.date data lists no Ubuntu LTS release' };
    };

    /**
     * @brief Is the OS release of a node outdated, and can the plugin upgrade it?
     * state 'unknown' = no clean answer (release not reported, or no fresh reference data):
     * such a device is NEVER upgraded and the reason says why.
     * @param {string} osDesc - node.osdesc.
     * @returns {object} { state:'current'|'outdated'|'unknown', outdated, method:'windows-feature'|'ubuntu-release'|null, current, target, note }
     */
    obj.osUpgradeInfo = function (osDesc, now) {
        var d = String(osDesc || ''), m;
        var res = function (state, method, current, target, note) { return { state: state, outdated: state === 'outdated', method: (state === 'outdated') ? method : null, current: current, target: target, note: note }; };
        if (/windows server/i.test(d)) return res('unknown', null, '', '', 'Windows Server: in-place upgrades need installation media - not offered');
        if (/windows (10|11)/i.test(d)) {
            var ref = obj.osCurrentWindows11(now);
            m = d.match(/\b(\d{2}h[12])\b/i);
            var win10 = /windows 10/i.test(d);
            var curLabel = win10 ? ('Windows 10' + (m ? ' ' + m[1].toUpperCase() : '')) : (m ? m[1].toUpperCase() : '');
            if (ref.release === '') return res('unknown', null, curLabel, '', 'current Windows 11 release unknown: ' + ref.reason);
            var tg = ref.release.toUpperCase();
            if (win10) return res('outdated', 'windows-feature', curLabel, tg, 'Windows 10 -> Windows 11 ' + tg + ' (the hardware must meet the Windows 11 requirements)');
            if (!m) return res('unknown', null, '', tg, 'the agent did not report the installed Windows 11 release');
            if (winRelNum(m[1]) < winRelNum(ref.release)) return res('outdated', 'windows-feature', curLabel, tg, '');
            return res('current', null, curLabel, tg, '');
        }
        if (/ubuntu/i.test(d)) {
            m = d.match(/(\d{2})\.(\d{2})/);
            var lts = obj.osCurrentUbuntuLts(now);
            if (!m) return res('unknown', null, '', lts.release, 'the agent did not report the installed Ubuntu release');
            var rel = m[1] + '.' + m[2];
            if (lts.release === '') return res('unknown', null, rel, '', 'current Ubuntu LTS release unknown: ' + lts.reason);
            if (ubuRelNum(rel) < ubuRelNum(lts.release)) return res('outdated', 'ubuntu-release', rel, lts.release, 'do-release-upgrade moves one release step per run');
            return res('current', null, rel, lts.release, '');
        }
        var st = obj.osSupportState(d);
        if (st.state === 'eol') return res('outdated', null, st.label, '', 'end of life, but there is no supported in-place upgrade tool for this distribution - not upgraded');
        if (st.state === 'supported') return res('current', null, st.label, '', 'release still supported (no newer-release check for this distribution)');
        return res('unknown', null, st.label || '', '', st.reason || 'release not recognized');
    };

    /** @type {string} WSUS classification id of "Upgrades" (feature updates) - language independent. */
    obj.WU_UPGRADES_CATEGORY = '3689bdc8-b205-4af4-8d4a-a63924c5e9d5';

    /**
     * @brief Windows script: Windows Update agent (COM Microsoft.Update.Session) search ->
     * download -> install, as SYSTEM, without reboot. 'update' skips the "Upgrades" classification
     * (feature updates), 'upgrade' sets the documented TargetReleaseVersion policy (ProductVersion
     * 'Windows 11' + TargetReleaseVersionInfo) so Windows Update offers that release, installs it and
     * restores the previous policy values afterwards. One statement per line (guarded by a test).
     * @param {string} mode - 'update' | 'upgrade'.
     * @param {string} [target] - Windows 11 release like '25H2' (validated; required for upgrade).
     * @returns {string} The script text.
     */
    obj.osBuildWindowsScript = function (mode, target) {
        var m = (mode === 'upgrade') ? 'upgrade' : 'update';
        var tg = (typeof target === 'string' && /^\d{2}H[12]$/i.test(target)) ? target.toUpperCase() : '';
        if (m === 'upgrade' && tg === '') { throw new Error('osBuildWindowsScript: upgrade requires a validated target release'); }
        var head = [
            "$ProgressPreference = 'SilentlyContinue'",
            "$invOsMode = '" + m + "'",
            "$invTarget = '" + tg + "'"
        ];
        return head.concat(obj.psTranscriptLines('invscanner-osupdate.log'), [
            "$invRes = @{ os = 'windows'; mode = $invOsMode; target = $invTarget; found = 0; installed = 0; failed = 0; reboot = $false; result = -1; updates = @(); error = '' }",
            "$invWuKey = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate'; $invPrev = $null; $invPolicyNames = @('TargetReleaseVersion', 'ProductVersion', 'TargetReleaseVersionInfo')",
            "if ($invOsMode -eq 'upgrade') { try { if (-not (Test-Path $invWuKey)) { $null = New-Item -Path $invWuKey -Force }; $invPrev = Get-ItemProperty -Path $invWuKey -ErrorAction SilentlyContinue; Set-ItemProperty -Path $invWuKey -Name 'TargetReleaseVersion' -Value 1 -Type DWord; Set-ItemProperty -Path $invWuKey -Name 'ProductVersion' -Value 'Windows 11' -Type String; Set-ItemProperty -Path $invWuKey -Name 'TargetReleaseVersionInfo' -Value $invTarget -Type String } catch { $invRes.error = 'policy: ' + $_.Exception.Message } }",
            "$invSess = $null; $invFound = $null",
            "try { $invSess = New-Object -ComObject Microsoft.Update.Session; $invSess.ClientApplicationID = 'InventoryScanner'; $invSr = $invSess.CreateUpdateSearcher(); $invFound = $invSr.Search(\"IsInstalled=0 and IsHidden=0 and Type='Software'\").Updates } catch { $invFound = $null; $invRes.error = 'search: ' + $_.Exception.Message }",
            "$invColl = New-Object -ComObject Microsoft.Update.UpdateColl",
            "if ($null -ne $invFound) { foreach ($invU in $invFound) { $invIsUpg = $false; foreach ($invC in $invU.Categories) { if ($invC.CategoryID -eq '" + obj.WU_UPGRADES_CATEGORY + "') { $invIsUpg = $true } }; if ($invIsUpg -and ($invOsMode -ne 'upgrade')) { continue }; if (-not $invU.EulaAccepted) { try { $invU.AcceptEula() } catch { } }; $null = $invColl.Add($invU) } }",
            "$invRes.found = [int]$invColl.Count",
            "if ($invColl.Count -gt 0) { try { $invDl = $invSess.CreateUpdateDownloader(); $invDl.Updates = $invColl; $null = $invDl.Download(); $invIn = $invSess.CreateUpdateInstaller(); $invIn.Updates = $invColl; $invIr = $invIn.Install(); $invRes.result = [int]$invIr.ResultCode; $invRes.reboot = [bool]$invIr.RebootRequired; for ($invK = 0; $invK -lt $invColl.Count; $invK++) { $invUr = $invIr.GetUpdateResult($invK); $invSt = 'failed'; if (($invUr.ResultCode -eq 2) -or ($invUr.ResultCode -eq 3)) { $invSt = 'ok'; $invRes.installed = $invRes.installed + 1 } else { $invRes.failed = $invRes.failed + 1 }; $invTi = [string]$invColl.Item($invK).Title; if ($invTi.Length -gt 200) { $invTi = $invTi.Substring(0, 200) }; $invRes.updates += @{ title = $invTi; state = $invSt; code = [int]$invUr.ResultCode; hresult = [int]$invUr.HResult } } } catch { $invRes.error = 'install: ' + $_.Exception.Message } } elseif ($invRes.error -eq '') { $invRes.result = 0 }",
            "if (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired') { $invRes.reboot = $true }",
            "if ($invOsMode -eq 'upgrade') { try { foreach ($invN in $invPolicyNames) { if (($null -ne $invPrev) -and ($null -ne $invPrev.$invN)) { Set-ItemProperty -Path $invWuKey -Name $invN -Value $invPrev.$invN } else { Remove-ItemProperty -Path $invWuKey -Name $invN -ErrorAction SilentlyContinue } } } catch { } }",
            "$invRes | ConvertTo-Json -Compress -Depth 5 | ForEach-Object { Write-Output ('" + obj.OS_MARKER + "' + $_) }",
            "Stop-Transcript -ErrorAction SilentlyContinue | Out-Null"
        ]).join(String.fromCharCode(10));
    };

    /**
     * @brief Linux script (POSIX sh, runs as root through the agent). Every package manager call
     * reads /dev/null as stdin (nothing can swallow script text or wait for input) and writes to
     * the root-only /var/log/invscanner-osupdate.log; only a short tail goes back to the server.
     * 'update': apt-get update + upgrade | dnf upgrade --refresh | yum update | zypper refresh +
     * update | pacman -Syu | apk update + upgrade. 'upgrade' (Ubuntu only): apt-get dist-upgrade,
     * then do-release-upgrade -f DistUpgradeViewNonInteractive (refused by the tool while a reboot
     * is pending - reported as 'reboot-needed', the device is never rebooted).
     * @param {string} mode - 'update' | 'upgrade'.
     * @returns {string} The script text.
     */
    obj.osBuildLinuxScript = function (mode) {
        var m = (mode === 'upgrade') ? 'upgrade' : 'update';
        return [
            "MODE='" + m + "'",
            "LOG=/var/log/invscanner-osupdate.log",
            "[ -L \"$LOG\" ] && LOG=/dev/null",
            "if [ -f \"$LOG\" ] && [ \"$(wc -c < \"$LOG\")\" -gt 5242880 ]; then mv -f \"$LOG\" \"$LOG.old\"; fi",
            "export DEBIAN_FRONTEND=noninteractive",
            "export NEEDRESTART_MODE=a",
            "PM=''; RC=0; STEP=''; NOTE=''; STATE=''",
            "APTOPT='-y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold'",
            "step() { STEP=\"$1\"; shift; echo \"== $(date '+%Y-%m-%d %H:%M:%S') [$MODE] $*\" >> \"$LOG\"; \"$@\" >> \"$LOG\" 2>&1 < /dev/null; RC=$?; return $RC; }",
            "if command -v apt-get >/dev/null 2>&1; then PM=apt; elif command -v dnf >/dev/null 2>&1; then PM=dnf; elif command -v yum >/dev/null 2>&1; then PM=yum; elif command -v zypper >/dev/null 2>&1; then PM=zypper; elif command -v pacman >/dev/null 2>&1; then PM=pacman; elif command -v apk >/dev/null 2>&1; then PM=apk; fi",
            "if [ \"$(id -u)\" != \"0\" ]; then STATE=failed; NOTE='the agent does not run as root'; fi",
            "if [ -z \"$STATE\" ] && [ -z \"$PM\" ]; then STATE=unsupported; NOTE='no supported package manager found'; fi",
            "if [ -z \"$STATE\" ] && [ \"$MODE\" = 'update' ]; then",
            "  case \"$PM\" in",
            "    apt) step refresh apt-get -q update && step upgrade apt-get $APTOPT upgrade ;;",
            "    dnf) step upgrade dnf -y upgrade --refresh ;;",
            "    yum) step upgrade yum -y update ;;",
            "    zypper) step refresh zypper --non-interactive refresh && step upgrade zypper --non-interactive update ;;",
            "    pacman) step upgrade pacman -Syu --noconfirm ;;",
            "    apk) step refresh apk update && step upgrade apk upgrade ;;",
            "  esac",
            "  if [ $RC -eq 0 ]; then STATE=ok; else STATE=failed; fi",
            "fi",
            "if [ -z \"$STATE\" ] && [ \"$MODE\" = 'upgrade' ]; then",
            "  if [ \"$PM\" != 'apt' ] || ! grep -qi '^ID=ubuntu' /etc/os-release 2>/dev/null; then STATE=unsupported; NOTE='release upgrades are only automated for Ubuntu';",
            "  elif grep -qi '^Prompt=never' /etc/update-manager/release-upgrades 2>/dev/null; then STATE=failed; NOTE='Prompt=never in /etc/update-manager/release-upgrades blocks release upgrades';",
            "  else",
            "    step refresh apt-get -q update && step dist-upgrade apt-get $APTOPT dist-upgrade",
            "    if [ $RC -eq 0 ] && ! command -v do-release-upgrade >/dev/null 2>&1; then step install-tool apt-get $APTOPT install update-manager-core; fi",
            "    if [ $RC -ne 0 ]; then STATE=failed;",
            "    elif [ -f /var/run/reboot-required ]; then STATE=reboot-needed; STEP=release-upgrade; NOTE='packages were upgraded; reboot the device, then run the OS upgrade again (do-release-upgrade refuses to start while a reboot is pending)';",
            "    else step release-upgrade do-release-upgrade -f DistUpgradeViewNonInteractive; if [ $RC -eq 0 ]; then STATE=ok; else STATE=failed; fi; fi",
            "  fi",
            "fi",
            "REBOOT=false; [ -f /var/run/reboot-required ] && REBOOT=true",
            "TAIL=$(tail -n 6 \"$LOG\" 2>/dev/null | tr '\\n\\r\\t' '   ' | tr -d '\\000-\\037\\\\\"' | cut -c1-400)",
            "NOTE=$(printf '%s' \"$NOTE\" | tr -d '\\\\\"')",
            "printf '%s{\"os\":\"linux\",\"mode\":\"%s\",\"pm\":\"%s\",\"state\":\"%s\",\"exit\":%d,\"step\":\"%s\",\"reboot\":%s,\"note\":\"%s\",\"log\":\"%s\"}\\n' '" + obj.OS_MARKER + "' \"$MODE\" \"$PM\" \"$STATE\" \"$RC\" \"$STEP\" \"$REBOOT\" \"$NOTE\" \"$TAIL\""
        ].join(String.fromCharCode(10));
    };

    /**
     * @brief One-line sh transport for runcommands type 3: the script travels as base64(gzip) and is
     * run by `sh -c` with stdin from /dev/null, so neither the agent's own stdin feed nor any
     * package manager prompt can interfere.
     */
    obj.osLinuxTransport = function (script) {
        var b64 = zlib.gzipSync(Buffer.from(String(script), 'utf8')).toString('base64');
        return 'sh -c "$(echo \'' + b64 + '\' | base64 -d | gzip -dc)" invscanner < /dev/null';
    };

    /**
     * @brief Devices for an OS batch. 'update' = every Windows/Linux node, 'upgrade' = only nodes
     * whose release is PROVABLY outdated (state 'outdated' from fresh lifecycle data) AND has an
     * upgrade method; 'unknown' devices are skipped and logged with the reason. Unknown-OS nodes are
     * never targeted, the winget exclusion list applies to both modes.
     * @param {string} mode - 'update' | 'upgrade'.
     * @param {function} cb - (Array<{id, platform, target}>)
     */
    obj.osTargetNodes = function (mode, cb) {
        try {
            var excl = obj.wingetConfig().excludeNodes;
            obj.db.GetAllType('node', function (err, nodes) {
                if (err || !nodes) { return cb([]); }
                var out = [];
                for (var i = 0; i < nodes.length; i++) {
                    var n = nodes[i];
                    if ((n == null) || (n._id == null) || (n.deleted != null) || excl.indexOf(n._id) >= 0) continue;
                    var pf = obj.osPlatformOf(n);
                    if (pf == null) continue;
                    if (mode === 'upgrade') {
                        var ui = obj.osUpgradeInfo(n.osdesc);
                        if (ui.state === 'unknown') { obj.osLog(n._id + ' - not upgraded, no clean answer: ' + ui.note); continue; }
                        if (!ui.outdated || ui.method == null) continue;
                        out.push({ id: n._id, platform: pf, target: ui.target });
                    } else { out.push({ id: n._id, platform: pf, target: '' }); }
                }
                cb(out);
            });
        } catch (e) { cb([]); }
    };

    /**
     * @brief Start an OS batch (never while a winget or OS batch runs).
     * @param {string} mode - 'update' | 'upgrade'.
     * @param {Array<string>} [nodeids] - explicit devices (validated by the caller); the mode's
     *   target rule still applies, so a current device is never "upgraded".
     * @param {function} [done] - called when the queue drained.
     * @returns {object} { started, busy? }
     */
    obj.osStartBatch = function (mode, nodeids, done) {
        if (obj.osBatchRunning || obj.wgBatchRunning) { return { started: false, busy: true }; }
        var m = (mode === 'upgrade') ? 'upgrade' : 'update';
        obj.osBatchRunning = true; // reserved now: the db lookup below is asynchronous
        obj.osBatchMode = m;
        obj.osTargetNodes(m, function (list) {
            if (Array.isArray(nodeids)) { list = list.filter(function (x) { return nodeids.indexOf(x.id) >= 0; }); }
            if (list.length === 0) {
                obj.osBatchRunning = false; obj.osBatchMode = '';
                obj.osLog('OS ' + m + ' batch - no target devices');
                if (done) done();
                return;
            }
            obj.osLog('OS ' + m + ' batch starting for ' + list.length + ' device(s)');
            obj.osQueue = list.slice(0, obj.WINGET_MAX_DEVICES);
            obj.osBatchDone = done || null;
            obj.osPump();
        });
        return { started: true };
    };

    /** @brief Feed the OS queue up to OS_MAX_PARALLEL devices. */
    obj.osPump = function () {
        try {
            while ((obj.osActive < obj.OS_MAX_PARALLEL) && (obj.osQueue.length > 0)) {
                var job = obj.osQueue.shift();
                var nodeid = job.id;
                if ((obj.osPending[nodeid] != null) || (obj.wgPending[nodeid] != null)) continue;
                var ws = obj.meshServer.webserver;
                if (!obj.routeHookInstalled) { try { obj.installRouteHook(); } catch (e) { } }
                var agent = (ws != null && ws.wsagents != null) ? ws.wsagents[nodeid] : null;
                if ((agent == null) || (typeof agent.send !== 'function')) {
                    obj.osResults[nodeid] = { time: new Date().toISOString(), mode: obj.osBatchMode, error: 'offline' };
                    obj.osLog(nodeid + ' - skipped, agent offline');
                    obj.wgRaiseNodeEvent(nodeid, 'OS ' + obj.osBatchMode + ': skipped, the agent was offline');
                    continue;
                }
                var sid = 'invscanner-os-' + safeNodeDir(nodeid);
                var entry = { nodeid: nodeid, sid: sid, since: Date.now(), mode: obj.osBatchMode, platform: job.platform };
                entry.timer = setTimeout(function () { obj.osTimeout(entry); }, obj.OS_RUN_TIMEOUT_MS);
                obj.osPending[nodeid] = entry;
                obj.osActive++;
                try {
                    var msg;
                    if (job.platform === 'windows') {
                        var tg = (obj.osBatchMode === 'upgrade') ? String(job.target || '') : '';
                        msg = { action: 'runcommands', type: 1, cmds: obj.wgTransport(obj.osBuildWindowsScript(obj.osBatchMode, tg)), runAsUser: 0, reply: true, sessionid: sid, responseid: sid };
                    } else {
                        msg = { action: 'runcommands', type: 3, cmds: obj.osLinuxTransport(obj.osBuildLinuxScript(obj.osBatchMode)), runAsUser: 0, reply: true, sessionid: sid, responseid: sid };
                    }
                    agent.send(JSON.stringify(msg));
                    obj.osLog(nodeid + ' - ' + job.platform + ' OS ' + obj.osBatchMode + ' script sent' + (job.target ? (' (target ' + job.target + ')') : ''));
                } catch (ex) {
                    clearTimeout(entry.timer); delete obj.osPending[nodeid]; obj.osActive--;
                    obj.osResults[nodeid] = { time: new Date().toISOString(), mode: obj.osBatchMode, error: 'send-failed: ' + ex.message };
                    obj.osLog(nodeid + ' - send failed: ' + ex.message);
                }
            }
            if ((obj.osActive === 0) && (obj.osQueue.length === 0) && obj.osBatchRunning) {
                obj.osBatchRunning = false;
                obj.osLog('OS ' + obj.osBatchMode + ' batch finished');
                obj.osBatchMode = '';
                obj.osSaveResults();
                var d = obj.osBatchDone; obj.osBatchDone = null;
                if (d) d();
            }
        } catch (e) { obj.osLog('pump error: ' + e.message); }
    };

    /** @brief Watchdog for a device that never answered. */
    obj.osTimeout = function (entry) {
        if ((entry == null) || (obj.osPending[entry.nodeid] !== entry)) return;
        delete obj.osPending[entry.nodeid];
        obj.osActive--;
        obj.osResults[entry.nodeid] = { time: new Date().toISOString(), mode: entry.mode, error: 'timeout' };
        obj.osLog(entry.nodeid + ' - no answer within the run timeout');
        obj.wgRaiseNodeEvent(entry.nodeid, 'OS ' + entry.mode + ': the device did not answer within the timeout');
        obj.osPump();
    };

    /**
     * @brief Answer of one OS session: parse the marker JSON, store a sanitized record, log,
     * raise the device event and advance the queue.
     */
    obj.osHandleResponse = function (nodeid, command) {
        var entry = obj.osPending[nodeid];
        if (entry == null) return;
        if (entry.timer) { clearTimeout(entry.timer); }
        delete obj.osPending[nodeid];
        obj.osActive--;
        var text = (typeof command.result === 'string') ? command.result : JSON.stringify(command.result || '');
        var data = obj.wgPayloadFromText(text, obj.OS_MARKER);
        if ((data == null) && (typeof entry.cbuf === 'string')) { data = obj.wgPayloadFromText(entry.cbuf, obj.OS_MARKER); }
        var s = function (v, n) { return String(v == null ? '' : v).substring(0, n); };
        var rec = { time: new Date().toISOString(), mode: entry.mode, platform: entry.platform };
        if (data == null) { rec.error = (text.indexOf(obj.OS_MARKER) >= 0) ? 'unparsable payload' : 'no marker in output'; }
        else if (entry.platform === 'windows') {
            var ups = data.updates; if (ups == null) { ups = []; } else if (!Array.isArray(ups)) { ups = [ups]; }
            rec.found = (typeof data.found === 'number') ? data.found : 0;
            rec.installed = (typeof data.installed === 'number') ? data.installed : 0;
            rec.failed = (typeof data.failed === 'number') ? data.failed : 0;
            rec.reboot = data.reboot === true;
            rec.target = s(data.target, 10);
            rec.updates = ups.slice(0, 100).filter(function (x) { return x && typeof x.title === 'string'; }).map(function (x) {
                return { title: s(x.title, 200), state: (x.state === 'ok') ? 'ok' : 'failed', hresult: (typeof x.hresult === 'number') ? x.hresult : null };
            });
            if (data.error) { rec.note = s(data.error, 300); }
            rec.state = (rec.failed > 0 || (data.error && rec.installed === 0)) ? 'failed' : 'ok';
        } else {
            var okStates = ['ok', 'failed', 'unsupported', 'reboot-needed'];
            rec.state = (okStates.indexOf(data.state) >= 0) ? data.state : 'failed';
            rec.pm = s(data.pm, 12); rec.step = s(data.step, 30); rec.exit = (typeof data.exit === 'number') ? data.exit : null;
            rec.reboot = data.reboot === true; rec.note = s(data.note, 300); rec.log = s(data.log, 500);
        }
        obj.osResults[nodeid] = rec;
        var sum;
        if (rec.error) { sum = rec.error; }
        else if (rec.platform === 'windows') { sum = rec.state + ': ' + rec.found + ' found, ' + rec.installed + ' installed, ' + rec.failed + ' failed' + (rec.reboot ? ', REBOOT PENDING' : '') + (rec.note ? (' (' + rec.note + ')') : ''); }
        else { sum = rec.state + ' via ' + (rec.pm || '?') + (rec.step ? (' at step ' + rec.step) : '') + (rec.exit != null ? (', exit ' + rec.exit) : '') + (rec.reboot ? ', REBOOT PENDING' : '') + (rec.note ? (' - ' + rec.note) : ''); }
        obj.osLog(nodeid + ' - OS ' + entry.mode + ' ' + sum);
        if (rec.platform === 'windows' && Array.isArray(rec.updates)) {
            for (var i = 0; i < rec.updates.length; i++) { if (rec.updates[i].state === 'failed') { obj.osLog(nodeid + ' - FAILED ' + rec.updates[i].title + (rec.updates[i].hresult != null ? (' (0x' + obj.wgExitHex(rec.updates[i].hresult) + ')') : '')); } }
        } else if (rec.state === 'failed' && rec.log) { obj.osLog(nodeid + ' - output tail: ' + rec.log); }
        obj.wgRaiseNodeEvent(nodeid, 'OS ' + entry.mode + ': ' + sum.substring(0, 300));
        obj.osSaveResults();
        obj.osPump();
    };

    /** @brief POST os_run: { mode: 'update'|'upgrade', nodeIds?: csv } - manual OS batch. */
    obj.osRunHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        var body = req.body || {};
        if (body.mode !== 'update' && body.mode !== 'upgrade') { return send({ error: 'mode must be update or upgrade.' }); }
        var ids = null;
        if (body.nodeIds != null && body.nodeIds !== '') {
            ids = [];
            var arr = String(body.nodeIds).split(',');
            for (var i = 0; i < arr.length && ids.length < 200; i++) {
                var x = arr[i].trim();
                if (/^node\/[^:]{1,100}$/.test(x) && ids.indexOf(x) < 0) ids.push(x);
            }
            if (ids.length === 0) { return send({ error: 'Invalid nodeIds.' }); }
        }
        if (obj.osBatchRunning || obj.wgBatchRunning) { return send({ started: false, busy: true }); }
        if (body.mode === 'upgrade') {
            // No guessing: without fresh reference data the "current release" is unknown, so an
            // upgrade would have no defensible target. Say so plainly instead of picking a version.
            var w11 = obj.osCurrentWindows11(), ul = obj.osCurrentUbuntuLts();
            if (w11.release === '' && ul.release === '') {
                return send({ started: false, error: 'OS Upgrade not started: the current release is unknown. Windows 11: ' + w11.reason + '. Ubuntu: ' + ul.reason + '. Refresh the OS support dates (Settings tab -> Update NVD database now) and try again.' });
            }
        }
        var r = obj.osStartBatch(body.mode, ids, null);
        send({ started: !!r.started, busy: !!r.busy, mode: body.mode });
    };

    /** @brief POST os_status: every Windows/Linux node with release, upgrade state and last OS run. */
    obj.osStatusHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        var excl = obj.wingetConfig().excludeNodes;
        obj.db.GetAllType('mesh', function (merr, meshes) {
            var meshNames = {};
            if (!merr && meshes) { for (var mi = 0; mi < meshes.length; mi++) { var mm = meshes[mi]; if (mm && mm._id && mm.deleted == null) meshNames[mm._id] = mm.name || mm._id; } }
            obj.db.GetAllType('node', function (nerr, nodes) {
                var ws = obj.meshServer.webserver, devices = [];
                if (!nerr && nodes) {
                    for (var i = 0; i < nodes.length; i++) {
                        var n = nodes[i];
                        if ((n == null) || (n._id == null) || (n.deleted != null)) continue;
                        var pf = obj.osPlatformOf(n);
                        if (pf == null) continue;
                        var ui = obj.osUpgradeInfo(n.osdesc);
                        devices.push({
                            id: n._id, host: obj.getHostName(n), given: (typeof n.name === 'string') ? n.name.trim() : '',
                            group: meshNames[n.meshid] || n.meshid || '', platform: pf, os: String(n.osdesc || '').substring(0, 120),
                            online: (ws != null && ws.wsagents != null && ws.wsagents[n._id] != null), excluded: excl.indexOf(n._id) >= 0,
                            outdated: ui.outdated, releaseState: ui.state, upgradable: ui.outdated && ui.method != null, target: ui.target, note: ui.note,
                            last: obj.osResults[n._id] || null, pending: obj.osPending[n._id] ? { since: obj.osPending[n._id].since, mode: obj.osPending[n._id].mode } : null
                        });
                    }
                }
                devices.sort(function (a, b) { return (a.group === b.group) ? String(a.given || a.host).localeCompare(String(b.given || b.host)) : String(a.group).localeCompare(String(b.group)); });
                var lts0 = function (x) { return String(x || ''); };
                var w11 = obj.osCurrentWindows11(), ults = obj.osCurrentUbuntuLts();
                send({ devices: devices, running: obj.osBatchRunning, mode: obj.osBatchMode, active: obj.osActive, queued: obj.osQueue.length,
                    current: { windows11: w11.release.toUpperCase(), windows11Reason: w11.reason, ubuntuLts: lts0(ults.release), ubuntuLtsReason: ults.reason } });
            });
        });
    };

    // ---- Scheduled group scans ----

    /**
     * @brief Read the automatic scan configuration from the server settings.
     * Reads <code>meshserver.config.settings.vulnerabilityScanner</code>:
     * <code>scanIntervalHours</code> (default 24, 0 disables) and
     * <code>scanMeshes</code> (array of mesh ids; empty/undefined = all meshes).
     * @returns {object} <code>{ intervalHours, meshes }</code>.
     */
    obj.scannerConfig = function () {
        var cfg = null;
        try { cfg = obj.effectiveSectionConfig('vulnerabilityScanner'); } catch (e) { }
        var intervalHours = 24;
        var meshes = null;
        var notifyOnScan = true;
        var notifyThreshold = 'HIGH'; // fallback severity for groups without a specific setting
        var notifyThresholds = {};    // meshId -> severity threshold (per-group override)
        var notifyUnratedRepeat = false; // remind on every scan about findings without a rating
        var autoProductMatch = true; // automatic product-token matching for unmapped names
        var cpeTableEnabled = true;  // refresh the curated table from the repository
        var cpeTableUrl = obj.CPE_TABLE_DEFAULT_URL;
        var distroManaged = true;      // distribution packages judged by the OS support state (v3.1.0)
        var osLifecycleEnabled = true; // fetch OS support dates from endoflife.date (v3.1.0)
        var osLifecycleUrl = obj.OS_LIFECYCLE_DEFAULT_URL;
        if (cfg && (typeof cfg === 'object')) {
            if (typeof cfg.distroManaged === 'boolean') { distroManaged = cfg.distroManaged; }
            if (typeof cfg.osLifecycleEnabled === 'boolean') { osLifecycleEnabled = cfg.osLifecycleEnabled; }
            if ((typeof cfg.osLifecycleUrl === 'string') && /^https:\/\/[^\s"'<>]{5,250}\/$/.test(cfg.osLifecycleUrl)) { osLifecycleUrl = cfg.osLifecycleUrl; }
            if (typeof cfg.scanIntervalHours === 'number' && cfg.scanIntervalHours >= 0) { intervalHours = cfg.scanIntervalHours; }
            if (Array.isArray(cfg.scanMeshes) && cfg.scanMeshes.length > 0) { meshes = cfg.scanMeshes.slice(); }
            if (typeof cfg.notifyOnScan === 'boolean') { notifyOnScan = cfg.notifyOnScan; }
            if (typeof cfg.notifyThreshold === 'string') { notifyThreshold = cfg.notifyThreshold.toUpperCase(); }
            if (typeof cfg.notifyUnratedRepeat === 'boolean') { notifyUnratedRepeat = cfg.notifyUnratedRepeat; }
            if (typeof cfg.autoProductMatch === 'boolean') { autoProductMatch = cfg.autoProductMatch; }
            if (typeof cfg.cpeTableEnabled === 'boolean') { cpeTableEnabled = cfg.cpeTableEnabled; }
            if ((typeof cfg.cpeTableUrl === 'string') && /^https:\/\//i.test(cfg.cpeTableUrl)) { cpeTableUrl = cfg.cpeTableUrl; }
            if (cfg.notify && (typeof cfg.notify === 'object')) {
                for (var mid in cfg.notify) {
                    if (typeof cfg.notify[mid] === 'string') { notifyThresholds[mid] = cfg.notify[mid].toUpperCase(); }
                }
            }
        }
        return { intervalHours: intervalHours, meshes: meshes, notifyOnScan: notifyOnScan, notifyThreshold: notifyThreshold, notifyThresholds: notifyThresholds, notifyUnratedRepeat: notifyUnratedRepeat, autoProductMatch: autoProductMatch, cpeTableEnabled: cpeTableEnabled, cpeTableUrl: cpeTableUrl, distroManaged: distroManaged, osLifecycleEnabled: osLifecycleEnabled, osLifecycleUrl: osLifecycleUrl };
    };

    /**
     * @brief Load persisted scheduled scan results from disk.
     */
    obj.loadScans = function () {
        try {
            if (fs.existsSync(obj.scansPath)) {
                obj.scanResults = JSON.parse(fs.readFileSync(obj.scansPath, 'utf8'));
                if ((obj.scanResults == null) || (typeof obj.scanResults !== 'object')) { obj.scanResults = {}; }
            } else { obj.scanResults = {}; }
        } catch (err) {
            obj.debug('plugin:inventory_scanner', 'Error loading scan results:', err.message);
            obj.scanResults = {};
        }
        // Restore the "last scan" timestamp shown in the panel header from the
        // persisted snapshots, so it survives server restarts.
        var latest = null;
        for (var id in obj.scanResults) {
            if (Object.prototype.hasOwnProperty.call(obj.scanResults, id)) {
                var rec = obj.scanResults[id];
                if (rec && (typeof rec.time === 'string') && ((latest == null) || (rec.time > latest))) { latest = rec.time; }
            }
        }
        if (latest != null) { obj.lastScan = latest; }
    };

    /**
     * @brief Persist the scheduled scan results to disk.
     */
    obj.saveScans = function () {
        try { fs.writeFileSync(obj.scansPath, JSON.stringify(obj.scanResults, null, 2)); }
        catch (err) { obj.debug('plugin:inventory_scanner', 'Error saving scan results:', err.message); }
    };

    // Severity ranking used for the notification threshold.
    obj.SEVERITY_RANK = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0 };

    // Maximum delay accepted by setTimeout (2^31-1 ms ~= 24.8 days). Node silently
    // forces larger values to 1 ms, which would spin the callback in a hot loop.
    var MAX_TIMEOUT_MS = 2147483647;

    /**
     * @brief setTimeout wrapper that safely supports intervals beyond ~24.8 days
     * (e.g. the monthly vulnerability scan) by chaining smaller chunks and
     * recomputing the remaining time from the wall clock after each chunk.
     * @param {function} callback - Invoked once the total delay has elapsed.
     * @param {number} ms - Total delay in milliseconds.
     * @param {function} [setter] - Scheduler to use (injectable for tests; defaults to setTimeout).
     * @param {function} [nowFn] - Clock to use (injectable for tests; defaults to Date.now).
     */
    obj.longTimeout = function (callback, ms, setter, nowFn) {
        if (setter == null) { setter = function (fn, d) { setTimeout(fn, d); }; }
        if (nowFn == null) { nowFn = Date.now; }
        if (ms <= MAX_TIMEOUT_MS) { setter(callback, ms); return; }
        var startTime = nowFn();
        function scheduleChunk() {
            var remaining = ms - (nowFn() - startTime);
            if (remaining <= 0) { callback(); return; }
            setter(scheduleChunk, Math.min(remaining, MAX_TIMEOUT_MS));
        }
        scheduleChunk();
    };

    /**
     * @brief Run the scheduled vulnerability scans for the configured meshes.
     * Scans each mesh, aggregates its unique CVEs (with group-wide assessments),
     * stores the result in <code>scanResults</code> and persists it. If
     * notifications are enabled, sends an admin notification listing any newly
     * found CVEs at or above <code>notifyThreshold</code>.
     */
    obj.runScheduledScans = function () {
        var cfg = obj.scannerConfig();
        if (cfg.intervalHours <= 0) { return; } // scheduled scanning disabled

        obj.meshServer.db.GetAllType('mesh', function (err, meshes) {
            if (err || !meshes) { return; }
            var targetRecords = [];
            for (var i = 0; i < meshes.length; i++) {
                var m = meshes[i];
                if ((m == null) || (m._id == null) || (m.deleted != null)) continue;
                if ((cfg.meshes != null) && (cfg.meshes.indexOf(m._id) < 0)) continue;
                targetRecords.push({ id: m._id, name: (m.name != null) ? m.name : m._id });
            }
            if (targetRecords.length === 0) { return; }

            // Snapshot the previously stored CVE sets so we can detect new findings.
            var prevByMesh = {};
            for (var prevId in obj.scanResults) {
                if (obj.scanResults[prevId] && Array.isArray(obj.scanResults[prevId].cves)) {
                    prevByMesh[prevId] = {};
                    for (var pc = 0; pc < obj.scanResults[prevId].cves.length; pc++) {
                        prevByMesh[prevId][obj.scanResults[prevId].cves[pc].cve] = 1;
                    }
                }
            }

            var done = 0;
            var alerts = []; // { meshName, newCves }

            targetRecords.forEach(function (mesh) {
                // Per-group notification threshold: specific setting wins, else the global fallback.
                var meshThresholdName = (cfg.notifyThresholds[mesh.id] != null) ? cfg.notifyThresholds[mesh.id] : cfg.notifyThreshold;
                var threshold = cfg.notifyOnScan ? (obj.SEVERITY_RANK[meshThresholdName] != null ? obj.SEVERITY_RANK[meshThresholdName] : obj.SEVERITY_RANK.HIGH) : -1;

                obj.scanMeshCves(mesh.id, function (scanErr, list) {
                    if (!scanErr) {
                        obj.scanResults[mesh.id] = { time: new Date().toISOString(), cves: list };

                        if (threshold >= 0) {
                            var newCves = [];
                            for (var j = 0; j < list.length; j++) {
                                var c = list[j];
                                // A group-rated (or false-positive-flagged) CVE is reviewed/mitigated
                                // and must never be reported again.
                                if (c.assessment != null) continue;
                                var eff = c.severity;
                                if ((obj.SEVERITY_RANK[eff] != null) && (obj.SEVERITY_RANK[eff] >= threshold)) {
                                    var isNew = (prevByMesh[mesh.id] == null) || !prevByMesh[mesh.id][c.cve];
                                    if (isNew) { newCves.push(c.cve + ' (' + eff + ', new)'); }
                                    // In repeat mode (monthly routine) unrated findings are listed
                                    // again on every scan, so the reminder survives until someone acts.
                                    else if (cfg.notifyUnratedRepeat) { newCves.push(c.cve + ' (' + eff + ', open)'); }
                                }
                            }
                            if (newCves.length > 0) { alerts.push({ meshName: mesh.name, newCves: newCves }); }
                        }
                    }
                    if (++done === targetRecords.length) {
                        obj.lastScan = new Date().toISOString();
                        obj.saveScans();
                        obj.debug('plugin:inventory_scanner', 'Scheduled scan finished for', targetRecords.length, 'groups');
                        if (alerts.length > 0) { obj.notifyAdmins(alerts); }
                    }
                });
            });
        });
    };

    /**
     * @brief Notify all full site administrators about newly found vulnerabilities.
     * Uses <code>DispatchEvent(['*'], ...)</code> which reaches full site admins and
     * users with the "all events" right.
     * @param {Array<object>} alerts - Array of <code>{ meshName, newCves }</code>.
     */
    obj.notifyAdmins = function (alerts) {
        if (!alerts || alerts.length === 0) return;
        var lines = [];
        for (var i = 0; i < alerts.length; i++) {
            lines.push(alerts[i].meshName + ': ' + alerts[i].newCves.length + ' finding(s) to act on (' + alerts[i].newCves.join(', ') + ')');
        }
        var value = 'Vulnerability scan: action needed\n' + lines.join('\n');
        var event = {
            etype: 'server',
            action: 'msg',
            type: 'notify',
            id: Math.random(),
            tag: 'ServerNotify',
            value: value,
            title: 'Vulnerability Scan'
        };
        try { obj.meshServer.DispatchEvent(['*'], obj, event); }
        catch (e) { obj.debug('plugin:inventory_scanner', 'Error dispatching notification:', e.message); }
    };

    /**
     * @brief Schedule periodic group scans.
     * Uses <code>scanIntervalHours</code> (default 24); disabled if 0.
     */
    obj.scheduleScans = function () {
        var intervalHours = obj.scannerConfig().intervalHours;
        if (intervalHours <= 0) { obj.debug('plugin:inventory_scanner', 'Scheduled scanning is disabled (scanIntervalHours=0)'); return; }
        var intervalMs = intervalHours * 3600 * 1000;
        // Restart-proof scheduling: the next run is computed from the persisted
        // last-scan timestamp, not from the startup time. Without a completed scan
        // yet (fresh install) the baseline runs shortly after startup.
        var delay = 60000; // 1 minute after startup
        if (obj.lastScan != null) {
            var elapsed = Date.now() - Date.parse(obj.lastScan);
            delay = (isNaN(elapsed) || (elapsed >= intervalMs)) ? 60000 : (intervalMs - elapsed);
        }
        obj.debug('plugin:inventory_scanner', 'Scheduled group scan every', intervalHours, 'hours; next run in', Math.round(delay / 60000), 'minutes');
        var gen = obj.timerGen;
        obj.longTimeout(function () {
            if (!obj.timerValid(gen)) { return; } // superseded by a settings save
            obj.runScheduledScans();
            obj.scheduleScans();
        }, delay);
    };

    // ---- Live inventory collection (installed software & patches) ----
    // MeshCentral does NOT persist installed software / patches anywhere in the
    // database (meshagent.js: "Todo - save software into database for offline
    // access but send to web clients for now"). The device-list UI fetches them
    // live from the agent on demand. This plugin therefore collects them from
    // online agents on a schedule and stores them in its own database so that
    // CSV exports and CVE scans can work offline.

    /**
     * @brief Read the live-collection configuration from the server settings.
     * Reads <code>meshserver.config.settings.inventoryScanner</code>:
     * <code>collectIntervalMinutes</code> (default 1440 = daily, 0 disables) and
     * <code>collectOnAgentConnect</code> (default true).
     * @returns {object} <code>{ intervalMinutes, collectOnAgentConnect }</code>.
     */
    obj.collectorConfig = function () {
        var cfg = null;
        try { cfg = obj.effectiveSectionConfig('inventoryScanner'); } catch (e) { }
        var intervalMinutes = 24 * 60; // default: daily (24h)
        var collectOnAgentConnect = true;
        if (cfg && (typeof cfg === 'object')) {
            if (typeof cfg.collectIntervalMinutes === 'number' && cfg.collectIntervalMinutes >= 0) { intervalMinutes = cfg.collectIntervalMinutes; }
            if (typeof cfg.collectOnAgentConnect === 'boolean') { collectOnAgentConnect = cfg.collectOnAgentConnect; }
        }
        return { intervalMinutes: intervalMinutes, collectOnAgentConnect: collectOnAgentConnect };
    };

    /**
     * @brief Build a safe filesystem fragment from a node id.
     * Node ids contain <code>node/&lt;domain&gt;/&lt;id&gt;</code>; the final segment
     * is used, cleaned of path-hostile characters.
     * @param {string} nodeId - The node id.
     * @returns {string} A safe directory name.
     */
    function safeNodeDir(nodeId) {
        if (!nodeId) return 'unknown';
        var parts = String(nodeId).split('/');
        var last = parts[parts.length - 1] || 'unknown';
        return last.replace(/[^A-Za-z0-9._-]/g, '_').substring(0, 120);
    }

    /**
     * @brief Path to the collected software file for a node.
     * @param {string} nodeId - The node id.
     * @returns {string} The JSON file path.
     */
    obj.softwarePathForNode = function (nodeId) {
        return path.join(obj.inventoryDataPath, safeNodeDir(nodeId), 'software.json');
    };

    /**
     * @brief Path to the collected Windows-updates state file for a node.
     * @param {string} nodeId - The node id.
     * @returns {string} The JSON file path.
     */
    obj.windowsUpdatesPathForNode = function (nodeId) {
        return path.join(obj.inventoryDataPath, safeNodeDir(nodeId), 'windowsupdates.json');
    };

    /**
     * @brief Path to the collection meta file for a node.
     * @param {string} nodeId - The node id.
     * @returns {string} The JSON file path.
     */
    obj.metaPathForNode = function (nodeId) {
        return path.join(obj.inventoryDataPath, safeNodeDir(nodeId), 'meta.json');
    };

    /**
     * @brief Load all previously collected inventory files into memory.
     */
    obj.loadCollectedInventory = function () {
        try {
            if (!fs.existsSync(obj.inventoryDataPath)) { fs.mkdirSync(obj.inventoryDataPath, { recursive: true }); }
            var dirs = fs.readdirSync(obj.inventoryDataPath, { withFileTypes: true });
            for (var i = 0; i < dirs.length; i++) {
                if (!dirs[i].isDirectory()) continue;
                var dir = path.join(obj.inventoryDataPath, dirs[i].name);
                try {
                    var sf = path.join(dir, 'software.json');
                    if (fs.existsSync(sf)) { obj.softwareInventory[dirs[i].name] = JSON.parse(fs.readFileSync(sf, 'utf8')); }
                } catch (e) { }
                try {
                    var wf = path.join(dir, 'windowsupdates.json');
                    if (fs.existsSync(wf)) { obj.windowsUpdates[dirs[i].name] = JSON.parse(fs.readFileSync(wf, 'utf8')); }
                } catch (e) { }
            }
            obj.debug('plugin:inventory_scanner', 'Loaded collected inventory for', Object.keys(obj.softwareInventory).length, 'nodes');
        } catch (e) {
            obj.debug('plugin:inventory_scanner', 'Error loading collected inventory:', e.message);
        }
    };

    /**
     * @brief Persist the collected software list for a node to disk.
     * @param {string} nodeId - The node id.
     * @param {object} entry - <code>{ time, apps }</code>.
     */
    obj.saveSoftwareInventory = function (nodeId, entry) {
        try {
            var dir = path.join(obj.inventoryDataPath, safeNodeDir(nodeId));
            fs.mkdirSync(dir, { recursive: true });
            fs.writeFileSync(obj.softwarePathForNode(nodeId), JSON.stringify(entry, null, 2));
            fs.writeFileSync(obj.metaPathForNode(nodeId), JSON.stringify({ time: entry.time }, null, 2));
        } catch (e) { obj.debug('plugin:inventory_scanner', 'Error saving software inventory:', e.message); }
    };

    /**
     * @brief Persist the collected Windows-updates state for a node to disk.
     * @param {string} nodeId - The node id.
     * @param {object} entry - <code>{ time, count, updates }</code>.
     */
    obj.saveWindowsUpdates = function (nodeId, entry) {
        try {
            var dir = path.join(obj.inventoryDataPath, safeNodeDir(nodeId));
            fs.mkdirSync(dir, { recursive: true });
            fs.writeFileSync(obj.windowsUpdatesPathForNode(nodeId), JSON.stringify(entry, null, 2));
            fs.writeFileSync(obj.metaPathForNode(nodeId), JSON.stringify({ time: entry.time }, null, 2));
        } catch (e) { obj.debug('plugin:inventory_scanner', 'Error saving Windows updates:', e.message); }
    };

    /**
     * @brief Install a runtime hook on the webserver's routeAgentCommand so that
     * agent responses to this plugin's collection commands are captured
     * server-side. This is injected on every server start and is entirely owned
     * by this plugin (never overwritten by MeshCentral updates).
     */
    obj.installRouteHook = function () {
        try {
            var ws = obj.meshServer.webserver;
            if ((ws == null) || (typeof ws.routeAgentCommand !== 'function')) {
                if (!obj.routeHookRetryPending) {
                    obj.routeHookRetryPending = true;
                    setTimeout(function () { obj.routeHookRetryPending = false; try { obj.installRouteHook(); } catch (e) { } }, 2000);
                }
                return;
            }
            if (ws.__inventoryscannerHookInstalled === true) { obj.routeHookInstalled = true; return; }
            var self = obj;
            var original = ws.routeAgentCommand.bind(ws);
            ws.routeAgentCommand = function (command, domainid, nodeid, meshid) {
                try {
                    if ((command != null) && (typeof command === 'object')) {
                        // Dispatch to whichever instance currently owns the slot, so a
                        // hot-swap during an upgrade keeps this hook alive on the new code.
                        var inst = (self.parent != null && self.parent.plugins != null) ? (self.parent.plugins[self.shortName] || self) : self;
                        if (inst.onAgentResponse(command, domainid, nodeid, meshid) === true) { return; }
                    }
                } catch (e) { }
                return original(command, domainid, nodeid, meshid);
            };
            ws.__inventoryscannerHookInstalled = true;
            obj.routeHookInstalled = true;
            obj.debug('plugin:inventory_scanner', 'Installed routeAgentCommand hook for live inventory collection');
        } catch (e) {
            obj.debug('plugin:inventory_scanner', 'Error installing route hook:', e.message);
        }
    };

    /**
     * @brief Handle an agent response routed by the server.
     * Captures software (installed apps / packages) and patch (QFE) responses
     * that belong to this plugin's collection requests.
     * @param {object} command - The response command from the agent.
     * @param {string} domainid - The domain id.
     * @param {string} nodeid - The node id the response came from.
     * @param {string} meshid - The mesh id.
     */
    obj.onAgentResponse = function (command, domainid, nodeid, meshid) {
        if ((nodeid == null) || (command == null)) return false;
        if (command.action === 'software') {
            // Only capture responses to this plugin's own collection requests: the agent answers
            // with sessionid = the request's sessionid, and the plugin sends none, so a reply WITH a
            // sessionid belongs to a browser session (Software tab) and is neither stored nor
            // consumed. Our own session-less reply is consumed, so it is not broadcast to every
            // user session with rights on the node (v3.0.1).
            if ((obj.pendingCollection[nodeid] === true) && (command.sessionid == null)) {
                obj.handleSoftwareResponse(nodeid, command);
                return true;
            }
            return false; // a UI-triggered request: route to the browser
        } else if ((command.action === 'msg') && (command.type === 'runcommands')) {
            // OS update sessions (v3.5.0): own prefix, same ownership rules as winget.
            var osOurs = (((typeof command.sessionid === 'string') && (command.sessionid.indexOf('invscanner-os-') === 0)) || ((typeof command.responseid === 'string') && (command.responseid.indexOf('invscanner-os-') === 0)));
            if (!osOurs && (obj.osPending[nodeid] != null) && (command.sessionid == null) && (command.responseid == null)) { osOurs = true; }
            if (osOurs) { obj.osHandleResponse(nodeid, command); return true; }
            // Answer to one of our update sessions (agent builds differ on whether the
            // reply carries sessionid, responseid or both - accept any prefix hit).
            var ours = (((typeof command.sessionid === 'string') && (command.sessionid.indexOf('invscanner-wg-') === 0)) || ((typeof command.responseid === 'string') && (command.responseid.indexOf('invscanner-wg-') === 0)));
            // Session-less answers (some agent builds) are only accepted while a run is pending for
            // that node AND the reply carries no session field at all - a reply addressed to another
            // (browser) session is never taken over (v3.0.1).
            if (!ours && (obj.wgPending != null) && (obj.wgPending[nodeid] != null) && (command.sessionid == null) && (command.responseid == null)) { ours = true; }
            if (ours) {
                obj.wgHandleResponse(nodeid, command);
                return true; // consumed - the marker JSON is plugin-internal
            }
            return false;
        } else if ((command.action === 'msg') && (command.type === 'console')) {
            // Winget answers arriving on the console channel (some agent builds emit
            // runcommands output as console text): capture when a wg session is pending.
            // Packets chunk the output, so the answer line can span several packets -
            // text accumulates on the pending entry and is only consumed once the
            // payload is complete and parses (otherwise the runcommands reply or the
            // watchdog finishes the session).
            var wge = (obj.wgPending != null) ? obj.wgPending[nodeid] : null;
            var ose = obj.osPending[nodeid];
            var osConsoleOurs = (command.sessionid == null) || ((typeof command.sessionid === 'string') && (command.sessionid.indexOf('invscanner-os-') === 0));
            if ((typeof command.value === 'string') && (ose != null) && osConsoleOurs) {
                ose.cbuf = (typeof ose.cbuf === 'string' ? ose.cbuf : '') + command.value;
                if (ose.cbuf.length > 262144) ose.cbuf = ose.cbuf.substring(ose.cbuf.length - 131072);
                if (obj.wgPayloadFromText(ose.cbuf, obj.OS_MARKER) != null) { obj.osHandleResponse(nodeid, { result: ose.cbuf }); return true; }
            }
            if ((typeof command.sessionid === 'string') && (command.sessionid.indexOf('invscanner-os-') === 0)) {
                var otext = String(command.value || '').substring(0, 200).replace(/[\r\n]+/g, ' ');
                if (otext !== '') { obj.osLog(nodeid + ' - agent console: ' + otext); }
            }
            // The agent's runcommands child echoes its output with sendConsoleText() WITHOUT a
            // sessionid (verified in meshcore.js), so only session-less console text or text on our
            // own wg session is buffered - console output of an admin's terminal session is left alone.
            var wgConsoleOurs = (command.sessionid == null) || ((typeof command.sessionid === 'string') && (command.sessionid.indexOf('invscanner-wg-') === 0));
            if ((typeof command.value === 'string') && (wge != null) && wgConsoleOurs) {
                wge.cbuf = (typeof wge.cbuf === 'string' ? wge.cbuf : '') + command.value;
                if (wge.cbuf.length > 262144) wge.cbuf = wge.cbuf.substring(wge.cbuf.length - 131072);
                if (obj.wgPayloadFromText(wge.cbuf) != null) {
                    obj.wgLog(nodeid + ' - answer captured via console channel');
                    obj.wgHandleResponse(nodeid, { result: wge.cbuf });
                    return true;
                }
            }
            // Windows-update status responses come back as console text. They are
            // identified by the plugin's own sessionid prefix; when captured we
            // consume them and do NOT forward them to browser clients.
            if ((command.sessionid != null) && (typeof command.sessionid === 'string') && (command.sessionid.indexOf('invscanner-wg-') === 0)) {
                var ctext = String(command.value || '').substring(0, 200).replace(/[\r\n]+/g, ' ');
                if (ctext !== '') { obj.wgLog(nodeid + ' - agent console: ' + ctext); }
            }
            if ((command.sessionid != null) && (typeof command.sessionid === 'string') && (command.sessionid.indexOf('invscanner-') === 0)) {
                if (obj.pendingWinUpdates[nodeid] === true && obj.looksLikeWindowsUpdatesResponse(command.value)) {
                    obj.handleWindowsUpdatesResponse(nodeid, command.value);
                    return true; // consumed, suppress browser forwarding
                }
            }
        }
        return false;
    };

    /**
     * @brief Heuristic check that a console value looks like the result of the
     * agent's <code>winupdates</code> command, i.e. the "Pending Updates (N):"
     * summary produced by <code>getAvailableUpdates()</code>.
     * @param {*} value - The console value.
     * @returns {boolean} True if the value looks like a pending-updates summary.
     */
    obj.looksLikeWindowsUpdatesResponse = function (value) {
        try {
            if (typeof value !== 'string') return false;
            var t = value.trim();
            // The final/meaningful results (the "Checking for pending updates..."
            // interim message is deliberately NOT treated as a result).
            if (/^Pending Updates \(\d+\):/.test(t)) return true;
            if (/^No pending updates\./i.test(t)) return true;
            if (/^Windows updates not supported/.test(t)) return true;
        } catch (e) { }
        return false;
    };

    /**
     * @brief Whether a software response is expected for a node.
     * @param {string} nodeId - The node id.
     * @returns {boolean} True if a collection request is pending.
     */
    obj.hasPendingSoftware = function (nodeId) {
        return obj.pendingCollection[nodeId] === true;
    };

    /**
     * @brief Store the parsed Windows-update status for a node.
     * Parses the "Pending Updates (N):" console summary and stores the count.
     * @param {string} nodeId - The node id.
     * @param {string} value - The console text.
     */
    obj.handleWindowsUpdatesResponse = function (nodeId, value) {
        var updates = [];
        try {
            var text = String(value);
            var lines = text.split('\n');
            for (var i = 0; i < lines.length; i++) {
                var lm = lines[i].match(/^\s*\[\d+\]\s+(.*)$/);
                if (lm) {
                    var title = lm[1];
                    var sev = '';
                    var sM = title.match(/\[(.*)\]$/);
                    if (sM) { sev = sM[1]; title = title.substring(0, sM.index).trim(); }
                    var kbs = [];
                    var kbM = title.match(/KB\d+/gi);
                    if (kbM) { for (var k = 0; k < kbM.length; k++) { kbs.push(kbM[k]); } }
                    updates.push({ title: title, kbArticleIDs: kbs, severity: sev });
                }
            }
        } catch (e) { updates = []; }

        // Count only security-relevant updates (Critical / Important). Optional,
        // Moderate and unknown-severity updates are ignored to avoid false
        // positives from a single optional driver update.
        var sevRank = { 'critical': 2, 'important': 1 };
        var filtered = [];
        for (var u = 0; u < updates.length; u++) {
            var s = String(updates[u].severity || '').trim().toLowerCase();
            if (sevRank[s]) { filtered.push(updates[u]); }
        }
        var count = filtered.length;

        var key = safeNodeDir(nodeId);
        obj.windowsUpdates[key] = { time: new Date().toISOString(), count: count, updates: filtered };
        obj.saveWindowsUpdates(nodeId, obj.windowsUpdates[key]);
        if (obj.pendingWinUpdates) { delete obj.pendingWinUpdates[nodeId]; }
        obj.debug('plugin:inventory_scanner', 'Collected Windows updates status:', count, 'critical/important pending for', nodeId);
    };

    /**
     * @brief Store the parsed software response for a node.
     * @param {string} nodeId - The node id.
     * @param {object} command - The response command (<code>value</code> is a JSON string).
     */
    obj.handleSoftwareResponse = function (nodeId, command) {
        delete obj.pendingCollection[nodeId];
        var apps = null, why = 'unrecognized answer';
        try {
            var raw = command.value;
            if (typeof raw === 'string') {
                var parsed = JSON.parse(raw);
                if (Array.isArray(parsed)) { apps = parsed; }
                else if ((parsed != null) && (typeof parsed === 'object') && Array.isArray(parsed.value)) { apps = parsed.value; }
                else if ((parsed != null) && (typeof parsed === 'object') && (parsed.error != null)) { why = 'agent error: ' + String(parsed.error).substring(0, 120); }
            } else if (Array.isArray(raw)) { apps = raw; }
        } catch (e) { apps = null; why = 'unparsable answer'; }
        // An error answer ("Denied", "Not supported", ...) must never overwrite the last good
        // inventory with an empty list - empty would read as "nothing installed" (v3.0.1).
        if (apps == null) {
            obj.debug('plugin:inventory_scanner', 'Software collection for', nodeId, 'not stored -', why);
            return;
        }
        if (apps.length > 20000) { apps = apps.slice(0, 20000); } // a device never has more; caps disk/memory use
        obj.softwareInventory[safeNodeDir(nodeId)] = { time: new Date().toISOString(), apps: apps };
        obj.saveSoftwareInventory(nodeId, obj.softwareInventory[safeNodeDir(nodeId)]);
        obj.debug('plugin:inventory_scanner', 'Collected', apps.length, 'software entries for', nodeId);
    };

    /**
     * @brief Schedule periodic live inventory collection.
     * Uses <code>collectIntervalMinutes</code> (default 1440 = daily); disabled if 0.
     */
    obj.scheduleInventoryCollection = function () {
        var cfg = obj.collectorConfig();
        if (cfg.intervalMinutes <= 0) { obj.debug('plugin:inventory_scanner', 'Live inventory collection is disabled (collectIntervalMinutes=0)'); return; }
        obj.debug('plugin:inventory_scanner', 'Live inventory collection every', cfg.intervalMinutes, 'minutes');
        var gen = obj.timerGen;
        // First pass shortly after startup (agents may need a moment to reconnect),
        // then keep collecting periodically.
        setTimeout(function () { if (obj.timerValid(gen)) { obj.collectAndReschedule(); } }, 20000);
    };

    /**
     * @brief Run one collection cycle and reschedule the next one after the interval.
     * @param {number} intervalMs - The delay in milliseconds before the next cycle.
     */
    obj.collectAndReschedule = function () {
        var gen = obj.timerGen;
        obj.collectAllOnline();
        // Re-read the config every cycle so settings saved in the UI take effect
        // without a restart; stop the chain if collection was disabled meanwhile.
        var intervalMs = obj.collectorConfig().intervalMinutes * 60 * 1000;
        if (intervalMs <= 0) { return; }
        obj.longTimeout(function () { if (obj.timerValid(gen)) { obj.collectAndReschedule(); } }, intervalMs);
    };

    /**
     * @brief Send collection commands to all currently online agents.
     * Asks each online agent for its installed software and (on Windows) its QFE patches.
     */
    obj.collectAllOnline = function () {
        try {
            var ws = obj.meshServer.webserver;
            if ((ws == null) || (ws.wsagents == null)) return;
            for (var nodeid in ws.wsagents) {
                var agent = ws.wsagents[nodeid];
                if (agent == null) continue;
                obj.collectNodeSequential(nodeid, agent);
            }
        } catch (e) {
            obj.debug('plugin:inventory_scanner', 'Error during inventory collection:', e.message);
        }
    };

    /**
     * @brief Send a software-collection command to a single agent.
     * @param {string} nodeId - The node id.
     * @param {object} agent - The agent websocket object.
     */
    obj.collectNodeSoftware = function (nodeId, agent) {
        try {
            if (typeof agent.send !== 'function') return;
            obj.pendingCollection[nodeId] = true;
            // Since MeshCentral commit cdc9582ada (2026-11-09) the agent refuses 'software'
            // commands without a numeric rights field. The server-side collector sends the least
            // value that permits the inventory read: Remote Control (8), NOT the full-admin mask -
            // uninstall types stay refused by the agent. Older agents ignore the field.
            agent.send(JSON.stringify({ action: 'software', type: 'installedapps', rights: 8, responseid: 'invscanner' }));
            // Clear the interest flag if no answer arrives (offline mid-request, old agent).
            setTimeout(function () { try { delete obj.pendingCollection[nodeId]; } catch (e) { } }, 120000);
        } catch (e) { delete obj.pendingCollection[nodeId]; }
    };

    /**
     * @brief Send a Windows-update status request to a single agent.
     * Uses the agent's console command <code>winupdates</code> (getAvailableUpdates),
     * which reports the number of missing/pending updates.
     * @param {string} nodeId - The node id.
     * @param {object} agent - The agent websocket object.
     */
    obj.collectNodeWindowsUpdates = function (nodeId, agent) {
        try {
            if (typeof agent.send !== 'function') return;
            if (obj.pendingWinUpdates == null) { obj.pendingWinUpdates = {}; }
            obj.pendingWinUpdates[nodeId] = true;
            // Clear the interest flag after a while if no answer arrives.
            setTimeout(function () { try { delete obj.pendingWinUpdates[nodeId]; } catch (e) { } }, 90000);
            // Sent through the agent's console-command channel with the console
            // rights bits (Remote Control 8 | Console 16 = 24) and a unique sessionid
            // so the response is identified and not delivered to any browser session.
            var sid = 'invscanner-' + safeNodeDir(nodeId);
            var rights = 24;
            agent.send(JSON.stringify({ action: 'msg', type: 'console', value: 'winupdates', rights: rights, sessionid: sid }));
        } catch (e) { if (obj.pendingWinUpdates) { delete obj.pendingWinUpdates[nodeId]; } }
    };

    /**
     * @brief Collect software and then the Windows-update status for a single agent.
     * This avoids firing both (potentially expensive) agent commands at once and
     * helps keep per-client load low. The update check can take up to a minute.
     * @param {string} nodeId - The node id.
     * @param {object} agent - The agent websocket object.
     */
    obj.collectNodeSequential = function (nodeId, agent) {
        try {
            if ((nodeId == null) || (agent == null) || (typeof agent.send !== 'function')) return;
            obj.collectNodeSoftware(nodeId, agent);
            setTimeout(function () {
                obj.collectNodeWindowsUpdates(nodeId, agent);
            }, 1500);
        } catch (e) { }
    };

    /**
     * @brief Random stagger delay used when many agents reconnect at once
     * (e.g. right after a server restart). Spreads collection over several
     * minutes so the fleet is not queried as a single "thundering herd".
     * @returns {number} Delay in milliseconds (5s to 5min).
     */
    obj.staggerDelay = function () {
        return 5000 + Math.floor(Math.random() * ((5 * 60 * 1000) - 5000));
    };

    /**
     * @brief MeshCentral hook called once an agent core connection is stable
     * (i.e. the agent just came online). Collects software/patches immediately
     * so fresh data is available shortly after a device reconnects, instead of
     * waiting for the next periodic pass. The request is staggered randomly so a
     * fleet reconnecting after a server restart does not all get queried at once.
     * @param {object} agentObj - The meshagent object (has <code>dbNodeKey</code> and <code>send</code>).
     * @param {object} parent - The meshagent module object.
     */
    obj.hook_agentCoreIsStable = function (agentObj, parent) {
        try {
            if ((agentObj == null) || (agentObj.dbNodeKey == null)) return;
            try {
                var wgNode = agentObj.dbNodeKey;
                setTimeout(function () { try { obj.wgQueueNode(wgNode, 'connect'); } catch (e) { } }, obj.staggerDelay ? obj.staggerDelay() : 60000);
            } catch (e) { }
            var cfg = obj.collectorConfig();
            if (cfg.collectOnAgentConnect === false) return;
            if (typeof agentObj.send !== 'function') return;
            // Let the agent fully settle, then spread the query over a random
            // window so a large fleet does not create a load spike on reconnect.
            setTimeout(function () {
                try { obj.collectNodeSequential(agentObj.dbNodeKey, agentObj); } catch (e) { }
            }, obj.staggerDelay());
        } catch (e) { }
    };

    /**
     * @brief Download a remote URL to a file on disk.
     * @param {string} url - The HTTPS URL to download.
     * @param {string} destPath - Local destination file path.
     * @param {function} callback - Called with <code>null</code> on success or an Error.
     */
    function httpGetToFile(url, destPath, callback, redirects) {
        var redirectsLeft = (redirects == null) ? 5 : redirects;
        var req = https.get(url, { timeout: 600000, headers: { 'User-Agent': 'MeshCentral-InventoryScanner' } }, function (res) {
            if ((res.statusCode >= 300) && (res.statusCode < 400) && (res.headers.location)) {
                res.resume();
                if (redirectsLeft <= 0) { callback(new Error('Too many redirects for ' + url)); return; }
                try { httpGetToFile(new URL(res.headers.location, url).href, destPath, callback, redirectsLeft - 1); }
                catch (e) { callback(new Error('Invalid redirect for ' + url)); }
                return;
            }
            if (res.statusCode !== 200) { res.resume(); callback(new Error('HTTP ' + res.statusCode + ' for ' + url)); return; }
            var out = fs.createWriteStream(destPath);
            res.pipe(out);
            out.on('finish', function () { out.close(function () { callback(null); }); });
            out.on('error', function (err) { try { fs.unlinkSync(destPath); } catch (e) { } callback(err); });
        });
        req.on('error', function (err) { callback(err); });
        req.on('timeout', function () { req.destroy(new Error('Timeout downloading ' + url)); });
    }

    /**
     * @brief Download and verify one year of the NVD 2.0 feed.
     * Downloads the <code>.meta</code> (sha256) and <code>.json.gz</code>, verifies
     * the SHA-256 checksum, then decompresses to <code>.json</code>.
     * @param {number|string} year - The feed year.
     * @param {function} callback - Called with <code>null</code> on success or an Error.
     */
    obj.downloadYear = function (year, callback) {
        var base = 'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-' + year;
        var gzPath = path.join(obj.nvdDataPath, 'nvdcve-2.0-' + year + '.json.gz');
        var jsonPath = path.join(obj.nvdDataPath, 'nvdcve-2.0-' + year + '.json');

        httpGetToFile(base + '.meta', gzPath + '.meta', function (metaErr) {
            var expectedSha = null;
            if (!metaErr) {
                try {
                    var m = fs.readFileSync(gzPath + '.meta', 'utf8').match(/^sha256:([0-9A-Fa-f]+)\s*$/m);
                    if (m) { expectedSha = m[1].toLowerCase(); }
                } catch (e) { }
            }

            httpGetToFile(base + '.json.gz', gzPath, function (dlErr) {
                if (dlErr) {
                    obj.nvdLog('NVD ' + year + ': download error, deleting partial gz: ' + dlErr.message);
                    try { fs.unlinkSync(gzPath); } catch (e) { }
                    callback(dlErr); return;
                }

                if (expectedSha) {
                    var actual = crypto.createHash('sha256').update(fs.readFileSync(gzPath)).digest('hex');
                    if (actual !== expectedSha) {
                        var sz = -1; try { sz = fs.statSync(gzPath).size; } catch (e) { }
                        // NVD sometimes serves a .meta checksum that does not match the
                        // .json.gz it actually delivers (verified: the gz is complete and
                        // hashes consistently, only the .meta is stale/wrong). Treat a
                        // mismatch as a warning, not a hard failure, so a valid feed is
                        // not discarded. The gz is complete and identical across retries.
                        obj.nvdLog('NVD ' + year + ': WARNING SHA-256 mismatch vs meta (expected ' + expectedSha + ', got ' + actual + '), continuing anyway. gz size: ' + sz + ' bytes');
                    }
                }

                var gunzip = zlib.createGunzip();
                var src = fs.createReadStream(gzPath);
                var out = fs.createWriteStream(jsonPath);
                src.pipe(gunzip).pipe(out);
                out.on('finish', function () {
                    var js = -1; try { js = fs.statSync(jsonPath).size; } catch (e) { }
                    obj.nvdLog('NVD ' + year + ': gunzip ok, json size: ' + js + ' bytes');
                    try { fs.unlinkSync(gzPath); } catch (e) { }
                    callback(null);
                });
                out.on('error', function (err) {
                    obj.nvdLog('NVD ' + year + ': gunzip error, deleting files: ' + err.message);
                    try { fs.unlinkSync(jsonPath); } catch (e) { }
                    try { fs.unlinkSync(gzPath); } catch (e) { }
                    callback(err);
                });
                src.on('error', function (err) {
                    obj.nvdLog('NVD ' + year + ': read gz stream error: ' + err.message);
                    try { fs.unlinkSync(jsonPath); } catch (e) { }
                    try { fs.unlinkSync(gzPath); } catch (e) { }
                    callback(err);
                });
            });
        });
    };

/**
     * @brief Download the NVD feeds for all years from FIRST_YEAR to the current year.
     * @param {boolean} refreshCurrentYear - If true, re-download the current year's feed
     * even when a file already exists (used by the scheduled update).
     * @param {function} [callback] - Called with (err) when all downloads complete.
     */
    obj.downloadNvdDatabase = function (refreshCurrentYear, callback) {
        var current = obj.currentYear();
        var years = [];
        for (var y = obj.FIRST_YEAR; y <= current; y++) { years.push(y); }

        // Load the years sequentially (one after another) instead of all at once:
        // NVD rate-limits the many simultaneous large downloads, which previously
        // left only the tiny .meta files behind. A short pause between years and a
        // per-year retry with exponential backoff make the download robust.
        var pending = years.filter(function (year) {
            var jsonPath = path.join(obj.nvdDataPath, 'nvdcve-2.0-' + year + '.json');
            var isCurrent = (year === current);
            return !(fs.existsSync(jsonPath) && !(refreshCurrentYear && isCurrent));
        });
        if (pending.length === 0) { obj.loadNvdFromAllFiles(); if (callback) callback(null); return; }

        var failed = 0;
        var idx = 0;

        var next = function () {
            if (idx >= pending.length) {
                if (failed === 0) {
                    obj.lastUpdate = new Date().toISOString();
                    obj.loadNvdFromAllFiles();
                }
                obj.nvdLog('NVD download run finished. Failures: ' + failed + ' of ' + pending.length + '. Years attempted: ' + pending.join(', '));
                obj.debug('plugin:inventory_scanner', 'NVD download finished, failures:', failed, 'of', pending.length);
                if (callback) callback(failed === 0 ? null : new Error('Some downloads failed'));
                return;
            }
            var year = pending[idx];
            var attempt = 0;
            var tryDownload = function () {
                attempt++;
                obj.nvdLog('NVD ' + year + ': starting download (attempt ' + attempt + ')');
                obj.downloadYear(year, function (err) {
                    if (err) {
                        obj.debug('plugin:inventory_scanner', 'NVD', year, 'download failed (attempt', attempt + '):', err.message);
                        // Exponential backoff: 5s, 30s, 2min, then give up
                        var delay = attempt === 1 ? 5000 : (attempt === 2 ? 30000 : 120000);
                        if (attempt < 3) {
                            obj.nvdLog('NVD ' + year + ': download failed (' + err.message + '), retrying in ' + (delay / 1000) + 's');
                            setTimeout(tryDownload, delay);
                            return;
                        }
                        failed++;
                        idx++;
                        obj.nvdLog('NVD ' + year + ': giving up after ' + attempt + ' attempts');
                        setTimeout(next, 2000);
                        return;
                    }
                    idx++;
                    obj.nvdLog('NVD ' + year + ': download complete');
                    setTimeout(next, 2000);
                });
            };
            tryDownload();
        };
        next();
    };

    // ---- Indexing ----

    /**
     * @brief Load all downloaded NVD feed files into the in-memory index.
     * Resets <code>productIndex</code> and <code>allCves</code> before loading.
     */
obj.loadNvdFromAllFiles = function () {
        obj.productIndex = {};
        obj.productIndexByProduct = {};
        obj.cpeProductTokens = {};
        obj.cpeVendorTokens = {};
        obj.allCves = [];
        var current = obj.currentYear();
        var newestMtime = null;
        for (var y = obj.FIRST_YEAR; y <= current; y++) {
            var file = path.join(obj.nvdDataPath, 'nvdcve-2.0-' + y + '.json');
            if (fs.existsSync(file)) {
                obj.loadNvdFromFile(file);
                try {
                    var mt = fs.statSync(file).mtimeMs;
                    if ((newestMtime == null) || (mt > newestMtime)) { newestMtime = mt; }
                } catch (e) { }
            }
        }
        // Derive the NVD status from the loaded feed files themselves, so the UI shows
        // a real timestamp even when the feeds were downloaded by an earlier run. Only
        // when no feed file exists at all is the database considered "not downloaded".
        if (newestMtime != null) { obj.lastUpdate = new Date(newestMtime).toISOString(); }
        else { obj.lastUpdate = null; }
        obj.debug('plugin:inventory_scanner', 'Total CVEs indexed:', obj.allCves.length);
    };

    /**
     * @brief Parse a single NVD feed file and index its vulnerabilities.
     * Files up to 256 MB are parsed in one piece. Larger files (the 2026 feed is ~520 MB,
     * above V8's maximum string length of ~512 MB, so readFileSync(...,'utf8') THROWS and
     * every CVE of that year was silently missing before v3.1.0) go through
     * splitNvdVulnerabilities, which never builds a string of the whole file.
     * @param {string} file - Path to a <code>nvdcve-2.0-<year>.json</code> file.
     * @returns {number} number of vulnerabilities indexed from this file.
     */
    obj.loadNvdFromFile = function (file) {
        try {
            var size = fs.statSync(file).size;
            if (size <= obj.NVD_WHOLE_PARSE_MAX) {
                var data = JSON.parse(fs.readFileSync(file, 'utf8'));
                if (data && Array.isArray(data.vulnerabilities)) { obj.processNvdData(data.vulnerabilities); return data.vulnerabilities.length; }
                return 0;
            }
            var n = 0, batch = [];
            obj.splitNvdVulnerabilities(fs.readFileSync(file), function (item) {
                batch.push(item); n++;
                if (batch.length >= 2000) { obj.processNvdData(batch); batch = []; }
            });
            if (batch.length > 0) { obj.processNvdData(batch); }
            return n;
        } catch (err) {
            obj.nvdLog('Error loading NVD file ' + path.basename(file) + ': ' + err.message);
            return 0;
        }
    };

    /** @type {number} files above this size are split instead of parsed whole (bytes). */
    obj.NVD_WHOLE_PARSE_MAX = 256 * 1024 * 1024;

    /**
     * @brief Split the "vulnerabilities" array of an NVD 2.0 feed buffer into single parsed
     * objects without ever creating a string of the whole buffer. Byte-level scanner: tracks
     * string/escape state and brace depth; every top-level array element is sliced out of the
     * buffer and JSON.parse'd on its own (a few KB each).
     * @param {Buffer} buf - Whole feed file.
     * @param {function} onItem - Called with each parsed vulnerability object.
     */
    obj.splitNvdVulnerabilities = function (buf, onItem) {
        var key = Buffer.from('"vulnerabilities"');
        var at = buf.indexOf(key);
        if (at < 0) { throw new Error('no vulnerabilities array'); }
        var i = buf.indexOf(0x5B, at + key.length); // '['
        if (i < 0) { throw new Error('no vulnerabilities array'); }
        i++;
        var len = buf.length, depth = 0, inStr = false, esc = false, start = -1;
        for (; i < len; i++) {
            var c = buf[i];
            if (inStr) {
                if (esc) { esc = false; }
                else if (c === 0x5C) { esc = true; }      // backslash
                else if (c === 0x22) { inStr = false; }   // quote
                continue;
            }
            if (c === 0x22) { inStr = true; continue; }
            if (c === 0x7B) { if (depth === 0) { start = i; } depth++; continue; }   // {
            if (c === 0x7D) {                                                          // }
                depth--;
                if (depth === 0 && start >= 0) { onItem(JSON.parse(buf.toString('utf8', start, i + 1))); start = -1; }
                continue;
            }
            if (c === 0x5D && depth === 0) { return; }   // ] closes the array
        }
        throw new Error('truncated vulnerabilities array');
    };

    /**
     * @brief Index a list of NVD vulnerability objects into <code>productIndex</code>.
     * @param {Array<object>} vulnerabilities - The <code>vulnerabilities[]</code> array from an NVD feed.
     */
    obj.processNvdData = function (vulnerabilities) {
        for (var i = 0; i < vulnerabilities.length; i++) {
            var cveData = vulnerabilities[i] && vulnerabilities[i].cve;
            if (!cveData || !cveData.id) continue;

            var cveRecord = {
                id: cveData.id,
                published: cveData.published || '',
                description: '',
                cvss: null,
                severity: 'UNKNOWN',
                references: []
            };

            if (Array.isArray(cveData.descriptions)) {
                for (var d = 0; d < cveData.descriptions.length; d++) {
                    if (cveData.descriptions[d] && cveData.descriptions[d].lang === 'en' && cveData.descriptions[d].value) {
                        cveRecord.description = cveData.descriptions[d].value;
                        break;
                    }
                }
            }

            // Prefer CVSS v3.1, then v3.0, then v2.
            if (cveData.metrics) {
                var cvssSources = [cveData.metrics.cvssMetricV31, cveData.metrics.cvssMetricV30, cveData.metrics.cvssMetricV2];
                for (var c = 0; c < cvssSources.length; c++) {
                    if (Array.isArray(cvssSources[c]) && cvssSources[c].length > 0 && cvssSources[c][0].cvssData) {
                        cveRecord.cvss = cvssSources[c][0].cvssData.baseScore || 0;
                        cveRecord.severity = cvssSources[c][0].cvssData.baseSeverity || 'UNKNOWN';
                        break;
                    }
                }
            }

            if (Array.isArray(cveData.references)) {
                for (var r = 0; r < cveData.references.length; r++) {
                    if (cveData.references[r] && cveData.references[r].url) { cveRecord.references.push(cveData.references[r].url); }
                }
            }

            // Index vulnerable CPEs from configurations[].nodes[].cpeMatch[].
            if (Array.isArray(cveData.configurations)) {
                var defs = obj.extractCpeDefsFromConfig(cveData.configurations);
                for (var p = 0; p < defs.length; p++) {
                    var def = defs[p];
                    var key = def.vendor + '|' + def.product;
                    if (!obj.productIndex[key]) { obj.productIndex[key] = []; }
                    def.cves = [cveRecord];
                    obj.productIndex[key].push(def);

                    // Build the product-only index (sorted at load time) so CVEs can
                    // be searched by product name alone, independent of vendor.
                    var pkey = def.product;
                    obj.cpeProductTokens[pkey] = 1;
                    if (def.part === 'a') { obj.cpeVendorTokens[def.vendor] = 1; }
                    if (!obj.productIndexByProduct[pkey]) { obj.productIndexByProduct[pkey] = []; }
                    var vendors = obj.productIndexByProduct[pkey];
                    var vfound = null;
                    for (var vi = 0; vi < vendors.length; vi++) {
                        if (vendors[vi].vendor === def.vendor) { vfound = vendors[vi]; break; }
                    }
                    if (!vfound) { vfound = { vendor: def.vendor, defs: [] }; vendors.push(vfound); }
                    vfound.defs.push(def);
                }
            }

            obj.allCves.push(cveRecord);
        }
    };

    /**
     * @brief Extract CPE match definitions from an NVD 2.0 configurations structure.
     * Includes applications (CPE part <code>'a'</code>) and operating systems
     * (CPE part <code>'o'</code>).
     * @param {Array<object>} config - The <code>configurations[]</code> array.
     * @returns {Array<object>} An array of CPE match definitions.
     */
    obj.extractCpeDefsFromConfig = function (config) {
        var defs = [];
        /**
         * @brief Recursively process a configurations node.
         * @param {object} node - A node within the configurations tree.
         */
        function processNode(node) {
            if (!node) return;
            if (Array.isArray(node.cpeMatch)) {
                for (var i = 0; i < node.cpeMatch.length; i++) {
                    var cm = node.cpeMatch[i];
                    if (!cm || (cm.vulnerable !== true) || !cm.criteria) continue;
                    var parts = String(cm.criteria).split(':');
                    if (parts.length < 5) continue;
                    var part = parts[2];
                    if ((part !== 'a') && (part !== 'o')) continue;
                    var vendor = String(parts[3] || '').toLowerCase();
                    var product = String(parts[4] || '').toLowerCase();
                    if (!vendor || !product) continue;

                    var criteriaVersion = parts[5] || '';
                    var hasRange = (cm.versionStartIncluding != null) || (cm.versionStartExcluding != null) ||
                                  (cm.versionEndIncluding != null) || (cm.versionEndExcluding != null);

                    var def;
                    if (hasRange) {
                        def = {
                            part: part, kind: 'range', vendor: vendor, product: product,
                            startInc: cm.versionStartIncluding != null ? String(cm.versionStartIncluding) : null,
                            startExc: cm.versionStartExcluding != null ? String(cm.versionStartExcluding) : null,
                            endInc: cm.versionEndIncluding != null ? String(cm.versionEndIncluding) : null,
                            endExc: cm.versionEndExcluding != null ? String(cm.versionEndExcluding) : null,
                            cves: []
                        };
                    } else if ((criteriaVersion === '*') || (criteriaVersion === '-')) {
                        def = { part: part, kind: 'any', vendor: vendor, product: product, cves: [] };
                    } else {
                        def = { part: part, kind: 'exact', vendor: vendor, product: product, version: criteriaVersion, cves: [] };
                    }
                    defs.push(def);
                }
            }
            if (Array.isArray(node.nodes)) {
                for (var j = 0; j < node.nodes.length; j++) { processNode(node.nodes[j]); }
            }
        }
        for (var k = 0; k < config.length; k++) { processNode(config[k]); }
        return defs;
    };

    /**
     * @brief Compare two CPE version strings segment-by-segment.
     * Numeric segments are compared numerically, otherwise lexically. A missing
     * segment sorts before a present one.
     * @param {string} a - First version.
     * @param {string} b - Second version.
     * @returns {number} -1, 0 or 1 depending on comparison.
     */
    obj.compareCpeVersions = function (a, b) {
        if (a === b) return 0;
        var sa = String(a).split('.');
        var sb = String(b).split('.');
        var len = Math.max(sa.length, sb.length);
        for (var i = 0; i < len; i++) {
            var pa = (i < sa.length) ? sa[i] : '';
            var pb = (i < sb.length) ? sb[i] : '';
            if (pa === pb) continue;
            if (pa === '') return -1;
            if (pb === '') return 1;
            var na = parseInt(pa, 10), nb = parseInt(pb, 10);
            if ((!isNaN(na)) && (!isNaN(nb))) {
                if (na < nb) return -1;
                if (na > nb) return 1;
                continue;
            }
            if (pa < pb) return -1;
            if (pa > pb) return 1;
        }
        return 0;
    };

    /**
     * @brief Test whether a CPE match definition covers an installed version.
     * @param {object} def - A CPE match definition.
     * @param {string} version - The installed version.
     * @returns {boolean} True if the definition matches the version.
     */
    /**
     * @brief Extract a comparable version core from an inventory version string.
     * Debian epochs ("1:1snap1-0ubuntu5") are stripped; a real numeric core is
     * returned without distro decoration ("22.04.0-1build1" -> "22.04.0",
     * "3.0~beta2-2" -> "3.0"). Wrapper versions that carry NO usable program
     * version (snap builds such as "1:1snap1-0ubuntu5" where the real Firefox
     * version lives inside the snap, not in dpkg) return '' - which routes the
     * row through the unknown-version logic in defMatches (only all-version
     * definitions, age-filtered) instead of comparing "parseInt('1:1snap1...')"
     * (=1) against fifteen-year-old ranges.
     * @param {string} v - Raw installed version.
     * @returns {string} numeric core, possibly empty = unknown.
     */
    obj.normalizeCveVersion = function (v) {
        var s = String(v == null ? '' : v).trim();
        if (s === '') return '';
        if (/^\d+:/.test(s)) { s = s.replace(/^\d+:/, ''); }
        var hasDot = /\d\.\d/.test(s);
        if (/ubuntu|dfsg|\+exp|bzr|deb\d|repack|~/.test(s)) {
            // Debian/Ubuntu patch upstream fixes into the SAME upstream version -
            // the NVD range check would report CVEs that the distro already fixed.
            // Without OVAL data the honest answer is: version not assessable.
            return '';
        }
        if (!hasDot && /(snap|ubuntu|deb\d|dfsg|ds|build|repack)/i.test(s) && /\d+[a-z]/i.test(s)) { return ''; }
        var m = s.match(/^\d+(?:\.\d+)*/);
        return (m ? m[0] : '');
    };


    obj.defMatches = function (def, version) {
        if (version == null) version = '';
        version = obj.normalizeCveVersion(version);
        if (version === '') {
            // Unknown installed version (entries without DisplayVersion): bounded definitions
            // cannot be asserted. An empty version sorts below every upper bound, so without
            // this guard EVERY historical CVE with an end boundary would match such software.
            // Only "applies to all versions" definitions stay reportable (age-filtered).
            return (def.kind === 'any');
        }
        if (def.kind === 'any') return true;
        if (def.kind === 'exact') {
            var dv = def.version;
            if ((dv === '*') || (dv === '-')) return true;
            return (dv === version);
        }
        if (def.startInc != null) { if (obj.compareCpeVersions(version, def.startInc) < 0) return false; }
        if (def.startExc != null) { if (obj.compareCpeVersions(version, def.startExc) <= 0) return false; }
        if (def.endInc != null) { if (obj.compareCpeVersions(version, def.endInc) > 0) return false; }
        if (def.endExc != null) { if (obj.compareCpeVersions(version, def.endExc) >= 0) return false; }
        return true;
    };

    /**
     * @brief Return the maximum age (in years) for which a CVE with an "any" version
     * (i.e. a CPE definition that applies to ALL versions) is still reported. Older
     * "any"-version CVEs are skipped because they are almost always historical and not
     * relevant to current software versions (they would otherwise match every installed
     * version). Configurable via <code>settings.vulnerabilityScanner.anyCveMaxAgeYears</code>;
     * a value of 0 disables the filter (keep all any-version CVEs). Respects the UI
     * settings overlay (scanner-settings.json overrides config.json).
     * @returns {number} The maximum age in years, or 0 to keep all.
     */
    obj.anyCveMaxAgeYears = function () {
        try {
            var cfg = obj.effectiveSectionConfig('vulnerabilityScanner');
            if (cfg && (typeof cfg.anyCveMaxAgeYears === 'number') && (cfg.anyCveMaxAgeYears >= 0)) {
                return cfg.anyCveMaxAgeYears;
            }
        } catch (e) { }
        return 5; // default: suppress any-version CVEs older than 5 years
    };

    /**
     * @brief Check whether a version-less ("any") CPE definition's CVE is too old to
     * report. An "any"-version definition matches every installed version; if its CVE
     * is older than <code>anyCveMaxAgeYears</code>, it is considered historical noise
     * and should be skipped for current software.
     * @param {object} def - A CPE match definition (<code>kind === 'any'</code>).
     * @param {object} cve - The CVE record (has <code>published</code>).
     * @returns {boolean} True if the CVE should be suppressed because it is too old.
     */
    obj.anyCveTooOld = function (def, cve) {
        if ((def == null) || (def.kind !== 'any') || (cve == null)) return false;
        var maxAge = obj.anyCveMaxAgeYears();
        if (maxAge <= 0) return false; // filter disabled
        var pub = (cve.published != null) ? String(cve.published) : '';
        var year = parseInt(pub.substring(0, 4), 10);
        if (!isNaN(year)) {
            return (obj.currentYear() - year) > maxAge;
        }
        return false;
    };

    /**
     * @brief Search the index for CVEs matching a product/version.
     * @param {string} vendor - The CPE vendor (lower-cased internally).
     * @param {string} product - The CPE product (lower-cased internally).
     * @param {string} version - The installed version.
     * @param {string} [partFilter] - CPE part filter: 'a' (default) or 'o'.
     * @returns {Array<object>} Matching CVE records, deduplicated and sorted by CVSS descending.
     */
    obj.searchCves = function (vendor, product, version, partFilter) {
        if (!vendor || !product) return [];
        var wantPart = partFilter || 'a';
        var defs = obj.productIndex[String(vendor).toLowerCase() + '|' + String(product).toLowerCase()];
        if (!defs || defs.length === 0) return [];

        var results = [];
        for (var i = 0; i < defs.length; i++) {
            if (defs[i].part !== wantPart) continue;
            if (obj.defMatches(defs[i], version)) {
                // Suppress historical "any"-version CVEs for current software.
                var dl = defs[i].cves || [];
                for (var d = 0; d < dl.length; d++) {
                    if (!obj.anyCveTooOld(defs[i], dl[d])) { results.push(dl[d]); }
                }
            }
        }
        var seen = {}, unique = [];
        for (var j = 0; j < results.length; j++) {
            if (results[j] && !seen[results[j].id]) { seen[results[j].id] = true; unique.push(results[j]); }
        }
        unique.sort(function (a, b) { return (b.cvss || 0) - (a.cvss || 0); });
        return unique;
    };

    /**
     * @brief Search the index for CVEs by product name alone, across all vendors.
     * Uses the pre-sorted product index (built at NVD load time) so this is a
     * fast lookup per product, independent of the vendor. Matches CPE application
     * parts only.
     * @param {string} product - The CPE product name (lower-cased).
     * @param {string} version - The installed version.
     * @returns {Array<object>} Matching CVE records, deduplicated and sorted by CVSS descending.
     */
    obj.searchCvesByProduct = function (product, version) {
        if (!product) return [];
        var pkey = String(product).toLowerCase();
        var vendors = obj.productIndexByProduct[pkey];
        if (!vendors || vendors.length === 0) return [];

        var results = [];
        for (var v = 0; v < vendors.length; v++) {
            var defs = vendors[v].defs;
            if (!defs) continue;
            for (var i = 0; i < defs.length; i++) {
                if (defs[i].part !== 'a') continue;
                if (obj.defMatches(defs[i], version)) {
                    // Suppress historical "any"-version CVEs for current software.
                    var dl = defs[i].cves || [];
                    for (var d = 0; d < dl.length; d++) {
                        if (!obj.anyCveTooOld(defs[i], dl[d])) { results.push(dl[d]); }
                    }
                }
            }
        }
        var seen = {}, unique = [];
        for (var j = 0; j < results.length; j++) {
            if (results[j] && !seen[results[j].id]) { seen[results[j].id] = true; unique.push(results[j]); }
        }
        unique.sort(function (a, b) { return (b.cvss || 0) - (a.cvss || 0); });
        return unique;
    };

    // ---- Scanning ----

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
        var tryFiles = [obj.cpeTablePath, path.join(__dirname, 'cpe-table.json')];
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

    // ---- Distribution-managed packages + OS support lifecycle (v3.1.0) ----
    // Linux distributions (Ubuntu, Debian, RHEL, ...) backport security fixes into the SAME
    // upstream version ("2.4.4-2ubuntu17.6" is a patched 2.4.4). An NVD version comparison is
    // therefore meaningless for distro packages: it reports CVEs that are long fixed (false
    // positives) and cannot see distro-only fixes. The honest rule: while the distribution
    // release still gets security updates, its package manager is responsible for these
    // packages; once the release is end-of-life, nothing patches them any more.
    // Support dates come from https://endoflife.date (community-maintained, public API, no key),
    // cached on disk, refreshed with the NVD cycle - never hard-coded.

    /** @type {string} on-disk cache of the lifecycle data. */
    obj.osLifecyclePath = path.join(obj.meshServer.datapath, 'plugins', 'inventoryscanner', 'os-lifecycle.json');
    /** @type {string} default API base (product slug is appended + '.json'). */
    obj.OS_LIFECYCLE_DEFAULT_URL = 'https://endoflife.date/api/';
    /** @type {object} slug -> { fetched, cycles:[{cycle, eol, support, extendedSupport, lts, releaseLabel, latest}] } */
    obj.osLifecycle = {};
    /** @type {Array<string>} products fetched (the slugs the OS detector can produce). */
    obj.OS_LIFECYCLE_SLUGS = ['ubuntu', 'debian', 'rhel', 'centos', 'centos-stream', 'almalinux', 'rocky-linux', 'fedora', 'linux-mint', 'opensuse', 'sles', 'alpine', 'windows', 'windows-server', 'macos'];
    /** @type {number} hard cap per lifecycle payload. */
    obj.OS_LIFECYCLE_MAX_BYTES = 512 * 1024;

    /** @brief Lifecycle status for the Settings tab. */
    obj.osLifecycleStatus = function () {
        var out = { products: 0, fetched: '', enabled: obj.scannerConfig().osLifecycleEnabled };
        for (var k in obj.osLifecycle) { if (Object.prototype.hasOwnProperty.call(obj.osLifecycle, k)) { out.products++; if (obj.osLifecycle[k].fetched > out.fetched) { out.fetched = obj.osLifecycle[k].fetched; } } }
        return out;
    };

    /** @brief Load the cached lifecycle data (silent). */
    obj.loadOsLifecycle = function () {
        obj.osLifecycle = {};
        try {
            if (fs.existsSync(obj.osLifecyclePath)) {
                var d = JSON.parse(fs.readFileSync(obj.osLifecyclePath, 'utf8'));
                if (d && typeof d === 'object') {
                    for (var k in d) {
                        if (Object.prototype.hasOwnProperty.call(d, k) && obj.OS_LIFECYCLE_SLUGS.indexOf(k) >= 0 && d[k] && Array.isArray(d[k].cycles)) {
                            obj.osLifecycle[k] = { fetched: String(d[k].fetched || ''), cycles: obj.sanitizeLifecycleCycles(d[k].cycles) };
                        }
                    }
                }
            }
        } catch (e) { obj.osLifecycle = {}; }
    };

    /** @brief Keep only the fields used, with strict types (the payload is external data). */
    obj.sanitizeLifecycleCycles = function (arr) {
        var out = [];
        var dateOrBool = function (v) { return (typeof v === 'boolean') ? v : ((typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v)) ? v : null); };
        for (var i = 0; i < arr.length && out.length < 500; i++) {
            var c = arr[i];
            if (!c || (typeof c.cycle !== 'string' && typeof c.cycle !== 'number')) continue;
            var cy = String(c.cycle);
            if (!/^[A-Za-z0-9._-]{1,40}$/.test(cy)) continue;
            out.push({
                cycle: cy, eol: dateOrBool(c.eol), support: dateOrBool(c.support), extendedSupport: dateOrBool(c.extendedSupport),
                lts: c.lts === true, releaseLabel: (typeof c.releaseLabel === 'string') ? c.releaseLabel.substring(0, 60) : '',
                latest: (typeof c.latest === 'string') ? c.latest.substring(0, 40) : ''
            });
        }
        return out;
    };

    /** @brief HTTP GET JSON for one lifecycle product (https only, size-capped; test indirection). */
    obj.osLifecycleHttpGet = function (url, callback) { obj.cpeTableHttpGet(url, callback); };

    /**
     * @brief Refresh the lifecycle cache when enabled and older than the NVD cycle. One request
     * per product, sequential; a failing product keeps its cached data.
     */
    obj.maybeFetchOsLifecycle = function (callback) {
        var scfg = obj.scannerConfig();
        if (!scfg.osLifecycleEnabled) { if (callback) callback(null, { skipped: 'disabled' }); return; }
        var uh = 168;
        try { var ec = obj.effectiveSectionConfig('vulnerabilityScanner'); if (ec && (typeof ec.updateHours === 'number') && (ec.updateHours >= 1)) { uh = ec.updateHours; } } catch (e) { }
        var now = Date.now(), due = [];
        for (var i = 0; i < obj.OS_LIFECYCLE_SLUGS.length; i++) {
            var s = obj.OS_LIFECYCLE_SLUGS[i], rec = obj.osLifecycle[s];
            var age = (rec && rec.fetched) ? (now - Date.parse(rec.fetched)) : Infinity;
            if (!(age < uh * 3600 * 1000)) { due.push(s); }
        }
        if (due.length === 0) { if (callback) callback(null, { skipped: 'fresh' }); return; }
        var base = scfg.osLifecycleUrl, ok = 0, failed = 0;
        var next = function (k) {
            if (k >= due.length) {
                if (ok > 0) {
                    try { fs.mkdirSync(path.dirname(obj.osLifecyclePath), { recursive: true }); fs.writeFileSync(obj.osLifecyclePath, JSON.stringify(obj.osLifecycle)); } catch (e) { }
                }
                obj.nvdLog('OS lifecycle data: ' + ok + ' product(s) refreshed, ' + failed + ' failed (source ' + base + ')');
                if (callback) callback(null, { ok: ok, failed: failed });
                return;
            }
            obj.osLifecycleHttpGet(base + due[k] + '.json', function (err, text) {
                var arr = null;
                if (!err) { try { arr = JSON.parse(text); } catch (e) { arr = null; } }
                if (Array.isArray(arr) && arr.length > 0) {
                    obj.osLifecycle[due[k]] = { fetched: new Date().toISOString(), cycles: obj.sanitizeLifecycleCycles(arr) };
                    ok++;
                } else { failed++; }
                next(k + 1);
            });
        };
        next(0);
    };

    /**
     * @brief Identify the OS release of a node for the lifecycle lookup.
     * @param {string} osDesc - node.osdesc ("Ubuntu 24.04.5 LTS", "Microsoft Windows 11 Pro - 25H2/26200", ...).
     * @returns {object|null} { slug, cycles:[candidate cycle names, most specific first], label }.
     */
    obj.osReleaseOf = function (osDesc) {
        var d = String(osDesc || ''), m;
        var ver = function (re) { var x = d.match(re); return x ? x : null; };
        if (/ubuntu/i.test(d) && (m = ver(/(\d{2})\.(\d{2})/))) return { slug: 'ubuntu', cycles: [m[1] + '.' + m[2]], label: 'Ubuntu ' + m[1] + '.' + m[2] };
        if (/linux mint/i.test(d) && (m = ver(/(\d+)(?:\.(\d+))?/))) return { slug: 'linux-mint', cycles: m[2] != null ? [m[1] + '.' + m[2], m[1]] : [m[1]], label: 'Linux Mint ' + m[0] };
        if (/debian/i.test(d) && (m = ver(/(\d+)/))) return { slug: 'debian', cycles: [m[1]], label: 'Debian ' + m[1] };
        if (/centos stream/i.test(d) && (m = ver(/(\d+)/))) return { slug: 'centos-stream', cycles: [m[1]], label: 'CentOS Stream ' + m[1] };
        if (/centos/i.test(d) && (m = ver(/(\d+)/))) return { slug: 'centos', cycles: [m[1]], label: 'CentOS ' + m[1] };
        if (/red hat|rhel/i.test(d) && (m = ver(/(\d+)/))) return { slug: 'rhel', cycles: [m[1]], label: 'RHEL ' + m[1] };
        if (/almalinux/i.test(d) && (m = ver(/(\d+)/))) return { slug: 'almalinux', cycles: [m[1]], label: 'AlmaLinux ' + m[1] };
        if (/rocky/i.test(d) && (m = ver(/(\d+)/))) return { slug: 'rocky-linux', cycles: [m[1]], label: 'Rocky Linux ' + m[1] };
        if (/fedora/i.test(d) && (m = ver(/(\d+)/))) return { slug: 'fedora', cycles: [m[1]], label: 'Fedora ' + m[1] };
        if (/suse linux enterprise|sles/i.test(d) && (m = ver(/(\d+)(?:\s*SP(\d+)|\.(\d+))?/i))) { var sp = m[2] || m[3]; return { slug: 'sles', cycles: sp != null ? [m[1] + '.' + sp] : [m[1] + '.0'], label: 'SLES ' + m[0] }; }
        if (/opensuse/i.test(d) && (m = ver(/(\d+\.\d+)/))) return { slug: 'opensuse', cycles: [m[1]], label: 'openSUSE ' + m[1] };
        if (/alpine/i.test(d) && (m = ver(/(\d+)\.(\d+)/))) return { slug: 'alpine', cycles: [m[1] + '.' + m[2]], label: 'Alpine ' + m[1] + '.' + m[2] };
        if (/windows server/i.test(d) && (m = ver(/(20\d\d)(\s*r2)?/i))) return { slug: 'windows-server', cycles: [m[1] + (m[2] ? '-r2' : '')], label: 'Windows Server ' + m[1] + (m[2] ? ' R2' : '') };
        if (/windows (10|11)/i.test(d) && (m = ver(/windows (10|11)/i))) {
            var rel = d.match(/\b(\d{2}h\d|\d{4})\b(?!\d)/i), ed = /enterprise|education/i.test(d) ? 'e' : 'w';
            if (rel) { var r = rel[1].toLowerCase(); return { slug: 'windows', cycles: [m[1] + '-' + r + '-' + ed, m[1] + '-' + r], label: 'Windows ' + m[1] + ' ' + r.toUpperCase() }; }
            return { slug: 'windows', cycles: [], label: 'Windows ' + m[1] };
        }
        if (/windows 7/i.test(d)) return { slug: 'windows', cycles: ['7-sp1'], label: 'Windows 7' };
        if (/windows 8\.1/i.test(d)) return { slug: 'windows', cycles: ['8.1'], label: 'Windows 8.1' };
        return null;
    };

    /**
     * @brief Support state of a node's OS release.
     * @param {string} osDesc - node.osdesc.
     * @param {number} [now] - epoch ms (tests).
     * @returns {object} { state:'supported'|'eol'|'unknown', label, eol, source, reason }.
     *   'unknown' = release not identified or no lifecycle data (offline / disabled).
     */
    obj.osSupportState = function (osDesc, now) {
        var rel = obj.osReleaseOf(osDesc);
        if (rel == null) return { state: 'unknown', label: String(osDesc || ''), eol: '', reason: 'OS release not recognized' };
        var data = obj.osLifecycle[rel.slug];
        if (!data || !Array.isArray(data.cycles) || data.cycles.length === 0) return { state: 'unknown', label: rel.label, eol: '', reason: 'no lifecycle data (endoflife.date not fetched yet or disabled)' };
        var hit = null;
        for (var i = 0; i < rel.cycles.length && hit == null; i++) {
            for (var j = 0; j < data.cycles.length; j++) { if (data.cycles[j].cycle.toLowerCase() === rel.cycles[i]) { hit = data.cycles[j]; break; } }
        }
        if (hit == null) return { state: 'unknown', label: rel.label, eol: '', reason: 'release cycle not listed at endoflife.date' };
        var t = (now != null) ? now : Date.now();
        var end = hit.eol;
        if (end === false) return { state: 'supported', label: rel.label, eol: '', reason: 'no end-of-life date announced' };
        if (end === true) return { state: 'eol', label: rel.label, eol: '', reason: 'end of life' };
        if (typeof end === 'string') {
            var supported = (Date.parse(end + 'T23:59:59Z') >= t);
            return { state: supported ? 'supported' : 'eol', label: rel.label, eol: end, reason: (supported ? 'security updates until ' : 'security updates ended ') + end };
        }
        return { state: 'unknown', label: rel.label, eol: '', reason: 'no end-of-life date in the lifecycle data' };
    };

    /**
     * @brief True when an inventory row was reported by a Linux package manager. The MeshCentral
     * agent tags these rows with location 'dpkg'|'rpm'|'pacman'|'apk' (verified in
     * agents/modules_meshcore/linux-info.js); older inventories without that field are
     * recognized by the Debian/RPM maintainer format "Name &lt;mail@host&gt;" in the publisher.
     * @param {object} sw - inventory row.
     * @returns {boolean}
     */
    obj.isDistroPackage = function (sw) {
        if (sw == null) return false;
        var loc = String(sw.location || sw.installLocation || '').toLowerCase();
        if (loc === 'dpkg' || loc === 'rpm' || loc === 'pacman' || loc === 'apk') return true;
        return /<[^<>@\s]+@[^<>\s]+>\s*$/.test(String(sw.publisher || sw.Publisher || ''));
    };
    /**
     * @brief Third-party repositories (Docker, NVIDIA, Google, ...) also install through the
     * package manager, but they are NOT patched by the distribution's security team. Rows whose
     * maintainer address belongs to the distribution itself are distro-managed; others stay
     * subject to the normal CVE check.
     * @param {object} sw - inventory row (isDistroPackage === true).
     * @returns {boolean}
     */
    obj.isDistroMaintained = function (sw) {
        var p = String(sw.publisher || sw.Publisher || '').toLowerCase();
        var m = p.match(/@([^<>\s]+)>\s*$/);
        if (!m) return String(sw.location || '').toLowerCase() === 'apk' || String(sw.location || '').toLowerCase() === 'pacman';
        return obj.DISTRO_MAINTAINER_DOMAINS.test(m[1]);
    };
    /** @type {RegExp} mail domains of distribution package maintainers (the distribution itself). */
    obj.DISTRO_MAINTAINER_DOMAINS = /(^|\.)(ubuntu\.com|canonical\.com|debian\.org|redhat\.com|fedoraproject\.org|centos\.org|almalinux\.org|rockylinux\.org|suse\.(com|de)|opensuse\.org|alpinelinux\.org|archlinux\.org|linuxmint\.com)$/;
    /**
     * @brief First table hit for a display name (custom entries win, then the active
     * curated table, first match). Returns { vendor, product } for a CPE mapping row
     * or { kind } for a driver/firmware exclusion row - the FIRST hit is final, so an
     * exclusion placed before a broader CPE row suppresses it on purpose.
     * @param {string} name - The software display name.
     * @returns {object|null} { vendor, product } | { kind } | null.
     */
    obj.matchTableEntry = function (name) {
        if (!name) return null;
        var custom = obj.compiledCustomCpe();
        for (var c = 0; c < custom.length; c++) {
            if (custom[c].match.test(name)) { return { vendor: custom[c].vendor, product: custom[c].product }; }
        }
        var table = obj.activeSoftwareTable();
        for (var i = 0; i < table.length; i++) {
            var e = table[i];
            if (e.match.test(name)) { return (e.kind != null) ? { kind: e.kind } : { vendor: e.vendor, product: e.product }; }
        }
        return null;
    };

    /**
     * @brief Map a display name to a known CPE vendor/product via the curated table
     * (kind/exclusion hits deliberately return null - use obj.matchTableEntry/classifySoftware).
     * @param {string} name - The software display name.
     * @returns {object|null} <code>{ vendor, product }</code>, or null.
     */
    obj.matchKnownProduct = function (name) {
        var ent = obj.matchTableEntry(name);
        if (ent == null || ent.kind != null) return null;
        return { vendor: ent.vendor, product: ent.product };
    };

    /** @brief Conservative name rule for clearly driver/firmware software - only consulted
     *  AFTER curated+auto matching proved there is no CPE for the row, and never for
     *  driver TOOLs (booster/wizard/... are applications about drivers, not drivers). */
    obj.DRIVERTOOL_RE = /\b(booster|commander|genius|hub|wizard|assistant|studio|sdk|installer|pack(age)?s?)\b/i;
    obj.guessDriverFirmware = function (name) {
        var n = String(name || '');
        if (n === '' || obj.DRIVERTOOL_RE.test(n)) return null;
        if (/\b(firmware|bios|uefi)\b/i.test(n)) return 'firmware';
        if (/\b(drivers?|treiber)\b/i.test(n)) return 'driver';
        return null;
    };

    /**
     * @brief Full classification of one installed-software row.
     * Order: table hit (CPE or explicit kind exclusion) -> automatic evidence matcher ->
     * conservative driver/firmware name guess (only when nothing else matched).
     * @param {string} name - Display name.
     * @param {string} publisher - Publisher.
     * @returns {object} {} | { search: {vendor,product,...} } | { kind: 'driver'|'firmware' }.
     */
    obj.classifySoftware = function (name, publisher) {
        var ent = obj.matchTableEntry(name);
        if (ent != null) {
            if (ent.kind != null) return { kind: ent.kind };
            return { search: { vendor: ent.vendor, product: ent.product, viaCurated: true } };
        }
        try {
            if (obj.scannerConfig().autoProductMatch !== false) {
                var auto = obj.autoMatchProductTokens(publisher, name);
                if (auto != null) return { search: auto };
            }
        } catch (ex) { }
        var g = obj.guessDriverFirmware(name);
        if (g != null) return { kind: g };
        return {};
    };

    /**
     * @brief Map a software display name + publisher to a CPE { vendor, product } target.
     * Matching order (most to least precise): custom entries, curated table (CPE rows),
     * then the automatic evidence matcher - the latter can be switched off with the
     * vulnerabilityScanner setting autoProductMatch (default: on). A table KIND hit is an
     * explicit exclusion and yields null here (classifySoftware reports the kind).
     * @param {string} publisher - The software publisher (vendor evidence).
     * @param {string} name - The software display name (product evidence).
     * @returns {object|null} <code>{ vendor, product, viaCurated|viaAuto }</code> or null.
     */
    obj.deriveCpeProduct = function (publisher, name) {
        if (!name) return null;
        var ent = obj.matchTableEntry(name);
        if (ent != null) { return (ent.kind != null) ? null : { vendor: ent.vendor, product: ent.product, viaCurated: true }; }
        try {
            if (obj.scannerConfig().autoProductMatch !== false) {
                var auto = obj.autoMatchProductTokens(publisher, name);
                if (auto) return auto;
            }
        } catch (ex) { }
        return null;
    };

    // ---- Automatic product-token matching (offline, no configuration) ----
    // Same principle as OWASP Dependency-Check's evidence matching: vendor/product
    // evidence is derived from the installed-software entry, and a CPE product is only
    // accepted when the token provably occurs in the loaded NVD CVE data
    // (obj.cpeProductTokens / obj.productIndexByProduct, built at feed load time).
    // CVE version ranges are always re-checked by the search itself, so a token hit on
    // a patched version reports "no CVE for <product>" instead of a finding. The NVD's
    // CPE dictionary API is never called.

    /** @type {Object<string, string>} Publisher keyword -> CPE vendor (word-boundary match). */
    obj.PUBLISHER_VENDOR_MAP = {
        'adobe': 'adobe', 'microsoft': 'microsoft', 'google': 'google', 'mozilla': 'mozilla',
        'videolan': 'videolan', 'oracle': 'oracle', 'ibm': 'ibm', 'sap': 'sap',
        'vmware': 'vmware', 'citrix': 'citrix', 'cisco': 'cisco',
        'zoom video communications': 'zoom', 'teamviewer': 'teamviewer', 'anydesk': 'anydesk',
        'fortinet': 'fortinet', 'kaspersky': 'kaspersky', 'eset': 'eset', 'avast': 'avast',
        'avg': 'avg', 'bitdefender': 'bitdefender', 'mcafee': 'mcafee', 'symantec': 'symantec',
        'trend micro': 'trend_micro', 'f secure': 'f-secure', 'sophos': 'sophos',
        'malwarebytes': 'malwarebytes', 'piriform': 'piriform', 'foxit': 'foxit',
        'autodesk': 'autodesk', 'solidworks': 'solidworks', 'corel': 'corel', 'nitro': 'nitro',
        'opera software': 'opera', 'brave software': 'brave', 'vivaldi': 'vivaldi',
        'libreoffice': 'libreoffice', 'document foundation': 'libreoffice',
        'python software foundation': 'python', 'eclipse foundation': 'eclipse', 'eclipse adoptium': 'eclipse',
        'adoptium': 'eclipse', 'node js': 'nodejs', 'docker': 'docker', 'git scm': 'git',
        'github': 'github', 'slack technologies': 'slack', 'realvnc': 'realvnc', 'turbovnc': 'turbovnc',
        'tightvnc': 'tightvnc', 'ultravnc': 'ultravnc', 'openvpn': 'openvpn', 'tailscale': 'tailscale',
        'dropbox': 'dropbox', 'logmein': 'logmein', 'securepoint': 'securepoint',
        'palo alto networks': 'paloaltonetworks'
    };

    /** @type {Object<string, 1>} Single-word tokens too generic for vendor-less searching. */
    obj.GENERIC_PRODUCT_TOKENS = {
        'client': 1, 'server': 1, 'agent': 1, 'agents': 1, 'service': 1, 'services': 1,
        'update': 1, 'updates': 1, 'updater': 1, 'driver': 1, 'drivers': 1, 'plugin': 1,
        'plugins': 1, 'extension': 1, 'extensions': 1, 'add-in': 1, 'addin': 1, 'tools': 1,
        'tool': 1, 'viewer': 1, 'player': 1, 'editor': 1, 'manager': 1, 'runtime': 1,
        'framework': 1, 'engine': 1, 'connector': 1, 'component': 1, 'library': 1, 'suite': 1,
        'software': 1, 'installer': 1, 'program': 1, 'desktop': 1, 'app': 1, 'apps': 1,
        'sync': 1, 'link': 1, 'pro': 1, 'plus': 1, 'core': 1, 'pack': 1, 'data': 1
    };

    /** @type {RegExp} Architecture / language suffix noise in display names. */
    obj.NAME_ARCH_LANG_RE = /\b(?:x[ -]?(?:64|86)|amd64|arm64|aarch64|32[- ]bit|64[- ]bit|(?:de|en|es|fr|it|nl|pl|ru|ja|zh|ko|pt|sv|tr)[-_](?:de|us|gb|fr|es|it|nl|pl|ru|jp|kr|br|se|tr|cn|tw)|multi[- ]?language|german|english|french|spanish|italian)\b/gi;
    /** @type {RegExp} Edition/installer noise in display names. */
    obj.NAME_EDITION_RE = /\b(?:installer|setup|program|version|build|edition|community|professional|enterprise|standard|home|education|student|trial|preview|insider|beta|alpha|lts)\b/gi;
    /** @type {RegExp} Version-number and year noise in display names. */
    obj.NAME_VERSION_RE = /\b(?:v?\d+[.,]\d+[\d.]*|\b(?:19|20)\d\d\b|update\s?\d+)\b/gi;

    /**
     * @brief Lower-case a display name into a CPE-style product token: parenthesized
     * parts are dropped, non-alphanumerics collapse to '_', '+' and '.' are kept.
     * @param {string} s - The raw display name.
     * @returns {string} The token (possibly empty).
     */
    obj.cpeTokenize = function (s) {
        var t = String(s || '').toLowerCase().replace(/\([^)]*\)/g, ' ');
        t = t.replace(/[^a-z0-9+._]+/g, '_').replace(/^_+|_+$/g, '').replace(/_{2,}/g, '_');
        return t;
    };

    /**
     * @brief Derive a CPE vendor from a publisher display name using word-boundary
     * keywords. Unmapped publishers yield '' (no vendor evidence).
     * @param {string} publisher - The publisher display name.
     * @returns {string} A vendor token or ''.
     */
    obj.deriveVendorFromPublisher = function (publisher) {
        var p = String(publisher || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
        if (!p) return '';
        var padded = ' ' + p + ' ';
        for (var key in obj.PUBLISHER_VENDOR_MAP) {
            if (padded.indexOf(' ' + key + ' ') >= 0) { return obj.PUBLISHER_VENDOR_MAP[key]; }
        }
        return obj.vendorFromPublisherIndex(publisher);
    };

    /** @type {RegExp} legal-form and filler words removed from publisher names. */
    obj.PUBLISHER_NOISE_RE = /\b(inc|incorporated|corp|corporation|co|company|gmbh|ag|ltd|limited|llc|s\s?r\s?o|kg|sa|bv|srl|plc|oy|ab|se|pty|technologies|technology|software|systems|international|group|the)\b/g;

    /**
     * @brief Generic publisher -> CPE vendor evidence (v3.1.0): the publisher, stripped of legal
     * forms, is accepted as vendor ONLY when exactly that token exists as a vendor in the loaded
     * NVD data ("JetBrains s.r.o." -> jetbrains, "Apache Friends" -> apache_friends,
     * "Nero AG" -> nero). It never invents a vendor; the product must still be proven by
     * autoMatchProductTokens. Maintainer e-mail publishers (Linux packages) are ignored.
     * @param {string} publisher - Publisher display name.
     * @returns {string} vendor token or ''.
     */
    obj.vendorFromPublisherIndex = function (publisher) {
        var raw = String(publisher || '');
        if (raw === '' || /@/.test(raw)) return '';
        if (obj.cpeVendorTokens == null || Object.keys(obj.cpeVendorTokens).length === 0) return '';
        var w = raw.toLowerCase().replace(/\(.*?\)/g, ' ').replace(/[,.&]/g, ' ').replace(obj.PUBLISHER_NOISE_RE, ' ').split(/[^a-z0-9+-]+/).filter(Boolean);
        if (w.length === 0) return '';
        var cands = [w.join('_'), w.join(''), w.join('-'), w[0]];
        for (var i = 0; i < cands.length; i++) {
            var c = cands[i];
            if (c && c.length >= 3 && !obj.GENERIC_PRODUCT_TOKENS[c] && obj.cpeVendorTokens[c] === 1) return c;
        }
        return '';
    };

    /** @brief True if a token is specific enough to be searched across all vendors. */
    obj.isTrustworthyProductToken = function (token) {
        if (!token || (token.length < 3)) return false;
        if (token.indexOf('_') >= 0) return true;
        return (token.length >= 6) && !obj.GENERIC_PRODUCT_TOKENS[token];
    };

    /**
     * @brief Automatic evidence matching (see block comment above). Candidate tokens:
     * the noise-stripped name, the raw name, the version-stripped name, and the name
     * minus a leading vendor word. Candidates are validated against the real product
     * tokens of the loaded NVD data; vendor evidence must not contradict them.
     * @param {string} publisher - Vendor evidence (may be empty).
     * @param {string} name - Product evidence (display name).
     * @returns {object|null} <code>{ vendor, product, viaAuto: true }</code> or null.
     */
    obj.autoMatchProductTokens = function (publisher, name) {
        var vendor = obj.deriveVendorFromPublisher(publisher);
        var raw = obj.cpeTokenize(name);
        if (!raw) return null;
        var semi = name.replace(obj.NAME_ARCH_LANG_RE, ' ').replace(obj.NAME_EDITION_RE, ' ');
        var light = obj.cpeTokenize(semi);
        var heavy = obj.cpeTokenize(semi.replace(obj.NAME_VERSION_RE, ' ').replace(/(?:\s|^)\d{1,4}(?=\s|$)/g, ' '));
        var cands = [];
        var push = function (t) { if (t && (t.length >= 3) && (cands.indexOf(t) < 0)) cands.push(t); };
        push(light); push(raw); push(heavy);
        if (vendor) {
            if ((light.indexOf(vendor + '_') === 0) && (light.length > vendor.length + 1)) push(light.substring(vendor.length + 1));
            if ((heavy.indexOf(vendor + '_') === 0) && (heavy.length > vendor.length + 1)) push(heavy.substring(vendor.length + 1));
        }
        for (var c = 0; c < cands.length; c++) {
            var token = cands[c];
            if (!obj.cpeProductTokens[token]) continue;
            var vendors = obj.productIndexByProduct[token];
            if (!vendors || (vendors.length === 0)) continue;
            if (vendor) {
                for (var v = 0; v < vendors.length; v++) {
                    if (vendors[v].vendor === vendor) { return { vendor: vendor, product: token, viaAuto: true }; }
                }
                continue;
            }
            if (vendors.length === 1) { return { vendor: vendors[0].vendor, product: token, viaAuto: true }; }
            if (obj.isTrustworthyProductToken(token)) { return { vendor: '', product: token, viaAuto: true }; }
        }
        return null;
    };


/**
     * @brief Scan a software inventory list for CVE matches.
     * Searches by product name only (independent of vendor) against the NVD index.
     * Products with a curated CPE mapping but no CVE match are reported as "no CVE for <product>".
     * Products proven by neither table nor automatic matching are reported as "not assessable".
     * @param {Array<object>} softwareList - The installed software list (from the plugin DB).
     * @param {function} callback - Called with <code>(deviceVulns)</code>.
     * @param {object} [ctx] - { osDesc } of the device (v3.1.0): enables the distro-managed rule.
     */
    obj.scanDeviceSoftware = function (softwareList, callback, ctx) {
        var deviceVulns = [];
        if (!Array.isArray(softwareList)) { if (callback) callback(deviceVulns); return; }
        var osState = null;
        var distroRule = obj.scannerConfig().distroManaged !== false;

        // Sequential processing to keep API load low and respect NVD rate limits.
        var idx = 0;
        var nextEntry = function () {
            if (idx >= softwareList.length) { if (callback) callback(deviceVulns); return; }
            var sw = softwareList[idx++];
            if (!sw) { nextEntry(); return; }
            var name = sw.name || sw.Name || sw.displayName || sw.DisplayName || '';
            var version = sw.version || sw.Version || '';
            var publisher = sw.publisher || sw.Publisher || sw.vendor || sw.Vendor || '';
            if (!name) { nextEntry(); return; }

            // Packages of the distribution itself: patched by its security team (backports into the
            // same upstream version), so an NVD version check would only produce false positives.
            // Judged by the support state of the OS release instead (see osSupportState).
            if (distroRule && obj.isDistroPackage(sw) && obj.isDistroMaintained(sw)) {
                if (osState == null) { osState = obj.osSupportState(ctx && ctx.osDesc); }
                var st = osState.state;
                deviceVulns.push({
                    status: (st === 'supported') ? 'distro-managed' : (st === 'eol' ? 'distro-eol' : 'distro-unknown'),
                    distro: st, isCve: false, cve: '', severity: '', cvss: '',
                    description: (st === 'supported')
                        ? ('Package of ' + osState.label + ' - patched by the distribution (' + osState.reason + '); NVD version ranges do not apply to backported distribution builds.')
                        : (st === 'eol'
                            ? ('Package of ' + osState.label + ' - the release no longer receives security updates (' + osState.reason + '); fixes are missing, upgrade the release.')
                            : ('Package of ' + (osState.label || 'an unrecognized OS') + ' - support state unknown (' + osState.reason + '); not checked against the NVD.')),
                    software: name, version: version, published: '', references: []
                });
                nextEntry();
                return;
            }

            // Map the display name to a CPE { vendor, product } target. When a vendor is
            // known (curated table or publisher), the CVE search is exact (vendor+product)
            // and cannot produce cross-vendor false positives. Only for product-only
            // matches (no vendor derivable) do we fall back to a search across all vendors.
            // classifySoftware additionally honours table kind rows and reports clearly
            // driver/firmware software as such (out of NVD application scope, see report).
            var classHit = obj.classifySoftware(name, publisher);
            var searchResult = classHit.search;

            if (searchResult) {
                var cves = [];
                if (searchResult.vendor) {
                    cves = obj.searchCves(searchResult.vendor, searchResult.product, version);
                } else {
                    cves = obj.searchCvesByProduct(searchResult.product, version);
                }
                if (cves.length > 0) {
                    // Real CVE matches: no API lookup needed (the token is already known).
                    for (var j = 0; j < cves.length; j++) {
                        deviceVulns.push({
                            status: 'CVE',
                            isCve: true,
                            cve: cves[j].id, severity: cves[j].severity, cvss: cves[j].cvss,
                            description: cves[j].description, software: name, version: version,
                            published: cves[j].published, references: cves[j].references
                        });
                    }
                    nextEntry();
                    return;
                }
            }

            // No CVE match in the curated list. If the product is known via the curated
            // table but has no CVEs in the NVD list -> "no CVE".
            // If neither curated table nor automatic token matching prove a real CPE
            // product -> "not assessable" (no API calls). Unknown/OEM/driver software is handled via Windows
            // Update / vendor channels and is transparently reported as such.
            if (searchResult) {
                deviceVulns.push({
                    status: 'no CVE for ' + searchResult.product,
                    isCve: false,
                    cve: '', severity: '', cvss: '',
                    description: 'CPE product "' + searchResult.vendor + '/' + searchResult.product + '" exists, but no matching CVE was found in the NVD list.' + (version === '' ? ' The installed version is unknown, so version-bounded CVEs were not asserted - only all-version entries were checked.' : ''),
                    software: name, version: version,
                    published: '', references: []
                });
            } else if (classHit.kind != null) {
                // Honest third category: drivers/firmware are patched via vendor tools and Windows
                // Update; the NVD application (part "a") data this scanner uses does not cover them.
                deviceVulns.push({
                    status: classHit.kind, outOfScope: true, isCve: false,
                    cve: '', severity: '', cvss: '',
                    description: (classHit.kind === 'driver'
                        ? 'Windows drivers are not covered by the NVD CVE application data - they are patched via the hardware vendor and Windows Update.'
                        : 'Firmware/BIOS is not covered by the NVD CVE application data this scan evaluates - updates come from the hardware vendor.'),
                    software: name, version: version,
                    published: '', references: []
                });
            } else {
                deviceVulns.push({
                    status: 'not assessable',
                    isCve: false,
                    cve: '', severity: '', cvss: '',
                    description: 'No verified CPE entry for "' + name + '". Patching/updates are not covered by the NVD CVE database.',
                    software: name, version: version,
                    published: '', references: []
                });
            }
            nextEntry();
        };
        nextEntry();
    };

    /**
     * @brief Curated OS description -> OS CPE mapping table.
     * @type {Array<object>}
     * Each entry: <code>{ match: RegExp, vendor, product }</code>.
     */
    obj.OS_CPE_TABLE = [
        { match: /windows server 2022/i, vendor: 'microsoft', product: 'windows_server_2022' },
        { match: /windows server 2019/i, vendor: 'microsoft', product: 'windows_server_2019' },
        { match: /windows server 2016/i, vendor: 'microsoft', product: 'windows_server_2016' },
        { match: /windows server 2012 r2/i, vendor: 'microsoft', product: 'windows_server_2012_r2' },
        { match: /windows server 2012/i, vendor: 'microsoft', product: 'windows_server_2012' },
        { match: /windows server 2008 r2/i, vendor: 'microsoft', product: 'windows_server_2008_r2' },
        { match: /windows server 2008/i, vendor: 'microsoft', product: 'windows_server_2008' },
        { match: /windows server/i, vendor: 'microsoft', product: 'windows_server' },
        { match: /windows 11/i, vendor: 'microsoft', product: 'windows_11' },
        { match: /windows 10/i, vendor: 'microsoft', product: 'windows_10' },
        { match: /windows 8\.1/i, vendor: 'microsoft', product: 'windows_8.1' },
        { match: /windows 8/i, vendor: 'microsoft', product: 'windows_8' },
        { match: /windows 7/i, vendor: 'microsoft', product: 'windows_7' },
        { match: /ubuntu/i, vendor: 'canonical', product: 'ubuntu_linux' },
        { match: /debian/i, vendor: 'debian', product: 'debian_linux' },
        { match: /centos/i, vendor: 'centos', product: 'centos' },
        { match: /red hat enterprise linux|^red hat/i, vendor: 'redhat', product: 'enterprise_linux' },
        { match: /fedora/i, vendor: 'fedora', product: 'fedora' },
        { match: /opensuse leap/i, vendor: 'opensuse', product: 'leap' },
        { match: /opensuse tumbleweed/i, vendor: 'opensuse', product: 'tumbleweed' },
        { match: /suse linux enterprise server/i, vendor: 'suse', product: 'linux_enterprise_server' },
        { match: /alpine/i, vendor: 'alpinelinux', product: 'alpine' },
        { match: /rocky linux/i, vendor: 'rocky', product: 'rocky_linux' },
        { match: /oracle linux/i, vendor: 'oracle', product: 'linux' },
        { match: /linux mint/i, vendor: 'linuxmint', product: 'linuxmint' },
        { match: /macos/i, vendor: 'apple', product: 'macos' },
        { match: /os x/i, vendor: 'apple', product: 'mac_os_x' }
    ];

    /**
     * @brief macOS version codenames -> numeric version.
     * @type {Object<string, string>}
     */
    obj.MACOS_CODENAME = {
        'sonoma': '14', 'ventura': '13', 'monterey': '12', 'big sur': '11',
        'catalina': '10.15', 'mojave': '10.14', 'high sierra': '10.13', 'sierra': '10.12',
        'el capitan': '10.11', 'yosemite': '10.10', 'mavericks': '10.9', 'mountain lion': '10.8',
        'lion': '10.7', 'snow leopard': '10.6', 'leopard': '10.5', 'tiger': '10.4', 'panther': '10.3'
    };

    /**
     * @brief Map an OS description (+ optional Windows build number) to an OS CPE target.
     * Windows uses the build number as the CPE version; macOS uses its codename; Linux
     * distros use major.minor.
     * @param {string} osDesc - The <code>node.osdesc</code> value.
     * @param {string} windowsBuild - The Windows build number, if known.
     * @returns {object|null} <code>{ vendor, product, version, versionKnown }</code>, or null if unrecognized.
     */
    obj.mapOsToCpe = function (osDesc, windowsBuild) {
        if (!osDesc) return null;
        for (var i = 0; i < obj.OS_CPE_TABLE.length; i++) {
            var entry = obj.OS_CPE_TABLE[i];
            if (entry.match.test(osDesc)) {
                var vendor = entry.vendor, product = entry.product, version = '', versionKnown = false;
                if (vendor === 'microsoft') {
                    version = windowsBuild || '';
                    versionKnown = !!version;
                } else if (vendor === 'apple') {
                    var lower = osDesc.toLowerCase();
                    for (var cn in obj.MACOS_CODENAME) {
                        if (lower.indexOf(cn) >= 0) { version = obj.MACOS_CODENAME[cn]; versionKnown = true; break; }
                    }
                    if (!versionKnown) {
                        var am = osDesc.match(/(\d+(?:\.\d+){1,2})/);
                        if (am) { version = am[1]; versionKnown = true; }
                    }
                } else {
                    var lm = osDesc.match(/(\d+)\.(\d+)/);
                    if (lm) { version = lm[1] + '.' + lm[2]; versionKnown = true; }
                    else {
                        var lm2 = osDesc.match(/(\d+)/);
                        if (lm2) { version = lm2[1] + '.0'; versionKnown = true; }
                    }
                }
                return { vendor: vendor, product: product, version: version, versionKnown: versionKnown };
            }
        }
        return null;
    };

    /**
     * @brief Search the index for OS (part 'o') CVE matches.
     * @param {string} vendor - The OS vendor.
     * @param {string} product - The OS product.
     * @param {string} version - The OS version.
     * @param {boolean} anyOnly - If true, only match definitions that explicitly apply to all versions ('any').
     * @returns {Array<object>} Matching CVE records.
     */
    obj.searchOsCves = function (vendor, product, version, anyOnly, boundedOnly) {
        var defs = obj.productIndex[String(vendor).toLowerCase() + '|' + String(product).toLowerCase()];
        if (!defs || defs.length === 0) return [];
        var results = [];
        for (var i = 0; i < defs.length; i++) {
            var def = defs[i];
            if (def.part !== 'o') continue;
            if (boundedOnly && def.kind !== 'range') continue; // only build-bounded definitions can be asserted
            if (anyOnly) {
                // Version-less OS match: apply the same historical "any"-CVE suppression
                // so ancient any-version OS CVEs do not appear on current OSes.
                if (def.kind === 'any') {
                    var dl = def.cves || [];
                    for (var d = 0; d < dl.length; d++) {
                        if (!obj.anyCveTooOld(def, dl[d])) { results.push(dl[d]); }
                    }
                }
                continue;
            }
            if (obj.defMatches(def, version)) {
                var dl2 = def.cves || [];
                for (var e = 0; e < dl2.length; e++) {
                    if (!obj.anyCveTooOld(def, dl2[e])) { results.push(dl2[e]); }
                }
            }
        }
        var seen = {}, unique = [];
        for (var j = 0; j < results.length; j++) {
            if (results[j] && !seen[results[j].id]) { seen[results[j].id] = true; unique.push(results[j]); }
        }
        unique.sort(function (a, b) { return (b.cvss || 0) - (a.cvss || 0); });
        return unique;
    };

    /**
     * @brief Scan an operating system (from <code>node.osdesc</code>) for CVE matches.
     * @param {string} osDesc - The OS description.
     * @param {string} windowsBuild - The Windows build number, if known.
     * @returns {Array<object>} OS-level CVE findings.
     */
    /**
     * @brief Windows 10/11 and Server 2016+ target: release-specific CPE product + full build.
     * The release comes from osdesc ("... - 25H2/26200"), the build from the agent's
     * osinfo.BuildRevision ("10.0.26200.9711" = Version + "." + UBR, verified in MeshCentral
     * agents/modules_meshcore/computer-identifiers.js). A bare build number ("26200") is not
     * enough for the ranges and yields build ''.
     * @param {string} osDesc - node.osdesc.
     * @param {string} windowsBuild - osinfo.BuildRevision || osinfo.BuildNumber.
     * @returns {object|null} { product, build } or null when not Windows 10/11/Server 2016+.
     */
    obj.windowsOsTarget = function (osDesc, windowsBuild) {
        var d = String(osDesc || '');
        var b = String(windowsBuild || '').trim();
        var build = /^10\.0\.\d{4,5}\.\d+$/.test(b) ? b : '';
        var m;
        if ((m = d.match(/windows server (2016|2019|2022|2025)\b/i))) { return { product: 'windows_server_' + m[1], build: build }; }
        if ((m = d.match(/windows (10|11)\b/i))) {
            var rel = d.match(/\b(\d{2}h\d|1[5-9]\d\d|20\d\d)\b/i);
            if (rel == null) { return { product: 'windows_' + m[1], build: build }; }
            return { product: 'windows_' + m[1] + '_' + rel[1].toLowerCase(), build: build };
        }
        return null;
    };

    obj.scanDeviceOs = function (osDesc, windowsBuild) {
        var osVulns = [];
        var win = obj.windowsOsTarget(osDesc, windowsBuild);
        if (win != null) {
            // Windows 10/11/Server 2016+ (v3.1.0): the NVD keeps the version-bounded data under the
            // release-specific CPE (windows_11_25h2, windows_server_2019, ...) with ranges on the full
            // build "10.0.<build>.<UBR>". The generic windows_11/windows_10 CPEs carry mostly
            // "all versions" entries from early releases and matched EVERY machine (568 identical
            // findings per Windows 11 PC before v3.1.0). Without a full build no assertion is made.
            if (win.build === '') { return osVulns; }
            var wc = obj.searchOsCves('microsoft', win.product, win.build, false, true);
            for (var w = 0; w < wc.length; w++) {
                osVulns.push({ cve: wc[w].id, severity: wc[w].severity, cvss: wc[w].cvss, description: wc[w].description, software: 'Operating System', version: osDesc + ' (' + win.build + ')', published: wc[w].published, references: wc[w].references });
            }
            return osVulns;
        }
        var target = obj.mapOsToCpe(osDesc, windowsBuild);
        if (!target) return osVulns;

        var cves = [];
        if (target.versionKnown) {
            cves = obj.searchOsCves(target.vendor, target.product, target.version, false);
            if (cves.length === 0) { cves = obj.searchOsCves(target.vendor, target.product, '*', false); }
        } else {
            cves = obj.searchOsCves(target.vendor, target.product, '', true);
        }

        for (var j = 0; j < cves.length; j++) {
            osVulns.push({
                cve: cves[j].id, severity: cves[j].severity, cvss: cves[j].cvss,
                description: cves[j].description, software: 'Operating System', version: osDesc,
                published: cves[j].published, references: cves[j].references
            });
        }

        return osVulns;
    };

    /**
     * @brief Look up a persisted group-wide assessment for a mesh/CVE pair.
     * @param {string} meshId - The mesh id (<code>mesh/&lt;domain&gt;/&lt;name&gt;</code>).
     * @param {string} cveId - The CVE id.
     * @returns {object|null} The assessment record, or null.
     */
    obj.getMeshAssessment = function (meshId, cveId) {
        var key = meshId + ':' + cveId;
        return obj.assessments[key] || null;
    };

    // ---- CSV helpers ----

    /**
     * @brief Format a single CSV field per RFC 4180.
     * Neutralizes CSV formula injection (CWE-1236) by prefixing a <code>'</code>
     * when the value starts with <code>= + - @ tab CR</code>.
     * @param {*} value - The value to format.
     * @returns {string} The escaped CSV field.
     */
    function formatCsvField(value) {
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
    }

    /**
     * @brief Format a complete CSV row from the given field values.
     * @param {...*} arguments - The field values.
     * @returns {string} The CSV row (comma-joined escaped fields).
     */
    function formatCsvRow() {
        var fields = [];
        for (var i = 0; i < arguments.length; i++) { fields.push(formatCsvField(arguments[i])); }
        return fields.join(',');
    }

    /**
     * @brief Format a byte count into a human-readable string.
     * @param {number} bytes - The number of bytes.
     * @returns {string} A human-readable size, or an empty string.
     */
    function formatBytes(bytes) {
        if ((bytes === null) || (bytes === undefined)) { return ''; }
        var b = Number(bytes);
        if (!isFinite(b) || (b === 0)) { return ''; }
        var sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        var i = parseInt(Math.floor(Math.log(Math.abs(b)) / Math.log(1024)), 10);
        if (i >= sizes.length) { i = sizes.length - 1; }
        return Math.round(b / Math.pow(1024, i), 2) + ' ' + sizes[i];
    }

    /**
     * @brief Build a filename timestamp.
     * @returns {string} The timestamp in <code>YYYYMMDD-HHMMSS</code> format.
     */
    function timestamp() {
        var now = new Date();
        return now.getFullYear() +
            ('0' + (now.getMonth() + 1)).slice(-2) + ('0' + now.getDate()).slice(-2) + '-' +
            ('0' + now.getHours()).slice(-2) + ('0' + now.getMinutes()).slice(-2) + ('0' + now.getSeconds()).slice(-2);
    }

    // ---- Shared node/sysinfo collection ----

    /**
     * @brief Fetch the sysinfo record for a node.
     * Sysinfo <code>_id</code> is <code>"si" + node._id</code>.
     * @param {object} node - The node record.
     * @param {function} callback - Called with <code>(err, sysinfoRecord|null)</code>.
     */
    function fetchSysinfo(node, callback) {
        if ((node == null) || (node._id == null)) { callback(null, null); return; }
        obj.db.Get('si' + node._id, function (err, docs) {
            if (err || !docs || docs.length === 0) { callback(null, null); return; }
            callback(null, docs[0]);
        });
    }

    /**
     * @brief Return the collected software list for a node.
     * Prefers the plugin's own database; falls back to the sysinfo <code>apps</code>
     * field if present (e.g. agents that do embed it).
     * @param {object} node - The node record.
     * @param {object} doc - The sysinfo document (may be empty).
     * @returns {Array<object>} The installed software list.
     */
    obj.getStoredSoftware = function (node, doc) {
        var key = safeNodeDir(node && node._id);
        var entry = obj.softwareInventory[key];
        if (entry && Array.isArray(entry.apps) && entry.apps.length > 0) { return obj.pruneSuperseded(entry.apps); }
        var docApps = (doc != null) ? (doc.apps || doc.Apps || doc.software || doc.installedApps) : null;
        if (Array.isArray(docApps)) { return obj.pruneSuperseded(docApps); }
        return [];
    };

    /**
     * @brief Return the collected patch list for a node.
     * Prefers the plugin's own database; falls back to the sysinfo <code>qfe</code>/
     * <code>packages</code> fields if present.
     * @param {object} node - The node record.
     * @param {object} doc - The sysinfo document (may be empty).
     * @returns {Array<object>} The installed patch / package list.
     */
    obj.getWindowsUpdates = function (node) {
        var key = safeNodeDir(node && node._id);
        var entry = obj.windowsUpdates[key];
        if (entry && (typeof entry.count === 'number')) {
            return { count: entry.count || 0, updates: Array.isArray(entry.updates) ? entry.updates : [] };
        }
        return null;
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

    /**
     * @brief Finding for a device whose OS release is end of life (v3.1.0, id OS-EOL): its
     * distribution packages / OS no longer get security fixes. Only raised when the lifecycle
     * data proves it (state 'eol'); unknown states never create a finding.
     * @param {object} node - node record.
     * @returns {object|null}
     */
    obj.osEolFinding = function (node) {
        if (obj.scannerConfig().osLifecycleEnabled === false) return null;
        var s = obj.osSupportState(node && node.osdesc);
        if (s.state !== 'eol') return null;
        return {
            cve: 'OS-EOL', isOsEol: true, severity: 'CRITICAL', cvss: 10,
            description: s.label + ' is end of life (' + s.reason + ', source endoflife.date): the operating system and its packages receive no security updates any more.',
            software: 'Operating System lifecycle', version: s.label, published: '', references: []
        };
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

    // ---- Admin request handling (vulnerability assessment panel) ----

    /**
     * @brief MeshCentral admin GET handler for the vulnerability assessment panel.
     * All routes are gated on full site admin.
     * <code>action=show</code> renders the assessment view;
     * <code>action=scan</code> returns the aggregated CVEs of a mesh as JSON.
     * @param {object} req - The Express request.
     * @param {object} res - The Express response.
     * @param {object} user - The authenticated user.
     */
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

    obj.handleAdminReq = function (req, res, user) {
        if (!obj.isAuthorizedAdmin(user)) { res.sendStatus(401); return; }
        if (req.query.action === 'show') { return obj.showAssessmentPanel(req, res, user); }
        if (req.query.action === 'scan') { return obj.assessmentScan(req, res, user); }
        if (req.query.action === 'show_cpe') { return obj.showCustomCpe(req, res, user); }
        if (req.query.action === 'report') { return obj.vulnerabilityReport(req, res, user); }
        if (req.query.action === 'deviceReport') { return obj.deviceReport(req, res, user); }
        if (req.query.action === 'export') { return obj.exportCsv(req, res, user); }
        res.sendStatus(404);
    };

    /**
     * @brief MeshCentral admin POST handler.
     * Gated on full site admin. Supports <code>action=save_assessment</code>
     * (urlencoded body) to store a group-wide rating with a mandatory comment.
     * @param {object} req - The Express request.
     * @param {object} res - The Express response.
     * @param {object} user - The authenticated user.
     */
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
    // ---- Plugin settings (Settings tab) ----

    /** @type {Array<string>} Valid severity values for notification thresholds. */
    obj.SETTING_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];

    /**
     * @brief Read a urlencoded boolean field.
     * @param {*} v - The raw body value ('true'/'false'/undefined).
     * @param {boolean} dflt - Value to use when the field is absent.
     * @returns {boolean} The parsed boolean.
     */
    function boolSetting(v, dflt) {
        if ((v === undefined) || (v === null) || (v === '')) { return dflt; }
        return String(v).toLowerCase() === 'true';
    }

    /**
     * @brief Return the effective scanner/collector settings plus the per-key source
     * ('file' = saved via this UI, 'config.json' = server config, 'default').
     * @param {object} res - The Express response.
     * @param {object} user - The authenticated user.
     */
    /**
     * @brief Return the tail of the NVD download log for the Settings tab viewer.
     * Fixed path inside the plugin NVD directory, capped at the last 200 lines of a
     * 256 KB window; never a caller-supplied path.
     * @param {object} req - The Express request (unused body).
     * @param {object} res - The Express response.
     * @param {object} user - The authenticated user.
     */
    obj.getNvdLogHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        try {
            var file = path.join(obj.nvdDataPath, 'nvd-download.log');
            if (!fs.existsSync(file)) { return send({ lines: [], note: 'No download log yet - the first feed download creates it.' }); }
            var st = fs.statSync(file);
            var fd = fs.openSync(file, 'r');
            var len = Math.min(st.size, 256 * 1024);
            var buf = Buffer.alloc(len);
            fs.readSync(fd, buf, 0, len, Math.max(0, st.size - len));
            fs.closeSync(fd);
            var lines = buf.toString('utf8').split(String.fromCharCode(10));
            if (lines.length > 0 && lines[lines.length - 1] === '') { lines.pop(); }
            if (len < st.size) { lines.shift(); }  // first line may be cut mid-way
            send({ lines: lines.slice(-200), size: st.size, file: 'nvd/nvd-download.log' });
        } catch (ex) {
            send({ lines: [], note: 'Could not read the log: ' + ex.message });
        }
    };

    obj.getSettingsHandler = function (req, res, user) {
        var sc = obj.scannerConfig();
        var cc = obj.collectorConfig();
        var vsc = obj.effectiveSectionConfig('vulnerabilityScanner') || {};
        var src = function (section, key) {
            var over = obj.pluginSettings[section];
            if (over && Object.prototype.hasOwnProperty.call(over, key)) { return 'file'; }
            var b = null;
            try { b = obj.meshServer.config.settings[section]; } catch (e) { }
            if (b && Object.prototype.hasOwnProperty.call(b, key)) { return 'config.json'; }
            return 'default';
        };
        var perGroupMap = function (section, key) {
            var out = {};
            var over = obj.pluginSettings[section];
            var b = null;
            try { b = obj.meshServer.config.settings[section]; } catch (e) { }
            var merge = function (o) { if (o && (typeof o === 'object')) { for (var k in o) { if (Object.prototype.hasOwnProperty.call(o, k)) { out[k] = 'file'; } } } };
            if (b && (typeof b[key] === 'object') && b[key]) { for (var k in b[key]) { if (out[k] == null) { out[k] = 'config.json'; } } }
            merge(over && over[key]);
            return out;
        };
        res.type('json');
        res.json({
            settings: {
                scanIntervalHours: sc.intervalHours,
                scanMeshes: sc.meshes || [],
                notifyOnScan: sc.notifyOnScan,
                notifyThreshold: sc.notifyThreshold,
                notifyUnratedRepeat: sc.notifyUnratedRepeat,
                notify: sc.notifyThresholds,
                updateHours: (typeof vsc.updateHours === 'number') ? vsc.updateHours : 168,
                anyCveMaxAgeYears: obj.anyCveMaxAgeYears(),
                collectIntervalMinutes: cc.intervalMinutes,
                collectOnAgentConnect: cc.collectOnAgentConnect,
                autoProductMatch: sc.autoProductMatch,
                cpeTableEnabled: sc.cpeTableEnabled,
                cpeTableUrl: sc.cpeTableUrl,
                distroManaged: sc.distroManaged,
                osLifecycleEnabled: sc.osLifecycleEnabled,
                osLifecycleUrl: sc.osLifecycleUrl
            },
            osLifecycle: obj.osLifecycleStatus(),
            sources: {
                scanIntervalHours: src('vulnerabilityScanner', 'scanIntervalHours'),
                scanMeshes: src('vulnerabilityScanner', 'scanMeshes'),
                notifyOnScan: src('vulnerabilityScanner', 'notifyOnScan'),
                notifyThreshold: src('vulnerabilityScanner', 'notifyThreshold'),
                notifyUnratedRepeat: src('vulnerabilityScanner', 'notifyUnratedRepeat'),
                updateHours: src('vulnerabilityScanner', 'updateHours'),
                anyCveMaxAgeYears: src('vulnerabilityScanner', 'anyCveMaxAgeYears'),
                notifyPerGroup: perGroupMap('vulnerabilityScanner', 'notify'),
                collectIntervalMinutes: src('inventoryScanner', 'collectIntervalMinutes'),
                collectOnAgentConnect: src('inventoryScanner', 'collectOnAgentConnect'),
                autoProductMatch: src('vulnerabilityScanner', 'autoProductMatch'),
                cpeTableEnabled: src('vulnerabilityScanner', 'cpeTableEnabled'),
                cpeTableUrl: src('vulnerabilityScanner', 'cpeTableUrl'),
                distroManaged: src('vulnerabilityScanner', 'distroManaged'),
                osLifecycleEnabled: src('vulnerabilityScanner', 'osLifecycleEnabled'),
                osLifecycleUrl: src('vulnerabilityScanner', 'osLifecycleUrl'),
                revertAllowed: {
                    autoProductMatch: (obj.pluginSettings.vulnerabilityScanner != null) && Object.prototype.hasOwnProperty.call(obj.pluginSettings.vulnerabilityScanner, 'autoProductMatch'),
                    cpeTableEnabled: (obj.pluginSettings.vulnerabilityScanner != null) && Object.prototype.hasOwnProperty.call(obj.pluginSettings.vulnerabilityScanner, 'cpeTableEnabled'),
                    cpeTableUrl: (obj.pluginSettings.vulnerabilityScanner != null) && Object.prototype.hasOwnProperty.call(obj.pluginSettings.vulnerabilityScanner, 'cpeTableUrl'),
                    osLifecycleUrl: (obj.pluginSettings.vulnerabilityScanner != null) && Object.prototype.hasOwnProperty.call(obj.pluginSettings.vulnerabilityScanner, 'osLifecycleUrl'),
                    scanIntervalHours: (obj.pluginSettings.vulnerabilityScanner != null) && Object.prototype.hasOwnProperty.call(obj.pluginSettings.vulnerabilityScanner, 'scanIntervalHours'),
                    updateHours: (obj.pluginSettings.vulnerabilityScanner != null) && Object.prototype.hasOwnProperty.call(obj.pluginSettings.vulnerabilityScanner, 'updateHours'),
                    anyCveMaxAgeYears: (obj.pluginSettings.vulnerabilityScanner != null) && Object.prototype.hasOwnProperty.call(obj.pluginSettings.vulnerabilityScanner, 'anyCveMaxAgeYears'),
                    collectIntervalMinutes: (obj.pluginSettings.inventoryScanner != null) && Object.prototype.hasOwnProperty.call(obj.pluginSettings.inventoryScanner, 'collectIntervalMinutes')
                }
            }
        });
    };

    /**
     * @brief Validate and persist the plugin settings from the Settings tab, then
     * apply them immediately (timer generation bump + reschedule). Sent values fully
     * replace the previous file content; 'reset=true' deletes all overrides instead.
     * @param {object} req - The Express request (urlencoded fields of both sections).
     * @param {object} res - The Express response.
     * @param {object} user - The authenticated user.
     */
    obj.saveSettingsHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        if (String(req.body.reset || '') === 'true') {
            obj.pluginSettings = {};
            obj.savePluginSettings(function (err) {
                if (err) { return send({ error: err.message }); }
                obj.rescheduleAll();
                send({ success: true, reset: true });
            });
            return;
        }
        var intSet = function (v, min, max, name) {
            var x = parseInt(String(v), 10);
            if (isNaN(x) || (x < min) || (x > max)) { return { error: 'Invalid ' + name + ' (expected ' + min + '..' + max + ').' }; }
            return { value: x };
        };
        var iv = intSet(req.body.scanIntervalHours, 0, 87600, 'scan interval (hours)'); if (iv.error) { return send(iv); }
        var uh = intSet(req.body.updateHours, 1, 87600, 'feed update interval (hours)'); if (uh.error) { return send(uh); }
        var ag = intSet(req.body.anyCveMaxAgeYears, 0, 50, 'any-CVE max age (years)'); if (ag.error) { return send(ag); }
        var ci = intSet(req.body.collectIntervalMinutes, 0, 525600, 'collection interval (minutes)'); if (ci.error) { return send(ci); }
        var notifyThreshold = String(req.body.notifyThreshold || '').toUpperCase();
        if (obj.SETTING_SEVERITIES.indexOf(notifyThreshold) < 0) { return send({ error: 'Invalid notification threshold.' }); }
        var scanMeshes = parseMeshIds(req.body.scanMeshes);
        var ids = String(req.body.notifyMeshIds || '').split(',');
        var sevs = String(req.body.notifySeverities || '').split(',');
        var notify = {};
        for (var i = 0; i < ids.length; i++) {
            var id = ids[i].trim();
            if (!id) { continue; }
            var sev = String(sevs[i] || '').toUpperCase();
            if (!/^mesh\/[^:]+$/.test(id) || (obj.SETTING_SEVERITIES.indexOf(sev) < 0)) { return send({ error: 'Invalid per-group notification setting.' }); }
            notify[id] = sev;
        }
        var cpeTableUrl = String(req.body.cpeTableUrl || '').trim();
        if (cpeTableUrl === '') { cpeTableUrl = obj.CPE_TABLE_DEFAULT_URL; }
        else if (!/^https:\/\/[^\s"'<>]{5,250}$/.test(cpeTableUrl)) { return send({ error: 'Invalid CPE table URL (must be a short https URL).' }); }
        var osLifecycleUrl = String(req.body.osLifecycleUrl || '').trim();
        if (osLifecycleUrl === '') { osLifecycleUrl = obj.OS_LIFECYCLE_DEFAULT_URL; }
        else if (!/^https:\/\/[^\s"'<>]{5,250}\/$/.test(osLifecycleUrl)) { return send({ error: 'Invalid lifecycle API URL (https, ending with /).' }); }
        obj.pluginSettings = {
            vulnerabilityScanner: {
                scanIntervalHours: iv.value,
                scanMeshes: scanMeshes,
                notifyOnScan: boolSetting(req.body.notifyOnScan, true),
                notifyThreshold: notifyThreshold,
                notifyUnratedRepeat: boolSetting(req.body.notifyUnratedRepeat, false),
                autoProductMatch: boolSetting(req.body.autoProductMatch, true),
                cpeTableEnabled: boolSetting(req.body.cpeTableEnabled, true),
                cpeTableUrl: cpeTableUrl,
                distroManaged: boolSetting(req.body.distroManaged, true),
                osLifecycleEnabled: boolSetting(req.body.osLifecycleEnabled, true),
                osLifecycleUrl: osLifecycleUrl,
                notify: notify,
                updateHours: uh.value,
                anyCveMaxAgeYears: ag.value
            },
            inventoryScanner: {
                collectIntervalMinutes: ci.value,
                collectOnAgentConnect: boolSetting(req.body.collectOnAgentConnect, true)
            }
        };
        obj.savePluginSettings(function (err) {
            if (err) { obj.pluginSettings = {}; return send({ error: err.message }); }
            obj.rescheduleAll();
            obj.getSettingsHandler({}, res, user);
        });
    };

    /**
     * @brief Revert a single setting override so the value from config.json (or the
     * built-in default) applies again. Expects one body key named after the setting.
     * @param {object} req - The Express request (urlencoded <code>revert&lt;Key&gt;=true</code>).
     * @param {object} res - The Express response.
     * @param {object} user - The authenticated user.
     */
    obj.revertSettingHandler = function (req, res, user) {
        var SETTING_MAP = {
            revertScanIntervalHours: ['vulnerabilityScanner', 'scanIntervalHours'],
            revertScanMeshes: ['vulnerabilityScanner', 'scanMeshes'],
            revertNotifyOnScan: ['vulnerabilityScanner', 'notifyOnScan'],
            revertNotifyThreshold: ['vulnerabilityScanner', 'notifyThreshold'],
            revertNotifyUnratedRepeat: ['vulnerabilityScanner', 'notifyUnratedRepeat'],
            revertNotify: ['vulnerabilityScanner', 'notify'],
            revertUpdateHours: ['vulnerabilityScanner', 'updateHours'],
            revertAnyCveMaxAgeYears: ['vulnerabilityScanner', 'anyCveMaxAgeYears'],
            revertAutoProductMatch: ['vulnerabilityScanner', 'autoProductMatch'],
            revertCpeTableEnabled: ['vulnerabilityScanner', 'cpeTableEnabled'],
            revertCpeTableUrl: ['vulnerabilityScanner', 'cpeTableUrl'],
            revertDistroManaged: ['vulnerabilityScanner', 'distroManaged'],
            revertOsLifecycleEnabled: ['vulnerabilityScanner', 'osLifecycleEnabled'],
            revertOsLifecycleUrl: ['vulnerabilityScanner', 'osLifecycleUrl'],
            revertCollectIntervalMinutes: ['inventoryScanner', 'collectIntervalMinutes'],
            revertCollectOnAgentConnect: ['inventoryScanner', 'collectOnAgentConnect']
        };
        var hit = null;
        for (var key in SETTING_MAP) {
            if (Object.prototype.hasOwnProperty.call(SETTING_MAP, key) && Object.prototype.hasOwnProperty.call(req.body, key)) { hit = SETTING_MAP[key]; break; }
        }
        if (hit == null) { res.type('json'); res.json({ error: 'Nothing to revert.' }); return; }
        var section = obj.pluginSettings[hit[0]];
        if (section) { delete section[hit[1]]; }
        obj.savePluginSettings(function (err) {
            if (err) { res.type('json'); res.json({ error: err.message }); return; }
            obj.rescheduleAll();
            obj.getSettingsHandler({}, res, user);
        });
    };

    /**
     * @brief Honest display values for a CVE row aggregated over devices.
     * Software display name and installed version are PER-DEVICE attributes, so an
     * aggregated row must never claim one arbitrary device's version as the truth
     * for all of them (that made the panel disagree with the per-device CSV).
     * Uniform values are kept; when they differ the row gets the flags
     * <code>softwareVaried</code>/<code>versionVaried</code> + the variant lists,
     * and <code>version</code> becomes '' (unknown-looking beats wrong-looking -
     * the UI renders "varies" with the full per-device breakdown).
     * @param {object} entry - CVE row with deviceList:[{name, software, version}].
     * @returns {object} The same entry, annotated.
     */
    obj.summarizeDeviceSwVer = function (entry) {
        var dl = Array.isArray(entry.deviceList) ? entry.deviceList : [];
        if (dl.length === 0) { entry.softwareVaried = false; entry.versionVaried = false; return entry; }
        var names = {}, vers = {}, nUn = 0, vUn = 0;
        for (var i = 0; i < dl.length; i++) {
            var nm = String(dl[i].software || ''), vr = String(dl[i].version || '');
            if (!Object.prototype.hasOwnProperty.call(names, nm)) { names[nm] = 1; nUn++; }
            if (!Object.prototype.hasOwnProperty.call(vers, vr)) { vers[vr] = 1; vUn++; }
        }
        entry.softwareVaried = nUn > 1;
        entry.versionVaried = vUn > 1;
        if (entry.softwareVaried) { entry.variedSoftware = Object.keys(names); entry.software = String(dl[0].software || ''); }
        if (entry.versionVaried) { entry.variedVersions = Object.keys(vers); entry.version = ''; }
        return entry;
    };

    /**
     * @brief Aggregate the unique CVEs found across all devices of a mesh.
     * Each CVE carries the mesh-wide assessment (if any).
     * @param {string} meshId - The mesh id to scan.
     * @param {function} callback - Called with <code>(err, cveList)</code> where
     * each entry is <code>{ cve, severity, cvss, description, software, version, assessment,
     * devices, deviceList }</code> - <code>devices</code> = device labels (admin given name
     * first, host name / id as fallback), <code>deviceList</code> = per-device
     * <code>{ name, software, version }</code> (the truth behind the aggregated display).
     */
    obj.scanMeshCves = function (meshId, callback) {
        obj.meshServer.db.GetAllType('node', function (err, nodes) {
            if (err) { if (callback) callback(err, []); return; }
            var meshNodes = [];
            if (nodes) {
                for (var i = 0; i < nodes.length; i++) {
                    var n = nodes[i];
                    if (n && (n.meshid === meshId) && (n.deleted == null)) { meshNodes.push(n); }
                }
            }
            if (meshNodes.length === 0) { if (callback) callback(null, []); return; }

            var found = {}; // cveId -> aggregated entry
            var pending = meshNodes.length;

            meshNodes.forEach(function (node) {
                // Admin labels in the panel read the given (renamed-by-admin) name first - same
                // rule as the wg_status table; printable reports intentionally keep host names.
                var deviceName = (typeof node.name === 'string' && node.name.trim() !== '') ? node.name.trim() : (obj.getHostName(node) || node._id);
                fetchSysinfo(node, function (err, sysinfoRecord) {
                    var doc = sysinfoRecord ? (sysinfoRecord.doc || sysinfoRecord) : {};
                    var windowsBuild = '';
                    if (doc && doc.hardware && doc.hardware.windows && doc.hardware.windows.osinfo) { windowsBuild = doc.hardware.windows.osinfo.BuildRevision || doc.hardware.windows.osinfo.BuildNumber || ''; }
                    obj.scanNodeSoftware(node, obj.getStoredSoftware(node, doc), function (softwareVulns) {
                        var deviceVulns = softwareVulns.concat(obj.scanDeviceOs(node.osdesc || '', windowsBuild));
                        // Windows-only: missing updates are treated as a critical finding.
                        var wu = obj.getWindowsUpdates(node);
                        if (wu && wu.count > 0) { deviceVulns.push(obj.windowsUpdatesFinding(wu.count)); }
                        var eolF = obj.osEolFinding(node); if (eolF != null) { deviceVulns.push(eolF); }

                        for (var j = 0; j < deviceVulns.length; j++) {
                            var v = deviceVulns[j];
                            if (!v.cve) continue;
                            if (!found[v.cve]) {
                                var assessment = obj.getMeshAssessment(meshId, v.cve);
                                found[v.cve] = {
                                    cve: v.cve,
                                    severity: v.severity,
                                    cvss: v.cvss,
                                    description: v.description,
                                    software: v.software,
                                    version: v.version,
                                    assessment: assessment,
                                    devices: [],
                                    deviceList: []
                                };
                            }
                            if (found[v.cve].devices.indexOf(deviceName) < 0) {
                                found[v.cve].devices.push(deviceName);
                                found[v.cve].deviceList.push({ name: deviceName, software: String(v.software || ''), version: String(v.version || '') });
                            }
                        }
                        if (--pending === 0) {
                            var list = [];
                            for (var c in found) { list.push(obj.summarizeDeviceSwVer(found[c])); }
                            list.sort(function (a, b) { return (b.cvss || 0) - (a.cvss || 0); });
                            if (callback) callback(null, list);
                        }
                    });
                });
            });
        });
    };

    /**
     * @brief Aggregate the unique CVEs found across a set of locations (meshes).
     * Each CVE carries the list of affected locations (with their affected device labels -
     * given names first, falling back to host name then id) and
     * the per-location assessments. When every affected location has the same assessment,
     * <code>assessment</code> holds it; otherwise <code>mixed</code> is true.
     * @param {Array<string>} meshIds - The mesh ids to scan.
     * @param {function} callback - Called with <code>(err, { meshes, cves })</code> where
     * each CVE entry is <code>{ cve, severity, cvss, description, software, version,
     * locations, assessments, assessment, mixed, anyFlagged }</code>.
     */
    obj.scanMultiMeshCves = function (meshIds, callback) {
        obj.meshServer.db.GetAllType('mesh', function (meshErr, meshes) {
            var names = {};
            if (!meshErr && meshes) {
                for (var i = 0; i < meshes.length; i++) {
                    var m = meshes[i];
                    if (m && m._id) { names[m._id] = m.name || m._id; }
                }
            }
            var found = {};
            var meshList = [];
            var pending = meshIds.length;
            if (pending === 0) { if (callback) callback(null, { meshes: [], cves: [] }); return; }

            meshIds.forEach(function (meshId) {
                obj.scanMeshCves(meshId, function (err, list) {
                    var meshName = names[meshId] || obj.getGroupName({ meshid: meshId }) || meshId;
                    meshList.push({ id: meshId, name: meshName });
                    if (!err && list) {
                        for (var j = 0; j < list.length; j++) {
                            var e = list[j];
                            if (!e || !e.cve) continue;
                            var r = found[e.cve];
                            if (!r) {
                                r = found[e.cve] = {
                                    cve: e.cve,
                                    severity: e.severity,
                                    cvss: e.cvss,
                                    description: e.description,
                                    software: e.software,
                                    version: e.version,
                                    locations: [],
                                    assessments: {},
                                    deviceList: []
                                };
                            }
                            r.locations.push({ meshId: meshId, name: meshName, devices: e.devices || [], deviceList: e.deviceList || [] });
                            if (e.deviceList) { r.deviceList = r.deviceList.concat(e.deviceList); }
                            r.assessments[meshId] = e.assessment || null;
                        }
                    }
                    if (--pending === 0) {
                        var out = [];
                        for (var c in found) {
                            if (!Object.prototype.hasOwnProperty.call(found, c)) continue;
                            var entry = found[c];
                            var uniform = true, firstA = null, any = false, anyFlagged = false;
                            for (var k = 0; k < entry.locations.length; k++) {
                                var a = entry.assessments[entry.locations[k].meshId];
                                if (!a) { uniform = false; continue; }
                                any = true;
                                if (a.flagged) { anyFlagged = true; }
                                if (firstA == null) { firstA = a; }
                                else if ((a.assessment !== firstA.assessment) || (!!a.flagged !== !!firstA.flagged)) { uniform = false; }
                            }
                            // "mixed" only when some (but not all) locations share the same assessment;
                            // a completely unrated finding is simply unrated.
                            entry.mixed = any && !uniform;
                            entry.assessment = (any && uniform) ? firstA : null;
                            entry.anyFlagged = anyFlagged;
                            // Recompute the software/version display from the FULL merged
                            // device list (across all locations), not the first mesh's row.
                            obj.summarizeDeviceSwVer(entry);
                            out.push(entry);
                        }
                        out.sort(function (a, b) { return (Number(b.cvss) || 0) - (Number(a.cvss) || 0) || String(a.cve).localeCompare(String(b.cve)); });
                        meshList.sort(function (a, b) { return String(a.name).localeCompare(String(b.name)); });
                        if (callback) callback(null, { meshes: meshList, cves: out });
                    }
                });
            });
        });
    };

    /**
     * @brief Return the aggregated CVEs of the selected locations as JSON for the assessment panel.
     * @param {object} req - The Express request (expects the <code>mesh</code> query param with a
     * comma-separated list of mesh ids; empty selects nothing).
     * @param {object} res - The Express response.
     * @param {object} user - The authenticated user.
     */
    obj.assessmentScan = function (req, res, user) {
        var meshParam = String(req.query.mesh || req.query.meshes || '');
        var meshIds = parseMeshIds(meshParam).slice(0, 1000); // same validation as every write path
        if (meshIds.length === 0) { res.type('json'); res.json({ error: 'No locations selected.' }); return; }
        obj.scanMultiMeshCves(meshIds, function (err, result) {
            if (err) { res.type('json'); res.json({ error: err.message }); return; }
            // Count findings flagged as false positives (excluded from the real vulnerability count).
            var flaggedCount = 0;
            for (var i = 0; i < result.cves.length; i++) {
                if (result.cves[i].assessment && result.cves[i].assessment.flagged) { flaggedCount++; }
            }
            res.type('json');
            res.json({
                meshes: result.meshes,
                cves: result.cves,
                flaggedCount: flaggedCount,
                totalCves: obj.allCves.length,
                lastUpdate: obj.lastUpdate || ''
            });
        });
    };

    /**
     * @brief Aggregate vulnerability data across ALL clients (all meshes) for the printable reports.
     * Iterates every node, runs the software/OS/update scan, and produces summary statistics.
     * The result is grouped by <b>location</b> (device group / mesh): <code>report.locations</code>
     * is an array of location records with their own KPIs, a deduplicated findings list and the
     * location's devices. <code>report.devices</code> holds the flat device list (used by the
     * separate device report). For severity counting, the manual (group) assessment rating is
     * used whenever one exists; otherwise the NVD severity. Findings flagged as false positives
     * are excluded from the counts and tracked separately.
     * @param {function} callback - Called with <code>(err, report)</code>.
     */
    obj.buildOverallReport = function (callback) {
        obj.meshServer.db.GetAllType('node', function (err, nodes) {
            if (err) { if (callback) callback(err, null); return; }
            var liveNodes = [];
            if (nodes) {
                for (var i = 0; i < nodes.length; i++) {
                    var n = nodes[i];
                    if (n && (n._id != null) && (n.deleted == null)) { liveNodes.push(n); }
                }
            }

            var report = {
                generated: new Date().toISOString(),
                totalSystems: liveNodes.length,
                totalPrograms: 0,
                assessablePrograms: 0,
                notAssessablePrograms: 0,
                outOfScopePrograms: 0,
                distroManagedPrograms: 0,
                distroEolPrograms: 0,
                distroUnknownPrograms: 0,
                coverageBase: 0,
                coveragePercent: 0,
                totalCves: 0,
                falsePositiveCves: 0,
                severityCounts: { 'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0 },
                uniqueCves: 0,
                uniqueCveIds: {},
                locations: [],
                devices: []
            };

            if (liveNodes.length === 0) { if (callback) callback(null, report); return; }

            // Group everything by location (device group / mesh), one report section per location.
            var locationsById = {};
            var getLocation = function (meshId) {
                var id = meshId || '';
                if (locationsById[id] == null) {
                    locationsById[id] = {
                        id: id,
                        name: obj.getGroupName({ meshid: id }) || '(ungrouped)',
                        totalSystems: 0,
                        totalPrograms: 0,
                        assessablePrograms: 0,
                        notAssessablePrograms: 0,
                        outOfScopePrograms: 0,
                        distroManagedPrograms: 0,
                        distroEolPrograms: 0,
                        distroUnknownPrograms: 0,
                        coverageBase: 0,
                        coveragePercent: 0,
                        totalCves: 0,
                        falsePositiveCves: 0,
                        severityCounts: { 'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0 },
                        uniqueCves: 0,
                        uniqueCveIds: {},
                        findingsById: {},
                        devices: []
                    };
                }
                return locationsById[id];
            };

            var pending = liveNodes.length;
            liveNodes.forEach(function (node) {
                var hostName = obj.getHostName(node) || node.name || node._id;
                var loc = getLocation(node.meshid);
                loc.totalSystems++;
                var deviceRec = {
                    hostName: hostName,
                    name: node.name || '',
                    group: loc.name,
                    os: node.osdesc || '',
                    programs: 0,
                    cveCount: 0,
                    critical: 0, high: 0, medium: 0, low: 0, unknown: 0,
                    severities: {}
                };
                fetchSysinfo(node, function (err2, sysinfoRecord) {
                    var doc = sysinfoRecord ? (sysinfoRecord.doc || sysinfoRecord) : {};
                    var windowsBuild = '';
                    if (doc && doc.hardware && doc.hardware.windows && doc.hardware.windows.osinfo) { windowsBuild = doc.hardware.windows.osinfo.BuildRevision || doc.hardware.windows.osinfo.BuildNumber || ''; }

                    var softwareList = obj.getStoredSoftware(node, doc);
                    deviceRec.programs = softwareList.length;
                    loc.totalPrograms += softwareList.length;
                    report.totalPrograms += softwareList.length;

                    obj.scanNodeSoftware(node, softwareList, function (softwareVulns) {
                        var deviceVulns = softwareVulns.concat(obj.scanDeviceOs(node.osdesc || '', windowsBuild));
                        var wu = obj.getWindowsUpdates(node);
                        if (wu && wu.count > 0) { deviceVulns.push(obj.windowsUpdatesFinding(wu.count)); }
                        var eolF = obj.osEolFinding(node); if (eolF != null) { deviceVulns.push(eolF); }

                        // CPE coverage: classify every installed program by its scan status row.
                        // assessable = a verified CPE mapping was checked against the NVD;
                        // notAssessable = a real program with no proven CPE (the honest blind spot);
                        // outOfScope = driver/firmware - not a program the NVD application data can
                        // ever cover, so it is reported separately and EXCLUDED from the coverage
                        // denominator instead of dragging it down.
                        var progSeen = {};
                        var devOK = 0, devNA = 0, devX = 0, devDM = 0, devDE = 0, devDU = 0;
                        for (var sk = 0; sk < softwareVulns.length; sk++) {
                            var sv = softwareVulns[sk];
                            var skey = (sv.software || '') + '@@' + (sv.version || '');
                            if (progSeen[skey]) continue;
                            progSeen[skey] = 1;
                            // Distribution packages are a separate, transparent category (v3.1.0): never in
                            // the coverage denominator - their patch state is the distribution's job.
                            if (sv.distro === 'supported') { devDM++; }
                            else if (sv.distro === 'eol') { devDE++; }
                            else if (sv.distro === 'unknown') { devDU++; }
                            else if (sv.outOfScope) { devX++; }
                            else if (sv.status === 'not assessable') { devNA++; }
                            else { devOK++; }
                        }
                        deviceRec.programsAssessable = devOK;
                        deviceRec.programsNotAssessable = devNA;
                        deviceRec.programsOutOfScope = devX;
                        deviceRec.programsDistroManaged = devDM + devDE + devDU;
                        deviceRec.osSupport = obj.osSupportState(node.osdesc).state;
                        loc.assessablePrograms += devOK;
                        loc.notAssessablePrograms += devNA;
                        loc.outOfScopePrograms += devX;
                        loc.distroManagedPrograms += devDM; loc.distroEolPrograms += devDE; loc.distroUnknownPrograms += devDU;
                        report.assessablePrograms += devOK;
                        report.notAssessablePrograms += devNA;
                        report.outOfScopePrograms += devX;
                        report.distroManagedPrograms += devDM; report.distroEolPrograms += devDE; report.distroUnknownPrograms += devDU;

                        // Deduplicate CVEs per device.
                        var seen = {};
                        for (var j = 0; j < deviceVulns.length; j++) {
                            var v = deviceVulns[j];
                            if (!v.cve) continue;
                            if (seen[v.cve]) continue;
                            seen[v.cve] = true;

                            // Effective severity: manual (group) assessment wins over NVD severity.
                            var assessment = obj.getMeshAssessment(node.meshid, v.cve);

                            // Unique finding record per location (deduplicated across devices).
                            var finding = loc.findingsById[v.cve];
                            if (finding == null) {
                                var effSev = (assessment && assessment.assessment) ? String(assessment.assessment).toUpperCase() : String(v.severity || 'UNKNOWN').toUpperCase();
                                finding = loc.findingsById[v.cve] = {
                                    cve: v.cve,
                                    severity: v.severity || 'UNKNOWN',
                                    cvss: (v.cvss != null) ? v.cvss : '',
                                    software: v.software || '',
                                    version: v.version || '',
                                    description: v.description || '',
                                    assessment: (assessment && assessment.assessment) ? assessment.assessment : '',
                                    comment: (assessment && assessment.comment) ? assessment.comment : '',
                                    flagged: !!(assessment && assessment.flagged),
                                    effectiveSeverity: (assessment && assessment.flagged) ? 'false positive' : effSev,
                                    devices: [],
                                    deviceList: []
                                };
                            }
                            if (finding.devices.indexOf(hostName) < 0) {
                                finding.devices.push(hostName);
                                finding.deviceList.push({ name: hostName, software: String(v.software || ''), version: String(v.version || '') });
                            }

                            // A finding flagged as false positive is not counted as a vulnerability
                            // (excluded from total findings and the severity distribution).
                            if (assessment && assessment.flagged) {
                                report.falsePositiveCves++;
                                loc.falsePositiveCves++;
                                continue;
                            }

                            deviceRec.cveCount++;
                            report.totalCves++;
                            loc.totalCves++;

                            var effSeverity = (assessment && assessment.assessment) ? assessment.assessment : (v.severity || 'UNKNOWN');
                            effSeverity = String(effSeverity).toUpperCase();
                            if (!report.severityCounts[effSeverity]) { report.severityCounts[effSeverity] = 0; }
                            report.severityCounts[effSeverity]++;
                            if (!loc.severityCounts[effSeverity]) { loc.severityCounts[effSeverity] = 0; }
                            loc.severityCounts[effSeverity]++;
                            if (!deviceRec.severities[effSeverity]) { deviceRec.severities[effSeverity] = 0; }
                            deviceRec.severities[effSeverity]++;

                            if (report.uniqueCveIds[v.cve] == null) { report.uniqueCveIds[v.cve] = 1; }
                            else { report.uniqueCveIds[v.cve]++; }
                            if (loc.uniqueCveIds[v.cve] == null) { loc.uniqueCveIds[v.cve] = 1; }
                            else { loc.uniqueCveIds[v.cve]++; }
                        }
                        deviceRec.critical = deviceRec.severities['CRITICAL'] || 0;
                        deviceRec.high = deviceRec.severities['HIGH'] || 0;
                        deviceRec.medium = deviceRec.severities['MEDIUM'] || 0;
                        deviceRec.low = deviceRec.severities['LOW'] || 0;
                        deviceRec.unknown = deviceRec.severities['UNKNOWN'] || 0;

                        loc.devices.push(deviceRec);
                        report.devices.push(deviceRec);
                        if (--pending === 0) {
                            for (var id in locationsById) {
                                if (!Object.prototype.hasOwnProperty.call(locationsById, id)) continue;
                                var L = locationsById[id];
                                L.uniqueCves = Object.keys(L.uniqueCveIds).length;
                                var fl = [];
                                for (var c in L.findingsById) {
                                    if (Object.prototype.hasOwnProperty.call(L.findingsById, c)) { fl.push(obj.summarizeDeviceSwVer(L.findingsById[c])); }
                                }
                                fl.sort(function (a, b) { return (Number(b.cvss) || 0) - (Number(a.cvss) || 0) || String(a.cve).localeCompare(String(b.cve)); });
                                L.findings = fl;
                                delete L.findingsById;
                                L.devices.sort(function (a, b) { return String(a.hostName).localeCompare(String(b.hostName)); });
                                var lDenom = L.assessablePrograms + L.notAssessablePrograms; // drivers/firmware excluded
                                L.coverageBase = lDenom;
                                L.coveragePercent = lDenom > 0 ? Math.round((L.assessablePrograms / lDenom) * 100) : 0;
                                report.locations.push(L);
                            }
                            report.locations.sort(function (a, b) { return String(a.name).localeCompare(String(b.name)); });
                            report.locationCount = report.locations.length;
                            report.devices.sort(function (a, b) { return (b.cveCount - a.cveCount) || String(a.hostName).localeCompare(String(b.hostName)); });
                            report.uniqueCves = Object.keys(report.uniqueCveIds).length;
                            var rDenom = report.assessablePrograms + report.notAssessablePrograms; // drivers/firmware excluded
                            report.coverageBase = rDenom;
                            report.coveragePercent = rDenom > 0 ? Math.round((report.assessablePrograms / rDenom) * 100) : 0;
                            if (callback) callback(null, report);
                        }
                    });
                });
            });
        });
    };

    /**
     * @brief Render the printable HTML vulnerability report for all clients.
     * @param {object} req - The Express request.
     * @param {object} res - The Express response.
     * @param {object} user - The authenticated user.
     */
    obj.vulnerabilityReport = function (req, res, user) {
        obj.buildOverallReport(function (err, report) {
            if (err || !report) { res.sendStatus(500); return; }
            res.render('report', {
                shortName: obj.shortName,
                report: report,
                totalCves: obj.allCves.length,
                lastUpdate: obj.lastUpdate || ''
            });
        });
    };

    /**
     * @brief Render the printable HTML device inventory report for all clients.
     * @param {object} req - The Express request.
     * @param {object} res - The Express response.
     * @param {object} user - The authenticated user.
     */
    obj.deviceReport = function (req, res, user) {
        obj.buildOverallReport(function (err, report) {
            if (err || !report) { res.sendStatus(500); return; }
            res.render('deviceReport', {
                shortName: obj.shortName,
                report: report,
                totalCves: obj.allCves.length,
                lastUpdate: obj.lastUpdate || ''
            });
        });
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
                var filename = base + '_' + timestamp() + '.csv';
                res.setHeader('Content-Disposition', 'attachment; filename="' + filename + '"');
                res.setHeader('Content-Type', 'text/csv; charset=utf-8');
                res.send('\uFEFF' + ((csvContent != null) ? csvContent : ''));
            });
        });
    };

    /**
     * @brief Parse a comma-separated list of mesh ids from a request field.
     * @param {*} value - The raw field value (one or more comma-separated mesh ids).
     * @returns {Array<string>} The valid, unique mesh ids (<code>mesh/&lt;domain&gt;/&lt;name&gt;</code>).
     */
    function parseMeshIds(value) {
        var out = [];
        var parts = String(value || '').split(',');
        for (var i = 0; i < parts.length; i++) {
            var id = parts[i].trim();
            // Validate meshId format (prevents key-poisoning in assessments.json).
            if (id && /^mesh\/[^:]+$/.test(id) && (out.indexOf(id) < 0)) { out.push(id); }
        }
        return out;
    }

    /**
     * @brief Validate a finding id: a real CVE id (CVE-YYYY-NNNNN) or the built-in
     * Windows-updates finding (<code>WINDOWS-UPDATES</code>).
     * @param {string} cveId - The finding id.
     * @returns {boolean} True when the id is valid.
     */
    function isFindingId(cveId) {
        return /^(CVE-\d{4}-\d{4,}|WINDOWS-UPDATES|OS-EOL)$/.test(cveId);
    }

    /**
     * @brief Save a group-wide assessment rating for one or more location/CVE pairs.
     * Enforces a mandatory, non-empty comment and a valid rating. The same rating is stored
     * for every given location (mesh), so a finding that affects several locations can be
     * assessed in a single step. Persists to <code>assessments.json</code>.
     * @param {object} req - The Express request (urlencoded <code>meshId</code> or
     * <code>meshIds</code> (comma-separated), <code>cveId</code>, <code>assessment</code>, <code>comment</code>).
     * @param {object} res - The Express response.
     * @param {object} user - The authenticated user.
     */
    obj.saveAssessmentHandler = function (req, res, user) {
        var meshIds = parseMeshIds(req.body.meshId || req.body.meshIds);
        var cveId = String(req.body.cveId || '');
        var assessment = String(req.body.assessment || '').toUpperCase();
        var comment = String(req.body.comment || '');

        var validRatings = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
        if ((meshIds.length === 0) || !cveId || (validRatings.indexOf(assessment) < 0)) {
            res.type('json'); res.json({ error: 'Missing or invalid fields.' }); return;
        }
        if (!comment.trim()) {
            res.type('json'); res.json({ error: 'A comment is required to rate a vulnerability.' }); return;
        }
        if (!isFindingId(cveId)) {
            res.type('json'); res.json({ error: 'Invalid CVE-ID format.' }); return;
        }

        // Sanitize comment: trim and limit length (stored raw, escaped when rendered).
        comment = comment.trim();
        if (comment.length > 1000) {
            res.type('json'); res.json({ error: 'Comment exceeds maximum length (1000 characters).' }); return;
        }

        for (var i = 0; i < meshIds.length; i++) {
            var key = meshIds[i] + ':' + cveId;
            obj.assessments[key] = {
                meshId: meshIds[i],
                cveId: cveId,
                assessment: assessment,
                comment: comment,
                lastModified: new Date().toISOString(),
                assessedBy: (user != null && user.name != null) ? user.name : '',
                assessedById: (user != null && user._id != null) ? user._id : ''
            };
        }
        obj.saveAssessments(function (err) {
            if (err) { res.type('json'); res.json({ error: err.message }); }
            else { res.type('json'); res.json({ success: true }); }
        });
    };

    /**
     * @brief Mark location/CVE findings as false positives (not applicable). Sets the effective
     * rating to UNKNOWN and adds the <code>flagged: true</code> marker so the finding is
     * excluded from vulnerability counts (in the printable reports and panel aggregation).
     * The comment is optional and may be left empty. Applies to every given location (mesh).
     * @param {object} req - The Express request (urlencoded <code>meshId</code> or
     * <code>meshIds</code> (comma-separated), <code>cveId</code>, optional <code>comment</code>).
     * @param {object} res - The Express response.
     * @param {object} user - The authenticated user.
     */
    obj.flagFalsePositiveHandler = function (req, res, user) {
        var meshIds = parseMeshIds(req.body.meshId || req.body.meshIds);
        var cveId = String(req.body.cveId || '');
        var comment = String(req.body.comment || '');
        if ((meshIds.length === 0) || !cveId) {
            res.type('json'); res.json({ error: 'Missing mesh or CVE.' }); return;
        }
        if (!isFindingId(cveId)) {
            res.type('json'); res.json({ error: 'Invalid CVE-ID format.' }); return;
        }
        comment = comment.trim();
        if (comment.length > 1000) {
            res.type('json'); res.json({ error: 'Comment exceeds maximum length (1000 characters).' }); return;
        }

        for (var i = 0; i < meshIds.length; i++) {
            var key = meshIds[i] + ':' + cveId;
            var existing = obj.assessments[key] || {};
            obj.assessments[key] = {
                meshId: meshIds[i],
                cveId: cveId,
                assessment: 'UNKNOWN',
                comment: comment,
                flagged: true,
                lastModified: new Date().toISOString(),
                assessedBy: (user != null && user.name != null) ? user.name : (existing.assessedBy || ''),
                assessedById: (user != null && user._id != null) ? user._id : (existing.assessedById || '')
            };
        }
        obj.saveAssessments(function (err) {
            if (err) { res.type('json'); res.json({ error: err.message }); }
            else { res.type('json'); res.json({ success: true, flagged: true }); }
        });
    };

    /**
     * @brief Remove the false-positive flag from location/CVE findings, restoring the NVD-based
     * effective rating (the assessment entry is removed so the finding is counted again).
     * @param {object} req - The Express request (urlencoded <code>meshId</code> or
     * <code>meshIds</code> (comma-separated), <code>cveId</code>).
     * @param {object} res - The Express response.
     * @param {object} user - The authenticated user.
     */
    obj.unflagFalsePositiveHandler = function (req, res, user) {
        var meshIds = parseMeshIds(req.body.meshId || req.body.meshIds);
        var cveId = String(req.body.cveId || '');
        if ((meshIds.length === 0) || !cveId) {
            res.type('json'); res.json({ error: 'Missing mesh or CVE.' }); return;
        }
        if (!isFindingId(cveId)) {
            res.type('json'); res.json({ error: 'Invalid CVE-ID format.' }); return;
        }
        for (var i = 0; i < meshIds.length; i++) {
            var key = meshIds[i] + ':' + cveId;
            if (obj.assessments[key] && obj.assessments[key].flagged) {
                delete obj.assessments[key];
            }
        }
        obj.saveAssessments(function (err) {
            if (err) { res.type('json'); res.json({ error: err.message }); }
            else { res.type('json'); res.json({ success: true, flagged: false }); }
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
            rows.push(formatCsvField('Group') + ',' + formatCsvField('Host Name') + ',' +
                formatCsvField('OS') + ',' + formatCsvField('Hardware Category') + ',' + formatCsvField('Component') + ',' + formatCsvField('Value') + ',' + formatCsvField('Details') + ',' + formatCsvField('Location'));
        } else if (type === 'software') {
            rows.push(formatCsvField('Group') + ',' + formatCsvField('Host Name') + ',' +
                formatCsvField('Software Name') + ',' + formatCsvField('Software Version') + ',' + formatCsvField('Software Publisher') + ',' + formatCsvField('Software Location') + ',' + formatCsvField('Software Install Date'));
        } else { // vulns
            rows.push(formatCsvField('Group') + ',' + formatCsvField('Host Name') + ',' +
                formatCsvField('Status') + ',' + formatCsvField('CVE ID') + ',' + formatCsvField('Severity') + ',' + formatCsvField('CVSS Score') + ',' + formatCsvField('Manual Rating') + ',' + formatCsvField('Comment') + ',' +
                formatCsvField('Software') + ',' + formatCsvField('Version') + ',' + formatCsvField('Description'));
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

            fetchSysinfo(node, function (err, sysinfoRecord) {
                if (err) { errored = true; finish(); return; }
                var doc = sysinfoRecord ? (sysinfoRecord.doc || sysinfoRecord) : {};

                if (type === 'hardware') {
                    var hasHardware = false;
                    var hw = (doc && doc.hardware) ? doc.hardware : {};
                    var ident = (hw && hw.identifiers) ? hw.identifiers : {};
                    var sysRow = function (cat, component, value, details, location) {
                        hasHardware = true;
                        rows.push(formatCsvRow(group, hostName, osDesc, cat, component, value, details, location));
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
                                formatBytes(cap), 'Speed: ' + (m.Speed || 'N/A') + ', Part: ' + (m.PartNumber || 'N/A'),
                                m.Manufacturer || '');
                        }
                    }
                    // Storage (SMBIOS storage devices)
                    if (Array.isArray(ident.storage_devices)) {
                        for (var si = 0; si < ident.storage_devices.length; si++) {
                            var sd = ident.storage_devices[si]; if (!sd) continue;
                            var sModel = sd.Model || sd.Caption || ('Disk ' + (si + 1));
                            sysRow('Storage', sModel, formatBytes(sd.Size), 'Model: ' + (sd.Model || 'N/A'), '');
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
                    if (!hasHardware) { rows.push(formatCsvRow(group, hostName, osDesc, 'System', 'No Hardware Data', 'No hardware information available', '', '')); }
                    finish();
                } else if (type === 'software') {
                    var softwareList = obj.getStoredSoftware(node, doc);
                    if (softwareList.length === 0) {
                        rows.push(formatCsvRow(group, hostName, '', '', '', '', ''));
                    } else {
                        for (var j = 0; j < softwareList.length; j++) {
                            var sw = softwareList[j]; if (!sw) continue;
                            rows.push(formatCsvRow(group, hostName,
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
                            rows.push(formatCsvRow(group, hostName, status, v.cve || '', v.severity || '', (v.cvss != null) ? v.cvss : '', rating, comment, v.software, v.version, v.description || ''));
                        }
                        finish();
                    });
                }
            });
        });
    };

    /**
     * @brief MeshCentral device-list toolbar hook.
     * Called for every plugin when a device-list toolbar button fires: a
     * customui.devicesbarbuttons button or one of the toolbar buttons this plugin
     * injects itself (see the exported onWebUIStartupEnd browser hook).
     * <code>command.selectedDevices</code> holds the selected node ids (already
     * rights-validated by MeshCentral, may be empty). The export type is taken from
     * <code>command.logmsg</code>. The resulting CSV is pushed to the browser via
     * <code>myparent.send()</code>.
     * @param {object} command - The parsed websocket command.
     * @param {object} myparent - The MeshUser websocket session object (has <code>.send()</code>).
     */
    obj.uiCustomEvent = function (command, myparent) {
        if ((command == null) || (myparent == null) || (myparent.send == null)) return;
        if (command.section !== 'devicesbarbuttons') return;
        // Same gate as every HTTP route (v3.0.1): only full site administrators get CSV data.
        // myparent is the MeshUser session; its .user is the authenticated account (meshuser.js).
        if (!obj.isAuthorizedAdmin(myparent.user)) return;
        // The front-end sends selectedDevices on the top level of the uicustomevent
        // command (default.handlebars customUIAction), never under command.src.
        var type = (typeof command.logmsg === 'string') ? command.logmsg : 'hardware';
        if (['hardware', 'software', 'vulns', 'assessment'].indexOf(type) < 0) { type = 'hardware'; }

        // "Vulnerability Assessment" opens the admin panel in a new browser tab
        // instead of producing a CSV download. No device records are needed - and
        // toolbar buttons may fire with an empty selection (the injected buttons, and
        // customui entries without "selection"), so the check below must come after it.
        if (type === 'assessment') {
            try { myparent.send({ action: 'plugin', plugin: obj.shortName, method: 'openAssessment' }); } catch (ex) { }
            return;
        }

        // Only well-formed node ids are looked up (the top-level selectedDevices list is NOT
        // rights-checked by MeshCentral, verified in meshuser.js); capped and de-duplicated.
        var nodeIds = [];
        if (Array.isArray(command.selectedDevices)) {
            for (var si = 0; (si < command.selectedDevices.length) && (nodeIds.length < 5000); si++) {
                var sid = command.selectedDevices[si];
                if ((typeof sid === 'string') && /^node\/[^\/:]*\/[^\/:]{1,128}$/.test(sid) && (nodeIds.indexOf(sid) < 0)) { nodeIds.push(sid); }
            }
        }
        if (nodeIds.length === 0) return;

        // Load the node records for the selected ids.

        var nodes = [];
        var pending = nodeIds.length;
        nodeIds.forEach(function (nodeId) {
            obj.db.Get(nodeId, function (err, docs) {
                if (!err && docs && docs.length > 0) { nodes.push(docs[0]); }
                if (--pending === 0) {
                    obj.buildCsvForNodes(nodes, type, function (err, csvContent, base) {
                        if (err || !csvContent) { return; }
                        var filename = base + '_' + timestamp() + '.csv';
                        myparent.send({ action: 'plugin', plugin: obj.shortName, method: 'inventoryCsv', data: csvContent, filename: filename });
                    });
                }
            });
        });
    };

    /**
     * @brief Browser-side function (exported via <code>exports</code>).
     * Called by the front-end websocket dispatcher when the server replies with
     * <code>{ action:'plugin', plugin:'inventoryscanner', method:'inventoryCsv', data, filename }</code>.
     * Triggers a CSV download via the global <code>saveAs</code> helper.
     * @param {object} server - The meshserver websocket object.
     * @param {object} message - The reply message containing <code>data</code> and <code>filename</code>.
     */
    obj.inventoryCsv = function (server, message) {
        try {
            if ((typeof saveAs !== 'function') || (message == null) || (message.data == null)) return;
            var bytes = (typeof message.data === 'string') ? message.data : JSON.stringify(message.data);
            saveAs(new Blob(['\uFEFF' + bytes], { type: 'text/csv;charset=utf-8' }), message.filename || 'inventory.csv');
        } catch (e) { }
    };

    /**
     * @brief Browser-side function (exported via <code>exports</code>).
     * Opens the Vulnerability Assessment admin panel in a new browser tab.
     * Called when the device-list toolbar's "Vulnerability Assessment" button fires
     * (<code>{ action:'plugin', plugin:'inventoryscanner', method:'openAssessment' }</code>).
     * @param {object} server - The meshserver websocket object.
     * @param {object} message - The (unused) reply message.
     */
    obj.openAssessment = function (server, message) {
        try {
            if (typeof window === 'undefined') return;
            // IMPORTANT: exported functions are serialized via Function.toString() into
            // the browser's pluginHandler namespace, which has no server-scope properties -
            // never reference them here, embed literals instead.
            window.open('/pluginadmin.ashx?pin=inventoryscanner&action=show', '_blank');
        } catch (e) { }
    };



    /**
     * @brief Browser hook dispatched by pluginHandler.callHook('onWebUIStartupEnd')
     * once the MeshCentral web UI has finished loading. Injects this plugin's toolbar
     * buttons into MeshCentral's own device-list button slot (the static
     * <span id="devsCustomUIBar"> element in the main view), so the buttons need no
     * server-side customui configuration. If the slot is already filled (an admin
     * defined customui.devicesbarbuttons entries), injection is skipped - no duplicates.
     * The click handlers replicate customUIAction semantics: node ids are collected
     * from the checked .DeviceCheckbox elements and sent as a uicustomevent command.
     * @param {object} server - The meshserver websocket object (unused, the global is used).
     */
    obj.onWebUIStartupEnd = function (server) {
        try {
            if (typeof document === 'undefined' || typeof meshserver === 'undefined') return;
            var bar = document.getElementById('devsCustomUIBar');
            if (bar == null || bar.innerHTML !== '') return;
            var defs = [['Hardware Inventory', 'hardware'], ['Software Inventory', 'software'], ['Vulnerability Assessment', 'assessment']];
            for (var i = 0; i < defs.length; i++) {
                (function (def) {
                    var b = document.createElement('input');
                    b.type = 'button';
                    b.value = def[0];
                    b.style.margin = '0 4px';
                    b.title = (def[1] === 'assessment') ? 'Open the vulnerability assessment panel in a new browser tab' : 'Export the checked devices as CSV';
                    b.onclick = function () {
                        try {
                            var elements = document.getElementsByClassName('DeviceCheckbox'), selectedDevices = [];
                            for (var k = 0; k < elements.length; k++) { if (elements[k].checked === true) { selectedDevices.push(elements[k].defaultValue.substring(6)); } }
                            if (selectedDevices.length === 0 && def[1] !== 'assessment') { if (typeof alert === 'function') alert('Select at least one device first.'); return; }
                            meshserver.send({ action: 'uicustomevent', section: 'devicesbarbuttons', element: '0', selectedDevices: selectedDevices, logmsg: def[1] });
                        } catch (ex) { }
                    };
                    bar.appendChild(b);
                })(defs[i]);
            }
        } catch (ex) { }
    };

    return obj;
};
