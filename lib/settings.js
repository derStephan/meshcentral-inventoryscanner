/**
 * @file lib/settings.js
 * @brief UI-managed scanner settings: the overlay file (scanner-settings.json) that overrides the same keys in the server config.json per key, plus the Settings-tab handlers.
 * The plugin never writes config.json - MeshCentral reads it only at startup and a failed write can make the whole server unbootable.
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
    /** @type {object} In-memory plugin settings overlay: <code>{ vulnerabilityScanner: {...}, inventoryScanner: {...} }</code>. */
    obj.pluginSettings = {};

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

    // ---- Plugin settings (Settings tab) ----

    /** @type {Array<string>} Valid severity values for notification thresholds. */
    obj.SETTING_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];

    /**
     * @brief Read a urlencoded boolean field.
     * @param {*} v - The raw body value ('true'/'false'/undefined).
     * @param {boolean} dflt - Value to use when the field is absent.
     * @returns {boolean} The parsed boolean.
     */
    obj.boolSetting = function (v, dflt) {
        if ((v === undefined) || (v === null) || (v === '')) { return dflt; }
        return String(v).toLowerCase() === 'true';
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
        var scanMeshes = obj.parseMeshIds(req.body.scanMeshes);
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
                notifyOnScan: obj.boolSetting(req.body.notifyOnScan, true),
                notifyThreshold: notifyThreshold,
                notifyUnratedRepeat: obj.boolSetting(req.body.notifyUnratedRepeat, false),
                autoProductMatch: obj.boolSetting(req.body.autoProductMatch, true),
                cpeTableEnabled: obj.boolSetting(req.body.cpeTableEnabled, true),
                cpeTableUrl: cpeTableUrl,
                distroManaged: obj.boolSetting(req.body.distroManaged, true),
                osLifecycleEnabled: obj.boolSetting(req.body.osLifecycleEnabled, true),
                osLifecycleUrl: osLifecycleUrl,
                notify: notify,
                updateHours: uh.value,
                anyCveMaxAgeYears: ag.value
            },
            inventoryScanner: {
                collectIntervalMinutes: ci.value,
                collectOnAgentConnect: obj.boolSetting(req.body.collectOnAgentConnect, true)
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
};
