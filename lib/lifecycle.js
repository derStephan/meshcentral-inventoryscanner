/**
 * @file lib/lifecycle.js
 * @brief MeshCentral startup hook: loads all persisted state, arms every schedule, hot-swaps newer code in after a web-installer upgrade and self-heals a stale NVD timer.
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
            try { diskVer = JSON.parse(fs.readFileSync(path.join(obj.pluginDir, 'config.json'), 'utf8')).version; } catch (e0) { }
            if (diskVer != null && obj.PLUGIN_VERSION !== 'unknown' && diskVer !== obj.PLUGIN_VERSION && obj.parent != null && obj.parent.plugins != null) {
                var sname = obj.shortName;
                obj.wgLog('upgrade detected on disk (' + obj.PLUGIN_VERSION + ' -> ' + diskVer + '), reloading without server restart');
                try {
                    Object.keys(require.cache).forEach(function (k) { if (k.indexOf(obj.pluginDir + path.sep) === 0) { delete require.cache[k]; } }); // path.sep: never touch a sibling folder such as inventoryscanner2
                    var fresh = require(path.join(obj.pluginDir, sname + '.js'))[sname](obj.parent);
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
        obj.swLoadFiles();
        obj.swLoadTasks();
        obj.swCleanStaleStaging();
        obj.installRouteHook();
        obj.ensureNvdData();
        // Self-heal: check if NVD timer is stale (> 1 week since last successful update)
        obj.checkAndRepairNvdTimer();
        obj.scheduleUpdate();
        obj.scheduleScans();
        obj.scheduleInventoryCollection();
        obj.scheduleWingetUpdates();
        obj.scheduleSwSweep();
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
};
