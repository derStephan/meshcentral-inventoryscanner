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
        // CACHED module after an upgrade - a new instance of the OLD code is created and
        // this hook runs on it. Detect the newer manifest beside the file and restart the
        // MeshCentral server through its own launcher (v4.3.2), so one Upgrade click is
        // enough. Without a launcher process the fresh code is hot-swapped in instead.
        try {
            var diskVer = null;
            try { diskVer = JSON.parse(fs.readFileSync(path.join(obj.pluginDir, 'config.json'), 'utf8')).version; } catch (e0) { }
            if (diskVer != null && obj.PLUGIN_VERSION !== 'unknown' && diskVer !== obj.PLUGIN_VERSION && obj.parent != null && obj.parent.plugins != null) {
                var sname = obj.shortName;
                if (obj.canRestartServer()) {
                    obj.nvdLog('upgrade detected on disk (' + obj.PLUGIN_VERSION + ' -> ' + diskVer + '), restarting the MeshCentral server to load it');
                    obj.__superseded = true;
                    obj.scheduleUpgradeRestart(diskVer);
                    return;
                }
                obj.nvdLog('upgrade detected on disk (' + obj.PLUGIN_VERSION + ' -> ' + diskVer + '), no MeshCentral launcher process - reloading without server restart');
                try {
                    Object.keys(require.cache).forEach(function (k) { if (k.indexOf(obj.pluginDir + path.sep) === 0) { delete require.cache[k]; } }); // path.sep: never touch a sibling folder such as inventoryscanner2
                    var fresh = require(path.join(obj.pluginDir, sname + '.js'))[sname](obj.parent);
                    obj.parent.plugins[sname] = fresh;
                    obj.parent.exports[sname] = fresh.exports;
                    obj.timerGen++;
                    obj.__superseded = true;
                    try { fresh.server_startup(); } catch (e1) { }
                    obj.nvdLog('hot reload complete, version ' + fresh.PLUGIN_VERSION + ' active');
                    return;
                } catch (e2) { obj.nvdLog('hot reload failed (' + e2.message + '); the next server restart applies the upgrade'); }
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

    /** @type {number} settle time after the upgrade was detected before the restart (ms). */
    obj.UPGRADE_RESTART_DELAY_MS = 5000;
    /** @type {number} give up waiting for a complete plugin tree after this long (ms). */
    obj.UPGRADE_RESTART_MAX_WAIT_MS = 120000;
    /** @type {number} poll interval while the plugin tree is still incomplete (ms). */
    obj.UPGRADE_RESTART_POLL_MS = 2000;

    /**
     * @brief True when this server runs as the child of MeshCentral's own launcher
     *   (meshcentral.js starts the real server with --launch and restarts it when it
     *   prints "Server restart..." and exits). Without that parent an exit would stop
     *   the server for good, so the hot swap is used instead.
     */
    obj.canRestartServer = function () {
        var a = obj.meshServer && obj.meshServer.args;
        return (a != null) && (a.launch != null) && (a.launch !== false);
    };

    /**
     * @brief The unpacked plugin tree looks complete: entry file, manifest, every lib/
     *   module and the panel view exist and are not empty (the installer writes them in
     *   ZIP order, lib/ and views/ last).
     */
    obj.upgradeTreeReady = function (wantVer) {
        try {
            var conf = JSON.parse(fs.readFileSync(path.join(obj.pluginDir, 'config.json'), 'utf8'));
            if (conf.version !== wantVer) { return false; }
            var files = [obj.shortName + '.js', path.join('views', 'assessment.handlebars')];
            fs.readdirSync(path.join(obj.pluginDir, 'lib')).forEach(function (f) { if (/\.js$/.test(f)) { files.push(path.join('lib', f)); } });
            for (var i = 0; i < files.length; i++) {
                if (fs.statSync(path.join(obj.pluginDir, files[i])).size === 0) { return false; }
            }
            return true;
        } catch (e) { return false; }
    };

    /** @brief End the server process (replaceable in tests). */
    obj.exitProcess = function (code) { process.exit(code); };

    /**
     * @brief Restart MeshCentral after a plugin upgrade (v4.3.2). Waits until the installer
     *   has finished (its DB update runs right after server_startup) and the new tree is
     *   complete, then uses the launcher's own restart signal - the same line and exit code
     *   as MeshCentral's "resetserver" console command. The new process loads the new code
     *   cleanly; nothing is hot-swapped in a server that already holds the old NVD index.
     */
    obj.scheduleUpgradeRestart = function (diskVer) {
        obj.timerGen++;
        var started = Date.now();
        var attempt = function () {
            if (!obj.upgradeTreeReady(diskVer) && (Date.now() - started) < obj.UPGRADE_RESTART_MAX_WAIT_MS) {
                setTimeout(attempt, obj.UPGRADE_RESTART_POLL_MS);
                return;
            }
            obj.nvdLog('restarting MeshCentral now to activate plugin version ' + diskVer);
            try {
                obj.meshServer.DispatchEvent(['*'], obj, { etype: 'server', action: 'msg', type: 'notify', domain: '', id: Math.random(), tag: 'ServerNotify',
                    title: 'Inventory & Vulnerability Scanner', value: 'Plugin upgraded to ' + diskVer + ' - the MeshCentral server restarts now. Reload the page in a moment.' });
            } catch (e) { }
            setTimeout(function () {
                console.log('Server restart...');
                setTimeout(function () { obj.exitProcess(0); }, 500);
            }, 1000);
        };
        setTimeout(attempt, obj.UPGRADE_RESTART_DELAY_MS);
    };

    /**
     * @brief Store the explicit panel url in the plugin doc (the plugin list itself opens
     *   pluginadmin.ashx?pin=<name> without an action, which handleAdminReq treats as 'show').
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
            domain: '', // default-domain sessions only (see lib/scheduling.js notifyAdmins)
            id: Math.random(),
            tag: 'ServerNotify',
            value: msg,
            title: 'NVD Database Stale'
        };
        try { obj.meshServer.DispatchEvent(['*'], obj, event); }
        catch (e) { obj.debug('plugin:inventory_scanner', 'Error dispatching NVD stale notification:', e.message); }
    };
};
