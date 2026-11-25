/**
 * @file lib/scheduling.js
 * @brief Scheduled group scans, their restart-proof timers, the persisted scan snapshots and the admin notifications with the two notification modes.
 * Node clamps setTimeout above 2^31-1 ms to 1 ms (a hot loop), so every long interval goes through obj.longTimeout (chunked, wall-clock based).
 *
 * Part of the MeshCentral Inventory & Vulnerability Scanner plugin; see ../inventoryscanner.js
 * for the module list and the attach order. Every member is attached to the shared plugin
 * object, so cross-module calls go through obj.name(...) and stay replaceable at runtime.
 */

"use strict";

const fs = require('fs');

/**
 * @brief Attach this module's members to one plugin instance.
 * @param {object} obj - The plugin object created by the entry point.
 */
module.exports.attach = function (obj) {
    /** @type {string|null} ISO timestamp of the last scheduled (or manual) group scan. */
    obj.lastScan = null;

    /** @type {Object} In-memory scheduled scan results: <code>meshId -> { time, cves }</code>. */
    obj.scanResults = {};

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
        var osUpgradeUrgentDays = 365; // an outdated OS release is "urgent" this many days before its support ends (v3.6.0)
        if (cfg && (typeof cfg === 'object')) {
            if (typeof cfg.osUpgradeUrgentDays === 'number' && Math.floor(cfg.osUpgradeUrgentDays) === cfg.osUpgradeUrgentDays && cfg.osUpgradeUrgentDays >= 0 && cfg.osUpgradeUrgentDays <= 3650) { osUpgradeUrgentDays = cfg.osUpgradeUrgentDays; }
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
        return { intervalHours: intervalHours, meshes: meshes, notifyOnScan: notifyOnScan, notifyThreshold: notifyThreshold, notifyThresholds: notifyThresholds, notifyUnratedRepeat: notifyUnratedRepeat, autoProductMatch: autoProductMatch, cpeTableEnabled: cpeTableEnabled, cpeTableUrl: cpeTableUrl, distroManaged: distroManaged, osLifecycleEnabled: osLifecycleEnabled, osLifecycleUrl: osLifecycleUrl, osUpgradeUrgentDays: osUpgradeUrgentDays };
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
    obj.MAX_TIMEOUT_MS = 2147483647;

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
        if (ms <= obj.MAX_TIMEOUT_MS) { setter(callback, ms); return; }
        var startTime = nowFn();
        function scheduleChunk() {
            var remaining = ms - (nowFn() - startTime);
            if (remaining <= 0) { callback(); return; }
            setter(scheduleChunk, Math.min(remaining, obj.MAX_TIMEOUT_MS));
        }
        scheduleChunk();
    };

    /**
     * @brief Cooperative loop over a list of work items - the shared answer to "the scan blocks the
     * whole server" (v4.4.0). Every device needs a sysinfo read, a per-program CVE lookup and a
     * mapping check; done as one synchronous pass over a few hundred devices that is tens of seconds
     * of CPU in ONE event-loop turn, and NOTHING else (not even another plugin tab) is served while
     * it runs. pacedEach keeps at most SCAN_PARALLEL devices in flight and yields with setImmediate
     * between item starts and completions, so pending HTTP requests and agent traffic run in between
     * - the scan takes a little longer, the server stays usable.
     * @param {Array<object>} list - Items to process (never modified).
     * @param {function} worker - <code>worker(item, itemDone)</code>; itemDone must be called once.
     * @param {function} done - Called once after the last item finished.
     * @param {number} [parallel] - In-flight items (default obj.SCAN_PARALLEL).
     */
    obj.pacedEach = function (list, worker, done, parallel) {
        var items = Array.isArray(list) ? list : [];
        var max = (typeof parallel === 'number' && parallel > 0) ? parallel : obj.SCAN_PARALLEL;
        var i = 0, active = 0, finished = false;
        if (items.length === 0) { done(); return; }
        function finishOnce() { if (finished === false) { finished = true; done(); } }
        function pump() {
            if (finished === true) return;
            var started = 0;
            while ((active < max) && (i < items.length) && (started < max)) {
                var item = items[i++];
                active++; started++;
                (function (it) {
                    var once = false;
                    worker(it, function () { if (once === false) { once = true; active--; setImmediate(pump); } });
                })(item);
            }
            if (i < items.length) {
                // Work left: continue in the NEXT event-loop turn, never in this one - a worker that
                // answers synchronously would otherwise let the whole list run inside a single turn,
                // which is exactly the blocking this helper exists to prevent.
                setImmediate(pump);
                return;
            }
            if (active === 0) { finishOnce(); }
        }
        pump();
    };

    /** @type {number} devices scanned/serialized at the same time inside one paced run. */
    obj.SCAN_PARALLEL = 4;

    /**
     * @brief Run the scheduled vulnerability scans for the configured meshes.
     * Scans each mesh, aggregates its unique CVEs (with group-wide assessments),
     * stores the result in <code>scanResults</code> and persists it. If
     * notifications are enabled, sends an admin notification listing any newly
     * found CVEs at or above <code>notifyThreshold</code>.
     */
    obj.runScheduledScans = function (done) {
        var fin = function () { if (typeof done === 'function') { var d = done; done = null; d(); } };
        var cfg = obj.scannerConfig();
        if (cfg.intervalHours <= 0) { return fin(); } // scheduled scanning disabled

        obj.meshServer.db.GetAllType('mesh', function (err, meshes) {
            if (err || !meshes) { return fin(); }
            var targetRecords = [];
            for (var i = 0; i < meshes.length; i++) {
                var m = meshes[i];
                if ((m == null) || (m._id == null) || (m.deleted != null)) continue;
                if ((cfg.meshes != null) && (cfg.meshes.indexOf(m._id) < 0)) continue;
                targetRecords.push({ id: m._id, name: (m.name != null) ? m.name : m._id });
            }
            if (targetRecords.length === 0) { obj.lastScan = new Date().toISOString(); return fin(); }

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
                        fin();
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
            domain: '', // default-domain sessions only: '*' also reaches sub-domain site admins (meshuser.js HandleEvent filters by event.domain)
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
            // v5.5.1 (audit 4): the next run is planned only AFTER this pass finished. Before, scheduleScans()
            // ran right after runScheduledScans() STARTED the asynchronous pass - lastScan was still the old
            // value, so the residual delay was the 60 s floor and a new full fleet pass started every minute
            // until the first one finished (measured: 6 passes for a 5-minute scan). A pass that never
            // finishes must not stop the schedule either, so a watchdog plans the next run after one interval.
            var planned = false;
            var planNext = function () { if (planned) { return; } planned = true; if (obj.timerValid(gen)) { obj.scheduleScans(); } };
            var wd = setTimeout(function () { if (!planned) { obj.debug('plugin:inventory_scanner', 'Scheduled scan did not finish within the interval - planning the next run anyway'); obj.lastScan = new Date().toISOString(); planNext(); } }, Math.min(intervalMs, obj.MAX_TIMEOUT_MS));
            if (wd && wd.unref) { wd.unref(); }
            obj.runScheduledScans(function () { clearTimeout(wd); planNext(); });
        }, delay);
    };
};
