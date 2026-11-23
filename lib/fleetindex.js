/**
 * @file lib/fleetindex.js
 * @brief Read-only fleet aggregation that powers the two unified views of issue #8: one row per distinct
 *        installed software across the whole fleet (with how many devices carry it, whether it is
 *        vulnerable, whether an update is queued and whether a license was collected) and a per-device
 *        CVE count for the unified device list.
 *
 * It introduces NO new agent command and NO new outbound request: it only reads the inventory the
 * collector already stored (`obj.getStoredSoftware`), runs the same in-memory matcher the CSV builder
 * and the printable reports use (`obj.scanNodeSoftware`), and joins it to the winget results and the
 * locally collected license maps that already live on this server. Nothing that was not already
 * reachable by a site admin through the CSV export or a report starts leaving the machine here.
 * The result is cached briefly (TTL) so switching between the two views does not re-scan the fleet.
 *
 * Part of the MeshCentral Inventory & Vulnerability Scanner plugin; see ../inventoryscanner.js
 * for the module list and the attach order.
 */

"use strict";

/**
 * @brief Attach this module's members to one plugin instance.
 * @param {object} obj - The plugin object created by the entry point.
 */
module.exports.attach = function (obj) {
    /** @type {number} How long a built fleet index is reused across the two views (ms). */
    obj.FLEET_INDEX_TTL = 60 * 1000;

    /** @type {object|null} Last built index { at, data } - in-memory only, never persisted. */
    obj._fleetIndexCache = null;

    /** @brief Map a severity word to a rank for "highest severity wins" comparisons. */
    obj.fleetSevRank = function (sev) {
        var s = String(sev || '').toUpperCase();
        if (s === 'CRITICAL') return 4; if (s === 'HIGH') return 3; if (s === 'MEDIUM') return 2;
        if (s === 'LOW') return 1; if (s === 'UNKNOWN') return 0; return -1;
    };

    /**
     * @brief Lower-cased software names that the last winget run saw an update for (state 'dry-run'
     *        or a target version that differs from the installed one). Used only to flag a row as
     *        "update available"; it triggers nothing.
     * @returns {object} map lowerName -> true
     */
    obj.wgUpdatableNames = function () {
        var out = {};
        var res = obj.wgResults || {};
        for (var nodeid in res) {
            var rec = res[nodeid];
            if (!rec || !Array.isArray(rec.results)) continue;
            for (var i = 0; i < rec.results.length; i++) {
                var r = rec.results[i];
                if (!r || typeof r.name !== 'string') continue;
                var from = String(r.from || ''), to = String(r.to || '');
                if (r.state === 'dry-run' || (to !== '' && to !== from)) out[r.name.toLowerCase()] = true;
            }
        }
        return out;
    };

    /**
     * @brief Build (or reuse the cached) fleet index. Calls back with (err, data) where
     *        data = { devices, software:[{name,version,versions,publisher,deviceCount,vulnerable,cve,
     *        maxSeverity,updatable,hasLicense}], byDevice:{<nodeId>:{cve,maxSeverity}}, generated }.
     * @param {function} callback - (err, data).
     * @param {boolean} force - true ignores the short cache.
     */
    obj.buildFleetIndex = function (callback, force) {
        if (!force && obj._fleetIndexCache && ((Date.now() - obj._fleetIndexCache.at) < obj.FLEET_INDEX_TTL)) {
            callback(null, obj._fleetIndexCache.data); return;
        }
        obj.db.GetAllType('node', function (nerr, nodes) {
            if (nerr) { callback(nerr); return; }
            var live = [];
            if (nodes) {
                for (var i = 0; i < nodes.length; i++) {
                    var n = nodes[i];
                    if ((n == null) || (n._id == null) || (n.deleted != null)) continue;
                    live.push(n);
                    if (live.length >= 5000) break;
                }
            }
            var soft = {}, byDev = {}, updatable = obj.wgUpdatableNames();
            var done = 0, total = live.length;
            var finish = function () {
                var list = [];
                for (var low in soft) {
                    var s = soft[low];
                    list.push({
                        name: s.name, version: s.sample, versions: Object.keys(s.vers).length,
                        publisher: s.publisher, deviceCount: s.devs, vulnerable: s.cveCount > 0,
                        cve: s.cveCount, maxSeverity: s.maxSeverity, updatable: !!updatable[low], hasLicense: s.hasLicense
                    });
                }
                list.sort(function (a, b) { return (b.deviceCount - a.deviceCount) || String(a.name).localeCompare(String(b.name)); });
                if (list.length > 4000) list = list.slice(0, 4000);
                var data = { devices: total, software: list, byDevice: byDev, generated: new Date().toISOString() };
                obj._fleetIndexCache = { at: Date.now(), data: data };
                callback(null, data);
            };
            if (total === 0) { finish(); return; }
            for (var ni = 0; ni < live.length; ni++) {
                (function (node) {
                    var apps = obj.getStoredSoftware(node, {});
                    var licMap = obj.licenseMapForNode ? obj.licenseMapForNode(node._id) : {};
                    // Register every installed app for this device once (covers non-vulnerable software too).
                    var seenName = {};
                    for (var ai = 0; ai < apps.length; ai++) {
                        var app = apps[ai];
                        var nm = String((app && (app.name || app.Name || app.displayName || app.DisplayName)) || '');
                        if (nm === '') continue;
                        var low = nm.toLowerCase();
                        var b = soft[low];
                        if (b == null) { b = soft[low] = { name: nm, devs: 0, vers: {}, sample: '', publisher: '', cves: {}, cveCount: 0, maxSeverity: null, hasLicense: false }; }
                        if (!seenName[low]) {
                            seenName[low] = 1; b.devs++;
                            var ver = String((app.version || app.Version) || '');
                            if (ver !== '' && !b.vers[ver]) { b.vers[ver] = 1; if (b.sample === '') b.sample = ver; }
                            if (b.publisher === '') { b.publisher = String((app.publisher || app.Publisher || app.vendor || app.Vendor) || '').substring(0, 120); }
                        }
                        if (licMap[low] && String(licMap[low].license || '') !== '') b.hasLicense = true;
                    }
                    // Run the SAME matcher the CSV/reports use to attach CVE + severity to the buckets.
                    obj.scanNodeSoftware(node, apps, function (vulns) {
                        var devCve = 0, devMax = null;
                        for (var vi = 0; vi < (vulns || []).length; vi++) {
                            var v = vulns[vi];
                            if (!v || v.isCve !== true) continue;
                            devCve++;
                            var rk = obj.fleetSevRank(v.severity);
                            if (devMax === null || rk > obj.fleetSevRank(devMax)) devMax = (v.severity || 'UNKNOWN');
                            var low2 = String(v.software || '').toLowerCase();
                            var b2 = soft[low2];
                            if (b2 == null) { b2 = soft[low2] = { name: String(v.software || ''), devs: 0, vers: {}, sample: String(v.version || ''), publisher: '', cves: {}, cveCount: 0, maxSeverity: null, hasLicense: false }; }
                            {
                                var cid = String(v.cve || '');
                                if (cid !== '' && !b2.cves[cid]) { b2.cves[cid] = 1; b2.cveCount++; }
                                if (b2.maxSeverity === null || rk > obj.fleetSevRank(b2.maxSeverity)) b2.maxSeverity = (v.severity || 'UNKNOWN');
                            }
                        }
                        byDev[node._id] = { cve: devCve, maxSeverity: devMax };
                        if (++done >= total) finish();
                    });
                })(live[ni]);
            }
        });
    };

    /** @brief POST sw_fleet: the read-only fleet index for the two unified views (?refresh=1 rebuilds now). */
    obj.swFleetHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        try {
            obj.buildFleetIndex(function (err, data) {
                if (err) { send({ error: err.message }); return; }
                send(data);
            }, String((req.body && req.body.refresh) || '') === '1' || String((req.query && req.query.refresh) || '') === '1');
        } catch (ex) { send({ error: ex.message }); }
    };
};
