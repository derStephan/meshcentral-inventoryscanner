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

    /** @type {object|null} last built index { at, data } - in-memory only, never persisted. */
    obj._fleetIndexCache = null;
    /** @type {Array<function>|null} waiters of a build that is already running (coalescing, v5.4.2). */
    obj._fleetIndexWaiters = null;

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
        // Coalescing (v5.4.2): a second request while a build is running joins it instead of starting a
        // second walk over the fleet - two parallel builds doubled the event-loop pressure that made
        // unrelated requests time out at the proxy (the reported 502s).
        if (obj._fleetIndexWaiters != null) { obj._fleetIndexWaiters.push(callback); return; }
        obj._fleetIndexWaiters = [callback];
        var answerAll = function (err, data) {
            var ws = obj._fleetIndexWaiters || [];
            obj._fleetIndexWaiters = null;
            for (var w = 0; w < ws.length; w++) { try { ws[w](err, data); } catch (e) { } }
        };
        obj.db.GetAllType('node', function (nerr, nodes) {
            if (nerr) { answerAll(nerr); return; }
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
            var total = live.length;
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
                answerAll(null, data);
            };
            if (total === 0) { finish(); return; }
            // v5.4.2: PACED, never a bare loop. collectNodeInventory -> scanDeviceSoftware runs its matcher
            // synchronously per program, so an unpaced walk over the fleet hogged the event loop for seconds
            // and every other request in flight (settings, license, locations, os_status) died at the proxy
            // with a 502. pacedEach yields between devices and caps the parallelism, like the CSV/report paths.
            obj.pacedEach(live, function (node, nodeDone) {
                // v5.1.0: the SAME canonical collection the CSV, the reports and the asset push use.
                obj.collectNodeInventory(node, function (cerr, inv) {
                    if (cerr || !inv) { byDev[node._id] = { cve: 0, maxSeverity: null }; nodeDone(); return; }
                    var licMap = obj.licenseMapForNode ? obj.licenseMapForNode(node._id) : {};
                    // Register every installed app for this device once (covers non-vulnerable software too),
                    // using the canonical projection so all consumers see the same name/version/publisher.
                    var seenName = {};
                    for (var ai = 0; ai < inv.softwareList.length; ai++) {
                        var app = inv.softwareList[ai];
                        var nm = String(app.name || '');
                        if (nm === '') continue;
                        var low = nm.toLowerCase();
                        var b = soft[low];
                        if (b == null) { b = soft[low] = { name: nm, devs: 0, vers: {}, sample: '', publisher: '', cves: {}, cveCount: 0, maxSeverity: null, hasLicense: false }; }
                        if (!seenName[low]) {
                            seenName[low] = 1; b.devs++;
                            var ver = String(app.version || '');
                            if (ver !== '' && !b.vers[ver]) { b.vers[ver] = 1; if (b.sample === '') b.sample = ver; }
                            if (b.publisher === '') { b.publisher = String(app.publisher || '').substring(0, 120); }
                        }
                        if (licMap[low] && String(licMap[low].license || '') !== '') b.hasLicense = true;
                    }
                    // Per-software CVE attribution uses the SOFTWARE findings only - the OS-level findings
                    // (WINDOWS-UPDATES, OS-EOL, OS CVEs) belong to the device, not to an installed program,
                    // and must not invent software rows.
                    for (var vi = 0; vi < inv.softwareFindings.length; vi++) {
                        var v = inv.softwareFindings[vi];
                        if (!v || v.isCve !== true) continue;
                        var rk = obj.fleetSevRank(v.severity);
                        var low2 = String(v.software || '').toLowerCase();
                        var b2 = soft[low2];
                        if (b2 == null) { b2 = soft[low2] = { name: String(v.software || ''), devs: 0, vers: {}, sample: String(v.version || ''), publisher: '', cves: {}, cveCount: 0, maxSeverity: null, hasLicense: false }; }
                        var cid = String(v.cve || '');
                        if (cid !== '' && !b2.cves[cid]) { b2.cves[cid] = 1; b2.cveCount++; }
                        if (b2.maxSeverity === null || rk > obj.fleetSevRank(b2.maxSeverity)) b2.maxSeverity = (v.severity || 'UNKNOWN');
                    }
                    // The device badge counts the FULL finding list (distinct ids) - exactly what the
                    // vulnerability CSV and the printable report show for this device.
                    byDev[node._id] = { cve: inv.counts.uniqueFindingIds, maxSeverity: inv.counts.maxSeverity, findings: inv.counts.findings };
                    nodeDone();
                });
            }, finish, 2);
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

    // ---------- on-demand details for the unified views (issue #9) ----------
    //
    // Both routes are READ-ONLY: they answer from data already stored on this server (the canonical
    // inventory record plus the persisted engine results) and send NO agent command. They exist so the
    // device list and the software list can stay compact - the detail is fetched when the admin clicks.

    /** @type {object|null} short-lived cache for one software detail lookup { at, name, data }. */
    obj._swDetailsCache = null;

    /**
     * @brief POST dev_details: everything stored about ONE device - the same facts the CSV exports and the
     * printable reports show, plus the last run of every engine. Never a license VALUE (counts only).
     * @param {object} req - body.nodeId.
     */
    obj.devDetailsHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        var nodeid = String((req.body && req.body.nodeId) || '').trim();
        if (!/^node\/[^:]{1,100}$/.test(nodeid)) { return send({ error: 'Invalid node id.' }); }
        obj.db.Get(nodeid, function (err, docs) {
            if (err || !docs || !docs.length || !docs[0] || (docs[0].deleted != null)) { return send({ error: 'Unknown device.' }); }
            var node = docs[0];
            obj.collectNodeInventory(node, function (cerr, inv) {
                if (cerr) { return send({ error: cerr.message }); }
                var i;
                // findings shaped like the CSV rows: everything with an id is a finding, the rest is coverage
                var findings = [], coverage = [];
                for (i = 0; i < inv.findings.length; i++) {
                    var f = inv.findings[i];
                    if (!f) { continue; }
                    var row = {
                        id: String(f.cve || ''), status: String(f.status || (f.isCve ? 'CVE' : '')),
                        severity: String(f.severity || 'UNKNOWN'), cvss: (f.cvss != null ? f.cvss : ''),
                        software: String(f.software || ''), version: String(f.version || ''),
                        description: String(f.description || '').substring(0, 400)
                    };
                    if (row.id !== '') { findings.push(row); } else { coverage.push(row); }
                }
                var wcfg = obj.wingetConfig();
                var wgRec = (obj.wgResults && obj.wgResults[nodeid]) || null;
                var wgRows = [];
                if (wgRec && Array.isArray(wgRec.results)) {
                    for (i = 0; i < wgRec.results.length && wgRows.length < 200; i++) {
                        var r = wgRec.results[i] || {};
                        wgRows.push({
                            id: String(r.id || '').substring(0, 128), name: String(r.name || '').substring(0, 200),
                            from: String(r.from || '').substring(0, 60), to: String(r.to || '').substring(0, 60),
                            state: String(r.state || 'unknown'), exit: (typeof r.exit === 'number' ? r.exit : null),
                            log: String(r.log || '').substring(0, 300)
                        });
                    }
                }
                var ui = obj.osUpgradeInfo(node.osdesc);
                var probe = (obj.devResults && obj.devResults[nodeid]) || null;
                var hasProbe = obj.devProbeFresh(probe);
                var lic = (obj.licenseInventory && obj.licenseInventory[obj.safeNodeDir(nodeid)]) || null;
                var licFound = 0, licMs = 0;
                if (lic && Array.isArray(lic.items)) {
                    for (i = 0; i < lic.items.length; i++) { if (lic.items[i] && lic.items[i].license) { licFound++; } }
                }
                if (lic && Array.isArray(lic.ms)) { licMs = lic.ms.length; }
                var pend = function (map) { return (map && map[nodeid]) ? { since: map[nodeid].since || 0, kind: map[nodeid].kind || map[nodeid].mode || '' } : null; };
                send({
                    device: {
                        id: inv.id, host: inv.host, given: inv.given, group: inv.group, os: inv.os,
                        platform: inv.platform, online: inv.online, ip: inv.ip, windowsBuild: inv.windowsBuild,
                        osSupport: inv.osSupport ? inv.osSupport.state : 'unknown'
                    },
                    hardware: inv.hardware,
                    software: inv.softwareList,
                    findings: findings,
                    coverage: coverage,
                    counts: inv.counts,
                    winget: {
                        excluded: wcfg.excludeNodes.indexOf(nodeid) >= 0,
                        last: wgRec ? { time: wgRec.time || '', dry: wgRec.dry === true, winget: wgRec.winget === true, error: wgRec.error || '' } : null,
                        rows: wgRows,
                        pending: pend(obj.wgPending)
                    },
                    os: {
                        releaseState: ui.state, outdated: !!ui.outdated, urgent: !!ui.urgent, upgradable: !!(ui.outdated && ui.method != null),
                        target: ui.target || '', note: ui.note || '', eol: ui.eol || '', daysLeft: (ui.daysLeft != null ? ui.daysLeft : null),
                        urgentReason: ui.urgentReason || '',
                        last: (obj.osResults && obj.osResults[nodeid]) || null,
                        pending: pend(obj.osPending)
                    },
                    wu: (obj.wuResults && obj.wuResults[nodeid]) || null,
                    wuPending: pend(obj.wuPending),
                    rb: (obj.rbResults && obj.rbResults[nodeid]) || null,
                    rbPending: pend(obj.rbPending),
                    reset: {
                        hasProbe: hasProbe,
                        probe: (probe && probe.kind === 'probe') ? probe : null,
                        modes: { clean: hasProbe ? obj.devModeAllowed(probe, 'clean', 'true').allowed : false, keepfiles: hasProbe ? obj.devModeAllowed(probe, 'keepfiles').allowed : false },
                        last: (obj.devLast && obj.devLast[nodeid]) || null,
                        pending: pend(obj.devPending)
                    },
                    // counts only - a collected license key is a secret and never leaves the server files
                    license: { enabled: obj.licenseConfig().collectEnabled, found: licFound, ms: licMs, time: (lic && lic.time) ? lic.time : '', pending: pend(obj.licPending) }
                });
            });
        });
    };

    /**
     * @brief POST sw_details: everything stored about ONE installed program across the fleet - which devices
     * have it in which version, which CVEs matched it, whether a license was collected (presence, never the
     * value) and what the last winget run reported for it. Read-only, no agent command.
     * @param {object} req - body.name (the installed display name), optional body.pkgId (exact winget id).
     */
    obj.swDetailsHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        var name = String((req.body && req.body.name) || '').trim();
        if (name === '' || name.length > 200) { return send({ error: 'Invalid software name.' }); }
        var pkgId = String((req.body && req.body.pkgId) || '').trim();
        if (pkgId !== '' && !obj.WINGET_ID_RE.test(pkgId)) { pkgId = ''; }
        var low = name.toLowerCase();
        if (obj._swDetailsCache && (obj._swDetailsCache.name === low) && ((Date.now() - obj._swDetailsCache.at) < obj.FLEET_INDEX_TTL)) {
            return send(obj._swDetailsCache.data);
        }
        obj.db.GetAllType('node', function (nerr, nodes) {
            if (nerr) { return send({ error: nerr.message }); }
            var live = [];
            if (nodes) {
                for (var n = 0; n < nodes.length; n++) {
                    var nd = nodes[n];
                    if ((nd == null) || (nd._id == null) || (nd.deleted != null)) { continue; }
                    live.push(nd);
                    if (live.length >= 5000) { break; }
                }
            }
            var devices = [], versions = {}, cves = {}, coverage = {}, licDevices = 0, matched = 0;
            // winget: find the package rows for this program in the stored last runs (by id when given, else by name)
            var wg = { pkgId: pkgId, name: name, ready: 0, ok: 0, failed: 0, skipped: 0, ignored: false, perDevice: [] };
            var igList = (obj.wingetConfig().ignorePackages || []);
            var res = obj.wgResults || {};
            for (var nodeid in res) {
                if (!Object.prototype.hasOwnProperty.call(res, nodeid)) { continue; }
                var rec = res[nodeid];
                if (!rec || !Array.isArray(rec.results)) { continue; }
                for (var ri = 0; ri < rec.results.length; ri++) {
                    var row = rec.results[ri] || {};
                    var byId = (pkgId !== '' && String(row.id || '') === pkgId);
                    var byName = (pkgId === '' && String(row.name || '').toLowerCase() === low);
                    if (!byId && !byName) { continue; }
                    if (wg.pkgId === '' && row.id) { wg.pkgId = String(row.id); }
                    var st = String(row.state || 'unknown');
                    if (st === 'dry-run') { wg.ready++; } else if (st === 'ok') { wg.ok++; } else if (st === 'failed') { wg.failed++; } else { wg.skipped++; }
                    if (wg.perDevice.length < 200) {
                        wg.perDevice.push({
                            node: nodeid, state: st, from: String(row.from || '').substring(0, 60),
                            to: String(row.to || '').substring(0, 60), time: rec.time || '', dry: rec.dry === true,
                            exit: (typeof row.exit === 'number' ? row.exit : null), log: String(row.log || '').substring(0, 200)
                        });
                    }
                }
            }
            for (var ig = 0; ig < igList.length; ig++) {
                if (wg.pkgId !== '' && String(igList[ig].id || '').toLowerCase() === String(wg.pkgId).toLowerCase()) { wg.ignored = true; }
            }
            var finish = function () {
                var vlist = [];
                for (var v in versions) { if (Object.prototype.hasOwnProperty.call(versions, v)) { vlist.push({ version: v, count: versions[v] }); } }
                vlist.sort(function (a, b) { return (b.count - a.count) || String(a.version).localeCompare(String(b.version)); });
                var clist = [];
                for (var c in cves) { if (Object.prototype.hasOwnProperty.call(cves, c)) { clist.push(cves[c]); } }
                clist.sort(function (a, b) { return (Number(b.cvss) || 0) - (Number(a.cvss) || 0) || String(a.id).localeCompare(String(b.id)); });
                var covlist = [];
                for (var k in coverage) { if (Object.prototype.hasOwnProperty.call(coverage, k)) { covlist.push({ status: k, count: coverage[k] }); } }
                var data = {
                    name: name, devices: devices, deviceCount: matched, versions: vlist,
                    cves: clist.slice(0, 200), coverage: covlist, licenseDevices: licDevices,
                    winget: wg, generated: new Date().toISOString()
                };
                obj._swDetailsCache = { at: Date.now(), name: low, data: data };
                send(data);
            };
            if (live.length === 0) { return finish(); }
            obj.pacedEach(live, function (node, nodeDone) {
                obj.collectNodeInventory(node, function (e, inv) {
                    if (!e && inv) {
                        var hit = false;
                        for (var i = 0; i < inv.softwareList.length; i++) {
                            var s = inv.softwareList[i];
                            if (String(s.name || '').toLowerCase() !== low) { continue; }
                            hit = true;
                            if (devices.length < 300) {
                                devices.push({ id: inv.id, host: inv.host, given: inv.given, group: inv.group, online: inv.online, version: s.version, location: s.location });
                            }
                            if (s.version) { versions[s.version] = (versions[s.version] || 0) + 1; }
                        }
                        if (hit) {
                            matched++;
                            for (var j = 0; j < inv.findings.length; j++) {
                                var f = inv.findings[j];
                                if (!f || String(f.software || '').toLowerCase() !== low) { continue; }
                                if (f.cve) {
                                    if (!cves[f.cve]) { cves[f.cve] = { id: String(f.cve), severity: String(f.severity || 'UNKNOWN'), cvss: (f.cvss != null ? f.cvss : ''), version: String(f.version || ''), description: String(f.description || '').substring(0, 300) }; }
                                } else {
                                    var stt = String(f.status || 'other');
                                    coverage[stt] = (coverage[stt] || 0) + 1;
                                }
                            }
                            var lm = obj.licenseMapForNode ? obj.licenseMapForNode(inv.id) : {};
                            if (lm[low] && String(lm[low].license || '') !== '') { licDevices++; }
                        }
                    }
                    nodeDone();
                });
            }, finish, 4);
        });
    };
};
