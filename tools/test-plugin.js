/**
 * Behavioral tests for the plugin module with a mocked MeshCentral server.
 * No dependencies, no network, no real server: the plugin is instantiated with
 * a fake parent/db/webserver, the CVE lookups are stubbed, and the routes,
 * handlers, report builder, scheduled-scan logic and notification modes are
 * asserted directly. Run: node tools/test-plugin.js
 */
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

const factory = require(path.join(__dirname, '..', 'inventoryscanner.js')).inventoryscanner;

// All plugin source (entry + lib/ modules) - for the tests that assert on emitted code text.
const PLUGIN_DIR = path.join(__dirname, '..');
/**
 * Run Windows PowerShell for a test. Returns null ONLY when PowerShell is not installed (ENOENT);
 * a PowerShell that ran and failed (parse error, exception, non-zero exit) returns
 * { failed: true, text } so the caller reports a FAIL - before audit 3 every failure was
 * silently reported as "SKIP ... PowerShell not available".
 */
function runPs(args, opts) {
    try { return { failed: false, text: require('child_process').execFileSync('powershell', args, Object.assign({ encoding: 'utf8', timeout: 60000 }, opts || {})) }; }
    catch (e) {
        if (e && e.code === 'ENOENT') { return null; }
        return { failed: true, text: String((e && (e.stderr || e.stdout || e.message)) || e).substring(0, 400) };
    }
}

// audit 4: the old "marker before Stop-Transcript" checks compared indexOf values - a REMOVED marker (-1) passed
// them. This helper demands that the marker exists and that EVERY marker emission comes before the next
// Stop-Transcript that follows it (a script may answer on several paths, each must answer before it stops).
function markerBeforeStop(script, marker) {
    var s = String(script), at = s.indexOf(marker);
    if (at < 0) { return false; }
    while (at >= 0) {
        var stop = s.indexOf('Stop-Transcript', at);
        if (stop < 0) { return false; }
        at = s.indexOf(marker, at + marker.length);
        if (at >= 0 && at < stop) { continue; }
    }
    return true;
}

function pluginSrc() {
    var s = fs.readFileSync(path.join(PLUGIN_DIR, 'inventoryscanner.js'), 'utf8');
    var libDir = path.join(PLUGIN_DIR, 'lib');
    if (fs.existsSync(libDir)) {
        fs.readdirSync(libDir).filter(f => f.endsWith('.js')).sort().forEach(f => { s += '\n' + fs.readFileSync(path.join(libDir, f), 'utf8'); });
    }
    return s;
}

// ---------- fixtures ----------
const nodes = [
    { _id: 'node//d1', meshid: 'mesh//grp1', rname: 'host1', name: 'Given1', osdesc: 'Windows 10' },
    { _id: 'node//d2', meshid: 'mesh//grp1', rname: 'host2', name: 'Given2', osdesc: 'Windows 11' },
    { _id: 'node//d3', meshid: 'mesh//grp2', rname: 'host3', name: 'Given3', osdesc: 'Ubuntu 22.04' },
    { _id: 'node//d4', meshid: 'mesh//grp2', name: 'Given4Only', osdesc: 'Windows 10' }
];
const meshes = [
    { _id: 'mesh//grp1', name: 'HQ' },
    { _id: 'mesh//grp2', name: 'Branch' },
    { _id: 'mesh//grpX', name: 'Deleted', deleted: 1 }
];
const apps = [{ name: 'Firefox', version: '1.0' }, { name: 'Chrome', version: '2.0' }, { name: 'OEM Tool', version: '1' }];
const sysinfo = {
    'sinode//d1': { _id: 'sinode//d1', doc: { hardware: { windows: { osinfo: { BuildRevision: '19045' } } }, apps: apps } },
    'sinode//d2': { _id: 'sinode//d2', doc: { apps: apps } },
    'sinode//d3': { _id: 'sinode//d3', doc: { apps: apps } },
    'sinode//d4': { _id: 'sinode//d4', doc: { apps: apps } }
};
const db = {
    GetAllType: function (type, cb) {
        if (type === 'node') { cb(null, nodes.slice()); }
        else if (type === 'mesh') { cb(null, meshes.slice()); }
        else { cb(null, []); }
    },
    Get: function (id, cb) {
        if (sysinfo[id]) { cb(null, [sysinfo[id]]); return; }
        for (const n of nodes) { if (n._id === id) { cb(null, [n]); return; } }
        cb(null, []);
    }
};
const meshServer = {
    db: db,
    datapath: fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-test-')),
    debug: function () { },
    config: { settings: {} },
    webserver: { meshes: { 'mesh//grp1': { name: 'HQ' }, 'mesh//grp2': { name: 'Branch' } } }
};
const obj = factory({ parent: meshServer });
obj.loadRemoteCpeTable(); // what server_startup does on a real server; since the v4.2.0 dedup the curated stage is ONLY cpe-table.json

// stub CVE matching (the real one needs the multi-GB NVD index)
const softwareVulns = [
    { status: 'CVE', isCve: true, cve: 'CVE-2024-0001', severity: 'CRITICAL', cvss: 9.8, description: 'crit bug', software: 'Firefox', version: '1.0', published: '', references: [] },
    { status: 'CVE', isCve: true, cve: 'CVE-2024-0002', severity: 'HIGH', cvss: 7.5, description: 'high bug', software: 'Chrome', version: '2.0', published: '', references: [] },
    { status: 'not assessable', isCve: false, cve: '', severity: '', cvss: '', description: 'n/a', software: 'OEM Tool', version: '1', published: '', references: [] }
];
obj.scanDeviceSoftware = function (list, cb) { cb(softwareVulns); };
obj.scanDeviceOs = function () {
    return [{ cve: 'CVE-2024-0003', severity: 'MEDIUM', cvss: 5.0, description: 'os bug', software: 'Operating System', version: 'x', published: '', references: [] }];
};
obj.saveAssessments = function (cb) { if (cb) cb(null); };
obj.saveCustomCpe = function (cb) { if (cb) cb(null); };

let failures = 0;
function check(name, cond, extra) {
    if (cond) { console.log('PASS ' + name); }
    else { failures++; console.log('FAIL ' + name + (extra !== undefined ? ' -> ' + JSON.stringify(extra) : '')); }
}
function mockRes(done) {
    var used = 0;
    var dd = function (d) {
        used++;
        if (used > 1) { failures++; console.log('FAIL response object answered ' + used + 'x, payload=' + JSON.stringify(d).substring(0, 120)); }
        done(d);
    };
    return {
        type: function () { return this; },
        json: function (d) { dd(d); },
        sendStatus: function (c) { dd({ _status: c }); },
        render: function (v, d) { dd({ _view: v, _data: d }); },
        setHeader: function (k, v) { if (!this._headers) { this._headers = {}; } this._headers[k] = v; },
        send: function (body) { dd({ _body: body, _headers: this._headers }); }
    };
}
const user = { name: 'admin', _id: 'user//u1', siteadmin: 0xFFFFFFFF, domain: '' };
// v3.0.1: every POST must carry the panel's request header (request-origin check)
const XHDR = { 'x-invscanner-request': '1' };

// v5.0.1: as_push answers immediately and runs in the background (like wg_run/os_run), so tests that
// assert on the RESULT must wait for the run to finish instead of trusting the response.
var waitPush = function (o, cb) {
    var n = 0;
    var poll = function () { if ((o.asPushing !== true) || (n++ > 400)) { cb(); } else { setTimeout(poll, 5); } };
    poll();
};

const steps = [];

// ---- buildOverallReport: locations, counting semantics, coverage ----
steps.push(function (next) {
    obj.assessments = {
        'mesh//grp1:CVE-2024-0002': { meshId: 'mesh//grp1', cveId: 'CVE-2024-0002', assessment: 'LOW', comment: 'mitigated', lastModified: 'x', assessedBy: 'a', assessedById: 'b' },
        'mesh//grp2:CVE-2024-0001': { meshId: 'mesh//grp2', cveId: 'CVE-2024-0001', assessment: 'UNKNOWN', comment: '', flagged: true, lastModified: 'x', assessedBy: 'a', assessedById: 'b' }
    };
    obj.buildOverallReport(function (err, report) {
        check('report: no error', !err, err);
        check('report: locations array sorted by name', report.locations.map(l => l.name).join(',') === 'Branch,HQ', report.locations.map(l => l.name));
        check('report: locationCount', report.locationCount === 2);
        const hq = report.locations.find(l => l.name === 'HQ');
        const br = report.locations.find(l => l.name === 'Branch');
        check('report: HQ occurrences (2 devices x 3 CVEs)', hq && hq.totalCves === 6, hq && hq.totalCves);
        check('report: manual rating overrides NVD severity in counting', hq && hq.severityCounts.LOW === 2 && hq.severityCounts.CRITICAL === 2, hq && hq.severityCounts);
        check('report: finding devices are host names', hq && hq.findings.find(f => f.cve === 'CVE-2024-0001').devices.join(',') === 'host1,host2');
        check('report: flagged occurrences excluded but counted as FP', br && br.totalCves === 4 && br.falsePositiveCves === 2, br && [br.totalCves, br.falsePositiveCves]);
        check('report: flagged finding effectiveSeverity', br && br.findings.find(f => f.cve === 'CVE-2024-0001').effectiveSeverity === 'false positive');
        check('report: totals 10 findings / 2 FP / 3 unique', report.totalCves === 10 && report.falsePositiveCves === 2 && report.uniqueCves === 3, [report.totalCves, report.falsePositiveCves, report.uniqueCves]);
        check('report: rname preferred, name fallback', report.devices.some(d => d.hostName === 'host1') && report.devices.some(d => d.hostName === 'Given4Only'), report.devices.map(d => d.hostName));
        check('report: coverage 12 programs, 8 assessable (67%)', report.totalPrograms === 12 && report.assessablePrograms === 8 && report.coveragePercent === 67, [report.totalPrograms, report.assessablePrograms, report.coveragePercent]);
        check('report: internal findingsById removed', hq && hq.findingsById === undefined);
        next();
    });
});

// ---- scanMultiMeshCves: aggregation + mixed/uniform logic ----
steps.push(function (next) {
    obj.scanMultiMeshCves(['mesh//grp1', 'mesh//grp2'], function (err, result) {
        check('scan: 3 unique findings', !err && result.cves.length === 3, result.cves.map(c => c.cve));
        const c1 = result.cves.find(c => c.cve === 'CVE-2024-0001');
        check('scan: partly flagged => mixed, anyFlagged', c1.mixed === true && c1.anyFlagged === true && c1.assessment === null);
        const c3 = result.cves.find(c => c.cve === 'CVE-2024-0003');
        check('scan: fully unrated => NOT mixed, no assessment', c3.mixed === false && c3.assessment === null);
        const c2 = result.cves.find(c => c.cve === 'CVE-2024-0002');
        check('scan: partly rated => mixed', c2.mixed === true);
        check('scan: meshes resolved by name', result.meshes.map(m => m.name).join(',') === 'Branch,HQ', result.meshes);
        next();
    });
});

// ---- POST routes: save / flag / unflag + validation ----
steps.push(function (next) {
    obj.handleAdminPostReq({ headers: XHDR, body: { action: 'save_assessment', meshIds: 'mesh//grp1,mesh//grp2', cveId: 'CVE-2024-0003', assessment: 'high', comment: 'patch tuesday' } },
        mockRes(function (d) {
            check('route save_assessment: stores for all meshIds', d.success === true && obj.assessments['mesh//grp1:CVE-2024-0003'].assessment === 'HIGH' && obj.assessments['mesh//grp2:CVE-2024-0003'].assessment === 'HIGH', d);
            next();
        }), user);
});

steps.push(function (next) {
    obj.handleAdminPostReq({ headers: XHDR, body: { action: 'flag_false_positive', meshIds: 'mesh//grp1', cveId: 'CVE-2024-0001' } },
        mockRes(function (d) {
            check('route flag: succeeds with NO comment', d.success === true && obj.assessments['mesh//grp1:CVE-2024-0001'].comment === '' && obj.assessments['mesh//grp1:CVE-2024-0001'].flagged === true, d);
            obj.handleAdminPostReq({ headers: XHDR, body: { action: 'save_assessment', meshId: 'mesh//grp1', cveId: 'CVE-2024-0002', assessment: 'LOW', comment: '   ' } },
                mockRes(function (d2) {
                    check('route save: empty comment still rejected', !!d2.error, d2);
                    next();
                }), user);
        }), user);
});

steps.push(function (next) {
    obj.handleAdminPostReq({ headers: XHDR, body: { action: 'unflag_false_positive', meshIds: 'mesh//grp1,mesh//grp2', cveId: 'CVE-2024-0001' } },
        mockRes(function (d) {
            check('route unflag: removes flags for all meshes', d.success === true && obj.assessments['mesh//grp2:CVE-2024-0001'] === undefined, d);
            obj.handleAdminPostReq({ headers: XHDR, body: { action: 'flag_false_positive', meshIds: 'mesh//grp1:evil', cveId: 'CVE-2024-0002' } },
                mockRes(function (d2) {
                    check('validation: colon-bearing meshId rejected (key poisoning)', !!d2.error, d2);
                    obj.handleAdminPostReq({ headers: XHDR, body: { action: 'save_assessment', meshId: 'mesh//grp1', cveId: 'DROP TABLE', assessment: 'LOW', comment: 'x' } },
                        mockRes(function (d3) {
                            check('validation: bogus cveId rejected', !!d3.error, d3);
                            obj.handleAdminPostReq({ headers: XHDR, body: { action: 'flag_false_positive', meshId: 'mesh//grp1', cveId: 'WINDOWS-UPDATES' } },
                                mockRes(function (d4) {
                                    check('WINDOWS-UPDATES is flaggable/rateable', d4.success === true, d4);
                                    next();
                                }), user);
                        }), user);
                }), user);
        }), user);
});

// ---- GET routes ----
steps.push(function (next) {
    // v5.5.1 (audit 4): a LIVE scan is an action (it queries every device) - without the panel header it is 403,
    // the cached read stays a plain GET; the panel's get() sends the header
    obj.handleAdminReq({ query: { action: 'scan', mesh: 'mesh//grp1' } }, mockRes(function (d0) {
        check('audit4 S1: a live scan without the X-InvScanner-Request header is refused (403) - a foreign link cannot start a fleet pass', d0._status === 403, d0);
    obj.handleAdminReq({ query: { action: 'scan', mesh: 'mesh//grp1,mesh//grp2' }, headers: XHDR }, mockRes(function (d) {
        check('route scan: multi-mesh json contract', Array.isArray(d.cves) && Array.isArray(d.meshes) && typeof d.flaggedCount === 'number' && typeof d.lastUpdate === 'string', Object.keys(d || {}));
        obj.handleAdminReq({ query: { action: 'report' } }, mockRes(function (d2) {
            check('route report: renders report with locations', d2._view === 'report' && Array.isArray(d2._data.report.locations));
            obj.handleAdminReq({ query: { action: 'deviceReport' } }, mockRes(function (d3) {
                check('route deviceReport: renders deviceReport', d3._view === 'deviceReport');
                obj.handleAdminReq({ query: { action: 'show' } }, mockRes(function (d4) {
                    check('route show: renders assessment, deleted meshes hidden', d4._view === 'assessment' && d4._data.meshList.length === 2, d4._data.meshList);
                    obj.handleAdminReq({ query: { action: 'bogus' } }, mockRes(function (d5) {
                        check('route unknown GET action -> 404', d5._status === 404, d5);
                        // v4.3.2: the plugin list link (goPlugin) opens pluginadmin.ashx?pin=<name> without an action
                        obj.handleAdminReq({ query: { pin: 'inventoryscanner' } }, mockRes(function (d6) {
                            check('route without action (MeshCentral plugin list link) renders the panel, not 404', d6._view === 'assessment', d6._status || d6._view);
                            next();
                        }), user);
                    }), user);
                }), user);
            }), user);
        }), user);
    }), user);
    }), user);
});

steps.push(function (next) {
    obj.handleAdminReq({ query: { action: 'show' } }, mockRes(function (d) { check('non-admin GET -> 401', d._status === 401, d); }), { name: 'x', siteadmin: 0 });
    obj.handleAdminPostReq({ headers: XHDR, body: { action: 'save_assessment', meshId: 'mesh//grp1', cveId: 'CVE-2024-0001', assessment: 'LOW', comment: 'ok' } },
        mockRes(function (d) { check('non-admin POST -> 401', d._status === 401, d); next(); }), { name: 'x', siteadmin: 0 });
});

// ---- v4.4.0: CSV rows sorted column by column ----
steps.push(function (next) {
    check('csv sort: cell compare is empty-first, case-insensitive and NATURAL (Firefox 9 before Firefox 121)',
        obj.csvCellCompare('', 'a') < 0 && obj.csvCellCompare('b', '') > 0 && obj.csvCellCompare('chrome', 'Chrome') === 0 &&
        obj.csvCellCompare('Firefox 9', 'Firefox 121') < 0 && obj.csvCellCompare('Windows 10', 'Windows 11') < 0);
    check('csv sort: row compare decides left to right',
        obj.csvRowCompare(['A', 'z'], ['B', 'a']) < 0 && obj.csvRowCompare(['A', 'b'], ['A', 'c']) < 0 && obj.csvRowCompare(['A'], ['A', '']) === 0);
    obj.buildCsvForNodes(nodes.slice(), 'software', function (cerr, csv) {
        var lines = String(csv).split('\r\n').filter(function (l) { return l !== ''; });
        var cells = lines.slice(1).map(function (l) { return l.split(/,(?![^"]*"(?:(?:[^"]*"){2})*[^"]*$)/); });
        var pairs = cells.map(function (c) { return c[0].replace(/"/g, '') + '|' + c[1].replace(/"/g, '') + '|' + c[2].replace(/"/g, ''); });
        var sortedCopy = pairs.slice().sort();
        check('csv software export: sorted by Group, then Host Name, then Software name (was: database order)',
            !cerr && pairs.join('#') === sortedCopy.join('#'), pairs);
        check('csv software export: Branch really comes before HQ and its devices sort by host name (Given4Only before host3)',
            pairs[0].indexOf('Branch|Given4Only|') === 0 && pairs.indexOf('Branch|host3|Chrome') > 0 &&
            pairs.filter(function (p) { return p.indexOf('Branch|') === 0; }).length < pairs.length, pairs.slice(0, 4));
        check('csv software export: inside one device the programs are alphabetical (Chrome, Firefox, OEM Tool)',
            pairs.filter(function (p) { return p.indexOf('Branch|host3|') === 0; }).map(function (p) { return p.split('|')[2]; }).join(',') === 'Chrome,Firefox,OEM Tool',
            pairs.filter(function (p) { return p.indexOf('Branch|host3|') === 0; }));
        obj.buildCsvForNodes(nodes.slice(), 'hardware', function (herr, csv2) {
            var hl = String(csv2).split('\r\n').filter(function (l) { return l !== ''; }).slice(1);
            var hg = hl.map(function (l) { var c = l.split(','); return c[0].replace(/"/g, '') + '|' + c[1].replace(/"/g, ''); });
            var runs = 1;
            for (var i = 1; i < hg.length; i++) { if (hg[i] !== hg[i - 1]) { runs++; } }
            var distinct = Object.keys(hg.reduce(function (a, k) { a[k] = 1; return a; }, {})).length;
            check('csv hardware export: exactly one contiguous block per device (runs == distinct devices), blocks in group/host order',
                runs === distinct && hg[0].indexOf('Branch|') === 0, { rows: hg.length, runs: runs, distinct: distinct, first: hg[0] });
            next();
        });
    });
});

// ---- v4.4.0: opening the panel reads the snapshot; live scans are paced and coalesced ----
steps.push(function (next) {
    var scans = 0, saves = 0;
    var realMesh = obj.scanMeshCves, realSave = obj.saveScans;
    obj.assessments = { 'mesh//grp1:CVE-2024-0001': { meshId: 'mesh//grp1', cveId: 'CVE-2024-0001', assessment: 'LOW', comment: 'patched tuesday', lastModified: 'x', assessedBy: 'a', assessedById: 'b' } };
    obj.scanResults = { 'mesh//grp1': { time: '2026-01-01T00:00:00Z', cves: [
        { cve: 'CVE-2024-0001', severity: 'CRITICAL', cvss: 9.8, description: 'crit bug', software: 'Firefox', version: '1.0', devices: ['host1'], deviceList: [{ name: 'host1', software: 'Firefox', version: '1.0' }] },
        { cve: 'CVE-2024-0009', severity: 'LOW', cvss: 2.0, description: 'old', software: 'Chrome', version: '2.0', devices: ['host1'], deviceList: [{ name: 'host1', software: 'Chrome', version: '2.0' }] }
    ] } };
    obj.scanMeshCves = function (meshId, cb) { scans++; return realMesh(meshId, cb); };
    obj.saveScans = function () { saves++; };

    obj.handleAdminReq({ query: { action: 'scan', mesh: 'mesh//grp1', cached: '1' } }, mockRes(function (d0) {
        check('scan cached=1: answers from the snapshot WITHOUT touching a single device',
            scans === 0 && d0.cached === true && d0.cves.length === 2 && d0.cacheTime === '2026-01-01T00:00:00Z' && (d0.missing || []).length === 0, [scans, d0.cacheTime, (d0.cves || []).length]);
        check('scan cached=1: the CURRENT rating is applied to the stored findings (a rating saved after the scan still counts)',
            d0.cves[0].assessment && d0.cves[0].assessment.assessment === 'LOW' && d0.cves[0].severity === 'CRITICAL', d0.cves[0].assessment);
        obj.handleAdminReq({ query: { action: 'scan', mesh: 'mesh//grp1,mesh//grp2', cached: '1' } }, mockRes(function (d1) {
            check('scan cached=1: locations with no stored result are reported as missing, not silently empty',
                scans === 0 && (d1.missing || []).join() === 'mesh//grp2' && d1.cves.length === 2, [d1.missing, d1.cves.length]);
            // a real device pass is asynchronous; the mock would otherwise finish inside one turn
            obj.scanMeshCves = function (meshId, cb) { scans++; setTimeout(function () { realMesh(meshId, cb); }, 25); };
            var live = [];
            obj.handleAdminReq({ query: { action: 'scan', mesh: 'mesh//grp1' }, headers: XHDR }, mockRes(function (dA) { live.push(dA); }), user);
            obj.handleAdminReq({ query: { action: 'scan', mesh: 'mesh//grp1' }, headers: XHDR }, mockRes(function (dB) { live.push(dB); }), user);
            setTimeout(function () {
                check('live scan: ONE device pass answered BOTH panels that pressed the button (the second joined it)',
                    live.length === 2 && scans === 1 && obj.scanInFlight == null &&
                    live[0].cached === false && JSON.stringify(live[0].cves) === JSON.stringify(live[1].cves), [live.length, scans]);
                check('live scan: the result became the stored snapshot (the next page open reads it, no device work)',
                    obj.scanResults['mesh//grp1'] != null && obj.scanResults['mesh//grp1'].time > '2026-01-01' && saves >= 1, [saves, obj.scanResults['mesh//grp1']]);
                obj.scanMeshCves = realMesh; obj.saveScans = realSave; obj.scanResults = {}; obj.assessments = {};
                var ghost = { key: 'mesh//grp1', waiters: [], started: Date.now() - (obj.SCAN_JOIN_MAX_MS + 1000) };
                obj.scanInFlight = ghost;
                obj.handleAdminReq({ query: { action: 'scan', mesh: 'mesh//grp1', cached: '1' } }, mockRes(function (dg) {
                    check('scan: an abandoned live pass never locks the panel out - a run older than SCAN_JOIN_MAX_MS is not joined',
                        dg.scanning !== true && dg.cached === true, dg);
                    obj.scanInFlight = null;
                }), user);
                var hits = 0, yielded = false;
                setImmediate(function () { yielded = true; });
                var many = [];
                for (var q = 0; q < 200; q++) { many.push(q); }
                obj.pacedEach(many, function (item, done) { hits++; done(); }, function () {
                    check('pacedEach: every item ran exactly once, done came last AND the loop yielded to the event loop (that is the whole point)',
                        hits === 200 && yielded === true, [hits, yielded]);
                    var peak = 0, live2 = 0;
                    obj.pacedEach(many.slice(0, 40), function (item, done) { live2++; if (live2 > peak) { peak = live2; } setTimeout(function () { live2--; done(); }, 0); }, function () {
                        check('pacedEach: never more than SCAN_PARALLEL items in flight', peak > 0 && peak <= obj.SCAN_PARALLEL, [peak, obj.SCAN_PARALLEL]);
                        var emptyWorkerRan = false;
                        obj.pacedEach([], function () { emptyWorkerRan = true; }, function () {
                            check('pacedEach: an empty list runs no worker but still calls done', emptyWorkerRan === false);
                            next();
                        });
                    });
                });
            }, 60);
        }), user);
    }), user);
});

// ---- direct CSV download (main-menu exports) ----
steps.push(function (next) {
    obj.handleAdminReq({ query: { action: 'export', type: 'vulns' } }, mockRes(function (d) {
        check('export: CSV body with BOM + vulns columns', typeof d._body === 'string' && d._body.charCodeAt(0) === 0xFEFF && d._body.indexOf('Manual Rating') >= 0, typeof d._body);
        check('export: attachment filename', /attachment; filename="Vulnerabilities_\d{8}-\d{6}\.csv"/.test((d._headers || {})['Content-Disposition'] || ''), d._headers);
        obj.handleAdminReq({ query: { action: 'export', type: 'hardware' } }, mockRes(function (d2) {
            check('export hardware: header line', typeof d2._body === 'string' && d2._body.indexOf('Hardware Category') >= 0);
            obj.handleAdminReq({ query: { action: 'export', type: 'bogus' } }, mockRes(function (d3) {
                check('export: invalid type -> 400', d3._status === 400, d3);
                obj.handleAdminReq({ query: { action: 'export' } }, mockRes(function (d4) {
                    check('export: default type = vulns', typeof d4._body === 'string' && d4._body.length > 50);
                    next();
                }), user);
            }), user);
        }), user);
    }), user);
});

// ---- CPE table handlers ----
steps.push(function (next) {
    obj.customCpeEntries = [{ match: '^my tool', vendor: 'acme', product: 'tool' }];
    var savedRemote = obj.remoteCpeEntries, savedLoadedAt = obj.cpeTableLoadedAt;
    obj.applyCpeTableText({ entries: [{ match: '^mozilla firefox', vendor: 'mozilla', product: 'firefox' }, { match: '^sumatrapdf', vendor: 'sumatrapdfreader', product: 'sumatrapdf' }] });
    obj.handleAdminPostReq({ headers: XHDR, body: { action: 'get_cpe_table' } }, mockRes(function (d) {
        const remote = d.entries.filter(e => e.source === 'remote');
        check('get_cpe_table: maintained-table rows visible', remote.length === 2 && remote[0].vendor === 'mozilla', remote);
        check('get_cpe_table: custom rows visible', d.entries.some(e => e.source === 'custom' && e.match === '^my tool'));
        obj.handleAdminPostReq({ headers: XHDR, body: { action: 'delete_cpe_table', match: '^my tool', vendor: 'acme', product: 'tool' } },
            mockRes(function (d2) {
                check('delete_cpe_table removes custom entry', d2.success === true && obj.customCpeEntries.length === 0, d2);
                obj.handleAdminPostReq({ headers: XHDR, body: { action: 'delete_cpe_table', match: '^mozilla firefox', vendor: 'mozilla', product: 'firefox' } },
                    mockRes(function (d3) {
                        check('maintained-table rows cannot be deleted via the API (they live in cpe-table.json)', !!d3.error, d3);
                        obj.remoteCpeEntries = savedRemote; obj.cpeTableLoadedAt = savedLoadedAt;
                        next();
                    }), user);
            }), user);
    }), user);
});

// ---- vulns CSV ----
steps.push(function (next) {
    obj.windowsUpdates = { 'd1': { time: 'now', count: 3, updates: [] } };
    obj.assessments['mesh//grp1:WINDOWS-UPDATES'] = { meshId: 'mesh//grp1', cveId: 'WINDOWS-UPDATES', assessment: 'UNKNOWN', comment: '', flagged: true };
    obj.buildCsvForNodes([nodes[0]], 'vulns', function (err, csv) {
        check('csv: built', !err && csv.length > 0, err);
        check('csv: Comment directly after Manual Rating', /Manual Rating,Comment(,|$)/.test(csv.split('\r\n')[0]), csv.split('\r\n')[0]);
        check('csv: flagged WINDOWS-UPDATES shows false positive', csv.indexOf('false positive') >= 0);
        obj.windowsUpdates = {};
        var stubOld = obj.scanDeviceSoftware;
        obj.scanDeviceSoftware = function (list, cb) {
            cb([{ status: 'driver', outOfScope: true, isCve: false, cve: '', severity: '', cvss: '', description: 'drv', software: 'Realtek Audio Driver', version: '1.0', published: '', references: [] },
                { status: 'firmware', outOfScope: true, isCve: false, cve: '', severity: '', cvss: '', description: 'fw', software: 'ACME BIOS Update', version: '1.0', published: '', references: [] }]);
        };
        obj.buildCsvForNodes([nodes[0]], 'vulns', function (err2, csv2) {
            obj.scanDeviceSoftware = stubOld;
            check('csv: out-of-scope rows name the reason instead of saying not assessable',
                csv2.indexOf('drivers are not covered by CVE data') >= 0 && csv2.indexOf('firmware is not covered by CVE data') >= 0 && csv2.indexOf('not assessable') < 0,
                (csv2 || '').split('\r\n').slice(1, 4));
            next();
        });
    });
});

// ---- long timers ----
steps.push(function (next) {
    const MAX = 2147483647;
    const delays = [];
    let fakeNow = 0, pending = null, fired = false;
    obj.longTimeout(function () { fired = true; }, 3000000000,
        function (fn, d) { delays.push(d); pending = fn; }, function () { return fakeNow; });
    check('longTimeout: first chunk clamped to 32-bit max', delays[0] === MAX, delays);
    fakeNow += delays[0]; pending();
    check('longTimeout: remainder as second chunk', delays[1] === 3000000000 - MAX, delays);
    fakeNow += delays[1]; pending();
    check('longTimeout: fires exactly once after total elapsed', fired === true);
    const shorts = [];
    obj.longTimeout(function () { }, 5000, function (fn, d) { shorts.push(d); }, Date.now);
    check('longTimeout: short path = single setTimeout', shorts.length === 1 && shorts[0] === 5000, shorts);
    next();
});

steps.push(function (next) {
    meshServer.config.settings.vulnerabilityScanner = { scanIntervalHours: 720 };
    obj.lastScan = new Date(Date.now() - 10 * 24 * 3600 * 1000).toISOString();
    let captured = [];
    const realLong = obj.longTimeout;
    obj.longTimeout = function (cb, ms) { captured.push(ms); };
    obj.scheduleScans();
    check('scheduleScans: restart-proof residual delay (~20 days)', captured.length === 1 && Math.abs(captured[0] - 20 * 24 * 3600 * 1000) < 60000, captured);
    obj.lastScan = null; captured = [];
    obj.scheduleScans();
    check('scheduleScans: no prior scan -> baseline run ~1 min after start', captured.length === 1 && captured[0] === 60000, captured);
    obj.longTimeout = realLong;
    next();
});

// ---- scheduled scan notifications ----
steps.push(function (next) {
    obj.windowsUpdates = {};
    obj.assessments = { 'mesh//grp1:CVE-2024-0002': { assessment: 'LOW', comment: 'mitigated' } };
    obj.scanResults = {
        'mesh//grp1': { time: '2026-08-01T00:00:00Z', cves: [{ cve: 'CVE-2024-0001' }, { cve: 'CVE-2024-0002' }] },
        'mesh//grp2': { time: '2026-08-01T00:00:00Z', cves: [{ cve: 'CVE-2024-0001' }] }
    };
    const dispatched = [];
    meshServer.DispatchEvent = function (ids, src, evt) { dispatched.push(evt); };
    meshServer.config.settings.vulnerabilityScanner = { scanIntervalHours: 720, notifyOnScan: true, notifyThreshold: 'HIGH', notifyUnratedRepeat: true };
    obj.runScheduledScans();
    setTimeout(function () {
        const value = dispatched.length ? dispatched[0].value : '';
        check('notify: single dispatch with notify type', dispatched.length === 1 && dispatched[0].type === 'notify', dispatched.length);
        check('notify repeat mode: old unrated finding re-listed as open', value.indexOf('CVE-2024-0001 (CRITICAL, open)') >= 0, value);
        check('notify repeat mode: appeared finding marked new', value.indexOf('CVE-2024-0002 (HIGH, new)') >= 0, value);
        check('notify: rated finding never repeated', (value.match(/CVE-2024-0002/g) || []).length === 1, value);
        check('notify: below threshold excluded', value.indexOf('CVE-2024-0003') < 0, value);
        check('notify: lastScan updated', typeof obj.lastScan === 'string' && obj.lastScan.length > 20);
        obj.scanResults = {
            'mesh//grp1': { time: '2026-08-01T00:00:00Z', cves: [{ cve: 'CVE-2024-0001' }, { cve: 'CVE-2024-0002' }] },
            'mesh//grp2': { time: '2026-08-01T00:00:00Z', cves: [{ cve: 'CVE-2024-0001' }] }
        };
        dispatched.length = 0;
        meshServer.config.settings.vulnerabilityScanner.notifyUnratedRepeat = false;
        obj.runScheduledScans();
        setTimeout(function () {
            const value2 = dispatched.length ? dispatched[0].value : '';
            check('notify once mode: no open entries', dispatched.length === 1 && value2.indexOf('open') < 0 && value2.indexOf('CVE-2024-0002 (HIGH, new)') >= 0, value2);
            next();
        }, 50);
    }, 50);
});

// ---- NVD status derivation ----
steps.push(function (next) {
    const nvdData = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-nvd-'));
    obj.nvdDataPath = nvdData;
    obj.allCves = [];
    obj.loadNvdFromAllFiles();
    check('nvd status: no feed files -> lastUpdate=null ("not downloaded")', obj.lastUpdate === null, obj.lastUpdate);
    fs.writeFileSync(path.join(nvdData, 'nvdcve-2.0-' + obj.currentYear() + '.json'), JSON.stringify({ vulnerabilities: [] }));
    obj.loadNvdFromAllFiles();
    check('nvd status: feeds on disk -> real timestamp (restart-proof)', (typeof obj.lastUpdate === 'string') && !isNaN(Date.parse(obj.lastUpdate)), obj.lastUpdate);
    next();
});

// ---- loadScans restores lastScan ----
steps.push(function (next) {
    obj.scansPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-scans-')), 'scans.json');
    fs.writeFileSync(obj.scansPath, JSON.stringify({ 'mesh//grp1': { time: '2026-09-01T00:00:00Z', cves: [] }, 'mesh//grp2': { time: '2026-09-15T00:00:00Z', cves: [] } }));
    obj.lastScan = null;
    obj.loadScans();
    check('loadScans: restores lastScan from newest snapshot', obj.lastScan === '2026-09-15T00:00:00Z', obj.lastScan);
    next();
});


// ---- plugin settings (Settings tab) ----
steps.push(function (next) {
    // overlay priority: plugin settings file > config.json > built-in defaults
    meshServer.config.settings.vulnerabilityScanner = { scanIntervalHours: 24, notifyThreshold: 'MEDIUM' };
    obj.pluginSettings = { vulnerabilityScanner: { scanIntervalHours: 1 } };
    var sc = obj.scannerConfig();
    check('overlay: file beats config.json, untouched keys come from config.json', sc.intervalHours === 1 && sc.notifyThreshold === 'MEDIUM', [sc.intervalHours, sc.notifyThreshold]);
    obj.pluginSettings = {};
    sc = obj.scannerConfig();
    check('overlay: without file, config.json applies', sc.intervalHours === 24 && sc.notifyThreshold === 'MEDIUM', [sc.intervalHours, sc.notifyThreshold]);
    next();
});

steps.push(function (next) {
    obj.pluginSettingsPath = require('path').join(require('os').tmpdir(), 'invscanner-settest-' + Date.now(), 'scanner-settings.json');
    obj.timerGen = 0;
    obj.lastScan = new Date().toISOString();
    var captured = [];
    var realLong = obj.longTimeout, realRun = obj.runScheduledScans;
    obj.longTimeout = function (cb, ms) { captured.push(ms); };
    obj.handleAdminPostReq({ headers: XHDR, body: { action: 'save_settings', scanIntervalHours: '720', updateHours: '168', anyCveMaxAgeYears: '5',
            collectIntervalMinutes: '1440', notifyThreshold: 'HIGH', notifyOnScan: 'true', notifyUnratedRepeat: 'true',
            collectOnAgentConnect: 'true', scanMeshes: 'mesh//grp1', notifyMeshIds: 'mesh//grp2', notifySeverities: 'CRITICAL' } },
        mockRes(function (d) {
            check('save_settings: returns effective settings', d.settings && d.settings.scanIntervalHours === 720 && d.settings.notify['mesh//grp2'] === 'CRITICAL' && d.settings.notifyUnratedRepeat === true, d.settings);
            check('save_settings: persisted to file', fs.existsSync(obj.pluginSettingsPath));
            check('save_settings: bumped timer generation + rescheduled', obj.timerGen === 1 && captured.length >= 1, [obj.timerGen, captured.length]);
            obj.handleAdminPostReq({ headers: XHDR, body: { action: 'get_settings' } }, mockRes(function (dg) {
                check('get_settings: source marking file vs config.json', dg.sources.scanIntervalHours === 'file' && dg.sources.notifyThreshold === 'file' && dg.sources.scanMeshes === 'file', dg.sources);
                obj.handleAdminPostReq({ headers: XHDR, body: { action: 'revert_setting', revertScanIntervalHours: 'true' } }, mockRes(function (d2) {
                    check('revert_setting: falls back to config.json value', d2.settings.scanIntervalHours === 24 && d2.sources.scanIntervalHours === 'config.json', d2.settings && d2.settings.scanIntervalHours);
                    obj.handleAdminPostReq({ headers: XHDR, body: { action: 'save_settings', scanIntervalHours: 'abc' } }, mockRes(function (d3) {
                        check('save_settings: rejects non-numeric interval', !!d3.error, d3);
                        obj.handleAdminPostReq({ headers: XHDR, body: { action: 'save_settings', scanIntervalHours: '24', updateHours: '168', anyCveMaxAgeYears: '5', collectIntervalMinutes: '60', notifyThreshold: 'NOPE' } },
                            mockRes(function (d4) { check('save_settings: rejects invalid severity', !!d4.error, d4); next(); }), user);
                    }), user);
                }), user);
            }), user);
        }), user);

    obj.longTimeout = realLong; obj.runScheduledScans = realRun;
    // (all mock callbacks are synchronous, so the restores above run after the nested asserts)
});

steps.push(function (next) {
    // stale timer chains must not act after a settings save bumped the generation
    obj.pluginSettings = { vulnerabilityScanner: { scanIntervalHours: 2 } };
    meshServer.config.settings.vulnerabilityScanner = { scanIntervalHours: 2 };
    obj.lastScan = new Date().toISOString();
    var scheduled = null, runs = 0;
    var realLong = obj.longTimeout, realRun = obj.runScheduledScans;
    obj.longTimeout = function (cb, ms) { scheduled = cb; };
    obj.runScheduledScans = function () { runs++; };
    obj.scheduleScans();
    obj.timerGen++;                     // simulate a settings save between scheduling and firing
    if (scheduled) scheduled();
    check('timers: stale chain discarded after generation bump', runs === 0, runs);
    scheduled = null;
    obj.scheduleScans();
    if (scheduled) scheduled();
    check('timers: current chain runs', runs === 1, runs);
    obj.longTimeout = realLong; obj.runScheduledScans = realRun;
    next();
});

steps.push(function (next) {
    // collector re-reads its interval every cycle (effective settings)
    obj.pluginSettings = { inventoryScanner: { collectIntervalMinutes: 7, collectOnAgentConnect: true } };
    var cycles = [];
    var realLong = obj.longTimeout, realCollect = obj.collectAllOnline;
    obj.collectAllOnline = function () { };
    obj.longTimeout = function (cb, ms) { cycles.push(ms); };
    obj.collectAndReschedule();
    check('collector: per-cycle effective interval (7 min)', cycles.length === 1 && cycles[0] === 7 * 60 * 1000, cycles);
    obj.pluginSettings = { inventoryScanner: { collectIntervalMinutes: 0 } };
    cycles = [];
    obj.collectAndReschedule();
    check('collector: interval 0 stops the chain', cycles.length === 0, cycles);
    obj.longTimeout = realLong; obj.collectAllOnline = realCollect;
    obj.pluginSettings = {};
    next();
});

// ---- uiCustomEvent: panel button without device selection ----
steps.push(function (next) {
    var sent = [];
    var fakeParent = { send: function (m) { sent.push(m); }, user: user };
    obj.uiCustomEvent({ section: "devicesbarbuttons", element: "0", logmsg: "assessment", selectedDevices: [] }, fakeParent);
    check("uievent: assessment button with NO selection opens the panel", sent.length === 1 && sent[0].method === "openAssessment", sent);
    sent = [];
    obj.uiCustomEvent({ section: "devicesbarbuttons", element: "0", logmsg: "vulns", selectedDevices: [] }, fakeParent);
    check("uievent: CSV export still needs a selection", sent.length === 0, sent);
    next();
});

// ---- exported browser functions are namespace-serialized: no server-scope refs ----
steps.push(function (next) {
    check('exports list matches function definitions', Array.isArray(obj.exports) && obj.exports.length === 3, obj.exports);
    var bad = obj.exports.filter(function (name) { return typeof obj[name] === 'function' && /\bobj\./.test(obj[name].toString()); });
    check('browser exports reference no server obj.*', bad.length === 0, bad);
    next();
});

// ---- v3.5.1 module architecture (entry = wiring only, functionality in lib/) ----
steps.push(function (next) {
    var libDir = path.join(PLUGIN_DIR, 'lib');
    var files = fs.readdirSync(libDir).filter(function (f) { return f.endsWith('.js'); }).sort();
    check('modules: lib/ holds the feature modules', files.length >= 15, files.length);
    check('modules: every lib file exports attach(obj)', files.every(function (f) { return typeof require(path.join(libDir, f)).attach === 'function'; }));
    var entrySrc = fs.readFileSync(path.join(PLUGIN_DIR, 'inventoryscanner.js'), 'utf8');
    check('modules: the entry file stays thin (wiring only)', entrySrc.split('\n').length < 300, entrySrc.split('\n').length);
    check('modules: the entry attaches every lib file by name', files.every(function (f) { return entrySrc.indexOf("'" + f.slice(0, -3) + "'") >= 0; }), files);
    // Module-level state = a declaration at COLUMN 0 outside attach (shared by every instance and
    // surviving a hot reload). Only `const x = require(...)` is allowed there (audit 3: the old
    // check looked at 4-space-indented locals inside attach, which are per call and harmless).
    var modState = files.filter(function (f) {
        return fs.readFileSync(path.join(libDir, f), 'utf8').split(/\r?\n/).some(function (l) { return /^(var|let|const) /.test(l) && !/^const [A-Za-z_$][\w$]* = require\('[^']+'\);\s*$/.test(l); });
    });
    check('modules: no lib file declares module-level state outside attach (only top-level requires)', modState.length === 0, modState);
    check('modules: the attach bodies hold no local declarations (state lives on obj)',
        files.every(function (f) { return !/^    (var|let|const) /m.test(fs.readFileSync(path.join(libDir, f), 'utf8')); }), files);
    var savedGen = global.__inventoryscannerInstanceGen;
    var fresh = factory({ parent: { db: db, datapath: fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-mod-')), debug: function () { }, config: { settings: {} }, webserver: {} } });
    var missing = Object.keys(obj).filter(function (k) { return typeof obj[k] === 'function' && typeof fresh[k] !== 'function'; });
    global.__inventoryscannerInstanceGen = savedGen;   // the throwaway instance must not supersede the test instance
    check('modules: a freshly built instance exposes the same function surface', missing.length === 0, missing);
    check('modules: all MeshCentral entry points are attached',
        ['server_startup', 'uiCustomEvent', 'hook_agentCoreIsStable', 'handleAdminReq', 'handleAdminPostReq'].every(function (k) { return typeof obj[k] === 'function'; }));
    next();
});

// ---- onWebUIStartupEnd injects the toolbar buttons into devsCustomUIBar (simulated browser DOM) ----
steps.push(function (next) {
    var sent = [], alerts = [], appended = [], boxes = null, bar = { innerHTML: '', appendChild: function (el) { appended.push(el); } };
    boxes = [{ checked: true, defaultValue: 'devid_node-AAA' }, { checked: false, defaultValue: 'devid_node-BBB' }];
    global.document = {
        getElementById: function (id) { return (id === 'devsCustomUIBar') ? bar : null; },
        getElementsByClassName: function (cls) { return (cls === 'DeviceCheckbox' && bar != null) ? boxes : []; },
        createElement: function (tag) { return { type: '', value: '', title: '', style: {}, onclick: null }; }
    };
    global.meshserver = { send: function (m) { sent.push(m); } };
    global.alert = function (m) { alerts.push(m); };
    obj.onWebUIStartupEnd();
    check('toolbar: three buttons injected into empty slot', appended.length === 3, appended.length);
    check('toolbar: button labels', appended.map(function (x) { return x.value; }).join(',') === 'Hardware Inventory,Software Inventory,Vulnerability Assessment', appended.map(function (x) { return x.value; }));
    appended[0].onclick();
    check('toolbar: hardware click sends checked ids', sent.length === 1 && sent[0].action === 'uicustomevent' && sent[0].section === 'devicesbarbuttons' && sent[0].logmsg === 'hardware' && sent[0].selectedDevices.length === 1 && sent[0].selectedDevices[0] === 'node-AAA', sent[0]);
    boxes[0].checked = false; sent.length = 0;
    appended[1].onclick();
    check('toolbar: csv click without selection warns, sends nothing', sent.length === 0 && alerts.length === 1, alerts);
    sent.length = 0;
    appended[2].onclick();
    check('toolbar: assessment click sends empty selection', sent.length === 1 && sent[0].logmsg === 'assessment' && sent[0].selectedDevices.length === 0, sent[0]);
    appended.length = 0; bar.innerHTML = '<input type=button>';
    obj.onWebUIStartupEnd();
    check('toolbar: no injection when slot filled', appended.length === 0, appended.length);
    bar = null; var threw = false;
    try { obj.onWebUIStartupEnd(); } catch (ex) { threw = true; }
    check('toolbar: missing slot is silent no-op', threw === false);
    delete global.document; delete global.meshserver; delete global.alert;
    next();
});

// ---- automatic product-token matching (offline evidence matcher) ----
steps.push(function (next) {
    var savedTokens = obj.cpeProductTokens, savedIndex = obj.productIndexByProduct, savedSettings = obj.pluginSettings;
    obj.cpeProductTokens = { chrome: 1, firefox: 1, vlc_media_player: 1, temurin: 1, client: 1 };
    obj.productIndexByProduct = {
        chrome: [{ vendor: 'google', defs: [] }],
        firefox: [{ vendor: 'mozilla', defs: [] }],
        vlc_media_player: [{ vendor: 'videolan', defs: [] }],
        temurin: [{ vendor: 'eclipse', defs: [] }],
        client: [{ vendor: 'vendor_a', defs: [] }, { vendor: 'vendor_b', defs: [] }]
    };
    var r3 = obj.deriveCpeProduct('Eclipse Adoptium', 'Eclipse Temurin 21 LTS (x64)');
    check('auto: vendor evidence + noise+version strip', r3 && r3.product === 'temurin' && r3.vendor === 'eclipse' && r3.viaAuto === true, r3);
    var r5 = obj.deriveCpeProduct('Mozilla Corporation', 'Firefox 121.0 (x86 de-DE)');
    check('auto: version-stripped token + vendor', r5 && r5.product === 'firefox' && r5.vendor === 'mozilla' && r5.viaAuto === true, r5);
    var r2 = obj.deriveCpeProduct('VideoLAN', 'VLC media player 3.0.20');
    check('auto: curated table wins before matching', r2 && r2.product === 'vlc_media_player' && r2.viaCurated === true, r2);
    var r4 = obj.deriveCpeProduct('Some OEM Inc', 'Client');
    check('auto: generic token rejected', r4 === null, r4);
    obj.pluginSettings = { vulnerabilityScanner: { autoProductMatch: false } };
    var r6 = obj.deriveCpeProduct('Eclipse Adoptium', 'Eclipse Temurin 21 LTS (x64)');
    check('auto: setting off disables matching', r6 === null, r6);
    obj.pluginSettings = { vulnerabilityScanner: {} };
    var r6b = obj.deriveCpeProduct('Eclipse Adoptium', 'Eclipse Temurin 21 LTS (x64)');
    check('auto: default when setting absent is on', r6b && r6b.viaAuto === true, r6b);
    var r8 = obj.cpeTokenize('Notepad++ (x64) 8.6.2');
    check('auto: tokenize keeps + and collapses noise', r8 === 'notepad++_8.6.2', r8);
    var r9 = obj.deriveVendorFromPublisher('Adobe Inc.');
    check('auto: publisher keyword map', r9 === 'adobe', r9);
    var r10 = obj.deriveVendorFromPublisher('Adobery Labs');
    check('auto: publisher word-boundary only', r10 === '', r10);
    obj.cpeProductTokens = savedTokens; obj.productIndexByProduct = savedIndex; obj.pluginSettings = savedSettings;
    next();
});
// ---- remotely maintained CPE table (apply/cache/fetch/settings) ----
steps.push(function (next) {
    var savedRemote = obj.remoteCpeEntries, savedLoadedAt = obj.cpeTableLoadedAt, savedSettings = obj.pluginSettings, savedPath = obj.cpeTablePath, savedOrigin = obj.cpeTableOrigin;
    var res1 = obj.applyCpeTableText(JSON.stringify({ entries: [
        { match: '^ZebraTool', vendor: 'Zebra', product: 'ZTool' },
        { match: '(((bad', vendor: 'x', product: 'y' },
        { match: '^ok2', vendor: 'v2', product: 'p2' } ] }));
    check('cpeTable: apply valid entries, skip broken regex', res1.ok === true && res1.applied === 2 && res1.skipped === 1, res1);
    var rz = obj.deriveCpeProduct('', 'ZebraTool 2.1');
    check('cpeTable: remote row resolves name', rz && rz.vendor === 'zebra' && rz.product === 'ztool', rz);
    check('cpeTable: status shows remote', obj.cpeTableStatus().source === 'remote' && obj.cpeTableStatus().entries === 2, obj.cpeTableStatus());
    check('cpeTable: non-JSON rejected', obj.applyCpeTableText('not json').ok === false);
    check('cpeTable: missing entries array rejected', obj.applyCpeTableText('{"foo":1}').ok === false);
    var cacheFilePath = require('path').join(require('os').tmpdir(), 'invscanner-cpetable-' + Date.now(), 'cpe-table.json');
    obj.cpeTablePath = cacheFilePath;
    require('fs').mkdirSync(require('path').dirname(obj.cpeTablePath), { recursive: true });
    require('fs').writeFileSync(obj.cpeTablePath, JSON.stringify({ entries: [{ match: '^CacheApp', vendor: 'cv', product: 'cp' }] }));
    obj.remoteCpeEntries = null; obj.loadRemoteCpeTable();
    check('cpeTable: loads cached file at startup', obj.cpeTableStatus().source === 'remote' && obj.cpeTableStatus().origin === 'cache' && !!obj.deriveCpeProduct('', 'CacheApp 1'), obj.cpeTableStatus());
    obj.cpeTablePath = require('path').join(require('os').tmpdir(), 'invscanner-cpetable-none-' + Date.now(), 'cpe-table.json');
    obj.remoteCpeEntries = null; obj.loadRemoteCpeTable();
    check('cpeTable: no cache file at the datapath -> the copy beside the code is live (installed servers already have it at the cache path, so no mirroring is ever needed)',
        obj.cpeTableStatus().source === 'remote' && obj.cpeTableStatus().origin === 'bundled' && obj.cpeTableStatus().entries > 40, obj.cpeTableStatus());
    obj.cpeTablePath = cacheFilePath;
    var httpCalls = 0, savedHttp = obj.cpeTableHttpGet;
    obj.cpeTableHttpGet = function (url, cb) { httpCalls++; cb(null, JSON.stringify({ entries: [{ match: '^FetchApp', vendor: 'fv', product: 'fp' }] })); };
    obj.remoteCpeEntries = null; obj.cpeTableLoadedAt = null; obj.pluginSettings = {};
    obj.maybeFetchCpeTable(function () { });
    check('cpeTable: maybeFetch fetches when stale and enabled', httpCalls === 1 && !!obj.deriveCpeProduct('', 'FetchApp') && obj.cpeTableStatus().origin === 'downloaded', [httpCalls, obj.cpeTableStatus().origin]);
    httpCalls = 0; obj.pluginSettings = { vulnerabilityScanner: { cpeTableEnabled: false } };
    obj.maybeFetchCpeTable(function () { });
    check('cpeTable: disabled means no HTTP at all', httpCalls === 0, httpCalls);
    httpCalls = 0; obj.pluginSettings = {}; obj.cpeTableLoadedAt = new Date().toISOString();
    obj.maybeFetchCpeTable(function () { });
    check('cpeTable: fresh cache skips fetch', httpCalls === 0, httpCalls);
    obj.handleAdminPostReq({ headers: XHDR, body: { action: 'save_settings', scanIntervalHours: '24', updateHours: '168', anyCveMaxAgeYears: '5', collectIntervalMinutes: '1440', notifyThreshold: 'HIGH', notifyOnScan: 'true', notifyUnratedRepeat: 'false', autoProductMatch: 'true', collectOnAgentConnect: 'true', cpeTableEnabled: 'true', cpeTableUrl: 'http://insecure.example/x' } },
        mockRes(function (d) { check('cpeTable settings: http URL rejected', d.error && /URL/.test(d.error), d); }), user);
    obj.handleAdminPostReq({ headers: XHDR, body: { action: 'save_settings', scanIntervalHours: '24', updateHours: '168', anyCveMaxAgeYears: '5', collectIntervalMinutes: '1440', notifyThreshold: 'HIGH', notifyOnScan: 'true', notifyUnratedRepeat: 'false', autoProductMatch: 'true', collectOnAgentConnect: 'true', cpeTableEnabled: 'false', cpeTableUrl: 'https://example.org/cpe-table.json', scanMeshes: '', notifyMeshIds: '', notifySeverities: '' } },
        mockRes(function (d) {
            check('cpeTable settings: save roundtrip', d.settings && d.settings.cpeTableEnabled === false && d.settings.cpeTableUrl === 'https://example.org/cpe-table.json', d.settings);
            check('cpeTable settings: sources marked file', d.sources && d.sources.cpeTableUrl === 'file' && d.sources.revertAllowed.cpeTableUrl === true, d.sources);
        }), user);
    obj.cpeTableHttpGet = savedHttp; obj.cpeTablePath = savedPath; obj.remoteCpeEntries = savedRemote; obj.cpeTableLoadedAt = savedLoadedAt; obj.pluginSettings = savedSettings; obj.cpeTableOrigin = savedOrigin;
    next();
});

// ---- NVD download log tailer ----
steps.push(function (next) {
    var savedNvd = obj.nvdDataPath;
    obj.nvdDataPath = require('path').join(require('os').tmpdir(), 'invscanner-nvdlog-' + Date.now());
    obj.handleAdminPostReq({ headers: XHDR, body: { action: 'get_nvdlog' } }, mockRes(function (d) {
        check('nvdlog: missing file -> note, no lines', Array.isArray(d.lines) && d.lines.length === 0 && !!d.note, d);
        require('fs').mkdirSync(obj.nvdDataPath, { recursive: true });
        var text = '';
        for (var i = 0; i < 500; i++) { text += 'line ' + i + String.fromCharCode(10); }
        require('fs').writeFileSync(require('path').join(obj.nvdDataPath, 'nvd-download.log'), text);
        obj.handleAdminPostReq({ headers: XHDR, body: { action: 'get_nvdlog' } }, mockRes(function (d2) {
            check('nvdlog: tails last 200 lines', d2.lines.length === 200 && d2.lines[199] === 'line 499', d2.lines && [d2.lines.length, d2.lines[199]]);
        }), user);
    }), user);
    obj.nvdDataPath = savedNvd;
    next();
});

// ---- manual NVD update trigger (concurrency-guarded) ----
steps.push(function (next) {
    var savedDl = obj.downloadNvdDatabase, savedRun = obj.nvdUpdateRunning;
    var dlCalls = 0, pendingCb = null;
    obj.downloadNvdDatabase = function (force, cb) { dlCalls++; pendingCb = cb; };
    obj.nvdUpdateRunning = false;
    obj.handleAdminPostReq({ headers: XHDR, body: { action: 'update_nvd' } }, mockRes(function (d) {
        check('update_nvd: starts a run', d.started === true && dlCalls === 1 && obj.nvdUpdateRunning === true, d);
        obj.handleAdminPostReq({ headers: XHDR, body: { action: 'update_nvd' } }, mockRes(function (d2) {
            check('update_nvd: second click reports alreadyRunning', d2.started === false && d2.alreadyRunning === true && dlCalls === 1, d2);
            var skipResult = null;
            obj.runNvdUpdate(true, function (err, r) { skipResult = r; });
            check('runNvdUpdate: concurrent call is skipped', skipResult === 'skipped', skipResult);
            pendingCb(null);
            check('runNvdUpdate: flag clears after finish', obj.nvdUpdateRunning === false);
            obj.handleAdminPostReq({ headers: XHDR, body: { action: 'update_nvd' } }, mockRes(function (d3) {
                check('update_nvd: works again after completion', d3.started === true && dlCalls === 2, d3);
                pendingCb(null);
            }), user);
        }), user);
    }), user);
    obj.downloadNvdDatabase = savedDl; obj.nvdUpdateRunning = savedRun;
    next();
});

// ---- unknown installed version must never assert version-bounded CVEs ----
steps.push(function (next) {
    check('defMatch: unknown version rejects bounded range', obj.defMatches({ part: 'a', kind: 'range', endExc: '3.6.13' }, '') === false);
    check('defMatch: unknown version rejects exact defs', obj.defMatches({ part: 'a', kind: 'exact', version: '3.6' }, '') === false);
    check('defMatch: unknown version keeps all-version defs', obj.defMatches({ part: 'a', kind: 'any' }, '') === true);
    var dp2 = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-verless-'));
    var obj2 = factory({ parent: { db: db, datapath: dp2, debug: function () { }, config: { settings: {} }, webserver: { meshes: {} } } });
    obj2.loadRemoteCpeTable(); // same as the main instance: the curated table comes ONLY from cpe-table.json (v4.2.0)
    obj2.productIndex['mozilla|firefox'] = [
        { part: 'a', kind: 'range', endExc: '3.6.13', cves: [{ id: 'CVE-2008-1111', severity: 'HIGH', cvss: 7, description: 'old flood', published: '2008-06-01T00:00:00', references: [] }] },
        { part: 'a', kind: 'range', startInc: '1.0', endExc: '3.6.28', cves: [{ id: 'CVE-2011-2222', severity: 'CRITICAL', cvss: 9.5, description: 'ancient', published: '2011-03-01T00:00:00', references: [] }] }
    ];
    obj2.scanDeviceSoftware([{ name: 'Mozilla Firefox', publisher: 'Mozilla Corporation', version: '' }], function (res2) {
        check('scan: versionless software asserts no bounded CVEs', res2.filter(function (x) { return x.isCve; }).length === 0, res2.map(function (x) { return x.cve; }));
        var row2 = res2.filter(function (x) { return /^no CVE/.test(x.status || ''); })[0];
        check('scan: versionless row explains the unknown version', !!row2 && /version is unknown/.test(row2.description), row2 && row2.description);
        obj2.scanDeviceSoftware([{ name: 'Mozilla Firefox', publisher: 'Mozilla Corporation', version: '121.0.1' }], function (res3) {
            check('scan: current version still not matched by history', res3.filter(function (x) { return x.isCve; }).length === 0, res3.map(function (x) { return x.cve; }));
            var row3 = res3.filter(function (x) { return /^no CVE/.test(x.status || ''); })[0];
            check('scan: known version omits the unknown-version note', !!row3 && !/version is unknown/.test(row3.description), row3 && row3.description);
            next();
        });
    });
});

// ---- v2.1.0: superseded pruning, two-stage due policy, dry-run, queue gate ----
steps.push(function (next) {
    var l1 = [{ name: 'Mozilla Firefox 3.6.24 (x86 de-DE)', version: '3.6.24', publisher: 'Mozilla' }, { name: 'Firefox 121.0.1 (x86 de-DE)', version: '121.0.1', publisher: 'Mozilla' }];
    var p1 = obj.pruneSuperseded(l1);
    check('prune: stale firefox row dropped', p1.length === 1 && String(p1[0].name).indexOf('121') > 0, p1);
    var p2 = obj.pruneSuperseded([{ name: 'Java 8 Update 202 (64-bit)', version: '8.202.1', publisher: 'Oracle' }, { name: 'Java 8 Update 351 (64-bit)', version: '8.351.0', publisher: 'Oracle' }, { name: 'Java SE Development Kit 17.0.2', version: '17.0.2.8', publisher: 'Oracle' }]);
    check('prune: same-major java dedup, other major kept', p2.length === 2, p2);
    var p3 = obj.pruneSuperseded([{ name: 'Python 3.11.9 (64-bit)', version: '3.11.9', publisher: 'Python Software Foundation' }, { name: 'Python 3.12.4 (64-bit)', version: '3.12.4', publisher: 'Python Software Foundation' }]);
    check('prune: python minors coexist', p3.length === 2, p3);
    var p4 = obj.pruneSuperseded([{ name: 'Acme Tool', version: '', publisher: 'Acme' }, { name: 'Acme Tool', version: '2.0', publisher: 'Acme' }]);
    check('prune: unversioned row is never superseded', p4.length === 2, p4);
    // Pinned to local noon: with Date.now() the "2h ago today" fixture silently fell onto
    // YESTERDAY when the suite ran between 00:00 and 02:00 local time (found during v4.0.0).
    var now = (function () { var nd = new Date(); nd.setHours(12, 0, 0, 0); return nd.getTime(); })();
    var iso = function (msAgo) { return new Date(now - msAgo).toISOString(); };
    check('due: never ran', obj.wgNodeDue('node//x', {}, now) === true);
    check('due: ran 2h ago today', obj.wgNodeDue('node//x', { 'node//x': { time: iso(2 * 3600 * 1000) } }, now) === false);
    check('due: ran yesterday', obj.wgNodeDue('node//x', { 'node//x': { time: iso(25 * 3600 * 1000) } }, now) === true);
    var sd = obj.wgBuildScript({ ignorePackages: [{ id: 'Foo.Bar' }], pinSync: true }, true);
    check('dry: script sets dry flag and reports dry-run state', sd.indexOf('$invDry = $true') >= 0 && sd.indexOf("state = 'dry-run'") >= 0);
    check('dry: pin block absent', sd.indexOf('winget pin add') < 0);
    var sr = obj.wgBuildScript({ ignorePackages: [{ id: 'Foo.Bar' }], pinSync: true }, false);
    check('real: not dry, pins present', sr.indexOf('$invDry = $false') >= 0 && sr.indexOf('pin add') >= 0);
    obj.pluginSettings = { wingetUpdater: { enabled: false } };
    check('queue: disabled switch blocks every auto path', obj.wgQueueNode('node//d1', 'connect') === false);
    check('sweep: disabled is a clean no-op', (function () { var hit = false; obj.wgSweepOnce(function () { hit = true; }); return hit; })() === true);
    obj.pluginSettings = {};
    next();
});



// ---- v2.1.1: Debian epoch / snap wrapper versions ----
steps.push(function (next) {
    check('normver: epoch + core extract, distro patch levels unknown', obj.normalizeCveVersion('1:2.3.4-1') === '2.3.4' && obj.normalizeCveVersion('22.04.0-1build2') === '22.04.0' && obj.normalizeCveVersion('2.7.7ubuntu5.3') === '' && obj.normalizeCveVersion('10.02.1~dfsg1-0ubuntu7.10') === '', [obj.normalizeCveVersion('1:2.3.4-1'), obj.normalizeCveVersion('2.7.7ubuntu5.3')]);
    check('normver: snap wrapper is unknown', obj.normalizeCveVersion('1:1snap1-0ubuntu5') === '', obj.normalizeCveVersion('1:1snap1-0ubuntu5'));
    check('normver: plain numbers untouched', obj.normalizeCveVersion('17') === '17' && obj.normalizeCveVersion('8u202') === '8', [obj.normalizeCveVersion('17'), obj.normalizeCveVersion('8u202')]);
    var bounded = { kind: 'range', startInc: null, startExc: null, endInc: null, endExc: '2.0.0.20' };
    check('defMatch: snap wrapper hits no historical range', obj.defMatches(bounded, '1:1snap1-0ubuntu5') === false);
    check('defMatch: any-def still matches (age filter applies)', obj.defMatches({ kind: 'any' }, '1:1snap1-0ubuntu5') === true);
    check('defMatch: real core compares', obj.defMatches({ kind: 'range', endInc: '22.04.5', startInc: '22.04' }, '1:22.04.0-1') === true && obj.defMatches({ kind: 'range', endExc: '22.04.0' }, '1:22.04.0-1') === false);
    next();
});


// ---- v2.1.2: status handler robustness ----
steps.push(function (next) {
    nodes.push({ _id: 'node//amt1', meshid: 'mesh//grp1', rname: 'amt-host', type: 2 });
    obj.wgResults['node//d2'] = { time: 'garbage-without-results' };
    obj.handleAdminPostReq({ headers: XHDR, body: { action: 'wg_status' } }, mockRes(function (d) {
        check('status: legacy type field no longer filters', (d.devices || []).filter(function (x) { return x.id === 'node//amt1'; }).length === 1, (d.devices || []).length);
        check('status: malformed result record does not crash', (d.devices || []).filter(function (x) { return x.id === 'node//d2'; }).length === 1, d.error);
        nodes.pop();
        delete obj.wgResults['node//d2'];
        next();
    }), user);
});


// ---- v2.1.3: non-Windows nodes hidden from the updater ----
steps.push(function (next) {
    nodes.push({ _id: 'node//iphone1', meshid: 'mesh//grp1', rname: 'iph1', name: 'Phone1', osdesc: 'iOS 17.5' });
    nodes.push({ _id: 'node//deb12', meshid: 'mesh//grp1', rname: 'debby', name: 'DebServer', osdesc: 'Debian GNU/Linux 12' });
    nodes.push({ _id: 'node//newbi', meshid: 'mesh//grp1', rname: 'fresh', name: 'FreshBox' });
    obj.handleAdminPostReq({ headers: XHDR, body: { action: 'wg_status' } }, mockRes(function (d) {
        var ids = (d.devices || []).map(function (x) { return x.id; });
        check('status: iPhone and Linux hidden, unknown-OS kept', ids.indexOf('node//iphone1') < 0 && ids.indexOf('node//deb12') < 0 && ids.indexOf('node//newbi') >= 0, ids);
        nodes.splice(nodes.length - 3, 3);
        next();
    }), user);
});


// ---- v2.1.4: dry watchdog, agent-console diagnostics, pending visibility ----
steps.push(function (next) {
    check('timeout: dry runs use the fast watchdog', obj.WINGET_DRY_TIMEOUT_MS === 10 * 60 * 1000 &&
        /wgBatchDry === true \? obj\.WINGET_DRY_TIMEOUT_MS/.test(pluginSrc()));
    obj.wgBatchDry = true;
    obj.wgPending['node//dryt'] = { nodeid: 'node//dryt', sid: 'invscanner-wg-node_dryt', since: Date.now() - 11 * 60 * 1000 };
    obj.wgTimeout(obj.wgPending['node//dryt']);
    check('timeout: fired record marked and logged', obj.wgResults['node//dryt'].error === 'timeout' && fs.readFileSync(obj.wingetLogPath, 'utf8').indexOf('no answer') >= 0, obj.wgResults['node//dryt']);
    delete obj.wgResults['node//dryt'];
    obj.wgActive = 0;
    obj.wgBatchDry = false;
    obj.onAgentResponse({ action: 'msg', type: 'console', sessionid: 'invscanner-wg-node_x', value: "Run commands can't execute, already busy." }, '', 'node//x');
    check('console: agent messages on wg sessions reach the log', fs.readFileSync(obj.wingetLogPath, 'utf8').indexOf('agent console: Run commands') >= 0);
    obj.wgPending['node//d1'] = { nodeid: 'node//d1', sid: 'invscanner-wg-node_d1', since: Date.now() };
    obj.handleAdminPostReq({ headers: XHDR, body: { action: 'wg_status' } }, mockRes(function (d) {
        var dd = d.devices.filter(function (x) { return x.id === 'node//d1'; })[0];
        check('status: running device exposes pending.since', dd.pending != null && dd.pending.since > 0, dd.pending);
        delete obj.wgPending['node//d1'];
        next();
    }), user);
});


// ---- v2.1.5: client transcript ----
steps.push(function (next) {
    var sc = obj.wgBuildScript({ ignorePackages: [{ id: 'Foo.Bar' }], pinSync: false }, true);
    check('transcript: script writes and closes a client log', sc.indexOf('Start-Transcript') >= 0 && sc.indexOf('Stop-Transcript') >= 0);
    check('transcript: answer is emitted BEFORE the transcript stops', markerBeforeStop(sc, obj.WINGET_MARKER), sc.indexOf(obj.WINGET_MARKER) + ':' + sc.indexOf('Stop-Transcript'));
    check('transcript: rotation guard present', sc.indexOf('-gt 5MB') >= 0);
    check('transcript: agent folder probe + protected ProgramData\\InventoryScanner fallback', sc.indexOf('Get-CimInstance Win32_Process') >= 0 && sc.indexOf("Join-Path $env:ProgramData 'InventoryScanner'") >= 0 && sc.indexOf('SetAccessRuleProtection($true, $false)') >= 0 && sc.indexOf("'S-1-5-18', 'S-1-5-32-544'") >= 0, sc.length);
    next();
});


// ---- v2.1.7: agent-build tolerant routing + transcript write probe ----
steps.push(function (next) {
    var sc = obj.wgBuildScript({ ignorePackages: [], pinSync: false }, true);
    check('transcript: Split-Path + Out-File probe', sc.indexOf('Split-Path $invPX') >= 0 && sc.indexOf('Out-File') >= 0);
    check('transcript: no user-writable fallback (no plain ProgramData file, no TEMP), reparse points refused', sc.indexOf('$env:TEMP') < 0 && sc.indexOf("Join-Path $env:ProgramData 'invscanner-winget.log'") < 0 && (sc.match(/ReparsePoint/g) || []).length >= 2 && (sc.match(/Out-File/g) || []).length === 1);
    check('transcript: no silent bad path', sc.indexOf("if (-not $invTDir)") < 0);
    // runcommands answer WITHOUT any session field is still consumed while pending
    obj.wgPending['node//orphan'] = { nodeid: 'node//orphan', sid: 'invscanner-wg-node_orphan' };
    obj.wgActive = (obj.wgActive || 0) + 1;
    var consumed = obj.onAgentResponse({ action: 'msg', type: 'runcommands', result: obj.WINGET_MARKER + '{"winget":true,"dry":true,"results":[]}' }, '', 'node//orphan');
    check('route: session-less runcommands consumed via pending', consumed === true && obj.wgResults['node//orphan'] != null, consumed);
    delete obj.wgResults['node//orphan'];
    // console-channel answer captured for pending node
    obj.wgPending['node//cons'] = { nodeid: 'node//cons', sid: 'invscanner-wg-node_cons' };
    obj.wgActive = (obj.wgActive || 0) + 1;
    var c2 = obj.onAgentResponse({ action: 'msg', type: 'console', value: 'junk' + obj.WINGET_MARKER + '{"winget":true,"results":[{"id":"A.B","state":"ok"}]}' }, '', 'node//cons');
    check('route: console-channel marker captured', c2 === true && obj.wgResults['node//cons'].results[0].state === 'ok', c2);
    delete obj.wgResults['node//cons'];
    obj.wgActive = 0;
    next();
});


// ---- v2.1.8: every script statement is single-line (agent runs PowerShell line-interactive) ----
steps.push(function (next) {
    var sc = obj.wgBuildScript({ ignorePackages: [{ id: 'A.B' }], pinSync: true }, false);
    var openers = sc.split(String.fromCharCode(10)).filter(function (l) { return /[({]s*$/.test(l) && !/^\s*\$/.test(l); });
    check('script: no line opens an unfinished block', openers.length === 0, openers.slice(0, 2));
    check('script: app-paths lookup present', sc.indexOf('App Paths') >= 0 && sc.indexOf('(default)') >= 0);
    check('script: transcript closes on early exit', sc.indexOf('Stop-Transcript -ErrorAction') >= 0 && sc.indexOf('false}') >= 0);
    next();
});


// ---- v2.2.0: one-click upgrade via in-plugin hot reload ----
steps.push(function (next) {
    var ph = { parent: meshServer, plugins: {}, exports: {} };
    var inst = factory(ph);
    inst.PLUGIN_VERSION = '0.0.1';
    ph.plugins.inventoryscanner = inst;
    inst.server_startup();
    check('upgrade: stale instance replaced in place', ph.plugins.inventoryscanner !== inst && ph.plugins.inventoryscanner.PLUGIN_VERSION !== '0.0.1', ph.plugins.inventoryscanner && ph.plugins.inventoryscanner.PLUGIN_VERSION);
    check('upgrade: exports point at the fresh instance', ph.exports.inventoryscanner === ph.plugins.inventoryscanner.exports);
    check('upgrade: old timers disarmed', inst.__superseded === true);
    ph.plugins.inventoryscanner.timerGen++;
    next();
});


// ---- v2.2.1: base64 scriptblock transport ----
steps.push(function (next) {
    var script = obj.wgBuildScript({ ignorePackages: [{ id: 'A.B' }], pinSync: false }, true);
    var line = obj.wgTransport(script);
    check('transport: single line, no newlines', line.indexOf(String.fromCharCode(10)) < 0 && line.indexOf(String.fromCharCode(13)) < 0);
    var m = line.match(/FromBase64String\('([A-Za-z0-9+/=]+)'\)/);
    check('transport: pure base64 payload', m != null);
    if (m != null) {
        var decoded = require('zlib').gunzipSync(Buffer.from(m[1], 'base64')).toString('utf8');
        check('transport: gunzips back to the script', decoded.indexOf(obj.WINGET_MARKER) >= 0 && decoded.indexOf('$invDry = $true') >= 0 && decoded === script, decoded.length + ':' + script.length);
    }
    check('transport: powershell -Command line via cmd', line.indexOf('powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command') === 0 && line.indexOf('Invoke-Expression') > 0);
    check('transport: well under cmd line limit', line.length < 8000, line.length);
    check('transport: fits the pipe (no cmd ceiling involved)', line.length > 100 && line.length < 60000, line.length);
    next();
});



// ---- v2.5.0: device events, pluginadmin url, per-row actions ----
steps.push(function (next) {
    var evts = [];
    var realDispatch = meshServer.DispatchEvent;
    meshServer.DispatchEvent = function (ids, src, ev) { evts.push({ ids: ids, ev: ev }); };
    var got = 0;
    var realGet = obj.db.Get;
    obj.db.Get = function (id, cb) { got++; return realGet.call(obj.db, id, function (e, docs) { cb(e, [{ _id: id, meshid: 'mesh//grp1' }]); }); };
    obj.wgRaiseNodeEvent('node//evt1', 'Winget updater: 1 package(s) updated, 0 failed');
    obj.db.Get = realGet;
    meshServer.DispatchEvent = realDispatch;
    check('events: node event dispatched to node+mesh targets', evts.length === 1 && evts[0].ids.indexOf('node//evt1') >= 0 && evts[0].ev.etype === 'node' && evts[0].ev.visibility === 'nodes', evts);
    var upd = [];
    var realGP = obj.db.getPlugins, realUP = obj.db.updatePlugin;
    obj.db.getPlugins = function (cb) { cb(null, [{ _id: 'plugin//p1', shortName: 'inventoryscanner', url: '/?viewmode=43' }]); };
    obj.db.updatePlugin = function (id, doc, cb) { upd.push([id, doc]); if (cb) cb(); };
    obj.fixOwnPluginUrl();
    obj.db.getPlugins = realGP; obj.db.updatePlugin = realUP;
    check('plugin list: configure url pointed at the admin panel', upd.length === 1 && upd[0][1].url.indexOf('/pluginadmin.ashx?pin=inventoryscanner') === 0, upd);
    next();
});


// ---- v2.5.2: dry-run 'unparsable payload' + transcript folder fixes ----
steps.push(function (next) {
    var sc = obj.wgBuildScript({ ignorePackages: [], pinSync: false }, true);
    check('transcript: every Stop-Transcript silenced (no notice after the answer line)',
        (sc.match(/Stop-Transcript/g) || []).length === 2 && (sc.match(/Stop-Transcript -ErrorAction SilentlyContinue \| Out-Null/g) || []).length === 2);
    check('transcript: ancestor walk to meshagent, not the cmd.exe parent',
        sc.indexOf('-imatch') >= 0 && sc.indexOf('meshagent') >= 0 && sc.indexOf('for ($invHop') >= 0, sc.split(String.fromCharCode(10))[3]);
    // trailing console text after the marker line must not corrupt the payload
    obj.wgPending['node//trail'] = { nodeid: 'node//trail', sid: 'invscanner-wg-node_trail' };
    obj.wgActive = (obj.wgActive || 0) + 1;
    obj.onAgentResponse({ action: 'msg', type: 'runcommands', result: obj.WINGET_MARKER + '{"winget":true,"dry":true,"results":[]}' + String.fromCharCode(13, 10) + 'Transcript stopped, output file is C:\\x\\invscanner-winget.log' }, '', 'node//trail');
    check('parse: text after the answer line ignored', obj.wgResults['node//trail'].error === undefined && obj.wgResults['node//trail'].winget === true, obj.wgResults['node//trail']);
    delete obj.wgResults['node//trail'];
    // a console chunk splitting the answer line must NOT end the session
    obj.wgPending['node//chunk'] = { nodeid: 'node//chunk', sid: 'invscanner-wg-node_chunk' };
    obj.wgActive = (obj.wgActive || 0) + 1;
    var a1 = obj.onAgentResponse({ action: 'msg', type: 'console', value: 'winget table...' + obj.WINGET_MARKER + '{"winget":true,"dry":true,"res' }, '', 'node//chunk');
    check('console: partial answer chunk keeps the session pending', a1 === false && obj.wgPending['node//chunk'] != null, a1);
    var a2 = obj.onAgentResponse({ action: 'msg', type: 'console', value: 'ults":[]}' + String.fromCharCode(13, 10) }, '', 'node//chunk');
    check('console: completing chunk consumes the session', a2 === true && obj.wgResults['node//chunk'].winget === true && obj.wgResults['node//chunk'].error === undefined, obj.wgResults['node//chunk']);
    delete obj.wgResults['node//chunk'];
    // runcommands reply wins even when the buffered console text was incomplete
    obj.wgPending['node//late'] = { nodeid: 'node//late', sid: 'invscanner-wg-node_late', cbuf: 'noise' + obj.WINGET_MARKER + '{"winget":tr' };
    obj.wgActive = (obj.wgActive || 0) + 1;
    obj.onAgentResponse({ action: 'msg', type: 'runcommands', sessionid: 'invscanner-wg-node_late', result: obj.WINGET_MARKER + '{"winget":true,"dry":true,"results":[{"id":"A.B","state":"dry-run"}]}' }, '', 'node//late');
    check('route: reply parsed despite broken console buffer', obj.wgResults['node//late'].error === undefined && obj.wgResults['node//late'].results.length === 1 && obj.wgResults['node//late'].results[0].state === 'dry-run', obj.wgResults['node//late']);
    delete obj.wgResults['node//late'];
    obj.wgActive = 0;
    next();
});


// ---- v2.6.0 (dryList) -> v2.7.0: wg_status carries per-device package rows ----
steps.push(function (next) {
    var many = [];
    for (var mi = 0; mi < 250; mi++) { many.push({ id: 'Pkg.Num' + mi, name: 'P' + mi, from: '1', to: '2', state: 'dry-run' }); }
    obj.wgResults['node//d1'] = { time: new Date().toISOString(), winget: true, dry: true, results: [
        { id: 'Foo.Bar', name: 'Foo', from: '1.0', to: '2.0', state: 'dry-run' },
        { id: 'Baz.Qux', name: 'Baz', from: '3', to: '4', state: 'skipped-ignored' },
        { id: 'Cap.Test9', name: 'Cap', from: '1', to: '2', state: 'dry-run' }
    ] };
    obj.wgResults['node//d2'] = { time: new Date().toISOString(), winget: true, dry: true, results: many };
    obj.wgResults['node//d4'] = { time: new Date().toISOString(), winget: true, dry: false, results: [{ id: 'Real.One', name: 'Real', from: '1', to: '2', state: 'ok' }] };
    obj.handleAdminPostReq({ headers: XHDR, body: { action: 'wg_status' } }, mockRes(function (d) {
        var a = d.devices.filter(function (x) { return x.id === 'node//d1'; })[0];
        var b = d.devices.filter(function (x) { return x.id === 'node//d2'; })[0];
        var c = d.devices.filter(function (x) { return x.id === 'node//d4'; })[0];
        check('status: rows carry EVERY package of the last run with state and versions',
            a.last.rows.length === 3 && a.last.rows[0].id === 'Foo.Bar' && a.last.rows[0].state === 'dry-run' && a.last.rows[1].state === 'skipped-ignored' && a.last.rows[0].to === '2.0', a.last);
        check('status: rows are capped at 200 entries', b.last.rows.length === 200, b.last.rows.length);
        check('status: real-run rows carry the ok state (exit null when absent)', c.last.rows.length === 1 && c.last.rows[0].state === 'ok' && c.last.rows[0].exit === null, c.last);
        delete obj.wgResults['node//d1'];
        delete obj.wgResults['node//d2'];
        delete obj.wgResults['node//d4'];
        next();
    }), user);
});


// ---- v3.0.0: driver/firmware out-of-scope + per-package update/uninstall everywhere ----
steps.push(function (next) {
    check('class: driver and firmware words classify', obj.guessDriverFirmware('Realtek Audio Driver') === 'driver' && obj.guessDriverFirmware('ACME BIOS Tool') === 'firmware');
    check('class: driver TOOLS and ordinary apps are never classified', obj.guessDriverFirmware('Driver Booster 11') === null && obj.guessDriverFirmware('Total Commander') === null);
    var savedRemote0 = obj.remoteCpeEntries;
    var rr0 = obj.applyCpeTableText('{"entries":[{"match":"acme virtual adapter","kind":"driver"},{"match":"^acme pdf$","vendor":"acme","product":"pdf"}]}');
    check('table: kind entries validate and apply', rr0.ok === true && rr0.applied === 2, rr0);
    check('table: kind row wins over guessing, CPE row still maps', obj.classifySoftware('Acme Virtual Adapter', 'Acme Inc').kind === 'driver' && obj.classifySoftware('Acme PDF', 'Acme Inc').search != null);
    obj.remoteCpeEntries = savedRemote0;

    var dpV3 = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-v3-'));
    var obj2 = factory({ parent: { db: db, datapath: dpV3, debug: function () { }, config: { settings: {} }, webserver: { meshes: {}, wsagents: {} } } });
    obj2.scanDeviceSoftware([{ name: 'Realtek Audio Driver', version: '1.0', publisher: 'Realtek' }], function (resX) {
        check('scan: driver rows get the honest out-of-scope status', resX.length === 1 && resX[0].status === 'driver' && resX[0].outOfScope === true && resX[0].isCve === false, resX[0]);

        var sUp = obj.wgBuildScript({ ignorePackages: [], pinSync: false }, false, { onlyId: 'Foo.Bar' });
        check('script: single-package update gate, no uninstall text', sUp.indexOf("$invOnly = 'Foo.Bar'") >= 0 && sUp.indexOf('-ine $invOnly') >= 0 && sUp.indexOf('uninstall') < 0);
        var sUn = obj.wgBuildScript({ ignorePackages: [], pinSync: false }, false, { mode: 'uninstall', onlyId: 'Foo.Bar' });
        check('script: uninstall probes, reports not-installed, never upgrades', sUn.indexOf('uninstall --id $invOnly') >= 0 && sUn.indexOf('list --id $invOnly --exact') >= 0 && sUn.indexOf('not-installed') >= 0 && sUn.indexOf('upgrade --id') < 0);
        // the probe must use a REAL PowerShell operator: -notimatch does not exist and broke
        // parsing of the whole script (verified with the PS 5.1 parser)
        check('script: only valid PowerShell comparison operators are emitted',
            sUn.indexOf('-notimatch') < 0 && sUn.indexOf('-inotmatch') >= 0, sUn.substring(sUn.indexOf('$invProbe'), sUn.indexOf('$invProbe') + 90));
        check('script: uninstall without an id refuses to build', (function () { try { obj.wgBuildScript({ ignorePackages: [], pinSync: false }, false, { mode: 'uninstall' }); return false; } catch (e) { return true; } })());
        check('script: onlyId passes the id whitelist (injection neutralised)', obj.wgBuildScript({ ignorePackages: [], pinSync: false }, false, { onlyId: "bad';rm -x" }).indexOf("$invOnly = ''") >= 0);

        obj.wgBatchRunning = false;
        var rPost = function (b, cb) { obj.handleAdminPostReq({ headers: XHDR, body: b }, mockRes(cb), user); };
        var runErrs = [];
        rPost({ action: 'wg_run', mode: 'uninstall' }, function (d1x) {
            runErrs.push(!!d1x.error);
            rPost({ action: 'wg_run', pkgId: 'Foo.Bar', mode: 'uninstall', dry: 'true' }, function (d2x) {
                runErrs.push(!!d2x.error);
                rPost({ action: 'wg_run', pkgId: 'bad id' }, function (d3x) {
                    runErrs.push(!!d3x.error);
                    check('route: uninstall-without-id, uninstall-dry and bad-id are rejected', runErrs.join(',') === 'true,true,true' && obj.wgBatchRunning === false, runErrs);

                    // end-to-end on a clean instance: ONE package uninstalled across the fleet,
                    // from the real runcommands payload down to the package table
                    var dpU = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-wgun-'));
                    var sentU = [];
                    var wsU = { meshes: { 'mesh//grp1': { name: 'HQ' } }, wsagents: { 'node//d1': { send: function (m) { sentU.push(JSON.parse(m)); } } } };
                    var objU = factory({ parent: { db: db, datapath: dpU, debug: function () { }, config: { settings: {} }, webserver: wsU } });
                    var stU = objU.wgStartBatch('pkg-uninstall', null, ['node//d1'], false, { mode: 'uninstall', onlyId: 'Foo.Bar' });
                    var mmU = (sentU.length === 1) ? String(sentU[0].cmds || '').match(/FromBase64String\('([A-Za-z0-9+\/=]+)'\)/) : null;
                    var scrU = mmU ? require('zlib').gunzipSync(Buffer.from(mmU[1], 'base64')).toString('utf8') : '';
                    check('e2e: the agent really receives the uninstall script for that one id',
                        stU.started === true && sentU.length === 1 && sentU[0].action === 'runcommands' &&
                        scrU.indexOf("$invMode = 'uninstall'") >= 0 && scrU.indexOf("$invOnly = 'Foo.Bar'") >= 0 &&
                        scrU.indexOf('uninstall --id $invOnly') >= 0 && scrU.indexOf('upgrade --id') < 0, [sentU.length, scrU.length]);
                    objU.onAgentResponse({ action: 'msg', type: 'runcommands', sessionid: String(sentU[0].sessionid), result: objU.WINGET_MARKER + '{"winget":true,"dry":false,"mode":"uninstall","results":[{"id":"Foo.Bar","name":"","from":"","to":"","state":"not-installed","exit":null,"log":""}]}' }, '', 'node//d1');
                    var lgU = '';
                    try { lgU = fs.readFileSync(objU.wingetLogPath, 'utf8'); } catch (exU) { }
                    check('e2e: not-installed drains the batch, is no failure and is worded honestly',
                        objU.wgBatchRunning === false && objU.wgResults['node//d1'].results[0].state === 'not-installed' &&
                        lgU.indexOf('0 uninstalled, 1 skipped/not-installed, 0 failed') >= 0, lgU.split(String.fromCharCode(10)).slice(-3));
                    var puRes = null;
                    objU.handleAdminPostReq({ headers: XHDR, body: { action: 'wg_programs' } }, mockRes(function (pu) { puRes = pu; }), user);
                    var upk = (puRes && puRes.packages && puRes.packages[0]) || null;
                    check('e2e: the package table shows the fleet result of that run',
                        upk != null && upk.id === 'Foo.Bar' && upk.skipped === 1 && upk.failed === 0 &&
                        upk.devices.length === 1 && upk.devices[0].state === 'not-installed', puRes && puRes.packages);

                    obj.wgResults['node//d1'] = { time: 'x', winget: true, dry: true, results: [{ id: 'Foo.Bar', name: 'Foo', from: '1', to: '2', state: 'dry-run' }, { id: 'Baz.Qux', name: 'Baz', from: '3', to: '4', state: 'skipped-ignored' }] };
                    obj.wgResults['node//d2'] = { time: 'y', winget: true, dry: false, results: [{ id: 'Foo.Bar', name: 'Foo', from: '1', to: '2', state: 'ok' }] };
                    rPost({ action: 'wg_programs' }, function (px) {
                        var p1 = px.packages.filter(function (x) { return x.id === 'Foo.Bar'; })[0];
                        var p2 = px.packages.filter(function (x) { return x.id === 'Baz.Qux'; })[0];
                        check('programs: aggregated per package with per-device states and labels', p1.ready === 1 && p1.ok === 1 && p1.devices.length === 2 && p1.devices[0].label === 'Given1' && p2.skipped === 1, px.packages);
                        delete obj.wgResults['node//d1'];
                        delete obj.wgResults['node//d2'];

                        var stubReal = obj.scanDeviceSoftware;
                        obj.buildOverallReport(function (e0, r0) {
                            var xRows = [
                                { status: 'driver', outOfScope: true, isCve: false, cve: '', severity: '', cvss: '', description: 'drv', software: 'Realtek Audio Driver', version: '1.0', published: '', references: [] },
                                { status: 'firmware', outOfScope: true, isCve: false, cve: '', severity: '', cvss: '', description: 'fw', software: 'ACME BIOS', version: '1.0', published: '', references: [] }
                            ];
                            obj.scanDeviceSoftware = function (list, cb) { cb(softwareVulns.concat(xRows)); };
                            obj.buildOverallReport(function (e1, r1) {
                                var devX = r1.devices.reduce(function (a, d) { return a + (d.programsOutOfScope || 0); }, 0);
                                check('report: driver/firmware rows count as out of scope, coverage denominator untouched',
                                    devX > 0 && devX === r1.outOfScopePrograms && r1.assessablePrograms === r0.assessablePrograms &&
                                    r1.notAssessablePrograms === r0.notAssessablePrograms && r1.coveragePercent === r0.coveragePercent,
                                    [r0.assessablePrograms, r0.notAssessablePrograms, r0.coveragePercent, devX, r1.outOfScopePrograms, r1.assessablePrograms, r1.notAssessablePrograms, r1.coveragePercent]);
                                obj.scanDeviceSoftware = stubReal;
                                next();
                            });
                        });
                    });
                });
            });
        });
    });
});

// ---- v2.8.0: honest CVE-row aggregation + coexistence-aware pruning ----
steps.push(function (next) {
    var pv1 = obj.pruneSuperseded([
        { name: 'Microsoft Edge', version: '157.0.4341.42', publisher: 'Microsoft Corporation' },
        { name: 'Microsoft Edge WebView2-Laufzeit', version: '157.0.4341.42', publisher: 'Microsoft Corporation' }
    ]);
    check('prune: edge and the webview2 runtime coexist (distinct products)', pv1.length === 2, pv1);
    var pw = obj.matchKnownProduct('Microsoft Edge WebView2-Laufzeit');
    check('table: webview2 maps to edge_webview2, never to edge', pw != null && pw.product === 'edge_webview2', pw);
    var pv2 = obj.pruneSuperseded([
        { name: 'Microsoft Visual C++ 2008 Redistributable - x64 9.0.30729.6161', version: '9.0.30729.6161', publisher: 'Microsoft Corporation' },
        { name: 'Microsoft Visual C++ 2008 Redistributable - x86 9.0.30729.6161', version: '9.0.30729.6161', publisher: 'Microsoft Corporation' }
    ]);
    check('prune: x64 and x86 installs of one product coexist', pv2.length === 2, pv2);
    var pv3 = obj.pruneSuperseded([
        { name: 'Nextcloud Talk (Machine - MSI)', version: '2.3.3.0', publisher: 'Nextcloud GmbH' },
        { name: 'Nextcloud Talk (Machine)', version: '2.3.3', publisher: 'Nextcloud GmbH' }
    ]);
    check('prune: same program, same name token -> newer version wins', pv3.length === 1 && String(pv3[0].name).indexOf('MSI') > 0, pv3);
    var pv4 = obj.pruneSuperseded([{ name: 'Dup Tool', version: '1.0', publisher: 'Dup Inc' }, { name: 'Dup Tool', version: '1.0', publisher: 'Dup Inc' }]);
    check('prune: exact duplicate rows collapse', pv4.length === 1, pv4);
    var pv5 = obj.pruneSuperseded([{ name: 'Google Chrome 1.0', version: '1.0', publisher: 'Google LLC' }, { name: 'Chrome 2.0', version: '2.0', publisher: 'Google LLC' }]);
    check('prune: mapped and unmapped name forms of one product still collapse (leftover fix stays)', pv5.length === 1 && String(pv5[0].version) === '2.0', pv5);
    var pv6 = obj.pruneSuperseded([{ name: 'Zeta Backup 3.6 (x64)', version: '3.6', publisher: 'Zeta Corp' }, { name: 'Zeta Backup 12.1 (x64)', version: '12.1', publisher: 'Zeta Corp' }]);
    check('prune: unknown-vendor leftovers collapse newest-wins', pv6.length === 1 && String(pv6[0].version) === '12.1', pv6);

    // aggregation across devices with DIFFERENT installed versions of the same product:
    var realScan = obj.scanDeviceSoftware;
    var savedDoc = sysinfo['sinode//d2'].doc;
    sysinfo['sinode//d2'].doc = { apps: [{ name: 'Nextcloud Talk (Machine)', version: '1.2.6.0', publisher: 'Nextcloud GmbH' }] };
    obj.scanDeviceSoftware = function (swlist, cb) {
        var out = [];
        for (var s = 0; s < swlist.length; s++) {
            out.push({ status: 'CVE', isCve: true, cve: 'CVE-2024-8888', severity: 'HIGH', cvss: 7.5, description: 'varies case', software: String(swlist[s].name || ''), version: String(swlist[s].version || ''), published: '', references: [] });
        }
        cb(out);
    };
    obj.scanMultiMeshCves(['mesh//grp1'], function (err, result) {
        var row = result.cves.filter(function (x) { return x.cve === 'CVE-2024-8888'; })[0];
        check('scan: varied per-device versions never collapse to the first device',
            row != null && row.versionVaried === true && row.version === '' && (row.variedVersions || []).sort().join(',') === '1.0,1.2.6.0' && row.softwareVaried === true, row);
        check('scan: deviceList keeps the exact per-device truth',
            row.deviceList.length === 2 && row.deviceList[0].name === 'Given1' && row.deviceList[0].version === '1.0' && row.deviceList[1].name === 'Given2' && row.deviceList[1].version === '1.2.6.0', row.deviceList);
        obj.buildOverallReport(function (e2, rep) {
            var hqf = rep.locations.filter(function (x) { return x.name === 'HQ'; })[0].findings.filter(function (x) { return x.cve === 'CVE-2024-8888'; })[0];
            check('report: findings carry the same honest version state', hqf.versionVaried === true && hqf.version === '' && hqf.deviceList.length === 2, hqf);
            sysinfo['sinode//d2'].doc = savedDoc;
            obj.scanDeviceSoftware = realScan;
            next();
        });
    });
});

// ---- v2.7.1: panel device labels are admin given names (reports keep host names) ----
steps.push(function (next) {
    obj.scanMultiMeshCves(['mesh//grp1'], function (err, result) {
        var c1 = result.cves.filter(function (x) { return x.cve === 'CVE-2024-0001'; })[0];
        check('scan: device labels prefer the admin given name', c1 && c1.locations[0].devices.join(',') === 'Given1,Given2', c1 && c1.locations[0].devices);
        next();
    });
});

// ---- v2.7.0: per-package log detail lines + ignore-list contracts ----
steps.push(function (next) {
    // builder: the saved ignore list MUST reach the client script and gate every upgrade
    var s7 = obj.wgBuildScript({ ignorePackages: [{ id: 'TrackerSoftware.PDF-XChangeEditor' }], pinSync: false }, false);
    check('script: ignore ids embedded as PS array', s7.indexOf("$invIgnore = @('TrackerSoftware.PDF-XChangeEditor')") >= 0, s7.split(String.fromCharCode(10))[12]);
    check('script: case-insensitive id check gates the upgrade call', /\$p\.id -ieq \$ig/.test(s7) && s7.indexOf("state = 'skipped-ignored'") >= 0);
    check('script: App Paths probe uses Test-Path (no PS error noise in the transcript)', s7.indexOf("if (Test-Path 'HKLM:") >= 0 && s7.indexOf("-ErrorAction Stop).'(default)'") < 0);

    // server log: FAILED lines with exit/reason, WARNING on ignore-list violations (exact + near-miss)
    obj.pluginSettings = { wingetUpdater: { enabled: true, ignorePackages: [{ id: 'Ign.Exact' }, { id: 'Similar.Prefix' }] } };
    obj.wgPending['node//detail'] = { nodeid: 'node//detail', sid: 'invscanner-wg-node_detail', since: Date.now() };
    obj.wgActive = (obj.wgActive || 0) + 1;
    var res7 = obj.WINGET_MARKER + JSON.stringify({ winget: true, dry: false, results: [
        { id: 'Ign.Exact', name: 'Exact', from: '1', to: '2', state: 'ok', exit: 0 },
        { id: 'Similar.Prefix.One', name: 'Near', from: '1', to: '2', state: 'ok', exit: 0 },
        { id: 'OBSProject.OBSStudio', name: 'OBS', from: '32', to: '33', state: 'failed', exit: -1, log: 'Files in use.\r\nTry again.' }
    ] });
    obj.onAgentResponse({ action: 'msg', type: 'runcommands', sessionid: 'invscanner-wg-node_detail', result: res7 }, '', 'node//detail');
    var lg7 = fs.readFileSync(obj.wingetLogPath, 'utf8');
    check('log: one FAILED line per failed package with exit code and reason',
        lg7.indexOf('node//detail - FAILED OBSProject.OBSStudio [32 -> 33] exit -1 (0xFFFFFFFF): Files in use. Try again.') >= 0, lg7.split(String.fromCharCode(10)).slice(-6));
    check('log: exact ignore violation is called out', lg7.indexOf('WARNING Ign.Exact is on the ignore list but was upgraded anyway') >= 0);
    check('log: near-miss ignore id is called out with the stored entry',
        lg7.indexOf('WARNING Similar.Prefix.One was upgraded although the similar ignore entry "Similar.Prefix" exists') >= 0, lg7.split(String.fromCharCode(10)).slice(-6));
    var rec7 = obj.wgResults['node//detail'];
    check('results: failed package keeps exit and log', rec7.results[2].state === 'failed' && rec7.results[2].exit === -1 && /Files in use/.test(rec7.results[2].log), rec7.results[2]);
    delete obj.wgResults['node//detail'];
    obj.pluginSettings = {};
    obj.wgActive = 0;
    next();
});

// ---- v3.0.1 (audit 2026-11-11): access control, request-origin check, agent routing, scripts ----
steps.push(function (next) {
    var codes = [];
    var postAs = function (u, hdr, cb) { obj.handleAdminPostReq({ headers: hdr, body: { action: 'get_locations' } }, mockRes(function (d) { codes.push(d._status || 'ok'); cb(); }), u); };
    postAs(user, {}, function () {
        postAs(user, { 'x-invscanner-request': '0' }, function () {
            postAs({ name: 'sub', siteadmin: 0xFFFFFFFF, domain: 'tenant2' }, XHDR, function () {
                postAs(user, XHDR, function () {
                    check('auth: POST without the panel header -> 403, wrong value -> 403, sub-domain admin -> 401, panel request ok', codes.join(',') === '403,403,401,ok', codes);
                    obj.handleAdminReq({ query: { action: 'show' } }, mockRes(function (d) {
                        check('auth: sub-domain site admin cannot open the panel (multi-tenant isolation)', d._status === 401, d);
                        var sent = [];
                        obj.uiCustomEvent({ section: 'devicesbarbuttons', logmsg: 'assessment', selectedDevices: [] }, { send: function (m) { sent.push(m); }, user: { siteadmin: 0 } });
                        obj.uiCustomEvent({ section: 'devicesbarbuttons', logmsg: 'hardware', selectedDevices: ['node//d1'] }, { send: function (m) { sent.push(m); }, user: { siteadmin: 0 } });
                        check('auth: toolbar hook ignores non-admin sessions (no CSV, no panel push)', sent.length === 0, sent);
                        var dbCalls = 0, realGet = obj.db.Get;
                        obj.db.Get = function (id, cb) { dbCalls++; cb(null, []); };
                        obj.uiCustomEvent({ section: 'devicesbarbuttons', logmsg: 'hardware', selectedDevices: [{ x: 1 }, '../../etc', 'node//d1', 'node//d1'] }, { send: function () { }, user: user });
                        obj.db.Get = realGet;
                        check('uievent: only well-formed, unique node ids are looked up', dbCalls === 1, dbCalls);
                        next();
                    }), { name: 'sub', siteadmin: 0xFFFFFFFF, domain: 'tenant2' });
                });
            });
        });
    });
});

steps.push(function (next) {
    obj.handleAdminPostReq({ headers: XHDR, body: { action: 'unflag_false_positive', meshIds: 'mesh//grp1', cveId: '__proto__' } }, mockRes(function (d) {
        check('validation: unflag rejects non-finding ids like the other write paths', !!d.error, d);
        obj.handleAdminReq({ query: { action: 'scan', mesh: 'mesh//grp1:x,bogus' } }, mockRes(function (d2) {
            check('validation: scan accepts only well-formed mesh ids', !!d2.error, d2);
            next();
        }), user);
    }), user);
});

steps.push(function (next) {
    // software inventory: browser-session replies are left alone, error answers never wipe a good list
    obj.softwareInventory = {};
    obj.pendingCollection['node//sw1'] = true;
    var r1 = obj.onAgentResponse({ action: 'software', sessionid: 'user//admin/abc', value: JSON.stringify([{ name: 'Browser Only' }]) }, '', 'node//sw1');
    check('software: reply addressed to a browser session is neither stored nor consumed', r1 === false && obj.softwareInventory.sw1 == null && obj.pendingCollection['node//sw1'] === true, obj.softwareInventory);
    var r2 = obj.onAgentResponse({ action: 'software', value: JSON.stringify([{ name: 'Good App', version: '1' }]) }, '', 'node//sw1');
    check('software: our session-less reply is stored and consumed (not broadcast)', r2 === true && obj.softwareInventory.sw1.apps.length === 1, obj.softwareInventory.sw1);
    obj.pendingCollection['node//sw1'] = true;
    obj.onAgentResponse({ action: 'software', value: JSON.stringify({ success: false, error: 'Denied' }) }, '', 'node//sw1');
    check('software: an error answer keeps the last good inventory', obj.softwareInventory.sw1.apps.length === 1 && obj.softwareInventory.sw1.apps[0].name === 'Good App', obj.softwareInventory.sw1);
    var sentSw = [];
    obj.collectNodeSoftware('node//sw2', { send: function (m) { sentSw.push(JSON.parse(m)); } });
    check('software: request carries a minimal numeric rights field (agent >= 2026-11-09 refuses commands without one)', sentSw.length === 1 && sentSw[0].rights === 8 && sentSw[0].type === 'installedapps', sentSw);
    delete obj.pendingCollection['node//sw2'];
    obj.softwareInventory = {};
    next();
});

steps.push(function (next) {
    // winget routing: replies of OTHER sessions are never taken over while a run is pending
    obj.wgPending['node//own'] = { nodeid: 'node//own', sid: 'invscanner-wg-own', since: Date.now() };
    obj.wgActive = 1;
    var foreign = obj.onAgentResponse({ action: 'msg', type: 'runcommands', sessionid: 'user//admin/xyz', result: 'admin output' }, '', 'node//own');
    var foreignCon = obj.onAgentResponse({ action: 'msg', type: 'console', sessionid: 'user//admin/xyz', value: obj.WINGET_MARKER + '{"winget":true,"results":[]}' }, '', 'node//own');
    check('wg routing: a pending run never consumes runcommands/console output of a browser session', foreign === false && foreignCon === false && obj.wgPending['node//own'] != null && obj.wgPending['node//own'].cbuf == null, [foreign, foreignCon]);
    delete obj.wgPending['node//own'];
    obj.wgActive = 0;
    next();
});

steps.push(function (next) {
    // winget scripts: verified CLI contracts (winget 1.29 on Windows 11, audit 2026-11-11)
    var sUn = obj.wgBuildScript({ ignorePackages: [], pinSync: false }, false, { mode: 'uninstall', onlyId: 'Foo.Bar' });
    var unLine = sUn.split(String.fromCharCode(10)).filter(function (l) { return l.indexOf('uninstall --id') >= 0; })[0] || '';
    check('script: uninstall never passes --accept-package-agreements (winget uninstall rejects it)', unLine !== '' && unLine.indexOf('--accept-package-agreements') < 0, unLine.substring(unLine.indexOf('uninstall --id'), unLine.indexOf('uninstall --id') + 120));
    var sUp = obj.wgBuildScript({ ignorePackages: [], pinSync: false }, false);
    check('script: upgrade keeps --accept-package-agreements (documented upgrade option)', /upgrade --id \$p\.id --exact --silent --accept-package-agreements/.test(sUp));
    check('script: Get-Command hit is read from .Path (ApplicationInfo has no FullName)', sUp.indexOf('$wc.Path') >= 0 && sUp.indexOf('-CommandType Application') >= 0);
    check('script: protected WindowsApps folder is tried before PATH', sUp.indexOf('WindowsApps') >= 0 && sUp.indexOf('WindowsApps') < sUp.indexOf('Get-Command winget'));
    check('script: table parser uses header column positions with the old regex as fallback', sUp.indexOf("# invscanner:parse-begin") >= 0 && sUp.indexOf("[regex]::Matches($invLines[$invH]") >= 0 && sUp.indexOf("\\s{2,}") >= 0);
    next();
});

steps.push(function (next) {
    // the PowerShell table parser itself, exercised against a REAL winget 1.29 table (audit machine):
    // single-space column gaps for full-width names/ids/versions and a '< x' version were dropped
    // by the pre-3.0.1 regex. Runs only where PowerShell exists (Windows); skipped elsewhere.
    var cp = require('child_process');
    var sUp = obj.wgBuildScript({ ignorePackages: [], pinSync: false }, false);
    var lines = sUp.split(String.fromCharCode(10));
    var a = lines.indexOf('# invscanner:parse-begin'), b = lines.indexOf('# invscanner:parse-end');
    var table = [
        'Name                                                         Id                                 Version          Available        Source',
        '----------------------------------------------------------------------------------------------------------------------------------------',
        'App Installer                                                Microsoft.AppInstaller             1.29.379.0       1.29.380         winget',
        'Microsoft OneDrive                                           Microsoft.OneDrive                 26.017.0126.0002 26.183.0920.0005 winget',
        'Microsoft Visual C++ v14 Redistributable (x64) - 14.51.36247 Microsoft.VCRedist.2015+.x64       14.51.36247.0    14.52.37029.0    winget',
        'Microsoft Windows Desktop Runtime 10.0.12 (x64)              Microsoft.DotNet.DesktopRuntime.10 10.0.12          10.0.15          winget',
        'TortoiseSVN 1.14.9.29743 (64 bit)                            TortoiseSVN.TortoiseSVN            < 1.15.0.29830   1.15.0.29830     winget',
        '13 upgrades available.'
    ].join('\r\n');
    var ps = "$raw = [IO.File]::ReadAllText($env:INV_T)\n$rows = @()\n" + lines.slice(a, b + 1).join('\n') + "\n$rows | ForEach-Object { $_.id + '|' + $_.from + '|' + $_.to }";
    var dir = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-ps-'));
    fs.writeFileSync(path.join(dir, 't.txt'), table); fs.writeFileSync(path.join(dir, 't.ps1'), ps);
    var psr = runPs(['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', path.join(dir, 't.ps1')], { env: Object.assign({}, process.env, { INV_T: path.join(dir, 't.txt') }) });
    if (psr == null) { console.log('SKIP script: winget table parser (PowerShell not available)'); next(); return; }
    if (psr.failed) { check('script: the winget table parser block runs in PowerShell without an error', false, psr.text); next(); return; }
    var out = psr.text;
    var got = out.split(/\r?\n/).filter(function (x) { return x !== ''; });
    check('script: real winget table - every upgradable row parsed, versions intact, footer ignored',
        got.length === 5 && got[1] === 'Microsoft.OneDrive|26.017.0126.0002|26.183.0920.0005' && got[2] === 'Microsoft.VCRedist.2015+.x64|14.51.36247.0|14.52.37029.0' &&
        got[3] === 'Microsoft.DotNet.DesktopRuntime.10|10.0.12|10.0.15' && got[4] === 'TortoiseSVN.TortoiseSVN|< 1.15.0.29830|1.15.0.29830', got);
    next();
});

steps.push(function (next) {
    // mapping table: every vendor:product pair was verified against the NVD CVE API on 2026-11-11
    var tbl = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'cpe-table.json'), 'utf8'));
    var pair = function (m) { var e = tbl.entries.filter(function (x) { return new RegExp(x.match, 'i').test(m); })[0]; return e ? e.vendor + ':' + e.product : null; };
    check('table: corrected NVD names (notepad++ escaped, sumatrapdf, keepass, filezilla, audacity, electron)',
        pair('Notepad++ (64-bit x64)') === 'notepad-plus-plus:notepad\\+\\+' && pair('SumatraPDF') === 'sumatrapdfreader:sumatrapdf' &&
        pair('KeePass Password Safe 2.57') === 'keepass:keepass' && pair('FileZilla 3.68.1') === 'filezilla-project:filezilla_client' &&
        pair('FileZilla Server') === 'filezilla-project:filezilla_server' && pair('Audacity 3.7') === 'audacityteam:audacity' && pair('Electron Fiddle') === 'electronjs:electron',
        [pair('Notepad++ (64-bit x64)'), pair('SumatraPDF'), pair('KeePass Password Safe 2.57'), pair('FileZilla 3.68.1')]);
    check('table: names without any NVD product are not mapped (pcvisit, chromium)', pair('pcvisit RemoteHost') === null && pair('Chromium') === null);
    check('table: single source of mappings - no seeded copy in the module code (v4.2.0 dedup)',
        pluginSrc().indexOf('SOFTWARE_CPE_TABLE') < 0 && obj.SOFTWARE_CPE_TABLE === undefined);
    var savedNone = obj.remoteCpeEntries; obj.remoteCpeEntries = null;
    check('table: without any table file the curated stage is EMPTY (no hidden fallback list), custom/auto still work',
        obj.activeSoftwareTable().length === 0 && obj.cpeTableStatus().source === 'none' && obj.cpeTableStatus().entries === 0, obj.cpeTableStatus());
    obj.remoteCpeEntries = savedNone;
    check('table: dangerous regex shapes are rejected (nested quantifier, backreference), normal ones pass',
        obj.isSafeTableRegex('(a+)+') === false && obj.isSafeTableRegex('(\\w+\\s?)+$') === false && obj.isSafeTableRegex('(.*)\\1') === false &&
        obj.isSafeTableRegex('adobe acrobat( \\(64-bit\\))?') === true && tbl.entries.every(function (e) { return obj.isSafeTableRegex(e.match); }));
    var rr = obj.applyCpeTableText({ entries: [{ match: '(a+)+$', vendor: 'x', product: 'y' }, { match: '^ok', vendor: 'v', product: 'p' }] });
    check('table: remote payload with a dangerous regex skips that row only', rr.ok === true && rr.applied === 1 && rr.skipped === 1, rr);
    obj.remoteCpeEntries = null; obj.loadRemoteCpeTable();
    obj.addCustomCpe('(x*)*y', 'a', 'b', function (err) {
        check('custom mapping: dangerous regex rejected by add_cpe', !!err, err && err.message);
        next();
    });
});

steps.push(function (next) {
    // pruning: side-by-side runtimes keyed by the token the mapping really produces
    var pr = obj.pruneSuperseded([
        { name: 'Microsoft Visual C++ 2008 Redistributable - x64 9.0.30729.6161', version: '9.0.30729.6161', publisher: 'Microsoft Corporation' },
        { name: 'Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.40.33810', version: '14.40.33810.0', publisher: 'Microsoft Corporation' },
        { name: 'Microsoft Windows Desktop Runtime - 8.0.11 (x64)', version: '8.0.11', publisher: 'Microsoft Corporation' },
        { name: 'Microsoft Windows Desktop Runtime - 10.0.12 (x64)', version: '10.0.12', publisher: 'Microsoft Corporation' }]);
    check('prune: VC++ 2008 + 2015 and .NET 8 + 10 runtimes coexist (older one is still scanned)', pr.length === 4, pr.map(function (x) { return x.name; }));
    check('batch: device cap constant is defined (was referenced but undefined)', typeof obj.WINGET_MAX_DEVICES === 'number' && obj.WINGET_MAX_DEVICES > 0);
    next();
});


// ---- winget updater: script builder, queue, parser, config, status ----
steps.push(function (next) {
    check('version: manifest beside the plugin parses', /^[0-9]+.[0-9]+.[0-9]+/.test(obj.PLUGIN_VERSION), obj.PLUGIN_VERSION);
    next();
});

steps.push(function (next) {
    var dp3 = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-wg-'));
    var ws3 = { meshes: { 'mesh//grp1': { name: 'HQ' }, 'mesh//grp2': { name: 'Branch' } }, wsagents: {} };
    var obj3 = factory({ parent: { db: db, datapath: dp3, debug: function () { }, config: { settings: {} }, webserver: ws3 } });
    obj3.pluginSettings = {};
    var sent = [];
    ws3.wsagents['node//d1'] = { send: function (m) { sent.push(JSON.parse(m)); } };
    ws3.wsagents['node//d2'] = { send: function (m) { sent.push(JSON.parse(m)); } };
    ws3.wsagents['node//d3'] = { send: function (m) { sent.push(JSON.parse(m)); } };

    // builder
    var sc = obj3.wgBuildScript({ ignorePackages: [{ id: 'Adobe.Acrobat.Reader.64-bit' }, { id: 'bad id;rm' }], pinSync: true });
    check('wg script: marker + json lines', sc.indexOf(obj3.WINGET_MARKER) >= 0 && sc.indexOf('ConvertTo-Json') >= 0);
    check('wg script: good id embedded, bad id dropped', sc.indexOf("'Adobe.Acrobat.Reader.64-bit'") >= 0 && sc.indexOf('bad id') < 0, sc.substring(0, 200));
    check('wg script: pin block present', sc.indexOf('pin add') >= 0);
    check('wg script: upgrade call shape', /upgrade --id \$p\.id --exact --silent/.test(sc));
    var sc2 = obj3.wgBuildScript({ ignorePackages: [], pinSync: false });
    check('wg script: pinSync off removes pin block', sc2.indexOf('pin add') < 0);

    // config validation via routes
    var wgTimers = [];
    obj3.longTimeout = function (cb, ms) { wgTimers.push(ms); };
    var post = function (body, cb) { obj3.handleAdminPostReq({ headers: XHDR, body: body }, mockRes(cb), user); };
    post({ action: 'wg_save_config', enabled: 'true', updateMeshes: '', excludeNodes: '', ignorePackages: '[]', pinSync: 'true' }, function (d) {
        check('wg cfg: save works without any interval field', !d.error && typeof d.config.scheduling === 'string', d);
        post({ action: 'wg_save_config', enabled: 'true', intervalHours: '48', updateMeshes: 'mesh//grp1', excludeNodes: 'node//d3', ignorePackages: JSON.stringify([{ id: 'OpenJS.NodeJS.18', note: 'lts license' }, { id: 'DROP TABLE' }]), pinSync: 'false' }, function (dBad) {
            check('wg cfg: invalid id rejected explicitly', !!dBad.error && /ignore/i.test(dBad.error), dBad);
            post({ action: 'wg_save_config', enabled: 'true', intervalHours: '48', updateMeshes: 'mesh//grp1', excludeNodes: 'node//d3', ignorePackages: JSON.stringify([{ id: 'OpenJS.NodeJS.18', note: 'lts license' }]), pinSync: 'false' }, function (d2) {
            check('wg cfg: save ok with valid id', !d2.error && d2.config.ignorePackages.length === 1 && d2.config.ignorePackages[0].id === 'OpenJS.NodeJS.18', d2.config);
            var w3 = obj3.wingetConfig();
            check('wg cfg: effective after save', w3.enabled === true && w3.meshes.length === 1 && w3.excludeNodes[0] === 'node//d3' && w3.pinSync === false, w3);

            // scope: updateMeshes gates SCHEDULED batches only; manual/package runs take every
            // Windows node that is not excluded (that is what "everywhere" means in the Packages view)
            var idsSch = null, idsMan = null;
            obj3.wgTargetNodes(true, function (x) { idsSch = x; });
            obj3.wgTargetNodes(false, function (x) { idsMan = x; });
            check('wg scope: scheduled respects updateMeshes, a package run ignores it but keeps exclusions',
                idsSch.slice().sort().join() === 'node//d1,node//d2' && idsMan.slice().sort().join() === 'node//d1,node//d2,node//d4',
                [idsSch, idsMan]);

            // batch: d1,d2 in scope (grp1), d3 excluded, d4 in grp2 not in meshes
            obj3.WINGET_MAX_PARALLEL = 2;
            var r = obj3.wgStartBatch('scheduled', null);
            check('wg batch: started and queued two (parallel cap)', obj3.wgBatchRunning === true && sent.length === 2, sent.length);
            if (sent.length < 2) { check('wg batch: two sends queued', false, sent.length); next(); return; }
            var msg0 = sent[0];
            check('wg batch: runcommands message shape', msg0.action === 'runcommands' && msg0.type === 1 && msg0.runAsUser === 0 && msg0.reply === true && String(msg0.sessionid).indexOf('invscanner-wg-') === 0, msg0);

            // responses: d1 ok (single result -> PS unwraps object), d2 no winget
            obj3.onAgentResponse({ action: 'msg', type: 'runcommands', sessionid: msg0.sessionid, result: 'noise' + String.fromCharCode(10) + obj3.WINGET_MARKER + '{"winget":true,"results":{"id":"OpenJS.NodeJS.18","name":"Node.js","from":"18.19.0","to":"18.20.8","state":"ok","exit":0,"log":"done"}}' }, '', 'node//d1');
            check('wg parse: unwrapped single result normalized', obj3.wgResults['node//d1'].results.length === 1 && obj3.wgResults['node//d1'].results[0].state === 'ok', obj3.wgResults['node//d1']);
            var m2 = sent[1];
            check('wg queue: second device was sent', m2.sessionid.indexOf('invscanner-wg-') === 0);
            obj3.onAgentResponse({ action: 'msg', type: 'runcommands', sessionid: m2.sessionid, result: obj3.WINGET_MARKER + '{"winget":false}' }, '', 'node//d2');
            check('wg parse: winget false recorded', obj3.wgResults['node//d2'].winget === false);
            // foreign sessions are not consumed
            check('wg hook: foreign runcommands not consumed', obj3.onAgentResponse({ action: 'msg', type: 'runcommands', sessionid: 'other', result: 'x' }, '', 'node//d1') === false);
            check('wg batch: drained after responses', obj3.wgBatchRunning === false);
            check('wg state: results persisted', fs.existsSync(obj3.wingetResultsPath));

            post({ action: 'wg_status' }, function (st) {
                var d1 = st.devices.filter(function (x) { return x.id === 'node//d1'; })[0];
                check('wg status: device table joined (windows only, given first)', st.devices.length === 3 && d1.last.ok === 1 && d1.given === 'Given1' && st.config.excludeNodes.indexOf('node//d3') >= 0, st.devices);
                obj3.wgResults['node//d1'] = { time: new Date().toISOString(), winget: true, dry: true, results: [{ id: 'Foo.Bar', name: 'Foo', from: '1', to: '2', state: 'dry-run' }] };
                post({ action: 'wg_status' }, function (st2) {
                    var dd = st2.devices.filter(function (x) { return x.id === 'node//d1'; })[0];
                    check('wg status: dry run counted as would-update', dd.last.dry === true && dd.last.would === 1 && dd.last.failed === 0, dd.last);
                    obj3.pluginSettings.wingetUpdater = { enabled: false };
                check('wg timer: hourly due-check sweep armed', wgTimers.indexOf(obj3.WINGET_SWEEP_MS) >= 0, wgTimers);
                });
                next();
            });
            });
        });
    });
});

steps.push(function (next) {
    // realistic upgrade (v3.0.1): installer unpacks new files, then re-requires the CACHED module and
    // calls server_startup on a NEW instance of the OLD code - that instance must notice it and reload.
    var base = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-upg-'));
    var pd = path.join(base, 'plugins', 'inventoryscanner');
    fs.mkdirSync(pd, { recursive: true });
    var srcDir = path.join(__dirname, '..');
    ['inventoryscanner.js', 'cpe-table.json'].forEach(function (f) { fs.copyFileSync(path.join(srcDir, f), path.join(pd, f)); });
    // v3.5.1: the feature modules live in lib/ - the installer unpacks them next to the entry file,
    // so the entry must require them by obj.pluginDir (never by a lib module's own __dirname).
    fs.mkdirSync(path.join(pd, 'lib'), { recursive: true });
    fs.readdirSync(path.join(srcDir, 'lib')).forEach(function (f) { fs.copyFileSync(path.join(srcDir, 'lib', f), path.join(pd, 'lib', f)); });
    fs.writeFileSync(path.join(pd, 'config.json'), fs.readFileSync(path.join(srcDir, 'config.json'), 'utf8').replace(/"version":\s*"[^"]+"/, '"version": "0.0.1"'));
    var ms2 = { db: db, datapath: base, debug: function () { }, config: { settings: { vulnerabilityScanner: { scanIntervalHours: 0, cpeTableEnabled: false }, inventoryScanner: { collectIntervalMinutes: 0 } } }, webserver: {} };
    var ph = { parent: ms2, plugins: {}, exports: {} };
    var oldInst = require(path.join(pd, 'inventoryscanner.js')).inventoryscanner(ph);
    fs.writeFileSync(path.join(pd, 'config.json'), fs.readFileSync(path.join(pd, 'config.json'), 'utf8').replace('"0.0.1"', '"0.0.2"'));
    fs.appendFileSync(path.join(pd, 'inventoryscanner.js'), '\nmodule.exports.__upgradedCode = true;\n');
    var second = require(path.join(pd, 'inventoryscanner.js')).inventoryscanner(ph); // cached module, like pluginHandler
    ph.plugins.inventoryscanner = second; ph.exports.inventoryscanner = second.exports;
    check('upgrade (real installer flow): a new instance of cached code still reports the OLD code version', second.PLUGIN_VERSION === '0.0.1', second.PLUGIN_VERSION);
    second.server_startup();
    var mod = require.cache[require.resolve(path.join(pd, 'inventoryscanner.js'))];
    check('upgrade (real installer flow): server_startup reloads the new code and swaps it in', mod && mod.exports.__upgradedCode === true && ph.plugins.inventoryscanner !== second && ph.plugins.inventoryscanner.PLUGIN_VERSION === '0.0.2', ph.plugins.inventoryscanner.PLUGIN_VERSION);
    check('upgrade: only the newest instance keeps timers alive', oldInst.timerValid(oldInst.timerGen) === false && second.timerValid(second.timerGen) === false && ph.plugins.inventoryscanner.timerValid(ph.plugins.inventoryscanner.timerGen) === true);
    // v3.5.1: the swap must also pull the lib/ modules of the NEW folder - a module that resolved a
    // library by its own __dirname would silently keep running the old code (obj.pluginDir is the fix).
    check('upgrade: the lib/ modules are re-required from the new folder', (function () {
        try { return require.cache[require.resolve(path.join(pd, 'lib', 'routes.js'))] != null; } catch (e) { return false; }
    })());
    ph.plugins.inventoryscanner.timerGen++;
    next();
});

steps.push(function (next) {
    // v4.3.2: under MeshCentral's launcher (--launch) the upgrade restarts the server instead of the
    // hot swap: one Upgrade click, the new process loads the new code from a clean state.
    var base = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-rst-'));
    var pd = path.join(base, 'plugins', 'inventoryscanner');
    fs.mkdirSync(path.join(pd, 'lib'), { recursive: true });
    var srcDir = path.join(__dirname, '..');
    ['inventoryscanner.js', 'cpe-table.json'].forEach(function (f) { fs.copyFileSync(path.join(srcDir, f), path.join(pd, f)); });
    fs.readdirSync(path.join(srcDir, 'lib')).forEach(function (f) { fs.copyFileSync(path.join(srcDir, 'lib', f), path.join(pd, 'lib', f)); });
    // the whole views/ tree, exactly like the installer unpacks it - since v5.3.0 the panel is composed of
    // handlebars partials under views/partials/, and an unresolved partial is a render error
    (function copyTree(rel) {
        var s = path.join(srcDir, rel), d = path.join(pd, rel);
        fs.mkdirSync(d, { recursive: true });
        fs.readdirSync(s, { withFileTypes: true }).forEach(function (e) {
            if (e.isDirectory()) { copyTree(path.join(rel, e.name)); }
            else { fs.copyFileSync(path.join(s, e.name), path.join(d, e.name)); }
        });
    })('views');
    fs.writeFileSync(path.join(pd, 'config.json'), fs.readFileSync(path.join(srcDir, 'config.json'), 'utf8').replace(/"version":\s*"[^"]+"/, '"version": "0.0.1"'));
    var events = [];
    var ms3 = { db: db, datapath: base, debug: function () { }, args: { launch: '1234' }, DispatchEvent: function (t, s, e) { events.push(e); },
        config: { settings: { vulnerabilityScanner: { scanIntervalHours: 0, cpeTableEnabled: false }, inventoryScanner: { collectIntervalMinutes: 0 } } }, webserver: {} };
    var ph = { parent: ms3, plugins: {}, exports: {} };
    var inst = require(path.join(pd, 'inventoryscanner.js')).inventoryscanner(ph);
    ph.plugins.inventoryscanner = inst;
    fs.writeFileSync(path.join(pd, 'config.json'), fs.readFileSync(path.join(pd, 'config.json'), 'utf8').replace('"0.0.1"', '"0.0.2"'));
    fs.writeFileSync(path.join(pd, 'lib', 'routes.js'), ''); // installer still busy: lib/ is unpacked last
    var exits = [], logged = [];
    inst.exitProcess = function (c) { exits.push(c); };
    inst.UPGRADE_RESTART_DELAY_MS = 10; inst.UPGRADE_RESTART_POLL_MS = 50;
    var noLauncher = ms3.args; ms3.args = {};
    var noLauncherOk = inst.canRestartServer() === false;
    ms3.args = noLauncher;
    check('restart: canRestartServer only under the MeshCentral launcher', inst.canRestartServer() === true && noLauncherOk);
    var genBefore = inst.timerGen;
    inst.server_startup();
    check('restart: no hot swap in the old instance, its timers stop', ph.plugins.inventoryscanner === inst && inst.__superseded === true && inst.timerValid(genBefore) === false);
    setTimeout(function () {
        check('restart: waits while the unpacked tree is incomplete', exits.length === 0 && inst.upgradeTreeReady('0.0.2') === false);
        fs.copyFileSync(path.join(srcDir, 'lib', 'routes.js'), path.join(pd, 'lib', 'routes.js'));
        var origLog = console.log;
        console.log = function (m) { logged.push(String(m)); origLog.apply(console, arguments); };
        setTimeout(function () {
            console.log = origLog;
            check('restart: complete tree -> launcher restart line + exit code 0 (MeshCentral resetserver semantics)',
                exits.length === 1 && exits[0] === 0 && logged.indexOf('Server restart...') >= 0, [exits, logged]);
            check('restart: admins get a default-domain toast before the restart', events.length === 1 && events[0].domain === '' && /0\.0\.2/.test(events[0].value), events);
            var lg = fs.readFileSync(path.join(inst.nvdDataPath, 'nvd-download.log'), 'utf8');
            check('restart: logged in the Settings-tab log (nvd-download.log), not in the winget log', lg.indexOf('restarting the MeshCentral server to load it') >= 0 && lg.indexOf('restarting MeshCentral now to activate plugin version 0.0.2') >= 0 &&
                !(fs.existsSync(inst.wingetLogPath) && fs.readFileSync(inst.wingetLogPath, 'utf8').indexOf('restarting') >= 0));
            // v5.3.0: the panel is composed of handlebars partials, and the installer unpacks views/ LAST -
            // an unresolved partial is a render error, so the tree must not be declared ready without them.
            var partFile = path.join(pd, 'views', 'partials', 'panels', 'reset.handlebars');
            var partBackup = fs.readFileSync(partFile, 'utf8');
            check('restart: a complete tree INCLUDING every partial is ready', inst.upgradeTreeReady('0.0.2') === true);
            fs.writeFileSync(partFile, '');
            check('restart: an EMPTY partial makes the tree incomplete', inst.upgradeTreeReady('0.0.2') === false);
            fs.writeFileSync(partFile, partBackup);
            fs.renameSync(partFile, partFile + '.missing');
            check('restart: a MISSING partial makes the tree incomplete too', inst.upgradeTreeReady('0.0.2') === false);
            fs.renameSync(partFile + '.missing', partFile);
            check('restart: restoring the partial makes the tree ready again', inst.upgradeTreeReady('0.0.2') === true);
            next();
        }, 2500);
    }, 300);
});

// ---- v3.1.0: big NVD feeds, distro-managed packages, OS lifecycle, Windows release CPEs ----
steps.push(function (next) {
    // splitter == whole parse; a feed above the whole-parse limit is indexed (2026 feed is ~520 MB)
    var feed = { format: 'NVD_CVE', vulnerabilities: [] };
    for (var i = 0; i < 40; i++) {
        feed.vulnerabilities.push({ cve: { id: 'CVE-2026-' + (10000 + i), published: '2026-01-01T00:00:00', descriptions: [{ lang: 'en', value: 'a "quoted" {brace} \\ and } text ' + i }],
            configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: 'cpe:2.3:a:acme:tool' + (i % 3) + ':*:*:*:*:*:*:*:*', versionEndExcluding: '2.0' }] }] }] } });
    }
    var dir = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-feed-'));
    var fp = path.join(dir, 'nvdcve-2.0-2026.json');
    fs.writeFileSync(fp, JSON.stringify(feed, null, 1));
    var mk = function () { return factory({ parent: { db: db, datapath: fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-f2-')), debug: function () { }, config: { settings: {} }, webserver: {} } }); };
    var a = mk(), b = mk();
    a.loadNvdFromFile(fp);
    b.NVD_WHOLE_PARSE_MAX = 10; // force the splitter
    var nb = b.loadNvdFromFile(fp);
    check('nvd: big-feed splitter indexes exactly what the whole parse indexes (strings with braces/quotes/escapes)',
        nb === 40 && a.allCves.length === 40 && b.allCves.length === 40 && JSON.stringify(Object.keys(a.productIndex).sort()) === JSON.stringify(Object.keys(b.productIndex).sort()) &&
        b.allCves[3].description === a.allCves[3].description, [nb, a.allCves.length, b.allCves.length]);
    var bad = mk(); bad.NVD_WHOLE_PARSE_MAX = 10;
    fs.writeFileSync(fp, '{"vulnerabilities":[{"cve":{"id":"CVE-2026-1"}}');
    check('nvd: a truncated big feed is reported, never half-indexed silently', bad.loadNvdFromFile(fp) === 0);
    next();
});

steps.push(function (next) {
    var o5 = factory({ parent: { db: db, datapath: fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-lc-')), debug: function () { }, config: { settings: {} }, webserver: {} } });
    var now = Date.parse('2026-11-12T00:00:00Z');
    o5.osLifecycle = {
        ubuntu: { fetched: new Date(now).toISOString(), cycles: o5.sanitizeLifecycleCycles([{ cycle: '24.04', eol: '2029-05-31', lts: true }, { cycle: '20.04', eol: '2025-05-29' }, { cycle: 'x;rm', eol: '2099-01-01' }]) },
        windows: { fetched: new Date(now).toISOString(), cycles: o5.sanitizeLifecycleCycles([{ cycle: '11-25h2-w', eol: '2027-10-12' }, { cycle: '11-23h2-w', eol: '2025-11-11' }, { cycle: '11-23h2-e', eol: '2026-11-10' }]) }
    };
    check('lifecycle: hostile cycle names are dropped by the sanitizer', o5.osLifecycle.ubuntu.cycles.length === 2);
    check('lifecycle: Ubuntu 24.04 supported, 20.04 end of life, unknown distro unknown',
        o5.osSupportState('Ubuntu 24.04.5 LTS', now).state === 'supported' && o5.osSupportState('Ubuntu 20.04.6 LTS', now).state === 'eol' && o5.osSupportState('Gentoo', now).state === 'unknown');
    check('lifecycle: Windows release + edition resolve to the right cycle (Pro = W, Enterprise = E)',
        o5.osSupportState('Microsoft Windows 11 Pro - 25H2/26200', now).state === 'supported' && o5.osSupportState('Microsoft Windows 11 Pro - 23H2/22631', now).state === 'eol' &&
        o5.osSupportState('Microsoft Windows 11 Enterprise - 23H2/22631', now).state === 'eol' && o5.osSupportState('Microsoft Windows 11 Enterprise - 23H2/22631', Date.parse('2026-11-01T00:00:00Z')).state === 'supported');
    check('lifecycle: no data means unknown, never "supported"', factory({ parent: { db: db, datapath: fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-lc0-')), debug: function () { }, config: { settings: {} }, webserver: {} } }).osSupportState('Ubuntu 24.04.5 LTS').state === 'unknown');

    var pkgs = [
        { name: 'python3-six', version: '1.16.0-4', publisher: 'Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>', location: 'dpkg' },
        { name: 'openssh-server', version: '1:9.6p1-3ubuntu13.20', publisher: 'Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>' },
        { name: 'docker-ce', version: '5:29.6.2-1~ubuntu.24.04~noble', publisher: 'Docker <support@docker.com>', location: 'dpkg' },
        { name: 'Mozilla Firefox', version: '121.0', publisher: 'Mozilla' }
    ];
    o5.scanDeviceSoftware(pkgs, function (rs) {
        var st = rs.map(function (x) { return x.software + '=' + x.status; });
        check('distro: distribution packages are "distro-managed" on a supported OS (also without the location field)',
            rs[0].status === 'distro-managed' && rs[1].status === 'distro-managed' && rs[0].isCve === false && /Ubuntu 24\.04/.test(rs[0].description), st);
        check('distro: third-party repository packages (docker.com) and Windows apps are NOT exempted',
            rs.filter(function (x) { return x.software === 'docker-ce'; })[0].status.indexOf('distro') < 0 && rs.filter(function (x) { return x.software === 'Mozilla Firefox'; })[0].status.indexOf('distro') < 0, st);
        o5.scanDeviceSoftware(pkgs.slice(0, 1), function (rEol) {
            check('distro: same package on an end-of-life release is "distro-eol"', rEol[0].status === 'distro-eol' && rEol[0].distro === 'eol', rEol[0].status);
            var eolF = o5.osEolFinding({ osdesc: 'Ubuntu 20.04.6 LTS' });
            check('distro: an end-of-life OS raises exactly one OS-EOL finding, a supported one none',
                eolF != null && eolF.cve === 'OS-EOL' && eolF.severity === 'CRITICAL' && o5.osEolFinding({ osdesc: 'Ubuntu 24.04.5 LTS' }) === null);
            o5.pluginSettings = { vulnerabilityScanner: { distroManaged: false } };
            o5.scanDeviceSoftware(pkgs.slice(0, 1), function (rOff) {
                check('distro: the rule can be switched off (then the package goes through normal matching)', rOff[0].status.indexOf('distro') < 0, rOff[0].status);
                o5.pluginSettings = {};
                next();
            }, { osDesc: 'Ubuntu 24.04.5 LTS' });
        }, { osDesc: 'Ubuntu 20.04.6 LTS' });
    }, { osDesc: 'Ubuntu 24.04.5 LTS' });
});

steps.push(function (next) {
    // lifecycle fetch: https only via the indirection, one request per product, cache written, failures kept
    var o6 = factory({ parent: { db: db, datapath: fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-lf-')), debug: function () { }, config: { settings: {} }, webserver: {} } });
    var urls = [];
    o6.osLifecycleHttpGet = function (u, cb) { urls.push(u); if (/ubuntu\.json$/.test(u)) { cb(null, JSON.stringify([{ cycle: '24.04', eol: '2029-05-31' }])); } else { cb(new Error('offline')); } };
    o6.maybeFetchOsLifecycle(function (e, r) {
        check('lifecycle fetch: one https request per product from the default endoflife.date API', urls.length === o6.OS_LIFECYCLE_SLUGS.length && urls.every(function (u) { return u.indexOf('https://endoflife.date/api/') === 0; }) && r.ok === 1 && r.failed === urls.length - 1, [urls.length, r]);
        check('lifecycle fetch: cache written and reloadable', fs.existsSync(o6.osLifecyclePath) && (function () { o6.osLifecycle = {}; o6.loadOsLifecycle(); return o6.osLifecycle.ubuntu && o6.osLifecycle.ubuntu.cycles[0].eol === '2029-05-31'; })());
        urls.length = 0;
        o6.maybeFetchOsLifecycle(function (e2, r2) {
            check('lifecycle fetch: fresh products are not fetched again, failed ones are retried', urls.indexOf('https://endoflife.date/api/ubuntu.json') < 0 && urls.length === o6.OS_LIFECYCLE_SLUGS.length - 1, urls.length);
            o6.pluginSettings = { vulnerabilityScanner: { osLifecycleEnabled: false } }; urls.length = 0;
            o6.maybeFetchOsLifecycle(function () {
                check('lifecycle fetch: disabled means no request at all', urls.length === 0);
                o6.handleAdminPostReq({ headers: XHDR, body: { action: 'save_settings', scanIntervalHours: '24', updateHours: '168', anyCveMaxAgeYears: '5', collectIntervalMinutes: '1440', notifyThreshold: 'HIGH', osLifecycleUrl: 'http://insecure.example/api/' } },
                    mockRes(function (d) { check('lifecycle settings: non-https API URL rejected', !!d.error && /lifecycle/i.test(d.error), d); next(); }), user);
            });
        });
    });
});

steps.push(function (next) {
    // Windows OS matching: release-specific CPE + full build; no blanket "all versions" findings
    var o7 = factory({ parent: { db: db, datapath: fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-win-')), debug: function () { }, config: { settings: {} }, webserver: {} } });
    var cve = function (id) { return { id: id, severity: 'HIGH', cvss: 8, description: 'x', published: '2026-10-01', references: [] }; };
    o7.productIndex['microsoft|windows_11'] = [{ part: 'o', kind: 'any', cves: [cve('CVE-2021-0001')] }];
    o7.productIndex['microsoft|windows_11_25h2'] = [{ part: 'o', kind: 'range', endExc: '10.0.26200.9711', cves: [cve('CVE-2026-0001')] }];
    check('winos: target uses the release CPE and the full build', JSON.stringify(o7.windowsOsTarget('Microsoft Windows 11 Pro - 25H2/26200', '10.0.26200.9711')) === JSON.stringify({ product: 'windows_11_25h2', build: '10.0.26200.9711' }));
    check('winos: patched build -> no OS CVE; older build -> the bounded CVE; generic all-version entries never reported',
        o7.scanDeviceOs('Microsoft Windows 11 Pro - 25H2/26200', '10.0.26200.9711').length === 0 &&
        o7.scanDeviceOs('Microsoft Windows 11 Pro - 25H2/26200', '10.0.26200.6899').map(function (x) { return x.cve; }).join() === 'CVE-2026-0001');
    check('winos: without the full build (old agent, bare "26200") nothing is asserted', o7.scanDeviceOs('Microsoft Windows 11 Pro - 25H2/26200', '26200').length === 0);
    next();
});

steps.push(function (next) {
    // generic publisher -> vendor evidence: only vendors that exist in the loaded NVD application data
    var o8 = factory({ parent: { db: db, datapath: fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-pv-')), debug: function () { }, config: { settings: {} }, webserver: {} } });
    o8.cpeVendorTokens = { jetbrains: 1, apache_friends: 1, nero: 1 };
    check('vendor: legal forms stripped, accepted only when the vendor exists in NVD',
        o8.deriveVendorFromPublisher('JetBrains s.r.o.') === 'jetbrains' && o8.deriveVendorFromPublisher('Apache Friends') === 'apache_friends' &&
        o8.deriveVendorFromPublisher('Nero AG') === 'nero' && o8.deriveVendorFromPublisher('Unknown Widgets GmbH') === '' &&
        o8.deriveVendorFromPublisher('Ubuntu Developers <x@lists.ubuntu.com>') === '');
    // shipped table: python row no longer swallows python3-* package names; Teams add-in is not the Teams client
    var tbl = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'cpe-table.json'), 'utf8'));
    var first = function (n) { var e = tbl.entries.filter(function (x) { return new RegExp(x.match, 'i').test(n); })[0]; return e ? e.vendor + ':' + e.product : null; };
    check('table: python3-* library packages and "Python Launcher" are not the interpreter; "Python 3.12.4 (64-bit)" is',
        first('python3-six') === null && first('Python Launcher') === null && first('Python 3.12.4 (64-bit)') === 'python:python', [first('python3-six'), first('Python 3.12.4 (64-bit)')]);
    check('table: Teams Meeting Add-in is not reported with Teams client CVEs; Nextcloud desktop client is not the server',
        first('Microsoft Teams Meeting Add-in for Microsoft Office') === 'microsoft:teams_meeting_add-in' && first('Microsoft Teams') === 'microsoft:teams' &&
        first('Nextcloud 3.17.3.20251009') === 'nextcloud:desktop' && first('Nextcloud Talk (Machine - MSI)') === null);
    check('table: new verified rows resolve (examples)', first('Dell Display Manager 2.1') === 'dell:display_manager' && first('JetBrains TeamCity 2019.1.4') === 'jetbrains:teamcity' && first('Visual Studio Build Tools 2019') === 'microsoft:visual_studio_2019');
    next();
});

// ---- v3.5.0: force OS updates / force OS Upgrade ----
steps.push(function (next) {
    var dpO = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-os-'));
    var sentO = [];
    var osNodes = [
        { _id: 'node//w23', meshid: 'mesh//grp1', rname: 'w23', name: 'Win23', osdesc: 'Microsoft Windows 11 Pro - 23H2/22631' },
        { _id: 'node//w25', meshid: 'mesh//grp1', rname: 'w25', name: 'Win25', osdesc: 'Microsoft Windows 11 Pro - 25H2/26200' },
        { _id: 'node//u22', meshid: 'mesh//grp2', rname: 'u22', name: 'Ubu22', osdesc: 'Ubuntu 22.04.5 LTS' },
        { _id: 'node//u24', meshid: 'mesh//grp2', rname: 'u24', name: 'Ubu24', osdesc: 'Ubuntu 24.04.3 LTS' },
        { _id: 'node//mac', meshid: 'mesh//grp2', rname: 'mac', name: 'Mac', osdesc: 'macOS 15' },
        { _id: 'node//none', meshid: 'mesh//grp2', rname: 'none', name: 'NoOs' }
    ];
    var dbO = { GetAllType: function (t, cb) { cb(null, t === 'node' ? osNodes.slice() : meshes.slice()); }, Get: function (id, cb) { cb(null, osNodes.filter(function (n) { return n._id === id; })); } };
    var agents = {};
    osNodes.forEach(function (n) { agents[n._id] = { send: function (m) { sentO.push(JSON.parse(m)); } }; });
    var oO = factory({ parent: { db: dbO, datapath: dpO, debug: function () { }, config: { settings: {} }, webserver: { meshes: {}, wsagents: agents }, DispatchEvent: function () { } } });
    var gunz = function (cmd, re) { var mm = String(cmd).match(re); return mm ? require('zlib').gunzipSync(Buffer.from(mm[1], 'base64')).toString('utf8') : ''; };

    check('os: platform detection (unknown OS and macOS are never targeted)',
        oO.osPlatformOf(osNodes[0]) === 'windows' && oO.osPlatformOf(osNodes[2]) === 'linux' && oO.osPlatformOf(osNodes[4]) === null && oO.osPlatformOf(osNodes[5]) === null);

    // no lifecycle data -> NO assumed release: state unknown with a reason, never "outdated"/"current"
    var uw = oO.osUpgradeInfo(osNodes[0].osdesc), uu = oO.osUpgradeInfo(osNodes[2].osdesc);
    check('os: without lifecycle data the current release is unknown (no built-in fallback version)',
        oO.osCurrentWindows11().release === '' && oO.osCurrentUbuntuLts().release === '' && typeof oO.OS_FALLBACK_CURRENT === 'undefined' &&
        uw.state === 'unknown' && uw.outdated === false && uw.method === null && /unknown/.test(uw.note) && uu.state === 'unknown' && uu.method === null, [uw, uu]);
    var fresh = new Date().toISOString();
    oO.osLifecycle = { windows: { fetched: '2020-01-01T00:00:00Z', cycles: [{ cycle: '11-25h2-w' }] }, ubuntu: { fetched: fresh, cycles: [{ cycle: '24.04', lts: true }] } };
    check('os: stale lifecycle data (>30 days) is not trusted to name the current release, the reason says so',
        oO.osCurrentWindows11().release === '' && /older than 30 days/.test(oO.osCurrentWindows11().reason) && oO.osCurrentUbuntuLts().release === '24.04');
    oO.osLifecycle = { windows: { fetched: fresh, cycles: [{ cycle: '11-26h1-w' }, { cycle: '11-25h2-e' }, { cycle: '11-23h2-w' }] }, ubuntu: { fetched: fresh, cycles: [{ cycle: '26.04', lts: true }, { cycle: '25.10', lts: false }, { cycle: '24.04', lts: true }] } };
    check('os: the current release follows the lifecycle data (newest Windows 11 release, newest Ubuntu LTS)',
        oO.osCurrentWindows11().release === '26h1' && oO.osCurrentUbuntuLts().release === '26.04');
    check('os: 23H2, 25H2, 22.04 and 24.04 are outdated against 26H1 / 26.04 and get the right method + target (no support end in this fixture -> "available", never guessed "urgent")',
        oO.osUpgradeInfo(osNodes[0].osdesc).method === 'windows-feature' && oO.osUpgradeInfo(osNodes[0].osdesc).target === '26H1' &&
        oO.osUpgradeInfo(osNodes[1].osdesc).state === 'available' && oO.osUpgradeInfo(osNodes[2].osdesc).method === 'ubuntu-release' &&
        oO.osUpgradeInfo(osNodes[2].osdesc).target === '26.04' && oO.osUpgradeInfo(osNodes[3].osdesc).state === 'available' &&
        oO.osUpgradeInfo(osNodes[0].osdesc).urgent === false && /support end unknown/.test(oO.osUpgradeInfo(osNodes[0].osdesc).urgentReason));
    check('os: a release equal to the newest one is current; Windows 11 without a reported release is unknown',
        oO.osUpgradeInfo('Microsoft Windows 11 Pro - 26H1/28000').state === 'current' && oO.osUpgradeInfo('Ubuntu 26.04 LTS').state === 'current' &&
        oO.osUpgradeInfo('Microsoft Windows 11 Pro').state === 'unknown');
    // for the batch tests below: 25H2 / 24.04 are the newest in this fixture
    oO.osLifecycle = { windows: { fetched: fresh, cycles: [{ cycle: '11-25h2-w' }, { cycle: '11-23h2-w' }] }, ubuntu: { fetched: fresh, cycles: [{ cycle: '24.04', lts: true }, { cycle: '22.04', lts: true }] } };

    var wsU = oO.osBuildWindowsScript('update');
    var wsG = oO.osBuildWindowsScript('upgrade', '25H2');
    check('os win script: built-in Windows Update agent, feature upgrades skipped on update, marker before transcript stop',
        wsU.indexOf('Microsoft.Update.Session') >= 0 && wsU.indexOf("$invOsMode = 'update'") >= 0 && wsU.indexOf(oO.WU_UPGRADES_CATEGORY) >= 0 &&
            markerBeforeStop(wsU, oO.OS_MARKER) && wsU.indexOf('invscanner-osupdate.log') >= 0);
    check('os win script: upgrade sets and restores TargetReleaseVersion, never reboots',
        wsG.indexOf("$invTarget = '25H2'") >= 0 && wsG.indexOf("'TargetReleaseVersionInfo' -Value $invTarget") >= 0 && wsG.indexOf('Remove-ItemProperty') >= 0 &&
        !/Restart-Computer|shutdown/i.test(wsG));
    check('os win script (issue #1): upgrade makes the running wuauserv re-read the policy (service restart before the search AND after the restore), update mode never touches the service',
        (wsG.match(/Start-Service -Name wuauserv/g) || []).length === 2 && wsG.indexOf('Stop-Service -Name wuauserv') < wsG.indexOf('Microsoft.Update.Session') &&
        wsG.indexOf('Remove-ItemProperty') < wsG.lastIndexOf('Start-Service -Name wuauserv') && wsG.lastIndexOf('Start-Service -Name wuauserv') < wsG.indexOf('ConvertTo-Json') &&
        !/wuauserv|Restart-Service/i.test(wsU));
    check('os win script: an unvalidated target refuses to build', (function () { try { oO.osBuildWindowsScript('upgrade', "25H2';x"); return false; } catch (e) { return true; } })());
    var openers = wsG.split(String.fromCharCode(10)).filter(function (l) { return /[({]\s*$/.test(l); });
    check('os win script: one statement per line', openers.length === 0, openers.slice(0, 2));

    var lsU = oO.osBuildLinuxScript('update'), lsG = oO.osBuildLinuxScript('upgrade');
    check('os linux script: apt/dnf/zypper/pacman/apk update paths, stdin from /dev/null',
        lsU.indexOf('aptrefresh; if [ $APFAIL -eq 0 ]; then step upgrade apt-get $APTOPT upgrade; fi') >= 0 && lsU.indexOf('dnf -y upgrade') >= 0 && lsU.indexOf('zypper --non-interactive update') >= 0 &&
        lsU.indexOf('pacman -Syu --noconfirm') >= 0 && lsU.indexOf('apk upgrade') >= 0 && lsU.indexOf('< /dev/null') >= 0);
    check('os linux script (issue #2): one broken third-party repository no longer fails the run - aptrefresh keeps the apt W:/E: line as a NOTE and only fails when NO list was refreshed at all (then the install step is skipped, so stale lists are never reported ok)',
        /aptrefresh\(\) \{ step refresh apt-get -q update; if \[ \$RC -ne 0 \]/.test(lsU) &&
        lsU.indexOf("APE=$(grep -hE '^[WE]:' \"$LOG\" 2>/dev/null | tail -n 1 | cut -c1-160)") >= 0 &&
        lsU.indexOf("-name '*Packages' -mmin -60") >= 0 && lsU.indexOf('APWARN="apt-get update reported a repository problem: $APE (the other repositories worked)"; RC=0') >= 0 &&
        lsU.indexOf('NOTE="apt-get update refreshed no repository at all: $APE"; APFAIL=1') >= 0 &&
        lsU.indexOf('if [ -n "$APWARN" ]; then') >= 0 && !/step refresh apt-get -q update &&/.test(lsU), lsU.split(String.fromCharCode(10)).filter(function (l) { return l.indexOf('aptrefresh') >= 0; }));
    check('os linux script: upgrade = dist-upgrade + do-release-upgrade (Ubuntu only), never reboots',
        lsG.indexOf('dist-upgrade') >= 0 && lsG.indexOf('do-release-upgrade -f DistUpgradeViewNonInteractive') >= 0 && lsG.indexOf('ID=ubuntu') >= 0 &&
        lsG.indexOf('aptrefresh; if [ $APFAIL -eq 0 ]; then step dist-upgrade apt-get $APTOPT dist-upgrade; fi') >= 0 &&
        !/\breboot\s*$|shutdown -r|systemctl reboot/m.test(lsG));
    var lt = oO.osLinuxTransport(lsU);
    check('os linux transport: one line, gunzips back to the script', lt.indexOf(String.fromCharCode(10)) < 0 && gunz(lt, /echo '([A-Za-z0-9+\/=]+)'/) === lsU);

    oO.handleAdminPostReq({ headers: XHDR, body: { action: 'os_run', mode: 'reboot' } }, mockRes(function (dBad) {
        check('os route: unknown mode rejected', !!dBad.error, dBad);
        var savedLc = oO.osLifecycle; oO.osLifecycle = {};
        oO.handleAdminPostReq({ headers: XHDR, body: { action: 'os_run', mode: 'upgrade', scope: 'all' } }, mockRes(function (dUnk) {
        check('os route: upgrade without reference data is refused with a clear reason, nothing sent',
            dUnk.started === false && /current release is unknown/.test(dUnk.error || '') && sentO.length === 0 && oO.osBatchRunning === false, dUnk);
        oO.osLifecycle = savedLc;
        oO.handleAdminPostReq({ headers: XHDR, body: { action: 'os_run', mode: 'upgrade', scope: 'all' } }, mockRes(function (d) {
            check('os upgrade: only the outdated devices receive a script (23H2 + 22.04), right shell type each',
                d.started === true && sentO.length === 2 && sentO.filter(function (m) { return m.type === 1; }).length === 1 && sentO.filter(function (m) { return m.type === 3; }).length === 1 &&
                sentO.every(function (m) { return m.action === 'runcommands' && m.runAsUser === 0 && String(m.sessionid).indexOf('invscanner-os-') === 0; }), sentO.map(function (m) { return [m.type, m.sessionid]; }));
            var winMsg = sentO.filter(function (m) { return m.type === 1; })[0];
            check('os upgrade e2e: the Windows device gets the 25H2 upgrade script', gunz(winMsg.cmds, /FromBase64String\('([A-Za-z0-9+\/=]+)'\)/).indexOf("$invTarget = '25H2'") >= 0);
            var wgBusy = oO.wgStartBatch('manual', null, ['node//w25'], false);
            check('os batch: blocks a winget batch while it runs', wgBusy.busy === true);
            oO.onAgentResponse({ action: 'msg', type: 'runcommands', sessionid: winMsg.sessionid, result: 'x' + oO.OS_MARKER + '{"os":"windows","mode":"upgrade","target":"25H2","found":1,"installed":1,"failed":0,"reboot":true,"updates":{"title":"Windows 11, version 25H2","state":"ok","hresult":0},"error":""}' }, '', 'node//w23');
            var rw = oO.osResults['node//w23'];
            check('os parse: windows answer stored (single update unwrapped, reboot flagged)', rw && rw.state === 'ok' && rw.installed === 1 && rw.reboot === true && rw.updates.length === 1, rw);
            var linMsg = sentO.filter(function (m) { return m.type === 3; })[0];
            check('os route: a foreign session is never consumed', oO.onAgentResponse({ action: 'msg', type: 'runcommands', sessionid: 'user//x', result: 'y' }, '', 'node//u22') === false);
            oO.onAgentResponse({ action: 'msg', type: 'console', value: oO.OS_MARKER + '{"os":"linux","mode":"upgrade","pm":"apt","state":"reboot-needed","exit":0,"step":"release-upgrade","reboot":true,"note":"reboot first","log":"tail"}' + String.fromCharCode(10) }, '', 'node//u22');
            var rl = oO.osResults['node//u22'];
            check('os parse: linux answer via console channel, batch drained', rl && rl.state === 'reboot-needed' && rl.pm === 'apt' && oO.osBatchRunning === false && fs.existsSync(oO.osResultsPath), [rl, oO.osBatchRunning]);
            var lg = fs.readFileSync(oO.osLogPath, 'utf8');
            check('os log: per-device lines', lg.indexOf('node//w23 - OS upgrade ok: 1 found, 1 installed, 0 failed, REBOOT PENDING') >= 0 && lg.indexOf('node//u22 - OS upgrade reboot-needed via apt') >= 0, lg.split(String.fromCharCode(10)).slice(-4));
            sentO.length = 0;
            oO.handleAdminPostReq({ headers: XHDR, body: { action: 'os_run', mode: 'update' } }, mockRes(function (d2) {
                check('os update: every Windows/Linux device, none with an unknown OS or macOS', d2.started === true && sentO.length === 2 && oO.osQueue.length === 2, [sentO.length, oO.osQueue.length]);
                oO.handleAdminPostReq({ headers: XHDR, body: { action: 'os_status' } }, mockRes(function (st) {
                    var w23 = st.devices.filter(function (x) { return x.id === 'node//w23'; })[0];
                    check('os status: four devices, release state, running batch, last result',
                        st.devices.length === 4 && st.running === true && st.mode === 'update' && w23.outdated === true && w23.upgradable === true && w23.last.state === 'ok' && w23.pending != null, st);
                    oO.handleAdminPostReq({ headers: XHDR, body: { action: 'os_run', mode: 'upgrade', scope: 'all' } }, mockRes(function (d3) {
                        check('os route: second batch while one runs answers busy', d3.busy === true, d3);
                        oO.handleAdminPostReq({ headers: XHDR, body: { action: 'get_log', type: 'os' } }, mockRes(function (lgr) {
                            check('os log route: tail available', Array.isArray(lgr.lines) && lgr.lines.length > 0 && lgr.file === 'plugins/inventoryscanner/os-update.log', lgr);
                            next();
                        }), user);
                            }), user);
                        }), user);
                    }), user);
                }), user);
            }), user);
    }), user);
});

// ---- v3.6.0: upgrade urgency (current / available / urgent / unknown) + scope of the fleet upgrade ----
steps.push(function (next) {
    var nowU = Date.parse('2026-11-12T12:00:00Z');
    var fetchedU = new Date(nowU - 3600 * 1000).toISOString();
    var dbU = { GetAllType: function (t, cb) { cb(null, t === 'node' ? uNodes.slice() : meshes.slice()); }, Get: function (id, cb) { cb(null, uNodes.filter(function (n) { return n._id === id; })); } };
    var uNodes = [
        { _id: 'node//p23', meshid: 'mesh//grp1', name: 'Pro23', osdesc: 'Microsoft Windows 11 Pro - 23H2/22631' },
        { _id: 'node//p25', meshid: 'mesh//grp1', name: 'Pro25', osdesc: 'Microsoft Windows 11 Pro - 25H2/26200' },
        { _id: 'node//e25', meshid: 'mesh//grp1', name: 'Ent25', osdesc: 'Microsoft Windows 11 Enterprise - 25H2/26200' },
        { _id: 'node//p26', meshid: 'mesh//grp1', name: 'Pro26', osdesc: 'Microsoft Windows 11 Pro - 26H2/26300' },
        { _id: 'node//u22', meshid: 'mesh//grp2', name: 'Ubu22', osdesc: 'Ubuntu 22.04.5 LTS' },
        { _id: 'node//u24', meshid: 'mesh//grp2', name: 'Ubu24', osdesc: 'Ubuntu 24.04.5 LTS' },
        { _id: 'node//deb10', meshid: 'mesh//grp2', name: 'Deb10', osdesc: 'Debian GNU/Linux 10 (buster)' },
        { _id: 'node//deb12', meshid: 'mesh//grp2', name: 'Deb12', osdesc: 'Debian GNU/Linux 12 (bookworm)' }
    ];
    var sentU = [], agU = {};
    uNodes.forEach(function (n) { agU[n._id] = { send: function (m) { sentU.push(JSON.parse(m)); } }; });
    var oU = factory({ parent: { db: dbU, datapath: fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-urg-')), debug: function () { }, config: { settings: {} }, webserver: { meshes: {}, wsagents: agU }, DispatchEvent: function () { } } });
    oU.rescheduleAll = function () { };
    // excerpt of the real endoflife.date payloads (windows.json / ubuntu.json / debian.json, fetched 2026-11-12)
    oU.osLifecycle = {
        windows: { fetched: fetchedU, cycles: oU.sanitizeLifecycleCycles([
            { cycle: '11-26h2-e', eol: '2029-10-09' }, { cycle: '11-26h2-w', eol: '2028-10-10' },
            { cycle: '11-25h2-e', eol: '2028-10-10' }, { cycle: '11-25h2-w', eol: '2027-10-12' },
            { cycle: '11-23h2-e', eol: '2026-11-10' }, { cycle: '11-23h2-w', eol: '2025-11-11' }]) },
        ubuntu: { fetched: fetchedU, cycles: oU.sanitizeLifecycleCycles([
            { cycle: '26.04', lts: true, eol: '2031-05-29' }, { cycle: '25.10', lts: false, eol: '2026-07-01' },
            { cycle: '24.04', lts: true, eol: '2029-05-31' }, { cycle: '22.04', lts: true, eol: '2027-06-01' }]) },
        debian: { fetched: fetchedU, cycles: oU.sanitizeLifecycleCycles([{ cycle: '12', eol: '2028-06-30' }, { cycle: '10', eol: '2024-06-30' }]) }
    };
    var st = function (i) { return oU.osUpgradeInfo(uNodes[i].osdesc, nowU); };
    check('urgency: default window is 365 days', oU.scannerConfig().osUpgradeUrgentDays === 365);
    check('urgency: 23H2 Pro (support ended 2025-11-11) is urgent -> 26H2',
        st(0).state === 'urgent' && st(0).urgent === true && st(0).target === '26H2' && st(0).method === 'windows-feature' && /support ended 2025-11-11/.test(st(0).urgentReason), st(0));
    check('urgency: 25H2 Pro (334 days left) is urgent with 365, the SAME release on Enterprise (698 days left) is only available',
        st(1).state === 'urgent' && st(1).daysLeft === 334 && st(2).state === 'available' && st(2).daysLeft === 698 && st(2).eol === '2028-10-10', [st(1), st(2)]);
    check('urgency: the newest release is current, never urgent', st(3).state === 'current' && st(3).urgent === false && st(3).outdated === false, st(3));
    check('urgency: Ubuntu 22.04 (201 days left) urgent, 24.04 (931 days left) available, both -> 26.04 via do-release-upgrade',
        st(4).state === 'urgent' && st(4).daysLeft === 201 && st(5).state === 'available' && st(5).daysLeft === 931 && st(5).target === '26.04' && st(5).method === 'ubuntu-release', [st(4), st(5)]);
    check('urgency: platforms without a newer-release check - Debian 10 (ended) urgent but no automatic upgrade, Debian 12 (596 days) unknown',
        st(6).state === 'urgent' && st(6).method === null && st(6).outdated === true && st(7).state === 'unknown' && st(7).method === null && /596 days left/.test(st(7).note), [st(6), st(7)]);
    oU.pluginSettings = { vulnerabilityScanner: { osUpgradeUrgentDays: 0 } };
    check('urgency: window 0 = only after support ended (25H2 Pro and Ubuntu 22.04 become available, 23H2 stays urgent)',
        st(1).state === 'available' && st(4).state === 'available' && st(0).state === 'urgent', [st(1).state, st(4).state, st(0).state]);
    oU.pluginSettings = { vulnerabilityScanner: { osUpgradeUrgentDays: 334 } };
    var b334 = st(1).state;
    oU.pluginSettings = { vulnerabilityScanner: { osUpgradeUrgentDays: 335 } };
    check('urgency: exact boundary - 334 days left is available with a 334-day window and urgent with 335', b334 === 'available' && st(1).state === 'urgent', [b334, st(1).state]);
    oU.pluginSettings = { vulnerabilityScanner: { osUpgradeUrgentDays: 5000 } };
    check('urgency: an out-of-range config value is ignored (default 365 applies)', oU.scannerConfig().osUpgradeUrgentDays === 365);
    oU.pluginSettings = {};
    var savedDeb = oU.osLifecycle.ubuntu;
    oU.osLifecycle.ubuntu = { fetched: fetchedU, cycles: oU.sanitizeLifecycleCycles([{ cycle: '26.04', lts: true, eol: '2031-05-29' }, { cycle: '24.04', lts: true }]) };
    var noEol = oU.osUpgradeInfo('Ubuntu 24.04.5 LTS', nowU);
    check('urgency: an outdated release WITHOUT a known support end is "available" with that reason, never "urgent"',
        noEol.state === 'available' && noEol.urgent === false && /support end unknown/.test(noEol.urgentReason), noEol);
    oU.osLifecycle.ubuntu = savedDeb;

    // routes use Date.now(): pin the fixture relative to the real clock so the same states hold
    var shift = Date.now() - nowU;
    var mv = function (d) { return new Date(Date.parse(d + 'T00:00:00Z') + shift).toISOString().substring(0, 10); };
    ['windows', 'ubuntu', 'debian'].forEach(function (k) { oU.osLifecycle[k].fetched = new Date().toISOString(); oU.osLifecycle[k].cycles.forEach(function (c) { if (typeof c.eol === 'string') c.eol = mv(c.eol); }); });
    var postU = function (b, cb) { oU.handleAdminPostReq({ headers: XHDR, body: b }, mockRes(cb), user); };
    postU({ action: 'os_run', mode: 'upgrade' }, function (r1) {
        check('scope: a fleet-wide upgrade without scope is refused, nothing sent', /needs scope urgent or all/.test(r1.error || '') && sentU.length === 0, r1);
        postU({ action: 'os_run', mode: 'upgrade', scope: 'soon' }, function (r2) {
            postU({ action: 'os_run', mode: 'update', scope: 'urgent' }, function (r3) {
                check('scope: an invalid scope and a scope on mode update are refused', /scope must be urgent or all/.test(r2.error || '') && /only applies to mode upgrade/.test(r3.error || '') && sentU.length === 0, [r2, r3]);
                postU({ action: 'os_status' }, function (s1) {
                    var byId = {}; s1.devices.forEach(function (x) { byId[x.id] = x; });
                    check('os_status: per-device releaseState/urgent/eol/daysLeft/urgentReason, counts per state and the active window',
                        s1.urgentDays === 365 && s1.counts.urgent === 4 && s1.counts.available === 2 && s1.counts.current === 1 && s1.counts.unknown === 1 &&
                        byId['node//p25'].releaseState === 'urgent' && byId['node//p25'].urgent === true && byId['node//e25'].releaseState === 'available' &&
                        byId['node//e25'].upgradable === true && byId['node//deb10'].upgradable === false && byId['node//u24'].eol !== '' && typeof byId['node//u24'].daysLeft === 'number' &&
                        /support until/.test(byId['node//u24'].urgentReason), [s1.counts, s1.urgentDays]);
                    postU({ action: 'os_run', mode: 'upgrade', scope: 'urgent' }, function (r4) {
                        // OS_MAX_PARALLEL = 2: answer every sent session until the queue is drained
                        var answered = 0;
                        var drain = function () {
                            while (answered < sentU.length) {
                                var m = sentU[answered++];
                                oU.onAgentResponse({ action: 'msg', type: 'runcommands', sessionid: m.sessionid, result: oU.OS_MARKER + '{"os":"x","state":"ok","found":0,"installed":0,"failed":0,"updates":[]}' }, '', 'node//' + m.sessionid.substring('invscanner-os-'.length));
                            }
                        };
                        check('scope urgent: two scripts in flight at once (OS_MAX_PARALLEL), the third device is queued', sentU.length === 2 && oU.osQueue.length === 1, [sentU.length, oU.osQueue.length]);
                        drain();
                        var got = sentU.map(function (m) { return m.sessionid; }).sort().join();
                        check('scope urgent: only the urgent AND upgradable devices (23H2 Pro, 25H2 Pro, Ubuntu 22.04) get a script; Debian 10 is urgent but has no automatic upgrade',
                            r4.started === true && r4.scope === 'urgent' && got === 'invscanner-os-p23,invscanner-os-p25,invscanner-os-u22', got);
                        var lgU = fs.readFileSync(oU.osLogPath, 'utf8');
                        check('scope urgent: skipped devices are logged with their reason',
                            lgU.indexOf('node//e25 - not upgraded by the urgent batch, upgrade only available: support until') >= 0 &&
                            lgU.indexOf('node//deb10 - not upgraded, urgent but no automatic upgrade') >= 0 && lgU.indexOf('OS upgrade (urgent) batch starting for 3 device(s)') >= 0, lgU.split(String.fromCharCode(10)).slice(-8));
                        check('scope urgent: batch drained', oU.osBatchRunning === false, oU.osBatchRunning);
                        sentU.length = 0; answered = 0;
                        postU({ action: 'os_run', mode: 'upgrade', scope: 'all' }, function (r5) {
                            drain();
                            var got5 = sentU.map(function (m) { return m.sessionid; }).sort().join();
                            check('scope all: every outdated, upgradable device (urgent + available), still none without an automatic upgrade path',
                                r5.started === true && r5.scope === 'all' && got5 === 'invscanner-os-e25,invscanner-os-p23,invscanner-os-p25,invscanner-os-u22,invscanner-os-u24' && oU.osBatchRunning === false, got5);
                            next();
                        });
                    });
                });
            });
        });
    });
});

// ---- v3.6.0: the urgency window is a regular setting; the Settings tab no longer drops other sections ----
steps.push(function (next) {
    var oS = factory({ parent: { db: db, datapath: fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-set-')), debug: function () { }, config: { settings: {} }, webserver: {} } });
    oS.rescheduleAll = function () { };
    var base = { action: 'save_settings', scanIntervalHours: '24', updateHours: '168', anyCveMaxAgeYears: '5', collectIntervalMinutes: '1440', notifyThreshold: 'HIGH' };
    var withU = function (v) { var b = JSON.parse(JSON.stringify(base)); if (v !== undefined) { b.osUpgradeUrgentDays = v; } return b; };
    var postS = function (b, cb) { oS.handleAdminPostReq({ headers: XHDR, body: b }, mockRes(cb), user); };
    oS.pluginSettings = { wingetUpdater: { enabled: true, excludeNodes: ['node//keep'], ignorePackages: [{ id: 'Keep.Me', note: 'licence' }], updateMeshes: ['mesh//grp1'], pinSync: false } };
    postS(withU('200'), function (d1) {
        check('setting: osUpgradeUrgentDays saved, effective and reported with its source',
            !d1.error && d1.settings.osUpgradeUrgentDays === 200 && d1.sources.osUpgradeUrgentDays === 'file' && d1.sources.revertAllowed.osUpgradeUrgentDays === true && oS.scannerConfig().osUpgradeUrgentDays === 200, d1.settings && d1.settings.osUpgradeUrgentDays);
        check('settings save: the winget configuration (incl. the exclusion list used by OS batches) survives a Settings-tab save',
            oS.wingetConfig().excludeNodes.join() === 'node//keep' && oS.wingetConfig().ignorePackages[0].id === 'Keep.Me' && oS.wingetConfig().enabled === true && oS.wingetConfig().pinSync === false, oS.pluginSettings);
        postS(withU(undefined), function (d2) {
            check('setting: a save without the field keeps the saved value (older panels never reset it silently)', d2.settings.osUpgradeUrgentDays === 200, d2.settings.osUpgradeUrgentDays);
            postS(withU('-1'), function (d3) {
                postS(withU('3651'), function (d4) {
                    postS(withU('12.5'), function (d5) {
                        check('setting: negative, too large and non-integer values are refused', /OS upgrade urgency/.test(d3.error || '') && /OS upgrade urgency/.test(d4.error || '') && /OS upgrade urgency/.test(d5.error || '') && oS.scannerConfig().osUpgradeUrgentDays === 200, [d3.error, d4.error, d5.error]);
                        postS({ action: 'revert_setting', revertOsUpgradeUrgentDays: 'true' }, function (d6) {
                            check('setting: revert hands the key back to config.json / the default', d6.settings.osUpgradeUrgentDays === 365 && d6.sources.osUpgradeUrgentDays === 'default', d6.settings.osUpgradeUrgentDays);
                            postS({ action: 'save_settings', reset: 'true' }, function (d7) {
                                check('settings reset: clears the Settings-tab sections only, the winget configuration stays',
                                    d7.reset === true && oS.pluginSettings.vulnerabilityScanner === undefined && oS.wingetConfig().excludeNodes.join() === 'node//keep' &&
                                    JSON.parse(fs.readFileSync(oS.pluginSettingsPath, 'utf8')).wingetUpdater.ignorePackages[0].id === 'Keep.Me', oS.pluginSettings);
                                next();
                            });
                        });
                    });
                });
            });
        });
    });
});

steps.push(function (next) {
    // generated scripts must parse: PowerShell parser for the Windows script, sh -n for Linux
    var cp = require('child_process');
    var dir = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-ospp-'));
    var pW = path.join(dir, 'os.ps1');
    fs.writeFileSync(pW, obj.osBuildWindowsScript('upgrade', '25H2'));
    var psr = runPs(['-NoProfile', '-NonInteractive', '-Command', "$t=$null;$e=$null;[void][System.Management.Automation.Language.Parser]::ParseFile('" + pW + "',[ref]$t,[ref]$e);$e.Count"]);
    if (psr == null) { console.log('SKIP os script: PowerShell parser (PowerShell not available)'); }
    else { check('os win script: PowerShell parser reports no errors', !psr.failed && psr.text.trim() === '0', psr.text.trim()); }
    var pL = path.join(dir, 'os.sh');
    fs.writeFileSync(pL, obj.osBuildLinuxScript('upgrade'));
    var pL2 = path.join(dir, 'os-update.sh');
    fs.writeFileSync(pL2, obj.osBuildLinuxScript('update'));
    var shOk = null;
    ['sh', 'bash', 'C:\\Program Files\\Git\\bin\\sh.exe'].some(function (sh) {
        try { cp.execFileSync(sh, ['-n', pL], { stdio: 'pipe', timeout: 30000 }); cp.execFileSync(sh, ['-n', pL2], { stdio: 'pipe', timeout: 30000 }); shOk = true; return true; }
        catch (e) { if (e.status != null) { shOk = false; return true; } return false; }
    });
    if (shOk == null) { console.log('SKIP os script: sh -n (no POSIX shell available)'); }
    else { check('os linux script: sh -n reports no syntax errors (upgrade AND update)', shOk === true); }
    next();
});

// ---- issue #2: the aptrefresh() of the GENERATED linux script, executed by a real POSIX shell ----
steps.push(function (next) {
    var cp = require('child_process');
    var SH = ['sh', 'bash', 'C:\\Program Files\\Git\\bin\\sh.exe'].filter(function (s) { try { cp.execFileSync(s, ['-c', 'exit 0'], { stdio: 'pipe', timeout: 20000 }); return true; } catch (e) { return false; } })[0];
    if (SH == null) { console.log('SKIP aptrefresh harness: no POSIX shell available'); return next(); }
    var posix = function (p) { return String(p).split(path.sep).join('/'); };
    var src = obj.osBuildLinuxScript('update');
    var line = src.split(String.fromCharCode(10)).filter(function (l) { return l.indexOf('aptrefresh() {') === 0; })[0];
    if (typeof line !== 'string' || line.length < 100) { check('aptrefresh harness: the function is present in the generated script, so the harness runs the REAL code', false, String(line).substring(0, 60)); return next(); }
    check('aptrefresh harness: the function is present in the generated script, so the harness runs the REAL code', line.indexOf('aptrefresh()') === 0 && line.indexOf('/var/lib/apt/lists') > 0, line.substring(0, 60));
    var dir = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-apt-'));
    var logFile = posix(path.join(dir, 'osupdate.log'));
    if (logFile.indexOf("'") >= 0) { console.log('SKIP aptrefresh harness: temp path holds a quote'); return next(); }
    var bin = path.join(dir, 'bin'); fs.mkdirSync(bin, { recursive: true });
    function wfile(p, txt) { fs.writeFileSync(p, txt, { mode: 0o755 }); try { fs.chmodSync(p, 0o755); } catch (e) { } }
    wfile(path.join(bin, 'apt-get'), '#!/bin/sh\necho "W: GPG error: http://dl.google.com/linux/chrome/deb stable InRelease: The following signatures could not be verified" >&2\nexit 100\n');
    wfile(path.join(bin, 'find'), '#!/bin/sh\nif [ "$1" = "--version" ]; then echo "find (GNU findutils) 4.9"; exit 0; fi\nif [ "${FAKE_FRESH:-yes}" = "yes" ]; then echo "/var/lib/apt/lists/partial_x_Packages"; fi\nexit 0\n');
    var runner = path.join(dir, 'run.sh');
    wfile(runner, ['#!/bin/sh', "LOG='" + logFile + "'", 'RC=0; STEP=\'\'; NOTE=\'\'; APWARN=\'\'; APFAIL=0',
        'step() { STEP="$1"; shift; echo "== step: $*" >> "$LOG"; "$@" >> "$LOG" 2>&1 < /dev/null; RC=$?; return $RC; }',
        line, 'aptrefresh', 'echo "RC=$RC APFAIL=$APFAIL NOTE=$NOTE"', 'echo "APWARN=$APWARN"', ''].join(String.fromCharCode(10)));
    var out = { yes: '', no: '' };
    ['yes', 'no'].forEach(function (k) {
        try { out[k] = cp.execFileSync(SH, [posix(runner)], { encoding: 'utf8', timeout: 30000, env: Object.assign({}, process.env, { PATH: posix(bin) + path.delimiter + process.env.PATH, FAKE_FRESH: k }) }); }
        catch (e) { out[k] = 'HARNESS-FAILED ' + (e && e.message ? e.message : e); }
    });
    check('aptrefresh behaviour (issue #2): one broken repository + fresh lists -> RC=0, APFAIL=0, the apt W: line lands in APWARN (the run continues)',
        out.yes.indexOf('RC=0 APFAIL=0 NOTE=') === 0 && /APWARN=apt-get update reported a repository problem: W: GPG error/.test(out.yes) && /the other repositories worked/.test(out.yes), out.yes);
    check('aptrefresh behaviour (issue #2): nothing refreshed at all -> the non-zero exit STANDS and APFAIL=1, so the install step is skipped',
        /RC=100 APFAIL=1 NOTE=apt-get update refreshed no repository at all: W: GPG error/.test(out.no), out.no);
    next();
});

// ---- v4.0.0 software deploy: script builders ----
steps.push(function (next) {
    var taskW = { stageFile: 'invsw-0123456789abcdef-fedcba9876543210.msi', sha256: 'ab'.repeat(32), ext: 'msi', fileName: "Tool'set up.msi", args: "/qn DIR='C:\\x' FOO=1" };
    var sW = obj.swBuildWindowsScript(taskW);
    check('deploy win script: waits for the wget file and verifies SHA-256 before running anything',
        sW.indexOf("$invStage = 'C:\\Windows\\Temp\\invsw-0123456789abcdef-fedcba9876543210.msi'") >= 0 &&
        sW.indexOf('Get-FileHash') >= 0 && sW.indexOf('-ieq $invHash') >= 0 && sW.indexOf('AddMinutes($invWaitMin)') >= 0);
    check('deploy win script: silent msiexec with /qn /norestart, exit 3010/1641 reported ok+reboot, never reboots itself',
        sW.indexOf('/i "') >= 0 && sW.indexOf('/qn /norestart') >= 0 && sW.indexOf('$invExit -eq 3010') >= 0 &&
        !/Restart-Computer|shutdown/i.test(sW));
    check('deploy win script: single quotes in file name and args are doubled (PowerShell quoting), marker before Stop-Transcript',
        sW.indexOf("$invName = 'Tool''set up.msi'") >= 0 && sW.indexOf("$invArgs = '/qn DIR=''C:\\x'' FOO=1'") >= 0 &&
        markerBeforeStop(sW, obj.SW_MARKER) && sW.indexOf('invscanner-deploy.log') >= 0);
    check('deploy win script: a missing download answers state no-file and is never executed',
        sW.indexOf("state='no-file'") >= 0 && sW.indexOf('break }') >= 0);
    check('deploy win script (7z "no-file" report): the answer names WHICH case happened - nothing appeared vs a file whose hash never matched',
        sW.indexOf('$invSaw = 1') >= 0 && sW.indexOf('$invWhy') >= 0 && sW.indexOf('$invSeen = [string]$invH') >= 0 &&
        sW.indexOf('but its SHA-256 never matched') >= 0 && sW.indexOf('nothing ever appeared at ') >= 0 &&
        sW.indexOf("error=('the download never arrived on the device: ' + $invWhy)") >= 0);
    var msp = obj.swBuildWindowsScript({ stageFile: 'invsw-x.msp', sha256: taskW.sha256, ext: 'msp', fileName: 'p.msp', args: '' });
    check('deploy win script: .msp uses msiexec /update /quiet', msp.indexOf('/update "') >= 0 && msp.indexOf('/quiet /norestart') >= 0);
    var ex = obj.swBuildWindowsScript({ stageFile: 'invsw-x.exe', sha256: taskW.sha256, ext: 'exe', fileName: 'a.exe', args: '--silent' });
    check('deploy win script: .exe runs through Start-Process -Wait with the raw arguments, from the protected run folder',
        ex.indexOf('Start-Process -FilePath $invRun -ArgumentList $invArgs -WorkingDirectory $invRunDir -Wait -PassThru') >= 0 &&
        ex.indexOf('Start-Process -FilePath $invStage') < 0);
    var openers = sW.split(String.fromCharCode(10)).filter(function (l) { return /[({]\s*$/.test(l); });
    check('deploy win script: one statement per line', openers.length === 0, openers.slice(0, 2));
    var sC = obj.swBuildWindowsScript({ stageFile: 'invsw-x.bin', sha256: taskW.sha256, ext: 'bin', fileName: 'f.bin', args: "a\nb\r'c" });
    check('deploy: control characters never reach a script line',
        sC.split(String.fromCharCode(10)).every(function (l) { return l.indexOf('\r') < 0; }) && sC.indexOf("$invArgs = 'a b ''c'") >= 0);

    var taskL = { stageFile: 'invsw-0123456789abcdef-fedcba9876543210.deb', sha256: 'cd'.repeat(32), ext: 'deb', fileName: 'Pkg 1.0.deb', args: '--force-confnew' };
    var sL = obj.swBuildLinuxScript(taskL);
    check('deploy linux script: sha256sum check, dpkg noninteractive, stdin from /dev/null, never reboots',
        sL.indexOf('sha256sum') >= 0 && sL.indexOf('dpkg -i "$P"') >= 0 && sL.indexOf('DEBIAN_FRONTEND=noninteractive') >= 0 &&
        sL.indexOf('< /dev/null') >= 0 && !/shutdown -r|systemctl reboot/.test(sL));
    check('deploy linux script: the no-file note distinguishes "never appeared" from "hash never matched" (same as Windows)',
        sL.indexOf('GOT=0; SAW=0; SEEN=') >= 0 && sL.indexOf('SAW=1') >= 0 && sL.indexOf('but its sha256 never matched') >= 0 &&
        sL.indexOf('nothing ever appeared at $F') >= 0 && (sL.match(/\bfi\b/g) || []).length === (sL.match(/\bthen\b/g) || []).length);
    var sR = obj.swBuildLinuxScript({ stageFile: 'invsw-x.rpm', sha256: 'ab'.repeat(32), ext: 'rpm', fileName: 'r.rpm', args: '' });
    var sB = obj.swBuildLinuxScript({ stageFile: 'invsw-x.bin', sha256: 'ab'.repeat(32), ext: 'bin', fileName: 'run.bin', args: '-q' });
    check('deploy linux script: rpm and direct bin cases, chmod 700 before direct execution',
        sR.indexOf('rpm -Uvh "$P"') >= 0 && sB.indexOf('set -- "$P" $ARGS') >= 0 && sB.indexOf('chmod 700') >= 0);
    var sQ = obj.swBuildLinuxScript({ stageFile: 'invsw-x.sh', sha256: 'ab'.repeat(32), ext: 'sh', fileName: 'a b.sh', args: "x'y" });
    check('deploy linux script: single quotes in args use the \'"\'" escape idiom', sQ.indexOf("ARGS='x'\\''y'") >= 0, sQ.split(String.fromCharCode(10)).slice(3, 4));
    var sM = obj.swBuildLinuxScript({ stageFile: 'invsw-x.msi', sha256: 'ab'.repeat(32), ext: 'msi', fileName: 'w.msi', args: '' });
    check('deploy linux script: a Windows package on Linux is refused, never executed', sM.indexOf('cannot be deployed to Linux') >= 0);
    next();
});

// Fixture for the deploy route tests: mocked MeshCentral with a files area, cookie issuer and
// capturing agents. Every step builds its own fixture so test order never matters.
function makeDeployFixture() {
    var fx = { sent: [], events: [], cookies: [] };
    fx.dp = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-deploy-'));
    fx.fsp = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-files-'));
    fx.nodes = [
        { _id: 'node//w1', meshid: 'mesh//grp1', rname: 'swin1', name: 'WinOne', osdesc: 'Microsoft Windows 11 Pro - 25H2/26200' },
        { _id: 'node//l1', meshid: 'mesh//grp2', rname: 'sux1', name: 'LinOne', osdesc: 'Ubuntu 24.04.1 LTS' },
        { _id: 'node//mac1', meshid: 'mesh//grp1', rname: 'mac1', name: 'MacOne', osdesc: 'macOS 15' },
        { _id: 'node//off1', meshid: 'mesh//grp2', rname: 'offwin', name: 'OffOne', osdesc: 'Microsoft Windows 10' }
    ];
    var dbW = {
        GetAllType: function (t, cb) { cb(null, t === 'node' ? fx.nodes.slice() : meshes.slice()); },
        Get: function (id, cb) {
            if (sysinfo[id]) { cb(null, [sysinfo[id]]); return; }
            for (const n of fx.nodes) { if (n._id === id) { cb(null, [n]); return; } }
            cb(null, []);
        }
    };
    fx.agents = {};
    fx.node = function (id) { fx.agents[id] = { send: function (m) { fx.sent.push(JSON.parse(m)); } }; };
    fx.offlineNode = function (id) { delete fx.agents[id]; };
    fx.ms = {
        db: dbW, datapath: fx.dp, filespath: fx.fsp, args: {}, debug: function () { },
        config: { settings: {} },
        webserver: { meshes: { 'mesh//grp1': { name: 'HQ' }, 'mesh//grp2': { name: 'Branch' } }, wsagents: fx.agents, webCertificateFullHashs: { '': Buffer.from([0x01, 0x02, 0x3f]) } },
        DispatchEvent: function (t, s, e) { fx.events.push(e); },
        encodeCookie: function (o) { fx.cookies.push(o); return 'ck' + fx.cookies.length; },
        loginCookieEncryptionKey: Buffer.alloc(80, 7)
    };
    fx.o = factory({ parent: fx.ms });
    fx.o.swLoadFiles(); fx.o.swLoadTasks();
    fx.post = function (body, cb) { fx.o.handleAdminPostReq({ headers: XHDR, body: body }, mockRes(cb), user); };
    fx.wait = function (cond, done, timeoutMs) {
        var tries = 0, cap = Math.ceil((timeoutMs || 6000) / 10);
        (function poll() { if (cond()) { return done(); } if (++tries > cap) { return done(); } setTimeout(poll, 10); })();
    };
    fx.shaOf = function (buf) { return require('crypto').createHash('sha256').update(buf).digest('hex'); };
    fx.data = Buffer.alloc(49152 + 1000);
    for (var xi = 0; xi < fx.data.length; xi++) { fx.data[xi] = xi % 251; }
    fx.gunz = function (cmd, re) { var mm = String(cmd).match(re); return mm ? require('zlib').gunzipSync(Buffer.from(mm[1], 'base64')).toString('utf8') : ''; };
    fx.upload = function (cb) {
        var uid = 'aabbccddeeff0011223344', o = fx.o, chunk = o.SW_CHUNK_BYTES, data = fx.data, i = 0;
        var step = function () {
            var start = i * chunk, end = Math.min(data.length, start + chunk);
            fx.post({ action: 'sw_upload', uploadId: uid, name: '..\\evil.msi', index: i, data: data.slice(start, end).toString('base64url'), last: (end >= data.length) ? 'true' : 'false' }, function (d) {
                if (d.done) { return cb(d.file); }
                if (d.error) { return cb(null, d.error); }
                i++; step();
            });
        };
        step();
    };
    fx.task = function (body, cb) { fx.post(Object.assign({ action: 'sw_create_task', source: 'library', args: '' }, body), cb); };
    return fx;
}

// ---- v4.0.0 deploy: installer library, chunked upload, rescan, delete ----
steps.push(function (next) {
    var fx = makeDeployFixture();
    fx.post({ action: 'sw_files' }, function (f0) {
        check('deploy files: empty library reports a chunk size that keeps every POST below the 100kb urlencoded body limit',
            !f0.error && f0.files.length === 0 && f0.limits.chunkBytes === fx.o.SW_CHUNK_BYTES && f0.limits.chunkBytes * 2 < 100000 &&
            f0.limits.exts.indexOf('msi') >= 0 && f0.limits.exts.indexOf('zip') < 0, f0.limits);
        fx.post({ action: 'sw_upload', uploadId: 'ZZZZ', name: 'a.msi', index: 0, data: '', last: 'false' }, function (badId) {
            check('deploy upload: non-hex upload id rejected', !!badId.error, badId);
            fx.post({ action: 'sw_upload', uploadId: 'aabbccddeeff0011223344', name: 'tool.zip', index: 0, data: 'aGk=', last: 'false' }, function (zip) {
                check('deploy upload: unsupported extension refused (.zip is not an installer)', !!zip.error && /Unsupported file type/.test(zip.error), zip);
                var uid = 'aabbccddeeff0011223344';
                fx.post({ action: 'sw_upload', uploadId: uid, name: '..\\evil.msi', index: 0, data: fx.data.slice(0, fx.o.SW_CHUNK_BYTES).toString('base64url'), last: 'false' }, function (c0) {
                    check('deploy upload: chunk 0 accepted, path stripped from the display name', c0.ok === true && c0.next === 1, c0);
                    fx.post({ action: 'sw_upload', uploadId: uid, index: 2, data: 'aGk=', last: 'false' }, function (gap) {
                        check('deploy upload: a skipped chunk is refused and names the resume point', !!gap.error && gap.next === 1 && gap.have === fx.o.SW_CHUNK_BYTES, gap);
                        fx.upload(function (file, uerr) {
                            check('deploy upload: committing yields id, size and a real sha256 (name "evil.msi")',
                                !uerr && file && /^[a-f0-9]{12}$/.test(file.id) && file.size === fx.data.length && file.sha256 === fx.shaOf(fx.data) && file.name === 'evil.msi', uerr || file);
                            check('deploy upload: stored under the library folder, part deleted, index persisted',
                                fs.existsSync(path.join(fx.o.swFilesDir, file.id + '.msi')) && !fs.existsSync(path.join(fx.o.swPartsDir, uid + '.part')) &&
                                JSON.parse(fs.readFileSync(fx.o.swStorePath, 'utf8'))[file.id].name === 'evil.msi');
                            var fid = file.id;
                            fx.post({ action: 'sw_upload', uploadId: 'ee'.repeat(10), name: 'e.msi', index: 0, data: '', last: 'true' }, function (emp) {
                                check('deploy upload: an empty file is rejected at commit', !!emp.error && /empty/i.test(emp.error), emp);
                                // interrupted upload survives a restart (parts dir reload)
                                var uid3 = '1213141516';
                                fx.post({ action: 'sw_upload', uploadId: uid3, name: 'resume.msi', index: 0, data: Buffer.alloc(1000, 7).toString('base64url'), last: 'false' }, function (r0) {
                                    check('deploy upload: an interrupted upload survives swLoadFiles and can resume',
                                        r0.ok === true && (function () { fx.o.swLoadFiles(); return fx.o.swUploads[uid3] && fx.o.swUploads[uid3].bytes === 1000; })(), fx.o.swUploads[uid3]);
                                    postW2();
                                });
                            });
                            function postW2() {
                                fx.post({ action: 'sw_delete_file', fileId: fid }, function (delOk) {
                                    check('deploy delete: unused library entry is removed with its file',
                                        delOk.success === true && !fs.existsSync(path.join(fx.o.swFilesDir, fid + '.msi')) && fx.o.swFiles[fid] == null, delOk);
                                    var strayId = 'abcdef012345';
                                    fs.writeFileSync(path.join(fx.o.swFilesDir, strayId + '.exe'), 'MZ-exe-bytes');
                                    fx.post({ action: 'sw_rescan_library' }, function (rs) {
                                        var stray = (rs.files || []).filter(function (x) { return x.name === strayId + '.exe'; })[0];
                                        check('deploy rescan: a file placed in the server folder is indexed (renamed to <id>.exe, hash, display name kept)',
                                            rs.added === 1 && stray != null && stray.sha256 === fx.shaOf(Buffer.from('MZ-exe-bytes')) &&
                                            /^[a-f0-9]{12}$/.test(String(stray.id || '')) && fs.existsSync(path.join(fx.o.swFilesDir, stray.id + '.exe')) &&
                                            !fs.existsSync(path.join(fx.o.swFilesDir, strayId + '.exe')), rs);
                                        fx.o.swLog('marker-line-for-the-log-test');
                                        fx.post({ action: 'get_log', type: 'deploy' }, function (lg) {
                                            check('deploy log: tail served under plugins/inventoryscanner/software-deploy.log',
                                                lg.file === 'plugins/inventoryscanner/software-deploy.log' && lg.lines.some(function (l) { return l.indexOf('marker-line-for-the-log-test') >= 0; }), lg.file);
                                            next();
                                        });
                                    });
                                });
                            }
                        });
                    });
                });
            });
        });
    });
});

// ---- v4.0.0 deploy: dispatch e2e, offline queue, retry, location expand ----
steps.push(function (next) {
    var fx = makeDeployFixture();
    fx.node('node//w1');
    fx.upload(function (file) {
        fx.task({ fileId: file.id, args: '/qn FOO=1', nodeIds: 'node//w1' }, function (created) {
            check('deploy task: create answers with a hex id and the device count', !created.error && /^[a-f0-9]{16}$/.test(created.taskId) && created.devices === 1, created);
            fx.wait(function () { return fx.sent.length >= 2; }, function () {
                var wget = fx.sent.filter(function (m) { return m.action === 'wget'; })[0];
                var rc = fx.sent.filter(function (m) { return m.action === 'runcommands'; })[0];
                var stageFile = wget ? String(wget.path || '').split(/[\\/]/).pop() : '';
                check('deploy dispatch: the agent wget has the verified upstream shape (cookie urlpath, overwrite, folder, cert hash)',
                    wget != null && wget.urlpath === '/agentdownload.ashx?c=ck1' && wget.overwrite === true && wget.consent === 0 &&
                    wget.path === 'C:\\Windows\\Temp\\' + stageFile && wget.folder === 'C:\\Windows\\Temp' && wget.servertlshash === '01023f' &&
                    /^invsw-[a-f0-9]{16}-[a-f0-9]{12}\.msi$/.test(stageFile), wget && wget.urlpath);
                check('deploy dispatch: the tmpdl cookie is minted per device AT DISPATCH time (5-minute expiry honoured)',
                    fx.cookies.length === 1 && fx.cookies[0].a === 'tmpdl' && fx.cookies[0].d === '' && fx.cookies[0].nid === 'node//w1' && fx.cookies[0].f === stageFile, fx.cookies[0]);
                check('deploy dispatch: the installer is staged into <filespath>/tmp and the SHA-256 is taken from the COPY',
                    fs.existsSync(path.join(fx.fsp, 'tmp', stageFile)) && fs.readFileSync(path.join(fx.fsp, 'tmp', stageFile)).length === fx.data.length &&
                    fx.o.swTasks[created.taskId].sha256 === fx.shaOf(fx.data));
                var scriptGz = rc ? fx.gunz(rc.cmds, /FromBase64String\('([A-Za-z0-9+\/=]+)'\)/) : '';
                check('deploy dispatch: runcommands type 1 as SYSTEM, invscanner-sw session, hash + stage path inside the gzipped script',
                    rc != null && rc.type === 1 && rc.runAsUser === 0 && rc.reply === true && String(rc.sessionid) === 'invscanner-sw-w1' &&
                    scriptGz.indexOf(fx.shaOf(fx.data)) >= 0 && scriptGz.indexOf(stageFile) >= 0, rc && rc.sessionid);
                check('deploy dispatch: device state running, task file written',
                    fx.o.swTasks[created.taskId].devices['node//w1'].state === 'running' && fs.existsSync(fx.o.swTasksPath));
                fx.post({ action: 'sw_status' }, function (st0) {
                    var t0 = (st0.tasks || [])[0] || {};
                    check('deploy status: open task shows the running device, sha and args',
                        t0.done === false && t0.counts.running === 1 && t0.sha256 === fx.shaOf(fx.data) && t0.args === '/qn FOO=1' &&
                        (t0.devices[0] || {}).node === 'node//w1', t0.counts);
                    check('deploy reply: a winget-sessionized answer never consumes the deploy session',
                        fx.o.onAgentResponse({ action: 'msg', type: 'runcommands', sessionid: 'invscanner-wg-w1', result: fx.o.SW_MARKER + '{"state":"ok"}' }, '', 'node//w1') === true &&
                        fx.o.swPending['node//w1'] != null && fx.o.swTasks[created.taskId].devices['node//w1'].state === 'running');
                    check('deploy reply: the marker JSON on our own session is consumed',
                        fx.o.onAgentResponse({ action: 'msg', type: 'runcommands', sessionid: rc.sessionid, result: 'noise' + fx.o.SW_MARKER + '{"deploy":true,"state":"ok","name":"evil.msi","exit":0,"reboot":false,"error":""}' + String.fromCharCode(13, 10) }, '', 'node//w1') === true);
                    check('deploy reply: task closes, staged file deleted, admins AND the device get the feedback',
                        fx.o.swTasks[created.taskId].done === true && fx.o.swTasks[created.taskId].counts.ok === 1 &&
                        !fs.existsSync(path.join(fx.fsp, 'tmp', stageFile)) &&
                        fx.events.some(function (e) { return e.type === 'notify' && /evil\.msi/.test(String(e.value)); }) &&
                        fx.events.some(function (e) { return e.etype === 'node' && e.nodeid === 'node//w1' && /deploy/i.test(String(e.msg)); }), fx.o.swTasks[created.taskId].counts);
                    offlineFlow();
                });
            });
        });
    });

    function offlineFlow() {
        fx.upload(function (f2) {
            fx.sent.length = 0;
            fx.task({ fileId: f2.id, nodeIds: 'node//off1' }, function (tOff) {
                check('deploy offline: a task for an offline device is created and stays queued - zero agent traffic',
                    !tOff.error && fx.sent.length === 0 && fx.o.swTasks[tOff.taskId].devices['node//off1'].state === 'queued', [tOff, fx.sent.length]);
                fx.post({ action: 'sw_delete_file', fileId: f2.id }, function (delOpen) {
                    check('deploy delete guard: a file referenced by an OPEN task cannot be deleted', !!delOpen.error && /Open tasks/.test(delOpen.error), delOpen);
                    fx.node('node//off1');
                    fx.o.swOnNodeConnect('node//off1');
                    fx.wait(function () { return fx.sent.length >= 2; }, function () {
                        var wget2 = fx.sent.filter(function (m) { return m.action === 'wget'; })[0];
                        var rc2 = fx.sent.filter(function (m) { return m.action === 'runcommands'; })[0];
                        check('deploy offline: on reconnect the queued task dispatches automatically ("install when the device is back")',
                            wget2 != null && fx.o.swTasks[tOff.taskId].devices['node//off1'].state === 'running', fx.sent.map(function (m) { return m.action; }));
                        check('deploy offline: the late download gets a FRESH cookie',
                            String(wget2.urlpath).indexOf('?c=ck') > 0 && fx.cookies[fx.cookies.length - 1].nid === 'node//off1', wget2 && wget2.urlpath);
                        fx.o.onAgentResponse({ action: 'msg', type: 'runcommands', sessionid: rc2.sessionid, result: fx.o.SW_MARKER + '{"deploy":true,"state":"no-file","exit":null,"error":"the download never arrived"}' }, '', 'node//off1');
                        check('deploy answer: no-file is final and counts as failed - nothing was executed on the device',
                            fx.o.swTasks[tOff.taskId].devices['node//off1'].state === 'no-file' && fx.o.swTasks[tOff.taskId].done === true && fx.o.swTasks[tOff.taskId].counts.failed === 1);
                        fx.sent.length = 0;
                        fx.post({ action: 'sw_retry_task', taskId: tOff.taskId }, function (rt) {
                            check('deploy retry: the not-ok device is queued again', !rt.error && rt.devices === 1, rt);
                            fx.wait(function () { return fx.sent.length >= 2; }, function () {
                                var rc3 = fx.sent.filter(function (m) { return m.action === 'runcommands'; })[0];
                                fx.o.onAgentResponse({ action: 'msg', type: 'runcommands', sessionid: rc3.sessionid, result: fx.o.SW_MARKER + '{"deploy":true,"state":"ok","exit":0}' }, '', 'node//off1');
                                check('deploy retry: re-staged with a fresh cookie and closed ok',
                                    fx.cookies[fx.cookies.length - 1].nid === 'node//off1' && fx.o.swTasks[tOff.taskId].counts.ok === 1 && fx.o.swTasks[tOff.taskId].done === true);
                                mixedFlow();
                            });
                        });
                    });
                });
            });
        });
    }

    function mixedFlow() {
        fx.upload(function (f3) {
            fx.node('node//mac1');
            fx.sent.length = 0;
            fx.task({ fileId: f3.id, meshIds: 'mesh//grp1' }, function (tMix) {
                check('deploy locations: a whole location expands to its devices (w1 + mac1)', !tMix.error && tMix.devices === 2, tMix);
                fx.wait(function () { return (fx.o.swTasks[tMix.taskId].devices['node//mac1'] || {}).state === 'unsupported' && fx.sent.some(function (m) { return m.action === 'runcommands'; }); }, function () {
                    check('deploy platform gate: the macOS device ends unsupported and its agent never receives a script',
                        !fx.sent.some(function (m) { return m.action === 'runcommands' && String(m.sessionid) === 'invscanner-sw-mac1'; }));
                    var rcM = fx.sent.filter(function (m) { return m.action === 'runcommands'; })[0];
                    fx.o.onAgentResponse({ action: 'msg', type: 'runcommands', sessionid: rcM.sessionid, result: fx.o.SW_MARKER + '{"deploy":true,"state":"failed","exit":1603,"error":""}' }, '', 'node//w1');
                    var tv = fx.o.swTaskView(fx.o.swTasks[tMix.taskId]);
                    check('deploy answer: failed keeps the exit code and closes the task (1603 shows decimal + hex in the UI)',
                        fx.o.swTasks[tMix.taskId].done === true && tv.counts.failed === 1 && tv.counts.other === 1 &&
                        tv.devices.some(function (x) { return x.exit === 1603; }), tv.counts);
                    fx.post({ action: 'sw_delete_file', fileId: f3.id }, function (delDone) {
                        check('deploy delete guard: after the task is done the file can be deleted again', delDone.success === true, delDone);
                        next();
                    });
                });
            });
        });
    }
});

// ---- v4.3.3 deploy: the download ticket stays alive while the device waits, and a failed wget is reported ----
steps.push(function (next) {
    var fx = makeDeployFixture();
    fx.node('node//w1');
    fx.upload(function (f) {
        fx.task({ fileId: f.id, nodeIds: 'node//w1' }, function (c) {
            fx.wait(function () { return fx.sent.length >= 2; }, function () {
                var e1 = fx.o.swPending['node//w1'];
                check('deploy dispatch: a waiting device also arms a download-ticket re-send timer (the agentdownload cookie lives only 5 minutes)',
                    e1 != null && e1.timer != null && e1.dlTimer != null && e1.wgetTries === 0, e1 && Object.keys(e1));
                var stageAgain = String(fx.sent.filter(function (m) { return m.action === 'wget'; })[0].path).split(/[\\/]/).pop();
                fx.sent.length = 0;
                fx.o.swWgetRetry(e1, Date.now() + 60000);
                check('deploy robustness: the re-send is the same target with a FRESH cookie (expired ticket / agent-side dropped wget self-heal instead of 15 silent minutes)',
                    fx.sent.length === 1 && fx.sent[0].action === 'wget' && fx.sent[0].path.indexOf(stageAgain) > 0 &&
                    String(fx.sent[0].urlpath).indexOf('c=ck2') > 0 && fx.cookies.length === 2 && e1.wgetTries === 1, [fx.sent.map(function (m) { return m.action; }), fx.cookies.length]);
                check('deploy robustness: a re-send stops by itself at the deadline (no endless timer chain)', e1.dlTimer == null, e1.dlTimer);
                e1.wgetTries = obj.SW_WGET_RETRIES_MAX - 1;
                fx.sent.length = 0;
                fx.o.swWgetRetry(e1, Date.now() + 900000);
                check('deploy robustness: the re-sends are capped (an agent keys its downloader by urlpath and holds at most 4 - piling up tickets would jam it)',
                    fx.sent.length === 1 && e1.wgetTries === obj.SW_WGET_RETRIES_MAX && e1.dlTimer == null, [fx.sent.length, e1.wgetTries, e1.dlTimer]);
                var lgR = fs.readFileSync(fx.o.swLogPath, 'utf8');
                check('deploy robustness: every re-send is logged', /download ticket re-sent \(attempt 1/.test(lgR), lgR.split(String.fromCharCode(10)).slice(-3));
                fx.sent.length = 0;
                fx.o.onAgentResponse({ action: 'msg', type: 'console', value: String.fromCharCode(10) + 'Batch upload failed, because the server replied with HTTP 404, file: C:\\Windows\\Temp\\' + stageAgain + String.fromCharCode(10) }, '', 'node//w1');
                check('deploy evidence: the session-less wget failure text is buffered, it never ends the session',
                    fx.o.swPending['node//w1'] === e1 && /HTTP 404/.test(e1.cbuf || ''), e1.cbuf);
                var rcR = fx.sent.filter(function (m) { return m.action === 'runcommands'; })[0];
                    fx.o.onAgentResponse({ action: 'msg', type: 'runcommands', sessionid: e1.sid, result: fx.o.SW_MARKER + '{"deploy":true,"state":"no-file","exit":null,"error":"the download never arrived on the device: nothing ever appeared at the staged path - the agent never fetched the file"}' }, '', 'node//w1');
                var dn = fx.o.swTasks[c.taskId].devices['node//w1'];
                check('deploy evidence: the agent\'s own reason lands in the device note (no-file used to be three guesses)',
                    dn.state === 'no-file' && /the device said:.*HTTP 404/.test(dn.note) && dn.note.indexOf('re-sent 4 time(s)') > 0, dn.note);
                check('deploy evidence: the finished session has no timer left and a late re-send sends nothing',
                    e1.dlTimer == null && (fx.sent.length = 0, fx.o.swWgetRetry(e1, Date.now() + 60000), fx.sent.length === 0), fx.sent.length);
                fx.o.swLoadTasks();
                var silent = fx.o.swTasks['silntask'];
                check('deploy evidence: the distiller keeps only download-related lines',
                    obj.swWgetCrumbs('') === '' && obj.swWgetCrumbs('normal winget output\nNothing here') === '' &&
                    /Connection reset by peer/.test(obj.swWgetCrumbs('x\nConnection reset by peer\nBadCert')) &&
                    !/the install ran fine/.test(obj.swWgetCrumbs('the install ran fine\nBatch upload failed, because the server replied with HTTP 302')),
                    obj.swWgetCrumbs('normal output\nNothing here'));
                silentFlow();
            });
        });
    });

    function silentFlow() {
        fx.upload(function (f2) {
            fx.sent.length = 0;
            fx.task({ fileId: f2.id, nodeIds: 'node//w1' }, function (t2) {
                fx.wait(function () { return fx.sent.length >= 2; }, function () {
                    var e2 = fx.o.swPending['node//w1'];
                    fx.o.onAgentResponse({ action: 'msg', type: 'runcommands', sessionid: e2.sid, result: fx.o.SW_MARKER + '{"deploy":true,"state":"no-file","exit":null,"error":"the download never arrived on the device: nothing ever appeared at the staged path"}' }, '', 'node//w1');
                    var d2 = fx.o.swTasks[t2.taskId].devices['node//w1'];
                    check('deploy evidence: a device that never reported ANYTHING gets the real hint (agent URL / proxy on agentdownload.ashx), not just "wget failed"',
                        d2.state === 'no-file' && /never reported a download attempt/.test(d2.note) && d2.note.indexOf('re-sent') < 0, d2.note);
                    next();
                });
            });
        });
    }
});

// ---- v4.0.0 deploy: linux transport, console-channel answers, watchdog, cancel ----
steps.push(function (next) {
    var fx = makeDeployFixture();
    fx.node('node//l1'); fx.node('node//w1');
    fx.upload(function (file) {
        fx.task({ fileId: file.id, nodeIds: 'node//l1' }, function (tL) {
            fx.wait(function () { return fx.sent.length >= 2; }, function () {
                var wgetL = fx.sent.filter(function (m) { return m.action === 'wget'; })[0];
                var rcL = fx.sent.filter(function (m) { return m.action === 'runcommands'; })[0];
                check('deploy linux: wget targets /var/tmp and the script rides runcommands type 3 (/bin/sh)',
                    /^\/var\/tmp\/invsw-[a-f0-9-]+\.msi$/.test(wgetL.path) && rcL.type === 3 && String(rcL.sessionid) === 'invscanner-sw-l1', [wgetL.path, rcL.type]);
                check('deploy linux: a foreign-session answer is not consumed by the deploy engine',
                    fx.o.onAgentResponse({ action: 'msg', type: 'runcommands', sessionid: 'user//admin/xyz', result: 'x' }, '', 'node//l1') === false && fx.o.swPending['node//l1'] != null);
                check('deploy linux: the answer may also arrive over the session-less console channel',
                    fx.o.onAgentResponse({ action: 'msg', type: 'console', value: 'output...' + fx.o.SW_MARKER + '{"deploy":true,"state":"ok","name":"evil.msi","exit":0,"reboot":false}' + String.fromCharCode(10) }, '', 'node//l1') === true &&
                    fx.o.swTasks[tL.taskId].done === true && fx.o.swTasks[tL.taskId].counts.ok === 1);
                fx.sent.length = 0;
                fx.task({ fileId: file.id, nodeIds: 'node//w1' }, function (tTo) {
                    fx.wait(function () { return fx.o.swPending['node//w1'] != null; }, function () {
                        fx.o.swTimeout(fx.o.swPending['node//w1']);
                        check('deploy watchdog: a silent device ends in timeout and the session slot is freed',
                            fx.o.swTasks[tTo.taskId].devices['node//w1'].state === 'timeout' && fx.o.swTasks[tTo.taskId].done === true &&
                            fx.o.swPending['node//w1'] == null && fx.o.swActive === 0 &&
                            fx.events.some(function (e) { return e.etype === 'node' && /timeout/i.test(String(e.msg)); }));
                        fx.offlineNode('node//off1');
                        fx.task({ fileId: file.id, nodeIds: 'node//off1' }, function (tC) {
                            check('deploy cancel: offline device starts out queued', !tC.error && fx.o.swTasks[tC.taskId].devices['node//off1'].state === 'queued', tC);
                            fx.post({ action: 'sw_cancel_task', taskId: tC.taskId }, function (cc) {
                                check('deploy cancel: queued devices are cancelled and the task completes',
                                    cc.success === true && cc.cancelled === 1 && fx.o.swTasks[tC.taskId].done === true && fx.o.swTasks[tC.taskId].counts.other === 1, cc);
                                fx.post({ action: 'sw_cancel_task', taskId: 'constructor' }, function (badC) {
                                    check('deploy cancel: a prototype-style task id is refused before any lookup', !!badC.error, badC);
                                    next();
                                });
                            });
                        });
                    });
                });
            });
        });
    });
});

// ---- v4.0.0 deploy: validation, server files, devices view, gating, persistence ----
steps.push(function (next) {
    var fx = makeDeployFixture();
    fx.node('node//w1');
    fx.upload(function (file) {
        fx.post({ action: 'sw_create_task', source: 'bogus', nodeIds: 'node//w1' }, function (badSrc) {
            check('deploy validation: unknown source rejected', !!badSrc.error, badSrc);
            fx.task({ fileId: file.id, nodeIds: 'node//nosuch' }, function (ghost) {
                check('deploy validation: a node id not present on the server answers "No device matched" (never a phantom task)',
                    !!ghost.error && /No device matched/.test(ghost.error) && Object.keys(fx.o.swTasks).length === 0, ghost);
                fx.task({ fileId: file.id, meshIds: 'mesh//grp9' }, function (nomesh) {
                    check('deploy validation: a location with no devices is an error', !!nomesh.error, nomesh);
                    fx.post({ action: 'sw_create_task', source: 'library', fileId: 'ffffffffffff', nodeIds: 'node//w1' }, function (badFile) {
                        check('deploy validation: unknown library id rejected', !!badFile.error, badFile);
                        fx.task({ fileId: file.id, nodeIds: 'node//w1', args: "quiet\r\n$(reboot)" }, function (tA) {
                            check('deploy validation: args lose control characters but keep their content',
                                !tA.error && !/[\r\n]/.test(fx.o.swTasks[tA.taskId].args) && fx.o.swTasks[tA.taskId].args.indexOf('$(reboot)') >= 0, fx.o.swTasks[tA.taskId].args);
                            var rcA = null;
                            fx.wait(function () { rcA = fx.sent.filter(function (m) { return m.action === 'runcommands'; })[0] || null; return rcA != null; }, function () {
                                var scr = fx.gunz(rcA.cmds, /FromBase64String\('([A-Za-z0-9+\/=]+)'\)/);
                                check('deploy security: the args only appear inside the quoted $invArgs assignment, never as loose shell text',
                                    scr.split(String.fromCharCode(10)).every(function (l) { return l.indexOf('$(reboot)') < 0 || /^\$invArgs = '/.test(l); }),
                                    scr.split(String.fromCharCode(10)).filter(function (l) { return l.indexOf('reboot') >= 0; }).slice(0, 2));
                                fx.o.onAgentResponse({ action: 'msg', type: 'runcommands', sessionid: rcA.sessionid, result: fx.o.SW_MARKER + '{"deploy":true,"state":"ok","exit":3010,"reboot":true}' }, '', 'node//w1');
                                check('deploy answer: 3010 stores ok + reboot pending (the plugin itself never reboots)',
                                    fx.o.swTasks[tA.taskId].devices['node//w1'].reboot === true && fx.o.swTasks[tA.taskId].counts.ok === 1);
                                serverFiles();
                            });
                        });
                    });
                });
            });
        });
    });

    function serverFiles() {
        var sfDir = path.join(fx.fsp, 'domain', 'mesh-grp1');
        fs.mkdirSync(sfDir, { recursive: true });
        fs.writeFileSync(path.join(sfDir, 'shared tool.msi'), fx.data);
        fs.writeFileSync(path.join(sfDir, '.hidden'), 'x');
        fx.post({ action: 'sw_serverfiles' }, function (sf) {
            check('deploy serverfiles: MeshCentral Server Files folders are listed, dot-files hidden',
                !sf.error && sf.folders.length === 1 && sf.folders[0].name === 'HQ' &&
                sf.folders[0].files.length === 1 && sf.folders[0].files[0].name === 'shared tool.msi', sf.folders);
            fx.post({ action: 'sw_create_task', source: 'serverfile', meshId: 'mesh//grp1', fileName: '../../etc/passwd', nodeIds: 'node//w1' }, function (trav) {
                check('deploy serverfiles: path traversal in the file name is rejected', !!trav.error, trav);
                fx.sent.length = 0;
                fx.post({ action: 'sw_create_task', source: 'serverfile', meshId: 'mesh//grp1', fileName: 'shared tool.msi', nodeIds: 'node//w1' }, function (sft) {
                    check('deploy serverfiles: task accepted', !sft.error && sft.devices === 1, sft);
                    fx.wait(function () { return fx.sent.length >= 2; }, function () {
                        var sfWget = fx.sent.filter(function (m) { return m.action === 'wget'; })[0];
                        var sfStage = String(sfWget.path).split(/[\\/]/).pop();
                        check('deploy serverfiles: the server file is staged through the same tmp channel with its hash',
                            fs.existsSync(path.join(fx.fsp, 'tmp', sfStage)) && fx.o.swTasks[sft.taskId].sha256 === fx.shaOf(fx.data));
                        var sfRc = fx.sent.filter(function (m) { return m.action === 'runcommands'; })[0];
                        fx.o.onAgentResponse({ action: 'msg', type: 'runcommands', sessionid: sfRc.sessionid, result: 'junk without marker' }, '', 'node//w1');
                        check('deploy answer: output without the marker is an error, never a silent success',
                            fx.o.swTasks[sft.taskId].devices['node//w1'].state === 'error' && /no marker/.test(fx.o.swTasks[sft.taskId].devices['node//w1'].note));
                        devicesAndGating();
                    });
                });
            });
        });
    }

    function devicesAndGating() {
        fx.post({ action: 'sw_devices' }, function (dv) {
            var w1 = dv.devices.filter(function (x) { return x.id === 'node//w1'; })[0];
            var mac1 = dv.devices.filter(function (x) { return x.id === 'node//mac1'; })[0];
            var off1 = dv.devices.filter(function (x) { return x.id === 'node//off1'; })[0];
            check('deploy devices: every node with group, online flag and platform (mac = other, offline flagged)',
                dv.devices.length === 4 && w1.online === true && w1.platform === 'windows' && w1.group === 'HQ' &&
                mac1.platform === 'other' && off1.online === false, dv.devices.map(function (x) { return [x.id, x.online, x.platform]; }));
            fx.o.handleAdminPostReq({ body: { action: 'sw_status' } }, mockRes(function (noHdr) {
                check('deploy route: POST without the X-InvScanner-Request header -> 403', noHdr._status === 403, noHdr);
                fx.o.handleAdminPostReq({ headers: XHDR, body: { action: 'sw_status' } }, mockRes(function (noRight) {
                    check('deploy route: non-admin -> 401', noRight._status === 401, noRight);
                    persistence();
                }), { name: 'guest', siteadmin: 0, domain: '' });
            }), user);
        });
    }

    function persistence() {
        var saved = JSON.parse(fs.readFileSync(fx.o.swTasksPath, 'utf8'));
        var anyId = Object.keys(saved)[0];
        saved[anyId].done = false; delete saved[anyId].finishTime;
        var anyDev = Object.keys(saved[anyId].devices)[0];
        saved[anyId].devices[anyDev].state = 'running';
        fs.writeFileSync(fx.o.swTasksPath, JSON.stringify(saved));
        var savedGen = global.__inventoryscannerInstanceGen;
        var objR = factory({ parent: fx.ms });
        objR.swLoadTasks();
        global.__inventoryscannerInstanceGen = savedGen;
        check('deploy persistence: after a restart a device stuck "running" (its session died) is reset to "queued" and runs again',
            objR.swTasks[anyId] != null && objR.swTasks[anyId].devices[anyDev].state === 'queued', objR.swTasks[anyId] && objR.swTasks[anyId].devices[anyDev]);
        check('deploy persistence: task records keep creator, source and stage name across restarts',
            typeof objR.swTasks[anyId].created === 'string' && /^invsw-[a-f0-9]{16}-[a-f0-9]{12}\.msi$/.test(objR.swTasks[anyId].stageFile));
        structural();
    }

    function structural() {
        var src = pluginSrc();
        check('deploy wiring: the collector routes invscanner-sw sessions and the reconnect hook calls the engine',
            src.indexOf('invscanner-sw-') >= 0 && /obj\.swHandleResponse\(nodeid, command\)/.test(src) && /obj\.swOnNodeConnect\(swNode\)/.test(src));
        check('deploy wiring: startup loads the store/tasks and arms the sweep; routes dispatch the sw actions',
            /obj\.swLoadFiles\(\)/.test(src) && /obj\.swLoadTasks\(\)/.test(src) && /obj\.swCleanStaleStaging\(\)/.test(src) && /obj\.scheduleSwSweep\(\)/.test(src) &&
            /action === 'sw_create_task'/.test(src) && /action === 'sw_upload'/.test(src));
        check('deploy wiring: the winget and OS pumps skip nodes with a deploy session (one runcommands per agent)',
            (src.match(/obj\.swPending != null && obj\.swPending\[nodeid\] != null/g) || []).length >= 2);
        var cp = require('child_process');
        var dir = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-swpp-'));
        var p1 = path.join(dir, 'deploy.ps1');
        fs.writeFileSync(p1, obj.swBuildWindowsScript({ stageFile: 'invsw-aa11.msi', sha256: 'ab'.repeat(32), ext: 'msi', fileName: 'a b.msi', args: "/qn X=1 'Y'" }));
        var psr = runPs(['-NoProfile', '-NonInteractive', '-Command', "$t=$null;$e=$null;[void][System.Management.Automation.Language.Parser]::ParseFile('" + p1 + "',[ref]$t,[ref]$e);$e.Count"]);
        if (psr == null) { console.log('SKIP deploy script: PowerShell parser (PowerShell not available)'); }
        else { check('deploy win script: PowerShell parser reports no errors', !psr.failed && psr.text.trim() === '0', psr.text.trim()); }
        var p2 = path.join(dir, 'deploy.sh');
        fs.writeFileSync(p2, obj.swBuildLinuxScript({ stageFile: '/var/tmp/invsw-aa11.deb', sha256: 'ab'.repeat(32), ext: 'deb', fileName: 'a.deb', args: '' }));
        var shOk = null;
        ['sh', 'bash', 'C:\\Program Files\\Git\\bin\\sh.exe'].some(function (sh) { try { cp.execFileSync(sh, ['-n', p2], { stdio: 'pipe', timeout: 30000 }); shOk = true; return true; } catch (e) { if (e.status != null) { shOk = false; return true; } return false; } });
        if (shOk == null) { console.log('SKIP deploy script: sh -n (no POSIX shell available)'); }
        else { check('deploy linux script: sh -n reports no syntax errors', shOk === true); }
        next();
    }
});

// ---- v4.0.0 deploy: a server without filespath degrades honestly ----
steps.push(function (next) {
    obj.handleAdminPostReq({ headers: XHDR, body: { action: 'sw_serverfiles' } }, mockRes(function (d) {
        check('deploy serverfiles: without a files area the route answers an error, never a crash', !!d.error && /not available/i.test(d.error), d);
        next();
    }), user);
});

// ---- v4.3.0 (audit 3): regressions for the fixed findings ----
steps.push(function (next) {
    // A1: typographic quotes are PowerShell quote characters - they must be doubled like '
    var q = String.fromCharCode(0x2019), lq = String.fromCharCode(0x2018);
    var hostile = 'a' + q + '; Write-Output INVPWNED; ' + lq + 'b.exe';
    var sQ = obj.swBuildWindowsScript({ stageFile: 'invsw-x.exe', sha256: 'ab'.repeat(32), ext: 'exe', fileName: hostile, args: 'x' + q + ' ; Write-Output INVPWNED2 ' + lq });
    check('audit3 A1: typographic single quotes in name/args are doubled inside the PowerShell literal',
        sQ.indexOf("$invName = 'a" + q + q + '; Write-Output INVPWNED; ' + lq + lq + "b.exe'") >= 0 && sQ.indexOf('x' + q + q + ' ; Write-Output INVPWNED2 ' + lq + lq) >= 0);
    var psr = runPs(['-NoProfile', '-NonInteractive', '-Command', sQ.split(String.fromCharCode(10)).filter(function (l) { return /^\$inv(Name|Args) = /.test(l); }).join('; ') + "; Write-Output ('N=' + $invName); Write-Output ('A=' + $invArgs)"]);
    if (psr == null) { console.log('SKIP audit3 A1: PowerShell execution (PowerShell not available)'); }
    else { check('audit3 A1: PowerShell keeps the hostile text as DATA (no injected command ran)', !psr.failed && psr.text.indexOf('INVPWNED\r') < 0 && /N=a.; Write-Output INVPWNED; .b\.exe/.test(psr.text) && psr.text.split(/\r?\n/).filter(function (l) { return /^INVPWNED/.test(l); }).length === 0, psr.text); }

    // A2: verified bytes == executed bytes
    var sW = obj.swBuildWindowsScript({ stageFile: 'invsw-x.msi', sha256: 'ab'.repeat(32), ext: 'msi', fileName: 'a.msi', args: '' });
    check('audit3 A2 win: the staged file is hashed through a FileShare.Read handle, the run copy stays write-locked until after the install',
        sW.indexOf('[System.IO.FileShare]::Read') >= 0 && sW.indexOf('Get-FileHash -InputStream $invFs') >= 0 &&
        sW.indexOf('Get-FileHash -InputStream $invRunFs') >= 0 &&
        sW.indexOf('$invRunFs.Dispose(); $invRunFs = $null } } catch { }') > sW.indexOf("Start-Process -FilePath 'msiexec.exe'"));
    // v4.3.1: an installer is never started from C:\Windows\Temp (DLL search order, CWE-427)
    check('v4.3.1 dll: installers start from a fresh folder created with a protected SYSTEM+Administrators ACL, which is also the working directory',
        sW.indexOf("('invsw-run-' + [guid]::NewGuid().ToString('N'))") >= 0 && sW.indexOf('SetAccessRuleProtection($true, $false)') >= 0 &&
        sW.indexOf('[System.IO.Directory]::CreateDirectory($invRunDir, $invDS)') >= 0 && sW.indexOf('AreAccessRulesProtected') >= 0 &&
        sW.indexOf("'/i \"' + $invRun + '\" /qn /norestart'") >= 0 && sW.indexOf('-WorkingDirectory $invRunDir') >= 0 &&
        !/Start-Process[^;]*\$invStage/.test(sW));
    check('v4.3.1 dll: a run folder that cannot be prepared answers error and executes nothing; the folder is removed afterwards',
        sW.indexOf("could not prepare the protected run folder, nothing was executed") >= 0 &&
        sW.lastIndexOf('Remove-Item -LiteralPath $invRunDir -Recurse -Force') > sW.indexOf("Start-Process -FilePath 'msiexec.exe'"));
    // Real run (Windows only): the generated script started from a stage folder must launch the program from the
    // protected run folder (proof: the program prints its own folder), and that folder is gone afterwards. The test
    // user's SID is added to the ACL ONLY in this copy, because a non-SYSTEM test cannot read a SYSTEM+Admins folder.
    (function () {
        if (process.platform !== 'win32') { console.log('SKIP v4.3.1 dll: real run (not Windows)'); return; }
        var who = runPs(['-NoProfile', '-NonInteractive', '-Command', '[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value']);
        if (who == null) { console.log('SKIP v4.3.1 dll: real run (PowerShell not available)'); return; }
        var sid = String(who.text || '').trim();
        var d = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-dll-'));
        var exe = fs.readFileSync(path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'cmd.exe'));
        fs.writeFileSync(path.join(d, 'invsw-aa-bb.exe'), exe);
        var sha = require('crypto').createHash('sha256').update(exe).digest('hex');
        var scr = obj.swBuildWindowsScript({ stageFile: 'invsw-aa-bb.exe', sha256: sha, ext: 'exe', fileName: 'p.exe', args: '/c cd > "%TEMP%\\invscanner-dll-cwd.txt"' })
            .split('C:\\Windows\\Temp\\').join(d + '\\').split("@('S-1-5-18', 'S-1-5-32-544')").join("@('S-1-5-18', 'S-1-5-32-544', '" + sid + "')");
        fs.writeFileSync(path.join(d, 'run.ps1'), scr);
        var cwdFile = path.join(os.tmpdir(), 'invscanner-dll-cwd.txt');
        try { fs.unlinkSync(cwdFile); } catch (e) { }
        var r = runPs(['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', path.join(d, 'run.ps1')], { timeout: 120000 });
        var cwd = ''; try { cwd = fs.readFileSync(cwdFile, 'utf8').trim(); } catch (e) { }
        var left = fs.readdirSync(d).filter(function (n) { return /^invsw-run-/.test(n); });
        check('v4.3.1 dll: real run - the program ran from the protected run folder (not the download folder), state ok, folder removed',
            r != null && !r.failed && /"state":"ok"/.test(r.text) && cwd.indexOf(path.join(d, 'invsw-run-')) === 0 && left.length === 0,
            [cwd, left, r && r.text.substring(0, 200)]);
        try { fs.unlinkSync(cwdFile); } catch (e) { }
        try { fs.rmSync(d, { recursive: true, force: true }); } catch (e) { }
    })();
    var sL = obj.swBuildLinuxScript({ stageFile: 'invsw-x.sh', sha256: 'ab'.repeat(32), ext: 'sh', fileName: 'a.sh', args: '' });
    check('audit3 A2 linux: only a private mktemp copy (re-hashed) is executed, never the /var/tmp download',
        sL.indexOf('mktemp -d /var/tmp/invsw-run.XXXXXXXX') >= 0 && sL.indexOf('H2=$(sha256sum "$P"') >= 0 &&
        sL.indexOf('sh) set -- sh "$P" $ARGS') >= 0 && sL.indexOf('set -- sh "$F"') < 0 && sL.indexOf('[ ! -L "$F" ]') >= 0);

    // A3: auto-update needs an explicit group opt-in, only Windows, db.Get answers an array
    var sentA = [];
    var nodesA = [{ _id: 'node//lx', meshid: 'mesh//g1', osdesc: 'Ubuntu 24.04 LTS' }, { _id: 'node//wx', meshid: 'mesh//g1', osdesc: 'Microsoft Windows 11 Pro' }];
    var msA = { db: { GetAllType: function (t, cb) { cb(null, t === 'node' ? nodesA : []); }, Get: function (id, cb) { cb(null, nodesA.filter(function (n) { return n._id === id; })); } },
        datapath: fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-a3-')), args: {}, debug: function () { }, config: { settings: {} },
        webserver: { routeAgentCommand: function () { }, wsagents: { 'node//lx': { send: function (m) { sentA.push(['lx', JSON.parse(m).action]); } }, 'node//wx': { send: function (m) { sentA.push(['wx', JSON.parse(m).action]); } } } } };
    var savedGen = global.__inventoryscannerInstanceGen;
    var oA = factory({ parent: msA });
    global.__inventoryscannerInstanceGen = savedGen;
    oA.pluginSettings = { wingetUpdater: { enabled: true, updateMeshes: [], excludeNodes: [], ignorePackages: [], pinSync: true } };
    var noGroup = oA.wgQueueNode('node//lx', 'connect');
    check('audit3 A3: enabled updater WITHOUT a ticked group runs nothing automatically', noGroup === false && sentA.length === 0, sentA);
    oA.pluginSettings = { wingetUpdater: { enabled: true, updateMeshes: ['mesh//g1'], excludeNodes: [], ignorePackages: [], pinSync: true } };
    oA.wgQueueNode('node//lx', 'connect');
    check('audit3 A3: a Linux device in a ticked group never receives a winget script', sentA.length === 0, sentA);
    oA.wgQueueNode('node//wx', 'connect');
    check('audit3 A3: a Windows device in a ticked group is updated on connect (db.Get array handled)',
        sentA.length === 1 && sentA[0][0] === 'wx' && sentA[0][1] === 'runcommands', sentA);
    Object.keys(oA.wgPending).forEach(function (k) { clearTimeout(oA.wgPending[k].timer); });

    // A4: rescan must not re-import files that already are library entries
    var fx = makeDeployFixture();
    fs.mkdirSync(fx.o.swFilesDir, { recursive: true });
    fs.writeFileSync(path.join(fx.o.swFilesDir, 'setup.exe'), 'MZ-a4');
    fx.post({ action: 'sw_rescan_library' }, function (r1) {
        var id1 = (r1.files || [])[0] && r1.files[0].id;
        fx.post({ action: 'sw_rescan_library' }, function (r2) {
            check('audit3 A4: a second rescan keeps the entry (same id, display name kept, nothing re-imported)',
                r1.added === 1 && r2.added === 0 && r2.removed === 0 && r2.files.length === 1 && r2.files[0].id === id1 && r2.files[0].name === 'setup.exe', [r1.added, r2.added, r2.removed, r2.files]);
            // A5: notifications are scoped to the default domain
            var evs = [];
            var oN = fx.o; var keep = oN.meshServer.DispatchEvent;
            oN.meshServer.DispatchEvent = function (t, s, e) { evs.push(e); };
            oN.notifyAdmins([{ meshName: 'HQ', newCves: ['CVE-2024-0001'] }]);
            oN.meshServer.DispatchEvent = keep;
            check('audit3 A5: admin notifications carry domain "" (sub-domain admins subscribed to * do not receive them)', evs.length === 1 && evs[0].domain === '', evs);
            next();
        });
    });
});

// ---- v4.5.0 device reset (issue #4): scripts, mode gating, routes, timeout ----
steps.push(function (next) {
    // builders + pure logic on the shared obj (no dispatch).
    var ps = obj.devBuildProbeScript();
    check('devreset probe script: reads systemreset/build/WinRE/BitLocker/domain/battery, prints the marker, runs no reboot command',
        ps.indexOf('systemreset.exe') >= 0 && ps.indexOf("reagentc '/info'") >= 0 && ps.indexOf('Get-BitLockerVolume') >= 0 && ps.indexOf('manage-bde') >= 0 &&
        ps.indexOf('Win32_Battery') >= 0 && ps.indexOf('PartOfDomain') >= 0 && ps.indexOf('UserName') >= 0 &&
        ps.indexOf(obj.DEV_MARKER) >= 0 && ps.indexOf('invscanner-devreset.log') >= 0 && !/Restart-Computer|shutdown/i.test(ps));
    var openersP = ps.split(String.fromCharCode(10)).filter(function (l) { return /[({]\s*$/.test(l); });
    check('devreset probe script: one statement per line', openersP.length === 0, openersP.slice(0, 2));

    var rc = obj.devBuildResetScript('clean', false);
    var rk = obj.devBuildResetScript('keepfiles', true);
    check('devreset reset script: launches systemreset non-interactively and prints the marker BEFORE the launch (the reboot wins the race)',
        rc.indexOf("$invSw = '-cleanpc'") >= 0 && rk.indexOf("$invSw = '-keepfiles'") >= 0 &&
        rc.indexOf("Start-Process -FilePath $invSr -ArgumentList $invSw,'-noUI'") >= 0 &&
        rc.indexOf(obj.DEV_MARKER) >= 0 && rc.indexOf(obj.DEV_MARKER) < rc.indexOf('Start-Process') && /-cleanpc|-keepfiles/.test(rc));
    check('devreset reset script: re-checks build/WinRE/BitLocker on the device; the only reboot path is systemreset (never Restart-Computer/shutdown)',
        rc.indexOf('-lt ' + obj.DEV_MIN_BUILD) >= 0 && rc.indexOf("reagentc '/info'") >= 0 && rc.indexOf('-inotmatch') >= 0 &&
        rc.indexOf('systemreset') >= 0 && !/Restart-Computer|shutdown/i.test(rc));
    check('devreset reset script: the recovery-key confirmation only travels as the ack literal, clean defaults to no-ack',
        rc.indexOf('$invAck = $false') >= 0 && rk.indexOf('$invAck = $true') >= 0);
    var openersR = rc.split(String.fromCharCode(10)).filter(function (l) { return /[({]\s*$/.test(l); });
    check('devreset reset script: one statement per line', openersR.length === 0, openersR.slice(0, 2));

    // v4.7.0 reboot policy: a reboot must be EXPLICIT and ANNOUNCED. The two things that restart a
    // device are the per-device PC Reset (systemreset) and the per-device Force Restart (shutdown),
    // both manual + typed-name confirmed; never a batch, never a schedule, never automatic, and no other
    // engine emits a reboot (the troubleshooter repairs reboot nothing and run no shutdown command).
    check('reboot policy: only PC Reset and Force Restart reboot, both manual per-device + confirmed - no batch/scheduled restart, no troubleshooter reboot',
        typeof obj.devStartBatch === 'undefined' && typeof obj.scheduleDevReset === 'undefined' &&
        typeof obj.devTargetNodes === 'undefined' && typeof obj.devPump === 'undefined' &&
        typeof obj.wuStartBatch === 'undefined' && typeof obj.scheduleWuRepair === 'undefined' && typeof obj.wuPump === 'undefined' &&
        typeof obj.rbStartBatch === 'undefined' && typeof obj.scheduleReboot === 'undefined' && typeof obj.rbPump === 'undefined' &&
        typeof obj.rbTargetNodes === 'undefined' && !/Restart-Computer|shutdown/i.test(obj.wuBuildRepairScript()));

    // mode gating is a pure decision on a probe object + a clock.
    var now = Date.now();
    var freshIso = new Date(now - 60000).toISOString();
    var oldIso = new Date(now - (7 * 24 * 60 * 60 * 1000)).toISOString();
    var base = { kind: 'probe', state: 'ok', systemreset: true, build: 26200, clean: true, keepfiles: true, winre: 'enabled', bitlocker: 'off', time: freshIso };
    check('devreset gate: a fresh passing probe allows both modes; a clean reset needs no ack when BitLocker is off',
        obj.devModeAllowed(base, 'clean', '').allowed === true && obj.devModeAllowed(base, 'keepfiles', '').allowed === true);
    check('devreset gate: "Remove everything" is blocked while BitLocker is on unless the recovery key is confirmed',
        obj.devModeAllowed(Object.assign({}, base, { bitlocker: 'on' }), 'clean', '').allowed === false &&
        /recovery key/.test(obj.devModeAllowed(Object.assign({}, base, { bitlocker: 'on' }), 'clean', '').reason) &&
        obj.devModeAllowed(Object.assign({}, base, { bitlocker: 'on' }), 'clean', 'true').allowed === true &&
        obj.devModeAllowed(Object.assign({}, base, { bitlocker: 'unknown' }), 'clean', '').allowed === false);
    check('devreset gate: an unknown BitLocker state blocks a clean reset (fail-safe), never silently allowed',
        obj.devModeAllowed(Object.assign({}, base, { bitlocker: 'unknown' }), 'clean', '').allowed === false);
    check('devreset gate: BitLocker does not block "Keep my files"',
        obj.devModeAllowed(Object.assign({}, base, { bitlocker: 'on' }), 'keepfiles', '').allowed === true);
    check('devreset gate: no/stale probe, missing systemreset, disabled WinRE or an unsupported build each refuse with a reason',
        obj.devModeAllowed(null, 'clean', 'true').allowed === false && obj.devModeAllowed({ kind: 'probe', state: 'ok', systemreset: true, clean: true, keepfiles: true, winre: 'enabled', bitlocker: 'off', time: oldIso }, 'clean', 'true').allowed === false &&
        obj.devModeAllowed(Object.assign({}, base, { systemreset: false }), 'keepfiles', '').allowed === false &&
        obj.devModeAllowed(Object.assign({}, base, { winre: 'disabled' }), 'keepfiles', '').allowed === false &&
        obj.devModeAllowed(Object.assign({}, base, { clean: false, bitlocker: 'off' }), 'clean', '').allowed === false);

    // PowerShell parser on both generated scripts (SKIP where PowerShell is absent).
    var dir = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-drps-'));
    var pp = path.join(dir, 'dr.ps1');
    fs.writeFileSync(pp, rc);
    var psr = runPs(['-NoProfile', '-NonInteractive', '-Command', "$t=$null;$e=$null;[void][System.Management.Automation.Language.Parser]::ParseFile('" + pp + "',[ref]$t,[ref]$e);$e.Count"]);
    if (psr == null) { console.log('SKIP devreset scripts: PowerShell parser (PowerShell not available)'); }
    else { check('devreset reset script: PowerShell parser reports no errors', !psr.failed && psr.text.trim() === '0', psr.text.trim()); }
    next();
});

steps.push(function (next) {
    var dpD = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-dr-'));
    var drNodes = [
        { _id: 'node//dw1', meshid: 'mesh//grp1', rname: 'dw1', name: 'ResetOne', osdesc: 'Microsoft Windows 11 Pro' },
        { _id: 'node//dl1', meshid: 'mesh//grp2', rname: 'dl1', name: 'LinuxOne', osdesc: 'Ubuntu 24.04 LTS' },
        { _id: 'node//doff', meshid: 'mesh//grp1', rname: 'doff', name: 'ResetOff', osdesc: 'Microsoft Windows 10' }
    ];
    var dbD = { GetAllType: function (t, cb) { cb(null, t === 'node' ? drNodes.slice() : meshes.slice()); }, Get: function (id, cb) { cb(null, drNodes.filter(function (n) { return n._id === id; })); } };
    var sentD = [];
    var agents = { 'node//dw1': { send: function (m) { sentD.push(JSON.parse(m)); } }, 'node//dl1': { send: function (m) { sentD.push(JSON.parse(m)); } } };
    var oD = factory({ parent: { db: dbD, datapath: dpD, debug: function () { }, config: { settings: {} }, webserver: { meshes: {}, wsagents: agents }, DispatchEvent: function () { } } });
    var gunz = function (cmd, re) { var mm = String(cmd).match(re); return mm ? require('zlib').gunzipSync(Buffer.from(mm[1], 'base64')).toString('utf8') : ''; };

    oD.handleAdminPostReq({ headers: XHDR, body: { action: 'dr_probe', nodeId: 'node//dw1' } }, mockRes(function (d1) {
        check('dr_probe: dispatches a read-only probe on an invscanner-dr- session (runcommands type 1)',
            d1.started === true && sentD.length === 1 && sentD[0].action === 'runcommands' && sentD[0].type === 1 &&
            String(sentD[0].sessionid).indexOf('invscanner-dr-') === 0 && oD.devPending['node//dw1'] != null, sentD[0]);
        oD.handleAdminPostReq({ headers: XHDR, body: { action: 'dr_probe', nodeId: 'node//dl1' } }, mockRes(function (dL) {
            check('dr_probe: a non-Windows device is refused (reset is a Windows tool)', !!dL.error && /Windows/.test(dL.error), dL);
            oD.onAgentResponse({ action: 'msg', type: 'runcommands', sessionid: sentD[0].sessionid, result: 'noise' + oD.DEV_MARKER +
                '{"probe":true,"state":"ok","systemreset":true,"build":26200,"clean":true,"keepfiles":true,"winre":"enabled","bitlocker":"on","bldetail":"On","domain":false,"user":"admin","battery":false,"onac":true}' + String.fromCharCode(10) }, '', 'node//dw1');
            var pr = oD.devResults['node//dw1'];
            check('dr_probe: the marker answer is consumed and stored as a fresh probe (BitLocker on)',
                pr && pr.kind === 'probe' && pr.systemreset === true && pr.bitlocker === 'on' && oD.devProbeFresh(pr) === true && oD.devPending['node//dw1'] == null, pr);

            oD.handleAdminPostReq({ headers: XHDR, body: { action: 'dr_reset', nodeId: 'node//dw1', mode: 'clean', confirm: 'ResetOne' } }, mockRes(function (dnc) {
                check('dr_reset: "Remove everything" is blocked while BitLocker is on and no recovery key is confirmed', !!dnc.error && /recovery key/.test(dnc.error), dnc);
                oD.handleAdminPostReq({ headers: XHDR, body: { action: 'dr_reset', nodeId: 'node//dw1', mode: 'keepfiles', confirm: 'WrongName' } }, mockRes(function (dwn) {
                    check('dr_reset: a mistyped device name is refused (the typed confirmation guard)', !!dwn.error && /device name/.test(dwn.error), dwn);
                    sentD.length = 0;
                    oD.handleAdminPostReq({ headers: XHDR, body: { action: 'dr_reset', nodeId: 'node//dw1', mode: 'clean', confirm: 'resetone', bitlockerAck: 'true' } }, mockRes(function (dgo) {
                        check('dr_reset: name typed (case-insensitive) + BitLocker confirmed -> a clean systemreset is dispatched',
                            dgo.started === true && dgo.mode === 'clean' && sentD.length === 1 && String(sentD[0].sessionid).indexOf('invscanner-dr-') === 0 &&
                            gunz(sentD[0].cmds, /FromBase64String\('([A-Za-z0-9+\/=]+)'\)/).indexOf('-cleanpc') >= 0, [dgo, sentD.length]);
                        var dms = oD.onAgentResponse({ action: 'msg', type: 'runcommands', sessionid: sentD[0].sessionid, result: oD.DEV_MARKER + '{"reset":true,"mode":"clean","result":"starting","error":"","build":26200}' + String.fromCharCode(10) }, '', 'node//dw1');
                        check('dr_reset: a "starting" answer stores state resetting (in the last-reset slot, the probe stays) and is consumed (no browser leak)',
                            dms === true && oD.devLast['node//dw1'].state === 'resetting' && oD.devLast['node//dw1'].kind === 'reset' &&
                            oD.devResults['node//dw1'].kind === 'probe' && oD.devPending['node//dw1'] == null, oD.devLast['node//dw1']);

                        oD.wgPending['node//dw1'] = { nodeid: 'node//dw1' };
                        oD.handleAdminPostReq({ headers: XHDR, body: { action: 'dr_probe', nodeId: 'node//dw1' } }, mockRes(function (busy) {
                            check('dr_probe: a device holding a winget/OS/deploy session is refused (one runcommands session per agent)', !!busy.error && /running/.test(busy.error), busy);
                            delete oD.wgPending['node//dw1'];
                            oD.handleAdminPostReq({ headers: XHDR, body: { action: 'dr_reset', nodeId: 'node//doff', mode: 'keepfiles', confirm: 'ResetOff' } }, mockRes(function (dof) {
                                check('dr_reset: an unchecked/offline device is refused - a reset never runs on a stale or absent check', !!dof.error && /Check/.test(dof.error), dof);
                                oD.handleAdminPostReq({ headers: XHDR, body: { action: 'dr_status' } }, mockRes(function (st) {
                                    var ids = st.devices.map(function (x) { return x.id; });
                                    var w = st.devices.filter(function (x) { return x.id === 'node//dw1'; })[0];
                                    check('dr_status: lists only Windows devices, with the fresh probe and both offered modes',
                                        st.devices.length === 2 && ids.indexOf('node//dl1') < 0 && w.hasProbe === true && w.modes.keepfiles === true && w.modes.clean === true, st.devices);
                                    oD.handleAdminPostReq({ headers: XHDR, body: { action: 'get_log', type: 'reset' } }, mockRes(function (lgr) {
                                        check('get_log reset: the device-reset audit log is reachable', Array.isArray(lgr.lines) && lgr.file === 'plugins/inventoryscanner/device-reset.log', lgr);
                                        next();
                                    }), user);
                                }), user);
                            }), user);
                        }), user);
                    }), user);
                }), user);
            }), user);
        }), user);
    }), user);
});

steps.push(function (next) {
    var dpT = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-drt-'));
    var tNodes = [{ _id: 'node//to1', meshid: 'mesh//grp1', rname: 'to1', name: 'ToOne', osdesc: 'Microsoft Windows 11' }];
    var dbT = { GetAllType: function (t, cb) { cb(null, t === 'node' ? tNodes.slice() : meshes.slice()); }, Get: function (id, cb) { cb(null, tNodes.filter(function (n) { return n._id === id; })); } };
    var agentsT = {};
    var oT = factory({ parent: { db: dbT, datapath: dpT, debug: function () { }, config: { settings: {} }, webserver: { meshes: {}, wsagents: agentsT }, DispatchEvent: function () { } } });
    var e1 = { nodeid: 'node//to1', kind: 'reset', mode: 'clean', since: Date.now() };
    oT.devPending['node//to1'] = e1;
    oT.devResetTimeout(e1);
    check('dr timeout: reset + the device went offline (it restarted into WinRE) = resetting, not a failure',
        oT.devLast['node//to1'] && oT.devLast['node//to1'].state === 'resetting' && oT.devPending['node//to1'] == null, oT.devLast['node//to1']);
    agentsT['node//to1'] = { send: function () { } };
    var e2 = { nodeid: 'node//to1', kind: 'reset', mode: 'clean', since: Date.now() };
    oT.devPending['node//to1'] = e2;
    oT.devResetTimeout(e2);
    check('dr timeout: reset + the device is still online and silent = no answer (the reset did not start)',
        oT.devLast['node//to1'] && oT.devLast['node//to1'].state === 'no-answer', oT.devLast['node//to1']);
    next();
});

// ---- v4.6.0 Windows Update troubleshooter (issue #3): scripts + routes + reboot reporting ----
steps.push(function (next) {
    var dg = obj.wuBuildDiagnoseScript();
    check('wu diagnose script: reads services, reboot state + when, download cache and WU-log errors, prints the marker, changes NOTHING',
        dg.indexOf('Get-Service') >= 0 && dg.indexOf('Win32_Service') >= 0 &&
        dg.indexOf("Auto Update\\RebootRequired") >= 0 && dg.indexOf('Component Based Servicing\\RebootPending') >= 0 &&
        dg.indexOf('SoftwareDistribution\\Download') >= 0 && dg.indexOf('Microsoft-Windows-WindowsUpdateClient') >= 0 &&
        dg.indexOf('winhttp show proxy') >= 0 && dg.indexOf(obj.WU_MARKER) >= 0 && dg.indexOf('invscanner-wutroubleshoot.log') >= 0 &&
        dg.indexOf('Stop-Service') < 0 && dg.indexOf('Set-Service') < 0 && dg.indexOf('catroot2') < 0 && !/Restart-Computer|shutdown/i.test(dg));

    var rp = obj.wuBuildRepairScript();
    check('wu repair script: restarts the WU services and resets download + catroot2 with a per-step ok/fail harness, marker, no reboot, no invasive winsock/proxy reset',
        rp.indexOf("function invWuStep") >= 0 && rp.indexOf('Stop-Service') >= 0 && rp.indexOf('Start-Service') >= 0 &&
        rp.indexOf("SoftwareDistribution\\Download'") >= 0 && rp.indexOf('catroot2') >= 0 && rp.indexOf('Set-Service') >= 0 &&
        rp.indexOf("-StartupType Automatic") >= 0 && rp.indexOf('$invWu.rebootTriggered = $false') >= 0 &&
        markerBeforeStop(rp, obj.WU_MARKER) &&
        !/Restart-Computer|shutdown/i.test(rp) && rp.indexOf('winsock') < 0 && rp.indexOf('reset proxy') < 0);
    var openersDg = dg.split(String.fromCharCode(10)).filter(function (l) { return /[({]\s*$/.test(l); });
    var openersRp = rp.split(String.fromCharCode(10)).filter(function (l) { return /[({]\s*$/.test(l); });
    check('wu scripts: one statement per line (diagnose and repair)', openersDg.length === 0 && openersRp.length === 0, [openersDg.slice(0, 2), openersRp.slice(0, 2)]);
    var dirw = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-wups-'));
    var fw = path.join(dirw, 'r.ps1'); fs.writeFileSync(fw, rp);
    var psrw = runPs(['-NoProfile', '-NonInteractive', '-Command', "$t=$null;$e=$null;[void][System.Management.Automation.Language.Parser]::ParseFile('" + fw + "',[ref]$t,[ref]$e);$e.Count"]);
    if (psrw == null) { console.log('SKIP wu repair script: PowerShell parser (PowerShell not available)'); }
    else { check('wu repair script: PowerShell parser reports no errors', !psrw.failed && psrw.text.trim() === '0', psrw.text.trim()); }

    // pump mutual-exclusion wiring: every engine must skip a node with a wu session, and vice versa.
    var src = pluginSrc();
    check('wu wiring: the winget/OS/deploy/reset pumps and dispatches skip a node holding a troubleshooter session',
        (src.match(/obj\.wuPending != null && obj\.wuPending\[nodeid\] != null/g) || []).length >= 2 &&
        (src.match(/obj\.wuPending && obj\.wuPending\[job\.nodeid\] != null/g) || []).length >= 1 &&
        src.indexOf('invscanner-wu-') >= 0 && /obj\.wuHandleResponse\(nodeid, command\)/.test(src));
    next();
});

steps.push(function (next) {
    var dpW = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-wu-'));
    var wuNodes = [
        { _id: 'node//wu1', meshid: 'mesh//grp1', rname: 'wu1', name: 'WinOne', osdesc: 'Microsoft Windows 11 Pro' },
        { _id: 'node//wul', meshid: 'mesh//grp2', rname: 'wul', name: 'LinOne', osdesc: 'Ubuntu 24.04 LTS' },
        { _id: 'node//wuoff', meshid: 'mesh//grp1', rname: 'wuoff', name: 'WinOff', osdesc: 'Microsoft Windows 10' }
    ];
    var dbW2 = { GetAllType: function (t, cb) { cb(null, t === 'node' ? wuNodes.slice() : meshes.slice()); }, Get: function (id, cb) { cb(null, wuNodes.filter(function (n) { return n._id === id; })); } };
    var sentW = [];
    var agentsW = { 'node//wu1': { send: function (m) { sentW.push(JSON.parse(m)); } }, 'node//wul': { send: function (m) { sentW.push(JSON.parse(m)); } } };
    var oW = factory({ parent: { db: dbW2, datapath: dpW, debug: function () { }, config: { settings: {} }, webserver: { meshes: {}, wsagents: agentsW }, DispatchEvent: function () { } } });
    var gunzW = function (cmd, re) { var mm = String(cmd).match(re); return mm ? require('zlib').gunzipSync(Buffer.from(mm[1], 'base64')).toString('utf8') : ''; };

    oW.handleAdminPostReq({ headers: XHDR, body: { action: 'wu_diag', nodeId: 'node//wu1' } }, mockRes(function (d1) {
        check('wu_diag: dispatches the read-only diagnose on an invscanner-wu- session (runcommands type 1)',
            d1.started === true && sentW.length === 1 && sentW[0].action === 'runcommands' && sentW[0].type === 1 &&
            String(sentW[0].sessionid).indexOf('invscanner-wu-') === 0 && oW.wuPending['node//wu1'] != null &&
            gunzW(sentW[0].cmds, /FromBase64String\('([A-Za-z0-9+\/=]+)'\)/).indexOf('Get-Service') >= 0, sentW[0]);
        oW.handleAdminPostReq({ headers: XHDR, body: { action: 'wu_diag', nodeId: 'node//wul' } }, mockRes(function (dL) {
            check('wu_diag: a non-Windows device is refused', !!dL.error && /Windows/.test(dL.error), dL);
            oW.onAgentResponse({ action: 'msg', type: 'runcommands', sessionid: sentW[0].sessionid, result: 'x' + oW.WU_MARKER +
                '{"diag":true,"services":[{"name":"wuauserv","status":"Running","startup":"Auto"},{"name":"bits","status":"Stopped","startup":"Auto"}],"swExists":true,"swBytes":1024,"swFiles":3,"events":[{"time":"2026-11-01T00:00:00Z","id":20,"level":"Error","msg":"download failed"}],"winhttp":"Access.","rebootPending":true,"rebootSource":"Windows Update","rebootNote":"A reboot is already pending","error":""}' + String.fromCharCode(10) }, '', 'node//wu1');
            var dg = oW.wuResults['node//wu1'];
            check('wu_diag: the answer is consumed + stored (services, download cache, a PENDING reboot surfaced)',
                dg && dg.kind === 'diag' && dg.state === 'ok' && dg.services.length === 2 && dg.swFiles === 3 &&
                dg.rebootPending === true && dg.rebootSource === 'Windows Update' && oW.wuPending['node//wu1'] == null &&
                fs.existsSync(oW.wuResultsPath), dg);
            oW.wuPending['node//wu1'] = { nodeid: 'node//wu1' }; oW.osPending['node//wu1'] = { nodeid: 'node//wu1' };
            oW.handleAdminPostReq({ headers: XHDR, body: { action: 'wu_repair', nodeId: 'node//wu1' } }, mockRes(function (busy) {
                delete oW.osPending['node//wu1'];
                check('wu_repair: a device holding another engine session is refused (one runcommands session per agent)', !!busy.error && /running/.test(busy.error), busy);
                delete oW.wuPending['node//wu1'];
                oW.handleAdminPostReq({ headers: XHDR, body: { action: 'wu_repair', nodeId: 'node//wuoff' } }, mockRes(function (off) {
                    check('wu_repair: an offline device is refused', !!off.error && /offline/i.test(off.error), off);
                    sentW.length = 0;
                    oW.handleAdminPostReq({ headers: XHDR, body: { action: 'wu_repair', nodeId: 'node//wu1' } }, mockRes(function (d2) {
                        check('wu_repair: a repair is dispatched on an invscanner-wu- session running the component reset',
                            d2.started === true && sentW.length === 1 && String(sentW[0].sessionid).indexOf('invscanner-wu-') === 0 &&
                            gunzW(sentW[0].cmds, /FromBase64String\('([A-Za-z0-9+\/=]+)'\)/).indexOf('invWuStep') >= 0, [d2, sentW.length]);
                        var okc = oW.onAgentResponse({ action: 'msg', type: 'runcommands', sessionid: sentW[0].sessionid, result: oW.WU_MARKER +
                            '{"repair":true,"state":"partial","steps":[{"name":"stop services","ok":true,"detail":""},{"name":"reset download folder","ok":false,"detail":"Access denied"},{"name":"reset catroot2","ok":true,"detail":""},{"name":"set start types","ok":true,"detail":""},{"name":"start services","ok":true,"detail":""}],"rebootTriggered":false,"rebootPending":false,"rebootSource":"","rebootNote":"The repair did NOT reboot the device and none is needed","error":""}' + String.fromCharCode(10) }, '', 'node//wu1');
                        var rr = oW.wuResults['node//wu1'];
                        check('wu_repair: a partial answer stores state partial + per-step detail, consumed; no reboot claimed',
                            okc === true && rr.kind === 'repair' && rr.state === 'partial' && rr.steps.length === 5 &&
                            rr.steps[1].ok === false && rr.rebootTriggered === false && oW.wuPending['node//wu1'] == null, rr);
                        oW.handleAdminPostReq({ headers: XHDR, body: { action: 'os_status' } }, mockRes(function (st) {
                            var w = st.devices.filter(function (x) { return x.id === 'node//wu1'; })[0];
                            check('os_status: a Windows device carries its last troubleshooter result (wu)', w && w.wu && w.wu.kind === 'repair' && w.wu.state === 'partial', w && w.wu);
                            oW.handleAdminPostReq({ headers: XHDR, body: { action: 'get_log', type: 'wu' } }, mockRes(function (lgr) {
                                check('get_log wu: the troubleshooter log is reachable', Array.isArray(lgr.lines) && lgr.file === 'plugins/inventoryscanner/wu-troubleshoot.log', lgr);
                                next();
                            }), user);
                        }), user);
                    }), user);
                }), user);
            }), user);
        }), user);
    }), user);
});

steps.push(function (next) {
    var dpT2 = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-wut-'));
    var t2 = [{ _id: 'node//wt1', meshid: 'mesh//grp1', rname: 'wt1', name: 'T', osdesc: 'Microsoft Windows 11' }];
    var dbT2 = { GetAllType: function (t, cb) { cb(null, t === 'node' ? t2.slice() : meshes.slice()); }, Get: function (id, cb) { cb(null, t2.filter(function (n) { return n._id === id; })); } };
    var oT2 = factory({ parent: { db: dbT2, datapath: dpT2, debug: function () { }, config: { settings: {} }, webserver: { meshes: {}, wsagents: {} }, DispatchEvent: function () { } } });
    var e = { nodeid: 'node//wt1', kind: 'diag', since: Date.now() };
    oT2.wuPending['node//wt1'] = e; oT2.wuTimeout(e);
    check('wu timeout: a diagnose that never answered is stored as timeout (no silent success)',
        oT2.wuResults['node//wt1'] && oT2.wuResults['node//wt1'].state === 'timeout' && oT2.wuPending['node//wt1'] == null, oT2.wuResults['node//wt1']);
    next();
});

// ---- v4.7.0 force restart + user notice (issue #6) ----
steps.push(function (next) {
    // message sanitizer: control chars + PowerShell/shell quoting chars are removed, length capped.
    var evil = obj.rbCleanMessage('save your work \u0000 $(reboot) `calc` "x" \\ y\n\tEND', 'DEFAULT');
    check('rbCleanMessage: strips $ ` " \\ and control chars, collapses spaces, caps length',
        evil.indexOf('$') < 0 && evil.indexOf('`') < 0 && evil.indexOf('"') < 0 && evil.indexOf('\\') < 0 && evil.indexOf('\n') < 0 &&
        /\s\s/.test(evil) === false && evil.indexOf('END') >= 0 && evil.length <= obj.RB_MAX_MESSAGE, evil);
    check('rbCleanMessage: empty input falls back to the default', obj.rbCleanMessage('', 'the default msg') === 'the default msg');

    var wn = obj.rbBuildNotifyWindowsScript('Maintenance');
    var wr = obj.rbBuildRebootWindowsScript('Maintenance restart', 60);
    var lr = obj.rbBuildRebootLinuxScript('Maintenance restart', 120);
    check('rb notify win script: msg.exe popup, reports pending reboot + users, NO shutdown command',
        wn.indexOf("msg '*'") >= 0 && wn.indexOf('Auto Update\\RebootRequired') >= 0 && wn.indexOf('Win32_ComputerSystem') >= 0 &&
        wn.indexOf(obj.RB_MARKER) >= 0 && wn.indexOf('shutdown /r') < 0);
    check('rb restart win script: msg + shutdown /r /t <secs> carrying the message, state scheduled, abort hint',
        wr.indexOf("msg '*'") >= 0 && wr.indexOf('shutdown /r /t $invSecs /c "$invMsg"') >= 0 && wr.indexOf('$invSecs = 60') >= 0 &&
        wr.indexOf("'shutdown /a'") >= 0 && wr.indexOf(obj.RB_MARKER) >= 0);
    check('rb restart linux script: wall + shutdown -r with a minute grace (ceil), state from exit code',
        lr.indexOf('wall "$M"') >= 0 && lr.indexOf('shutdown -r $T') >= 0 && lr.indexOf('/var/run/reboot-required') >= 0 &&
        lr.indexOf('who') >= 0 && lr.indexOf(obj.RB_MARKER) >= 0);
    check('rb scripts: the message never reaches the script as a literal (travels base64 only)',
        wr.indexOf('Maintenance restart') < 0 && lr.indexOf('Maintenance restart') < 0);

    // PowerShell parser on the two Windows scripts.
    var dir = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-rbps-'));
    var fp = path.join(dir, 'r.ps1'); fs.writeFileSync(fp, wr);
    var psr = runPs(['-NoProfile', '-NonInteractive', '-Command', "$t=$null;$e=$null;[void][System.Management.Automation.Language.Parser]::ParseFile('" + fp + "',[ref]$t,[ref]$e);$e.Count"]);
    if (psr == null) { console.log('SKIP rb scripts: PowerShell parser (PowerShell not available)'); }
    else { check('rb restart win script: PowerShell parser reports no errors', !psr.failed && psr.text.trim() === '0', psr.text.trim()); }

    var src = pluginSrc();
    check('rb wiring: every engine pump/dispatch skips a node holding a restart session (one runcommands per agent)',
        (src.match(/obj\.rbPending != null && obj\.rbPending\[nodeid\] != null/g) || []).length >= 2 &&
        (src.match(/obj\.rbPending && obj\.rbPending\[job\.nodeid\] != null/g) || []).length >= 1 &&
        src.indexOf('invscanner-rb-') >= 0 && /obj\.rbHandleResponse\(nodeid, command\)/.test(src));
    next();
});

steps.push(function (next) {
    var dpR = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-rb-'));
    var rbNodes = [
        { _id: 'node//rw', meshid: 'mesh//grp1', rname: 'rw', name: 'WinBox', osdesc: 'Microsoft Windows 11 Pro' },
        { _id: 'node//rl', meshid: 'mesh//grp2', rname: 'rl', name: 'LinBox', osdesc: 'Ubuntu 24.04 LTS' },
        { _id: 'node//rmac', meshid: 'mesh//grp1', rname: 'rmac', name: 'MacBox', osdesc: 'macOS 15' },
        { _id: 'node//roff', meshid: 'mesh//grp1', rname: 'roff', name: 'OffBox', osdesc: 'Microsoft Windows 10' }
    ];
    var dbR = { GetAllType: function (t, cb) { cb(null, t === 'node' ? rbNodes.slice() : meshes.slice()); }, Get: function (id, cb) { cb(null, rbNodes.filter(function (n) { return n._id === id; })); } };
    var sentR = [];
    var agentsR = { 'node//rw': { send: function (m) { sentR.push(JSON.parse(m)); } }, 'node//rl': { send: function (m) { sentR.push(JSON.parse(m)); } }, 'node//rmac': { send: function (m) { sentR.push(JSON.parse(m)); } } };
    var oR = factory({ parent: { db: dbR, datapath: dpR, debug: function () { }, config: { settings: {} }, webserver: { meshes: {}, wsagents: agentsR }, DispatchEvent: function () { } } });
    var gunzR = function (cmd) {
        var m = String(cmd).match(/FromBase64String\('([A-Za-z0-9+\/=]+)'\)/) || String(cmd).match(/echo '([A-Za-z0-9+\/=]+)' \| base64 -d \| gzip/);
        return m ? require('zlib').gunzipSync(Buffer.from(m[1], 'base64')).toString('utf8') : '';
    };

    // notify: windows (type 1) - no reboot, no typed name needed.
    oR.handleAdminPostReq({ headers: XHDR, body: { action: 'reboot_notify', nodeId: 'node//rw', message: 'heads up' } }, mockRes(function (n1) {
        check('reboot_notify win: dispatches msg.exe notice on an invscanner-rb- session, runcommands type 1, no shutdown',
            n1.started === true && n1.platform === 'windows' && sentR.length === 1 && sentR[0].type === 1 &&
            String(sentR[0].sessionid).indexOf('invscanner-rb-') === 0 && gunzR(sentR[0].cmds).indexOf('msg') >= 0 &&
            gunzR(sentR[0].cmds).indexOf('shutdown /r') < 0, sentR[0]);
        oR.onAgentResponse({ action: 'msg', type: 'runcommands', sessionid: sentR[0].sessionid, result: 'x' + oR.RB_MARKER +
            '{"notify":true,"platform":"windows","state":"sent","pendingReboot":true,"source":"Windows Update","users":"alice","msg":"heads up","error":""}' + String.fromCharCode(10) }, '', 'node//rw');
        var nr = oR.rbResults['node//rw'];
        check('reboot_notify: answer consumed + stored (sent) and a PENDING reboot + user surfaced',
            nr && nr.kind === 'notify' && nr.state === 'sent' && nr.pendingReboot === true && nr.users === 'alice' && oR.rbPending['node//rw'] == null, nr);

        // linux reboot: type 3 + minute grace.
        sentR.length = 0;
        oR.handleAdminPostReq({ headers: XHDR, body: { action: 'reboot_now', nodeId: 'node//rl', secs: 120, message: 'reboot for upgrade', confirm: 'LinBox' } }, mockRes(function (n2) {
            check('reboot_now linux: runcommands type 3, sh transport, wall + shutdown -r, 2-minute grace (ceil at runtime)',
                n2.started === true && n2.platform === 'linux' && n2.secs === 120 && sentR.length === 1 && sentR[0].type === 3 &&
                gunzR(sentR[0].cmds).indexOf('shutdown -r') >= 0 && gunzR(sentR[0].cmds).indexOf('(120 + 59) / 60') >= 0, sentR[0]);

            // mac / no-platform refused.
            oR.handleAdminPostReq({ headers: XHDR, body: { action: 'reboot_now', nodeId: 'node//rmac', confirm: 'MacBox' } }, mockRes(function (nM) {
                check('reboot_now: macOS / unreported-OS device is refused (restart is Windows + Linux only)', !!nM.error && /Windows and Linux/.test(nM.error), nM);

                // wrong typed name.
                oR.handleAdminPostReq({ headers: XHDR, body: { action: 'reboot_now', nodeId: 'node//rw', secs: 30, confirm: 'Wrong' } }, mockRes(function (nW) {
                    check('reboot_now: a mistyped device name is refused (the typed confirmation guard)', !!nW.error && /device name/.test(nW.error), nW);
                    sentR.length = 0;
                    oR.handleAdminPostReq({ headers: XHDR, body: { action: 'reboot_now', nodeId: 'node//rw', secs: 0, confirm: 'winbox', message: 'now' } }, mockRes(function (n3) {
                        check('reboot_now win: name typed (case-insensitive) -> dispatches shutdown /r /t 0 (immediate)',
                            n3.started === true && n3.secs === 0 && sentR.length === 1 && gunzR(sentR[0].cmds).indexOf('$invSecs = 0') >= 0, [n3, sentR.length]);
                        // reply with state scheduled (grace 0 -> but here we still got a reply)
                        oR.onAgentResponse({ action: 'msg', type: 'runcommands', sessionid: sentR[0].sessionid, result: oR.RB_MARKER +
                            '{"reboot":true,"platform":"windows","state":"scheduled","secs":0,"abort":"shutdown /a","pendingReboot":false,"source":"","users":"","msg":"now","error":""}' }, '', 'node//rw');
                        check('reboot_now: scheduled answer consumed + stored, no browser leak',
                            oR.rbResults['node//rw'].kind === 'reboot' && oR.rbResults['node//rw'].state === 'scheduled' && oR.rbPending['node//rw'] == null, oR.rbResults['node//rw']);

                        // busy: another engine holds the session.
                        oR.osPending['node//rw'] = { nodeid: 'node//rw' };
                        oR.handleAdminPostReq({ headers: XHDR, body: { action: 'reboot_notify', nodeId: 'node//rw', message: 'hi' } }, mockRes(function (bus) {
                            check('reboot_notify: a device holding an OS/winget/deploy/reset/wu session is refused', !!bus.error && /running/.test(bus.error), bus);
                            delete oR.osPending['node//rw'];
                            oR.handleAdminPostReq({ headers: XHDR, body: { action: 'reboot_now', nodeId: 'node//roff', confirm: 'OffBox' } }, mockRes(function (off) {
                                check('reboot_now: an offline device is refused', !!off.error && /offline/i.test(off.error), off);
                                oR.handleAdminPostReq({ headers: XHDR, body: { action: 'get_log', type: 'reboot' } }, mockRes(function (lgr) {
                                    check('get_log reboot: the restart audit log is reachable', Array.isArray(lgr.lines) && lgr.file === 'plugins/inventoryscanner/device-reboot.log', lgr);
                                    // os_status carries the restart record now.
                                    oR.handleAdminPostReq({ headers: XHDR, body: { action: 'os_status' } }, mockRes(function (st) {
                                        var w = st.devices.filter(function (x) { return x.id === 'node//rw'; })[0];
                                        check('os_status: carries the last restart/notice record per device', w && w.rb && w.rb.kind === 'reboot' && w.rb.state === 'scheduled', w && w.rb);
                                        next();
                                    }), user);
                                }), user);
                            }), user);
                        }), user);
                    }), user);
                }), user);
            }), user);
        }), user);
    }), user);
});

steps.push(function (next) {
    var dpT3 = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-rbt-'));
    var t3 = [{ _id: 'node//rt1', meshid: 'mesh//grp1', rname: 'rt1', name: 'RT1', osdesc: 'Microsoft Windows 11' }];
    var dbT3 = { GetAllType: function (t, cb) { cb(null, t === 'node' ? t3.slice() : meshes.slice()); }, Get: function (id, cb) { cb(null, t3.filter(function (n) { return n._id === id; })); } };
    var agentsT3 = {};
    var oT3 = factory({ parent: { db: dbT3, datapath: dpT3, debug: function () { }, config: { settings: {} }, webserver: { meshes: {}, wsagents: agentsT3 }, DispatchEvent: function () { } } });
    var e = { nodeid: 'node//rt1', kind: 'reboot', platform: 'windows', since: Date.now() };
    oT3.rbPending['node//rt1'] = e; oT3.rbTimeout(e);
    check('rb timeout: restart + device offline (it is rebooting) = rebooted, not a failure',
        oT3.rbResults['node//rt1'] && oT3.rbResults['node//rt1'].state === 'rebooted' && oT3.rbPending['node//rt1'] == null, oT3.rbResults['node//rt1']);
    agentsT3['node//rt1'] = { send: function () { } };
    var e2 = { nodeid: 'node//rt1', kind: 'reboot', platform: 'windows', since: Date.now() };
    oT3.rbPending['node//rt1'] = e2; oT3.rbTimeout(e2);
    check('rb timeout: restart + still online and silent = no-answer', oT3.rbResults['node//rt1'] && oT3.rbResults['node//rt1'].state === 'no-answer', oT3.rbResults['node//rt1']);
    next();
});

// ---- v4.8.0 license keys in the software CSV (issue #7) ----
steps.push(function (next) {
    check('license opt-in: collection is OFF by default AND the schedule is off by default (interval 0 = on demand only)',
        obj.licenseConfig().collectEnabled === false && obj.licenseConfig().collectIntervalHours === 0 &&
        typeof obj.licPump === 'undefined' && typeof obj.licStartBatch === 'undefined');

    // table apply + safety + rule sanitization
    var good = JSON.stringify({ entries: [{ match: 'adobe', label: 'Adobe Acrobat', rules: [{ type: 'registry', path: 'HKLM:\\SOFTWARE\\Adobe', value: 'Serial' }] }] });
    var rGood = obj.applyLicenseTableText(good);
    check('license table: valid {match,label,rules[registry]} applies', rGood.ok === true && rGood.applied === 1, rGood);
    var badType = obj.applyLicenseTableText(JSON.stringify({ entries: [{ match: 'x', label: 'X', rules: [{ type: 'command', cmd: 'calc' }] }] }));
    check('license table: a rule of a type other than registry/file/wmi is rejected (no command rule exists)', badType.applied === 0, badType);
    var bomb = obj.applyLicenseTableText(JSON.stringify({ entries: [{ match: '(a+)+', label: 'X', rules: [{ type: 'file', path: 'C:\\a' }] }] }));
    check('license table: a catastrophic-backtracking match regex is skipped (same gate as the CPE table)', bomb.applied === 0, bomb);
    check('license sanitize: registry needs path+value, wmi needs class+property, file needs path, max 8 rules',
        obj.sanitizeLicenseRules([{ type: 'registry', path: 'p' }]) === null &&
        obj.sanitizeLicenseRules([{ type: 'wmi', class: 'c' }]) === null &&
        obj.sanitizeLicenseRules([{ type: 'file', path: 'p', regex: '(b+)+' }]) === null &&
        obj.sanitizeLicenseRules(Array(9).fill({ type: 'file', path: 'p' })) === null &&
        (function () { var s = obj.sanitizeLicenseRules([{ type: 'file', path: 'C:\\a', regex: 'K=([0-9A-Z]+)' }]); return s && s[0].regex === 'K=([0-9A-Z]+)'; })());

    // resolution order: custom beats curated table
    obj.customLicenseEntries = []; obj.remoteLicenseEntries = null;
    obj.applyLicenseTableText(JSON.stringify({ entries: [{ match: 'office', label: 'Office(table)', rules: [{ type: 'registry', path: 'HKLM:\\a', value: 'v' }] }] }));
    obj.customLicenseEntries = [{ match: 'office', label: 'Office(custom)', rules: [{ type: 'file', path: 'C:\\c.lic', line: 1 }] }];
    check('license resolve: custom rules are consulted before the curated table', obj.licenseRulesForApp('Microsoft Office 2019').label === 'Office(custom)');
    check('license resolve: a name with no rule yields null', obj.licenseRulesForApp('Notepad') === null);
    obj.customLicenseEntries = [];

    // script shape: read-only, base64-embedded rules, marker; no reboot / no write commands
    var scr = obj.licenseBuildScript([{ name: 'Adobe Acrobat', label: 'Adobe Acrobat', rules: [{ type: 'registry', path: 'HKLM:\\SOFTWARE\\Adobe', value: 'Serial' }, { type: 'file', path: 'C:\\lic.dat', regex: 'KEY=([A-Z-]+)' }, { type: 'wmi', class: 'SoftwareLicensingProduct', property: 'PartialProductKey' }] }], true);
    check('license script: reads via GetValue/Get-Content/Get-CimInstance, emits the marker, never writes or reboots',
        scr.indexOf('.GetValue(') >= 0 && scr.indexOf('Get-Content') >= 0 && scr.indexOf('SoftwareLicensingProduct') >= 0 && scr.indexOf(obj.LIC_MARKER) >= 0 &&
        !/Set-|New-Item|Remove-Item|shutdown|Restart-Computer/i.test(scr));
    check('license script: the rule strings are base64, never a literal path in the script body', scr.indexOf('FromBase64String') >= 0 && scr.indexOf('HKLM:\\SOFTWARE\\Adobe') < 0);
    var openersL = scr.split(String.fromCharCode(10)).filter(function (l) { return /[({]\s*$/.test(l); });
    check('license script: one statement per line', openersL.length === 0, openersL.slice(0, 2));
    var dir = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-licps-'));
    var fp = path.join(dir, 'l.ps1'); fs.writeFileSync(fp, scr);
    var psr = runPs(['-NoProfile', '-NonInteractive', '-Command', "$t=$null;$e=$null;[void][System.Management.Automation.Language.Parser]::ParseFile('" + fp + "',[ref]$t,[ref]$e);$e.Count"]);
    if (psr == null) { console.log('SKIP license script: PowerShell parser (PowerShell not available)'); }
    else { check('license script: PowerShell parser reports no errors', !psr.failed && psr.text.trim() === '0', psr.text.trim()); }

    var src = pluginSrc();
    check('license wiring: collector routes invscanner-lic- sessions and every pump/dispatch skips a license run',
        src.indexOf('invscanner-lic-') >= 0 && /obj\.licHandleResponse\(nodeid, command\)/.test(src) &&
        (src.match(/obj\.licPending != null && obj\.licPending\[nodeid\] != null/g) || []).length >= 2 &&
        (src.match(/obj\.licPending && obj\.licPending\[job\.nodeid\] != null/g) || []).length >= 1 &&
        /action === 'lic_collect'/.test(src) && /action === 'lic_status'/.test(src));
    next();
});

steps.push(function (next) {
    var dpL = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-lic-'));
    var lNodes = [
        { _id: 'node//lc1', meshid: 'mesh//grp1', rname: 'lc1', name: 'LicWin', osdesc: 'Microsoft Windows 11 Pro' },
        { _id: 'node//lmac', meshid: 'mesh//grp1', rname: 'lmac', name: 'LicMac', osdesc: 'macOS 15' },
        { _id: 'node//loff', meshid: 'mesh//grp1', rname: 'loff', name: 'LicOff', osdesc: 'Microsoft Windows 10' }
    ];
    var dbL = { GetAllType: function (t, cb) { cb(null, t === 'node' ? lNodes.slice() : meshes.slice()); }, Get: function (id, cb) { cb(null, lNodes.filter(function (n) { return n._id === id; })); } };
    var sentL = [];
    var agentsL = { 'node//lc1': { send: function (m) { sentL.push(JSON.parse(m)); } }, 'node//lmac': { send: function (m) { sentL.push(JSON.parse(m)); } } };
    var oL = factory({ parent: { db: dbL, datapath: dpL, debug: function () { }, config: { settings: {} }, webserver: { meshes: {}, wsagents: agentsL }, DispatchEvent: function () { } } });
    var gunzL = function (cmd) { var m = String(cmd).match(/FromBase64String\('([A-Za-z0-9+\/=]+)'\)/); return m ? require('zlib').gunzipSync(Buffer.from(m[1], 'base64')).toString('utf8') : ''; };
    // seed software on lc1 + a custom rule so the script has something to read
    oL.softwareInventory = { lc1: { time: new Date().toISOString(), apps: [{ name: 'Adobe Acrobat Pro', version: '11' }] } };
    oL.customLicenseEntries = [{ match: 'acrobat', label: 'Adobe Acrobat', rules: [{ type: 'registry', path: 'HKLM:\\SOFTWARE\\Adobe', value: 'Serial' }] }];

    // off first: collect refused
    oL.handleAdminPostReq({ headers: XHDR, body: { action: 'lic_collect', nodeId: 'node//lc1' } }, mockRes(function (off) {
        check('lic_collect: refused while collection is off (opt-in)', !!off.error && /off/i.test(off.error), off);
        oL.pluginSettings = { inventoryScanner: { licenseCollectionEnabled: true, licenseMsKeys: true } };
        oL.handleAdminPostReq({ headers: XHDR, body: { action: 'lic_collect', nodeId: 'node//lmac' } }, mockRes(function (mac) {
            check('lic_collect: macOS device is refused (license extraction is Windows)', !!mac.error && /Windows/.test(mac.error), mac);
            oL.handleAdminPostReq({ headers: XHDR, body: { action: 'lic_collect', nodeId: 'node//loff' } }, mockRes(function (o2) {
                check('lic_collect: offline device refused', !!o2.error && /offline/i.test(o2.error), o2);
                sentL.length = 0;
                oL.handleAdminPostReq({ headers: XHDR, body: { action: 'lic_collect', nodeId: 'node//lc1' } }, mockRes(function (d1) {
                    check('lic_collect: dispatches a read-only rule script on invscanner-lic- (type 1) and reserves the node',
                        d1.started === true && sentL.length === 1 && sentL[0].type === 1 && String(sentL[0].sessionid).indexOf('invscanner-lic-') === 0 &&
                        oL.licPending['node//lc1'] != null && gunzL(sentL[0].cmds).indexOf('.GetValue(') >= 0, sentL[0]);
                    var consumed = oL.onAgentResponse({ action: 'msg', type: 'runcommands', sessionid: sentL[0].sessionid, result: 'x' + oL.LIC_MARKER +
                        '{"collect":true,"items":[{"name":"Adobe Acrobat Pro","label":"Adobe Acrobat","source":"registry","license":"AA-BB-CC","ok":true}],"ms":[{"name":"Windows","key":"*****-WXYZ"}],"error":""}' + String.fromCharCode(10) }, '', 'node//lc1');
                    var inv = oL.licenseInventory['lc1'];
                    check('lic_collect: answer consumed + stored per node + a license map by name',
                        consumed === true && inv && inv.items[0].license === 'AA-BB-CC' && oL.licPending['node//lc1'] == null &&
                        fs.existsSync(path.join(oL.inventoryDataPath, 'lc1', 'license.json')) &&
                        oL.licenseMapForNode('node//lc1')['adobe acrobat pro'].license === 'AA-BB-CC', inv);

                    // busy: another engine holds the session
                    oL.osPending['node//lc1'] = { nodeid: 'node//lc1' };
                    oL.handleAdminPostReq({ headers: XHDR, body: { action: 'lic_collect', nodeId: 'node//lc1' } }, mockRes(function (bs) {
                        check('lic_collect: a device with another engine session is refused (one runcommands session per agent)', !!bs.error && /running/i.test(bs.error), bs);
                        delete oL.osPending['node//lc1'];
                        // custom add/remove round trip
                        oL.handleAdminPostReq({ headers: XHDR, body: { action: 'add_license', match: '^Zoom', label: 'Zoom', rules: JSON.stringify([{ type: 'file', path: 'C:\\z.json', jsonfield: 'license' }]) } }, mockRes(function (ad) {
                            check('add_license: valid custom rule stored + retrievable via get_license_table', ad.success === true && oL.customLicenseEntries.length === 2, ad);
                            oL.handleAdminPostReq({ headers: XHDR, body: { action: 'add_license', match: 'x', label: 'X', rules: JSON.stringify([{ type: 'command', cmd: 'calc' }]) } }, mockRes(function (badAdd) {
                                check('add_license: a rule of an unknown type is rejected', !!badAdd.error && /registry|file|wmi/i.test(badAdd.error), badAdd);
                                oL.handleAdminPostReq({ headers: XHDR, body: { action: 'lic_status' } }, mockRes(function (st) {
                                    var w = st.devices.filter(function (x) { return x.id === 'node//lc1'; })[0];
                                    check('lic_status: Windows devices only + collected summary', st.devices.length === 2 && w && w.collected && w.collected.found === 1 && w.collected.ms === 1, st.devices);
                                    oL.handleAdminPostReq({ headers: XHDR, body: { action: 'get_log', type: 'license' } }, mockRes(function (lg) {
                                        check('get_log license: the collection log is reachable', Array.isArray(lg.lines) && lg.file === 'plugins/inventoryscanner/license-collection.log', lg);
                                        // license columns reach the software CSV via the shared obj
                                        obj.licenseInventory = { d1: { time: new Date().toISOString(), items: [{ name: 'Firefox', source: 'registry', license: 'FIRE-KEY', ok: true }], ms: [] } };
                                        obj.buildCsvForNodes([nodes[0]], 'software', function (cerr, csv) {
                                            check('CSV software: gains License + License Source columns with the collected value',
                                                /License Source/.test(csv) && /FIRE-KEY/.test(csv), (csv || '').split('\r\n').slice(0, 2));
                                            obj.licenseInventory = {};
                                            next();
                                        });
                                    }), user);
                                }), user);
                            }), user);
                        }), user);
                    }), user);
                }), user);
            }), user);
        }), user);
    }), user);
});

steps.push(function (next) {
    var dpF = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-fleet-'));
    var fNodes = [
        { _id: 'node//f1', meshid: 'mesh//grp1', rname: 'f1', name: 'Alpha', osdesc: 'Microsoft Windows 11' },
        { _id: 'node//f2', meshid: 'mesh//grp1', rname: 'f2', name: 'Beta', osdesc: 'Microsoft Windows 10' }
    ];
    var dbF = { GetAllType: function (t, cb) { cb(null, t === 'node' ? fNodes.slice() : meshes.slice()); }, Get: function (id, cb) { cb(null, fNodes.filter(function (n) { return n._id === id; })); } };
    var sentF = [];
    var agentsF = { 'node//f1': { send: function (m) { sentF.push(m); } }, 'node//f2': { send: function (m) { sentF.push(m); } } };
    var oF = factory({ parent: { db: dbF, datapath: dpF, debug: function () { }, config: { settings: {} }, webserver: { meshes: {}, wsagents: agentsF }, DispatchEvent: function () { } } });
    oF.softwareInventory = {
        f1: { time: new Date().toISOString(), apps: [{ name: 'Firefox', version: '1.0', publisher: 'Mozilla' }, { name: 'Notepad', version: '11', publisher: 'Microsoft' }] },
        f2: { time: new Date().toISOString(), apps: [{ name: 'Firefox', version: '1.2', publisher: 'Mozilla' }] }
    };
    oF.licenseInventory = { f1: { time: new Date().toISOString(), items: [{ name: 'Firefox', license: 'FIRE-KEY', source: 'registry' }], ms: [] } };
    oF.wgResults = { 'node//f1': { time: new Date().toISOString(), dry: true, results: [{ id: 'Microsoft.Notepad', name: 'Notepad', from: '11', to: '12', state: 'dry-run' }] } };
    oF.scanDeviceSoftware = function (list, cb) {
        var out = [];
        for (var i = 0; i < (list || []).length; i++) {
            var a = list[i]; var nm = String((a && (a.name || a.Name)) || '');
            if (/firefox/i.test(nm)) out.push({ isCve: true, cve: 'CVE-2024-0001', severity: 'CRITICAL', software: nm, version: String(a.version || '') });
            else out.push({ isCve: false, cve: '', severity: '', software: nm, version: String(a.version || '') });
        }
        cb(out);
    };
    check('fleet index: buildFleetIndex + swFleetHandler exist and the route is wired',
        typeof oF.buildFleetIndex === 'function' && typeof oF.swFleetHandler === 'function' && /action === 'sw_fleet'/.test(pluginSrc()));

    oF.handleAdminPostReq({ headers: XHDR, body: { action: 'sw_fleet' } }, mockRes(function (d) {
        var ff = (d.software || []).filter(function (x) { return /firefox/i.test(x.name); })[0];
        var nn = (d.software || []).filter(function (x) { return /notepad/i.test(x.name); })[0];
        check('sw_fleet: read-only - the route sends NO agent command', sentF.length === 0, sentF.length);
        check('sw_fleet: deviceCount per software + fleet device count', d.devices === 2 && ff && ff.deviceCount === 2 && nn && nn.deviceCount === 1, [d.devices, ff, nn]);
        check('sw_fleet: vulnerable flag + distinct CVE count + max severity per software',
            ff && ff.vulnerable === true && ff.cve === 1 && ff.maxSeverity === 'CRITICAL' && nn && nn.vulnerable === false, [ff, nn]);
        check('sw_fleet: the winget updatable flag joins the last dry run by name', nn && nn.updatable === true && ff && ff.updatable === false, [ff, nn]);
        check('sw_fleet: the collected-license flag comes only from the local license map', ff && ff.hasLicense === true && nn && nn.hasLicense === false, [ff, nn]);
        check('sw_fleet: byDevice carries the per-device CVE count for the unified device list',
            d.byDevice && d.byDevice['node//f1'] && d.byDevice['node//f1'].cve === 1 && d.byDevice['node//f2'] && d.byDevice['node//f2'].cve === 1, d.byDevice);
        check('sw_fleet: distinct installed versions are counted (Firefox has 2 across the fleet)', ff && ff.versions === 2, ff);
        oF.buildFleetIndex(function (e1, data1) {
            check('sw_fleet: the result is cached (the next read returns the same object, no re-scan)', data1 === d && oF._fleetIndexCache != null, typeof data1);
            oF.buildFleetIndex(function (e2, data2) {
                check('sw_fleet: force bypasses the cache and rebuilds a fresh object', data2 !== d && Array.isArray(data2.software), typeof data2);
                check('fleet index: the module adds no scheduler/pump and sends no command (pure aggregation)',
                    typeof oF.licPump === 'undefined' && typeof oF.swFleetPump === 'undefined' && typeof oF.scheduleFleetIndex === 'undefined' && sentF.length === 0, sentF.length);
                next();
            }, true);
        });
    }), user);
});

// ---- v5.0.0 external asset-management connector (issue #5): opt-in, validation ----
steps.push(function (next) {
    var dpA = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-as-'));
    var aNodes = [
        { _id: 'node//a1', meshid: 'mesh//grp1', rname: 'ah1', name: 'AssetOne', osdesc: 'Microsoft Windows 11 Pro', ip: '10.0.0.5' },
        { _id: 'node//a2', meshid: 'mesh//grp1', rname: 'ah2', name: 'AssetTwo', osdesc: 'Ubuntu 24.04 LTS' }
    ];
    var dbA = { GetAllType: function (t, cb) { cb(null, t === 'node' ? aNodes.slice() : meshes.slice()); }, Get: function (id, cb) { cb(null, aNodes.filter(function (n) { return n._id === id; })); } };
    var sentA = [];
    var agentsA = { 'node//a1': { send: function (m) { sentA.push(m); } }, 'node//a2': { send: function (m) { sentA.push(m); } } };
    var oA = factory({ parent: { db: dbA, datapath: dpA, debug: function () { }, config: { settings: {} }, webserver: { meshes: {}, wsagents: agentsA }, DispatchEvent: function () { } } });

    var c0 = oA.assetConfig();
    check('asset: OFF by default - no target, no interval, nothing can leave the server',
        c0.enabled === false && c0.intervalHours === 0 && c0.targetType === 'generic' && c0.endpointUrl === '' && c0.only === 'all', c0);
    check('asset: the connector defines no agent-facing pump/dispatch (it never reaches a device)',
        typeof oA.asPump === 'undefined' && typeof oA.asDispatch === 'undefined' && typeof oA.asBuildScript === 'undefined');

    oA.handleAdminPostReq({ headers: XHDR, body: { action: 'as_push' } }, mockRes(function (ref) {
        check('as_push: refused while disabled (opt-in, deliberate)', !!ref.error && /disabled/i.test(ref.error), ref);
        oA.handleAdminPostReq({ headers: XHDR, body: { action: 'as_save_config', enabled: 'true', targetType: 'generic', endpointUrl: 'http://insecure.example.com/ingest', bodyTemplate: '{}' } }, mockRes(function (v1) {
            check('as_save_config: a non-https endpoint is rejected (credentials must never travel in the clear)', !!v1.error && /https/i.test(v1.error), v1);
            oA.handleAdminPostReq({ headers: XHDR, body: { action: 'as_save_config', enabled: 'true', targetType: 'generic', endpointUrl: '' } }, mockRes(function (v2) {
                check('as_save_config: enabling without an endpoint URL is rejected', !!v2.error, v2);
                oA.handleAdminPostReq({ headers: XHDR, body: { action: 'as_save_config', enabled: 'true', targetType: 'jira', endpointUrl: 'https://acme.atlassian.net', jiraProject: '' } }, mockRes(function (v3) {
                    check('as_save_config: the Jira preset needs a project key', !!v3.error && /project/i.test(v3.error), v3);
                    oA.handleAdminPostReq({ headers: XHDR, body: { action: 'as_save_config', enabled: 'true', targetType: 'generic', endpointUrl: 'https://am.example.com/ingest', bodyTemplate: '{ not json' } }, mockRes(function (v4) {
                        check('as_save_config: an invalid JSON body template is rejected before anything is stored', !!v4.error && /JSON/i.test(v4.error), v4);
                        check('asset: every rejected save left the connector disabled', oA.assetConfig().enabled === false && sentA.length === 0, sentA.length);
                        next();
                    }), user);
                }), user);
            }), user);
        }), user);
    }), user);
});

// ---- v5.0.0 asset connector: secrets, request builders, the push itself, log redaction, scheduler ----
steps.push(function (next) {
    var dpB = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-as2-'));
    var bNodes = [
        { _id: 'node//b1', meshid: 'mesh//grp1', rname: 'bh1', name: 'AssetOne', osdesc: 'Microsoft Windows 11 Pro', ip: '10.0.0.9' },
        { _id: 'node//b2', meshid: 'mesh//grp1', rname: 'bh2', name: 'AssetTwo', osdesc: 'Ubuntu 24.04 LTS' }
    ];
    var bSys = {
        'sinode//b1': { _id: 'sinode//b1', doc: { hardware: { identifiers: { cpu_name: 'Intel i7', manufacturer: 'Dell', model: 'OptiPlex', serial: 'SN-B1', bios_version: '1.2.3' }, totalMemory: 17179869184 } } },
        'sinode//b2': { _id: 'sinode//b2', doc: { hardware: { identifiers: { cpu_name: 'AMD EPYC', serial: 'SN-B2' } } } }
    };
    var dbB = { GetAllType: function (t, cb) { cb(null, t === 'node' ? bNodes.slice() : meshes.slice()); }, Get: function (id, cb) { if (bSys[id]) { cb(null, [bSys[id]]); return; } cb(null, bNodes.filter(function (n) { return n._id === id; })); } };
    var sentB = [];
    var agentsB = { 'node//b1': { send: function (m) { sentB.push(m); } }, 'node//b2': { send: function (m) { sentB.push(m); } } };
    var oB = factory({ parent: { db: dbB, datapath: dpB, debug: function () { }, config: { settings: {} }, webserver: { meshes: {}, wsagents: agentsB }, DispatchEvent: function () { } } });
    oB.softwareInventory = {
        b1: { time: 'x', apps: [{ name: 'Firefox', version: '1.0', publisher: 'Mozilla' }, { name: 'Notepad', version: '11', publisher: 'Microsoft' }] },
        b2: { time: 'x', apps: [{ name: 'vim', version: '9', publisher: '' }] }
    };
    oB.scanDeviceSoftware = function (list, cb) {
        var out = [];
        for (var i = 0; i < (list || []).length; i++) {
            var nm = String((list[i] && (list[i].name || list[i].Name)) || '');
            if (/firefox/i.test(nm)) out.push({ isCve: true, cve: 'CVE-2024-0001', severity: 'CRITICAL', cvss: 9.8, software: nm, version: String(list[i].version || '') });
            else out.push({ isCve: false, cve: '', severity: '', software: nm, version: String(list[i].version || '') });
        }
        cb(out);
    };
    // other sections of the settings file must survive an asset save (the winget trap of v3.5.1)
    oB.pluginSettings = { wingetUpdater: { enabled: true, excludeNodes: ['node//b2'] }, inventoryScanner: { collectIntervalMinutes: 60 } };

    var SECRETTOKEN = 'SECRETTOKEN-abc123';
    var captured = [];
    oB.assetHttp = function (opts, cb) { captured.push(opts); cb(null, { statusCode: 201, text: '{"id":"ext-77","key":"INV-77"}' }); };

    oB.handleAdminPostReq({ headers: XHDR, body: {
        action: 'as_save_config', enabled: 'true', targetType: 'generic', endpointUrl: 'https://am.example.com/ingest',
        authMode: 'bearer', token: SECRETTOKEN, method: 'POST', only: 'all', intervalHours: '0',
        headersJson: '{"X-Tenant":"acme"}', externalIdPath: 'id',
        bodyTemplate: '{"name":"{{device.given}} {{device.host}}","os":"{{device.os}}","serial":"{{hardware.serial}}","apps":"{{software}}","vulns":"{{vulnerabilities}}","n":"{{counts.software}}"}'
    } }, mockRes(function (saved) {
        check('as_save_config: a valid https target is stored and the connector is enabled', saved.config && saved.config.enabled === true && oB.assetConfig().endpointUrl === 'https://am.example.com/ingest', saved.config);
        check('as_save_config: the OTHER sections of scanner-settings.json survive (wingetUpdater + inventoryScanner)',
            oB.pluginSettings.wingetUpdater && oB.pluginSettings.wingetUpdater.excludeNodes[0] === 'node//b2' && oB.pluginSettings.inventoryScanner.collectIntervalMinutes === 60, Object.keys(oB.pluginSettings));
        check('as_save_config: the secret is stored on the server (so the push can authenticate)', oB.assetConfig().token === SECRETTOKEN);
        check('as_get_config: the secret is NEVER returned in the clear - only a mask + a "is set" flag',
            saved.config.tokenMask === oB.AS_MASK && saved.config.hasToken === true && JSON.stringify(saved).indexOf(SECRETTOKEN) < 0, saved.config.tokenMask);

        // a blank secret keeps the stored one; the explicit sentinel clears it
        oB.handleAdminPostReq({ headers: XHDR, body: { action: 'as_save_config', enabled: 'true', targetType: 'generic', endpointUrl: 'https://am.example.com/ingest', authMode: 'bearer', token: '', bodyTemplate: '{}' } }, mockRes(function (keepRes) {
            check('as_save_config: leaving the secret blank KEEPS the stored value (it is never round-tripped through the browser)', oB.assetConfig().token === SECRETTOKEN, keepRes.config && keepRes.config.hasToken);
            // v5.0.1: an enabled bearer target without a token would only ever produce 401s -> refused
            oB.handleAdminPostReq({ headers: XHDR, body: { action: 'as_save_config', enabled: 'true', targetType: 'generic', endpointUrl: 'https://am.example.com/ingest', authMode: 'bearer', token: oB.AS_CLEAR, bodyTemplate: '{"a":1}' } }, mockRes(function (refClear) {
                check('v5.0.1 save: clearing the token while enabled+bearer is refused (it would only ever fail with 401)', !!refClear.error && /needs a token/i.test(refClear.error) && oB.assetConfig().token === SECRETTOKEN, refClear.error);
            oB.handleAdminPostReq({ headers: XHDR, body: { action: 'as_save_config', enabled: 'false', targetType: 'generic', endpointUrl: 'https://am.example.com/ingest', authMode: 'bearer', token: oB.AS_CLEAR, bodyTemplate: '{"a":1}' } }, mockRes(function () {
                check('as_save_config: the clear sentinel erases the stored secret (with the connector disabled)', oB.assetConfig().token === '' && oB.assetConfig()._hasToken === false);
                // restore for the push test (the section is replaced wholesale on every save)
                oB.pluginSettings.assetManagement.enabled = true;
                oB.pluginSettings.assetManagement.token = SECRETTOKEN;
                oB.pluginSettings.assetManagement.headersJson = '{"X-Tenant":"acme"}';
                oB.pluginSettings.assetManagement.externalIdPath = 'id';
                oB.pluginSettings.assetManagement.bodyTemplate = '{"name":"{{device.given}} {{device.host}}","os":"{{device.os}}","serial":"{{hardware.serial}}","apps":"{{software}}","vulns":"{{vulnerabilities}}","n":"{{counts.software}}"}';

                // ---- builders (pure) ----
                var rec = {
                    device: { id: 'node//b1', host: 'bh1', given: 'AssetOne', group: 'HQ', os: 'Microsoft Windows 11 Pro', platform: 'windows', online: true },
                    hardware: { cpu: 'Intel i7', manufacturer: 'Dell', model: 'OptiPlex', serial: 'SN-B1', bios: '1.2.3', memoryBytes: 17179869184, os: 'Microsoft Windows 11 Pro', ip: '10.0.0.9' },
                    software: [{ name: 'Firefox', version: '1.0', publisher: 'Mozilla', location: '', date: '' }],
                    vulnerabilities: [{ id: 'CVE-2024-0001', status: 'CVE', severity: 'CRITICAL', cvss: 9.8, software: 'Firefox', version: '1.0', description: '' }],
                    coverage: [],
                    counts: { software: 1, vulnerabilities: 1, coverage: 0, findings: 1, uniqueFindingIds: 1, maxSeverity: 'CRITICAL' }
                };
                var gcfg = oB.assetConfig();
                var gb = oB.asBuildRequests(rec, gcfg, null);
                var g0 = (gb.requests && gb.requests[0]) || null;
                check('generic builder: method/https URL + the admin headers + the bearer auth are applied',
                    !gb.error && g0 && g0.method === 'POST' && g0.url === 'https://am.example.com/ingest' &&
                    g0.headers['X-Tenant'] === 'acme' && g0.headers['Authorization'] === 'Bearer ' + SECRETTOKEN, gb.error || g0);
                check('generic builder: the template is filled - text interpolation, typed array injection and numbers',
                    !!g0 && g0.body.name === 'AssetOne bh1' && g0.body.serial === 'SN-B1' &&
                    Array.isArray(g0.body.apps) && g0.body.apps[0].name === 'Firefox' &&
                    Array.isArray(g0.body.vulns) && g0.body.vulns[0].id === 'CVE-2024-0001' &&
                    g0.body.n === 1, g0 && g0.body);

                var jcfg = { targetType: 'jira', endpointUrl: 'https://acme.atlassian.net/', authMode: 'basic', username: 'admin@acme.com', password: 'apitok', jiraProject: 'IT', jiraIssueType: 'Task', jiraLabel: 'inventory-scanner', jiraSummary: '[Inventory] {{device.host}}' };
                var jNew = oB.asBuildRequests(rec, jcfg, null);
                var j0 = (jNew.requests && jNew.requests[0]) || null;
                check('jira builder: first push CREATES an issue (project + issue type + label + an ADF description)',
                    !!j0 && j0.method === 'POST' && j0.url === 'https://acme.atlassian.net/rest/api/3/issue' &&
                    j0.body.fields.project.key === 'IT' && j0.body.fields.issuetype.name === 'Task' &&
                    j0.body.fields.labels[0] === 'inventory-scanner' && j0.body.fields.summary === '[Inventory] bh1' &&
                    j0.body.fields.description.type === 'doc', jNew.error || j0);
                check('jira builder: basic auth is base64(user:password)',
                    !!j0 && j0.headers['Authorization'] === 'Basic ' + Buffer.from('admin@acme.com:apitok').toString('base64'), j0 && j0.headers);
                var jUpd = oB.asBuildRequests(rec, jcfg, 'INV-77');
                var ju0 = (jUpd.requests && jUpd.requests[0]) || null;
                check('jira builder: a later push UPDATES the stored issue instead of creating a duplicate',
                    !!ju0 && ju0.method === 'PUT' && ju0.url === 'https://acme.atlassian.net/rest/api/3/issue/INV-77', jUpd.error || ju0);

                var scfg = { targetType: 'snipeit', endpointUrl: 'https://snipe.example.com', authMode: 'bearer', token: 'snipetok', snipeNameTemplate: '{{device.given}}', snipeCategory: 3 };
                var sNew = oB.asBuildRequests(rec, scfg, null);
                var s0 = (sNew.requests && sNew.requests[0]) || null;
                check('snipeit builder: first push POSTs a hardware asset with the mapped fields',
                    !!s0 && s0.method === 'POST' && s0.url === 'https://snipe.example.com/api/hardware' &&
                    s0.body.name === 'AssetOne' && s0.body.serial === 'SN-B1' && s0.body.category_id === 3 &&
                    s0.headers['Authorization'] === 'Bearer snipetok', sNew.error || s0);
                var sUpd = oB.asBuildRequests(rec, scfg, '4711');
                var su0 = (sUpd.requests && sUpd.requests[0]) || null;
                check('snipeit builder: a later push PATCHes the stored asset id (no duplicates)',
                    !!su0 && su0.method === 'PATCH' && su0.url === 'https://snipe.example.com/api/hardware/4711', sUpd.error || su0);

                var hcfg = { targetType: 'generic', endpointUrl: 'http://plain.example.com', authMode: 'none', method: 'POST', bodyTemplate: '{}' };
                check('builder: a non-https endpoint is refused even at build time', !!oB.asBuildRequests(rec, hcfg, null).error);
                var hhdr = oB.asAuthHeaders({ authMode: 'header', headerName: 'X-Api-Key', headerValue: 'k1' });
                check('auth: the custom-header mode sets exactly the configured header', hhdr['X-Api-Key'] === 'k1' && Object.keys(hhdr).length === 1, hhdr);

                // ---- the push itself ----
                captured.length = 0;
                oB.handleAdminPostReq({ headers: XHDR, body: { action: 'as_push' } }, mockRes(function (pushed) {
                    check('as_push: answers IMMEDIATELY and runs in the background (no HTTP timeout on a big fleet)',
                        pushed.started === true && pushed.devices === 2 && pushed.background === true, pushed);
                    waitPush(oB, function () {
                    check('as_push: it issues NO agent command at all (server-side aggregation only)', sentB.length === 0, sentB.length);
                    check('as_push: one https request per device to the configured endpoint with the filled body',
                        captured.length === 2 && captured.every(function (c) { return c.url === 'https://am.example.com/ingest' && c.method === 'POST'; }) &&
                        captured.some(function (c) { return c.body.name === 'AssetOne bh1'; }) && captured.some(function (c) { return c.body.name === 'AssetTwo bh2'; }), captured.map(function (c) { return c.body && c.body.name; }));
                    check('as_push: the external id from the answer is stored so the next push updates instead of duplicating',
                        oB.asResults['node//b1'] && oB.asResults['node//b1'].status === 'ok' && oB.asResults['node//b1'].httpCode === 201 &&
                        oB.asResults['node//b1'].externalId === 'ext-77' && fs.existsSync(oB.asResultsPath), oB.asResults['node//b1']);
                    check('as_push: the connector is unlocked again once the run finished', oB.asPushing === false, oB.asPushing);

                    var logText = fs.readFileSync(oB.asLogPath, 'utf8');
                    check('asset log: records device + status only - NEVER the credential and NEVER the payload',
                        logText.indexOf(SECRETTOKEN) < 0 && logText.indexOf('Authorization') < 0 && logText.indexOf('Firefox') < 0 &&
                        logText.indexOf('Mozilla') < 0 && logText.indexOf('SN-B1') < 0 && logText.indexOf('push ok') >= 0, logText.substring(0, 300));

                    // only=vulnerable skips clean devices
                    oB.pluginSettings.assetManagement.only = 'vulnerable';
                    captured.length = 0;
                    oB.handleAdminPostReq({ headers: XHDR, body: { action: 'as_push', nodeIds: 'node//b2' } }, mockRes(function (sk) {
                        waitPush(oB, function () {
                        check('as_push: "only devices with vulnerabilities" skips a clean device without sending anything',
                            captured.length === 0 && oB.asResults['node//b2'] && oB.asResults['node//b2'].status === 'skipped', oB.asResults['node//b2']);
                        oB.pluginSettings.assetManagement.only = 'all';

                        // test request + scheduler + log route
                        captured.length = 0;
                        oB.handleAdminPostReq({ headers: XHDR, body: { action: 'as_test' } }, mockRes(function (tst) {
                            check('as_test: sends exactly one request and reports the HTTP status', tst.ok === true && tst.httpCode === 201 && captured.length === 1, tst);

                            var timers = [];
                            var realLT = oB.longTimeout;
                            oB.longTimeout = function (fn, ms) { timers.push(ms); };
                            oB.pluginSettings.assetManagement.enabled = false; oB.pluginSettings.assetManagement.intervalHours = 24;
                            oB.scheduleAssetSync();
                            check('scheduler: with the connector DISABLED no sync timer is registered (no automatic push)', timers.length === 0, timers);
                            oB.pluginSettings.assetManagement.enabled = true; oB.pluginSettings.assetManagement.intervalHours = 0;
                            oB.scheduleAssetSync();
                            check('scheduler: interval 0 means on-demand only - still no timer', timers.length === 0, timers);
                            oB.pluginSettings.assetManagement.intervalHours = 24;
                            oB.scheduleAssetSync();
                            check('scheduler: only enabled + interval > 0 registers the cycle (24 h)', timers.length === 1 && timers[0] === 24 * 3600 * 1000, timers);
                            oB.longTimeout = realLT;

                            oB.handleAdminPostReq({ headers: XHDR, body: { action: 'get_log', type: 'asset' } }, mockRes(function (lg) {
                                check('get_log asset: the sync log is reachable and named', Array.isArray(lg.lines) && lg.file === 'plugins/inventoryscanner/asset-sync.log', lg.file);
                                oB.handleAdminPostReq({ headers: XHDR, body: { action: 'as_status' } }, mockRes(function (st) {
                                    check('as_status: per-device last push + a config summary with masked secrets',
                                        st.devices.length === 2 && st.config.hasToken === true && JSON.stringify(st).indexOf(SECRETTOKEN) < 0, st.config);
                                    next();
                                }), user);
                            }), user);
                        }), user);
                        });
                    }), user);
                    });
                }), user);
            }), user);
            }), user);
        }), user);
    }), user);
});

// ---- v5.0.1 review fixes: per-finding Jira issues, header validation, node filter, pruning, watchdog ----
steps.push(function (next) {
    var dpC = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-as3-'));
    var cNodes = [
        { _id: 'node//c1', meshid: 'mesh//grp1', rname: 'ch1', name: 'Named', osdesc: 'Microsoft Windows 11 Pro' },
        { _id: 'node//c2', meshid: 'mesh//grp1', rname: 'ch2', osdesc: 'Ubuntu 24.04 LTS' } // deliberately NO name property
    ];
    var cSys = { 'sinode//c1': { _id: 'sinode//c1', doc: { hardware: { identifiers: { serial: 'SN-C1' } } } } };
    var dbC = { GetAllType: function (t, cb) { cb(null, t === 'node' ? cNodes.slice() : meshes.slice()); }, Get: function (id, cb) { if (cSys[id]) { cb(null, [cSys[id]]); return; } cb(null, cNodes.filter(function (n) { return n._id === id; })); } };
    var sentC = [];
    var oC = factory({ parent: { db: dbC, datapath: dpC, debug: function () { }, config: { settings: {} }, webserver: { meshes: {}, wsagents: {} }, DispatchEvent: function () { } } });
    oC.softwareInventory = { c1: { apps: [{ name: 'Firefox', version: '1.0' }] }, c2: { apps: [{ name: 'Firefox', version: '2.0' }] } };
    oC.scanDeviceSoftware = function (list, cb) {
        cb([{ isCve: true, cve: 'CVE-2024-0001', severity: 'CRITICAL', cvss: 9.8, software: 'Firefox', version: '1.0' },
            { isCve: true, cve: 'CVE-2024-0002', severity: 'HIGH', cvss: 7.5, software: 'Firefox', version: '1.0' }]);
    };
    var capturedC = [];
    oC.assetHttp = function (opts, cb) { capturedC.push(opts); cb(null, { statusCode: 201, text: '{"id":"ID-' + capturedC.length + '","key":"KEY-' + capturedC.length + '"}' }); };

    // 1) the jiraVulnIssues option really does something now (it was stored but ignored before)
    var recC = {
        device: { id: 'node//c1', host: 'ch1', given: 'Named', group: 'HQ', os: 'W11', online: true },
        hardware: { serial: 'SN-C1' }, software: [{ name: 'Firefox', version: '1.0', publisher: '', location: '', date: '' }],
        vulnerabilities: [{ id: 'CVE-2024-0001', status: 'CVE', severity: 'CRITICAL', cvss: 9.8, software: 'Firefox', version: '1.0', description: '' }, { id: 'CVE-2024-0002', status: 'CVE', severity: 'HIGH', cvss: 7.5, software: 'Firefox', version: '1.0', description: '' }],
        coverage: [],
        counts: { software: 1, vulnerabilities: 2, coverage: 0, findings: 2, uniqueFindingIds: 2, maxSeverity: 'CRITICAL' }
    };
    var jcfgOff = { targetType: 'jira', endpointUrl: 'https://acme.atlassian.net', authMode: 'none', jiraProject: 'IT', jiraIssueType: 'Task', jiraLabel: 'inv', jiraSummary: '[Inventory] {{device.host}}', jiraVulnIssues: false };
    var off = oC.asBuildRequests(recC, jcfgOff, null, {});
    check('v5.0.1 jira: with "one issue per vulnerability" OFF there is exactly the device issue', !!off.requests && off.requests.length === 1 && off.requests[0].idSlot === 'device', off.requests && off.requests.length);
    var jcfgOn = Object.assign({}, jcfgOff, { jiraVulnIssues: true });
    var on = oC.asBuildRequests(recC, jcfgOn, null, {});
    check('v5.0.1 jira: turning the option ON adds one CREATE issue per finding, each with its own id slot',
        !!on.requests && on.requests.length === 3 && on.requests[0].idSlot === 'device' &&
        on.requests[1].idSlot === 'cve:CVE-2024-0001' && on.requests[2].idSlot === 'cve:CVE-2024-0002' &&
        on.requests[1].method === 'POST' && on.requests[1].body.fields.summary.indexOf('CVE-2024-0001') >= 0 &&
        on.requests[1].body.fields.labels.indexOf('vulnerability') >= 0, on.requests && on.requests.map(function (r) { return r.idSlot; }));
    var upd = oC.asBuildRequests(recC, jcfgOn, 'KEY-9', { 'CVE-2024-0001': 'KEY-1' });
    check('v5.0.1 jira: a stored per-CVE id makes the next push UPDATE that issue instead of duplicating it',
        !!upd.requests && upd.requests.length === 3 && upd.requests[0].method === 'PUT' && upd.requests[0].url.indexOf('/issue/KEY-9') >= 0 &&
        upd.requests[1].method === 'PUT' && upd.requests[1].url.indexOf('/issue/KEY-1') >= 0 && upd.requests[2].method === 'POST',
        upd.requests && upd.requests.map(function (r) { return r.method + ' ' + r.idSlot; }));
    var many = { vulnerabilities: [] };
    for (var mi = 0; mi < 150; mi++) { many.vulnerabilities.push({ id: 'CVE-2024-1' + mi, status: 'CVE', severity: 'LOW', software: 'x', version: '1', description: '' }); }
    many.device = recC.device; many.hardware = {}; many.software = []; many.coverage = [];
    many.counts = { software: 0, vulnerabilities: 150, coverage: 0, findings: 150, uniqueFindingIds: 150, maxSeverity: 'LOW' };
    var capped = oC.asBuildRequests(many, jcfgOn, null, {});
    check('v5.0.1 jira: the per-finding issues are capped (100) so one device cannot create an unbounded issue storm',
        !!capped.requests && capped.requests.length === 1 + oC.AS_MAX_VULN_ISSUES, capped.requests && capped.requests.length);

    // 2) header safety at save time
    oC.handleAdminPostReq({ headers: XHDR, body: { action: 'as_save_config', enabled: 'true', targetType: 'generic', endpointUrl: 'https://am.example.com/i', authMode: 'header', headerName: 'Bad Header Name', headerValue: 'x', bodyTemplate: '{"a":1}' } }, mockRes(function (hn) {
        check('v5.0.1 save: an invalid custom header NAME is rejected (RFC 7230 token)', !!hn.error && /header name/i.test(hn.error), hn.error);
        oC.handleAdminPostReq({ headers: XHDR, body: { action: 'as_save_config', enabled: 'true', targetType: 'generic', endpointUrl: 'https://am.example.com/i', authMode: 'header', headerName: 'X-Api-Key', headerValue: 'a\r\nX-Injected: 1', bodyTemplate: '{"a":1}' } }, mockRes(function (hv) {
            check('v5.0.1 save: a header VALUE with CRLF/control characters is rejected (header injection)', !!hv.error && /control characters/i.test(hv.error), hv.error);
            oC.handleAdminPostReq({ headers: XHDR, body: { action: 'as_save_config', enabled: 'true', targetType: 'generic', endpointUrl: 'https://am.example.com/i', headersJson: '{"Bad Name":"x"}', bodyTemplate: '{"a":1}' } }, mockRes(function (hj) {
                check('v5.0.1 save: an invalid name inside the extra-headers JSON is rejected too', !!hj.error && /extra header name/i.test(hj.error), hj.error);

                // 3) a valid config, then the push: node filter + pruning + status sanitising
                oC.handleAdminPostReq({ headers: XHDR, body: { action: 'as_save_config', enabled: 'true', targetType: 'generic', endpointUrl: 'https://am.example.com/i', authMode: 'bearer', token: 'TOK-C', bodyTemplate: '{"host":"{{device.host}}","apps":"{{software}}"}', externalIdPath: 'id' } }, mockRes(function () {
                    oC.asResults['node//ghost'] = { time: 'x', status: 'ok', externalId: 'old' }; // a deleted device
                    oC.pluginSettings.assetManagement.jiraVulnIssues = false;
                    capturedC.length = 0;
                    oC.handleAdminPostReq({ headers: XHDR, body: { action: 'as_push' } }, mockRes(function (p) {
                        check('v5.0.1 push: answers immediately with the number of devices it will push', p.started === true && p.devices === 2 && p.background === true, p);
                        waitPush(oC, function () {
                        check('v5.0.1 push: a device WITHOUT a name property is no longer silently skipped',
                            capturedC.length === 2 && sentC.length === 0, [capturedC.length, sentC.length]);
                        check('v5.0.1 push: results of deleted devices are pruned so asset-sync.json cannot grow forever',
                            oC.asResults['node//ghost'] === undefined && oC.asResults['node//c1'] != null, Object.keys(oC.asResults));
                        oC.asResults['node//c1'].vulnIssues = { 'CVE-2024-0001': 'KEY-1', 'CVE-2024-0002': 'KEY-2' };
                        oC.handleAdminPostReq({ headers: XHDR, body: { action: 'as_status' } }, mockRes(function (st) {
                            var d1 = st.devices.filter(function (x) { return x.id === 'node//c1'; })[0];
                            check('v5.0.1 status: the internal per-CVE id map is not shipped to the browser - only a count',
                                !!d1 && d1.last && d1.last.vulnIssues === 2 && JSON.stringify(st).indexOf('KEY-1') < 0, d1 && d1.last);
                            next();
                        }), user);
                        });
                    }), user);
                }), user);
            }), user);
        }), user);
    }), user);
});

// ---- v5.0.1: a stuck push must not block the connector forever (watchdog) ----
steps.push(function (next) {
    var dpD = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-as4-'));
    var dNodes = [{ _id: 'node//d1', meshid: 'mesh//grp1', rname: 'dh1', name: 'Stuck', osdesc: 'Microsoft Windows 11' }];
    var dbD = { GetAllType: function (t, cb) { cb(null, t === 'node' ? dNodes.slice() : meshes.slice()); }, Get: function (id, cb) { cb(null, dNodes.filter(function (n) { return n._id === id; })); } };
    var oD = factory({ parent: { db: dbD, datapath: dpD, debug: function () { }, config: { settings: {} }, webserver: { meshes: {}, wsagents: {} }, DispatchEvent: function () { } } });
    oD.softwareInventory = { d1: { apps: [{ name: 'Firefox', version: '1.0' }] } };
    oD.scanDeviceSoftware = function (list, cb) { cb([]); };
    oD.pluginSettings = { assetManagement: { enabled: true, targetType: 'generic', endpointUrl: 'https://am.example.com/i', authMode: 'none', bodyTemplate: '{"a":1}', intervalHours: 0 } };
    oD.assetHttp = function () { /* never answers - simulates a hung target */ };
    oD.AS_PUSH_MAX_MS = 40;
    oD.handleAdminPostReq({ headers: XHDR, body: { action: 'as_push' } }, mockRes(function (r) {
        check('v5.0.1 watchdog: the push answers immediately (background) even though the target never responds',
            r.started === true && r.background === true && r.devices === 1, r);
        check('v5.0.1 watchdog: the connector is locked while the hung push is in flight', oD.asPushing === true, oD.asPushing);
        setTimeout(function () {
            check('v5.0.1 watchdog: a hung push is aborted and the connector UNLOCKED, so the next push is not refused as busy',
                oD.asPushing === false, oD.asPushing);
            var logD = '';
            try { logD = fs.readFileSync(oD.asLogPath, 'utf8'); } catch (e) { }
            check('v5.0.1 watchdog: the abort is recorded in the log', logD.indexOf('ABORTED') >= 0, logD.substring(0, 160));
            next();
        }, 200);
    }), user);
});

// ---- v5.0.1: the matcher must receive the RAW inventory rows (Linux distro packages need location) ----
steps.push(function (next) {
    var dpE = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-as5-'));
    var eNodes = [{ _id: 'node//e1', meshid: 'mesh//grp2', rname: 'eh1', name: 'LinBox', osdesc: 'Ubuntu 24.04 LTS' }];
    var dbE = { GetAllType: function (t, cb) { cb(null, t === 'node' ? eNodes.slice() : meshes.slice()); }, Get: function (id, cb) { cb(null, eNodes.filter(function (n) { return n._id === id; })); } };
    var oE = factory({ parent: { db: dbE, datapath: dpE, debug: function () { }, config: { settings: {} }, webserver: { meshes: {}, wsagents: {} }, DispatchEvent: function () { } } });
    oE.softwareInventory = { e1: { apps: [{ name: 'libc6', version: '2.39', location: 'dpkg' }, { name: 'nginx', version: '1.24', installLocation: 'dpkg', publisher: 'Debian' }] } };
    var seen = null;
    oE.scanNodeSoftware = function (node, list, cb) { seen = list; cb([]); };
    oE.asCollectDeviceRecord(eNodes[0], function (err, rec) {
        check('v5.0.1 record: the matcher gets the RAW stored rows, so location/installLocation survive (distro-managed detection)',
            !err && Array.isArray(seen) && seen.length === 2 && seen[0].location === 'dpkg' && seen[1].installLocation === 'dpkg', seen);
        check('v5.0.1 record: the pushed software list keeps name/version/publisher and now also the install location',
            !!rec && rec.software.length === 2 && rec.software[0].name === 'libc6' && rec.software[0].version === '2.39' &&
            rec.software[0].location === 'dpkg' && rec.software[1].location === 'dpkg' && rec.software[1].publisher === 'Debian', rec && rec.software);
        check('v5.0.1 record: the distro-managed rows are NOT reported as vulnerabilities (no false positives pushed)',
            !!rec && rec.counts.vulnerabilities === 0 && rec.vulnerabilities.length === 0, rec && rec.counts);
        // a corrupt results file must not poison the lookup map
        fs.mkdirSync(path.dirname(oE.asResultsPath), { recursive: true });
        fs.writeFileSync(oE.asResultsPath, '[1,2,3]');
        oE.loadAssetResults();
        check('v5.0.1 results: an array-shaped/corrupt asset-sync.json is ignored instead of becoming the map',
            oE.asResults && !Array.isArray(oE.asResults) && Object.keys(oE.asResults).length === 0, oE.asResults);
        next();
    });
});

// ---- v5.1.0: ONE canonical collector - browser list, CSV, report, fleet index and push must agree 1:1 ----
steps.push(function (next) {
    var dpF = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-canon-'));
    var fNodes = [{ _id: 'node//k1', meshid: 'mesh//grp1', rname: 'kh1', name: 'Canon', osdesc: 'Microsoft Windows 11 Pro', ip: '10.1.2.3' }];
    var fMeshes = [{ _id: 'mesh//grp1', name: 'HQ' }];
    var fSys = {
        'sinode//k1': {
            _id: 'sinode//k1',
            doc: {
                hardware: {
                    identifiers: {
                        cpu_name: 'Intel Core i7-12700', gpu_name: ['Intel UHD 770'], serial: 'CHASSIS-SN-1',
                        bios_vendor: 'Dell Inc.', bios_version: '1.4.2', bios_serial: 'BIOS-SN-1', bios_mode: 'UEFI',
                        board_vendor: 'Dell Inc.', board_name: '0AB1CD', board_serial: 'BOARD-SN-1', board_version: 'A00',
                        product_name: 'OptiPlex 7090', chassis_manufacturer: 'Dell Inc.', chassis_serial: 'CHASSIS-SN-1', chassis_assettag: 'ASSET-42',
                        storage_devices: [{ Model: 'NVMe 512GB', Size: 512110190592 }]
                    },
                    windows: {
                        osinfo: { BuildRevision: '2600', BuildNumber: '22621' },
                        memory: [{ BankLabel: 'BANK 0', Capacity: 17179869184, Speed: 3200, PartNumber: 'CMK32', Manufacturer: 'Corsair' }]
                    },
                    tpm: { SpecVersion: '2.0', IsActivated: true, IsEnabled: true, IsOwned: true, ManufacturerId: 'INTC' },
                    network: { dns: ['1.1.1.1', '8.8.8.8'] }
                }
            }
        }
    };
    var dbF = {
        GetAllType: function (t, cb) { cb(null, t === 'node' ? fNodes.slice() : (t === 'mesh' ? fMeshes.slice() : [])); },
        Get: function (id, cb) { if (fSys[id]) { cb(null, [fSys[id]]); return; } cb(null, fNodes.filter(function (n) { return n._id === id; })); }
    };
    var oF = factory({ parent: { db: dbF, datapath: dpF, debug: function () { }, config: { settings: {} }, webserver: { meshes: { 'mesh//grp1': { name: 'HQ' } }, wsagents: { 'node//k1': {} } }, DispatchEvent: function () { } } });
    oF.softwareInventory = {
        k1: {
            time: 'x', apps: [
                { name: 'Firefox', version: '120.0', publisher: 'Mozilla', location: 'C:\\Program Files' },
                { name: 'libc6', version: '2.39', location: 'dpkg', publisher: 'Ubuntu Developers <ubuntu-devel@lists.ubuntu.com>' },
                { name: 'Mystery Tool', version: '9.9', publisher: 'Some OEM' }
            ]
        }
    };
    oF.windowsUpdates = { k1: { count: 3, updates: [] } };
    // deterministic matcher: one real CVE, one distro-managed row, one blind spot
    oF.scanDeviceSoftware = function (list, cb) {
        var out = [];
        for (var i = 0; i < (list || []).length; i++) {
            var nm = String((list[i] && list[i].name) || '');
            if (/firefox/i.test(nm)) out.push({ status: 'CVE', isCve: true, cve: 'CVE-2024-0001', severity: 'CRITICAL', cvss: 9.8, description: 'crit', software: nm, version: String(list[i].version || '') });
            else if (/libc6/i.test(nm)) out.push({ status: 'distro-managed', distro: 'supported', isCve: false, cve: '', severity: '', cvss: '', description: 'patched by the distribution', software: nm, version: String(list[i].version || '') });
            else out.push({ status: 'not assessable', isCve: false, cve: '', severity: '', cvss: '', description: 'no proven CPE', software: nm, version: String(list[i].version || '') });
        }
        cb(out);
    };
    // an OS-level CVE, so the OS findings are part of the comparison (this is what the push used to drop)
    oF.scanDeviceOs = function () { return [{ cve: 'CVE-2024-0009', isCve: true, severity: 'HIGH', cvss: 7.8, description: 'os bug', software: 'Operating System', version: 'Windows 11 Pro' }]; };
    oF.osSupportState = function () { return { state: 'eol', label: 'Windows 11 Pro', reason: 'test fixture' }; };
    oF.saveAssessments = function (cb) { if (cb) cb(null); };

    // the expected finding ids, straight from the canonical collector
    oF.collectNodeInventory(fNodes[0], function (cerr, inv) {
        check('canonical collector: no error and the raw software rows reach the matcher (location kept)', !cerr && !!inv && inv.software.length === 3 && inv.software[1].location === 'dpkg', cerr || (inv && inv.software));
        var expectedIds = [];
        for (var i = 0; i < inv.findings.length; i++) { if (inv.findings[i].cve && expectedIds.indexOf(inv.findings[i].cve) < 0) expectedIds.push(inv.findings[i].cve); }
        expectedIds.sort();
        check('canonical collector: the findings contain software CVE + OS CVE + WINDOWS-UPDATES + OS-EOL',
            expectedIds.join(',') === 'CVE-2024-0001,CVE-2024-0009,OS-EOL,WINDOWS-UPDATES', expectedIds);
        check('canonical collector: the coverage rows (distro-managed, not assessable) are kept, not silently dropped',
            inv.counts.findings === 6 && inv.counts.uniqueFindingIds === 4 && inv.counts.cves === 2 && inv.counts.software === 3, inv.counts);

        // 1) the vulnerability CSV must list exactly the same finding ids
        oF.buildCsvForNodes([fNodes[0]], 'vulns', function (e1, csvV) {
            var csvIds = [];
            String(csvV).split('\r\n').slice(1).forEach(function (line) {
                if (!line) return;
                var cells = line.split(',');
                var id = String(cells[3] || '').replace(/"/g, '');
                if (id && csvIds.indexOf(id) < 0) csvIds.push(id);
            });
            csvIds.sort();
            check('1:1 - the vulnerability CSV lists exactly the canonical finding ids', csvIds.join(',') === expectedIds.join(','), [csvIds, expectedIds]);

            // 2) the asset push payload must carry exactly the same finding ids (this FAILED before v5.1.0)
            oF.pluginSettings = { assetManagement: { enabled: true, targetType: 'generic', endpointUrl: 'https://am.example.com/i', authMode: 'none', bodyTemplate: '{"host":"{{device.host}}","vulns":"{{vulnerabilities}}","cov":"{{coverage}}","apps":"{{software}}","serial":"{{hardware.serial}}","cpu":"{{hardware.cpu}}"}', externalIdPath: 'id' } };
            // a collected license key must NEVER ride along in the push (v5.2.0 collects on a schedule, so this matters)
            oF.licenseInventory = { k1: { time: 'x', items: [{ name: 'Firefox', license: 'SECRET-LIC-KEY-9', source: 'registry' }], ms: [{ name: 'Windows', key: 'MS-PARTIAL-7' }] } };
            var cap = [];
            oF.assetHttp = function (opts, cb) { cap.push(opts); cb(null, { statusCode: 200, text: '{"id":"K1"}' }); };
            oF.handleAdminPostReq({ headers: XHDR, body: { action: 'as_push' } }, mockRes(function () {
                waitPush(oF, function () {
                    var body = cap.length ? cap[0].body : null;
                    var pushIds = (body && body.vulns ? body.vulns.map(function (v) { return v.id; }) : []).filter(function (x) { return !!x; }).sort();
                    check('1:1 - the asset push carries EXACTLY the same findings as the CSV (OS CVE, WINDOWS-UPDATES and OS-EOL included)',
                        !!body && pushIds.join(',') === expectedIds.join(','), [pushIds, expectedIds]);
                    check('1:1 - the push also carries the coverage rows, so no CSV information is lost',
                        !!body && Array.isArray(body.cov) && body.cov.length === 2 &&
                        body.cov.some(function (c) { return c.status === 'distro-managed'; }) &&
                        body.cov.some(function (c) { return c.status === 'not assessable'; }), body && body.cov);
                    check('1:1 - the pushed software list equals the canonical projection (name/version/publisher/location)',
                        !!body && body.apps.length === 3 && body.apps[0].name === 'Firefox' && body.apps[1].location === 'dpkg' && body.apps[1].publisher.indexOf('Ubuntu') >= 0, body && body.apps);
                    check('1:1 - the pushed hardware equals the hardware-CSV facts (serial + cpu from the same derivation)',
                        !!body && body.serial === 'CHASSIS-SN-1' && body.cpu === 'Intel Core i7-12700', body && [body.serial, body.cpu]);
                    check('v5.2.0 security: collected license keys NEVER ride along in the asset push (they stay on this server)',
                        !!body && JSON.stringify(body).indexOf('SECRET-LIC-KEY-9') < 0 && JSON.stringify(body).indexOf('MS-PARTIAL-7') < 0,
                        Object.keys(body || {}));

                    // 3) the software CSV must list the same programs as the push
                    oF.buildCsvForNodes([fNodes[0]], 'software', function (e2, csvS) {
                        var csvNames = String(csvS).split('\r\n').slice(1).map(function (l) { return l.split(',')[2]; }).filter(function (x) { return !!x; }).sort();
                        var pushNames = body.apps.map(function (a) { return a.name; }).sort();
                        check('1:1 - the software CSV and the push list the same programs', csvNames.join(',') === pushNames.join(','), [csvNames, pushNames]);

                        // 4) the hardware CSV must contain the same serial/cpu as the push
                        oF.buildCsvForNodes([fNodes[0]], 'hardware', function (e3, csvH) {
                            check('1:1 - the hardware CSV contains the same serial and CPU the push sends',
                                String(csvH).indexOf('CHASSIS-SN-1') >= 0 && String(csvH).indexOf('Intel Core i7-12700') >= 0 && String(csvH).indexOf('ASSET-42') >= 0, String(csvH).substring(0, 160));

                            // 5) the fleet index (browser device list) must report the same finding count
                            oF.buildFleetIndex(function (e4, data) {
                                var bd = data.byDevice['node//k1'];
                                check('1:1 - the browser device list shows the same finding count as the CSV/report (4 distinct ids)',
                                    !!bd && bd.cve === 4 && bd.maxSeverity === 'CRITICAL', bd);
                                var swNames = data.software.map(function (s) { return s.name; }).sort();
                                check('1:1 - the browser software list shows the same programs as the CSV/push',
                                    swNames.join(',') === pushNames.join(','), [swNames, pushNames]);

                                // 6) the printable report must count the same distinct findings for this device
                                oF.buildOverallReport(function (e5, report) {
                                    var dev = report.devices.filter(function (d) { return d.hostName === 'kh1'; })[0];
                                    check('1:1 - the printable report counts the same distinct findings for the device',
                                        !!dev && dev.cveCount === 4, dev && dev.cveCount);
                                    check('1:1 - the report sees the same number of installed programs as the CSV/push',
                                        report.totalPrograms === 3 && !!dev && dev.programs === 3, [report.totalPrograms, dev && dev.programs]);
                                    next();
                                });
                            }, true);
                        });
                    });
                });
            }), user);
        });
    });
});

// ---- v5.1.0: the license path uses the SAME software source as the CSV (sysinfo doc included) ----
steps.push(function (next) {
    var dpL2 = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-lic2-'));
    var lNodes = [{ _id: 'node//L1', meshid: 'mesh//grp1', rname: 'Lh1', name: 'LicSysinfo', osdesc: 'Microsoft Windows 11 Pro' }];
    // the software exists ONLY in the sysinfo document - the plugin's own store is empty for this device
    var lSys = { 'sinode//L1': { _id: 'sinode//L1', doc: { apps: [{ name: 'Adobe Acrobat Pro', version: '11' }] } } };
    var dbL2 = { GetAllType: function (t, cb) { cb(null, t === 'node' ? lNodes.slice() : meshes.slice()); }, Get: function (id, cb) { if (lSys[id]) { cb(null, [lSys[id]]); return; } cb(null, lNodes.filter(function (n) { return n._id === id; })); } };
    var sentL2 = [];
    var agentsL2 = { 'node//L1': { send: function (m) { sentL2.push(JSON.parse(m)); } } };
    var oL2 = factory({ parent: { db: dbL2, datapath: dpL2, debug: function () { }, config: { settings: {} }, webserver: { meshes: {}, wsagents: agentsL2 }, DispatchEvent: function () { } } });
    oL2.softwareInventory = {};
    oL2.customLicenseEntries = [{ match: 'acrobat', label: 'Adobe Acrobat', rules: [{ type: 'registry', path: 'HKLM:\\SOFTWARE\\Adobe\\Acrobat', value: 'Serial' }] }];
    oL2.pluginSettings = { inventoryScanner: { licenseCollectionEnabled: true, licenseMsKeys: false } };
    var gunzL2 = function (cmd) { var m = String(cmd).match(/FromBase64String\('([A-Za-z0-9+\/=]+)'\)/); return m ? require('zlib').gunzipSync(Buffer.from(m[1], 'base64')).toString('utf8') : ''; };

    // the canonical row source must see the sysinfo-only program
    oL2.fetchNodeSoftware(lNodes[0], function (e, got) {
        check('v5.1.0 fetchNodeSoftware: the sysinfo document is a software source like the plugin store (one canonical accessor)',
            !e && got.rows.length === 1 && got.rows[0].name === 'Adobe Acrobat Pro', got && got.rows);
        check('v5.1.0 licenseAppRules: takes the canonical rows and matches the rule for a sysinfo-only program',
            oL2.licenseAppRules(got.rows).length === 1 && oL2.licenseAppRules(got.rows)[0].label === 'Adobe Acrobat', oL2.licenseAppRules(got.rows));
        oL2.handleAdminPostReq({ headers: XHDR, body: { action: 'lic_collect', nodeId: 'node//L1' } }, mockRes(function (d) {
            var script = sentL2.length ? gunzL2(sentL2[0].cmds) : '';
            // the rules travel base64-encoded inside the script (never as a literal path), so decode them
            var blobs = []; var re = /FromBase64String\('([A-Za-z0-9+\/=]+)'\)/g; var mm;
            while ((mm = re.exec(script)) !== null) { try { blobs.push(Buffer.from(mm[1], 'base64').toString('utf8')); } catch (e) { } }
            var hasRule = blobs.some(function (b) { return b.indexOf('Adobe') >= 0 && b.indexOf('Serial') >= 0; });
            check('v5.1.0 lic_collect: a program listed only in sysinfo still gets its license rule dispatched (was invisible before)',
                d.started === true && sentL2.length === 1 && hasRule, [d, script.length, blobs.length]);
            // and the CSV lists exactly the same program for the same device
            oL2.buildCsvForNodes([lNodes[0]], 'software', function (ce, csv) {
                check('v5.1.0 1:1 - the software CSV lists the same program the license run was built from',
                    String(csv).indexOf('Adobe Acrobat Pro') >= 0, String(csv).split('\r\n').slice(0, 2));
                next();
            });
        }), user);
    });
});

// ---- v5.2.0: the NVD feed timer is due-aware (a stale feed is fetched, not postponed forever) ----
steps.push(function (next) {
    var dpN = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-nvd-'));
    var dbN = { GetAllType: function (t, cb) { cb(null, t === 'node' ? [] : meshes.slice()); }, Get: function (id, cb) { cb(null, []); } };
    var oN = factory({ parent: { db: dbN, datapath: dpN, debug: function () { }, config: { settings: {} }, webserver: { meshes: {}, wsagents: {} }, DispatchEvent: function () { } } });
    oN.pluginSettings = { vulnerabilityScanner: { updateHours: 168 } };
    var timers = [];
    oN.longTimeout = function (fn, ms) { timers.push({ fn: fn, ms: ms }); };
    var hour = 3600 * 1000;

    // the reported symptom: lastUpdate 285h old, interval 168h -> the run must be due NOW, not in 168h
    oN.lastUpdate = new Date(Date.now() - 285 * hour).toISOString();
    timers.length = 0;
    oN.scheduleUpdate();
    check('v5.2.0 NVD timer: a feed that is 285h old (interval 168h) is fetched within a minute, NOT postponed another 168h',
        timers.length === 1 && timers[0].ms === oN.NVD_MIN_DELAY_MS, timers.map(function (t) { return t.ms; }));
    check('v5.2.0 NVD timer: before the fix this was the bug - the delay is no longer the full interval',
        timers[0].ms !== 168 * hour, timers[0].ms);

    // a fresh feed waits (almost) the full interval
    oN.lastUpdate = new Date(Date.now() - 1 * hour).toISOString();
    timers.length = 0;
    oN.scheduleUpdate();
    check('v5.2.0 NVD timer: a fresh feed waits the remaining interval (167h), not the floor',
        timers.length === 1 && timers[0].ms === (168 * hour) - (1 * hour), timers.map(function (t) { return t.ms; }));

    // no lastUpdate at all -> due immediately (floored so the server can settle)
    oN.lastUpdate = null;
    timers.length = 0;
    oN.scheduleUpdate();
    check('v5.2.0 NVD timer: without any lastUpdate the run is due immediately (floored to the settle delay)',
        timers.length === 1 && timers[0].ms === oN.NVD_MIN_DELAY_MS, timers.map(function (t) { return t.ms; }));

    // a FAILED run must not turn into a retry storm against the rate-limited NVD
    var nvdCalls = 0;
    oN.runNvdUpdate = function (force, cb) { nvdCalls++; cb(new Error('download failed')); };
    var licRefresh = 0;
    oN.maybeFetchCpeTable = function () { }; oN.maybeFetchOsLifecycle = function () { }; oN.maybeFetchLicenseTable = function () { licRefresh++; };
    oN.lastUpdate = new Date(Date.now() - 285 * hour).toISOString();
    timers.length = 0;
    oN.scheduleUpdate();
    timers[0].fn();   // fires the run, which fails
    check('v5.2.0 NVD timer: a failed run retries after the bounded retry delay (6h), never in a tight loop',
        nvdCalls === 1 && timers.length === 2 && timers[1].ms === oN.NVD_RETRY_MS, timers.map(function (t) { return t.ms; }));
    check('audit4: the NVD cycle also refreshes the license table (documented, but it only ran at server start before)', licRefresh === 1, licRefresh);

    // a successful run refreshes lastUpdate, so the next delay is the normal cycle
    oN.runNvdUpdate = function (force, cb) { oN.lastUpdate = new Date().toISOString(); cb(null); };
    timers.length = 0;
    oN.scheduleUpdate();
    timers[0].fn();
    check('v5.2.0 NVD timer: after a successful run the next cycle is the full interval again',
        timers.length === 2 && timers[1].ms > (167 * hour), timers.map(function (t) { return t.ms; }));

    // bug 2: rescheduleAll bumps timerGen (killing the armed NVD timer) - it MUST re-arm it
    var schedCalls = 0;
    var realSched = oN.scheduleUpdate;
    oN.scheduleUpdate = function () { schedCalls++; };
    oN.rescheduleAll();
    check('v5.2.0 NVD timer: a settings save (rescheduleAll) RE-ARMS the feed timer instead of silently killing it',
        schedCalls === 1, schedCalls);
    oN.scheduleUpdate = realSched;

    // the self-heal must report staleness but NOT arm a second timer (server_startup arms one)
    var logged = [];
    oN.nvdLog = function (m) { logged.push(m); };
    oN.notifyAdminsNvdStale = function () { };
    schedCalls = 0;
    oN.scheduleUpdate = function () { schedCalls++; };
    oN.lastUpdate = new Date(Date.now() - 309 * hour).toISOString();
    var stale = oN.checkAndRepairNvdTimer();
    check('v5.2.0 self-heal: reports the stale feed and notifies, but arms NO second timer (server_startup does that once)',
        stale === true && schedCalls === 0 && logged.length === 1 && /309h old/.test(logged[0]) && /due/.test(logged[0]), [stale, schedCalls, logged]);
    oN.scheduleUpdate = realSched;
    oN.lastUpdate = new Date().toISOString();
    check('v5.2.0 self-heal: a fresh feed is reported as not stale', oN.checkAndRepairNvdTimer() === false);
    next();
});

// ---- v5.2.0: the optional license collection schedule ----
steps.push(function (next) {
    var dpLS = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-licsch-'));
    var lsNodes = [
        { _id: 'node//ls1', meshid: 'mesh//grp1', rname: 'ls1', name: 'WinOnline', osdesc: 'Microsoft Windows 11 Pro' },
        { _id: 'node//ls2', meshid: 'mesh//grp1', rname: 'ls2', name: 'WinOffline', osdesc: 'Microsoft Windows 10' },
        { _id: 'node//ls3', meshid: 'mesh//grp2', rname: 'ls3', name: 'LinOnline', osdesc: 'Ubuntu 24.04 LTS' },
        { _id: 'node//ls4', meshid: 'mesh//grp1', rname: 'ls4', name: 'WinBusy', osdesc: 'Microsoft Windows 11' }
    ];
    var dbLS = { GetAllType: function (t, cb) { cb(null, t === 'node' ? lsNodes.slice() : meshes.slice()); }, Get: function (id, cb) { cb(null, lsNodes.filter(function (n) { return n._id === id; })); } };
    var sentLS = [];
    var sentLS4 = [];
    var agentsLS = { 'node//ls1': { send: function (m) { sentLS.push(JSON.parse(m)); } }, 'node//ls3': { send: function () { } }, 'node//ls4': { send: function (m) { sentLS4.push(JSON.parse(m)); } } };
    var oLS = factory({ parent: { db: dbLS, datapath: dpLS, debug: function () { }, config: { settings: {} }, webserver: { meshes: {}, wsagents: agentsLS }, DispatchEvent: function () { } } });
    oLS.softwareInventory = { ls1: { apps: [{ name: 'Adobe Acrobat Pro', version: '11' }] }, ls4: { apps: [{ name: 'Adobe Acrobat Pro', version: '11' }] } };
    oLS.customLicenseEntries = [{ match: 'acrobat', label: 'Adobe Acrobat', rules: [{ type: 'registry', path: 'HKLM:\\SOFTWARE\\Adobe', value: 'Serial' }] }];
    var timersLS = [];
    oLS.longTimeout = function (fn, ms) { timersLS.push({ fn: fn, ms: ms }); };

    // scheduler arming rules
    oLS.pluginSettings = { inventoryScanner: { licenseCollectionEnabled: false, licenseCollectIntervalHours: 24 } };
    timersLS.length = 0; oLS.scheduleLicenseCollection();
    check('v5.2.0 license schedule: nothing is armed while the master switch is OFF (even with an interval set)', timersLS.length === 0, timersLS.length);
    oLS.pluginSettings = { inventoryScanner: { licenseCollectionEnabled: true, licenseCollectIntervalHours: 0 } };
    timersLS.length = 0; oLS.scheduleLicenseCollection();
    check('v5.2.0 license schedule: interval 0 means on demand only - nothing is armed', timersLS.length === 0, timersLS.length);
    oLS.pluginSettings = { inventoryScanner: { licenseCollectionEnabled: true, licenseCollectIntervalHours: 24 } };
    timersLS.length = 0; oLS.scheduleLicenseCollection();
    check('v5.2.0 license schedule: enabled + interval 24h arms exactly one 24h cycle',
        timersLS.length === 1 && timersLS[0].ms === 24 * 3600 * 1000, timersLS.map(function (t) { return t.ms; }));

    // the sweep itself: online Windows only, and a device busy with another engine is skipped
    oLS.wgPending['node//ls4'] = { nodeid: 'node//ls4' };
    sentLS.length = 0; sentLS4.length = 0;
    oLS.licSweepOnce('the test', function (err, r) {
        check('v5.2.0 license sweep: sends only to the ONLINE Windows device - not offline, not Linux, and NOT to a device busy with another engine (one runcommands session per agent)',
            !err && r.candidates === 2 && r.started === 1 && sentLS.length === 1 && sentLS4.length === 0 &&
            String(sentLS[0].sessionid).indexOf('invscanner-lic-') === 0 && sentLS[0].type === 1, [r, sentLS.length, sentLS4.length]);
        var script = (function () { var m = String(sentLS[0].cmds).match(/FromBase64String\('([A-Za-z0-9+\/=]+)'\)/); return m ? require('zlib').gunzipSync(Buffer.from(m[1], 'base64')).toString('utf8') : ''; })();
        check('v5.2.0 license sweep: the scheduled run is the SAME read-only script (no write, no reboot)',
            script.indexOf('.GetValue(') >= 0 && !/Set-|New-Item|Remove-Item|shutdown|Restart-Computer/i.test(script), script.length);
        check('v5.2.0 license sweep: the run is logged with its trigger and a count, never a key',
            fs.readFileSync(oLS.licenseLogPath, 'utf8').indexOf('by the test') >= 0 &&
            fs.readFileSync(oLS.licenseLogPath, 'utf8').indexOf('Serial') < 0);

        // the settings round trip: stored, sourced, revertable - and an ABSENT field keeps the saved value
        oLS.longTimeout = function (fn, ms) { };
        oLS.handleAdminPostReq({ headers: XHDR, body: { action: 'save_settings', scanIntervalHours: '24', updateHours: '168', anyCveMaxAgeYears: '5', collectIntervalMinutes: '1440', notifyThreshold: 'HIGH', licenseCollectIntervalHours: '12' } }, mockRes(function (d1) {
            check('v5.2.0 settings: the license interval is stored and reported with its source',
                d1.settings && d1.settings.licenseCollectIntervalHours === 12 && d1.sources.licenseCollectIntervalHours === 'file', d1.settings && d1.settings.licenseCollectIntervalHours);
            oLS.handleAdminPostReq({ headers: XHDR, body: { action: 'save_settings', scanIntervalHours: '24', updateHours: '168', anyCveMaxAgeYears: '5', collectIntervalMinutes: '1440', notifyThreshold: 'HIGH' } }, mockRes(function (d2) {
                check('v5.2.0 settings: a save WITHOUT the field keeps the stored value (an older cached panel is not locked out)',
                    d2.settings && d2.settings.licenseCollectIntervalHours === 12, d2.settings && d2.settings.licenseCollectIntervalHours);
                oLS.handleAdminPostReq({ headers: XHDR, body: { action: 'save_settings', scanIntervalHours: '24', updateHours: '168', anyCveMaxAgeYears: '5', collectIntervalMinutes: '1440', notifyThreshold: 'HIGH', licenseCollectIntervalHours: '99999' } }, mockRes(function (d3) {
                    check('v5.2.0 settings: an out-of-range interval is rejected (0..8760)', !!d3.error && /license collection interval/i.test(d3.error), d3.error);
                    oLS.handleAdminPostReq({ headers: XHDR, body: { action: 'revert_setting', revertLicenseCollectIntervalHours: 'true' } }, mockRes(function (d4) {
                        check('v5.2.0 settings: the interval can be reverted to config.json/default (back to 0 = off)',
                            d4.settings && d4.settings.licenseCollectIntervalHours === 0 && d4.sources.licenseCollectIntervalHours === 'default', d4.settings && d4.settings.licenseCollectIntervalHours);
                        next();
                    }), user);
                }), user);
            }), user);
        }), user);
    });
});

// ---- v5.4.0 (issue #9): the atomic winget toggles + the two read-only detail routes ----
steps.push(function (next) {
    var dpD2 = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-det-'));
    var dNodes = [
        { _id: 'node//d1', meshid: 'mesh//grp1', rname: 'dh1', name: 'DetailWin', osdesc: 'Microsoft Windows 11 Pro', ip: '10.0.0.7' },
        { _id: 'node//d2', meshid: 'mesh//grp1', rname: 'dh2', name: 'DetailTwo', osdesc: 'Microsoft Windows 10' }
    ];
    var dSys = {
        'sinode//d1': { _id: 'sinode//d1', doc: { hardware: { identifiers: { cpu_name: 'Intel i5', chassis_serial: 'SN-D1', product_name: 'ThinkPad' }, windows: { osinfo: { BuildRevision: '2600' }, memory: [{ BankLabel: 'B0', Capacity: 8589934592 }] } } } },
        'sinode//d2': { _id: 'sinode//d2', doc: { apps: [{ name: 'Firefox', version: '121.0', publisher: 'Mozilla' }] } }
    };
    var dbD2 = {
        GetAllType: function (t, cb) { cb(null, t === 'node' ? dNodes.slice() : (t === 'mesh' ? meshes.slice() : [])); },
        Get: function (id, cb) { if (dSys[id]) { cb(null, [dSys[id]]); return; } cb(null, dNodes.filter(function (n) { return n._id === id; })); }
    };
    var sentD2 = [];
    var oD2 = factory({ parent: { db: dbD2, datapath: dpD2, debug: function () { }, config: { settings: {} }, webserver: { meshes: { 'mesh//grp1': { name: 'HQ' } }, wsagents: { 'node//d1': {} } }, DispatchEvent: function () { } } });
    oD2.loadRemoteCpeTable();   // v5.6.0: the curated licenseType comes from the shipped table
    oD2.softwareInventory = { d1: { apps: [{ name: 'Firefox', version: '120.0', publisher: 'Mozilla' }, { name: 'Notepad', version: '11' }] } };
    oD2.windowsUpdates = { d1: { count: 2, updates: [] } };
    // the Microsoft entry carries the v5.6.0 license-TYPE fields (measured on a real Windows 11) beside the key
    oD2.licenseInventory = {
        d1: {
            time: 'x', items: [{ name: 'Firefox', license: 'SUPER-SECRET-KEY', source: 'registry' }],
            ms: [{ name: 'Windows(R) Operating System, OEM_DM channel', key: 'MS-SECRET', product: 'Windows(R), Professional edition', family: 'Professional', channel: 'OEM:DM', channelType: 'OEM', status: '1', statusText: 'licensed', grace: '0', evalEnd: '', appId: '55c92734-d682-4d71-983e-d6ec3f16059f' }]
        }
    };
    oD2.scanDeviceSoftware = function (list, cb) {
        var out = [];
        for (var i = 0; i < (list || []).length; i++) {
            var nm = String((list[i] && list[i].name) || '');
            out.push(/firefox/i.test(nm)
                ? { status: 'CVE', isCve: true, cve: 'CVE-2024-0001', severity: 'CRITICAL', cvss: 9.8, software: nm, version: String(list[i].version || ''), description: 'crit' }
                : { status: 'not assessable', isCve: false, cve: '', severity: '', cvss: '', software: nm, version: String(list[i].version || ''), description: '' });
        }
        cb(out);
    };
    oD2.scanDeviceOs = function () { return [{ cve: 'CVE-2024-0009', isCve: true, severity: 'HIGH', cvss: 7.8, software: 'Operating System', version: 'W11' }]; };
    oD2.osSupportState = function () { return { state: 'eol', label: 'Windows 11 Pro', reason: 'fixture' }; };

    // 1) the atomic exclude toggle must change ONE key and keep every other winget setting
    oD2.pluginSettings = { wingetUpdater: { enabled: true, updateMeshes: ['mesh//grp1'], excludeNodes: [], ignorePackages: [{ id: 'Some.Package', note: 'keep' }], pinSync: true } };
    oD2.handleAdminPostReq({ headers: XHDR, body: { action: 'wg_toggle_exclude', nodeId: 'node//d1', excluded: 'true' } }, mockRes(function (r1) {
        var s1 = oD2.pluginSettings.wingetUpdater;
        check('wg_toggle_exclude: adds the device and KEEPS enabled/updateMeshes/ignorePackages/pinSync (the old wg_save_config path read them from the DOM and would have wiped them)',
            r1.success === true && s1.excludeNodes.length === 1 && s1.excludeNodes[0] === 'node//d1' && s1.enabled === true &&
            s1.updateMeshes[0] === 'mesh//grp1' && s1.ignorePackages.length === 1 && s1.pinSync === true, s1);
        oD2.handleAdminPostReq({ headers: XHDR, body: { action: 'wg_toggle_exclude', nodeId: 'node//d1', excluded: 'false' } }, mockRes(function (r2) {
            check('wg_toggle_exclude: takes the device off the list again', r2.success === true && oD2.pluginSettings.wingetUpdater.excludeNodes.length === 0, r2);
            oD2.handleAdminPostReq({ headers: XHDR, body: { action: 'wg_toggle_exclude', nodeId: 'not-a-node', excluded: 'true' } }, mockRes(function (r3) {
                check('wg_toggle_exclude: an invalid node id is refused', !!r3.error, r3);

                // 2) the atomic ignore toggle
                oD2.handleAdminPostReq({ headers: XHDR, body: { action: 'wg_toggle_ignore', pkgId: 'Adobe.Acrobat.Reader', ignore: 'true', note: 'pinned' } }, mockRes(function (r4) {
                    var s4 = oD2.pluginSettings.wingetUpdater;
                    check('wg_toggle_ignore: adds the package and keeps every other winget key',
                        r4.success === true && s4.ignorePackages.length === 2 && s4.ignorePackages[1].id === 'Adobe.Acrobat.Reader' && s4.enabled === true && s4.updateMeshes.length === 1, s4);
                    oD2.handleAdminPostReq({ headers: XHDR, body: { action: 'wg_toggle_ignore', pkgId: 'Adobe.Acrobat.Reader', ignore: 'false' } }, mockRes(function (r5) {
                        check('wg_toggle_ignore: removes it again', r5.success === true && oD2.pluginSettings.wingetUpdater.ignorePackages.length === 1, r5);
                        oD2.handleAdminPostReq({ headers: XHDR, body: { action: 'wg_toggle_ignore', pkgId: 'bad id with spaces', ignore: 'true' } }, mockRes(function (r6) {
                            check('wg_toggle_ignore: an invalid package id is refused', !!r6.error, r6);

                            // 3) dev_details: the full picture for one device, read-only, and NO secret in it
                            sentD2.length = 0;
                            oD2.handleAdminPostReq({ headers: XHDR, body: { action: 'dev_details', nodeId: 'node//d1' } }, mockRes(function (d) {
                                var all = JSON.stringify(d);
                                check('dev_details: identity + hardware come from the canonical record',
                                    d.device.host === 'dh1' && d.device.group === 'HQ' && d.hardware.serial === 'SN-D1' && d.hardware.cpu === 'Intel i5' && d.hardware.memoryBanks.length === 1, d.device);
                                check('dev_details: the findings are the FULL list - software CVE, OS CVE, WINDOWS-UPDATES and OS-EOL (what the CSV shows)',
                                    d.findings.map(function (f) { return f.id; }).sort().join(',') === 'CVE-2024-0001,CVE-2024-0009,OS-EOL,WINDOWS-UPDATES', d.findings.map(function (f) { return f.id; }));
                                check('dev_details: the coverage rows (not assessable) are reported separately, not dropped',
                                    d.coverage.length === 1 && d.coverage[0].status === 'not assessable', d.coverage);
                                check('dev_details: installed programs + the windows update count are included',
                                    d.software.length === 2 && d.counts.software === 2, d.software);
                                check('dev_details: SECURITY - it reports license COUNTS only, never a collected key',
                                    d.license.found === 1 && d.license.ms === 1 && all.indexOf('SUPER-SECRET-KEY') < 0 && all.indexOf('MS-SECRET') < 0, d.license);
                                var ml = (d.license && d.license.msLicenses) || [];
                                var ml0 = ml[0] || {};
                                var msS = (d.license && d.license.msSummary) || {};
                                check('v5.6.0 dev_details: the Microsoft license TYPE is reported - edition, key channel and activation state',
                                    ml.length === 1 && ml0.channel === 'OEM:DM' && ml0.channelType === 'OEM' &&
                                    ml0.statusText === 'licensed' && ml0.family === 'Professional', ml0);
                                check('v5.6.0 dev_details: SECURITY - the Microsoft entry loses its key on the way out (metadata only, no value)',
                                    ml.length === 1 && !Object.prototype.hasOwnProperty.call(ml0, 'key') &&
                                    msS.licensed === 1 && msS.notLicensed === 0, ml0);
                                check('v5.6.0 dev_details: every installed program carries a licenseType field, and a display name no curated row matches stays EMPTY (the fixture name is the bare "Firefox", the row is "mozilla firefox") - unknown is never guessed',
                                    (d.software || []).every(function (s) { return typeof s.licenseType === 'string'; }) &&
                                    (d.software || []).filter(function (s) { return s.name === 'Firefox'; })[0].licenseType === '', d.software);
                                check('dev_details: it is read-only - no agent command is sent', sentD2.length === 0, sentD2.length);
                                oD2.handleAdminPostReq({ headers: XHDR, body: { action: 'dev_details', nodeId: 'bogus' } }, mockRes(function (d2) {
                                    check('dev_details: an invalid node id is refused', !!d2.error, d2);

                                    // 4) sw_details: the fleet picture for one program
                                    oD2.handleAdminPostReq({ headers: XHDR, body: { action: 'sw_details', name: 'Firefox' } }, mockRes(function (s) {
                                        var sall = JSON.stringify(s);
                                        check('sw_details: lists the devices and versions that carry the program',
                                            s.deviceCount === 2 && s.devices.length === 2 && s.versions.length === 2 &&
                                            s.devices.some(function (x) { return x.version === '120.0'; }) && s.devices.some(function (x) { return x.version === '121.0'; }), [s.deviceCount, s.versions]);
                                        check('sw_details: the CVEs matched for this program are reported',
                                            s.cves.length === 1 && s.cves[0].id === 'CVE-2024-0001' && s.cves[0].severity === 'CRITICAL', s.cves);
                                        check('sw_details: SECURITY - a collected license is reported as presence, never as a value',
                                            s.licenseDevices === 1 && sall.indexOf('SUPER-SECRET-KEY') < 0, s.licenseDevices);
                                        check('v5.6.0 sw_details: reports the curated license type of the program (device-independent) - empty here because the bare name "Firefox" matches no curated row',
                                            typeof s.licenseType === 'string' && s.licenseType === '', s.licenseType);
                                        check('sw_details: read-only - no agent command is sent', sentD2.length === 0, sentD2.length);
                                        oD2.handleAdminPostReq({ headers: XHDR, body: { action: 'sw_details', name: '' } }, mockRes(function (s2) {
                                            check('sw_details: an empty name is refused', !!s2.error, s2);
                                            next();
                                        }), user);
                                    }), user);
                                }), user);
                            }), user);
                        }), user);
                    }), user);
                }), user);
            }), user);
        }), user);
    }), user);
});

// ---- v5.4.2: the fleet index walk is paced and parallel builds coalesce (the reported 502s) ----
steps.push(function (next) {
    var dpG = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-idx-'));
    var gNodes = [];
    for (var gi = 0; gi < 6; gi++) { gNodes.push({ _id: 'node//g' + gi, meshid: 'mesh//grp1', rname: 'gh' + gi, name: 'G' + gi, osdesc: 'Microsoft Windows 11' }); }
    // an ASYNC db like the real one - a synchronous mock would finish the build inside the first request
    var dbG = {
        GetAllType: function (t, cb) { setImmediate(function () { cb(null, t === 'node' ? gNodes.slice() : meshes.slice()); }); },
        Get: function (id, cb) { setImmediate(function () { cb(null, gNodes.filter(function (n) { return n._id === id; })); }); }
    };
    var oG = factory({ parent: { db: dbG, datapath: dpG, debug: function () { }, config: { settings: {} }, webserver: { meshes: {}, wsagents: {} }, DispatchEvent: function () { } } });
    oG.softwareInventory = {};
    for (var gj = 0; gj < 6; gj++) { oG.softwareInventory['g' + gj] = { apps: [{ name: 'Prog' + gj, version: '1.0' }] }; }
    var walks = 0;
    oG.scanDeviceSoftware = function (list, cb) { walks += (list || []).length; setImmediate(function () { cb([]); }); };
    check('fleet index: the device walk goes through obj.pacedEach (the project rule for every device iteration)',
        /obj\.pacedEach\(live, function \(node, nodeDone\)/.test(pluginSrc()) && pluginSrc().indexOf('for (var ni = 0; ni < live.length; ni++)') < 0);
    var r1 = null, r2 = null, done1 = false, done2 = false;
    oG.handleAdminPostReq({ headers: XHDR, body: { action: 'sw_fleet', refresh: '1' } }, mockRes(function (d1) { r1 = d1; done1 = true; maybe(); }), user);
    // the second request arrives WHILE the first build is still waiting on the database
    oG.handleAdminPostReq({ headers: XHDR, body: { action: 'sw_fleet', refresh: '1' } }, mockRes(function (d2) { r2 = d2; done2 = true; maybe(); }), user);
    function maybe() {
        if (!done1 || !done2) { return; }
        check('sw_fleet: two parallel builds COALESCE - the fleet is walked once and both answers are the same object',
            walks === 6 && r1 === r2 && r1.software.length === 6, [walks, r1 && r1.software && r1.software.length]);
        check('sw_fleet: both waiters are answered exactly once (mockRes guards double answers)', !!r1 && !!r2);
        next();
    }
});

// ---- v5.5.0 (issue #10): per-user rules, subkey/file wildcard, first-ok-wins map ----
steps.push(function (next) {
    // 1) schema: accept the new forms, reject the unsafe/meaningless ones
    var okReg = obj.sanitizeLicenseRules([{ type: 'registry', path: 'HKCU:\\Software\\Vendor', value: 'Serial', perUser: true }]);
    var okWild = obj.sanitizeLicenseRules([{ type: 'registry', path: 'HKLM:\\SOFTWARE\\V\\Product\\License.ws.*', value: 'Serial' }]);
    var okFile = obj.sanitizeLicenseRules([{ type: 'file', path: '{{profile}}\\AppData\\Roaming\\P\\*.lic', perUser: true }]);
    check('v5.5.0 schema: perUser registry (HKCU), one wildcard segment and perUser file with {{profile}} are accepted',
        !!okReg && okReg[0].perUser === true && !!okWild && !!okFile && okFile[0].perUser === true, [okReg, okWild, okFile]);
    check('v5.5.0 schema: perUser on an HKLM path is refused (it would mean nothing)',
        obj.sanitizeLicenseRules([{ type: 'registry', path: 'HKLM:\\SOFTWARE\\V', value: 'S', perUser: true }]) === null);
    check('v5.5.0 schema: {{profile}} without perUser is refused',
        obj.sanitizeLicenseRules([{ type: 'file', path: '{{profile}}\\a.lic' }]) === null);
    check('v5.5.0 schema: more than one wildcard per path is refused (registry and file)',
        obj.sanitizeLicenseRules([{ type: 'registry', path: 'HKLM:\\A\\*\\B\\*', value: 'S' }]) === null &&
        obj.sanitizeLicenseRules([{ type: 'file', path: 'C:\\*\\x\\*.lic' }]) === null);
    check('v5.5.0 schema: a wildcard in the registry VALUE and perUser on wmi are refused',
        obj.sanitizeLicenseRules([{ type: 'registry', path: 'HKLM:\\A', value: 'S*' }]) === null &&
        obj.sanitizeLicenseRules([{ type: 'wmi', class: 'C', property: 'P', perUser: true }]) === null);

    // 2) script shape: per-user discovery from ProfileList, loaded hives only, capped wildcards, NO hive loading
    var puRules = [{ name: 'PerUserApp', label: 'PerUserApp', rules: [{ type: 'registry', path: 'HKCU:\\Software\\Vendor', value: 'Serial', perUser: true }] },
        { name: 'WildApp', label: 'WildApp', rules: [{ type: 'registry', path: 'HKLM:\\SOFTWARE\\V\\Product\\License.ws.*', value: 'Serial' }] },
        { name: 'FileApp', label: 'FileApp', rules: [{ type: 'file', path: '{{profile}}\\AppData\\Roaming\\P\\*.lic', perUser: true }] }];
    var scr = obj.licenseBuildScript(puRules, false);
    check('v5.5.0 script: enumerates users read-only from ProfileList and caps them at LIC_MAX_USERS',
        scr.indexOf('ProfileList') >= 0 && scr.indexOf('ProfileImagePath') >= 0 && scr.indexOf('-ge ' + obj.LIC_MAX_USERS) >= 0, scr.length);
    check('v5.5.0 script: per-user registry reads loaded hives only (HKEY_USERS by SID), HKCU prefix replaced',
        scr.indexOf("Registry::HKEY_USERS\\") >= 0 && scr.indexOf('-replace \'^HKCU:') >= 0 && scr.indexOf('Test-Path -LiteralPath (\'Registry::HKEY_USERS\\\'') >= 0, scr.substring(0, 80));
    // audit 4 (v5.5.1): ONE unreadable profile (on a real Windows 11 Test-Path on S-1-5-18's systemprofile throws
    // "access denied") used to end the whole discovery loop - no user was ever found. The try is per profile now.
    var discLine = scr.split(String.fromCharCode(10)).filter(function (l) { return l.indexOf('foreach ($invPl in $invPls)') === 0; })[0] || '';
    check('audit4 B1: user discovery isolates every profile in its own try (one denied profile no longer ends the loop) and skips the service SIDs 18/19/20',
        discLine !== '' && discLine.indexOf('{ break }; try {') > 0 && /catch \{ \} \}$/.test(discLine) && discLine.indexOf("'^S-1-5-(18|19|20)$'") > 0, discLine.substring(0, 160));
    check('v5.5.0 script: the profile placeholder is replaced per user (as an escaped regex) and wildcards are enumerated with caps',
        scr.indexOf('\\{\\{profile\\}\\}') >= 0 && (scr.match(/-ge 20/g) || []).length >= 2 && scr.indexOf('-ge 5') >= 0, scr.length);
    check('v5.5.0 script: NEVER loads or saves a hive (the read-only guarantee incl. offline users)',
        !/reg(\.exe)?\s+load/i.test(scr) && scr.indexOf('LoadKey') < 0 && !/reg(\.exe)?\s+save/i.test(scr) && scr.indexOf('Mount-Registry') < 0);
    check('v5.5.0 script: still read-only overall - no write/reboot cmdlet, marker kept, rules stay base64',
        !/Set-|New-Item|Remove-Item|shutdown|Restart-Computer/i.test(scr) && scr.indexOf(obj.LIC_MARKER) >= 0 &&
        scr.indexOf('HKCU:\\Software\\Vendor') < 0 && scr.indexOf('FromBase64String') >= 0);
    var openersPU = scr.split(String.fromCharCode(10)).filter(function (l) { return /[({]\s*$/.test(l); });
    check('v5.5.0 script: one statement per line (agent runs PowerShell line-interactive)', openersPU.length === 0, openersPU.slice(0, 3));
    var dirPU = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-pups-'));
    var fpPU = path.join(dirPU, 'pu.ps1'); fs.writeFileSync(fpPU, scr);
    var psrPU = runPs(['-NoProfile', '-NonInteractive', '-Command', "$t=$null;$e=$null;[void][System.Management.Automation.Language.Parser]::ParseFile('" + fpPU + "',[ref]$t,[ref]$e);$e.Count"]);
    if (psrPU == null) { console.log('SKIP v5.5.0 script: PowerShell parser (PowerShell not available)'); }
    else { check('v5.5.0 script: PowerShell parser reports no errors', !psrPU.failed && psrPU.text.trim() === '0', psrPU.text.trim()); }

    // 3) stored answers carry the user; the map is first-ok-wins; the CSV names the user
    var dpU = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-licu-'));
    var uNodes = [{ _id: 'node//u1', meshid: 'mesh//grp1', rname: 'uh1', name: 'UserOne', osdesc: 'Microsoft Windows 11 Pro' }];
    var dbU = { GetAllType: function (t, cb) { cb(null, t === 'node' ? uNodes.slice() : meshes.slice()); }, Get: function (id, cb) { cb(null, uNodes.filter(function (n) { return n._id === id; })); } };
    var sentU = [];
    var oU = factory({ parent: { db: dbU, datapath: dpU, debug: function () { }, config: { settings: {} }, webserver: { meshes: {}, wsagents: { 'node//u1': { send: function (m) { sentU.push(JSON.parse(m)); } } } }, DispatchEvent: function () { } } });
    oU.softwareInventory = { u1: { apps: [{ name: 'PerUserApp', version: '1' }] } };
    oU.customLicenseEntries = [{ match: 'peruserapp', label: 'PerUserApp', rules: [{ type: 'registry', path: 'HKCU:\\Software\\Vendor', value: 'Serial', perUser: true }] }];
    oU.pluginSettings = { inventoryScanner: { licenseCollectionEnabled: true, licenseMsKeys: false } };
    oU.handleAdminPostReq({ headers: XHDR, body: { action: 'lic_collect', nodeId: 'node//u1' } }, mockRes(function (dU) {
        var gunzU = function (cmd) { var m = String(cmd).match(/FromBase64String\('([A-Za-z0-9+\/=]+)'\)/); return m ? require('zlib').gunzipSync(Buffer.from(m[1], 'base64')).toString('utf8') : ''; };
        check('v5.5.0 collect: a per-user rule is dispatched on the lic session with the per-user script',
            dU.started === true && sentU.length === 1 && String(sentU[0].sessionid).indexOf('invscanner-lic-') === 0 &&
            gunzU(sentU[0].cmds).indexOf('ProfileList') >= 0, [dU, sentU.length]);
        var sess = oU.licPending['node//u1'] ? oU.licPending['node//u1'].sid : 'invscanner-lic-u1';
        var consumed = oU.onAgentResponse({ action: 'msg', type: 'runcommands', sessionid: sess, result: 'x' + oU.LIC_MARKER +
            '{"collect":true,"items":[{"name":"PerUserApp","label":"PerUserApp","source":"registry","license":"","ok":false,"user":""},{"name":"PerUserApp","label":"PerUserApp","source":"registry","license":"PU-KEY-1","ok":true,"user":"alice"},{"name":"PerUserApp","label":"PerUserApp","source":"registry","license":"PU-KEY-2","ok":true,"user":"bob"}],"ms":[],"error":""}' + String.fromCharCode(10) }, '', 'node//u1');
        var invU = oU.licenseInventory['u1'];
        check('v5.5.0 response: the user of each read is stored per item',
            consumed === true && invU.items.length === 3 && invU.items[1].user === 'alice' && invU.items[2].user === 'bob' && invU.items[0].user === '', invU.items);
        var mapU = oU.licenseMapForNode('node//u1');
        check('v5.5.0 map: the FIRST successful read wins (a later value no longer overwrites, a failing rule no longer masks)',
            mapU['peruserapp'].license === 'PU-KEY-1' && mapU['peruserapp'].source === 'registry (user: alice)', mapU['peruserapp']);
        check('v5.5.0 map: the source names the rule type AND the user for the CSV',
            mapU['peruserapp'].source === 'registry (user: alice)', mapU['peruserapp'].source);
        oU.licenseInventory['u1'] = { time: 'x', items: [{ name: 'OnlyFail', license: '', source: 'file', ok: false, user: '' }], ms: [] };
        check('v5.5.0 map: an all-failing rule set yields an empty license (never a stale value)', oU.licenseMapForNode('node//u1')['onlyfail'].license === '');
        obj.licenseInventory = { d1: { time: 'x', items: [{ name: 'Firefox', license: 'FIRE-KEY', source: 'registry', ok: true, user: 'alice' }], ms: [] } };
        obj.buildCsvForNodes([nodes[0]], 'software', function (cerr, csvU) {
            check('v5.5.0 CSV: the License Source column shows "registry (user: alice)"', String(csvU).indexOf('registry (user: alice)') >= 0 && String(csvU).indexOf('FIRE-KEY') >= 0, String(csvU).split('\r\n').slice(1, 2));
            obj.licenseInventory = {};

            // 4) the shipped curated table: new entries survive the same validation a running server applies
            var tbl = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'license-table.json'), 'utf8'));
            var app = obj.applyLicenseTableText(JSON.stringify(tbl));
            check('v5.5.0 table: the shipped file applies (4 entries) with the new schema', app.ok === true && app.applied === 4 && app.skipped === 0, app);
            var vm = tbl.entries.filter(function (e) { return /vmware/i.test(e.label); })[0];
            var md = tbl.entries.filter(function (e) { return /mountain/i.test(e.label); })[0];
            check('v5.5.0 table: VMware is covered by the version-subkey wildcard (both registry views), with a cited source',
                !!vm && vm.rules.length === 2 && vm.rules.every(function (r) { return r.type === 'registry' && r.value === 'Serial' && (r.path.match(/\*/g) || []).length === 1; }) && !!vm._source, vm && vm.rules);
            check('v5.5.1 table: Mountain Duck reads the documented %AppData%\\Cyberduck key file per user plus the machine-wide C:\\ProgramData\\Cyberduck copy, extracts the Transaction id and cites its source',
                !!md && md.rules.length === 2 && md.rules[0].type === 'file' && md.rules[0].perUser === true &&
                md.rules[0].path === '{{profile}}\\AppData\\Roaming\\Cyberduck\\*.mountainducklicense' &&
                md.rules[1].path === 'C:\\ProgramData\\Cyberduck\\*.mountainducklicense' && md.rules[1].perUser !== true &&
                md.rules.every(function (r) { return /Transaction/.test(r.regex || '') && obj.isSafeTableRegex(r.regex); }) && /Cyberduck/.test(md._source || ''), md && md.rules);
            var mdRx = new RegExp(md.rules[0].regex);
            var mdHit = mdRx.exec('<plist><dict><key>Email</key>\n\t<string>a@b</string>\n\t<key>Transaction</key>\n\t<string>pi_ABC123</string></dict></plist>');
            check('v5.5.1 table: the Mountain Duck regex returns the Transaction value of a real-format key file (group 1), not the e-mail or the signed blob',
                !!mdHit && mdHit[1] === 'pi_ABC123', mdHit);

            // 5) add_license stamps perUser from the editor checkbox and still rejects unsafe combos
            oU.handleAdminPostReq({ headers: XHDR, body: { action: 'add_license', match: '^Stamped', label: 'Stamped', perUser: 'true', rules: JSON.stringify([{ type: 'registry', path: 'HKCU:\\Software\\S', value: 'K' }]) } }, mockRes(function (adU) {
                var stored = oU.customLicenseEntries[oU.customLicenseEntries.length - 1];
                check('v5.5.0 add_license: the editor checkbox stamps perUser onto registry/file rules',
                    adU.success === true && stored.rules[0].perUser === true, stored);
                oU.handleAdminPostReq({ headers: XHDR, body: { action: 'add_license', match: '^BadPU', label: 'Bad', perUser: 'true', rules: JSON.stringify([{ type: 'registry', path: 'HKLM:\\Software\\S', value: 'K' }]) } }, mockRes(function (bdU) {
                    check('v5.5.0 add_license: perUser on an HKLM path is refused with a message that names the rule model',
                        !!bdU.error && /perUser|HKCU/i.test(bdU.error), bdU.error);
                    next();
                }), user);
            }), user);
        });
    }), user);
});

// ---- audit 4 (v5.5.1): independent full audit - regression tests for every fixed finding ----
// Ids here are REALISTIC: MeshCentral generates mesh/node ids as 'mesh//' + base64(48 random bytes) with '+' -> '@'
// and '/' -> '$' (meshuser.js createmesh) - the simplified 'mesh//grp1' ids of the older fixtures hid finding B2.
function realId(kind) { return kind + '//' + require('crypto').randomBytes(48).toString('base64').replace(/\+/g, '@').replace(/\//g, '$'); }
steps.push(function (next) {
    // B3: the regex-safety gate (ReDoS) - every pattern below was measured or is a textbook catastrophic shape
    var badRx = ['((a+))+$', '(a|a)+$', '(a|aa)+$', '(a+)+$', '(\\w+\\s?)+$', '(a+){2,}', '(?:a+)+$', '([a-z]+)*$', '((ab)*)+', '(?:(?:a|b)c)+', '(?<n>a+)+', '(a)\\1', '(?<n>a)\\k<n>', '((x)?)+'];
    var goodRx = ['^firefox', 'mozilla firefox|firefox esr', '(x64|x86)?', '^7-zip( \\d+)?', 'notepad\\+\\+', '(?:google )?chrome', '[a-z]+ \\d+', '^(adobe )?acrobat (reader|pro)'];
    var badPassed = badRx.filter(function (r) { return obj.isSafeTableRegex(r); });
    var goodFailed = goodRx.filter(function (r) { return !obj.isSafeTableRegex(r); });
    check('audit4 B3: nested quantifiers at ANY depth, alternation under a quantifier and backreferences are refused (((a+))+$ took 45 s, (a|a)+$ 72 s before)', badPassed.length === 0, badPassed);
    check('audit4 B3: ordinary patterns (optional groups, top-level alternation, escaped +) stay accepted', goodFailed.length === 0, goodFailed);
    var shipped = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'cpe-table.json'), 'utf8')).entries.concat(JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'license-table.json'), 'utf8')).entries);
    var shippedBad = shipped.filter(function (e) { return !obj.isSafeTableRegex(e.match); }).map(function (e) { return e.match; });
    check('audit4 B3: every shipped cpe-table/license-table regex still passes the stricter gate', shippedBad.length === 0, shippedBad);
    check('audit4 B3: a tampered remote table with a catastrophic regex is skipped, not applied', obj.applyCpeTableText({ entries: [{ match: '((a+))+$', vendor: 'v', product: 'p' }] }).ok === false);

    // B2: Server Files with REAL mesh ids, plus the domain-traversal guard
    var grp = realId('mesh'), nodeR = realId('node');
    var fsp = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-a4sf-'));
    fs.mkdirSync(path.join(fsp, 'tmp'), { recursive: true });
    fs.mkdirSync(path.join(fsp, 'domain', 'mesh-' + grp.split('/')[2]), { recursive: true });
    fs.writeFileSync(path.join(fsp, 'domain', 'mesh-' + grp.split('/')[2], 'tool.msi'), 'MSIDATA');
    var nodesR = [{ _id: nodeR, meshid: grp, rname: 'rh', name: 'RealOne', osdesc: 'Microsoft Windows 11 Pro' }];
    var sentR = [];
    var dbR = { GetAllType: function (t, cb) { cb(null, t === 'node' ? nodesR.slice() : [{ _id: grp, name: 'Real group' }]); }, Get: function (id, cb) { cb(null, nodesR.filter(function (n) { return n._id === id; })); } };
    var wsa = {}; wsa[nodeR] = { send: function (m) { sentR.push(JSON.parse(m)); } };
    var oR = factory({ parent: { db: dbR, datapath: fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-a4d-')), filespath: fsp, debug: function () { }, config: { settings: {} },
        webserver: { meshes: {}, wsagents: wsa }, encodeCookie: function () { return 'COOKIE'; }, loginCookieEncryptionKey: 'k', DispatchEvent: function () { } } });
    oR.installRouteHook = function () { };
    check('audit4 B2: swServerFilesDir accepts a real mesh id (@ and $) and resolves INSIDE <filespath>',
        oR.swServerFilesDir(grp) === path.resolve(fsp, 'domain', 'mesh-' + grp.split('/')[2]), oR.swServerFilesDir(grp));
    check('audit4 B2: a domain part that is a path (mesh/a\\..\\..\\x/g, mesh/../g) or a dot group is refused',
        oR.swServerFilesDir('mesh/a\\..\\..\\..\\Windows/grp1') === null && oR.swServerFilesDir('mesh/../grp1') === null && oR.swServerFilesDir('mesh//..') === null && oR.swServerFilesDir('mesh//a/b') === null);
    oR.handleAdminPostReq({ headers: XHDR, body: { action: 'sw_serverfiles' } }, mockRes(function (sf) {
        var f = (sf.folders || []).filter(function (x) { return x.meshId === grp; })[0];
        check('audit4 B2: sw_serverfiles lists the Server Files folder of a group with a REAL id (it was always missing)', !!f && f.files.length === 1 && f.files[0].name === 'tool.msi', sf);
        oR.handleAdminPostReq({ headers: XHDR, body: { action: 'sw_create_task', source: 'serverfile', meshId: 'mesh/a\\..\\..\\..\\Windows/grp1', fileName: 'x.msi', nodeIds: nodeR } }, mockRes(function (tr) {
            check('audit4 B2: sw_create_task refuses a server-files group id that would leave <filespath>', /Invalid server-files group id/.test(tr.error || ''), tr);
            oR.handleAdminPostReq({ headers: XHDR, body: { action: 'sw_create_task', source: 'serverfile', meshId: grp, fileName: 'tool.msi', nodeIds: nodeR } }, mockRes(function (tk) {
                setTimeout(function () {
                    var task = oR.swTasks[tk.taskId];
                    var dev = task ? task.devices[nodeR] : null;
                    check('audit4 B2: a Server Files deploy with a real group id is staged and dispatched (wget + runcommands), not "invalid server-files group"',
                        !!dev && dev.state === 'running' && /^[a-f0-9]{64}$/.test(task.sha256) && sentR.map(function (m) { return m.action; }).join(',') === 'wget,runcommands', [dev, sentR.length]);
                    a4scheduler();
                }, 300);
            }), user);
        }), user);
    }), user);

    // B4: one scheduled pass at a time - the next run is planned only after the running pass finished
    function a4scheduler() {
        var oS = factory({ parent: { db: { GetAllType: function (t, cb) { cb(null, t === 'mesh' ? [{ _id: 'mesh//g', name: 'G' }] : []); }, Get: function (id, cb) { cb(null, []); } },
            datapath: fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-a4s-')), debug: function () { }, config: { settings: { vulnerabilityScanner: { scanIntervalHours: 24 } } }, webserver: { meshes: {} }, DispatchEvent: function () { } } });
        var timers = [], passes = 0, finishPass = null;
        oS.longTimeout = function (cb, ms) { timers.push({ cb: cb, ms: ms }); };
        oS.saveScans = function () { };
        oS.scanMeshCves = function (id, cb) { passes++; finishPass = function () { cb(null, []); }; };
        oS.lastScan = new Date(Date.now() - 25 * 3600 * 1000).toISOString();
        oS.scheduleScans();
        check('audit4 B4: a due schedule arms exactly one timer (the 60 s floor)', timers.length === 1 && timers[0].ms === 60000, timers.map(function (t) { return t.ms; }));
        timers.shift().cb();   // fire: the pass starts and is still running
        check('audit4 B4: while the pass runs NO next timer is armed (before: a new full fleet pass started every minute)', passes === 1 && timers.length === 0, [passes, timers.length]);
        finishPass();
        check('audit4 B4: when the pass finished, the next run is armed one full interval later (lastScan is fresh)',
            timers.length === 1 && Math.abs(timers[0].ms - 24 * 3600 * 1000) < 5000 && oS.lastScan > new Date(Date.now() - 5000).toISOString(), timers.map(function (t) { return t.ms; }));
        a4rest();
    }

    function a4rest() {
        // S2: generic extra-header values are masked like every other secret, and a masked value keeps the stored one
        var oA = factory({ parent: { db: db, datapath: fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-a4a-')), debug: function () { }, config: { settings: {} }, webserver: { meshes: {} }, DispatchEvent: function () { } } });
        oA.handleAdminPostReq({ headers: XHDR, body: { action: 'as_save_config', enabled: 'false', targetType: 'generic', endpointUrl: 'https://am.example.com/i', headersJson: '{"X-Api-Key":"SECRET-KEY-1","X-Host":"{{device.host}}"}', bodyTemplate: '{"a":1}' } }, mockRes(function (s1) {
            var shown = JSON.parse(s1.config.headersJson);
            check('audit4 S2: as_get_config masks a literal extra-header value (it can carry an API key) and keeps a placeholder value visible',
                shown['X-Api-Key'] === oA.AS_MASK && shown['X-Host'] === '{{device.host}}' && JSON.stringify(s1).indexOf('SECRET-KEY-1') < 0, shown);
            oA.handleAdminPostReq({ headers: XHDR, body: { action: 'as_save_config', enabled: 'false', targetType: 'generic', endpointUrl: 'https://am.example.com/i', headersJson: s1.config.headersJson, bodyTemplate: '{"a":1}' } }, mockRes(function () {
                check('audit4 S2: re-saving the masked form keeps the stored header value (no secret is lost, none is shown)',
                    JSON.parse(oA.pluginSettings.assetManagement.headersJson)['X-Api-Key'] === 'SECRET-KEY-1', oA.pluginSettings.assetManagement.headersJson);
                oA.handleAdminPostReq({ headers: XHDR, body: { action: 'as_save_config', enabled: 'false', targetType: 'generic', endpointUrl: 'https://am.example.com/i', headersJson: '{"X-New":"' + oA.AS_MASK + '"}', bodyTemplate: '{"a":1}' } }, mockRes(function (s3) {
                    check('audit4 S2: a mask for a header that has no stored value is refused instead of sending "--------"', /no stored value/.test(s3.error || ''), s3);

                    // S3: program names that are Object.prototype keys must not vanish from the unified views
                    var protoNodes = [{ _id: 'node//pp', meshid: 'mesh//grp1', rname: 'pp', name: 'PP', osdesc: 'Windows 11' }];
                    var oP = factory({ parent: { db: { GetAllType: function (t, cb) { cb(null, t === 'node' ? protoNodes.slice() : meshes.slice()); }, Get: function (id, cb) { cb(null, id === 'sinode//pp' ? [{ doc: { apps: [{ name: '__proto__', version: '1' }, { name: 'constructor', version: '2' }, { name: 'Firefox', version: '3' }] } }] : protoNodes.filter(function (n) { return n._id === id; })); } },
                        datapath: fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-a4p-')), debug: function () { }, config: { settings: {} }, webserver: { meshes: {} } } });
                    oP.scanDeviceSoftware = function (l, cb) { cb([]); }; oP.scanDeviceOs = function () { return []; };
                    oP.handleAdminPostReq({ headers: XHDR, body: { action: 'sw_fleet', refresh: '1' } }, mockRes(function (fl) {
                        var names = (fl.software || []).map(function (x) { return x.name; }).sort().join(',');
                        check('audit4 S3: programs named "__proto__" and "constructor" are listed in sw_fleet (they silently disappeared before)', names === 'Firefox,__proto__,constructor', names);
                        check('audit4 S3: and Object.prototype stays clean', ({}).devs === undefined && Object.keys(Object.prototype).length === 0);

                        // S4: the lifecycle fetch passes its own 512 KB cap to the shared getter
                        var seenCap = null, savedGet = obj.cpeTableHttpGet;
                        obj.cpeTableHttpGet = function (u, cb, cap) { seenCap = cap; cb(null, '[]'); };
                        obj.osLifecycleHttpGet('https://endoflife.date/api/ubuntu.json', function () { });
                        obj.cpeTableHttpGet = savedGet;
                        check('audit4 S4: the OS lifecycle download is capped at OS_LIFECYCLE_MAX_BYTES (512 KB), not the 2 MB table cap', seenCap === obj.OS_LIFECYCLE_MAX_BYTES && seenCap === 512 * 1024, seenCap);

                        // Gate matrix: EVERY POST action of the dispatcher answers 401 without admin, 403 without the header,
                        // 400 without an object body - pinned for all of them, not just two (the old suite tested 2 of 53)
                        var src = fs.readFileSync(path.join(__dirname, '..', 'lib', 'routes.js'), 'utf8');
                        var acts = []; var mre = /req\.body\.action === '([a-z_]+)'/g; var mm;
                        while ((mm = mre.exec(src)) !== null) { if (acts.indexOf(mm[1]) < 0) { acts.push(mm[1]); } }
                        var badGate = [];
                        var subAdmin = { name: 'tenant', _id: 'user/t/x', siteadmin: 0xFFFFFFFF, domain: 't' };
                        acts.forEach(function (a) {
                            var r401 = null, r401s = null, r403 = null, r400 = null;
                            obj.handleAdminPostReq({ headers: XHDR, body: { action: a } }, { sendStatus: function (c) { r401 = c; }, type: function () { return this; }, json: function () { r401 = 'json'; } }, { name: 'x', siteadmin: 0, domain: '' });
                            obj.handleAdminPostReq({ headers: XHDR, body: { action: a } }, { sendStatus: function (c) { r401s = c; }, type: function () { return this; }, json: function () { r401s = 'json'; } }, subAdmin);
                            obj.handleAdminPostReq({ headers: {}, body: { action: a } }, { sendStatus: function (c) { r403 = c; }, type: function () { return this; }, json: function () { r403 = 'json'; } }, user);
                            obj.handleAdminPostReq({ headers: XHDR, body: 'action=' + a }, { sendStatus: function (c) { r400 = c; }, type: function () { return this; }, json: function () { r400 = 'json'; } }, user);
                            if (r401 !== 401 || r401s !== 401 || r403 !== 403 || r400 !== 400) { badGate.push([a, r401, r401s, r403, r400]); }
                        });
                        check('audit4 gates: all ' + acts.length + ' POST actions refuse a non-admin (401), a SUB-DOMAIN full admin (401), a request without the header (403) and a non-object body (400)', acts.length >= 50 && badGate.length === 0, badGate.slice(0, 5));

                        // Direct tests for helpers that had none
                        check('audit4 helpers: formatCsvField neutralises = + - @ TAB CR at the start and quotes , " CR LF',
                            obj.formatCsvField('=1+1') === "'=1+1" && obj.formatCsvField('+x') === "'+x" && obj.formatCsvField('-x') === "'-x" && obj.formatCsvField('@x') === "'@x" &&
                            obj.formatCsvField('\tx') === "'\tx" && obj.formatCsvField('a,b') === '"a,b"' && obj.formatCsvField('a"b') === '"a""b"' && obj.formatCsvField('a\nb') === '"a\nb"' &&
                            obj.formatCsvField('=HYPERLINK("x")') === '"\'=HYPERLINK(""x"")"' && obj.formatCsvField(null) === '""' && obj.formatCsvField('plain') === 'plain');
                        check('audit4 helpers: safeNodeDir never returns a path element (.. / \\ : are neutralised)',
                            ['node//..', 'node//a/../b', 'node//a\\b', 'node//c:x', ''].every(function (x) { var d = obj.safeNodeDir(x); return d !== '..' && d !== '.' && !/[\/\\:]/.test(d) && d !== ''; }),
                            ['node//..', 'node//a\\b'].map(obj.safeNodeDir));
                        check('audit4 helpers: rbCleanMessage caps at 200 and strips quotes/control chars', obj.rbCleanMessage(new Array(600).join('x'), '').length === 200 && obj.rbCleanMessage("it's \"a\" `b` $c \\d", '') === 'its a b c d');
                        check('audit4 helpers: swPsQuote doubles all five PowerShell quote characters', obj.swPsQuote("a'b\u2018c\u2019d\u201Ae\u201Bf") === "a''b\u2018\u2018c\u2019\u2019d\u201A\u201Ae\u201B\u201Bf");
                        next();
                    }), user);
                }), user);
            }), user);
        }), user);
    }
});

// ---- v5.6.0: the curated license type in the CPE table (SPDX / Proprietary / Freeware) ----
steps.push(function (next) {
    // the sanitizer is the single gate for table, remote and custom rows
    check('v5.6.0 licenseType: SPDX ids keep their case and the three descriptors pass',
        obj.sanitizeLicenseType('GPL-2.0-or-later') === 'GPL-2.0-or-later' && obj.sanitizeLicenseType('MIT') === 'MIT' &&
        obj.sanitizeLicenseType('curl') === 'curl' && obj.sanitizeLicenseType('LGPL-2.1-only') === 'LGPL-2.1-only' &&
        obj.sanitizeLicenseType('Proprietary') === 'Proprietary' && obj.sanitizeLicenseType('Freeware') === 'Freeware' &&
        obj.sanitizeLicenseType('Freeware (non-commercial)') === 'Freeware (non-commercial)' &&
        obj.sanitizeLicenseType('  MIT  ') === 'MIT');
    check('v5.6.0 licenseType: path, quote and angle-bracket characters are refused (it reaches a CSV cell and an HTML attribute)',
        ['C:\\lic', 'a"b', "a'b", 'a<b>c', 'a,b', 'a\nb', '{}'].every(function (v) { return obj.sanitizeLicenseType(v) === ''; }),
        ['C:\\lic', 'a"b', 'a<b>c'].map(obj.sanitizeLicenseType));
    check('v5.6.0 licenseType: a non-string or an empty value yields empty, and the value is capped at 80 characters',
        obj.sanitizeLicenseType(null) === '' && obj.sanitizeLicenseType(undefined) === '' && obj.sanitizeLicenseType('') === '' &&
        obj.sanitizeLicenseType(42) === '' && obj.sanitizeLicenseType({}) === '' &&
        obj.sanitizeLicenseType(new Array(200).join('A')).length === 80);

    // apply: the field is optional, survives on CPE rows, is dropped on kind rows and never kills a row
    var savedCpe = obj.remoteCpeEntries;
    var ap = obj.applyCpeTableText({
        entries: [
            { match: '^lic-a', vendor: 'V', product: 'P', licenseType: 'MIT' },
            { match: '^lic-b', vendor: 'V', product: 'P', licenseType: 'EVIL"; DROP' },
            { match: '^lic-c', kind: 'driver', licenseType: 'MIT' },
            { match: '^lic-d', vendor: 'V', product: 'P' },
            { match: '^lic-e', vendor: 'V', product: 'P', licenseType: 42 }
        ]
    });
    var rows = obj.remoteCpeEntries;
    check('v5.6.0 applyCpeTableText: a valid licenseType is kept verbatim (no lowercasing - SPDX ids are case-sensitive)',
        ap.ok === true && ap.applied === 5 && rows[0].licenseType === 'MIT', rows[0]);
    check('v5.6.0 applyCpeTableText: an unusable licenseType is dropped but the MAPPING row still applies (a bad annotation must not lose CVE coverage)',
        rows[1].vendor === 'v' && rows[1].licenseType === undefined && rows[4].licenseType === undefined, [rows[1], rows[4]]);
    check('v5.6.0 applyCpeTableText: a kind (driver/firmware) row carries no license annotation - it is an exclusion marker, not a product',
        rows[2].kind === 'driver' && rows[2].licenseType === undefined, rows[2]);
    obj.remoteCpeEntries = savedCpe;

    // resolution: the table answers, custom wins, unknown stays unknown
    check('v5.6.0 licenseTypeFor: the curated row answers for a real display name',
        obj.licenseTypeFor('Mozilla Firefox 120.0 (x64 en-US)') === 'MPL-2.0' &&
        obj.licenseTypeFor('Notepad++ (64-bit x64)') === 'GPL-3.0-or-later' &&
        obj.licenseTypeFor('7-Zip 24.09 (x64)') === 'LGPL-2.1-only', obj.licenseTypeFor('Mozilla Firefox 120.0'));
    check('v5.6.0 licenseTypeFor: a name with no row answers EMPTY - unknown is never guessed (the auto matcher proves a CPE, not a license)',
        obj.licenseTypeFor('Chrome') === '' && obj.licenseTypeFor('Some Mystery Tool 3.1') === '' && obj.licenseTypeFor('') === '');
    check('v5.6.0 licenseTypeFor: a driver/firmware kind row has no license type', obj.licenseTypeFor('Realtek USB Audio') === '');
    check('v5.6.0 licenseTypeFor: the free Community Edition is not reported with the commercial licence of its product family',
        obj.licenseTypeFor('IntelliJ IDEA 2024.1 (Community Edition)') === 'Apache-2.0' &&
        obj.licenseTypeFor('PyCharm Community Edition 2024.1') === 'Apache-2.0' &&
        obj.licenseTypeFor('IntelliJ IDEA 2024.1 (Ultimate Edition)') === 'Proprietary',
        [obj.licenseTypeFor('IntelliJ IDEA 2024.1 (Community Edition)'), obj.licenseTypeFor('IntelliJ IDEA 2024.1 (Ultimate Edition)')]);
    var savedCustom = obj.customCpeEntries.slice();
    obj.customCpeEntries = [{ match: '^mozilla firefox', vendor: 'mozilla', product: 'firefox', licenseType: 'Proprietary' }];
    check('v5.6.0 licenseTypeFor: a custom entry wins over the curated table (same precedence as the CPE mapping itself)',
        obj.licenseTypeFor('Mozilla Firefox 120.0') === 'Proprietary', obj.licenseTypeFor('Mozilla Firefox 120.0'));
    obj.customCpeEntries = savedCustom;
    check('v5.6.0 matchTableEntry: the license type travels with the mapping hit and a kind hit stays a kind hit',
        obj.matchTableEntry('Mozilla Firefox 120.0').licenseType === 'MPL-2.0' &&
        obj.matchTableEntry('Realtek USB Audio').kind === 'driver' &&
        obj.matchTableEntry('Realtek USB Audio').licenseType === undefined, obj.matchTableEntry('Mozilla Firefox 120.0'));
    check('v5.6.0 classifySoftware: the annotation reaches the scan result without changing the CPE target',
        obj.classifySoftware('Mozilla Firefox 120.0', 'Mozilla').search.vendor === 'mozilla' &&
        obj.classifySoftware('Mozilla Firefox 120.0', 'Mozilla').search.licenseType === 'MPL-2.0' &&
        obj.classifySoftware('Realtek USB Audio', 'Realtek').kind === 'driver');

    // the shipped table: the invariant is "filled, or documented why not" - not a frozen count
    var tbl = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'cpe-table.json'), 'utf8'));
    var cpeRows = tbl.entries.filter(function (e) { return e.kind == null; });
    var kindRows = tbl.entries.filter(function (e) { return e.kind != null; });
    var VOCAB = /^(Proprietary|Freeware|Freeware \(non-commercial\))$|^[A-Za-z0-9][A-Za-z0-9.+-]{0,63}$/;
    var badVocab = cpeRows.filter(function (e) { return e.licenseType && !VOCAB.test(e.licenseType); }).map(function (e) { return e.licenseType; });
    check('v5.6.0 shipped table: every licenseType is an SPDX identifier or one of the three documented descriptors', badVocab.length === 0, badVocab);
    var unfilled = cpeRows.filter(function (e) { return !e.licenseType; });
    check('v5.6.0 shipped table: a CPE row without a licenseType must DOCUMENT why (evidence rule - omit, never guess)',
        unfilled.every(function (e) { return typeof e._licenseNote === 'string' && e._licenseNote.length > 20; }),
        unfilled.map(function (e) { return e.match; }));
    check('v5.6.0 shipped table: the license type is curated for essentially every product row', unfilled.length <= 2 && cpeRows.length - unfilled.length >= 120,
        [cpeRows.length, unfilled.length]);
    check('v5.6.0 shipped table: kind (driver/firmware) rows carry no licenseType', kindRows.length > 0 && kindRows.every(function (e) { return e.licenseType === undefined; }), kindRows.length);
    var idxComm = tbl.entries.map(function (e) { return e.match; }).indexOf('^intellij idea.*community');
    var idxGen = tbl.entries.map(function (e) { return e.match; }).indexOf('^intellij idea');
    check('v5.6.0 shipped table: the edition-specific Community row sits BEFORE the generic IDE row (first hit wins)',
        idxComm >= 0 && idxGen >= 0 && idxComm < idxGen, [idxComm, idxGen]);
    check('v5.6.0 shipped table: the note documents the vocabulary and that the field is not the purchase model of one installation',
        typeof tbl._licenseNote === 'string' && /SPDX/.test(tbl._licenseNote) && /Proprietary/.test(tbl._licenseNote) &&
        /Freeware \(non-commercial\)/.test(tbl._licenseNote) && /ProductKeyChannel/.test(tbl._licenseNote), (tbl._licenseNote || '').length);

    // custom entries: the editor route accepts, sanitizes and persists the annotation
    var dpLT = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-lt-'));
    var oLT = factory({ parent: { db: db, datapath: dpLT, debug: function () { }, config: { settings: {} }, webserver: { meshes: {}, wsagents: {} }, DispatchEvent: function () { } } });
    oLT.loadRemoteCpeTable();
    // an assertion inside a response callback must NEVER throw: the route's catch would answer a second time
    // and the suite would report "answered 2x" plus a hung step instead of the real failure.
    var pickRow = function (arr, m) { for (var i = 0; i < (arr || []).length; i++) { if (arr[i] && arr[i].match === m) { return arr[i]; } } return null; };
    oLT.handleAdminPostReq({ headers: XHDR, body: { action: 'add_cpe', match: '^Acme Tool', vendor: 'acme', product: 'tool', licenseType: 'GPL-3.0-only' } }, mockRes(function (a1) {
        check('v5.6.0 add_cpe: stores the license type with the custom mapping', a1.success === true && a1.entries[0].licenseType === 'GPL-3.0-only', a1.entries[0]);
        oLT.handleAdminPostReq({ headers: XHDR, body: { action: 'add_cpe', match: '^Acme Two', vendor: 'acme', product: 'two', licenseType: 'bad/value"here' } }, mockRes(function (a2) {
            check('v5.6.0 add_cpe: an unusable license type is dropped but the mapping is still saved',
                a2.success === true && a2.entries[1].licenseType === '' && oLT.customCpeEntries[1].licenseType === undefined, a2.entries[1]);
            oLT.handleAdminPostReq({ headers: XHDR, body: { action: 'add_cpe', match: '^Acme Three', vendor: 'acme', product: 'three' } }, mockRes(function (a3) {
                check('v5.6.0 add_cpe: the field is optional - a mapping without it stays valid', a3.success === true && a3.entries[2].licenseType === '', a3.entries[2]);
                var stored = JSON.parse(fs.readFileSync(oLT.customCpePath, 'utf8'));
                check('v5.6.0 custom-cpe.json: the annotation is persisted and reloaded', stored[0].licenseType === 'GPL-3.0-only' && !Object.prototype.hasOwnProperty.call(stored[1], 'licenseType'), stored);
                oLT.loadCustomCpe();
                check('v5.6.0 loadCustomCpe: the reloaded entry answers through licenseTypeFor and a dropped one does not resurrect',
                    oLT.licenseTypeFor('Acme Tool 1.0') === 'GPL-3.0-only' && oLT.licenseTypeFor('Acme Two 1.0') === '', oLT.licenseTypeFor('Acme Tool 1.0'));
                oLT.handleAdminPostReq({ headers: XHDR, body: { action: 'get_cpe_table' } }, mockRes(function (gt) {
                    var acme = pickRow(gt.entries, '^Acme Tool');
                    var ff = pickRow(gt.entries, 'mozilla firefox');
                    var realtek = pickRow(gt.entries, '^realtek usb audio');
                    check('v5.6.0 get_cpe_table: every row reports a licenseType string, the custom annotation and the maintained one both arrive',
                        Array.isArray(gt.entries) && gt.entries.every(function (e) { return typeof e.licenseType === 'string'; }) &&
                        acme != null && acme.licenseType === 'GPL-3.0-only' && acme.source === 'custom' &&
                        ff != null && ff.licenseType === 'MPL-2.0' && ff.source === 'remote', [acme, ff]);
                    check('v5.6.0 get_cpe_table: a kind row is still shown as an exclusion and carries no license type',
                        realtek != null && realtek.product === 'excluded: driver' && realtek.licenseType === '', realtek);
                    // show_cpe is a legacy GET action, not a POST one - call the handler directly (synchronous,
                    // so a throwing assertion cannot cascade into the outer response callbacks).
                    var scPayload = null;
                    oLT.showCustomCpe({}, { type: function () { return this; }, json: function (d) { scPayload = d; } }, user);
                    check('v5.6.0 show_cpe: the legacy GET list carries the annotation too',
                        scPayload != null && Array.isArray(scPayload.entries) && scPayload.entries.length > 0 &&
                        scPayload.entries[0].licenseType === 'GPL-3.0-only', scPayload && scPayload.entries[0]);
                    next();
                }), user);
            }), user);
        }), user);
    }), user);
});

// ---- v5.6.0: the Microsoft license TYPE + activation state from SoftwareLicensingProduct ----
steps.push(function (next) {
    // the server-side translation of what the device reports (numbers stay numbers on the device)
    check('v5.6.0 msLicenseStatusText: the documented codes become words',
        obj.msLicenseStatusText(0) === 'unlicensed' && obj.msLicenseStatusText('1') === 'licensed' &&
        obj.msLicenseStatusText(2) === 'out-of-box grace period' && obj.msLicenseStatusText(3) === 'out-of-tolerance grace period' &&
        obj.msLicenseStatusText(4) === 'non-genuine grace period' && obj.msLicenseStatusText('5') === 'notification mode (not activated)' &&
        obj.msLicenseStatusText(6) === 'extended grace period', obj.msLicenseStatusText(5));
    check('v5.6.0 msLicenseStatusText: a missing or unknown code stays EMPTY - never reported as "unlicensed" (that would accuse a device on a missing value)',
        obj.msLicenseStatusText('') === '' && obj.msLicenseStatusText(null) === '' && obj.msLicenseStatusText(undefined) === '' &&
        obj.msLicenseStatusText('99') === '' && obj.msLicenseStatusText('abc') === '', obj.msLicenseStatusText('99'));
    check('v5.6.0 msLicenseChannelType: the channels measured on a real Windows 11 normalize to the license type',
        obj.msLicenseChannelType('Retail') === 'Retail' && obj.msLicenseChannelType('OEM:DM') === 'OEM' &&
        obj.msLicenseChannelType('OEM:NONSLP') === 'OEM' && obj.msLicenseChannelType('Volume:MAK') === 'Volume (MAK)' &&
        obj.msLicenseChannelType('Volume:KMSCLIENT') === 'Volume (KMS)' && obj.msLicenseChannelType('Volume:GVLK') === 'Volume (KMS)' &&
        obj.msLicenseChannelType('Volume:CSVLK') === 'Volume (KMS)' && obj.msLicenseChannelType('Volume:SOMETHING') === 'Volume' &&
        obj.msLicenseChannelType('Subscription') === 'Subscription', obj.msLicenseChannelType('Volume:KMSCLIENT'));
    check('v5.6.0 msLicenseChannelType: empty stays empty, an unknown channel is passed through instead of being invented',
        obj.msLicenseChannelType('') === '' && obj.msLicenseChannelType(null) === '' && obj.msLicenseChannelType('SomethingNew') === 'SomethingNew');
    check('v5.6.0 msLicenseSummary: counts by activation state and is null-safe',
        JSON.stringify(obj.msLicenseSummary({ ms: [{ status: '1' }, { status: '5' }, { status: '1' }, { status: '' }] })) === '{"total":4,"licensed":2,"notLicensed":1,"unknown":1}' &&
        obj.msLicenseSummary(null).total === 0 && obj.msLicenseSummary({}).total === 0 && obj.msLicenseSummary({ ms: [] }).total === 0,
        obj.msLicenseSummary({ ms: [{ status: '1' }, { status: '5' }] }));

    // the device script: reads the type, never a full key, never activates anything
    var scrM = obj.licenseBuildScript([{ name: 'Microsoft Office', label: 'Microsoft Office', rules: [{ type: 'registry', path: 'HKLM:\\SOFTWARE\\Microsoft\\Office\\ClickToRun\\Configuration', value: 'ProductReleaseIds' }] }], true);
    check('v5.6.0 license script: reads the license TYPE fields of SoftwareLicensingProduct (family, channel, status, grace, evaluation end, application id)',
        ['LicenseFamily', 'ProductKeyChannel', 'LicenseStatus', 'GracePeriodRemaining', 'EvaluationEndDate', 'ApplicationID'].every(function (k) { return scrM.indexOf(k) >= 0; }),
        ['LicenseFamily', 'ProductKeyChannel', 'LicenseStatus'].filter(function (k) { return scrM.indexOf(k) < 0; }));
    check('v5.6.0 license script: SECURITY - still only the PARTIAL key: no DigitalProductId decode, no firmware OA3xOriginalProductKey, no slmgr, no activation',
        scrM.indexOf('DigitalProductId') < 0 && scrM.indexOf('OA3xOriginalProductKey') < 0 &&
        !/slmgr/i.test(scrM) && !/\/ato\b/i.test(scrM) && scrM.indexOf('PartialProductKey') >= 0);
    check('v5.6.0 license script: still read-only and one statement per line (the shape the transport needs)',
        !/Set-|New-Item|Remove-Item|shutdown|Restart-Computer/i.test(scrM) &&
        scrM.split(String.fromCharCode(10)).filter(function (l) { return /[({]\s*$/.test(l); }).length === 0);
    // the Microsoft block is gated by the msKeys switch - the gate travels in the base64 rule blob, not in the
    // script text (the read line is always present and does nothing while the blob says ms:false). Inside the
    // script the blob is PLAIN base64; only wgTransport gzips the whole script afterwards.
    var blobOf = function (s) { return JSON.parse(Buffer.from(String(s).match(/FromBase64String\('([A-Za-z0-9+\/=]+)'\)/)[1], 'base64').toString('utf8')); };
    check('v5.6.0 license script: the Microsoft block is still behind the msKeys switch (blob ms:false / ms:true)',
        blobOf(obj.licenseBuildScript([], false)).ms === false && blobOf(scrM).ms === true,
        [blobOf(obj.licenseBuildScript([], false)).ms, blobOf(scrM).ms]);

    // the shipped license-table rule that never matched: Office reads ProductKeys then ProductReleaseIds
    var dpM = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-ms-'));
    var mNodes = [{ _id: 'node//m1', meshid: 'mesh//grp1', rname: 'mh1', name: 'MsWin', osdesc: 'Microsoft Windows 11 Pro' }];
    var dbM = { GetAllType: function (t, cb) { cb(null, t === 'node' ? mNodes.slice() : (t === 'mesh' ? meshes.slice() : [])); }, Get: function (id, cb) { cb(null, mNodes.filter(function (n) { return n._id === id; })); } };
    var sentM = [];
    var oM = factory({ parent: { db: dbM, datapath: dpM, debug: function () { }, config: { settings: {} }, webserver: { meshes: { 'mesh//grp1': { name: 'HQ' } }, wsagents: { 'node//m1': { send: function (m) { sentM.push(JSON.parse(m)); } } } }, DispatchEvent: function () { } } });
    oM.loadLicenseTable();   // the shipped license-table.json, exactly like server_startup
    oM.loadRemoteCpeTable();
    var offRules = oM.licenseRulesForApp('Microsoft Office Professional Plus 2019');
    check('v5.6.0 shipped license-table: Office reads ProductKeys and ProductReleaseIds - NOT the ProductIds value that does not exist on a ClickToRun install (measured)',
        offRules != null && offRules.rules.length === 2 && offRules.rules[0].value === 'ProductKeys' && offRules.rules[1].value === 'ProductReleaseIds' &&
        offRules.rules.every(function (r) { return r.value !== 'ProductIds'; }), offRules && offRules.rules.map(function (r) { return r.value; }));
    var offTbl = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'license-table.json'), 'utf8')).entries.filter(function (e) { return e.label === 'Microsoft Office'; })[0];
    check('v5.6.0 shipped license-table: the corrected Office entry cites its evidence (_source), like every curated row must',
        typeof offTbl._source === 'string' && /ProductReleaseIds/.test(offTbl._source) && /ClickToRun/.test(offTbl._source), (offTbl._source || '').length);

    // a dispatched run whose answer carries the real measured shape
    oM.pluginSettings = { inventoryScanner: { licenseCollectionEnabled: true, licenseMsKeys: true } };
    oM.softwareInventory = { m1: { time: new Date().toISOString(), apps: [{ name: 'Microsoft Office Professional Plus 2019', version: '16.0' }, { name: 'Mozilla Firefox 120.0', version: '120.0', publisher: 'Mozilla' }] } };
    oM.handleAdminPostReq({ headers: XHDR, body: { action: 'lic_collect', nodeId: 'node//m1' } }, mockRes(function (d1) {
        check('v5.6.0 lic_collect: dispatches with the corrected Office rule inside the base64 blob', d1.started === true && sentM.length === 1, d1);
        // two levels: wgTransport gzips the whole script, and the script itself carries the rules as base64 JSON
        var script = require('zlib').gunzipSync(Buffer.from(String(sentM[0].cmds).match(/FromBase64String\('([A-Za-z0-9+\/=]+)'\)/)[1], 'base64')).toString('utf8');
        var rulesBlob = JSON.parse(Buffer.from(script.match(/FromBase64String\('([A-Za-z0-9+\/=]+)'\)/)[1], 'base64').toString('utf8'));
        var sentValues = (rulesBlob.apps[0].rules || []).map(function (r) { return r.value; });
        check('v5.6.0 lic_collect: the Office rules travel to the device as ProductKeys + ProductReleaseIds, never as the nonexistent "ProductIds"',
            rulesBlob.ms === true && sentValues.join(',') === 'ProductKeys,ProductReleaseIds', sentValues);
        var answer = '{"collect":true,"items":[{"name":"Microsoft Office Professional Plus 2019","label":"Microsoft Office","source":"registry","license":"","ok":false},{"name":"Microsoft Office Professional Plus 2019","label":"Microsoft Office","source":"registry","license":"Professional2019Retail","ok":true}],"ms":[' +
            '{"name":"Office 19, RETAIL channel","key":"AAAAA","product":"Office 19, Office19HomeBusiness2019R_Grace edition","family":"Office19HomeBusiness2019R_Grace","channel":"Retail","status":"5","grace":"0","evalEnd":"","appId":"0ff1ce15-a989-479d-af46-f275c6370663"},' +
            '{"name":"Office 19, RETAIL channel","key":"BBBBB","product":"Office 19, Office19Professional2019R_OEM_Perp edition","family":"Office19Professional2019R_OEM_Perp","channel":"OEM:NONSLP","status":"1","grace":"0","evalEnd":"","appId":"0ff1ce15-a989-479d-af46-f275c6370663"},' +
            '{"name":"Windows(R) Operating System, OEM_DM channel","key":"CCCCC","product":"Windows(R), Professional edition","family":"Professional","channel":"OEM:DM","status":"1","grace":"0","evalEnd":"","appId":"55c92734-d682-4d71-983e-d6ec3f16059f"}],"error":""}';
        oM.onAgentResponse({ action: 'msg', type: 'runcommands', sessionid: sentM[0].sessionid, result: 'x' + oM.LIC_MARKER + answer + String.fromCharCode(10) }, '', 'node//m1');
        var rec = oM.licenseInventory['m1'];
        var ms = (rec && rec.ms) || [];
        var msAt = function (i) { return ms[i] || {}; };
        var mapM = oM.licenseMapForNode('node//m1')['microsoft office professional plus 2019'] || {};
        check('v5.6.0 lic answer: the first successful read wins, so an EMPTY ProductKeys no longer masks the ProductReleaseIds value',
            mapM.license === 'Professional2019Retail', mapM);
        check('v5.6.0 lic answer: the Microsoft entries keep the license TYPE beside the partial key',
            ms.length === 3 && msAt(0).family === 'Office19HomeBusiness2019R_Grace' && msAt(0).channel === 'Retail' &&
            msAt(1).channel === 'OEM:NONSLP' && msAt(2).channel === 'OEM:DM' && msAt(2).product === 'Windows(R), Professional edition', msAt(0));
        check('v5.6.0 lic answer: the server translates status and channel (the device only reports numbers and raw strings)',
            ms.length === 3 && msAt(0).statusText === 'notification mode (not activated)' && msAt(1).statusText === 'licensed' &&
            msAt(0).channelType === 'Retail' && msAt(1).channelType === 'OEM' && msAt(2).channelType === 'OEM', [msAt(0).statusText, msAt(1).channelType]);
        check('v5.6.0 lic answer: the stored record is persisted with the new fields',
            JSON.parse(fs.readFileSync(path.join(oM.inventoryDataPath, 'm1', 'license.json'), 'utf8')).ms[0].channelType === 'Retail');
        var logTxt = fs.readFileSync(oM.licenseLogPath, 'utf8');
        check('v5.6.0 license log: names the NOT-activated count and still records no key and no value',
            /1 not activated/.test(logTxt) && logTxt.indexOf('AAAAA') < 0 && logTxt.indexOf('Professional2019Retail') < 0 && logTxt.indexOf('Office19HomeBusiness') < 0, logTxt.split('\n').slice(-2));
        oM.handleAdminPostReq({ headers: XHDR, body: { action: 'lic_status' } }, mockRes(function (st) {
            var w = (st.devices || []).filter(function (x) { return x.id === 'node//m1'; })[0] || {};
            var col = w.collected || {};
            check('v5.6.0 lic_status: reports the activation state as COUNTS (2 licensed, 1 not, 0 unknown) and never a value',
                col.ms === 3 && col.msLicensed === 2 && col.msNotLicensed === 1 && col.msUnknown === 0 &&
                JSON.stringify(st).indexOf('AAAAA') < 0 && JSON.stringify(st).indexOf('Office19HomeBusiness') < 0, col);
            next();
        }), user);
    }), user);
});


// ---- v5.6.0: the license type reaches the collection, the CSV, the fleet index and the push WITHOUT any collection run ----
steps.push(function (next) {
    var dpW = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-ltwire-'));
    var wNodes = [{ _id: 'node//w1', meshid: 'mesh//grp1', rname: 'wh1', name: 'WireWin', osdesc: 'Microsoft Windows 11 Pro' }];
    var dbW = {
        GetAllType: function (t, cb) { cb(null, t === 'node' ? wNodes.slice() : (t === 'mesh' ? meshes.slice() : [])); },
        Get: function (id, cb) { if (id === 'sinode//w1') { cb(null, [{ _id: id, doc: { apps: wApps } }]); return; } cb(null, wNodes.filter(function (n) { return n._id === id; })); }
    };
    var wApps = [
        { name: 'Mozilla Firefox 120.0', version: '120.0', publisher: 'Mozilla' },
        { name: 'Microsoft Office Professional Plus 2019', version: '16.0', publisher: 'Microsoft Corporation' },
        { name: '7-Zip 24.09 (x64)', version: '24.09', publisher: 'Igor Pavlov' },
        { name: 'Mystery Tool', version: '9.9', publisher: 'Some OEM' },
        { name: 'Realtek USB Audio', version: '1.0', publisher: 'Realtek' }
    ];
    var sentW = [];
    var oW = factory({ parent: { db: dbW, datapath: dpW, debug: function () { }, config: { settings: {} }, webserver: { meshes: { 'mesh//grp1': { name: 'HQ' } }, wsagents: { 'node//w1': { send: function (m) { sentW.push(JSON.parse(m)); } } } }, DispatchEvent: function () { } } });
    oW.loadRemoteCpeTable();
    oW.scanDeviceSoftware = function (list, cb) {
        cb((list || []).map(function (s) { return { status: 'not assessable', isCve: false, cve: '', severity: '', cvss: '', description: '', software: String(s.name || ''), version: String(s.version || '') }; }));
    };
    oW.scanDeviceOs = function () { return []; };
    oW.osSupportState = function () { return { state: 'supported', label: 'Windows 11 Pro', reason: 'fixture' }; };
    // NO licenseInventory at all: the license TYPE must be known without ever touching a device
    oW.licenseInventory = {};

    var proj = oW.softwareProjection(wApps);
    check('v5.6.0 projection: every row carries the curated license type - SPDX, descriptor, and empty where the table has no statement',
        proj[0].licenseType === 'MPL-2.0' && proj[1].licenseType === 'Proprietary' && proj[2].licenseType === 'LGPL-2.1-only' &&
        proj[3].licenseType === '' && proj[4].licenseType === '', proj.map(function (p) { return p.licenseType; }));
    check('v5.6.0 projection: a driver/firmware kind row is NOT annotated (it is an exclusion marker) and the other fields are unchanged',
        proj[4].name === 'Realtek USB Audio' && proj[0].version === '120.0' && proj[0].publisher === 'Mozilla', proj[4]);

    oW.buildCsvForNodes(wNodes, 'software', function (cerr, csv) {
        var head = (csv || '').split('\r\n')[0];
        check('v5.6.0 software CSV: gains a License Type column, placed with the other license columns',
            head === 'Group,Host Name,Software Name,Software Version,Software Publisher,Software Location,Software Install Date,License Type,License,License Source', head);
        check('v5.6.0 software CSV: the curated types appear although NO license collection ever ran, and the collected License columns stay empty',
            /MPL-2\.0/.test(csv) && /LGPL-2\.1-only/.test(csv) && /Proprietary/.test(csv) &&
            !/FIRE-KEY|AA-BB-CC/.test(csv) && csv.split('\r\n')[1].split(',').slice(-2).join(',') === ',', csv.split('\r\n').slice(1, 3));
        oW.handleAdminPostReq({ headers: XHDR, body: { action: 'sw_fleet' } }, mockRes(function (fx) {
            var byName = {};
            (fx.software || []).forEach(function (s) { byName[s.name] = s; });
            var lt = function (n) { return byName[n] ? byName[n].licenseType : '<missing row>'; };
            check('v5.6.0 sw_fleet: the browser software list carries the same license type as the CSV (one collection, many consumers)',
                lt('Mozilla Firefox 120.0') === 'MPL-2.0' && lt('7-Zip 24.09 (x64)') === 'LGPL-2.1-only' &&
                lt('Microsoft Office Professional Plus 2019') === 'Proprietary' && lt('Mystery Tool') === '',
                (fx.software || []).map(function (s) { return s.name + '=' + s.licenseType; }));
            check('v5.6.0 sw_fleet: hasLicense stays a separate fact - a curated type does NOT pretend a key was collected',
                byName['Mozilla Firefox 120.0'] != null && byName['Mozilla Firefox 120.0'].hasLicense === false && sentW.length === 0,
                byName['Mozilla Firefox 120.0']);
            oW.asCollectDeviceRecord(wNodes[0], function (aerr, rec) {
                var sw = (rec && rec.software) || [];
                check('v5.6.0 asset push: the pushed software rows carry licenseType, so an external asset system gets the type without a device read',
                    !aerr && sw.length === 5 && sw[0].licenseType === 'MPL-2.0' && sw[1].licenseType === 'Proprietary', sw.map(function (s) { return s.licenseType; }));
                check('v5.6.0 asset push: SECURITY - the record carries the curated TYPE only, never a collected license value, and no agent command is sent',
                    sw.every(function (s) { return !Object.prototype.hasOwnProperty.call(s, 'license'); }) &&
                    JSON.stringify(sw).indexOf('"license"') < 0 && sentW.length === 0, sw[0]);
                next();
            });
        }), user);
    });
});

// The runner MUST stay the last statement: every steps.push() above has to be registered before
// step 0 starts (pre-3.0.1 it sat mid-file and the trailing steps only ran because an earlier
// step happened to be asynchronous). New steps go ABOVE this block.
console.log('registered steps: ' + steps.length);
var stepsDone = 0;
// A step whose callback never fires used to end the process silently with exit 0 (every later
// step skipped, CI green). The exit guard turns that into a failure (audit 3, v4.3.0).
process.on('exit', function (code) {
    if (code === 0 && stepsDone !== steps.length) {
        console.log('FAIL runner: only ' + stepsDone + ' of ' + steps.length + ' steps completed (a step never called next())');
        process.exitCode = 1;
    }
});
(function run(i) {
    if (i >= steps.length) {
        stepsDone = steps.length;
        console.log(failures === 0 ? '\ntest-plugin: ALL PASSED' : '\ntest-plugin: ' + failures + ' FAILURE(S)');
        process.exit(failures === 0 ? 0 : 1);
    }
    var once = false;
    // Per-step watchdog: a step that never calls next() either ends the process silently
    // (empty event loop) or hangs on open timers until the CI job timeout - both are failures.
    var guard = setTimeout(function () {
        console.log('FAIL runner: step ' + i + ' did not call next() within 120 s');
        process.exit(1);
    }, 120000);
    steps[i](function () {
        if (once) { failures++; console.log('FAIL step ' + i + ' called next() twice'); return; }
        once = true; clearTimeout(guard); stepsDone = i + 1; run(i + 1);
    });
})(0);
