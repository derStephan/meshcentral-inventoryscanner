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
    obj.handleAdminReq({ query: { action: 'scan', mesh: 'mesh//grp1,mesh//grp2' } }, mockRes(function (d) {
        check('route scan: multi-mesh json contract', Array.isArray(d.cves) && Array.isArray(d.meshes) && typeof d.flaggedCount === 'number' && typeof d.lastUpdate === 'string', Object.keys(d || {}));
        obj.handleAdminReq({ query: { action: 'report' } }, mockRes(function (d2) {
            check('route report: renders report with locations', d2._view === 'report' && Array.isArray(d2._data.report.locations));
            obj.handleAdminReq({ query: { action: 'deviceReport' } }, mockRes(function (d3) {
                check('route deviceReport: renders deviceReport', d3._view === 'deviceReport');
                obj.handleAdminReq({ query: { action: 'show' } }, mockRes(function (d4) {
                    check('route show: renders assessment, deleted meshes hidden', d4._view === 'assessment' && d4._data.meshList.length === 2, d4._data.meshList);
                    obj.handleAdminReq({ query: { action: 'bogus' } }, mockRes(function (d5) {
                        check('route unknown GET action -> 404', d5._status === 404, d5);
                        next();
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
    obj.handleAdminPostReq({ headers: XHDR, body: { action: 'get_cpe_table' } }, mockRes(function (d) {
        const builtin = d.entries.filter(e => e.source === 'built-in');
        check('get_cpe_table: built-in rows visible', builtin.length > 20, builtin.length);
        check('get_cpe_table: custom rows visible', d.entries.some(e => e.source === 'custom' && e.match === '^my tool'));
        obj.handleAdminPostReq({ headers: XHDR, body: { action: 'delete_cpe_table', match: '^my tool', vendor: 'acme', product: 'tool' } },
            mockRes(function (d2) {
                check('delete_cpe_table removes custom entry', d2.success === true && obj.customCpeEntries.length === 0, d2);
                obj.handleAdminPostReq({ headers: XHDR, body: { action: 'delete_cpe_table', match: '/mozilla firefox/i', vendor: 'mozilla', product: 'firefox' } },
                    mockRes(function (d3) {
                        check('built-in cannot be deleted via API', !!d3.error, d3);
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
    var now = Date.now();
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
        /wgBatchDry === true \? obj\.WINGET_DRY_TIMEOUT_MS/.test(fs.readFileSync(require('path').join(__dirname, '..', 'inventoryscanner.js'), 'utf8')));
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
    check('transcript: answer is emitted BEFORE the transcript stops', sc.indexOf('@@INVWUP@@') < sc.indexOf('Stop-Transcript') || sc.indexOf(obj.WINGET_MARKER) < sc.indexOf('Stop-Transcript'), sc.indexOf(obj.WINGET_MARKER) + ':' + sc.indexOf('Stop-Transcript'));
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
    var out = null;
    try { out = cp.execFileSync('powershell', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', path.join(dir, 't.ps1')], { env: Object.assign({}, process.env, { INV_T: path.join(dir, 't.txt') }), encoding: 'utf8', timeout: 60000 }); } catch (e) { out = null; }
    if (out == null) { console.log('SKIP script: winget table parser (PowerShell not available)'); next(); return; }
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
    check('table: built-in seed agrees with the shipped table for the corrected rows',
        obj.SOFTWARE_CPE_TABLE.filter(function (e) { return e.match.test('Notepad++'); })[0].product === 'notepad\\+\\+' &&
        obj.SOFTWARE_CPE_TABLE.filter(function (e) { return e.match.test('SumatraPDF'); })[0].vendor === 'sumatrapdfreader');
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

// The runner MUST stay the last statement: every steps.push() above has to be registered before
// step 0 starts (pre-3.0.1 it sat mid-file and the trailing steps only ran because an earlier
// step happened to be asynchronous).
steps.push(function (next) {
    // realistic upgrade (v3.0.1): installer unpacks new files, then re-requires the CACHED module and
    // calls server_startup on a NEW instance of the OLD code - that instance must notice it and reload.
    var base = fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-upg-'));
    var pd = path.join(base, 'plugins', 'inventoryscanner');
    fs.mkdirSync(pd, { recursive: true });
    var srcDir = path.join(__dirname, '..');
    ['inventoryscanner.js', 'cpe-table.json'].forEach(function (f) { fs.copyFileSync(path.join(srcDir, f), path.join(pd, f)); });
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
    ph.plugins.inventoryscanner.timerGen++;
    next();
});

console.log('registered steps: ' + steps.length);
(function run(i) {
    if (i >= steps.length) {
        console.log(failures === 0 ? '\ntest-plugin: ALL PASSED' : '\ntest-plugin: ' + failures + ' FAILURE(S)');
        process.exit(failures === 0 ? 0 : 1);
    }
    var once = false;
    steps[i](function () {
        if (once) { failures++; console.log('FAIL step ' + i + ' called next() twice'); return; }
        once = true; run(i + 1);
    });
})(0);
