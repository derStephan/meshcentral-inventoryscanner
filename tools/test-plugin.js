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

const factory = require(path.join(__dirname, '..', 'inventoryscanner', 'inventoryscanner.js')).inventoryscanner;

// ---------- fixtures ----------
const nodes = [
    { _id: 'node//d1', meshid: 'mesh//grp1', rname: 'host1', name: 'Given1', osdesc: 'Windows 10' },
    { _id: 'node//d2', meshid: 'mesh//grp1', rname: 'host2', name: 'Given2', osdesc: 'Ubuntu 22.04' },
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
    return {
        type: function () { return this; },
        json: function (d) { done(d); },
        sendStatus: function (c) { done({ _status: c }); },
        render: function (v, d) { done({ _view: v, _data: d }); },
        setHeader: function (k, v) { if (!this._headers) { this._headers = {}; } this._headers[k] = v; },
        send: function (body) { done({ _body: body, _headers: this._headers }); }
    };
}
const user = { name: 'admin', _id: 'user//u1', siteadmin: 0xFFFFFFFF };

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
    obj.handleAdminPostReq({ body: { action: 'save_assessment', meshIds: 'mesh//grp1,mesh//grp2', cveId: 'CVE-2024-0003', assessment: 'high', comment: 'patch tuesday' } },
        mockRes(function (d) {
            check('route save_assessment: stores for all meshIds', d.success === true && obj.assessments['mesh//grp1:CVE-2024-0003'].assessment === 'HIGH' && obj.assessments['mesh//grp2:CVE-2024-0003'].assessment === 'HIGH', d);
            next();
        }), user);
});

steps.push(function (next) {
    obj.handleAdminPostReq({ body: { action: 'flag_false_positive', meshIds: 'mesh//grp1', cveId: 'CVE-2024-0001' } },
        mockRes(function (d) {
            check('route flag: succeeds with NO comment', d.success === true && obj.assessments['mesh//grp1:CVE-2024-0001'].comment === '' && obj.assessments['mesh//grp1:CVE-2024-0001'].flagged === true, d);
            obj.handleAdminPostReq({ body: { action: 'save_assessment', meshId: 'mesh//grp1', cveId: 'CVE-2024-0002', assessment: 'LOW', comment: '   ' } },
                mockRes(function (d2) {
                    check('route save: empty comment still rejected', !!d2.error, d2);
                    next();
                }), user);
        }), user);
});

steps.push(function (next) {
    obj.handleAdminPostReq({ body: { action: 'unflag_false_positive', meshIds: 'mesh//grp1,mesh//grp2', cveId: 'CVE-2024-0001' } },
        mockRes(function (d) {
            check('route unflag: removes flags for all meshes', d.success === true && obj.assessments['mesh//grp2:CVE-2024-0001'] === undefined, d);
            obj.handleAdminPostReq({ body: { action: 'flag_false_positive', meshIds: 'mesh//grp1:evil', cveId: 'CVE-2024-0002' } },
                mockRes(function (d2) {
                    check('validation: colon-bearing meshId rejected (key poisoning)', !!d2.error, d2);
                    obj.handleAdminPostReq({ body: { action: 'save_assessment', meshId: 'mesh//grp1', cveId: 'DROP TABLE', assessment: 'LOW', comment: 'x' } },
                        mockRes(function (d3) {
                            check('validation: bogus cveId rejected', !!d3.error, d3);
                            obj.handleAdminPostReq({ body: { action: 'flag_false_positive', meshId: 'mesh//grp1', cveId: 'WINDOWS-UPDATES' } },
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
    obj.handleAdminPostReq({ body: { action: 'save_assessment', meshId: 'mesh//grp1', cveId: 'CVE-2024-0001', assessment: 'LOW', comment: 'ok' } },
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
    obj.handleAdminPostReq({ body: { action: 'get_cpe_table' } }, mockRes(function (d) {
        const builtin = d.entries.filter(e => e.source === 'built-in');
        check('get_cpe_table: built-in rows visible', builtin.length > 20, builtin.length);
        check('get_cpe_table: custom rows visible', d.entries.some(e => e.source === 'custom' && e.match === '^my tool'));
        obj.handleAdminPostReq({ body: { action: 'delete_cpe_table', match: '^my tool', vendor: 'acme', product: 'tool' } },
            mockRes(function (d2) {
                check('delete_cpe_table removes custom entry', d2.success === true && obj.customCpeEntries.length === 0, d2);
                obj.handleAdminPostReq({ body: { action: 'delete_cpe_table', match: '/mozilla firefox/i', vendor: 'mozilla', product: 'firefox' } },
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
        next();
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
    obj.handleAdminPostReq({ body: { action: 'save_settings', scanIntervalHours: '720', updateHours: '168', anyCveMaxAgeYears: '5',
            collectIntervalMinutes: '1440', notifyThreshold: 'HIGH', notifyOnScan: 'true', notifyUnratedRepeat: 'true',
            collectOnAgentConnect: 'true', scanMeshes: 'mesh//grp1', notifyMeshIds: 'mesh//grp2', notifySeverities: 'CRITICAL' } },
        mockRes(function (d) {
            check('save_settings: returns effective settings', d.settings && d.settings.scanIntervalHours === 720 && d.settings.notify['mesh//grp2'] === 'CRITICAL' && d.settings.notifyUnratedRepeat === true, d.settings);
            check('save_settings: persisted to file', fs.existsSync(obj.pluginSettingsPath));
            check('save_settings: bumped timer generation + rescheduled', obj.timerGen === 1 && captured.length >= 1, [obj.timerGen, captured.length]);
            obj.handleAdminPostReq({ body: { action: 'get_settings' } }, mockRes(function (dg) {
                check('get_settings: source marking file vs config.json', dg.sources.scanIntervalHours === 'file' && dg.sources.notifyThreshold === 'file' && dg.sources.scanMeshes === 'file', dg.sources);
                obj.handleAdminPostReq({ body: { action: 'revert_setting', revertScanIntervalHours: 'true' } }, mockRes(function (d2) {
                    check('revert_setting: falls back to config.json value', d2.settings.scanIntervalHours === 24 && d2.sources.scanIntervalHours === 'config.json', d2.settings && d2.settings.scanIntervalHours);
                    obj.handleAdminPostReq({ body: { action: 'save_settings', scanIntervalHours: 'abc' } }, mockRes(function (d3) {
                        check('save_settings: rejects non-numeric interval', !!d3.error, d3);
                        obj.handleAdminPostReq({ body: { action: 'save_settings', scanIntervalHours: '24', updateHours: '168', anyCveMaxAgeYears: '5', collectIntervalMinutes: '60', notifyThreshold: 'NOPE' } },
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
    var fakeParent = { send: function (m) { sent.push(m); } };
    obj.uiCustomEvent({ section: "devicesbarbuttons", element: "0", logmsg: "assessment", selectedDevices: [] }, fakeParent);
    check("uievent: assessment button with NO selection opens the panel", sent.length === 1 && sent[0].method === "openAssessment", sent);
    sent = [];
    obj.uiCustomEvent({ section: "devicesbarbuttons", element: "0", logmsg: "vulns", selectedDevices: [] }, fakeParent);
    check("uievent: CSV export still needs a selection", sent.length === 0, sent);
    next();
});

(function run(i) {
    if (i >= steps.length) {
        console.log(failures === 0 ? '\ntest-plugin: ALL PASSED' : '\ntest-plugin: ' + failures + ' FAILURE(S)');
        process.exit(failures === 0 ? 0 : 1);
    }
    steps[i](function () { run(i + 1); });
})(0);
