/**
 * View render tests: compile all three Handlebars views and render them with
 * representative data AND with empty data (must not throw). Requires the
 * devDependency handlebars (run `npm install` once, or `npm test`).
 */
'use strict';

const fs = require('fs');
const path = require('path');

let Handlebars;
try {
    Handlebars = require('handlebars');
} catch (e) {
    console.log('SKIP test-views: handlebars not installed. Run `npm install` first (or `npm test`).');
    process.exit(0);
}

const viewsDir = path.join(__dirname, '..', 'views');

const loc = {
    id: 'mesh//grp1', name: 'HQ & Co <b>',
    totalSystems: 2, totalPrograms: 10, assessablePrograms: 3, notAssessablePrograms: 5, outOfScopePrograms: 2, coverageBase: 8, coveragePercent: 38,
    totalCves: 3, falsePositiveCves: 1,
    severityCounts: { CRITICAL: 1, HIGH: 1, MEDIUM: 1, LOW: 0, UNKNOWN: 0 },
    uniqueCves: 3,
    findings: [
        { cve: 'CVE-2024-1234', severity: 'CRITICAL', cvss: 9.8, software: 'Mozilla Firefox', version: '122.0',
            description: 'd', assessment: 'HIGH', comment: 'mitigated & <i>approved</i>', flagged: false,
            effectiveSeverity: 'HIGH', devices: ['host1', 'host2'] },
        { cve: 'WINDOWS-UPDATES', severity: 'CRITICAL', cvss: 10, software: 'Windows Updates', version: '2 pending',
            description: 'd2', assessment: 'UNKNOWN', comment: '', flagged: true, effectiveSeverity: 'false positive',
            devices: ['host1'] }
    ],
    devices: [
        { hostName: 'host1', name: 'Given1', group: 'HQ', os: 'Win 11', programs: 5, cveCount: 2, critical: 1, high: 1, medium: 0, low: 0, unknown: 0 },
        { hostName: 'host2', name: 'Given2', group: 'HQ', os: 'Ubuntu', programs: 5, cveCount: 1, critical: 0, high: 0, medium: 1, low: 0, unknown: 0 }
    ]
};
const data = {
    shortName: 'inventoryscanner',
    meshList: [{ id: 'mesh//grp1', name: 'HQ & Co <b>' }, { id: 'mesh//grp2', name: 'Branch' }],
    lastUpdate: '2026-09-20T00:00:00Z', lastScan: '2026-09-25T02:00:00Z', scanIntervalHours: 720,
    totalCves: 61268,
    report: {
        generated: '2026-09-25T00:00:00Z', totalSystems: 2, totalPrograms: 10, assessablePrograms: 3,
        notAssessablePrograms: 5, outOfScopePrograms: 2, coverageBase: 8, coveragePercent: 38, totalCves: 3, falsePositiveCves: 1,
        severityCounts: { CRITICAL: 1, HIGH: 1, MEDIUM: 1, LOW: 0, UNKNOWN: 0 }, uniqueCves: 3,
        locationCount: 1, locations: [loc], devices: loc.devices
    }
};
const empty = {
    shortName: 'inventoryscanner', meshList: [], lastUpdate: '', lastScan: '', scanIntervalHours: 0, totalCves: 0, version: '9.9.9',
    report: { generated: 'x', totalSystems: 0, totalPrograms: 0, assessablePrograms: 0, notAssessablePrograms: 0, outOfScopePrograms: 0, coverageBase: 0,
        coveragePercent: 0, totalCves: 0, falsePositiveCves: 0,
        severityCounts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 }, uniqueCves: 0,
        locationCount: 0, locations: [], devices: [] }
};

let failed = 0;
const outDir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'invscanner-render-'));
for (const name of ['assessment', 'report', 'deviceReport']) {
    const src = fs.readFileSync(path.join(viewsDir, name + '.handlebars'), 'utf8');
    for (const [label, d] of [['data', data], ['empty', empty]]) {
        try {
            const out = Handlebars.compile(src)(d);
            fs.writeFileSync(path.join(outDir, name + '-' + label + '.html'), out, 'utf8');
            console.log('PASS ' + name + ' (' + label + ') renders (' + out.length + ' chars)');
        } catch (e) {
            failed++;
            console.log('FAIL ' + name + ' (' + label + '): ' + e.message);
        }
    }
}
// spot check: HTML escaping of hostile names, host names present, given names absent in device report
try {
    const rep = fs.readFileSync(path.join(outDir, 'report-data.html'), 'utf8');
    console.log((rep.indexOf('HQ &amp; Co &lt;b&gt;') >= 0 ? 'PASS ' : (failed++, 'FAIL ')) + 'report escapes location names');
    console.log((rep.indexOf('mitigated &amp; &lt;i&gt;approved&lt;/i&gt;') >= 0 ? 'PASS ' : (failed++, 'FAIL ')) + 'report escapes comments');
    const dev = fs.readFileSync(path.join(outDir, 'deviceReport-data.html'), 'utf8');
    console.log(((dev.indexOf('host1') >= 0 && dev.indexOf('Given1') < 0) ? 'PASS ' : (failed++, 'FAIL ')) + 'device report shows host names, not given names');
} catch (e) { failed++; console.log('FAIL spot checks: ' + e.message); }

console.log(failed === 0 ? '\ntest-views: ALL PASSED' : '\ntest-views: ' + failed + ' FAILURE(S)');
process.exit(failed === 0 ? 0 : 1);
