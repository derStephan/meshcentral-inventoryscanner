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
    // In CI (GITHUB_ACTIONS / CI set, `npm ci` ran) a missing handlebars is a broken setup and
    // must FAIL - a silent exit 0 would report the view tests as passed (audit 3).
    if (process.env.CI) { console.log('FAIL test-views: handlebars is not installed in CI'); process.exit(1); }
    console.log('SKIP test-views: handlebars not installed. Run `npm ci` first (or `npm test`).');
    process.exit(0);
}

const viewsDir = path.join(__dirname, '..', 'views');

// Register the partials exactly the way express-handlebars@8 does for a MeshCentral plugin:
// pluginHandler sets app.set('views', <plugin>/views) per request, the engine is created without a
// partialsDir, so it derives `<plugin>/views/partials/` per render and globs `**/*.handlebars` with
// posix paths - the partial name is the relative path minus the extension (sub-folders = namespaces).
const partialsDir = path.join(viewsDir, 'partials');
const registeredPartials = [];
(function registerPartials(dir, prefix) {
    if (!fs.existsSync(dir)) { return; }
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        if (e.isDirectory()) { registerPartials(path.join(dir, e.name), prefix + e.name + '/'); }
        else if (e.name.endsWith('.handlebars')) {
            const name = prefix + e.name.slice(0, -'.handlebars'.length);
            Handlebars.registerPartial(name, fs.readFileSync(path.join(dir, e.name), 'utf8'));
            registeredPartials.push(name);
        }
    }
})(partialsDir, '');
console.log('registered ' + registeredPartials.length + ' partial(s): ' + (registeredPartials.join(', ') || '(none)'));

const loc = {
    id: 'mesh//grp1', name: 'HQ & Co <b>',
    totalSystems: 2, totalPrograms: 10, assessablePrograms: 3, notAssessablePrograms: 5, outOfScopePrograms: 2, coverageBase: 8, coveragePercent: 38,
    distroManagedPrograms: 7, distroEolPrograms: 4, distroUnknownPrograms: 1,
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
        { hostName: 'host1', name: 'Given1', group: 'HQ', os: 'Win 11', osSupport: 'supported', programs: 5, cveCount: 2, critical: 1, high: 1, medium: 0, low: 0, unknown: 0 },
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
        distroManagedPrograms: 7, distroEolPrograms: 4, distroUnknownPrograms: 1,
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
    console.log((rep.indexOf('7 <em>Linux distribution packages</em>') >= 0 && rep.indexOf('4 distribution packages run on an end-of-life OS release') >= 0 && rep.indexOf('Distribution packages:</b> 7') >= 0 ? 'PASS ' : (failed++, 'FAIL ')) + 'report states distro-managed and end-of-life package counts');
    const dev = fs.readFileSync(path.join(outDir, 'deviceReport-data.html'), 'utf8');
    console.log((dev.indexOf('<td>supported</td>') >= 0 ? 'PASS ' : (failed++, 'FAIL ')) + 'device report shows the OS support state');
    console.log(((dev.indexOf('host1') >= 0 && dev.indexOf('Given1') < 0) ? 'PASS ' : (failed++, 'FAIL ')) + 'device report shows host names, not given names');
} catch (e) { failed++; console.log('FAIL spot checks: ' + e.message); }

// v4.9.0 issue #8: two-layer navigation (main sections + sub tabs), old flat nav gone, no moved-control id duplicates
try {
    const a = fs.readFileSync(path.join(outDir, 'assessment-data.html'), 'utf8');
    // the panel must resolve a partial from views/partials/ - the mechanism the view modularisation needs
    console.log(((a.indexOf('inv-partial-probe') >= 0) ? 'PASS ' : (failed++, 'FAIL ')) + 'partials: the panel resolves {{> probe }} from views/partials/');
    console.log(((registeredPartials.length > 0) ? 'PASS ' : (failed++, 'FAIL ')) + 'partials: at least one partial file is registered for the render');
    const count = (s, re) => (s.match(re) || []).length;
    console.log((/class="maintab[^"]*" data-main="devices"/.test(a) && /data-main="software"/.test(a) && /data-main="vulns"/.test(a) && /data-main="settings"/.test(a) ? 'PASS ' : (failed++, 'FAIL ')) + 'nav: four main sections present');
    console.log(((a.indexOf('id="subnav"') >= 0 && a.indexOf('id="mainnav"') >= 0) ? 'PASS ' : (failed++, 'FAIL ')) + 'nav: sub-nav container present');
    console.log((a.indexOf('data-tab=') < 0 && a.indexOf('class="navtab') < 0 ? 'PASS ' : (failed++, 'FAIL ')) + 'nav: old flat navtab markup removed');
    console.log(((count(a, /id="tab-cpe"/g) === 1 && count(a, /id="tab-nvd"/g) === 1 && count(a, /id="tab-license"/g) === 1) ? 'PASS ' : (failed++, 'FAIL ')) + 'nav: CPE table, NVD database and license panels exist once each (issue #9 split the old "data" panel)');
    console.log(((a.indexOf('data-main="vulns" data-sub="cpe"') >= 0 && a.indexOf('data-main="vulns" data-sub="nvd"') >= 0 && a.indexOf('data-main="software" data-sub="license"') >= 0) ? 'PASS ' : (failed++, 'FAIL ')) + 'nav: every panel carries its main+sub tags');
    // v5.4.1: documents are ONE-CLICK links in the sub-nav row (no panel holding a link button any more)
    console.log(((a.indexOf('href="#exports"') >= 0 && a.indexOf("href: base + '&action=deviceReport'") >= 0 && a.indexOf("href: base + '&action=report'") >= 0 && a.indexOf("href: base + '&action=export&type=hardware'") >= 0 && a.indexOf("href: base + '&action=export&type=vulns'") >= 0) ? 'PASS ' : (failed++, 'FAIL ')) + 'v5.4.1: reports and CSV exports are direct one-click links of the navigation');
    console.log(((a.indexOf('class="subtab ext"') >= 0 || a.indexOf("'subtab ext'") >= 0) ? 'PASS ' : (failed++, 'FAIL ')) + 'v5.4.1: external nav links render in their own (marked) sub-tab style');
    console.log(((a.indexOf("'nav.devreport'") >= 0 && a.indexOf("'nav.vulnreport'") >= 0 && a.indexOf("'nav.exphw'") >= 0 && a.indexOf("'nav.expsw'") >= 0 && a.indexOf("'nav.expvulns'") >= 0) ? 'PASS ' : (failed++, 'FAIL ')) + 'v5.4.1: the explanation of the removed link panels lives in the nav hover help');
    console.log((count(a, /id="setUpdateHours"/g) === 1 ? 'PASS ' : (failed++, 'FAIL ')) + 'nav: moved NVD-refresh field appears exactly once (no id collision)');
    console.log((count(a, /id="setCpeTableEnabled"/g) === 1 && count(a, /id="setLicCollect"/g) === 1 ? 'PASS ' : (failed++, 'FAIL ')) + 'nav: moved CPE/license config fields appear once each');
    console.log(((a.indexOf('doSaveSettings') >= 0 && a.indexOf('saveSettingsBtn2') >= 0 && a.indexOf('saveSettingsBtn3') >= 0) ? 'PASS ' : (failed++, 'FAIL ')) + 'nav: relocated settings keep one shared save path');
    // v4.9.5: the two unified views (issue #8 second half) - new panels + loaders, built from existing routes.
    console.log(((a.indexOf('id="tab-devicelist"') >= 0 && a.indexOf('data-main="devices" data-sub="devicelist"') >= 0) ? 'PASS ' : (failed++, 'FAIL ')) + 'v4.9.5: unified device panel present under Devices');
    console.log(((a.indexOf('id="tab-swlist"') >= 0 && a.indexOf('data-main="software" data-sub="softwarelist"') >= 0) ? 'PASS ' : (failed++, 'FAIL ')) + 'v4.9.5: unified software panel present under Software');
    console.log(((a.indexOf("key: 'devicelist'") >= 0 && a.indexOf("key: 'softwarelist'") >= 0) ? 'PASS ' : (failed++, 'FAIL ')) + 'v4.9.5: the two new sub-tabs are in the nav tree');
    console.log(((a.indexOf('function loadDeviceList') >= 0 && a.indexOf('function loadSwFleet') >= 0) ? 'PASS ' : (failed++, 'FAIL ')) + 'v4.9.5: both views have loaders');
    console.log(((a.indexOf("post('sw_fleet'") >= 0 && a.indexOf("post('os_status'") >= 0) ? 'PASS ' : (failed++, 'FAIL ')) + 'v4.9.5: views reuse existing routes (no invented endpoint)');
    // v4.9.6: the CPE + License help text that the v4.9.0 move had dropped must be back (guards the regression).
    console.log(((a.indexOf('Fix a wrong row') >= 0 && a.indexOf('dictionary that tells the scanner') >= 0) ? 'PASS ' : (failed++, 'FAIL ')) + 'v4.9.6: CPE mapping help text present again');
    console.log(((a.indexOf('For asset management the software-inventory CSV') >= 0 && a.indexOf('SoftwareLicensingProduct') >= 0 && a.indexOf('no key is ever written to a log') >= 0) ? 'PASS ' : (failed++, 'FAIL ')) + 'v4.9.6: License keys help text present again');
    // v5.2.0: the optional license collection schedule must be visible + honestly described in the panel
    console.log(((a.indexOf('id="setLicInterval"') >= 0 && a.indexOf('id="setLicIntervalSrc"') >= 0) ? 'PASS ' : (failed++, 'FAIL ')) + 'v5.2.0: the license collection interval is configurable in the panel (with source/revert)');
    const an = a.replace(/\s+/g, ' ');   // phrase checks must survive the source line wrapping
    console.log(((an.indexOf('0 = off (on demand only, the default)') >= 0 && an.indexOf('never reboots it') >= 0 && an.indexOf('keys stay on this server') >= 0 && an.indexOf('read-only collection on every ONLINE Windows device') >= 0) ? 'PASS ' : (failed++, 'FAIL ')) + 'v5.2.0: the schedule is described as opt-in, read-only and server-local');
    // v5.0.0 issue #5: the optional external asset-management connector (Settings > Asset management)
    console.log(((a.indexOf('id="tab-asset"') >= 0 && a.indexOf('data-main="settings" data-sub="asset"') >= 0) ? 'PASS ' : (failed++, 'FAIL ')) + 'v5.0.0: asset-management panel lives under Settings');
    console.log(((a.indexOf("key: 'asset'") >= 0 && a.indexOf('function loadAssetSection') >= 0) ? 'PASS ' : (failed++, 'FAIL ')) + 'v5.0.0: asset sub-tab + loader present');
    console.log(((a.indexOf('only place where this plugin sends data OFF the server') >= 0 && a.indexOf('disabled by default') >= 0) ? 'PASS ' : (failed++, 'FAIL ')) + 'v5.0.0: the off-server transfer is disclosed prominently in the panel');
    console.log(((a.indexOf("post('as_get_config'") >= 0 && a.indexOf("post('as_save_config'") >= 0 && a.indexOf("post('as_push'") >= 0 && a.indexOf("post('as_test'") >= 0) ? 'PASS ' : (failed++, 'FAIL ')) + 'v5.0.0: the panel uses the as_* routes');
    console.log(((a.indexOf('asToken') >= 0 && a.indexOf('type="password"') >= 0 && a.indexOf('clear the stored token') >= 0) ? 'PASS ' : (failed++, 'FAIL ')) + 'v5.0.0: credentials are password fields with an explicit clear, never prefilled');
    console.log((a.indexOf('asPush(null)') >= 0 && a.indexOf('This leaves the server') >= 0 ? 'PASS ' : (failed++, 'FAIL ')) + 'v5.0.0: pushing asks for explicit consent every time');

    // v5.3.0: the frozen panel inventory. Every static id, help text, report/export link and nav panel that
    // existed when the fixture was generated must still be reachable - a restructure cannot silently drop a
    // control or a help block (the v4.9.6 lesson: id-less prose went missing and no test noticed). Removing
    // something ON PURPOSE means updating tools/fixtures/panel-inventory.json in the same commit, which makes
    // the loss visible in review instead of silent at runtime.
    const inv = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'panel-inventory.json'), 'utf8'));
    // same normalisation the fixture was built with: tags replaced by a space, whitespace collapsed
    const norm = a.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');
    const missIds = inv.ids.filter((x) => a.indexOf('id="' + x + '"') < 0);
    console.log((missIds.length === 0 ? 'PASS ' : (failed++, 'FAIL ')) + 'inventory: all ' + inv.ids.length + ' static element ids are still present'
        + (missIds.length ? ' -> MISSING: ' + missIds.join(', ') : ''));
    const missProse = inv.prose.filter((p) => {
        const t = norm.indexOf(p.head);
        return t < 0;
    });
    console.log((missProse.length === 0 ? 'PASS ' : (failed++, 'FAIL ')) + 'inventory: all ' + inv.prose.length + ' info/hint help texts are still present'
        + (missProse.length ? ' -> MISSING: ' + missProse.map((p) => p.head.substring(0, 50)).join(' | ') : ''));
    const missLinks = inv.links.filter((l) => a.indexOf(l.replace('&', '&amp;')) < 0 && a.indexOf(l) < 0);
    console.log((missLinks.length === 0 ? 'PASS ' : (failed++, 'FAIL ')) + 'inventory: all ' + inv.links.length + ' report/export links are still present'
        + (missLinks.length ? ' -> MISSING: ' + missLinks.join(', ') : ''));
    const missPanels = inv.panels.filter((p) => {
        const mm = p.split('/');
        return a.indexOf('data-main="' + mm[0] + '" data-sub="' + mm[1] + '"') < 0;
    });
    console.log((missPanels.length === 0 ? 'PASS ' : (failed++, 'FAIL ')) + 'inventory: all ' + inv.panels.length + ' navigation panels are still present'
        + (missPanels.length ? ' -> MISSING: ' + missPanels.join(', ') : ''));

    // issue #9 phase 1: deep links, the sorting fix, the inline location row and the hover help box
    console.log(((a.indexOf('href="#exports"') >= 0 && a.indexOf('#devices/devicelist') >= 0 && a.indexOf('#vulns/assessment') >= 0 && a.indexOf('#settings/general') >= 0) ? 'PASS ' : (failed++, 'FAIL ')) + '#9: five main sections incl. Exports, and the nav anchors carry real deep-link hashes');
    console.log(((a.indexOf('function applyHash') >= 0 && a.indexOf("addEventListener('hashchange'") >= 0 && a.indexOf('navLock') >= 0) ? 'PASS ' : (failed++, 'FAIL ')) + '#9: the URL hash drives the view (copy/paste a link and the back button work)');
    console.log(((a.indexOf("sortKey: 'severity'") >= 0 && a.indexOf("sortKey: 'cvss'") < 0) ? 'PASS ' : (failed++, 'FAIL ')) + '#9: the findings table sorts by EFFECTIVE severity by default, not by the raw CVSS (a manual rating re-orders it)');
    console.log(((a.indexOf('key !== \'cvss\'') >= 0 && a.indexOf('return cb2 - ca;') >= 0) ? 'PASS ' : (failed++, 'FAIL ')) + '#9: inside one severity the higher CVSS wins (tiebreaker), then the CVE id for a stable order');
    console.log(((a.indexOf('class="locbar"') >= 0 && a.indexOf('location-toggle') < 0 && a.indexOf('locClose') < 0) ? 'PASS ' : (failed++, 'FAIL ')) + '#9: the location selection is an inline row above the table - the floating panel and its toggle are gone');
    console.log(((a.indexOf('id="locList"') >= 0 && a.indexOf('id="locApply"') >= 0 && a.indexOf('invscanner_locations') >= 0) ? 'PASS ' : (failed++, 'FAIL ')) + '#9: the inline location row keeps its ids and the localStorage persistence');
    console.log(((a.indexOf('id="helpBox"') >= 0 && a.indexOf('function bindHelpBox') >= 0 && a.indexOf('data-help=') >= 0) ? 'PASS ' : (failed++, 'FAIL ')) + '#9: the hover help box exists and buttons carry data-help');
    console.log(((a.indexOf("'scan.review'") >= 0 && a.indexOf("'dl.reboot'") >= 0 && a.indexOf("'swf.uninstall'") >= 0 && a.indexOf("'as.pushall'") >= 0) ? 'PASS ' : (failed++, 'FAIL ')) + '#9: the help registry covers the actions of every area');
    // v5.4.1: the reported UX defects are pinned so they cannot come back
    console.log(((a.indexOf('dlApp.details') >= 0 && a.indexOf('swfApp.details') >= 0 && a.indexOf('dlLoadDetails(id, true)') >= 0) ? 'PASS ' : (failed++, 'FAIL ')) + 'v5.4.1: device and software details are cached - a re-render or poll does not refetch them (the reported request loop)');
    console.log(((a.indexOf('button.rowbtn') >= 0 && a.indexOf('.cellacts') >= 0 && count(a, /class="rowbtn/g) >= 0) ? 'PASS ' : (failed++, 'FAIL ')) + 'v5.4.1: row buttons share one calm style (rowbtn) and wrap inside .cellacts instead of forcing a horizontal scroll');
    console.log(((a.indexOf('global threshold') >= 0 && a.indexOf('What the notify threshold does') >= 0) ? 'PASS ' : (failed++, 'FAIL ')) + 'v5.4.1: the per-group notify threshold is explained and the Source column is never blank');
    console.log(((a.indexOf("'selectSub'") >= 0 || a.indexOf('function selectSub') >= 0) && a.indexOf('function selectLinksMain') >= 0 ? 'PASS ' : (failed++, 'FAIL ')) + 'v5.4.1: a link-only main section (Exports) renders its links without stealing the active panel');
    // v5.4.2: the two reported defects - details must reach their row, and hidden panels must not poll
    console.log(((a.indexOf('function rowOf') >= 0 && a.indexOf('function swfKey') >= 0 && a.indexOf("swfd-' + swfKey(low)") >= 0 && a.indexOf("swfd-' + i + '") < 0) ? 'PASS ' : (failed++, 'FAIL ')) + 'v5.4.2: software detail cells are keyed by NAME (not by row index) and rows are found by climbing to the <tr>');
    console.log(((a.indexOf('rowOf(b)') >= 0 && count(a, /rowOf\(b\)/g) >= 2) ? 'PASS ' : (failed++, 'FAIL ')) + 'v5.4.2: both unified lists resolve the clicked row via rowOf (the .cellacts wrapper no longer breaks the parent chain)');
    console.log(((a.indexOf('function stopViewPolls') >= 0 && a.indexOf('stopViewPolls();') >= 0 && a.indexOf('gen !== asPollGen || currentSub !== \'asset\'') >= 0) ? 'PASS ' : (failed++, 'FAIL ')) + 'v5.4.2: leaving a view stops its background polls (asset poll guarded by generation + visible sub)');
    console.log(((a.indexOf("busy && currentSub === 'devicelist'") >= 0 && a.indexOf("running && currentSub === 'updates'") >= 0 && a.indexOf("currentSub === 'license'") >= 0 && a.indexOf("currentSub === 'reset'") >= 0 && a.indexOf("currentSub === 'deploy'") >= 0) ? 'PASS ' : (failed++, 'FAIL ')) + 'v5.4.2: every remaining poller only runs while its own page is open');
} catch (e) { failed++; console.log('FAIL nav checks: ' + e.message); }

console.log(failed === 0 ? '\ntest-views: ALL PASSED' : '\ntest-views: ' + failed + ' FAILURE(S)');
process.exit(failed === 0 ? 0 : 1);
