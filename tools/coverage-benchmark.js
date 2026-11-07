/**
 * Coverage benchmark: aggregates the NVD CVE counts per CPE product from the feed
 * files (same loader the plugin uses), takes the top N products and checks whether
 * the plugin's mapping (custom + curated table + automatic evidence matcher) finds
 * each one from realistic Windows-style display names. Fully offline, read-only.
 *
 * usage: node tools/coverage-benchmark.js [--nvd <dir with nvdcve-2.0-*.json>] [--top 200]
 *        Default --nvd: <repo>/../meshcentral-data/nvd, else %TEMP%/invscanner-bench-*.
 * The same tool can run on the MeshCentral server against its real <datapath>/nvd.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const factory = require(path.join(__dirname, '..', 'inventoryscanner.js')).inventoryscanner;

let nvdDir = null, topN = 200;
const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--nvd' && argv[i + 1]) { nvdDir = argv[++i]; }
    else if (argv[i] === '--top' && argv[i + 1]) { topN = parseInt(argv[++i], 10) || 200; }
}
if (!nvdDir) {
    const guess = path.join(__dirname, '..', '..', 'meshcentral-data', 'nvd');
    nvdDir = fs.existsSync(guess) ? guess : fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-bench-'));
}

// Plugin instance on a throwaway data path (nothing is ever written here).
const meshServer = {
    db: { GetAllType: (t, cb) => cb(null, []), Get: (id, cb) => cb(null, []) },
    datapath: fs.mkdtempSync(path.join(os.tmpdir(), 'invscanner-benchdata-')),
    debug: function () { },
    config: { settings: {} },
    webserver: { meshes: {} }
};
fs.mkdirSync(path.join(meshServer.datapath, 'nvd'), { recursive: true });
const realNvd = path.join(meshServer.datapath, 'nvd');
let files = [];
try { files = fs.readdirSync(nvdDir).filter(f => /^nvdcve-2\.0-\d{4}\.json$/.test(f)); } catch (e) { }
if (files.length === 0) {
    console.log('No nvdcve-2.0-<year>.json files found in ' + nvdDir);
    console.log('Run this on the server against <datapath>/nvd, or decompress feeds there first.');
    process.exit(1);
}
for (const f of files) fs.copyFileSync(path.join(nvdDir, f), path.join(realNvd, f));

const obj = factory({ parent: meshServer });
obj.loadNvdFromAllFiles();
console.log('Indexed CVEs: ' + obj.allCves.length + ' from ' + files.length + ' feed year(s) of ' + nvdDir);

// CVE count per vendor|product straight from the plugin index
const counts = {};
for (const v in obj.productIndexByProduct) {
    for (const ent of obj.productIndexByProduct[v]) {
        const key = ent.vendor + '|' + v;
        const ids = {};
        for (const d of ent.defs) { for (const c of (d.cves || [])) { ids[c.id] = 1; } }
        counts[key] = (counts[key] || 0) + Object.keys(ids).length;
    }
}
const rows = Object.keys(counts).map(k => {
    const p = k.split('|');
    return { vendor: p[0], product: p[1], cves: counts[k] };
}).sort((a, b) => b.cves - a.cves);
const top = rows.slice(0, topN);

// ---- realistic display-name variants per product ----
function pretty(tok) {
    return tok.split(/[_\s]+/).map(w => w.length ? (w[0].toUpperCase() + w.slice(1)) : w).join(' ')
        .replace(/\s+\d{4}$/g, m => m); // keep years visible (they are in real registry names too)
}
function publisherOf(vendor) { return pretty(vendor) + ' Inc'; }
const variants = (vendor, product) => ([
    ['', pretty(product)],
    ['', pretty(product) + ' 1.2.3.4'],
    [publisherOf(vendor), pretty(vendor) + ' ' + pretty(product)],
    ['', pretty(product) + ' (x64)'],
    [publisherOf(vendor), pretty(vendor) + ' ' + pretty(product) + ' version 1.2.3']
]);

// web/mobile/enterprise products a Windows installed-software scanner can never see
const notDesktop = /^wp_|^wordpress|^drupal|^joomla|^android$|^ios$|^iphone_os$|^ipad_os$|^macos$|^mac_os|linux|chrome_os$|^windows_server|_server$|^jenkins$|^gitlab$|^grafana|^nextcloud$|^apache$|router|firmware$|^firewall|modem|web-based|management_system|^campcodes$|^qualcomm$/i;

let exact = 0, loose = 0, miss = 0, desktopTotal = 0, desktopCovered = 0;
const misses = [], desktopMisses = [];
for (const r of top) {
    let best = null;
    for (const v of variants(r.vendor, r.product)) {
        const got = obj.deriveCpeProduct(v[0], v[1]);
        if (got && got.product === r.product && got.vendor === r.vendor) { best = 'exact'; break; }
        if (got && got.product === r.product && !best) { best = 'loose'; }
    }
    if (best === 'exact') exact++; else if (best === 'loose') loose++; else miss++;
    const desk = !notDesktop.test(r.product) && !notDesktop.test(r.vendor);
    if (desk) { desktopTotal++; if (best) desktopCovered++; else desktopMisses.push(r); }
    if (!best) misses.push(r);
}

function fmt(list) { return list.slice(0, 30).map(r => '    ' + r.cves + '\t' + r.vendor + '|' + r.product).join('\n'); }
console.log('\n=== Top ' + top.length + ' CPE products by 2024-CVE count: mapping coverage ===');
console.log('exact vendor+product : ' + exact);
console.log('product only (loose) : ' + loose);
console.log('not mapped           : ' + miss);
console.log('desktop-relevant subset: ' + desktopCovered + '/' + desktopTotal +
    (desktopTotal ? ' = ' + Math.round(100 * desktopCovered / desktopTotal) + '%' : ''));
console.log('\nAll unmapped top products (CVE count | vendor|product):');
console.log(fmt(misses) || '    (none)');
if (misses.length > 30) console.log('    ... ' + (misses.length - 30) + ' more');
