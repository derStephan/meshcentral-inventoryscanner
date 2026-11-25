/**
 * Regenerates tools/fixtures/panel-inventory.json - the frozen inventory of what the rendered admin panel
 * contains (static element ids, info/hint help texts, report/export links, navigation panels).
 *
 * tools/test-views.js asserts every entry is still present, so a restructure cannot silently drop a control
 * or a help block (the v4.9.6 lesson: id-less help prose went missing and no test noticed). When something is
 * removed ON PURPOSE - e.g. issue #9 drops a column or a register - run this tool and commit the fixture in
 * the SAME change, so the loss is a visible, reviewed diff instead of a silent one.
 *
 * Run: node tools/gen-panel-inventory.js   (needs the devDependency handlebars: `npm ci` once)
 */
'use strict';

const fs = require('fs');
const path = require('path');

let Handlebars;
try {
    Handlebars = require('handlebars');
} catch (e) {
    console.log('Cannot run: handlebars is not installed. Run `npm ci` first.');
    process.exit(1);
}

const viewsDir = path.join(__dirname, '..', 'views');
const partialsDir = path.join(viewsDir, 'partials');

// Register the partials exactly the way express-handlebars does for a MeshCentral plugin: the partial name is
// the path relative to views/partials/ without the extension (sub-folders become namespaces).
(function register(dir, prefix) {
    if (!fs.existsSync(dir)) { return; }
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        if (e.isDirectory()) { register(path.join(dir, e.name), prefix + e.name + '/'); }
        else if (e.name.endsWith('.handlebars')) {
            Handlebars.registerPartial(prefix + e.name.slice(0, -'.handlebars'.length), fs.readFileSync(path.join(dir, e.name), 'utf8'));
        }
    }
})(partialsDir, '');

// Representative render data - the inventory is about the STATIC markup, so the values only need to be valid.
const data = {
    shortName: 'inventoryscanner',
    meshList: [{ id: 'mesh//grp1', name: 'HQ' }, { id: 'mesh//grp2', name: 'Branch' }],
    lastUpdate: new Date().toISOString(), lastScan: new Date().toISOString(), scanIntervalHours: 720,
    totalCves: 12345, version: 'generated'
};
const out = Handlebars.compile(fs.readFileSync(path.join(viewsDir, 'assessment.handlebars'), 'utf8'))(data);

const ids = new Set();
let m;
const reId = /id="([A-Za-z0-9_\-]+)"/g;
while ((m = reId.exec(out)) !== null) { ids.add(m[1]); }

// Help prose has no ids, so it needs its own fingerprint: the first 80 characters of the tag-stripped,
// whitespace-collapsed text plus its full length (a truncated block would change the length).
const prose = [];
const reProse = /<div class="(info|hint)"[^>]*>([\s\S]*?)<\/div>/g;
while ((m = reProse.exec(out)) !== null) {
    const t = m[2].replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
    if (t.length > 25) { prose.push({ head: t.substring(0, 80), len: t.length }); }
}

const links = [];
const reLink = /action=([a-zA-Z]+)(?:&(?:amp;)?type=([a-zA-Z]+))?/g;
while ((m = reLink.exec(out)) !== null) { links.push('action=' + m[1] + (m[2] ? '&type=' + m[2] : '')); }

const panels = [];
const rePanel = /data-main="([a-z]+)" data-sub="([a-z]+)"/g;
while ((m = rePanel.exec(out)) !== null) { panels.push(m[1] + '/' + m[2]); }

const fixture = {
    _comment: 'Frozen inventory of the rendered admin panel. tools/test-views.js asserts every entry is still present. Regenerate with `node tools/gen-panel-inventory.js` and commit it in the SAME change when something is removed on purpose.',
    generatedFrom: 'views/assessment.handlebars + views/partials/**',
    ids: [...ids].sort(),
    prose: prose,
    links: links.sort(),
    panels: panels.sort()
};
const target = path.join(__dirname, 'fixtures', 'panel-inventory.json');
fs.mkdirSync(path.dirname(target), { recursive: true });
fs.writeFileSync(target, JSON.stringify(fixture, null, 1), 'utf8');
console.log('written ' + path.relative(path.join(__dirname, '..'), target) + ': ' +
    fixture.ids.length + ' ids, ' + fixture.prose.length + ' help texts, ' + fixture.links.length + ' links, ' + fixture.panels.length + ' panels');
