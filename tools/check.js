/**
 * Static consistency checks - no dependencies, run anywhere with Node >= 16.
 * 1. node --check on inventoryscanner.js AND on every lib/<module>.js, plus the v3.5.1 module
 *    contract: the entry attaches exactly the files that exist (no orphan, no missing), the
 *    entry stays wiring-only (thin), and no lib file resolves paths by its own __dirname.
 * 2. assessment.handlebars inline <script>: extracts, node --check, and verifies it
 *    contains no accidental '{{' (Handlebars would eat it; only the '{{shortName}}'
 *    server token is allowed).
 * 3. JSON validity of config files.
 * 4. res.render('<name>') calls (entry + lib/) match views/<name>.handlebars files EXACTLY
 *    (case-sensitive; a mismatch is a 500 on Linux but passes on Windows).
 */
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFileSync } = require('child_process');

const root = path.join(__dirname, '..');
const pluginDir = root; // flat layout: plugin files live at repository root (web installer requirement)
const viewsDir = path.join(pluginDir, 'views');
let failed = 0;

function report(name, ok, extra) {
    console.log((ok ? 'PASS ' : 'FAIL ') + name + (ok || extra === undefined ? '' : ' -> ' + extra));
    if (!ok) failed++;
}

function jsCheck(file, label) {
    try {
        execFileSync(process.execPath, ['--check', file], { stdio: 'pipe' });
        report(label, true);
    } catch (e) {
        report(label, false, String(e.stderr || e.message).trim());
    }
}

// 1. plugin main file + every lib module
const mainJs = path.join(pluginDir, 'inventoryscanner.js');
report('inventoryscanner.js exists', fs.existsSync(mainJs));
if (fs.existsSync(mainJs)) jsCheck(mainJs, 'inventoryscanner.js syntax');
const libDir = path.join(pluginDir, 'lib');
const libFiles = fs.existsSync(libDir) ? fs.readdirSync(libDir).filter(f => f.endsWith('.js')).sort() : [];
report('lib/ exists and holds the feature modules', libFiles.length > 0, 'found ' + libFiles.length);
for (const f of libFiles) jsCheck(path.join(libDir, f), 'lib/' + f + ' syntax');

// 1b. wiring: the entry must attach every module file, and no module file may be orphaned
const entrySrc = fs.existsSync(mainJs) ? fs.readFileSync(mainJs, 'utf8') : '';
const modBlock = (entrySrc.match(/const modules = \[([\s\S]*?)\];/) || [])[1] || '';
const attached = (modBlock.match(/'([^']+)'/g) || []).map(s => s.slice(1, -1));
report('inventoryscanner.js declares a non-empty module list', attached.length > 0, modBlock.trim().split('\n').length + ' lines');
for (const f of libFiles) {
    report('lib/' + f + ' is attached by inventoryscanner.js', attached.indexOf(f.slice(0, -3)) >= 0);
}
for (const m of attached) {
    report('attached module ' + m + ' exists as lib/' + m + '.js', libFiles.indexOf(m + '.js') >= 0);
}
report('entry point keeps the flat-layout contract (inventoryscanner.js at plugin root)',
    /module\.exports\.inventoryscanner = function \(parent\)/.test(entrySrc));
report('inventoryscanner.js stays wiring only (< 300 lines)', entrySrc.split('\n').length < 300,
    entrySrc.split('\n').length + ' lines');
report('the entry does not implement features (no obj.x = function beyond its own identity)',
    (entrySrc.match(/^ {4}obj\.[\w$]+ = function/gm) || []).length <= 3,
    (entrySrc.match(/^ {4}obj\.([\w$]+) = function/gm) || []).join(' | '));
// lib modules run from lib/, so their own __dirname would point at the wrong folder
for (const f of libFiles) {
    const src = fs.readFileSync(path.join(libDir, f), 'utf8');
    report('lib/' + f + ' uses obj.pluginDir, not its own __dirname', src.indexOf('__dirname') < 0,
        src.split('\n').filter(l => l.indexOf('__dirname') >= 0)[0]);
}

// 2. inline script of the panel view
const assPath = path.join(viewsDir, 'assessment.handlebars');
if (fs.existsSync(assPath)) {
    const src = fs.readFileSync(assPath, 'utf8');
    const m = src.match(/<script>([\s\S]*?)<\/script>/);
    report('assessment.handlebars has an inline <script>', !!m);
    if (m) {
        const js = m[1];
        const stray = js.replace(/\{\{shortName\}\}/g, '').indexOf('{{');
        report('panel script: no stray {{ (only {{shortName}})', stray < 0,
            stray >= 0 ? js.substring(Math.max(0, stray - 40), stray + 40) : undefined);
        const tmp = path.join(os.tmpdir(), 'invscanner-inline-check-' + Date.now() + '.js');
        fs.writeFileSync(tmp, js, 'utf8');
        jsCheck(tmp, 'panel inline script syntax');
        try { fs.unlinkSync(tmp); } catch (e) { }
    }
} else {
    report('assessment.handlebars exists', false);
}

// 3. JSON files
for (const f of [path.join(pluginDir, 'config.json'), path.join(root, 'package.json')]) {
    let ok = false, err = '';
    try { JSON.parse(fs.readFileSync(f, 'utf8')); ok = true; } catch (e) { err = e.message; }
    report('valid JSON: ' + path.relative(root, f), ok, err);
}

// 3b. plugin manifest: fields MeshCentral's web installer validates (isValidConfig + downloadUrl)
const man = JSON.parse(fs.readFileSync(path.join(root, 'config.json'), 'utf8'));
report('config.json meets installer requirements (name/shortName/manifest fields)',
    typeof man.name === 'string' && man.shortName === 'inventoryscanner' && typeof man.version === 'string' &&
    typeof man.description === 'string' && typeof man.hasAdminPanel === 'boolean' && typeof man.homepage === 'string' &&
    typeof man.changelogUrl === 'string' && typeof man.configUrl === 'string' && typeof man.downloadUrl === 'string' &&
    man.repository && typeof man.repository.type === 'string' && typeof man.repository.url === 'string' &&
    typeof man.meshCentralCompat === 'string');

// 4. render names vs view file names (the render calls live in the lib/ modules, not in the entry)
let allSrc = fs.existsSync(mainJs) ? fs.readFileSync(mainJs, 'utf8') : '';
for (const f of libFiles) { allSrc += '\n' + fs.readFileSync(path.join(libDir, f), 'utf8'); }
const renderNames = [];
let mm;
const re = /res\.render\(\s*'([^']+)'/g;
while ((mm = re.exec(allSrc)) !== null) { renderNames.push(mm[1]); }
const viewFiles = fs.existsSync(viewsDir) ? fs.readdirSync(viewsDir).filter(f => f.endsWith('.handlebars')).map(f => f.slice(0, -11)) : [];
for (const name of renderNames) {
    report("render('" + name + "') has exactly views/" + name + ".handlebars", viewFiles.indexOf(name) >= 0, viewFiles.join(', '));
}
for (const v of viewFiles) {
    report('view ' + v + '.handlebars is used by a render call', renderNames.indexOf(v) >= 0);
}

console.log(failed === 0 ? '\ncheck: OK' : '\ncheck: ' + failed + ' FAILURE(S)');
process.exit(failed === 0 ? 0 : 1);
