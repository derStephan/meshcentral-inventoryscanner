/**
 * Static consistency checks - no dependencies, run anywhere with Node >= 16.
 * 1. node --check on inventoryscanner.js
 * 2. assessment.handlebars inline <script>: extracts, node --check, and verifies it
 *    contains no accidental '{{' (Handlebars would eat it; only the '{{shortName}}'
 *    server token is allowed).
 * 3. JSON validity of config files.
 * 4. res.render('<name>') calls match views/<name>.handlebars files EXACTLY
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

// 1. plugin main file
const mainJs = path.join(pluginDir, 'inventoryscanner.js');
report('inventoryscanner.js exists', fs.existsSync(mainJs));
if (fs.existsSync(mainJs)) jsCheck(mainJs, 'inventoryscanner.js syntax');

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

// 4. render names vs view file names
const mainSrc = fs.existsSync(mainJs) ? fs.readFileSync(mainJs, 'utf8') : '';
const renderNames = [];
let mm;
const re = /res\.render\(\s*'([^']+)'/g;
while ((mm = re.exec(mainSrc)) !== null) { renderNames.push(mm[1]); }
const viewFiles = fs.existsSync(viewsDir) ? fs.readdirSync(viewsDir).filter(f => f.endsWith('.handlebars')).map(f => f.slice(0, -11)) : [];
for (const name of renderNames) {
    report("render('" + name + "') has exactly views/" + name + ".handlebars", viewFiles.indexOf(name) >= 0, viewFiles.join(', '));
}
for (const v of viewFiles) {
    report('view ' + v + '.handlebars is used by a render call', renderNames.indexOf(v) >= 0);
}

console.log(failed === 0 ? '\ncheck: OK' : '\ncheck: ' + failed + ' FAILURE(S)');
process.exit(failed === 0 ? 0 : 1);
