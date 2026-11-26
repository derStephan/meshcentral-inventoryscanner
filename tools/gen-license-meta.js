/**
 * @file tools/gen-license-meta.js
 * @brief Evidence tool for the curated `licenseType` field of cpe-table.json (v5.6.0).
 *
 * The license type of a product is NOT something the plugin may derive at runtime - a guess in an asset
 * report is worse than an empty cell. So the value is curated once, in the table, and this tool is how a
 * contributor produces and re-verifies it: it reads the winget community manifests (microsoft/winget-pkgs,
 * MIT license - compatible with this project's MIT) through the locally installed winget client and reports
 * what upstream states about each mapped product.
 *
 * The winget id per table row lives in tools/winget-ids.json, keyed by the row's `match` regex so that
 * edition-specific rows (the JetBrains Community Editions) map to their own package. A row that is not in
 * that file has no winget package; its licenseType came from the project's own license statement and this
 * tool leaves it alone.
 *
 * Usage (Windows with winget installed; on any other machine it reports SKIP and exits 0):
 *   node tools/gen-license-meta.js             report: evidence vs. the curated value, drift + unmapped strings
 *   node tools/gen-license-meta.js --write     write the NORMALIZED evidence into cpe-table.json
 *   node tools/gen-license-meta.js --json      machine-readable report
 *
 * Normalization is explicit and conservative: only strings listed in NORMALIZE are translated, an SPDX
 * identifier or one of the three descriptors passes through unchanged, and anything else is reported as
 * UNMAPPED and NEVER written - the honest answer stays "no curated statement".
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const TABLE = path.join(ROOT, 'cpe-table.json');
const IDS = path.join(__dirname, 'winget-ids.json');

/** The vocabulary cpe-table.json's `_licenseNote` and CONTRIBUTING.md define. */
const DESCRIPTORS = ['Proprietary', 'Freeware', 'Freeware (non-commercial)'];

/** An SPDX identifier: letters, digits and the . + - separators, e.g. GPL-2.0-or-later, LGPL-2.1-only, curl. */
const SPDX_RE = /^[A-Za-z0-9][A-Za-z0-9.+-]{0,63}$/;

/**
 * Explicit translations of the non-SPDX strings winget-pkgs actually uses (measured 2026-11-26).
 * Anything not listed here and not already valid is reported UNMAPPED, never guessed.
 */
const NORMALIZE = {
    'commercial': 'Proprietary',
    'proprietary': 'Proprietary',
    'proprietary (freeware)': 'Freeware',
    'proprietary, free for private and non-commercial use': 'Freeware (non-commercial)',
    'freeware': 'Freeware',
    'shareware': 'Proprietary',
    'microsoft software license': 'Freeware',
    'oracle no-fee terms and conditions': 'Proprietary',
    'nero': 'Proprietary',
    'gplv2': 'GPL-2.0-or-later',
    'gplv3': 'GPL-3.0-or-later',
    'gpl-2.0': 'GPL-2.0-only',
    'gpl-3.0': 'GPL-3.0-only',
    'lgpl-2.1': 'LGPL-2.1-only',
    'lgpl-3.0': 'LGPL-3.0-only',
    'agpl-3.0': 'AGPL-3.0-only',
    'php license v3.01': 'PHP-3.01'
};

function normalize(raw) {
    const s = String(raw == null ? '' : raw).trim();
    if (s === '') { return { ok: false, why: 'empty', value: '' }; }
    if (DESCRIPTORS.indexOf(s) >= 0) { return { ok: true, value: s }; }
    const low = s.toLowerCase();
    if (Object.prototype.hasOwnProperty.call(NORMALIZE, low)) { return { ok: true, value: NORMALIZE[low] }; }
    if (SPDX_RE.test(s)) { return { ok: true, value: s }; }
    return { ok: false, why: 'unmapped', value: '' };
}

/** Run `winget show` for one id and return its License / License Url lines ('' when absent). */
function wingetLicense(id) {
    let out = '';
    try {
        out = execFileSync('winget', ['show', '--id', id, '--exact', '--locale', 'en-US',
            '--accept-source-agreements', '--disable-interactivity'],
            { encoding: 'utf8', timeout: 90000, stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (e) {
        const txt = String((e && (e.stdout || e.message)) || '');
        if (/No package found|not recognized/i.test(txt)) { return { found: false, license: '', url: '' }; }
        if (e && e.code === 'ENOENT') { return { nowinget: true, found: false, license: '', url: '' }; }
        return { found: false, license: '', url: '', error: txt.split('\n')[0].substring(0, 160) };
    }
    const lic = /(?:^|\n)License:\s*(.+?)\s*(?:\n|$)/.exec(out);
    const url = /(?:^|\n)License Url:\s*(.+?)\s*(?:\n|$)/.exec(out);
    return { found: true, license: lic ? lic[1] : '', url: url ? url[1] : '' };
}

function main() {
    const argv = process.argv.slice(2);
    const write = argv.indexOf('--write') >= 0;
    const asJson = argv.indexOf('--json') >= 0;

    const table = JSON.parse(fs.readFileSync(TABLE, 'utf8'));
    const idFile = JSON.parse(fs.readFileSync(IDS, 'utf8'));
    const idMap = idFile.ids || {};
    const overrides = idFile.overrides || {};

    const rows = [];
    let drift = 0, unmapped = 0, noPackage = 0, missing = 0, confirmed = 0, overridden = 0, changed = 0, writable = 0, skipped = 0;

    for (const e of table.entries) {
        if (e.kind != null) { skipped++; continue; }   // exclusion markers carry no license statement
        const id = idMap[e.match];
        const ovr = overrides[e.match];
        const row = { match: e.match, product: e.vendor + ':' + e.product, curated: e.licenseType || '', wingetId: id || '', evidence: '', value: '', state: '' };

        // A documented override decides the value even when winget states something else (see
        // tools/winget-ids.json `_overridesComment`): winget's License field names the TERMS, this table
        // answers whether a license has to be bought. An override whose value is not the curated one is a
        // real mistake and is reported as DRIFT, exactly like a contradicting manifest.
        if (ovr && typeof ovr.licenseType === 'string' && ovr.licenseType !== '') {
            row.value = ovr.licenseType;
            if (row.curated === '') { row.state = 'missing-in-table'; missing++; }
            else if (row.curated !== ovr.licenseType) { row.state = 'DRIFT'; drift++; }
            else { row.state = 'override'; overridden++; }
            if (!id) { rows.push(row); continue; }
            const w0 = wingetLicense(id);
            row.evidence = w0.found ? w0.license : '';
            if (row.curated !== ovr.licenseType) { writable++; if (write) { e.licenseType = ovr.licenseType; changed++; } }
            rows.push(row);
            continue;
        }

        if (!id) {
            row.state = (row.curated === '') ? 'no-evidence' : 'curated-only';
            if (row.curated === '') { missing++; }
            rows.push(row);
            continue;
        }
        const w = wingetLicense(id);
        if (w.nowinget) {
            console.log('SKIP: winget is not installed - this tool needs the winget client to read the manifests.');
            console.log('      (Nothing was compared and nothing was written.)');
            process.exit(0);
        }
        if (!w.found) { row.state = 'package-missing'; noPackage++; rows.push(row); continue; }
        row.evidence = w.license;
        const n = normalize(w.license);
        if (!n.ok) { row.state = 'unmapped:' + n.why; row.value = ''; unmapped++; rows.push(row); continue; }
        row.value = n.value;
        if (row.curated === '') { row.state = 'missing-in-table'; missing++; }
        else if (row.curated !== n.value) { row.state = 'DRIFT'; drift++; }
        else { row.state = 'confirmed'; confirmed++; }
        if (row.curated !== n.value) { writable++; if (write) { e.licenseType = n.value; changed++; } }
        rows.push(row);
    }

    if (write && changed > 0) {
        table.updated = new Date().toISOString().substring(0, 10);
        fs.writeFileSync(TABLE, JSON.stringify(table, null, 2) + '\n');
    }

    if (asJson) {
        console.log(JSON.stringify({ written: write && changed > 0, changed: changed, counts: { confirmed: confirmed, override: overridden, drift: drift, unmapped: unmapped, noPackage: noPackage, missing: missing, skippedKindRows: skipped }, rows: rows }, null, 1));
        return;
    }

    const pad = function (s, n) { s = String(s == null ? '' : s); return (s.length > n) ? (s.substring(0, n - 1) + '\u2026') : (s + ' '.repeat(n - s.length)); };
    console.log('licenseType evidence report (' + (write ? 'WRITE mode' : 'report only') + ')');
    console.log(pad('state', 18) + pad('curated', 26) + pad('winget evidence', 34) + pad('normalized', 26) + 'row');
    for (const r of rows) {
        if (r.state === 'confirmed' && argv.indexOf('--all') < 0) { continue; }
        console.log(pad(r.state, 18) + pad(r.curated, 26) + pad(r.evidence, 34) + pad(r.value, 26) + r.match);
    }
    console.log('');
    console.log('confirmed=' + confirmed + ' override=' + overridden + ' drift=' + drift + ' unmapped=' + unmapped + ' package-missing=' + noPackage +
        ' missing-in-table=' + missing + ' kind-rows(skipped)=' + skipped + (write ? (' written=' + changed) : ''));
    if (!write && writable > 0) {
        console.log('Re-run with --write to refresh ' + writable + ' curated value(s) from the evidence above.');
    }
    if (unmapped > 0) {
        console.log('Unmapped evidence strings were NOT written - extend NORMALIZE in this tool first (never guess a license).');
    }
}

main();
