'use strict';
/**
 * @file tools/workdir.js
 * @brief Shared working-directory policy for every tool in this folder (v5.6.0).
 *
 * Why this exists: the test suite created its scratch directories with `fs.mkdtempSync(os.tmpdir(), ...)`
 * and never removed them, and three of its steps call the real `server_startup()` against a temporary
 * datapath - which made `ensureNvdData()` download the COMPLETE NVD feed set (~2.8 GB) into each of them.
 * Measured on a contributor machine: 12,821 leftover directories totalling 47.9 GB in %TEMP%, roughly
 * 8-9 GB per `npm test` run.
 *
 * What `install()` does, for every tool that calls it:
 *  1. **Redirect** - when the environment variable `INVSCANNER_WORKDIR` names a writable folder, ALL
 *     temporary paths of the process are created there instead of in the system temp folder
 *     (`os.tmpdir()` is redirected, so no call site has to change). Unset - the default, and what CI
 *     uses - keeps `os.tmpdir()` exactly as before.
 *  2. **Track** - every directory created through `fs.mkdtempSync` is registered, and every path handed
 *     out by `tmpFile()` too.
 *  3. **Clean up** - registered directories and files are removed when the process exits, also after a
 *     failing step. Removal failures are ignored (a locked file must not fail the run).
 *
 * The NVD download itself is prevented separately by `seedEmptyNvd()` in test-plugin.js (a 0-CVE feed
 * file for the current year, the same trick the CI container test uses) - redirecting the directory does
 * not stop a multi-gigabyte download, it only puts it somewhere else.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const dirs = [];
const files = [];
let installed = false;
let redirected = '';

/** @brief The base folder temporary paths are created in (after install()). */
function base() { return os.tmpdir(); }

/** @brief Where the redirect points to ('' when INVSCANNER_WORKDIR is not in effect). */
function workdir() { return redirected; }

/**
 * @brief Register a temporary FILE path for cleanup and return it (the caller writes the file).
 * Prefer this over `path.join(os.tmpdir(), name)`: it is redirected like everything else and it is
 * removed on exit even when the caller throws before its own unlink.
 * @param {string} name - File name (no directory part).
 * @returns {string} The absolute path inside base().
 */
function tmpFile(name) {
    const f = path.join(base(), name);
    files.push(f);
    return f;
}

/**
 * @brief Register a temporary DIRECTORY path for cleanup and return it (the caller creates it).
 * For the call sites that build a timestamped path themselves instead of using fs.mkdtempSync -
 * those are invisible to the mkdtempSync wrapper and used to survive every run.
 * @param {string} name - Directory name (no directory part).
 * @returns {string} The absolute path inside base().
 */
function tmpDir(name) {
    const d = path.join(base(), name);
    dirs.push(d);
    return d;
}

/**
 * @brief Register an already-built absolute path (file or directory) for cleanup.
 * @param {string} p - Absolute path.
 * @returns {string} The same path, so it can be used inline.
 */
function track(p) {
    dirs.push(p);
    return p;
}

/** @brief Remove everything registered so far. Safe to call more than once. */
function cleanup() {
    while (files.length) {
        const f = files.pop();
        try { fs.rmSync(f, { force: true }); } catch (e) { }
    }
    while (dirs.length) {
        const d = dirs.pop();
        try { fs.rmSync(d, { recursive: true, force: true, maxRetries: 2 }); } catch (e) { }
    }
}

/** @brief Apply the redirect + tracking + exit cleanup. Idempotent; call once at the top of a tool. */
function install() {
    if (installed) { return; }
    installed = true;
    const wanted = process.env.INVSCANNER_WORKDIR;
    if (wanted) {
        try {
            fs.mkdirSync(wanted, { recursive: true });
            const probe = path.join(wanted, '.invscanner-write-probe');
            fs.writeFileSync(probe, 'ok'); fs.rmSync(probe, { force: true });
            os.tmpdir = function () { return wanted; };
            redirected = wanted;
        } catch (e) {
            console.log('WARNING: INVSCANNER_WORKDIR (' + wanted + ') is not usable (' + e.message + ') - keeping the system temp folder');
        }
    }
    const realMkdtempSync = fs.mkdtempSync;
    fs.mkdtempSync = function (prefix, options) {
        const dir = realMkdtempSync.call(fs, prefix, options);
        dirs.push(dir);
        return dir;
    };
    process.on('exit', cleanup);
}

module.exports = { install: install, cleanup: cleanup, tmpFile: tmpFile, tmpDir: tmpDir, track: track, base: base, workdir: workdir };
