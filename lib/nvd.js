/**
 * @file lib/nvd.js
 * @brief NVD 2.0 feed management: yearly download with .meta check and retry, the on-disk cache under <datapath>/nvd, loading it into the index, the download log and the scheduled refresh.
 * A feed above NVD_WHOLE_PARSE_MAX is split by a byte-level scanner instead of being read as one string: the 2026 file (~520 MB) is beyond V8's maximum string length, so readFileSync(..., 'utf8') threw and that whole year was silently missing before v3.1.0.
 *
 * Part of the MeshCentral Inventory & Vulnerability Scanner plugin; see ../inventoryscanner.js
 * for the module list and the attach order. Every member is attached to the shared plugin
 * object, so cross-module calls go through obj.name(...) and stay replaceable at runtime.
 */

"use strict";

const fs = require('fs');
const path = require('path');
const https = require('https');
const zlib = require('zlib');
const crypto = require('crypto');

/**
 * @brief Attach this module's members to one plugin instance.
 * @param {object} obj - The plugin object created by the entry point.
 */
module.exports.attach = function (obj) {
    /** @type {string|null} ISO timestamp of the last successful feed download. */
    obj.lastUpdate = null;

    // ---- NVD feed management ----

    /**
     * @brief Return the current calendar year.
     * @returns {number} The current year.
     */
    obj.currentYear = function () { return new Date().getFullYear(); };

    /**
     * @brief Append a diagnostic line to <code>nvd/nvd-download.log</code> - the log shown in the
     * Settings tab. Besides the NVD feed download it also records plugin lifecycle events
     * (upgrade detected, server restart, hot reload). Appends with a timestamp; never throws.
     * @param {string} msg - The message to log.
     */
    obj.nvdLog = function (msg) {
        try {
            var line = '[' + new Date().toISOString() + '] ' + msg + '\n';
            if (!fs.existsSync(obj.nvdDataPath)) { fs.mkdirSync(obj.nvdDataPath, { recursive: true }); }
            fs.appendFileSync(path.join(obj.nvdDataPath, 'nvd-download.log'), line);
        } catch (e) { }
        obj.debug('plugin:inventory_scanner', msg);
    };

    /**
     * @brief Ensure the NVD database is available at startup.
     * Loads existing feeds, or downloads all missing year feeds if none are present.
     */
    /** @type {boolean} True while an NVD download run (scheduled or manual) is in flight. */
    obj.nvdUpdateRunning = false;

    /**
     * @brief Single entry point for NVD downloads with a concurrency guard.
     * Concurrent callers get callback(null, "skipped") - the already running
     * download covers them (it refreshes the current year when asked to).
     * @param {boolean} force - Re-download the current year even if cached.
     * @param {function} [callback] - Called with (err, result).
     */
    obj.runNvdUpdate = function (force, callback) {
        if (obj.nvdUpdateRunning) { if (callback) callback(null, 'skipped'); return; }
        obj.nvdUpdateRunning = true;
        obj.downloadNvdDatabase(force, function (err) {
            obj.nvdUpdateRunning = false;
            if (callback) callback(err, err ? null : 'done');
        });
    };

    /**
     * @brief Manual "update now" trigger from the Settings tab.
     * Answers immediately (the download continues in the background); reports
     * alreadyRunning when a scheduled or manual run is in flight.
     * @param {object} req - The Express request (unused body).
     * @param {object} res - The Express response.
     * @param {object} user - The authenticated user.
     */
    obj.updateNvdHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        if (obj.nvdUpdateRunning) { return send({ started: false, alreadyRunning: true }); }
        obj.runNvdUpdate(true, function (err) {
            obj.debug('plugin:inventory_scanner', err ? ('NVD update run failed: ' + err.message) : 'NVD update run finished');
        });
        send({ started: true });
    };

    obj.ensureNvdData = function () {
        var latestYearFile = path.join(obj.nvdDataPath, 'nvdcve-2.0-' + obj.currentYear() + '.json');
        if (fs.existsSync(latestYearFile)) {
            obj.debug('plugin:inventory_scanner', 'Loading existing NVD database');
            obj.loadNvdFromAllFiles();
        } else {
            obj.debug('plugin:inventory_scanner', 'Downloading NVD database');
            obj.runNvdUpdate(false, null);
        }
    };

    /**
     * @brief Schedule periodic NVD feed updates.
     * Defaults to every 7 days; overridable via
     * <code>meshserver.config.settings.vulnerabilityScanner.updateHours</code>.
     */
    obj.scheduleUpdate = function () {
        var hours = 24 * 7; // weekly default
        try {
            var cfg = obj.effectiveSectionConfig('vulnerabilityScanner');
            if (cfg && (typeof cfg.updateHours === 'number') && (cfg.updateHours >= 1)) { hours = cfg.updateHours; }
        } catch (e) { }
        obj.debug('plugin:inventory_scanner', 'Next NVD update scheduled in', hours, 'hours');
        var gen = obj.timerGen;
        obj.longTimeout(function () {
            if (!obj.timerValid(gen)) { return; }
            obj.runNvdUpdate(true, function (err) {
                if (!obj.timerValid(gen)) { return; }
                if (!err) {
                    obj.updateTimerArmed = true;
                }
                obj.maybeFetchCpeTable();
                obj.maybeFetchOsLifecycle();
                obj.scheduleUpdate();
            });
        }, hours * 3600 * 1000);
    };

// ============================================================================
// winget automatic software updates (engine)
// ----------------------------------------------------------------------------
// Verified transport (meshcore.js): {action:'runcommands', type:1 (cmd.exe), cmds,
// runAsUser:0, reply:true, sessionid, responseid} -> the agent answers
// {action:'msg', type:'runcommands', result, sessionid, responseid}, captured
// by this plugin's routeAgentCommand hook. Verified winget CLI usage from the
// official docs (list --upgrade-available / upgrade --id --exact --silent /
// pin add --id --installed --exact, all with --accept-*-agreements and
// --disable-interactivity). One script per device does
// list -> filter(ignore) -> per-package upgrade -> pin sync and answers with a
// single @@INVWUP@@ marker line containing compressed JSON.
// ============================================================================

    /**
     * @brief Download a remote URL to a file on disk.
     * @param {string} url - The HTTPS URL to download.
     * @param {string} destPath - Local destination file path.
     * @param {function} callback - Called with <code>null</code> on success or an Error.
     */
    obj.httpGetToFile = function (url, destPath, callback, redirects) {
        var redirectsLeft = (redirects == null) ? 5 : redirects;
        var req = https.get(url, { timeout: 600000, headers: { 'User-Agent': 'MeshCentral-InventoryScanner' } }, function (res) {
            if ((res.statusCode >= 300) && (res.statusCode < 400) && (res.headers.location)) {
                res.resume();
                if (redirectsLeft <= 0) { callback(new Error('Too many redirects for ' + url)); return; }
                try { obj.httpGetToFile(new URL(res.headers.location, url).href, destPath, callback, redirectsLeft - 1); }
                catch (e) { callback(new Error('Invalid redirect for ' + url)); }
                return;
            }
            if (res.statusCode !== 200) { res.resume(); callback(new Error('HTTP ' + res.statusCode + ' for ' + url)); return; }
            var out = fs.createWriteStream(destPath);
            res.pipe(out);
            out.on('finish', function () { out.close(function () { callback(null); }); });
            out.on('error', function (err) { try { fs.unlinkSync(destPath); } catch (e) { } callback(err); });
        });
        req.on('error', function (err) { callback(err); });
        req.on('timeout', function () { req.destroy(new Error('Timeout downloading ' + url)); });
    };

    /**
     * @brief Download and verify one year of the NVD 2.0 feed.
     * Downloads the <code>.meta</code> (sha256) and <code>.json.gz</code>, verifies
     * the SHA-256 checksum, then decompresses to <code>.json</code>.
     * @param {number|string} year - The feed year.
     * @param {function} callback - Called with <code>null</code> on success or an Error.
     */
    obj.downloadYear = function (year, callback) {
        var base = 'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-' + year;
        var gzPath = path.join(obj.nvdDataPath, 'nvdcve-2.0-' + year + '.json.gz');
        var jsonPath = path.join(obj.nvdDataPath, 'nvdcve-2.0-' + year + '.json');

        obj.httpGetToFile(base + '.meta', gzPath + '.meta', function (metaErr) {
            var expectedSha = null;
            if (!metaErr) {
                try {
                    var m = fs.readFileSync(gzPath + '.meta', 'utf8').match(/^sha256:([0-9A-Fa-f]+)\s*$/m);
                    if (m) { expectedSha = m[1].toLowerCase(); }
                } catch (e) { }
            }

            obj.httpGetToFile(base + '.json.gz', gzPath, function (dlErr) {
                if (dlErr) {
                    obj.nvdLog('NVD ' + year + ': download error, deleting partial gz: ' + dlErr.message);
                    try { fs.unlinkSync(gzPath); } catch (e) { }
                    callback(dlErr); return;
                }

                if (expectedSha) {
                    var actual = crypto.createHash('sha256').update(fs.readFileSync(gzPath)).digest('hex');
                    if (actual !== expectedSha) {
                        var sz = -1; try { sz = fs.statSync(gzPath).size; } catch (e) { }
                        // NVD sometimes serves a .meta checksum that does not match the
                        // .json.gz it actually delivers (verified: the gz is complete and
                        // hashes consistently, only the .meta is stale/wrong). Treat a
                        // mismatch as a warning, not a hard failure, so a valid feed is
                        // not discarded. The gz is complete and identical across retries.
                        obj.nvdLog('NVD ' + year + ': WARNING SHA-256 mismatch vs meta (expected ' + expectedSha + ', got ' + actual + '), continuing anyway. gz size: ' + sz + ' bytes');
                    }
                }

                var gunzip = zlib.createGunzip();
                var src = fs.createReadStream(gzPath);
                var out = fs.createWriteStream(jsonPath);
                src.pipe(gunzip).pipe(out);
                out.on('finish', function () {
                    var js = -1; try { js = fs.statSync(jsonPath).size; } catch (e) { }
                    obj.nvdLog('NVD ' + year + ': gunzip ok, json size: ' + js + ' bytes');
                    try { fs.unlinkSync(gzPath); } catch (e) { }
                    callback(null);
                });
                out.on('error', function (err) {
                    obj.nvdLog('NVD ' + year + ': gunzip error, deleting files: ' + err.message);
                    try { fs.unlinkSync(jsonPath); } catch (e) { }
                    try { fs.unlinkSync(gzPath); } catch (e) { }
                    callback(err);
                });
                src.on('error', function (err) {
                    obj.nvdLog('NVD ' + year + ': read gz stream error: ' + err.message);
                    try { fs.unlinkSync(jsonPath); } catch (e) { }
                    try { fs.unlinkSync(gzPath); } catch (e) { }
                    callback(err);
                });
            });
        });
    };

/**

     * @brief Download the NVD feeds for all years from FIRST_YEAR to the current year.
     * @param {boolean} refreshCurrentYear - If true, re-download the current year's feed
     * even when a file already exists (used by the scheduled update).
     * @param {function} [callback] - Called with (err) when all downloads complete.
     */
    obj.downloadNvdDatabase = function (refreshCurrentYear, callback) {
        var current = obj.currentYear();
        var years = [];
        for (var y = obj.FIRST_YEAR; y <= current; y++) { years.push(y); }

        // Load the years sequentially (one after another) instead of all at once:
        // NVD rate-limits the many simultaneous large downloads, which previously
        // left only the tiny .meta files behind. A short pause between years and a
        // per-year retry with exponential backoff make the download robust.
        var pending = years.filter(function (year) {
            var jsonPath = path.join(obj.nvdDataPath, 'nvdcve-2.0-' + year + '.json');
            var isCurrent = (year === current);
            return !(fs.existsSync(jsonPath) && !(refreshCurrentYear && isCurrent));
        });
        if (pending.length === 0) { obj.loadNvdFromAllFiles(); if (callback) callback(null); return; }

        var failed = 0;
        var idx = 0;

        var next = function () {
            if (idx >= pending.length) {
                if (failed === 0) {
                    obj.lastUpdate = new Date().toISOString();
                    obj.loadNvdFromAllFiles();
                }
                obj.nvdLog('NVD download run finished. Failures: ' + failed + ' of ' + pending.length + '. Years attempted: ' + pending.join(', '));
                obj.debug('plugin:inventory_scanner', 'NVD download finished, failures:', failed, 'of', pending.length);
                if (callback) callback(failed === 0 ? null : new Error('Some downloads failed'));
                return;
            }
            var year = pending[idx];
            var attempt = 0;
            var tryDownload = function () {
                attempt++;
                obj.nvdLog('NVD ' + year + ': starting download (attempt ' + attempt + ')');
                obj.downloadYear(year, function (err) {
                    if (err) {
                        obj.debug('plugin:inventory_scanner', 'NVD', year, 'download failed (attempt', attempt + '):', err.message);
                        // Exponential backoff: 5s, 30s, 2min, then give up
                        var delay = attempt === 1 ? 5000 : (attempt === 2 ? 30000 : 120000);
                        if (attempt < 3) {
                            obj.nvdLog('NVD ' + year + ': download failed (' + err.message + '), retrying in ' + (delay / 1000) + 's');
                            setTimeout(tryDownload, delay);
                            return;
                        }
                        failed++;
                        idx++;
                        obj.nvdLog('NVD ' + year + ': giving up after ' + attempt + ' attempts');
                        setTimeout(next, 2000);
                        return;
                    }
                    idx++;
                    obj.nvdLog('NVD ' + year + ': download complete');
                    setTimeout(next, 2000);
                });
            };
            tryDownload();
        };
        next();
    };


    /**
     * @brief Load all downloaded NVD feed files into the in-memory index.
     * Resets <code>productIndex</code> and <code>allCves</code> before loading.
     */
obj.loadNvdFromAllFiles = function () {
        obj.productIndex = {};
        obj.productIndexByProduct = {};
        obj.cpeProductTokens = {};
        obj.cpeVendorTokens = {};
        obj.allCves = [];
        var current = obj.currentYear();
        var newestMtime = null;
        for (var y = obj.FIRST_YEAR; y <= current; y++) {
            var file = path.join(obj.nvdDataPath, 'nvdcve-2.0-' + y + '.json');
            if (fs.existsSync(file)) {
                obj.loadNvdFromFile(file);
                try {
                    var mt = fs.statSync(file).mtimeMs;
                    if ((newestMtime == null) || (mt > newestMtime)) { newestMtime = mt; }
                } catch (e) { }
            }
        }
        // Derive the NVD status from the loaded feed files themselves, so the UI shows
        // a real timestamp even when the feeds were downloaded by an earlier run. Only
        // when no feed file exists at all is the database considered "not downloaded".
        if (newestMtime != null) { obj.lastUpdate = new Date(newestMtime).toISOString(); }
        else { obj.lastUpdate = null; }
        obj.debug('plugin:inventory_scanner', 'Total CVEs indexed:', obj.allCves.length);
    };

    /**
     * @brief Parse a single NVD feed file and index its vulnerabilities.
     * Files up to 256 MB are parsed in one piece. Larger files (the 2026 feed is ~520 MB,
     * above V8's maximum string length of ~512 MB, so readFileSync(...,'utf8') THROWS and
     * every CVE of that year was silently missing before v3.1.0) go through
     * splitNvdVulnerabilities, which never builds a string of the whole file.
     * @param {string} file - Path to a <code>nvdcve-2.0-<year>.json</code> file.
     * @returns {number} number of vulnerabilities indexed from this file.
     */
    obj.loadNvdFromFile = function (file) {
        try {
            var size = fs.statSync(file).size;
            if (size <= obj.NVD_WHOLE_PARSE_MAX) {
                var data = JSON.parse(fs.readFileSync(file, 'utf8'));
                if (data && Array.isArray(data.vulnerabilities)) { obj.processNvdData(data.vulnerabilities); return data.vulnerabilities.length; }
                return 0;
            }
            var n = 0, batch = [];
            obj.splitNvdVulnerabilities(fs.readFileSync(file), function (item) {
                batch.push(item); n++;
                if (batch.length >= 2000) { obj.processNvdData(batch); batch = []; }
            });
            if (batch.length > 0) { obj.processNvdData(batch); }
            return n;
        } catch (err) {
            obj.nvdLog('Error loading NVD file ' + path.basename(file) + ': ' + err.message);
            return 0;
        }
    };

    /** @type {number} files above this size are split instead of parsed whole (bytes). */
    obj.NVD_WHOLE_PARSE_MAX = 256 * 1024 * 1024;

    /**
     * @brief Split the "vulnerabilities" array of an NVD 2.0 feed buffer into single parsed
     * objects without ever creating a string of the whole buffer. Byte-level scanner: tracks
     * string/escape state and brace depth; every top-level array element is sliced out of the
     * buffer and JSON.parse'd on its own (a few KB each).
     * @param {Buffer} buf - Whole feed file.
     * @param {function} onItem - Called with each parsed vulnerability object.
     */
    obj.splitNvdVulnerabilities = function (buf, onItem) {
        var key = Buffer.from('"vulnerabilities"');
        var at = buf.indexOf(key);
        if (at < 0) { throw new Error('no vulnerabilities array'); }
        var i = buf.indexOf(0x5B, at + key.length); // '['
        if (i < 0) { throw new Error('no vulnerabilities array'); }
        i++;
        var len = buf.length, depth = 0, inStr = false, esc = false, start = -1;
        for (; i < len; i++) {
            var c = buf[i];
            if (inStr) {
                if (esc) { esc = false; }
                else if (c === 0x5C) { esc = true; }      // backslash
                else if (c === 0x22) { inStr = false; }   // quote
                continue;
            }
            if (c === 0x22) { inStr = true; continue; }
            if (c === 0x7B) { if (depth === 0) { start = i; } depth++; continue; }   // {
            if (c === 0x7D) {                                                          // }
                depth--;
                if (depth === 0 && start >= 0) { onItem(JSON.parse(buf.toString('utf8', start, i + 1))); start = -1; }
                continue;
            }
            if (c === 0x5D && depth === 0) { return; }   // ] closes the array
        }
        throw new Error('truncated vulnerabilities array');
    };

    /**
     * @brief Return the effective scanner/collector settings plus the per-key source
     * ('file' = saved via this UI, 'config.json' = server config, 'default').
     * @param {object} res - The Express response.
     * @param {object} user - The authenticated user.
     */
    /**
     * @brief Return the tail of the NVD download log for the Settings tab viewer.
     * Fixed path inside the plugin NVD directory, capped at the last 200 lines of a
     * 256 KB window; never a caller-supplied path.
     * @param {object} req - The Express request (unused body).
     * @param {object} res - The Express response.
     * @param {object} user - The authenticated user.
     */
    obj.getNvdLogHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        try {
            var file = path.join(obj.nvdDataPath, 'nvd-download.log');
            if (!fs.existsSync(file)) { return send({ lines: [], note: 'No download log yet - the first feed download creates it.' }); }
            var st = fs.statSync(file);
            var fd = fs.openSync(file, 'r');
            var len = Math.min(st.size, 256 * 1024);
            var buf = Buffer.alloc(len);
            fs.readSync(fd, buf, 0, len, Math.max(0, st.size - len));
            fs.closeSync(fd);
            var lines = buf.toString('utf8').split(String.fromCharCode(10));
            if (lines.length > 0 && lines[lines.length - 1] === '') { lines.pop(); }
            if (len < st.size) { lines.shift(); }  // first line may be cut mid-way
            send({ lines: lines.slice(-200), size: st.size, file: 'nvd/nvd-download.log' });
        } catch (ex) {
            send({ lines: [], note: 'Could not read the log: ' + ex.message });
        }
    };
};
