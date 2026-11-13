/**
 * @file lib/swstore.js
 * @brief Software deploy foundation (v4.0.0): the installer library (index + stored files + resumable upload parts), the deploy task store, the per-task staging into MeshCentral's <filespath>/tmp and the one-shot agentdownload cookie. Pure storage/paths/quoting - the scripts and the queue live in lib/swdeploy.js.
 * Every fact this module relies on was verified in official MeshCentral source:
 * webserver.js handleAgentDownloadFile serves <filespath>/tmp/<f> for a cookie
 * {a:'tmpdl', d:domain, nid:node, f:file} minted with parent.encodeCookie(..., loginCookieEncryptionKey)
 * and DECODED WITH A 5-MINUTE TIMEOUT - so a cookie must be created at dispatch time, never earlier;
 * handleUploadFileBatch stages there with a name getRandomPassword()+'-'+safeName (the agent wget
 * silently SKIPS an existing file unless overwrite:true, so every dispatch uses overwrite:true and a
 * unique random name anyway). getServerFilePath shows the Server Files layout:
 * <filespath>/domain[-<x>]/mesh-<group>/<files> (the per-group folders of the MeshCentral Files tab).
 *
 * Part of the MeshCentral Inventory & Vulnerability Scanner plugin; see ../inventoryscanner.js
 * for the module list and the attach order. Every member is attached to the shared plugin
 * object, so cross-module calls go through obj.name(...) and stay replaceable at runtime.
 */

"use strict";

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/**
 * @brief Attach this module's members to one plugin instance.
 * @param {object} obj - The plugin object created by the entry point.
 */
module.exports.attach = function (obj) {
    /** @type {Object<string, object>} fileId -> { name, ext, size, sha256, time, by }. */
    obj.swFiles = {};
    /** @type {Object<string, object>} taskId -> task record (devices map included). */
    obj.swTasks = {};
    /** @type {Object<string, object>} uploadId -> in-progress chunked upload (bytes only until committed). */
    obj.swUploads = {};

    /** @type {Array<string>} installer extensions the scripts know how to run. */
    obj.SW_EXTS = ['msi', 'msp', 'exe', 'deb', 'rpm', 'sh', 'bin'];
    /** @type {number} raw bytes per upload chunk: 4/3 of it travels as base64url inside ONE urlencoded
     *  POST - the pluginadmin route parses bodies with body-parser's 100kb urlencoded DEFAULT (verified
     *  in webserver.js: app.post('pluginadmin.ashx', bodyParser.urlencoded({extended:false}))). */
    obj.SW_CHUNK_BYTES = 49152;
    obj.SW_MAX_FILE_BYTES = 2 * 1024 * 1024 * 1024;
    obj.SW_MAX_TASKS = 100;
    /** @type {number} a staged temp file older than this is swept (server restarted mid-task). */
    obj.SW_STAGE_MAX_AGE_MS = 24 * 60 * 60 * 1000;

    // ---- log ----

    /** @brief Append a line to the deploy log (rotated once at ~5 MB). */
    obj.swLog = function (line) {
        try {
            var dir = path.dirname(obj.swLogPath);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            try { if (fs.existsSync(obj.swLogPath) && (fs.statSync(obj.swLogPath).size > 5 * 1024 * 1024)) { fs.renameSync(obj.swLogPath, obj.swLogPath + '.old'); } } catch (e) { }
            fs.appendFileSync(obj.swLogPath, new Date().toISOString() + ' ' + line + String.fromCharCode(10));
        } catch (e) { }
    };

    // ---- store ----

    /** @brief Ensure the library folders exist. */
    obj.swStoreDirs = function () {
        try { fs.mkdirSync(obj.swFilesDir, { recursive: true }); } catch (e) { }
        try { fs.mkdirSync(obj.swPartsDir, { recursive: true }); } catch (e) { }
    };

    /** @brief Load the installer library index (plus interrupted part files, so an upload can resume). */
    obj.swLoadFiles = function () {
        obj.swFiles = {};
        obj.swUploads = {};
        try {
            if (fs.existsSync(obj.swStorePath)) {
                var d = JSON.parse(fs.readFileSync(obj.swStorePath, 'utf8'));
                if (d && (typeof d === 'object')) {
                    for (var id in d) {
                        var f = d[id];
                        if ((f != null) && (typeof f === 'object') && typeof f.name === 'string' && /^[a-f0-9]{12}$/.test(id) &&
                            (typeof f.size === 'number') && /^[a-f0-9]{64}$/.test(String(f.sha256 || '')) && obj.SW_EXTS.indexOf(String(f.ext || '')) >= 0) {
                            obj.swFiles[id] = { name: f.name.substring(0, 200), ext: f.ext, size: f.size, sha256: String(f.sha256).toLowerCase(), time: String(f.time || ''), by: String(f.by || '').substring(0, 100) };
                        }
                    }
                }
            }
        } catch (e) { obj.swFiles = {}; }
        try {
            if (fs.existsSync(obj.swPartsDir)) {
                var parts = fs.readdirSync(obj.swPartsDir).filter(function (x) { return /^[a-f0-9]{8,40}\.part$/.test(x); });
                for (var i = 0; i < parts.length; i++) {
                    var uid = parts[i].substring(0, parts[i].length - 5);
                    var sz = 0; try { sz = fs.statSync(path.join(obj.swPartsDir, parts[i])).size; } catch (e) { }
                    obj.swUploads[uid] = { bytes: sz }; // name/ext unknown after a restart: re-sent with the next chunk
                }
            }
        } catch (e) { }
    };

    /** @brief Persist the installer library index. */
    obj.swSaveFiles = function () {
        try {
            obj.swStoreDirs();
            fs.writeFileSync(obj.swStorePath, JSON.stringify(obj.swFiles, null, 2));
        } catch (e) { obj.swLog('could not save the software index: ' + e.message); }
    };

    /** @brief Load persisted deploy tasks; a crash leaves devices in queued, never lost. */
    obj.swLoadTasks = function () {
        obj.swTasks = {};
        try {
            if (fs.existsSync(obj.swTasksPath)) {
                var d = JSON.parse(fs.readFileSync(obj.swTasksPath, 'utf8'));
                if (d && (typeof d === 'object')) { obj.swTasks = d; }
            }
        } catch (e) { obj.swTasks = {}; }
        for (var id in obj.swTasks) {
            var t = obj.swTasks[id];
            if ((t == null) || (typeof t !== 'object') || (typeof t.id !== 'string') || (t.devices == null) || (typeof t.devices !== 'object')) { delete obj.swTasks[id]; continue; }
            t.stageBusy = false; // an in-memory lock must never be resurrected from disk
            // A 'running' device whose session died with the server: nothing was ever answered -
            // queue it again instead of freezing the task forever (the pump would never wait on it).
            for (var nid in t.devices) { if (t.devices[nid] && t.devices[nid].state === 'running') { t.devices[nid].state = 'queued'; } }
        }
    };

    /** @brief Persist the deploy tasks (state file). */
    obj.swSaveTasks = function () {
        try {
            var dir = path.dirname(obj.swTasksPath);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            fs.writeFileSync(obj.swTasksPath, JSON.stringify(obj.swTasks));
        } catch (e) { obj.swLog('could not save tasks: ' + e.message); }
    };

    /** @brief Drop the oldest finished tasks beyond SW_MAX_TASKS (and their staged temp files). */
    obj.swPruneTasks = function () {
        try {
            var ids = Object.keys(obj.swTasks);
            var done = ids.filter(function (x) { return obj.swTasks[x] && obj.swTasks[x].done === true; });
            if (done.length > obj.SW_MAX_TASKS) {
                done.sort(function (a, b) { return String(obj.swTasks[a].created).localeCompare(String(obj.swTasks[b].created)); });
                while (done.length > obj.SW_MAX_TASKS) {
                    var old = obj.swTasks[done.shift()];
                    if (old != null) {
                        if (old.stageFile) { obj.swDeleteStage(old); }
                        delete obj.swTasks[old.id];
                    }
                }
                obj.swSaveTasks();
            }
        } catch (e) { }
    };

    // ---- helpers ----

    /** @brief Cryptographic hex of n bytes (never Math.random for names/ids). */
    obj.swRand = function (n) { try { return crypto.randomBytes(n).toString('hex'); } catch (e) { return crypto.createHash('sha256').update('' + Date.now() + JSON.stringify(obj.swTasks)).digest('hex').substring(0, n * 2); } };

    /** @brief Async SHA-256 of a file (a sync 2 GB hash would freeze the event loop). */
    obj.swFileHash = function (file, cb) {
        try {
            var h = crypto.createHash('sha256');
            var s = fs.createReadStream(file);
            s.on('data', function (d) { h.update(d); });
            s.on('error', function (err) { cb(err); });
            s.on('end', function () { cb(null, h.digest('hex')); });
        } catch (ex) { cb(ex); }
    };

    /** @brief Plain display name: basename only, path-hostile characters removed. */
    obj.swSanitizeName = function (name) {
        var n = String(name == null ? '' : name).split('\\').join('/');
        n = n.substring(n.lastIndexOf('/') + 1);
        n = n.replace(/["<>:|?*\u0000-\u001f]/g, '').trim();
        if (n.length > 200) { n = n.substring(0, 200); }
        return n;
    };

    /** @brief Lowercase extension of a file name, '' when unknown/unsupported. */
    obj.swExtOf = function (name) {
        var n = String(name || '');
        var dot = n.lastIndexOf('.');
        if (dot < 1 || dot < n.length - 5) return '';
        var e = n.substring(dot + 1).toLowerCase();
        return /^[a-z0-9]{1,4}$/.test(e) ? e : '';
    };

    /**
     * @brief Sanitize command-line install parameters: control characters out (newlines would break
     * the one-statement-per-line rule), max 500 chars. The quoting is complete on both shells
     * (PowerShell single quotes doubled, sh '\''-escape), so nothing can leave the string.
     * @returns {string} '' or the cleaned argument string.
     */
    obj.swSafeArgs = function (args) {
        var a = String(args == null ? '' : args).replace(/[\u0000-\u001f\u007f]/g, ' ').trim();
        if (a.length > 500) { a = a.substring(0, 500); }
        return a;
    };

    /** @brief The domain part of a node id (node/<domain>/<id>). */
    obj.swNodeDomain = function (nodeid) { var p = String(nodeid || '').split('/'); return (p.length === 3) ? p[1] : ''; };

    /** @brief URL prefix of a domain WITH leading slash: '/' default domain, '/tenant/' otherwise.
     *  The wget request path must always start with '/' (meshcore sets options.path = urlpath), and
     *  agentdownload resolves the domain from this prefix (cookie.d is checked against it) - upstream
     *  batch upload hard-codes '/agentdownload.ashx' and therefore only works in the default domain. */
    obj.swDomainUrlPrefix = function (domainid) {
        var u = null;
        try { u = obj.meshServer.config.domains[domainid].url; } catch (e) { return '/'; }
        if (u == null || u === '') return '/';
        if (!/^\/[A-Za-z0-9._-]{1,64}\/$/.test(u)) return '/';
        return u;
    };

    /** @brief MeshCentral's server-side temp area for agent downloads: <filespath>/tmp (agentdownload.ashx serves ONLY from there). */
    obj.swTmpDir = function () {
        var fsx = null;
        try { fsx = obj.meshServer.filespath; } catch (e) { }
        if (typeof fsx !== 'string' || fsx === '') { return null; }
        return path.join(fsx, 'tmp');
    };

    /**
     * @brief Mint the one-shot agentdownload cookie AT DISPATCH TIME (5-minute lifetime, verified
     * in webserver.js: decodeCookie(req.query.c, loginCookieEncryptionKey, 5)).
     * @returns {string|null} the ?c= value or null when the server cannot issue cookies.
     */
    obj.swDownloadCookie = function (nodeid, stageFile) {
        try {
            if (typeof obj.meshServer.encodeCookie !== 'function' || obj.meshServer.loginCookieEncryptionKey == null) return null;
            var c = obj.meshServer.encodeCookie({ a: 'tmpdl', d: obj.swNodeDomain(nodeid), nid: nodeid, f: stageFile }, obj.meshServer.loginCookieEncryptionKey);
            return (typeof c === 'string' && c !== '') ? c : null;
        } catch (e) { return null; }
    };

    /** @brief {file, winPath, linPath} of a task's staged copy (server-generated names only). */
    obj.swStagePaths = function (task) {
        var f = String(task.stageFile || '');
        return { file: f, winPath: 'C:\\Windows\\Temp\\' + f, linPath: '/var/tmp/' + f };
    };

    /** @brief Delete a task's staged temp copy (best effort; the stale sweep is the backstop). */
    obj.swDeleteStage = function (task) {
        try {
            var dir = obj.swTmpDir();
            if (dir != null && task.stageFile) { var p = path.join(dir, task.stageFile); if (fs.existsSync(p)) fs.unlinkSync(p); }
        } catch (e) { }
    };

    /** @brief Remove invsw-* files older than a day (left by a server restart in the middle of tasks). */
    obj.swCleanStaleStaging = function () {
        try {
            var dir = obj.swTmpDir();
            if (dir == null || !fs.existsSync(dir)) return;
            var now = Date.now();
            var names = fs.readdirSync(dir).filter(function (x) { return /^invsw-[a-f0-9-]{1,80}\.[a-z0-9]{1,4}$/.test(x); });
            for (var i = 0; i < names.length; i++) {
                var active = false;
                for (var tid in obj.swTasks) { var t = obj.swTasks[tid]; if (t && t.done !== true && t.stageFile === names[i]) { active = true; break; } }
                if (active) continue;
                var p = path.join(dir, names[i]);
                try { if (now - fs.statSync(p).mtimeMs > obj.SW_STAGE_MAX_AGE_MS) { fs.unlinkSync(p); obj.swLog('swept stale staging file ' + names[i]); } } catch (e) { }
            }
        } catch (e) { }
    };

    /**
     * @brief Resolve a task's source to an absolute server path (validated against the folders it
     * may come from - never a caller-supplied path). cb(err, { p, size }).
     */
    obj.swSourcePath = function (task, cb) {
        try {
            if (task.source && task.source.type === 'library') {
                var f = obj.swFiles[task.source.fileId];
                if (f == null) { return cb(new Error('the library file "' + task.fileName + '" no longer exists')); }
                var p = path.join(obj.swFilesDir, task.source.fileId + '.' + f.ext);
                var st = null; try { st = fs.statSync(p); } catch (e) { return cb(new Error('the library file is missing on disk')); }
                if (!st.isFile() || st.size <= 0 || st.size > obj.SW_MAX_FILE_BYTES) { return cb(new Error('library file size invalid')); }
                return cb(null, { p: p, size: st.size });
            }
            if (task.source && task.source.type === 'serverfile') {
                var tmp = obj.swTmpDir();
                if (tmp == null) { return cb(new Error('the server files folder is not available')); }
                var root = path.dirname(tmp); // <filespath>
                var parts = String(task.source.meshId || '').split('/');
                var dom = parts.length === 3 ? parts[1] : '';
                var grp = parts.length === 3 ? parts[2] : '';
                if (!/^[A-Za-z0-9._-]{1,128}$/.test(grp)) { return cb(new Error('invalid server-files group')); }
                var fname = String(task.source.name || '');
                if (!/^[^\\/:*?"<>|]{1,200}$/.test(fname) || fname.indexOf('..') >= 0 || fname.charAt(0) === '.') { return cb(new Error('invalid server-files name')); }
                var base = path.join(root, dom === '' ? 'domain' : 'domain-' + dom, 'mesh-' + grp);
                var p2 = path.resolve(base, fname);
                if (p2.indexOf(path.resolve(base) + path.sep) !== 0) { return cb(new Error('invalid server-files path')); }
                var st2 = null; try { st2 = fs.statSync(p2); } catch (e) { return cb(new Error('the server file "' + fname + '" is not readable')); }
                if (!st2.isFile() || st2.size <= 0 || st2.size > obj.SW_MAX_FILE_BYTES) { return cb(new Error('server file size invalid')); }
                return cb(null, { p: p2, size: st2.size });
            }
            cb(new Error('unknown task source'));
        } catch (ex) { cb(ex); }
    };

    /** @brief Copy the source into <filespath>/tmp once per task and hash the COPY (what the devices verify). */
    obj.swEnsureStaged = function (task, cb, waited) {
        try {
            var dir = obj.swTmpDir();
            if (dir == null) { return cb(new Error('the server temp folder (filespath/tmp) is not available')); }
            try { fs.mkdirSync(dir, { recursive: true }); } catch (e) { }
            var staged = path.join(dir, task.stageFile);
            if (task.sha256 && fs.existsSync(staged)) { return cb(null); } // already staged
            if (task.stageBusy === true) {
                // Another device of the same task is staging right now - never hash a half-written
                // copy: wait for it (copying a large file can take a while).
                if ((waited || 0) > 300) { return cb(new Error('staging did not finish in 10 minutes')); }
                setTimeout(function () { obj.swEnsureStaged(task, cb, (waited || 0) + 1); }, 2000);
                return;
            }
            task.stageBusy = true;
            obj.swSourcePath(task, function (err, src) {
                if (err) { task.stageBusy = false; return cb(err); }
                fs.copyFile(src.p, staged, function (cerr) {
                    if (cerr) { task.stageBusy = false; return cb(cerr); }
                    obj.swFileHash(staged, function (herr, sha) {
                        task.stageBusy = false;
                        if (herr) { obj.swDeleteStage(task); return cb(herr); }
                        task.sha256 = sha; task.size = src.size;
                        cb(null);
                    });
                });
            });
        } catch (ex) { task.stageBusy = false; cb(ex); }
    };
};
