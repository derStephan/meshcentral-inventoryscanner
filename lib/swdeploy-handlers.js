/**
 * @file lib/swdeploy-handlers.js
 * @brief POST handlers of the Deploy tab: installer library (chunked upload from the browser, rescan of the server-side folder), MeshCentral Server Files browser, device picker, task create/retry/cancel and the task status view.
 * Every POST is already gated by lib/routes.js (site admin + X-InvScanner-Request header); these
 * handlers validate EVERY field again - node/mesh ids, upload ids, chunk indexes, file names and
 * extensions - because the values end up in scripts that run as SYSTEM/root on the devices.
 * Uploads travel as urlencoded base64url chunks of obj.SW_CHUNK_BYTES raw bytes: the pluginadmin
 * route is parsed by body-parser's urlencoded middleware with its 100 kb default limit (verified in
 * webserver.js), so one POST body must stay below that - 48 KiB raw are 64 KiB base64, plus fields.
 *
 * Part of the MeshCentral Inventory & Vulnerability Scanner plugin; see ../inventoryscanner.js
 * for the module list and the attach order. Every member is attached to the shared plugin
 * object, so cross-module calls go through obj.name(...) and stay replaceable at runtime.
 */

"use strict";

const fs = require('fs');
const path = require('path');

/**
 * @brief Attach this module's members to one plugin instance.
 * @param {object} obj - The plugin object created by the entry point.
 */
module.exports.attach = function (obj) {
    /** @brief Shape of the library entries for the UI. */
    obj.swFileView = function (id) {
        var f = obj.swFiles[id];
        return { id: id, name: f.name, ext: f.ext, size: f.size, sha256: f.sha256, time: f.time, by: f.by };
    };

    /** @brief POST sw_files: the installer library + interrupted uploads + the limits. */
    obj.swFilesHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        try {
            obj.swStoreDirs();
            var files = Object.keys(obj.swFiles).sort(function (a, b) {
                return String(obj.swFiles[b].time).localeCompare(String(obj.swFiles[a].time));
            }).map(obj.swFileView);
            var parts = Object.keys(obj.swUploads).map(function (u) {
                return { uploadId: u, bytes: obj.swUploads[u].bytes || 0 };
            });
            send({
                files: files, parts: parts,
                limits: { chunkBytes: obj.SW_CHUNK_BYTES, maxBytes: obj.SW_MAX_FILE_BYTES, exts: obj.SW_EXTS.slice() },
                note: (files.length === 0) ? 'The library is empty - upload an installer or drop files into the plugin software folder on the server and rescan.' : ''
            });
        } catch (ex) { send({ error: ex.message }); }
    };

    /**
     * @brief POST sw_upload: one chunk of a chunked upload.
     * Fields: uploadId ([a-f0-9]{8,40}), name (original file name; first chunk only),
     * index (0-based chunk number), data (base64/base64url of SW_CHUNK_BYTES raw bytes),
     * last ('true' on the final chunk).
     * The data lands in software/parts/<uploadId>.part, so a server restart mid-upload only
     * loses the chunks that were never acked. The last chunk is hashed and committed into the
     * library with a fresh immutable id.
     */
    obj.swUploadHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        try {
            var body = req.body || {};
            var uid = String(body.uploadId || '');
            if (!/^[a-f0-9]{8,40}$/.test(uid)) { return send({ error: 'Invalid upload id (hex).' }); }
            var idx = parseInt(String(body.index), 10);
            if (isNaN(idx) || idx < 0 || idx > 200000) { return send({ error: 'Invalid chunk index.' }); }
            var up = obj.swUploads[uid];
            var partFile = path.join(obj.swPartsDir, uid + '.part');
            var isStart = (idx === 0);
            if (isStart) {
                // First chunk: (re)create the part file and validate the name/extension.
                var name = obj.swSanitizeName(body.name);
                var ext = obj.swExtOf(name);
                if (name === '' || ext === '') { return send({ error: 'Upload needs a file name with an extension.' }); }
                if (obj.SW_EXTS.indexOf(ext) < 0) { return send({ error: 'Unsupported file type .' + ext + ' (allowed: ' + obj.SW_EXTS.join(', ') + ').' }); }
                obj.swStoreDirs();
                try { if (fs.existsSync(partFile)) fs.unlinkSync(partFile); } catch (e0) { }
                up = obj.swUploads[uid] = { bytes: 0, name: name, ext: ext };
            }
            if (up == null) { return send({ error: 'Unknown upload - restart from chunk 0.', restart: true }); }
            if (typeof up.name !== 'string' || obj.SW_EXTS.indexOf(String(up.ext || '')) < 0) {
                // resumed from disk after a server restart: the name travels again with every chunk
                var rn = obj.swSanitizeName(body.name);
                var re = obj.swExtOf(rn);
                if (rn === '' || obj.SW_EXTS.indexOf(re) < 0) { return send({ error: 'Resumed upload needs its original name - send it with the next chunk (or restart from 0).' }); }
                up.name = rn; up.ext = re;
            }
            var expected = idx * obj.SW_CHUNK_BYTES;
            if (up.bytes !== expected) {
                // Out-of-order or lost chunk: never append blindly; tell the panel where to resume.
                var next = Math.floor(up.bytes / obj.SW_CHUNK_BYTES);
                return send({ error: 'Chunk order broken.', next: next, have: up.bytes });
            }
            var dataStr = String(body.data || '');
            if (dataStr.length > (obj.SW_CHUNK_BYTES * 2)) { return send({ error: 'Chunk too large.' }); }
            var data;
            try {
                data = Buffer.from(dataStr.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
            } catch (e1) { return send({ error: 'Invalid base64 chunk.' }); }
            if (data.length === 0 && !isStart) { return send({ error: 'Empty chunk.' }); }
            if (data.length > obj.SW_CHUNK_BYTES) { return send({ error: 'Chunk exceeds the negotiated size.' }); }
            if (up.bytes + data.length > obj.SW_MAX_FILE_BYTES) {
                try { fs.unlinkSync(partFile); delete obj.swUploads[uid]; } catch (e2) { }
                return send({ error: 'File exceeds the size limit.' });
            }
            try { fs.appendFileSync(partFile, data); } catch (e3) { return send({ error: 'Write failed: ' + e3.message }); }
            up.bytes += data.length;
            var last = (body.last === 'true' || body.last === true);
            if (!last) { return send({ ok: true, next: Math.ceil(up.bytes / obj.SW_CHUNK_BYTES), bytes: up.bytes }); }
            // Final chunk: hash the complete file and commit it to the library.
            if (up.bytes <= 0) {
                try { fs.unlinkSync(partFile); } catch (e6) { }
                delete obj.swUploads[uid];
                return send({ error: 'The uploaded file is empty.' });
            }
            delete obj.swUploads[uid];
            obj.swFileHash(partFile, function (herr, sha) {
                try {
                    if (herr) { try { fs.unlinkSync(partFile); } catch (e4) { } return send({ error: 'Hashing failed: ' + herr.message }); }
                    var id = obj.swRand(6);
                    var finalPath = path.join(obj.swFilesDir, id + '.' + up.ext);
                    obj.swStoreDirs();
                    fs.rename(partFile, finalPath, function (rerr) {
                        var doneMove = function () {
                            obj.swFiles[id] = { name: up.name, ext: up.ext, size: up.bytes, sha256: sha, time: new Date().toISOString(), by: String((user && user.name) || '').substring(0, 100) };
                            obj.swSaveFiles();
                            obj.swLog('library: uploaded "' + up.name + '" (' + up.bytes + ' bytes, sha256 ' + sha.substring(0, 12) + '...) by ' + ((user && user.name) || '?'));
                            send({ done: true, file: obj.swFileView(id) });
                        };
                        if (rerr && rerr.code === 'EXDEV') {
                            // Cross-device rename (parts and files on different volumes): copy+unlink.
                            fs.copyFile(partFile, finalPath, function (cerr) {
                                if (cerr) { return send({ error: 'Commit failed: ' + cerr.message }); }
                                try { fs.unlinkSync(partFile); } catch (e5) { }
                                doneMove();
                            });
                            return;
                        }
                        if (rerr) { return send({ error: 'Commit failed: ' + rerr.message }); }
                        doneMove();
                    });
                } catch (ex2) { send({ error: ex2.message }); }
            });
        } catch (ex) { send({ error: ex.message }); }
    };

    /** @brief POST sw_delete_file: remove a library entry and its stored file. */
    obj.swDeleteFileHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        var id = String((req.body || {}).fileId || '');
        if (!/^[a-f0-9]{12}$/.test(id)) { return send({ error: 'Invalid file id.' }); }
        var f = obj.swFiles[id];
        if (f == null) { return send({ error: 'Unknown file id.' }); }
        var referenced = [];
        for (var tid in obj.swTasks) {
            var t = obj.swTasks[tid];
            if (t && t.done !== true && t.source && t.source.type === 'library' && t.source.fileId === id) { referenced.push(tid); }
        }
        if (referenced.length > 0) { return send({ error: 'Open tasks still use this file (finish or cancel them first): ' + referenced.slice(0, 5).join(', ') }); }
        delete obj.swFiles[id];
        try { obj.swSaveFiles(); } catch (e) { }
        try { fs.unlinkSync(path.join(obj.swFilesDir, id + '.' + f.ext)); } catch (e) { }
        obj.swLog('library: deleted "' + f.name + '" by ' + ((user && user.name) || '?'));
        send({ success: true });
    };

    /**
     * @brief POST sw_rescan_library: index installers that were placed in the server-side folder
     * manually (any plain file name, allowed extension). A picked-up file is RENAMED to the
     * library convention <id>.<ext> (ids are immutable, uploads and rescan share the scheme) and
     * keeps its original name as the display name. Index entries whose file vanished are dropped.
     */
    obj.swRescanLibraryHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        try { obj.swStoreDirs(); } catch (e0) { }
        var names = [];
        try { names = fs.readdirSync(obj.swFilesDir); } catch (e) { return send({ error: 'Cannot read the library folder: ' + e.message }); }
        var physical = {};
        for (var id0b in obj.swFiles) { physical[obj.swFiles[id0b].id + '.' + obj.swFiles[id0b].ext] = true; }
        var toHash = names.filter(function (n) {
            if (physical[n]) return false;
            if (!/^[^\\/:*?"<>|]{1,200}$/.test(n) || n.charAt(0) === '.') return false;
            return obj.SW_EXTS.indexOf(obj.swExtOf(n)) >= 0;
        }).slice(0, 50);
        var added = 0, failed = 0, i = 0;
        var nextFile = function () {
            if (i >= toHash.length) {
                // Index entries whose file vanished from disk are dropped (honest listing).
                var removed = 0;
                for (var id in obj.swFiles) {
                    var p = path.join(obj.swFilesDir, id + '.' + obj.swFiles[id].ext);
                    if (!fs.existsSync(p)) { delete obj.swFiles[id]; removed++; }
                }
                if (added > 0 || removed > 0) { obj.swSaveFiles(); }
                obj.swLog('library rescan: ' + added + ' added, ' + removed + ' removed by ' + ((user && user.name) || '?'));
                return send({ added: added, removed: removed, failed: failed, files: Object.keys(obj.swFiles).sort(function (a, b) { return obj.swFiles[a].name.localeCompare(obj.swFiles[b].name); }).map(obj.swFileView) });
            }
            var name = toHash[i++];
            var ext = obj.swExtOf(name);
            var p2 = path.join(obj.swFilesDir, name);
            var st = null;
            try { st = fs.statSync(p2); } catch (e2) { failed++; return nextFile(); }
            if (!st.isFile() || st.size <= 0 || st.size > obj.SW_MAX_FILE_BYTES) { failed++; return nextFile(); }
            obj.swFileHash(p2, function (herr, sha) {
                if (herr) { failed++; return nextFile(); }
                var id2 = obj.swRand(6);
                try {
                    fs.renameSync(p2, path.join(obj.swFilesDir, id2 + '.' + ext));
                } catch (e3) { failed++; return nextFile(); }
                obj.swFiles[id2] = { name: name, ext: ext, size: st.size, sha256: sha, time: new Date(st.mtime).toISOString(), by: 'server folder' };
                added++;
                nextFile();
            });
        };
        nextFile();
    };

    /**
     * @brief POST sw_serverfiles: MeshCentral's own Server Files areas (the per-device-group
     * folders of the Files tab, <filespath>/domain[-x]/mesh-<name>) listed for the deploy form.
     * Only the server's own directory names and MeshCentral mesh ids are used - never a caller
     * supplied path. Flat files only, capped.
     */
    obj.swServerFilesHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        var tmp = obj.swTmpDir();
        if (tmp == null) { return send({ error: 'The server files folder is not available on this server.' }); }
        var root = path.dirname(tmp);
        obj.db.GetAllType('mesh', function (merr, meshes) {
            var folders = [];
            var list = [];
            if (!merr && meshes) {
                for (var i = 0; i < meshes.length; i++) {
                    var m = meshes[i];
                    if ((m == null) || (m._id == null) || (m.deleted != null)) continue;
                    var parts = String(m._id).split('/');
                    if (parts.length !== 3) continue;
                    list.push({ meshId: m._id, name: (m.name != null) ? m.name : parts[2], dom: parts[1], grp: parts[2] });
                }
            }
            var done = function () {
                folders.sort(function (a, b) { return String(a.name).localeCompare(String(b.name)); });
                send({ folders: folders.slice(0, 100), note: folders.length === 0 ? 'No Server Files entries - use the MeshCentral Files tab (per device group) or upload here.' : '' });
            };
            var at = 0;
            var next = function () {
                if (at >= list.length) { return done(); }
                var e = list[at++];
                if (!/^[A-Za-z0-9._-]{1,128}$/.test(e.grp)) { return next(); }
                var dir = path.join(root, e.dom === '' ? 'domain' : 'domain-' + e.dom, 'mesh-' + e.grp);
                var names = [];
                try { names = fs.readdirSync(dir); } catch (er) { return next(); }
                var files = [];
                for (var k = 0; k < names.length && files.length < 200; k++) {
                    var n = names[k];
                    if (!/^[^\\/:*?"<>|]{1,200}$/.test(n) || n.charAt(0) === '.' || n.indexOf('..') >= 0) continue;
                    var st = null;
                    try { st = fs.statSync(path.join(dir, n)); } catch (er2) { continue; }
                    if (!st.isFile() || st.size <= 0 || st.size > obj.SW_MAX_FILE_BYTES) continue;
                    files.push({ name: n, size: st.size, time: new Date(st.mtime).toISOString() });
                }
                if (files.length > 0) { folders.push({ meshId: e.meshId, name: e.name, files: files }); }
                next();
            };
            next();
        });
    };

    /** @brief POST sw_devices: everything a device could be deployed to (Windows + Linux + other). */
    obj.swDevicesHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        obj.db.GetAllType('mesh', function (merr, meshes) {
            var meshNames = {};
            if (!merr && meshes) {
                for (var mi = 0; mi < meshes.length; mi++) {
                    var m = meshes[mi];
                    if ((m != null) && (m._id != null) && (m.deleted == null)) { meshNames[m._id] = (m.name != null) ? m.name : m._id; }
                }
            }
            obj.db.GetAllType('node', function (nerr, nodes) {
                var devices = [];
                var ws = obj.meshServer.webserver;
                if (!nerr && nodes) {
                    for (var i = 0; i < nodes.length && devices.length < 2000; i++) {
                        var n = nodes[i];
                        if ((n == null) || (n._id == null) || (n.deleted != null)) continue;
                        var pf = obj.osPlatformOf(n);
                        devices.push({
                            id: n._id, host: obj.getHostName(n),
                            given: (typeof n.name === 'string' && n.name.trim() !== '') ? n.name.trim() : '',
                            group: meshNames[n.meshid] || n.meshid || '', meshid: n.meshid || '',
                            online: (ws != null && ws.wsagents != null && ws.wsagents[n._id] != null),
                            platform: pf || 'other', os: String(n.osdesc || '').substring(0, 120)
                        });
                    }
                }
                devices.sort(function (a, b) { return (a.group === b.group) ? String(a.given || a.host).localeCompare(String(b.given || b.host)) : String(a.group).localeCompare(String(b.group)); });
                send({ devices: devices });
            });
        });
    };

    /**
     * @brief POST sw_create_task: validate the source, the arguments and the targets, create the
     * task and queue every device (online ones run immediately, offline ones wait for connect).
     * Fields: source 'library'|'serverfile', fileId OR (meshId + fileName), args?, nodeIds (csv),
     * meshIds (csv - every device of those locations).
     */
    obj.swCreateTaskHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        var body = req.body || {};
        var source = null, fileName = '', ext = '';
        if (body.source === 'library') {
            var id = String(body.fileId || '');
            if (!/^[a-f0-9]{12}$/.test(id)) { return send({ error: 'Invalid library file id.' }); }
            var f = obj.swFiles[id];
            if (f == null) { return send({ error: 'Unknown library file.' }); }
            source = { type: 'library', fileId: id };
            fileName = f.name; ext = f.ext;
        } else if (body.source === 'serverfile') {
            var mids = obj.parseMeshIds(body.meshId);
            if (mids.length !== 1) { return send({ error: 'Invalid server-files group id.' }); }
            var nm = obj.swSanitizeName(body.fileName);
            if (nm === '' || nm.charAt(0) === '.' || nm.indexOf('..') >= 0 || !/^[^\\/:*?"<>|]{1,200}$/.test(nm)) { return send({ error: 'Invalid server file name.' }); }
            ext = obj.swExtOf(nm);
            if (ext === '' || obj.SW_EXTS.indexOf(ext) < 0) { return send({ error: 'Unsupported file type .' + ext + ' (allowed: ' + obj.SW_EXTS.join(', ') + ').' }); }
            source = { type: 'serverfile', meshId: mids[0], name: nm };
            fileName = nm;
        } else { return send({ error: 'source must be library or serverfile.' }); }
        var args = obj.swSafeArgs(body.args);
        var explicit = [];
        if (body.nodeIds != null && body.nodeIds !== '') {
            var arr = String(body.nodeIds).split(',');
            for (var i = 0; i < arr.length; i++) {
                var x = arr[i].trim();
                if (x === '') continue;
                if (!/^node\/[^:]{1,100}$/.test(x)) { return send({ error: 'Invalid node id: ' + x.substring(0, 60) }); }
                if (explicit.indexOf(x) < 0) explicit.push(x);
            }
        }
        var meshIds = obj.parseMeshIds(body.meshIds);
        if (explicit.length === 0 && meshIds.length === 0) { return send({ error: 'Select devices or at least one location.' }); }
        var task = obj.swCreateTask(source, args, fileName, user);
        obj.db.GetAllType('node', function (nerr, nodes) {
            if (nerr || !nodes) { delete obj.swTasks[task.id]; return send({ error: 'Could not resolve the devices.' }); }
            var targets = [];
            for (var k = 0; k < nodes.length && targets.length < obj.SW_MAX_DEVICES + 1; k++) {
                var n = nodes[k];
                if ((n == null) || (n._id == null) || (n.deleted != null)) continue;
                if (explicit.indexOf(n._id) >= 0 || (n.meshid != null && meshIds.indexOf(n.meshid) >= 0)) { targets.push(n._id); }
            }
            if (explicit.length > obj.SW_MAX_DEVICES || targets.length === 0 || targets.length > obj.SW_MAX_DEVICES) {
                delete obj.swTasks[task.id];
                return send({ error: targets.length === 0 ? 'No device matched the selection.' : ('Too many devices (max ' + obj.SW_MAX_DEVICES + ').') });
            }
            obj.swSaveTasks();
            obj.swEnqueueDevices(task.id, targets);
            obj.swLog('task ' + task.id + ' created by ' + ((user && user.name) || '?') + ': ' + fileName + (args ? (' [' + args.replace(/[\r\n]+/g, ' ') + ']') : '') + ' on ' + targets.length + ' device(s)');
            send({ taskId: task.id, devices: targets.length, note: 'Queued - offline devices install as soon as they reconnect.' });
        });
    };

    /** @brief POST sw_status: the task list for the panel (device rows capped, open tasks first). */
    obj.swStatusHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        var tasks = Object.keys(obj.swTasks).filter(function (id) { return obj.swTasks[id] != null; }).map(function (id) { return obj.swTaskView(obj.swTasks[id]); });
        tasks.sort(function (a, b) { return (a.done === b.done) ? String(b.created).localeCompare(String(a.created)) : (a.done ? 1 : -1); });
        if (tasks.length > 60) tasks = tasks.slice(0, 60);
        send({ tasks: tasks, active: obj.swActive, queued: obj.swQueue.length, running: (function () { for (var nid in obj.swPending) { if (obj.swPending[nid] != null) return true; } return false; })() });
    };

    /**
     * @brief POST sw_retry_task: run the not-yet-ok devices of a task again (or explicit ids).
     * The taskId is validated BEFORE the object lookup - a 'constructor'-style key must never
     * reach the device walk (prototype-key poisoning guard, same rule as every id in this plugin).
     */
    obj.swRetryTaskHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        var body = req.body || {};
        var tid = String(body.taskId || '');
        if (!/^[a-f0-9]{8,32}$/.test(tid) || !Object.prototype.hasOwnProperty.call(obj.swTasks, tid)) { return send({ error: 'Unknown task.' }); }
        var task = obj.swTasks[tid];
        var ids = [];
        if (body.nodeIds != null && body.nodeIds !== '') {
            var arr = String(body.nodeIds).split(',');
            for (var i = 0; i < arr.length; i++) {
                var x = arr[i].trim();
                if (x === '') continue;
                if (!/^node\/[^:]{1,100}$/.test(x)) { return send({ error: 'Invalid node id.' }); }
                if (task.devices[x] == null) { return send({ error: 'That device is not part of the task.' }); }
                if (ids.indexOf(x) < 0) ids.push(x);
            }
        } else {
            for (var nid in task.devices) { var d = task.devices[nid]; if (d && d.state !== 'ok' && d.state !== 'running') ids.push(nid); }
        }
        if (ids.length === 0) { return send({ error: 'Nothing to retry.' }); }
        task.done = false; delete task.finishTime;
        obj.swEnqueueDevices(task.id, ids);
        obj.swLog('task ' + task.id + ': retry for ' + ids.length + ' device(s) by ' + ((user && user.name) || '?'));
        send({ success: true, devices: ids.length });
    };

    /** @brief POST sw_cancel_task: drop the queued devices of a task (running ones finish). */
    obj.swCancelTaskHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        var tid = String((req.body || {}).taskId || '');
        if (!/^[a-f0-9]{8,32}$/.test(tid) || !Object.prototype.hasOwnProperty.call(obj.swTasks, tid)) { return send({ error: 'Unknown task.' }); }
        var task = obj.swTasks[tid];
        var n = 0;
        for (var nid in task.devices) {
            var d = task.devices[nid];
            // Queued devices never ran - mark them cancelled. A device whose script is already
            // running on the agent cannot be recalled safely, so it finishes normally.
            if (d && d.state === 'queued') { d.state = 'cancelled'; d.time = new Date().toISOString(); n++; }
        }
        obj.swQueue = obj.swQueue.filter(function (q) { return q.taskId !== task.id; });
        obj.swSaveTasks();
        obj.swLog('task ' + task.id + ': cancelled ' + n + ' queued device(s) by ' + ((user && user.name) || '?'));
        obj.swTaskDoneCheck(task);
        send({ success: true, cancelled: n, note: 'Devices with a running install finish normally.' });
    };
};
