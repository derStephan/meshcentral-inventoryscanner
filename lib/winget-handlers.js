/**
 * @file lib/winget-handlers.js
 * @brief POST handlers of the Updates tab: winget configuration read/write, manual/dry/single-package batches, per-device status and the aggregated Packages view.
 *
 * Part of the MeshCentral Inventory & Vulnerability Scanner plugin; see ../inventoryscanner.js
 * for the module list and the attach order. Every member is attached to the shared plugin
 * object, so cross-module calls go through obj.name(...) and stay replaceable at runtime.
 */

"use strict";

/**
 * @brief Attach this module's members to one plugin instance.
 * @param {object} obj - The plugin object created by the entry point.
 */
module.exports.attach = function (obj) {
    /** @brief POST wg_get_config: effective winget-updater config + per-key source. */
    obj.wgGetConfigHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        var wcfg = obj.wingetConfig();
        var over = obj.pluginSettings.wingetUpdater || {};
        var b = null;
        try { b = obj.meshServer.config.settings.wingetUpdater; } catch (e) { }
        var srcOf = function (key) {
            if (Object.prototype.hasOwnProperty.call(over, key)) { return 'file'; }
            if (b && Object.prototype.hasOwnProperty.call(b, key)) { return 'config.json'; }
            return 'default';
        };
        send({
            config: {
                enabled: wcfg.enabled, scheduling: obj.WINGET_SCHEDULING_DESC,
                updateMeshes: wcfg.meshes || [], excludeNodes: wcfg.excludeNodes,
                ignorePackages: wcfg.ignorePackages, pinSync: wcfg.pinSync
            },
            sources: {
                enabled: srcOf('enabled'),
                updateMeshes: srcOf('updateMeshes'), excludeNodes: srcOf('excludeNodes'),
                ignorePackages: srcOf('ignorePackages'), pinSync: srcOf('pinSync')
            },
            running: obj.wgBatchRunning, active: obj.wgActive, queued: obj.wgQueue.length
        });
    };

    /** @brief POST wg_save_config: validate everything, store override, reschedule. */
    obj.wgSaveConfigHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        var body = (req.body || {});
        var meshes = obj.parseMeshIds(body.updateMeshes);
        var excludes = [];
        if (typeof body.excludeNodes === 'string') {
            excludes = body.excludeNodes.split(',').map(function (x) { return x.trim(); }).filter(function (x) { return x !== ''; });
        } else if (Array.isArray(body.excludeNodes)) { excludes = body.excludeNodes; }
        for (var ei = 0; ei < excludes.length; ei++) {
            if (typeof excludes[ei] !== 'string' || !/^node\/[^:]{1,100}$/.test(excludes[ei])) { return send({ error: 'Invalid excluded node id.' }); }
        }
        var ignore = [];
        var ig = body.ignorePackages;
        if (typeof ig === 'string') { try { ig = JSON.parse(ig); } catch (e) { ig = null; } }
        if (ig == null) { ig = []; }
        if (!Array.isArray(ig) || ig.length > 500) { return send({ error: 'Invalid ignore list (max 500 entries).' }); }
        for (var ii = 0; ii < ig.length; ii++) {
            var ent = ig[ii];
            if ((ent == null) || (typeof ent.id !== 'string') || !obj.WINGET_ID_RE.test(ent.id.trim())) { return send({ error: 'Invalid package id in ignore list.' }); }
            var nid = ent.id.trim();
            if (!ignore.some(function (x) { return x.id === nid; })) {
                ignore.push({ id: nid, note: (typeof ent.note === 'string') ? ent.note.trim().substring(0, 200) : '' });
            }
        }
        obj.pluginSettings.wingetUpdater = {
            enabled: obj.boolSetting(body.enabled, false),
            updateMeshes: meshes,
            excludeNodes: excludes,
            ignorePackages: ignore,
            pinSync: obj.boolSetting(body.pinSync, true)
        };
        obj.savePluginSettings(function (err) {
            if (err) { return send({ error: err.message }); }
            obj.rescheduleAll();
            obj.wgGetConfigHandler({}, res, user);
        });
    };

    /**
     * @brief POST wg_run: manual batch; optional nodeIds (one or several
     *   devices, bypasses scope filters), dry=true (report only) and the
     *   per-package mode: pkgId (exact winget id, validated) limits the batch
     *   to that ONE package across all targeted devices, mode 'update'
     *   (default) upgrades it everywhere, 'uninstall' removes it everywhere
     *   (devices without the package report 'not-installed'). Uninstall never
     *   runs dry and always requires pkgId.
     */
    obj.wgRunHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        if (obj.wgBatchRunning || obj.osBatchRunning) { return send({ started: false, busy: true }); }
        var body = (req.body || {});
        var ids = null;
        if (body.nodeIds != null) {
            var arr = body.nodeIds;
            if (typeof arr === 'string') { try { arr = JSON.parse(arr); } catch (e) { arr = arr.split(','); } }
            if (!Array.isArray(arr)) arr = [arr];
            ids = [];
            for (var i = 0; i < arr.length && ids.length < 200; i++) {
                var x = String(arr[i] == null ? '' : arr[i]).trim();
                if (x !== '' && /^node\/[^:]{1,100}$/.test(x) && ids.indexOf(x) < 0) ids.push(x);
            }
            if (ids.length === 0) { return send({ error: 'Invalid nodeIds.' }); }
        }
        var dry = (body.dry === 'true' || body.dry === true);
        var pkgId = (typeof body.pkgId === 'string') ? body.pkgId.trim() : '';
        var mode = (body.mode === 'uninstall') ? 'uninstall' : (body.mode === 'update' ? 'update' : '');
        if (pkgId !== '' && !obj.WINGET_ID_RE.test(pkgId)) { return send({ error: 'Invalid package id.' }); }
        if (mode === 'uninstall') {
            if (pkgId === '') { return send({ error: 'Uninstall needs an exact package id.' }); }
            if (dry) { return send({ error: 'Uninstall does not support dry runs.' }); }
        }
        var opts = (pkgId !== '' || mode !== '') ? { onlyId: (pkgId !== '' ? pkgId : null), mode: (mode !== '' ? mode : 'update') } : null;
        if (opts != null && opts.onlyId == null) delete opts.onlyId;
        var reason = (mode === 'uninstall') ? 'pkg-uninstall' : (pkgId !== '' ? 'pkg-update' : (dry ? 'dry-run' : 'manual'));
        var r = obj.wgStartBatch(reason, null, ids, dry, opts);
        send({ started: !!r.started, busy: !!r.busy, dry: dry, pkgId: pkgId, mode: (mode !== '' ? mode : 'update'), devices: ids == null ? -1 : ids.length });
    };

    /**
     * @brief POST wg_programs: the per-program view across all devices.
     * Aggregates the stored per-device run results (last run per device, dry
     * or real) into one row per winget package id: which devices carry it,
     * from which version to which, and which state the last run produced -
     * the base for "update/uninstall this program on every device at once".
     * Stale device ids (deleted nodes) are dropped.
     */
    obj.wgProgramsHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        obj.db.GetAllType('node', function (nerr, nodes) {
            var labels = {};
            if (!nerr && nodes) {
                for (var i = 0; i < nodes.length; i++) {
                    var n = nodes[i];
                    if ((n == null) || (n._id == null) || (n.deleted != null)) continue;
                    labels[n._id] = ((typeof n.name === 'string' && n.name.trim() !== '') ? n.name.trim() : '') || obj.getHostName(n) || n._id;
                }
            }
            var byId = {}, order = [];
            var nodeids = Object.keys(obj.wgResults);
            for (var k = 0; k < nodeids.length; k++) {
                var rec = obj.wgResults[nodeids[k]];
                if ((rec == null) || (labels[nodeids[k]] == null)) continue; // deleted/unknown device
                var rl = Array.isArray(rec.results) ? rec.results : [];
                for (var ri = 0; ri < rl.length; ri++) {
                    var r2 = rl[ri];
                    if ((r2 == null) || (typeof r2.id !== 'string') || r2.id === '') continue;
                    var p = byId[r2.id];
                    if (p == null) { p = byId[r2.id] = { id: r2.id, name: '', devices: [], ready: 0, ok: 0, failed: 0, skipped: 0 }; order.push(r2.id); }
                    if ((p.name === '') && (typeof r2.name === 'string')) { p.name = r2.name; }
                    var st = String(r2.state || '');
                    if (st === 'dry-run') p.ready++;
                    else if (st === 'ok') p.ok++;
                    else if (st === 'failed') p.failed++;
                    else p.skipped++;
                    p.devices.push({ node: nodeids[k], label: labels[nodeids[k]], state: st || 'unknown', from: String(r2.from || '').substring(0, 60), to: String(r2.to || '').substring(0, 60), time: rec.time || '', dry: rec.dry === true });
                }
            }
            var pkgs = order.map(function (x) { return byId[x]; });
            pkgs.sort(function (a, b) { return (b.ready + b.failed) - (a.ready + a.failed) || String(a.id).localeCompare(String(b.id)); });
            if (pkgs.length > 400) pkgs = pkgs.slice(0, 400);
            for (var pi = 0; pi < pkgs.length; pi++) { if (pkgs[pi].devices.length > 200) pkgs[pi].devices = pkgs[pi].devices.slice(0, 200); }
            send({ packages: pkgs, note: (pkgs.length === 0) ? 'No stored run results yet - start a dry run to populate this table.' : '' });
        });
    };

    /**
     * @brief POST wg_status: per-device table for the Updates tab.
     * All desktop nodes with group, online flag, exclusion and the compact
     * summary of the last run (ok/skipped/failed counts, error state).
     */
    obj.wgStatusHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        var wcfg = obj.wingetConfig();
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
                    for (var i = 0; i < nodes.length; i++) {
                        var n = nodes[i];
                        if ((n == null) || (n._id == null) || (n.deleted != null)) continue;
                        if (!obj.wgIsWindowsNode(n)) continue;
                        var rec = obj.wgResults[n._id];
                        var sum = null;
                        if (rec != null) {
                            var okN = 0, skN = 0, faN = 0, wdN = 0;
                            var pkgRows = [];
                            var rl = Array.isArray(rec.results) ? rec.results : [];
                            for (var ri = 0; ri < rl.length; ri++) {
                                var s = (rl[ri] && rl[ri].state) ? rl[ri].state : '';
                                // Every package row of the last run (dry or real) goes into rows so the
                                // panel can list outcome, exit code and winget's message per package -
                                // nobody should need the client transcript to find out what failed.
                                if (s === 'ok') okN++;
                                else if (s === 'dry-run') wdN++;
                                else if (s.indexOf('skipped') === 0 || s === 'not-installed') skN++; else faN++;
                                if (rl[ri] != null && pkgRows.length < 200) {
                                    pkgRows.push({ id: String(rl[ri].id || '').substring(0, 128), name: String(rl[ri].name || '').substring(0, 200), from: String(rl[ri].from || '').substring(0, 60), to: String(rl[ri].to || '').substring(0, 60), state: s || 'unknown', exit: (typeof rl[ri].exit === 'number') ? rl[ri].exit : null, log: String(rl[ri].log || '').substring(0, 500) });
                                }
                            }
                            sum = { time: rec.time, winget: rec.winget === true, dry: rec.dry === true, ok: okN, would: wdN, skipped: skN, failed: faN, error: rec.error || '', rows: pkgRows };
                        }
                        devices.push({
                            id: n._id, host: obj.getHostName ? obj.getHostName(n) : (n.rname || n.name || n._id),
                            given: (typeof n.name === 'string' && n.name.trim() !== '') ? n.name.trim() : '',
                            group: meshNames[n.meshid] || n.meshid || '',
                            online: (ws != null && ws.wsagents != null && ws.wsagents[n._id] != null),
                            excluded: wcfg.excludeNodes.indexOf(n._id) >= 0,
                            inScope: (wcfg.meshes == null) ? false : (wcfg.meshes.indexOf(n.meshid) >= 0),
                            last: sum, pending: (obj.wgPending != null && obj.wgPending[n._id] != null) ? { since: (obj.wgPending[n._id].since || 0) } : null
                        });
                    }
                }
                devices.sort(function (a, b) { return (a.group === b.group) ? String(a.given || a.host).localeCompare(String(b.given || b.host)) : String(a.group).localeCompare(String(b.group)); });
                send({
                    devices: devices, running: obj.wgBatchRunning, active: obj.wgActive, queued: obj.wgQueue.length,
                    config: { enabled: wcfg.enabled, scheduling: obj.WINGET_SCHEDULING_DESC, updateMeshes: wcfg.meshes || [], excludeNodes: wcfg.excludeNodes, ignorePackages: wcfg.ignorePackages, pinSync: wcfg.pinSync }
                });
            });
        });
    };
};
