/**
 * @file lib/collector.js
 * @brief Live inventory collection from agents: installed software and pending Windows updates, captured through the routeAgentCommand hook and cached under data/<nodeid>/.
 * Only session-less replies are ours (the plugin sends no sessionid, the agent echoes one) and an error answer never overwrites the last good list.
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
    /** @type {Object<string, boolean>} Set of pending live collection requests (nodeid -> true). */
    obj.pendingCollection = {};

    /** @type {Object<string, boolean>} Set of pending Windows-update collection requests (nodeid -> true). */
    obj.pendingWinUpdates = {};

    /** @type {boolean} True once the webserver.routeAgentCommand hook has been installed. */
    obj.routeHookInstalled = false;

    // ---- Live inventory collection (installed software & patches) ----
    // MeshCentral does NOT persist installed software / patches anywhere in the
    // database (meshagent.js: "Todo - save software into database for offline
    // access but send to web clients for now"). The device-list UI fetches them
    // live from the agent on demand. This plugin therefore collects them from
    // online agents on a schedule and stores them in its own database so that
    // CSV exports and CVE scans can work offline.

    /**
     * @brief Read the live-collection configuration from the server settings.
     * Reads <code>meshserver.config.settings.inventoryScanner</code>:
     * <code>collectIntervalMinutes</code> (default 1440 = daily, 0 disables) and
     * <code>collectOnAgentConnect</code> (default true).
     * @returns {object} <code>{ intervalMinutes, collectOnAgentConnect }</code>.
     */
    obj.collectorConfig = function () {
        var cfg = null;
        try { cfg = obj.effectiveSectionConfig('inventoryScanner'); } catch (e) { }
        var intervalMinutes = 24 * 60; // default: daily (24h)
        var collectOnAgentConnect = true;
        if (cfg && (typeof cfg === 'object')) {
            if (typeof cfg.collectIntervalMinutes === 'number' && cfg.collectIntervalMinutes >= 0) { intervalMinutes = cfg.collectIntervalMinutes; }
            if (typeof cfg.collectOnAgentConnect === 'boolean') { collectOnAgentConnect = cfg.collectOnAgentConnect; }
        }
        return { intervalMinutes: intervalMinutes, collectOnAgentConnect: collectOnAgentConnect };
    };

    /**
     * @brief Build a safe filesystem fragment from a node id.
     * Node ids contain <code>node/&lt;domain&gt;/&lt;id&gt;</code>; the final segment
     * is used, cleaned of path-hostile characters.
     * @param {string} nodeId - The node id.
     * @returns {string} A safe directory name.
     */
    obj.safeNodeDir = function (nodeId) {
        if (!nodeId) return 'unknown';
        var parts = String(nodeId).split('/');
        var last = parts[parts.length - 1] || 'unknown';
        return last.replace(/[^A-Za-z0-9._-]/g, '_').substring(0, 120);
    };

    /**
     * @brief Path to the collected software file for a node.
     * @param {string} nodeId - The node id.
     * @returns {string} The JSON file path.
     */
    obj.softwarePathForNode = function (nodeId) {
        return path.join(obj.inventoryDataPath, obj.safeNodeDir(nodeId), 'software.json');
    };

    /**
     * @brief Path to the collected Windows-updates state file for a node.
     * @param {string} nodeId - The node id.
     * @returns {string} The JSON file path.
     */
    obj.windowsUpdatesPathForNode = function (nodeId) {
        return path.join(obj.inventoryDataPath, obj.safeNodeDir(nodeId), 'windowsupdates.json');
    };

    /**
     * @brief Path to the collection meta file for a node.
     * @param {string} nodeId - The node id.
     * @returns {string} The JSON file path.
     */
    obj.metaPathForNode = function (nodeId) {
        return path.join(obj.inventoryDataPath, obj.safeNodeDir(nodeId), 'meta.json');
    };

    /**
     * @brief Load all previously collected inventory files into memory.
     */
    obj.loadCollectedInventory = function () {
        try {
            if (!fs.existsSync(obj.inventoryDataPath)) { fs.mkdirSync(obj.inventoryDataPath, { recursive: true }); }
            var dirs = fs.readdirSync(obj.inventoryDataPath, { withFileTypes: true });
            for (var i = 0; i < dirs.length; i++) {
                if (!dirs[i].isDirectory()) continue;
                var dir = path.join(obj.inventoryDataPath, dirs[i].name);
                try {
                    var sf = path.join(dir, 'software.json');
                    if (fs.existsSync(sf)) { obj.softwareInventory[dirs[i].name] = JSON.parse(fs.readFileSync(sf, 'utf8')); }
                } catch (e) { }
                try {
                    var wf = path.join(dir, 'windowsupdates.json');
                    if (fs.existsSync(wf)) { obj.windowsUpdates[dirs[i].name] = JSON.parse(fs.readFileSync(wf, 'utf8')); }
                } catch (e) { }
            }
            obj.debug('plugin:inventory_scanner', 'Loaded collected inventory for', Object.keys(obj.softwareInventory).length, 'nodes');
        } catch (e) {
            obj.debug('plugin:inventory_scanner', 'Error loading collected inventory:', e.message);
        }
    };

    /**
     * @brief Persist the collected software list for a node to disk.
     * @param {string} nodeId - The node id.
     * @param {object} entry - <code>{ time, apps }</code>.
     */
    obj.saveSoftwareInventory = function (nodeId, entry) {
        try {
            var dir = path.join(obj.inventoryDataPath, obj.safeNodeDir(nodeId));
            fs.mkdirSync(dir, { recursive: true });
            fs.writeFileSync(obj.softwarePathForNode(nodeId), JSON.stringify(entry, null, 2));
            fs.writeFileSync(obj.metaPathForNode(nodeId), JSON.stringify({ time: entry.time }, null, 2));
        } catch (e) { obj.debug('plugin:inventory_scanner', 'Error saving software inventory:', e.message); }
    };

    /**
     * @brief Persist the collected Windows-updates state for a node to disk.
     * @param {string} nodeId - The node id.
     * @param {object} entry - <code>{ time, count, updates }</code>.
     */
    obj.saveWindowsUpdates = function (nodeId, entry) {
        try {
            var dir = path.join(obj.inventoryDataPath, obj.safeNodeDir(nodeId));
            fs.mkdirSync(dir, { recursive: true });
            fs.writeFileSync(obj.windowsUpdatesPathForNode(nodeId), JSON.stringify(entry, null, 2));
            fs.writeFileSync(obj.metaPathForNode(nodeId), JSON.stringify({ time: entry.time }, null, 2));
        } catch (e) { obj.debug('plugin:inventory_scanner', 'Error saving Windows updates:', e.message); }
    };

    /**
     * @brief Install a runtime hook on the webserver's routeAgentCommand so that
     * agent responses to this plugin's collection commands are captured
     * server-side. This is injected on every server start and is entirely owned
     * by this plugin (never overwritten by MeshCentral updates).
     */
    obj.installRouteHook = function () {
        try {
            var ws = obj.meshServer.webserver;
            if ((ws == null) || (typeof ws.routeAgentCommand !== 'function')) {
                if (!obj.routeHookRetryPending) {
                    obj.routeHookRetryPending = true;
                    setTimeout(function () { obj.routeHookRetryPending = false; try { obj.installRouteHook(); } catch (e) { } }, 2000);
                }
                return;
            }
            if (ws.__inventoryscannerHookInstalled === true) { obj.routeHookInstalled = true; return; }
            var self = obj;
            var original = ws.routeAgentCommand.bind(ws);
            ws.routeAgentCommand = function (command, domainid, nodeid, meshid) {
                try {
                    if ((command != null) && (typeof command === 'object')) {
                        // Dispatch to whichever instance currently owns the slot, so a
                        // hot-swap during an upgrade keeps this hook alive on the new code.
                        var inst = (self.parent != null && self.parent.plugins != null) ? (self.parent.plugins[self.shortName] || self) : self;
                        if (inst.onAgentResponse(command, domainid, nodeid, meshid) === true) { return; }
                    }
                } catch (e) { }
                return original(command, domainid, nodeid, meshid);
            };
            ws.__inventoryscannerHookInstalled = true;
            obj.routeHookInstalled = true;
            obj.debug('plugin:inventory_scanner', 'Installed routeAgentCommand hook for live inventory collection');
        } catch (e) {
            obj.debug('plugin:inventory_scanner', 'Error installing route hook:', e.message);
        }
    };

    /**
     * @brief Handle an agent response routed by the server.
     * Captures software (installed apps / packages) and patch (QFE) responses
     * that belong to this plugin's collection requests.
     * @param {object} command - The response command from the agent.
     * @param {string} domainid - The domain id.
     * @param {string} nodeid - The node id the response came from.
     * @param {string} meshid - The mesh id.
     */
    obj.onAgentResponse = function (command, domainid, nodeid, meshid) {
        if ((nodeid == null) || (command == null)) return false;
        if (command.action === 'software') {
            // Only capture responses to this plugin's own collection requests: the agent answers
            // with sessionid = the request's sessionid, and the plugin sends none, so a reply WITH a
            // sessionid belongs to a browser session (Software tab) and is neither stored nor
            // consumed. Our own session-less reply is consumed, so it is not broadcast to every
            // user session with rights on the node (v3.0.1).
            if ((obj.pendingCollection[nodeid] === true) && (command.sessionid == null)) {
                obj.handleSoftwareResponse(nodeid, command);
                return true;
            }
            return false; // a UI-triggered request: route to the browser
        } else if ((command.action === 'msg') && (command.type === 'runcommands')) {
            // Software deploy sessions (v4.0.0): own prefix, same ownership rules as winget/OS.
            var swOurs = (((typeof command.sessionid === 'string') && (command.sessionid.indexOf('invscanner-sw-') === 0)) || ((typeof command.responseid === 'string') && (command.responseid.indexOf('invscanner-sw-') === 0)));
            if (!swOurs && (obj.swPending != null) && (obj.swPending[nodeid] != null) && (command.sessionid == null) && (command.responseid == null)) { swOurs = true; }
            if (swOurs) { obj.swHandleResponse(nodeid, command); return true; }
            // OS update sessions (v3.5.0): own prefix, same ownership rules as winget.
            var osOurs = (((typeof command.sessionid === 'string') && (command.sessionid.indexOf('invscanner-os-') === 0)) || ((typeof command.responseid === 'string') && (command.responseid.indexOf('invscanner-os-') === 0)));
            if (!osOurs && (obj.osPending[nodeid] != null) && (command.sessionid == null) && (command.responseid == null)) { osOurs = true; }
            if (osOurs) { obj.osHandleResponse(nodeid, command); return true; }
            // Answer to one of our update sessions (agent builds differ on whether the
            // reply carries sessionid, responseid or both - accept any prefix hit).
            var ours = (((typeof command.sessionid === 'string') && (command.sessionid.indexOf('invscanner-wg-') === 0)) || ((typeof command.responseid === 'string') && (command.responseid.indexOf('invscanner-wg-') === 0)));
            // Session-less answers (some agent builds) are only accepted while a run is pending for
            // that node AND the reply carries no session field at all - a reply addressed to another
            // (browser) session is never taken over (v3.0.1).
            if (!ours && (obj.wgPending != null) && (obj.wgPending[nodeid] != null) && (command.sessionid == null) && (command.responseid == null)) { ours = true; }
            if (ours) {
                obj.wgHandleResponse(nodeid, command);
                return true; // consumed - the marker JSON is plugin-internal
            }
            return false;
        } else if ((command.action === 'msg') && (command.type === 'console')) {
            // Winget answers arriving on the console channel (some agent builds emit
            // runcommands output as console text): capture when a wg session is pending.
            // Packets chunk the output, so the answer line can span several packets -
            // text accumulates on the pending entry and is only consumed once the
            // payload is complete and parses (otherwise the runcommands reply or the
            // watchdog finishes the session).
            var swe = obj.swPending[nodeid];
            var swConsoleOurs = (command.sessionid == null) || ((typeof command.sessionid === 'string') && (command.sessionid.indexOf('invscanner-sw-') === 0));
            if ((typeof command.value === 'string') && (swe != null) && swConsoleOurs) {
                swe.cbuf = (typeof swe.cbuf === 'string' ? swe.cbuf : '') + command.value;
                if (swe.cbuf.length > 262144) swe.cbuf = swe.cbuf.substring(swe.cbuf.length - 131072);
                if (obj.wgPayloadFromText(swe.cbuf, obj.SW_MARKER) != null) { obj.swHandleResponse(nodeid, { result: swe.cbuf }); return true; }
            }
            if ((typeof command.sessionid === 'string') && (command.sessionid.indexOf('invscanner-sw-') === 0)) {
                var swtext = String(command.value || '').substring(0, 200).replace(/[\r\n]+/g, ' ');
                if (swtext !== '') { obj.swLog(nodeid + ' - agent console: ' + swtext); }
            }
            var wge = (obj.wgPending != null) ? obj.wgPending[nodeid] : null;
            var ose = obj.osPending[nodeid];
            var osConsoleOurs = (command.sessionid == null) || ((typeof command.sessionid === 'string') && (command.sessionid.indexOf('invscanner-os-') === 0));
            if ((typeof command.value === 'string') && (ose != null) && osConsoleOurs) {
                ose.cbuf = (typeof ose.cbuf === 'string' ? ose.cbuf : '') + command.value;
                if (ose.cbuf.length > 262144) ose.cbuf = ose.cbuf.substring(ose.cbuf.length - 131072);
                if (obj.wgPayloadFromText(ose.cbuf, obj.OS_MARKER) != null) { obj.osHandleResponse(nodeid, { result: ose.cbuf }); return true; }
            }
            if ((typeof command.sessionid === 'string') && (command.sessionid.indexOf('invscanner-os-') === 0)) {
                var otext = String(command.value || '').substring(0, 200).replace(/[\r\n]+/g, ' ');
                if (otext !== '') { obj.osLog(nodeid + ' - agent console: ' + otext); }
            }
            // The agent's runcommands child echoes its output with sendConsoleText() WITHOUT a
            // sessionid (verified in meshcore.js), so only session-less console text or text on our
            // own wg session is buffered - console output of an admin's terminal session is left alone.
            var wgConsoleOurs = (command.sessionid == null) || ((typeof command.sessionid === 'string') && (command.sessionid.indexOf('invscanner-wg-') === 0));
            if ((typeof command.value === 'string') && (wge != null) && wgConsoleOurs) {
                wge.cbuf = (typeof wge.cbuf === 'string' ? wge.cbuf : '') + command.value;
                if (wge.cbuf.length > 262144) wge.cbuf = wge.cbuf.substring(wge.cbuf.length - 131072);
                if (obj.wgPayloadFromText(wge.cbuf) != null) {
                    obj.wgLog(nodeid + ' - answer captured via console channel');
                    obj.wgHandleResponse(nodeid, { result: wge.cbuf });
                    return true;
                }
            }
            // Windows-update status responses come back as console text. They are
            // identified by the plugin's own sessionid prefix; when captured we
            // consume them and do NOT forward them to browser clients.
            if ((command.sessionid != null) && (typeof command.sessionid === 'string') && (command.sessionid.indexOf('invscanner-wg-') === 0)) {
                var ctext = String(command.value || '').substring(0, 200).replace(/[\r\n]+/g, ' ');
                if (ctext !== '') { obj.wgLog(nodeid + ' - agent console: ' + ctext); }
            }
            if ((command.sessionid != null) && (typeof command.sessionid === 'string') && (command.sessionid.indexOf('invscanner-') === 0)) {
                if (obj.pendingWinUpdates[nodeid] === true && obj.looksLikeWindowsUpdatesResponse(command.value)) {
                    obj.handleWindowsUpdatesResponse(nodeid, command.value);
                    return true; // consumed, suppress browser forwarding
                }
            }
        }
        return false;
    };

    /**
     * @brief Heuristic check that a console value looks like the result of the
     * agent's <code>winupdates</code> command, i.e. the "Pending Updates (N):"
     * summary produced by <code>getAvailableUpdates()</code>.
     * @param {*} value - The console value.
     * @returns {boolean} True if the value looks like a pending-updates summary.
     */
    obj.looksLikeWindowsUpdatesResponse = function (value) {
        try {
            if (typeof value !== 'string') return false;
            var t = value.trim();
            // The final/meaningful results (the "Checking for pending updates..."
            // interim message is deliberately NOT treated as a result).
            if (/^Pending Updates \(\d+\):/.test(t)) return true;
            if (/^No pending updates\./i.test(t)) return true;
            if (/^Windows updates not supported/.test(t)) return true;
        } catch (e) { }
        return false;
    };

    /**
     * @brief Whether a software response is expected for a node.
     * @param {string} nodeId - The node id.
     * @returns {boolean} True if a collection request is pending.
     */
    obj.hasPendingSoftware = function (nodeId) {
        return obj.pendingCollection[nodeId] === true;
    };

    /**
     * @brief Store the parsed Windows-update status for a node.
     * Parses the "Pending Updates (N):" console summary and stores the count.
     * @param {string} nodeId - The node id.
     * @param {string} value - The console text.
     */
    obj.handleWindowsUpdatesResponse = function (nodeId, value) {
        var updates = [];
        try {
            var text = String(value);
            var lines = text.split('\n');
            for (var i = 0; i < lines.length; i++) {
                var lm = lines[i].match(/^\s*\[\d+\]\s+(.*)$/);
                if (lm) {
                    var title = lm[1];
                    var sev = '';
                    var sM = title.match(/\[(.*)\]$/);
                    if (sM) { sev = sM[1]; title = title.substring(0, sM.index).trim(); }
                    var kbs = [];
                    var kbM = title.match(/KB\d+/gi);
                    if (kbM) { for (var k = 0; k < kbM.length; k++) { kbs.push(kbM[k]); } }
                    updates.push({ title: title, kbArticleIDs: kbs, severity: sev });
                }
            }
        } catch (e) { updates = []; }

        // Count only security-relevant updates (Critical / Important). Optional,
        // Moderate and unknown-severity updates are ignored to avoid false
        // positives from a single optional driver update.
        var sevRank = { 'critical': 2, 'important': 1 };
        var filtered = [];
        for (var u = 0; u < updates.length; u++) {
            var s = String(updates[u].severity || '').trim().toLowerCase();
            if (sevRank[s]) { filtered.push(updates[u]); }
        }
        var count = filtered.length;

        var key = obj.safeNodeDir(nodeId);
        obj.windowsUpdates[key] = { time: new Date().toISOString(), count: count, updates: filtered };
        obj.saveWindowsUpdates(nodeId, obj.windowsUpdates[key]);
        if (obj.pendingWinUpdates) { delete obj.pendingWinUpdates[nodeId]; }
        obj.debug('plugin:inventory_scanner', 'Collected Windows updates status:', count, 'critical/important pending for', nodeId);
    };

    /**
     * @brief Store the parsed software response for a node.
     * @param {string} nodeId - The node id.
     * @param {object} command - The response command (<code>value</code> is a JSON string).
     */
    obj.handleSoftwareResponse = function (nodeId, command) {
        delete obj.pendingCollection[nodeId];
        var apps = null, why = 'unrecognized answer';
        try {
            var raw = command.value;
            if (typeof raw === 'string') {
                var parsed = JSON.parse(raw);
                if (Array.isArray(parsed)) { apps = parsed; }
                else if ((parsed != null) && (typeof parsed === 'object') && Array.isArray(parsed.value)) { apps = parsed.value; }
                else if ((parsed != null) && (typeof parsed === 'object') && (parsed.error != null)) { why = 'agent error: ' + String(parsed.error).substring(0, 120); }
            } else if (Array.isArray(raw)) { apps = raw; }
        } catch (e) { apps = null; why = 'unparsable answer'; }
        // An error answer ("Denied", "Not supported", ...) must never overwrite the last good
        // inventory with an empty list - empty would read as "nothing installed" (v3.0.1).
        if (apps == null) {
            obj.debug('plugin:inventory_scanner', 'Software collection for', nodeId, 'not stored -', why);
            return;
        }
        if (apps.length > 20000) { apps = apps.slice(0, 20000); } // a device never has more; caps disk/memory use
        obj.softwareInventory[obj.safeNodeDir(nodeId)] = { time: new Date().toISOString(), apps: apps };
        obj.saveSoftwareInventory(nodeId, obj.softwareInventory[obj.safeNodeDir(nodeId)]);
        obj.debug('plugin:inventory_scanner', 'Collected', apps.length, 'software entries for', nodeId);
    };

    /**
     * @brief Schedule periodic live inventory collection.
     * Uses <code>collectIntervalMinutes</code> (default 1440 = daily); disabled if 0.
     */
    obj.scheduleInventoryCollection = function () {
        var cfg = obj.collectorConfig();
        if (cfg.intervalMinutes <= 0) { obj.debug('plugin:inventory_scanner', 'Live inventory collection is disabled (collectIntervalMinutes=0)'); return; }
        obj.debug('plugin:inventory_scanner', 'Live inventory collection every', cfg.intervalMinutes, 'minutes');
        var gen = obj.timerGen;
        // First pass shortly after startup (agents may need a moment to reconnect),
        // then keep collecting periodically.
        setTimeout(function () { if (obj.timerValid(gen)) { obj.collectAndReschedule(); } }, 20000);
    };

    /**
     * @brief Run one collection cycle and reschedule the next one after the interval.
     * @param {number} intervalMs - The delay in milliseconds before the next cycle.
     */
    obj.collectAndReschedule = function () {
        var gen = obj.timerGen;
        obj.collectAllOnline();
        // Re-read the config every cycle so settings saved in the UI take effect
        // without a restart; stop the chain if collection was disabled meanwhile.
        var intervalMs = obj.collectorConfig().intervalMinutes * 60 * 1000;
        if (intervalMs <= 0) { return; }
        obj.longTimeout(function () { if (obj.timerValid(gen)) { obj.collectAndReschedule(); } }, intervalMs);
    };

    /**
     * @brief Send collection commands to all currently online agents.
     * Asks each online agent for its installed software and (on Windows) its QFE patches.
     */
    obj.collectAllOnline = function () {
        try {
            var ws = obj.meshServer.webserver;
            if ((ws == null) || (ws.wsagents == null)) return;
            for (var nodeid in ws.wsagents) {
                var agent = ws.wsagents[nodeid];
                if (agent == null) continue;
                obj.collectNodeSequential(nodeid, agent);
            }
        } catch (e) {
            obj.debug('plugin:inventory_scanner', 'Error during inventory collection:', e.message);
        }
    };

    /**
     * @brief Send a software-collection command to a single agent.
     * @param {string} nodeId - The node id.
     * @param {object} agent - The agent websocket object.
     */
    obj.collectNodeSoftware = function (nodeId, agent) {
        try {
            if (typeof agent.send !== 'function') return;
            obj.pendingCollection[nodeId] = true;
            // Since MeshCentral commit cdc9582ada (2026-11-09) the agent refuses 'software'
            // commands without a numeric rights field. The server-side collector sends the least
            // value that permits the inventory read: Remote Control (8), NOT the full-admin mask -
            // uninstall types stay refused by the agent. Older agents ignore the field.
            agent.send(JSON.stringify({ action: 'software', type: 'installedapps', rights: 8, responseid: 'invscanner' }));
            // Clear the interest flag if no answer arrives (offline mid-request, old agent).
            setTimeout(function () { try { delete obj.pendingCollection[nodeId]; } catch (e) { } }, 120000);
        } catch (e) { delete obj.pendingCollection[nodeId]; }
    };

    /**
     * @brief Send a Windows-update status request to a single agent.
     * Uses the agent's console command <code>winupdates</code> (getAvailableUpdates),
     * which reports the number of missing/pending updates.
     * @param {string} nodeId - The node id.
     * @param {object} agent - The agent websocket object.
     */
    obj.collectNodeWindowsUpdates = function (nodeId, agent) {
        try {
            if (typeof agent.send !== 'function') return;
            if (obj.pendingWinUpdates == null) { obj.pendingWinUpdates = {}; }
            obj.pendingWinUpdates[nodeId] = true;
            // Clear the interest flag after a while if no answer arrives.
            setTimeout(function () { try { delete obj.pendingWinUpdates[nodeId]; } catch (e) { } }, 90000);
            // Sent through the agent's console-command channel with the console
            // rights bits (Remote Control 8 | Console 16 = 24) and a unique sessionid
            // so the response is identified and not delivered to any browser session.
            var sid = 'invscanner-' + obj.safeNodeDir(nodeId);
            var rights = 24;
            agent.send(JSON.stringify({ action: 'msg', type: 'console', value: 'winupdates', rights: rights, sessionid: sid }));
        } catch (e) { if (obj.pendingWinUpdates) { delete obj.pendingWinUpdates[nodeId]; } }
    };

    /**
     * @brief Collect software and then the Windows-update status for a single agent.
     * This avoids firing both (potentially expensive) agent commands at once and
     * helps keep per-client load low. The update check can take up to a minute.
     * @param {string} nodeId - The node id.
     * @param {object} agent - The agent websocket object.
     */
    obj.collectNodeSequential = function (nodeId, agent) {
        try {
            if ((nodeId == null) || (agent == null) || (typeof agent.send !== 'function')) return;
            obj.collectNodeSoftware(nodeId, agent);
            setTimeout(function () {
                obj.collectNodeWindowsUpdates(nodeId, agent);
            }, 1500);
        } catch (e) { }
    };

    /**
     * @brief Random stagger delay used when many agents reconnect at once
     * (e.g. right after a server restart). Spreads collection over several
     * minutes so the fleet is not queried as a single "thundering herd".
     * @returns {number} Delay in milliseconds (5s to 5min).
     */
    obj.staggerDelay = function () {
        return 5000 + Math.floor(Math.random() * ((5 * 60 * 1000) - 5000));
    };

    /**
     * @brief MeshCentral hook called once an agent core connection is stable
     * (i.e. the agent just came online). Collects software/patches immediately
     * so fresh data is available shortly after a device reconnects, instead of
     * waiting for the next periodic pass. The request is staggered randomly so a
     * fleet reconnecting after a server restart does not all get queried at once.
     * @param {object} agentObj - The meshagent object (has <code>dbNodeKey</code> and <code>send</code>).
     * @param {object} parent - The meshagent module object.
     */
    obj.hook_agentCoreIsStable = function (agentObj, parent) {
        try {
            if ((agentObj == null) || (agentObj.dbNodeKey == null)) return;
            try {
                var wgNode = agentObj.dbNodeKey;
                setTimeout(function () { try { obj.wgQueueNode(wgNode, 'connect'); } catch (e) { } }, obj.staggerDelay ? obj.staggerDelay() : 60000);
            } catch (e) { }
            try {
                // v4.0.0: "install as soon as the device is back" - run the queued deploy tasks.
                var swNode = agentObj.dbNodeKey;
                setTimeout(function () { try { obj.swOnNodeConnect(swNode); } catch (e) { } }, obj.staggerDelay ? obj.staggerDelay() : 60000);
            } catch (e) { }
            var cfg = obj.collectorConfig();
            if (cfg.collectOnAgentConnect === false) return;
            if (typeof agentObj.send !== 'function') return;
            // Let the agent fully settle, then spread the query over a random
            // window so a large fleet does not create a load spike on reconnect.
            setTimeout(function () {
                try { obj.collectNodeSequential(agentObj.dbNodeKey, agentObj); } catch (e) { }
            }, obj.staggerDelay());
        } catch (e) { }
    };
};
