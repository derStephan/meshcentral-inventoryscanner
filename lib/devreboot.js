/**
 * @file lib/devreboot.js
 * @brief Per-device forced restart + user notification (issue #6, v4.7.0). Under the v4.6.0 "a reboot
 * must be explicit and announced" policy this adds the SECOND intentional reboot path (the first is the
 * PC Reset, lib/devreset.js): restart ONE Windows or Linux device, with a grace period, so an admin can
 * reboot a machine before or after an upgrade. It is per-device, manual, gated on a full site admin and
 * needs the device name typed to confirm - never a batch, never scheduled, never automatic.
 * "Inform the current user if possible" is done two ways: (1) the restart itself carries a message that
 * the OS shows to logged-on users (Windows shutdown /c + msg.exe, Linux shutdown broadcast + wall), and
 * (2) a separate Notify action sends a message WITHOUT rebooting. Every run also reports whether a
 * reboot was already pending and which users are logged on, so the admin can see who will be affected.
 * Same transport as the OS engine: invscanner-rb- sessions (runcommands type 1 Windows / type 3 Linux),
 * marker @@INVRB@@, on the shared routeAgentCommand hook. A device with a reboot/notify in flight is
 * skipped by the winget/OS/deploy/reset/troubleshooter pumps (one runcommands session per agent).
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
    /** @brief marker of the one-line JSON answer of a restart/notify script. */
    obj.RB_MARKER = '@@INVRB@@';

    /** @brief session/responseid prefix of a restart/notify command. */
    obj.RB_SESSION_PREFIX = 'invscanner-rb-';

    /** @type {number} shutdown schedules and returns fast; the reply usually arrives, a hard reboot may not. */
    obj.RB_TIMEOUT_MS = 4 * 60 * 1000;

    /** @type {number} The user-facing message is capped so it fits a message box / shutdown banner. */
    obj.RB_MAX_MESSAGE = 200;

    /** @type {number} Default grace before the restart - enough for a user to save work. */
    obj.RB_DEFAULT_SECS = 60;

    /** @type {number} Upper bound for the grace period. */
    obj.RB_MAX_SECS = 3600;

    /** @type {Object<string, object>} nodeid -> live { sid, kind:'now'|'notify', since, timer }. */
    obj.rbPending = {};

    /** @type {Object<string, object>} nodeid -> last restart/notify record (persisted). */
    obj.rbResults = {};

    /** @brief Append a line to the restart log (rotated once at ~5 MB). */
    obj.rbLog = function (line) {
        try {
            var dir = path.dirname(obj.rbLogPath);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            try { if (fs.existsSync(obj.rbLogPath) && (fs.statSync(obj.rbLogPath).size > 5 * 1024 * 1024)) { fs.renameSync(obj.rbLogPath, obj.rbLogPath + '.old'); } } catch (e) { }
            fs.appendFileSync(obj.rbLogPath, new Date().toISOString() + ' ' + line + String.fromCharCode(10));
        } catch (e) { }
    };

    obj.rbLoadResults = function () {
        obj.rbResults = {};
        try { if (fs.existsSync(obj.rbResultsPath)) { var d = JSON.parse(fs.readFileSync(obj.rbResultsPath, 'utf8')); if (d && typeof d === 'object') { obj.rbResults = d; } } } catch (e) { obj.rbResults = {}; }
    };

    obj.rbSaveResults = function () {
        try {
            var dir = path.dirname(obj.rbResultsPath);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            fs.writeFileSync(obj.rbResultsPath, JSON.stringify(obj.rbResults));
        } catch (e) { obj.rbLog('could not save results: ' + e.message); }
    };

    /** @brief Platform of a node for a restart: 'windows' | 'linux' | null (null = not restartable here). */
    obj.rbPlatformOf = function (node) {
        var pf = obj.osPlatformOf(node);
        return (pf === 'windows' || pf === 'linux') ? pf : null;
    };

    /**
     * @brief Sanitize the admin's message to the device user: control characters and the shell / PowerShell
     * quoting characters are removed, the text is length-capped. It still travels base64-encoded, so the
     * only reason to clean it is to keep it readable and free of terminal control codes.
     * @param {*} m - raw field.
     * @param {string} dflt - used when m is empty.
     * @returns {string}
     */
    obj.rbCleanMessage = function (m, dflt) {
        var t = (typeof m === 'string') ? m : '';
        if (t === '') { return String(dflt == null ? '' : dflt).replace(/[\r\n\t]+/g, ' ').replace(/[`$"'\\]/g, '').trim().substring(0, obj.RB_MAX_MESSAGE); }
        t = t.replace(/[\r\n\t]+/g, ' ').replace(/[`$"'\\]/g, '').replace(/[\x00-\x1F\x7F]/g, '').replace(/\s{2,}/g, ' ').trim();
        return t.substring(0, obj.RB_MAX_MESSAGE);
    };

    /** @brief UTF-8 text -> base64 (safe to embed in a single-quoted shell/PowerShell literal). */
    obj.rbB64 = function (text) { return Buffer.from(String(text), 'utf8').toString('base64'); };

    /** @brief The shared "who is affected" detection lines (reboot state + logged-on users). */
    obj.rbProbeLines = function (platform) {
        if (platform === 'windows') {
            return [
                "$invRb.pendingReboot = $false; $invRb.source = ''; $invRb.users = ''",
                "if (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired') { $invRb.pendingReboot = $true; $invRb.source = 'Windows Update' }",
                "if (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending') { $invRb.pendingReboot = $true; if ($invRb.source) { $invRb.source = $invRb.source + ' + CBS' } else { $invRb.source = 'CBS' } }",
                "try { $invU = [string](Get-CimInstance Win32_ComputerSystem).UserName; if ($invU) { $invRb.users = $invU } } catch { }"
            ];
        }
        return [
            "PR=0; SRC=''; WHO=''",
            "if [ -f /var/run/reboot-required ]; then PR=1; SRC='reboot-required'; fi",
            "WHO=$(who 2>/dev/null | awk '{print $1}' | sort -u | tr '\\n' ',' | cut -c1-120)"
        ];
    };

    /**
     * @brief Windows notify-without-reboot script: message.exe popup to the interactive user, no reboot.
     * @param {string} message - already sanitized.
     * @returns {string}
     */
    obj.rbBuildNotifyWindowsScript = function (message) {
        return [
            "$ProgressPreference = 'SilentlyContinue'",
            "$ErrorActionPreference = 'SilentlyContinue'",
            "$invMsg = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + obj.rbB64(message) + "'))",
            "$invRb = @{ notify = $true; platform = 'windows'; state = 'sent'; pendingReboot = $false; source = ''; users = ''; msg = $invMsg; error = '' }"
        ].concat(obj.rbProbeLines('windows'), [
            "$invGot = $false; if ($invMsg) { try { $null = (msg '*' $invMsg 2>&1); $invGot = ($LASTEXITCODE -eq 0) } catch { $invGot = $false } }",
            "if (-not $invGot) { $invRb.state = 'not-delivered'; $invRb.error = 'msg.exe failed or no interactive session (msg is not available on Windows Home)' }",
            "$invRb | ConvertTo-Json -Compress -Depth 4 | ForEach-Object { Write-Output ('" + obj.RB_MARKER + "' + $_) }"
        ]).join(String.fromCharCode(10));
    };

    /**
     * @brief Linux notify-without-reboot script: wall broadcast to terminal users (GUI may not see it).
     * @param {string} message - already sanitized.
     * @returns {string}
     */
    obj.rbBuildNotifyLinuxScript = function (message) {
        return [
            "M=$(echo '" + obj.rbB64(message) + "' | base64 -d | tr -d '\\000')"
        ].concat(obj.rbProbeLines('linux'), [
            "if [ -n \"$M\" ]; then wall \"$M\" 2>/dev/null; fi",
            "printf '%s{\"notify\":true,\"platform\":\"linux\",\"state\":\"sent\",\"note\":\"broadcast to terminal users; GUI desktops may not show wall\",\"pendingReboot\":%s,\"source\":\"%s\",\"users\":\"%s\"}\\n' '" + obj.RB_MARKER + "' \"$PR\" \"$SRC\" \"$WHO\""
        ]).join(String.fromCharCode(10));
    };

    /**
     * @brief Windows restart script: show the message (msg.exe), then schedule the reboot with the same
     * message and a grace period (shutdown /r /t). The reply comes back during the grace window.
     * @param {string} message - sanitized.
     * @param {number} secs - grace seconds (0 = now).
     * @returns {string}
     */
    obj.rbBuildRebootWindowsScript = function (message, secs) {
        var s = (typeof secs === 'number' && secs >= 0 && secs <= obj.RB_MAX_SECS) ? Math.floor(secs) : obj.RB_DEFAULT_SECS;
        return [
            "$ProgressPreference = 'SilentlyContinue'",
            "$ErrorActionPreference = 'SilentlyContinue'",
            "$invMsg = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + obj.rbB64(message) + "'))",
            "$invSecs = " + s,
            "$invRb = @{ reboot = $true; platform = 'windows'; state = 'scheduled'; secs = $invSecs; abort = 'shutdown /a'; pendingReboot = $false; source = ''; users = ''; msg = $invMsg; error = '' }"
        ].concat(obj.rbProbeLines('windows'), [
            "if ($invMsg) { try { $null = (msg '*' $invMsg 2>&1) } catch { } }",
            "try { $null = (shutdown /r /t $invSecs /c \"$invMsg\" 2>&1); $invRb.state = 'scheduled' } catch { $invRb.state = 'failed'; $invRb.error = $_.Exception.Message }",
            "$invRb | ConvertTo-Json -Compress -Depth 4 | ForEach-Object { Write-Output ('" + obj.RB_MARKER + "' + $_) }"
        ]).join(String.fromCharCode(10));
    };

    /**
     * @brief Linux restart script: wall the message, then 'shutdown -r' with the message and a grace of
     * ceil(secs/60) minutes (now when secs == 0).
     * @param {string} message - sanitized.
     * @param {number} secs - grace seconds.
     * @returns {string}
     */
    obj.rbBuildRebootLinuxScript = function (message, secs) {
        var s = (typeof secs === 'number' && secs >= 0 && secs <= obj.RB_MAX_SECS) ? Math.floor(secs) : obj.RB_DEFAULT_SECS;
        return [
            "M=$(echo '" + obj.rbB64(message) + "' | base64 -d | tr -d '\\000')"
        ].concat(obj.rbProbeLines('linux'), [
            "if [ " + s + " -le 0 ]; then T=now; else T=+$(( (" + s + " + 59) / 60 )); fi",
            "if [ -n \"$M\" ]; then wall \"$M\" 2>/dev/null; fi",
            "shutdown -r $T \"$M\" 2>/dev/null; RC=$?",
            "if [ $RC -eq 0 ]; then ST=scheduled; else ST=failed; fi",
            "printf '%s{\"reboot\":true,\"platform\":\"linux\",\"state\":\"%s\",\"secs\":" + s + ",\"abort\":\"shutdown -c cancelled\",\"pendingReboot\":%s,\"source\":\"%s\",\"users\":\"%s\"}\\n' '" + obj.RB_MARKER + "' \"$ST\" \"$PR\" \"$SRC\" \"$WHO\""
        ]).join(String.fromCharCode(10));
    };

    /** @brief The script text + agent command type for one platform/kind (reboot uses both transports like the OS engine). */
    obj.rbBuildScript = function (kind, platform, message, secs) {
        if (kind === 'notify') { return (platform === 'windows') ? obj.rbBuildNotifyWindowsScript(message) : obj.rbBuildNotifyLinuxScript(message); }
        return (platform === 'windows') ? obj.rbBuildRebootWindowsScript(message, secs) : obj.rbBuildRebootLinuxScript(message, secs);
    };

    /**
     * @brief Send one restart/notify command to a single, online, idle device (Windows or Linux).
     * Reserves the node's runcommands session synchronously (same rule as devDispatch/wuDispatch).
     * @returns {object} { started } | { busy } | { error }
     */
    obj.rbDispatch = function (nodeid, kind, platform, script) {
        try {
            var ws = obj.meshServer.webserver;
            if (!obj.routeHookInstalled) { try { obj.installRouteHook(); } catch (e) { } }
            var agent = (ws != null && ws.wsagents != null) ? ws.wsagents[nodeid] : null;
            if ((agent == null) || (typeof agent.send !== 'function')) return { error: 'offline' };
            if ((obj.rbPending[nodeid] != null) ||
                (obj.wuPending != null && obj.wuPending[nodeid] != null) || (obj.devPending != null && obj.devPending[nodeid] != null) ||
                (obj.wgPending != null && obj.wgPending[nodeid] != null) || (obj.osPending != null && obj.osPending[nodeid] != null) ||
                (obj.swPending != null && obj.swPending[nodeid] != null)) {
                return { busy: true };
            }
            var sid = obj.RB_SESSION_PREFIX + obj.safeNodeDir(nodeid);
            var entry = { nodeid: nodeid, sid: sid, kind: kind, platform: platform, since: Date.now() };
            entry.timer = setTimeout(function () { obj.rbTimeout(entry); }, obj.RB_TIMEOUT_MS);
            obj.rbPending[nodeid] = entry;
            try {
                var msg;
                if (platform === 'windows') { msg = { action: 'runcommands', type: 1, cmds: obj.wgTransport(script), runAsUser: 0, reply: true, sessionid: sid, responseid: sid }; }
                else { msg = { action: 'runcommands', type: 3, cmds: obj.osLinuxTransport(script), runAsUser: 0, reply: true, sessionid: sid, responseid: sid }; }
                agent.send(JSON.stringify(msg));
            } catch (ex) {
                clearTimeout(entry.timer); delete obj.rbPending[nodeid];
                return { error: 'send-failed: ' + ex.message };
            }
            return { started: true, sid: sid };
        } catch (e) { return { error: e.message }; }
    };

    /** @brief True when a node currently has a restart/notify session in flight. */
    obj.rbIsBusy = function (nodeid) { return (nodeid != null) && (obj.rbPending != null) && (obj.rbPending[nodeid] != null); };

    /** @brief Answer of one restart/notify session (consumed by lib/collector.js). */
    obj.rbHandleResponse = function (nodeid, command) {
        var entry = obj.rbPending[nodeid];
        if (entry == null) return;
        if (entry.timer) { clearTimeout(entry.timer); }
        delete obj.rbPending[nodeid];
        var text = (typeof command.result === 'string') ? command.result : JSON.stringify(command.result || '');
        var data = obj.wgPayloadFromText(text, obj.RB_MARKER);
        if ((data == null) && (typeof entry.cbuf === 'string')) { data = obj.wgPayloadFromText(entry.cbuf, obj.RB_MARKER); }
        var s = function (v, n) { return String(v == null ? '' : v).substring(0, n); };
        var rec = { kind: entry.kind, time: new Date().toISOString(), platform: entry.platform };
        if (data == null) {
            rec.state = (text.indexOf(obj.RB_MARKER) >= 0) ? 'error' : 'no-marker';
            obj.rbResults[nodeid] = rec; obj.rbLog(nodeid + ' - ' + entry.kind + ': ' + rec.state); obj.rbSaveResults();
            return;
        }
        rec.pendingReboot = data.pendingReboot === true;
        rec.source = s(data.source, 40);
        rec.users = s(data.users, 160);
        if (entry.kind === 'notify') {
            rec.state = (data.state === 'not-delivered') ? 'not-delivered' : 'sent';
            if (data.error) { rec.note = s(data.error, 200); }
            obj.rbLog(nodeid + ' - notify: ' + rec.state + (rec.pendingReboot ? (' (reboot pending: ' + rec.source + ')') : '') + (rec.users ? (' users: ' + rec.users) : ''));
        } else {
            rec.state = (data.state === 'failed') ? 'failed' : 'scheduled';
            rec.secs = (typeof data.secs === 'number') ? data.secs : null;
            rec.abort = s(data.abort, 60);
            if (data.error) { rec.note = s(data.error, 200); }
            obj.rbLog(nodeid + ' - restart: ' + rec.state + (rec.secs != null ? (' in ' + rec.secs + 's') : '') + ' (msg sent; abort with ' + rec.abort + ')' + (rec.pendingReboot ? ' - NOTE reboot was already pending (' + rec.source + ')' : ''));
        }
        obj.rbResults[nodeid] = rec; obj.rbSaveResults();
        var ev = (entry.kind === 'notify')
            ? ('Restart notice ' + rec.state + ' to ' + (rec.users || 'the device user') + (rec.pendingReboot ? (' - a reboot is pending (' + rec.source + ')') : ''))
            : ('Restart ' + rec.state + (rec.secs ? (' in ' + rec.secs + 's') : '') + ' by ' + (entry.by || 'admin') + (rec.pendingReboot ? (' (a reboot was already pending: ' + rec.source + ')') : ''));
        obj.wgRaiseNodeEvent(nodeid, ev.substring(0, 300));
    };

    /**
     * @brief Watchdog. A restart with a grace period normally answers first; with 0s grace the machine
     * goes down before the reply, so an offline node means "rebooted" (the device will come back).
     */
    obj.rbTimeout = function (entry) {
        if ((entry == null) || (obj.rbPending[entry.nodeid] !== entry)) return;
        delete obj.rbPending[entry.nodeid];
        var ws = obj.meshServer.webserver;
        var online = (ws != null && ws.wsagents != null && ws.wsagents[entry.nodeid] != null);
        if (entry.kind === 'notify') {
            obj.rbResults[entry.nodeid] = { kind: 'notify', state: 'timeout', time: new Date().toISOString() };
            obj.rbLog(entry.nodeid + ' - notify: no answer within the timeout');
            obj.rbSaveResults();
            return;
        }
        var rec = { kind: 'reboot', time: new Date().toISOString(), platform: entry.platform };
        if (!online) { rec.state = 'rebooted'; rec.note = 'the device went offline right after the restart command - it is rebooting.'; }
        else { rec.state = 'no-answer'; rec.note = 'the device is still online but never answered - the restart may not have been accepted.'; }
        obj.rbResults[entry.nodeid] = rec;
        obj.rbLog(entry.nodeid + ' - restart: ' + rec.state + (online ? ' (still online)' : ' (offline, rebooting)'));
        obj.wgRaiseNodeEvent(entry.nodeid, 'Force restart: ' + rec.note);
        obj.rbSaveResults();
    };

    /** @brief Shared validation + dispatch of one restart/notify on a single device. */
    obj.rbStart = function (req, res, user, kind) {
        var send = function (o) { res.type('json'); res.json(o); };
        var body = req.body || {};
        var nodeid = String(body.nodeId || '');
        if (!/^node\/[^:]{1,100}$/.test(nodeid)) { return send({ error: 'Invalid node id.' }); }
        obj.db.Get(nodeid, function (err, docs) {
            if (err || !docs || !docs.length || docs[0] == null || docs[0].deleted != null) { return send({ error: 'Unknown device.' }); }
            var node = docs[0];
            var pf = obj.rbPlatformOf(node);
            if (pf == null) { return send({ error: 'A restart/notice is only available on Windows and Linux devices with a reported OS.' }); }
            var defMsg = (kind === 'reboot') ? 'A maintenance restart was triggered by the administrator - please save your work.' : 'The administrator sent a maintenance notice for this device.';
            var message = obj.rbCleanMessage(body.message, defMsg);
            var secs = obj.RB_DEFAULT_SECS;
            if (kind === 'reboot') {
                // typed-name confirmation guard (only for the reboot, not the notice).
                var typed = String(body.confirm || '').trim();
                var given = (typeof node.name === 'string') ? node.name.trim() : '';
                var host = String(obj.getHostName(node) || '').trim();
                var want = given !== '' ? given : host;
                if (typed === '' || (typed.toLowerCase() !== String(want || '').toLowerCase() && (given === '' || typed.toLowerCase() !== host.toLowerCase()))) {
                    return send({ error: 'Type the device name "' + (want || nodeid) + '" exactly to confirm the restart.' });
                }
                var n = parseInt(String(body.secs), 10);
                if (!isNaN(n) && n >= 0 && n <= obj.RB_MAX_SECS) secs = n;
            }
            var ws = obj.meshServer.webserver;
            if (ws == null || ws.wsagents == null || ws.wsagents[nodeid] == null) { return send({ error: 'The device is offline.' }); }
            var script = obj.rbBuildScript(kind, pf, message, secs);
            var r = obj.rbDispatch(nodeid, kind, pf, script);
            if (r.error) { return send({ error: r.error === 'offline' ? 'The device is offline.' : r.error }); }
            if (r.busy) { return send({ error: 'Another task is still running on this device (winget, OS update, deploy, reset or troubleshooter) - try again later.' }); }
            obj.rbLog(nodeid + ' - ' + kind + (kind === 'reboot' ? (' (' + secs + 's)') : '') + ' dispatched by ' + ((user && user.name) || '?'));
            send({ started: true, kind: kind, platform: pf, secs: (kind === 'reboot' ? secs : 0) });
        });
    };

    /** @brief POST reboot_now: restart one device with a grace period + a message to its user. */
    obj.rbRebootHandler = function (req, res, user) { obj.rbStart(req, res, user, 'reboot'); };

    /** @brief POST reboot_notify: message one device's user without rebooting. */
    obj.rbNotifyHandler = function (req, res, user) { obj.rbStart(req, res, user, 'notify'); };
};
