/**
 * @file lib/devreset.js
 * @brief Per-device Windows PC reset (issue #4, v4.5.0): resets ONE Windows PC with the built-in
 * 'systemreset' tool - 'Remove everything' or 'Keep my files' - only after an explicit typed
 * confirmation. THIS IS THE ONE FEATURE THAT REBOOTS THE DEVICE: a reset cannot be done from inside
 * the running OS, so the machine restarts into Windows RE and finishes there. Everything else about
 * it is deliberately conservative: per-device only (never a fleet, never scheduled, never automatic),
 * gated on a full site admin like every route, and the exact device name has to be typed before the
 * command is sent. 'Remove everything' is additionally hard-blocked while BitLocker protection is on,
 * unless the operator confirms the recovery key is available.
 * Same transport and marker pattern as the OS engine (lib/osupdate.js): a read-only PROBE first reads
 * the facts that decide whether a reset is possible and safe (systemreset present, build, WinRE,
 * BitLocker, domain, battery, logged-on user), then the RESET command runs the chosen mode. Own
 * sessions ('invscanner-dr-' + node) and marker '@@INVDR@@' on the shared routeAgentCommand hook. A
 * reset dispatches one command per node directly (no queue): the runcommands session is reserved via
 * devPending so the winget/OS/deploy pumps never overlap it (one runcommands session per agent).
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
    /** @brief marker of the one-line JSON answer of a probe/reset script. */
    obj.DEV_MARKER = '@@INVDR@@';

    /** @brief session/responseid prefix of a device-reset command (agent echoes it back). */
    obj.DEV_SESSION_PREFIX = 'invscanner-dr-';

    /** @type {number} A read-only probe is quick; if it never answers the session is dropped. */
    obj.DEV_PROBE_TIMEOUT_MS = 2 * 60 * 1000;

    /**
     * @type {number} After a reset is dispatched the device restarts into WinRE, so the agent
     * usually never returns a reply - the watchdog then decides between "resetting" (offline, as
     * expected) and "no answer" (still online, so nothing happened).
     */
    obj.DEV_RESET_TIMEOUT_MS = 15 * 60 * 1000;

    /** @type {number} A reset needs a fresh probe: facts older than this must be re-read first. */
    obj.DEV_PROBE_MAX_AGE_MS = 6 * 60 * 60 * 1000;

    /**
     * @type {number} First Windows 10 build where 'systemreset' carries the non-interactive
     * '-cleanpc' / '-keepfiles' switches (1809). Below it the tool only opens the interactive UI,
     * so an unattended reset is not offered.
     */
    obj.DEV_MIN_BUILD = 17763;

    /** @type {Object<string, object>} nodeid -> { sid, kind:'probe'|'reset', mode, ack, since, timer }. */
    obj.devPending = {};

    /** @type {Object<string, object>} nodeid -> latest PROBE record (persisted, the gate for a reset). */
    obj.devResults = {};

    /** @type {Object<string, object>} nodeid -> latest RESET record (persisted, shown as "last reset"). */
    obj.devLast = {};

    /** @brief Append a line to the device-reset audit log (rotated once at ~5 MB). */
    obj.devLog = function (line) {
        try {
            var dir = path.dirname(obj.devLogPath);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            try { if (fs.existsSync(obj.devLogPath) && (fs.statSync(obj.devLogPath).size > 5 * 1024 * 1024)) { fs.renameSync(obj.devLogPath, obj.devLogPath + '.old'); } } catch (e) { }
            fs.appendFileSync(obj.devLogPath, new Date().toISOString() + ' ' + line + String.fromCharCode(10));
        } catch (e) { }
    };

    obj.devLoadResults = function () {
        obj.devResults = {}; obj.devLast = {};
        try {
            if (fs.existsSync(obj.devResultsPath)) {
                var d = JSON.parse(fs.readFileSync(obj.devResultsPath, 'utf8'));
                if (d && typeof d === 'object') {
                    if (d.probes && typeof d.probes === 'object') obj.devResults = d.probes;
                    if (d.last && typeof d.last === 'object') obj.devLast = d.last;
                }
            }
        } catch (e) { obj.devResults = {}; obj.devLast = {}; }
    };

    obj.devSaveResults = function () {
        try {
            var dir = path.dirname(obj.devResultsPath);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            fs.writeFileSync(obj.devResultsPath, JSON.stringify({ probes: obj.devResults, last: obj.devLast }));
        } catch (e) { obj.devLog('could not save results: ' + e.message); }
    };

    /**
     * @brief Windows node test (this feature is Windows-only: 'systemreset' is a Windows tool).
     * An unknown OS is NOT treated as Windows here - a reset must never run on a device whose
     * platform was not positively identified as Windows.
     * @param {object} node - The node record.
     * @returns {boolean} true only when the reported OS is Windows.
     */
    obj.devIsWindowsNode = function (node) {
        if (node == null) return false;
        return /windows/i.test(String(node.osdesc || ''));
    };

    /**
     * @brief True when a cached probe of a node can still be trusted to decide "safe to reset".
     * @param {object} probe - obj.devResults[nodeid] with kind 'probe'.
     * @returns {boolean}
     */
    obj.devProbeFresh = function (probe, now) {
        if ((probe == null) || probe.kind !== 'probe') return false;
        var t = Date.parse(String(probe.time || ''));
        if (isNaN(t)) return false;
        return ((now != null ? now : Date.now()) - t) <= obj.DEV_PROBE_MAX_AGE_MS;
    };

    /**
     * @brief BitLocker verdict of a probe for the "remove everything" gate. Protected or unknown is
     * blocking (fail-safe: an unreadable status never lets a clean reset through unchecked).
     * @param {object} probe - a cached probe (kind 'probe').
     * @returns {string} 'off' | 'on' | 'unknown'
     */
    obj.devBitlockerState = function (probe) {
        var s = probe && typeof probe.bitlocker === 'string' ? probe.bitlocker : 'unknown';
        return (s === 'off' || s === 'on' || s === 'unknown') ? s : 'unknown';
    };

    /**
     * @brief Whether a mode is offered for a node right now, with the reason when it is not. The
     * rules mirror what the reset script re-checks on the device (defence in depth).
     * @param {object} probe - cached probe (may be null).
     * @param {string} mode - 'clean' | 'keepfiles'.
     * @param {string} [bitlockerAck] - 'true' when the recovery-key checkbox was ticked.
     * @returns {object} { allowed, reason }
     */
    obj.devModeAllowed = function (probe, mode, bitlockerAck) {
        if (!obj.devProbeFresh(probe)) return { allowed: false, reason: 'run the Check on this device first (the facts must be current)' };
        if (probe.state !== 'ok') return { allowed: false, reason: 'the last check did not answer (state "' + probe.state + '") - run it again' };
        if (probe.systemreset !== true) return { allowed: false, reason: 'this device has no systemreset.exe - it is not a resettable Windows PC' };
        var m = (mode === 'keepfiles') ? 'keepfiles' : 'clean';
        if (m === 'clean' && probe.clean !== true) return { allowed: false, reason: 'this Windows build does not support the non-interactive "Remove everything" reset' };
        if (m === 'keepfiles' && probe.keepfiles !== true) return { allowed: false, reason: 'this Windows build does not support the non-interactive "Keep my files" reset' };
        if (probe.winre === 'disabled') return { allowed: false, reason: 'Windows RE is disabled - run "reagentc /enable" on the device first' };
        if (m === 'clean') {
            var bl = obj.devBitlockerState(probe);
            if (bl !== 'off' && bitlockerAck !== 'true') {
                return { allowed: false, reason: 'BitLocker protection on the system drive is ' + bl + ' - "Remove everything" is blocked until you confirm the recovery key is available' };
            }
        }
        return { allowed: true, reason: '' };
    };

    /**
     * @brief Read-only probe script (PowerShell, runs as SYSTEM through the agent). Reports every
     * fact the server needs to decide whether and how a reset is possible. Never changes anything.
     * One statement per line (guarded by a test).
     * @returns {string} The script text.
     */
    obj.devBuildProbeScript = function () {
        return [
            "$ProgressPreference = 'SilentlyContinue'",
            "$ErrorActionPreference = 'SilentlyContinue'",
            "$invDr = @{ probe = $true; state = 'ok'; systemreset = $false; build = 0; clean = $false; keepfiles = $false; winre = 'unknown'; bitlocker = 'unknown'; bldetail = ''; domain = $false; user = ''; battery = $false; onac = $true; error = '' }"
        ].concat(obj.psTranscriptLines('invscanner-devreset.log'), [
            "$invSys = $env:SystemDrive; if (-not $invSys) { $invSys = [string](Get-CimInstance Win32_OperatingSystem).SystemDrive }; if (-not $invSys) { $invSys = 'C:' }",
            "$invBuild = 0; try { $invBuild = [int](Get-CimInstance Win32_OperatingSystem).BuildNumber } catch { }; if ($invBuild -le 0) { try { $invBuild = [int](Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').CurrentBuildNumber } catch { $invBuild = 0 } }",
            "$invDr.build = $invBuild",
            "$invSr = Join-Path $env:SystemRoot 'System32\\systemreset.exe'; if (Test-Path -LiteralPath $invSr) { $invDr.systemreset = $true }",
            "if ($invDr.systemreset) { $invHelp = ((& $invSr '/?') 2>&1 | Out-String); if ($invHelp -imatch '-cleanpc') { $invDr.clean = $true }; if ($invHelp -imatch '-keepfiles') { $invDr.keepfiles = $true }; if ($invBuild -ge " + obj.DEV_MIN_BUILD + ") { $invDr.clean = $true; $invDr.keepfiles = $true } }",
            "$invRe = ((& reagentc '/info') 2>&1 | Out-String); if ($invRe -imatch 'disabled') { $invDr.winre = 'disabled' } elseif ($invRe -imatch 'enabled') { $invDr.winre = 'enabled' }",
            "$invBl = ''; try { $invBv = Get-BitLockerVolume -MountPoint $invSys -ErrorAction Stop; $invBl = [string]$invBv.ProtectionStatus } catch { $invBl = '' }",
            "if ($invBl -eq '') { $invMb = ((& manage-bde '-status' $invSys) 2>&1 | Out-String); if ($invMb -imatch 'Protection Status:\\s*On') { $invBl = 'On' } elseif ($invMb -imatch 'Protection Status:\\s*Off') { $invBl = 'Off' } }",
            "if ($invBl -imatch 'On') { $invDr.bitlocker = 'on' } elseif ($invBl -imatch 'Off') { $invDr.bitlocker = 'off' } else { $invDr.bitlocker = 'unknown' }; $invDr.bldetail = $invBl",
            "try { $invDr.domain = [bool](Get-CimInstance Win32_ComputerSystem).PartOfDomain } catch { }",
            "try { $invDr.user = [string](Get-CimInstance Win32_ComputerSystem).UserName } catch { }",
            "$invBat = $null; try { $invBat = @(Get-CimInstance Win32_Battery) } catch { }; if ($invBat -and $invBat.Count -gt 0) { $invDr.battery = $true; if ($invBat[0].BatteryStatus -ne 2) { $invDr.onac = $false } }",
            "$invDr | ConvertTo-Json -Compress -Depth 4 | ForEach-Object { Write-Output ('" + obj.DEV_MARKER + "' + $_) }",
            "Stop-Transcript -ErrorAction SilentlyContinue | Out-Null"
        ]).join(String.fromCharCode(10));
    };

    /**
     * @brief Reset script (PowerShell, as SYSTEM). Re-checks the safety facts ON THE DEVICE (a probe
     * can be stale) and then launches the chosen 'systemreset' mode non-interactively. The answer
     * line is printed BEFORE the reset starts, because the machine restarts into WinRE while this
     * script's own command session is still considered open - the reply may never come back. When a
     * pre-check fails the script answers result='refused' and runs nothing.
     * @param {string} mode - 'clean' | 'keepfiles'.
     * @param {boolean} ack - recovery key confirmed (only meaningful for 'clean').
     * @returns {string} The script text.
     */
    obj.devBuildResetScript = function (mode, ack) {
        var m = (mode === 'keepfiles') ? 'keepfiles' : 'clean';
        var sw = (m === 'clean') ? '-cleanpc' : '-keepfiles';
        var ackLit = ack === true ? '$true' : '$false';
        return [
            "$ProgressPreference = 'SilentlyContinue'",
            "$ErrorActionPreference = 'SilentlyContinue'",
            "$invMode = '" + m + "'",
            "$invAck = " + ackLit,
            "$invSw = '" + sw + "'",
            "$invDr = @{ reset = $true; mode = $invMode; result = 'starting'; error = ''; build = 0 }"
        ].concat(obj.psTranscriptLines('invscanner-devreset.log'), [
            "$invSr = Join-Path $env:SystemRoot 'System32\\systemreset.exe'; if (-not (Test-Path -LiteralPath $invSr)) { $invDr.result = 'refused'; $invDr.error = 'systemreset.exe not found' }",
            "$invBuild = 0; try { $invBuild = [int](Get-CimInstance Win32_OperatingSystem).BuildNumber } catch { }; if ($invBuild -le 0) { try { $invBuild = [int](Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').CurrentBuildNumber } catch { $invBuild = 0 } }; $invDr.build = $invBuild",
            "if ($invDr.result -eq 'starting' -and $invBuild -lt " + obj.DEV_MIN_BUILD + ") { $invDr.result = 'refused'; $invDr.error = 'this Windows build (' + $invBuild + ') does not support a non-interactive reset' }",
            "if ($invDr.result -eq 'starting') { $invRe = ((& reagentc '/info') 2>&1 | Out-String); if ($invRe -imatch 'disabled') { $invDr.result = 'refused'; $invDr.error = 'Windows RE is disabled - run reagentc /enable first' } }",
            "if ($invDr.result -eq 'starting' -and $invMode -eq 'clean') { $invSys = $env:SystemDrive; if (-not $invSys) { $invSys = [string](Get-CimInstance Win32_OperatingSystem).SystemDrive }; $invBl = ''; try { $invBl = [string](Get-BitLockerVolume -MountPoint $invSys).ProtectionStatus } catch { $invBl = 'unknown' }; if (($invBl -inotmatch 'Off') -and (-not $invAck)) { $invDr.result = 'refused'; $invDr.error = ('BitLocker protection is ' + $invBl + ' - confirm the recovery key is available and retry') } }",
            "$invDr | ConvertTo-Json -Compress -Depth 4 | ForEach-Object { Write-Output ('" + obj.DEV_MARKER + "' + $_) }",
            "if ($invDr.result -eq 'starting') { try { $null = Start-Process -FilePath $invSr -ArgumentList $invSw,'-noUI' -WindowStyle Hidden } catch { $invDr.result = 'refused'; $invDr.error = ('launch failed: ' + $_.Exception.Message); Write-Output ('" + obj.DEV_MARKER + "' + ($invDr | ConvertTo-Json -Compress -Depth 4)) } }",
            "Stop-Transcript -ErrorAction SilentlyContinue | Out-Null"
        ]).join(String.fromCharCode(10));
    };

    /**
     * @brief Send one probe or reset command to a single, online, idle Windows node. Reserves the
     * node's single runcommands session synchronously (like wgPump/osPump) so no other engine can
     * start there while this one is in flight.
     * @param {string} nodeid - The device.
     * @param {string} kind - 'probe' | 'reset'.
     * @param {string} script - The generated PowerShell text.
     * @param {object} meta - { mode, ack } for a reset (ignored for a probe).
     * @returns {object} { started } | { busy } | { error }
     */
    obj.devDispatch = function (nodeid, kind, script, meta) {
        try {
            var ws = obj.meshServer.webserver;
            if (!obj.routeHookInstalled) { try { obj.installRouteHook(); } catch (e) { } }
            var agent = (ws != null && ws.wsagents != null) ? ws.wsagents[nodeid] : null;
            if ((agent == null) || (typeof agent.send !== 'function')) return { error: 'offline' };
            if ((obj.devPending[nodeid] != null) || (obj.wgPending != null && obj.wgPending[nodeid] != null) ||
                (obj.osPending != null && obj.osPending[nodeid] != null) || (obj.swPending != null && obj.swPending[nodeid] != null) ||
                (obj.wuPending != null && obj.wuPending[nodeid] != null)) {
                return { busy: true };
            }
            var sid = obj.DEV_SESSION_PREFIX + obj.safeNodeDir(nodeid);
            var entry = { nodeid: nodeid, sid: sid, kind: kind, mode: (meta && meta.mode) || '', ack: !!(meta && meta.ack), since: Date.now() };
            entry.timer = setTimeout(function () { obj.devResetTimeout(entry); }, kind === 'reset' ? obj.DEV_RESET_TIMEOUT_MS : obj.DEV_PROBE_TIMEOUT_MS);
            obj.devPending[nodeid] = entry;
            try {
                agent.send(JSON.stringify({ action: 'runcommands', type: 1, cmds: obj.wgTransport(script), runAsUser: 0, reply: true, sessionid: sid, responseid: sid }));
            } catch (ex) {
                clearTimeout(entry.timer); delete obj.devPending[nodeid];
                return { error: 'send-failed: ' + ex.message };
            }
            return { started: true, sid: sid };
        } catch (e) { return { error: e.message }; }
    };

    /** @brief True when a node currently has a device-reset session in flight. */
    obj.devIsBusy = function (nodeid) { return (nodeid != null) && (obj.devPending != null) && (obj.devPending[nodeid] != null); };

    /**
     * @brief Answer of one probe/reset session. Consumed by the route hook (lib/collector.js).
     * @param {string} nodeid - The device.
     * @param {object} command - The runcommands reply ({ result }) or an accumulated console buffer.
     */
    obj.devHandleResponse = function (nodeid, command) {
        var entry = obj.devPending[nodeid];
        if (entry == null) return;
        if (entry.timer) { clearTimeout(entry.timer); }
        delete obj.devPending[nodeid];
        var text = (typeof command.result === 'string') ? command.result : JSON.stringify(command.result || '');
        var data = obj.wgPayloadFromText(text, obj.DEV_MARKER);
        if ((data == null) && (typeof entry.cbuf === 'string')) { data = obj.wgPayloadFromText(entry.cbuf, obj.DEV_MARKER); }
        if (entry.kind === 'reset') { obj.devFinishReset(nodeid, entry, data, text); return; }
        obj.devFinishProbe(nodeid, entry, data, text);
    };
    /** @brief Store + log the probe verdict for one node. */
    obj.devFinishProbe = function (nodeid, entry, data, text) {
        var rec = { kind: 'probe', time: new Date().toISOString() };
        if (data == null) {
            rec.state = (String(text).indexOf(obj.DEV_MARKER) >= 0) ? 'error' : 'no-marker';
            obj.devResults[nodeid] = rec;
            obj.devLog(nodeid + ' - probe: ' + rec.state);
            obj.devSaveResults();
            return;
        }
        var s = function (v, n) { return String(v == null ? '' : v).substring(0, n); };
        rec.state = 'ok';
        rec.systemreset = data.systemreset === true;
        rec.build = (typeof data.build === 'number') ? data.build : 0;
        rec.clean = data.clean === true;
        rec.keepfiles = data.keepfiles === true;
        rec.winre = ['enabled', 'disabled', 'unknown'].indexOf(data.winre) >= 0 ? data.winre : 'unknown';
        rec.bitlocker = ['off', 'on', 'unknown'].indexOf(data.bitlocker) >= 0 ? data.bitlocker : 'unknown';
        rec.bldetail = s(data.bldetail, 20);
        rec.domain = data.domain === true;
        rec.user = s(data.user, 120);
        rec.battery = data.battery === true;
        rec.onac = data.onac !== false;
        obj.devResults[nodeid] = rec;
        obj.devLog(nodeid + ' - probe: resettable=' + rec.systemreset + ' build=' + rec.build + ' winre=' + rec.winre +
            ' bitlocker=' + rec.bitlocker + ' clean=' + rec.clean + ' keepfiles=' + rec.keepfiles + ' domain=' + rec.domain);
        obj.devSaveResults();
    };

    /** @brief Store + log + raise the event of one reset answer (result starting/refused). */
    obj.devFinishReset = function (nodeid, entry, data, text) {
        var rec = { kind: 'reset', time: new Date().toISOString(), mode: entry.mode };
        if (data == null) {
            // No parsable marker but the device answered. Treat a reachable answer as inconclusive;
            // the watchdog (offline) is the normal success path of a reset.
            rec.state = (String(text).indexOf(obj.DEV_MARKER) >= 0) ? 'error' : 'no-answer';
            rec.note = 'the device answered without a usable result - check whether it restarted';
            obj.devLast[nodeid] = rec;
            obj.devLog(nodeid + ' - reset ' + entry.mode + ': ' + rec.state + ' (device still online)');
            obj.wgRaiseNodeEvent(nodeid, 'PC reset (' + entry.mode + '): ' + rec.note);
            obj.devSaveResults();
            return;
        }
        if (data.result === 'refused') {
            rec.state = 'refused';
            rec.note = String(data.error || 'refused on the device').substring(0, 300);
            obj.devLast[nodeid] = rec;
            obj.devLog(nodeid + ' - reset ' + entry.mode + ' REFUSED: ' + rec.note);
            obj.wgRaiseNodeEvent(nodeid, 'PC reset (' + entry.mode + '): refused - ' + rec.note);
            obj.devSaveResults();
            return;
        }
        // result 'starting' (or anything else): the reset was launched, the device reboots now.
        rec.state = 'resetting';
        rec.build = (typeof data.build === 'number') ? data.build : null;
        rec.note = 'the device restarts into Windows RE and resets now; it returns as a ' + (entry.mode === 'keepfiles' ? 'fresh system that keeps personal files' : 'clean system') + '.';
        obj.devLast[nodeid] = rec;
        obj.devLog(nodeid + ' - reset ' + entry.mode + ' started (confirmed by the device)');
        obj.wgRaiseNodeEvent(nodeid, 'PC reset (' + entry.mode + '): started, the device is restarting to reset itself.');
        obj.devSaveResults();
    };

    /**
     * @brief Watchdog for a session that never answered. For a reset this is the NORMAL path: the
     * machine went offline into WinRE, so an offline node means "resetting (not confirmed by a
     * reply)"; a node that is still online never started the reset.
     */
    obj.devResetTimeout = function (entry) {
        if ((entry == null) || (obj.devPending[entry.nodeid] !== entry)) return;
        delete obj.devPending[entry.nodeid];
        var ws = obj.meshServer.webserver;
        var online = (ws != null && ws.wsagents != null && ws.wsagents[entry.nodeid] != null);
        if (entry.kind === 'reset') {
            var rec = { kind: 'reset', time: new Date().toISOString(), mode: entry.mode };
            if (!online) {
                rec.state = 'resetting';
                rec.note = 'the device went offline right after the reset command, as expected when it restarts into Windows RE; the reset is running.';
                obj.devLast[entry.nodeid] = rec;
                obj.devLog(entry.nodeid + ' - reset ' + entry.mode + ': device offline as expected (resetting, no reply needed)');
                obj.wgRaiseNodeEvent(entry.nodeid, 'PC reset (' + entry.mode + '): the device restarted, the reset is running.');
            } else {
                rec.state = 'no-answer';
                rec.note = 'the device is still online but never answered - the reset did not start.';
                obj.devLast[entry.nodeid] = rec;
                obj.devLog(entry.nodeid + ' - reset ' + entry.mode + ': NO ANSWER (device still online)');
                obj.wgRaiseNodeEvent(entry.nodeid, 'PC reset (' + entry.mode + '): the device stayed online and did not reset.');
            }
            obj.devSaveResults();
            return;
        }
        // probe timeout
        obj.devResults[entry.nodeid] = { kind: 'probe', state: 'no-answer', time: new Date().toISOString() };
        obj.devLog(entry.nodeid + ' - probe: no answer within the timeout');
        obj.devSaveResults();
    };

    /**
     * @brief Validate a node id and resolve it; calls cb(node) or sends the error itself.
     * Only a live Windows node is accepted (the caller must have a real device, never a stale id).
     */
    obj.devResolveWindowsNode = function (nodeid, cb, fail) {
        if (!/^node\/[^:]{1,100}$/.test(String(nodeid))) { return fail('Invalid node id.'); }
        obj.db.Get(nodeid, function (err, docs) {
            if (err || !docs || !docs.length) { return fail('Unknown device.'); }
            var node = docs[0];
            if ((node == null) || (node.deleted != null)) { return fail('Unknown device.'); }
            if (!obj.devIsWindowsNode(node)) { return fail('PC reset is only available on Windows devices.'); }
            cb(node);
        });
    };

    /** @brief POST dr_status: the Windows devices with their cached probe + reset state. */
    obj.devResetStatusHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        try {
            var excl = obj.wingetConfig().excludeNodes;
            obj.db.GetAllType('mesh', function (merr, meshes) {
                var meshNames = {};
                if (!merr && meshes) { for (var mi = 0; mi < meshes.length; mi++) { var mm = meshes[mi]; if (mm && mm._id && mm.deleted == null) meshNames[mm._id] = mm.name || mm._id; } }
                obj.db.GetAllType('node', function (nerr, nodes) {
                    var ws = obj.meshServer.webserver, devices = [];
                    if (!nerr && nodes) {
                        for (var i = 0; i < nodes.length && devices.length < 2000; i++) {
                            var n = nodes[i];
                            if ((n == null) || (n._id == null) || (n.deleted != null)) continue;
                            if (!obj.devIsWindowsNode(n)) continue;
                            var probe = obj.devResults[n._id];
                            var hasProbe = obj.devProbeFresh(probe);
                            var pend = obj.devPending[n._id];
                            devices.push({
                                id: n._id, host: obj.getHostName(n), given: (typeof n.name === 'string') ? n.name.trim() : '',
                                group: meshNames[n.meshid] || n.meshid || '', os: String(n.osdesc || '').substring(0, 120),
                                online: (ws != null && ws.wsagents != null && ws.wsagents[n._id] != null),
                                excluded: excl.indexOf(n._id) >= 0,
                                probe: (probe && probe.kind === 'probe') ? probe : null,
                                hasProbe: hasProbe,
                                modes: {
                                    clean: hasProbe ? obj.devModeAllowed(probe, 'clean', 'true').allowed : false,
                                    keepfiles: hasProbe ? obj.devModeAllowed(probe, 'keepfiles').allowed : false
                                },
                                last: obj.devLast[n._id] || null,
                                pending: pend ? { since: pend.since, kind: pend.kind } : null
                            });
                        }
                    }
                    var pendings = [];
                    for (var pk in obj.devPending) { if (obj.devPending[pk] != null) pendings.push(pk); }
                    devices.sort(function (a, b) { return (a.group === b.group) ? String(a.given || a.host).localeCompare(String(b.given || b.host)) : String(a.group).localeCompare(String(b.group)); });
                    send({ devices: devices, minBuild: obj.DEV_MIN_BUILD, pending: pendings });
                });
            });
        } catch (ex) { send({ error: ex.message }); }
    };

    /** @brief POST dr_probe: re-read the facts of ONE Windows device. */
    obj.devProbeHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        var nodeid = String((req.body || {}).nodeId || '');
        obj.devResolveWindowsNode(nodeid, function (node) {
            var r = obj.devDispatch(nodeid, 'probe', obj.devBuildProbeScript(), null);
            if (r.error) { return send({ error: r.error === 'offline' ? 'The device is offline.' : r.error }); }
            if (r.busy) { return send({ error: 'Another task is still running on this device (winget, OS update, deploy or a reset) - try again when it is done.' }); }
            obj.devLog(nodeid + ' - probe dispatched by ' + ((user && user.name) || '?'));
            send({ started: true });
        }, function (msg) { send({ error: msg }); });
    };

    /**
     * @brief POST dr_reset: reset ONE Windows device after every guard passed.
     * Fields: nodeId, mode ('clean'|'keepfiles'), confirm (typed device name), bitlockerAck ('true').
     * Server-side gates (all re-checked on the device by the script):
     *  - the device name has to be typed exactly (case-insensitive, trimmed) - the confirmation guard;
     *  - a fresh probe is required, and the mode must be allowed by it;
     *  - 'clean' with BitLocker protection on/unknown needs bitlockerAck='true' (recovery key);
     *  - the device must be online and idle (no other engine's session).
     */
    obj.devResetHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        var body = req.body || {};
        var nodeid = String(body.nodeId || '');
        var mode = (body.mode === 'keepfiles') ? 'keepfiles' : ((body.mode === 'clean') ? 'clean' : '');
        if (mode === '') { return send({ error: 'mode must be clean or keepfiles.' }); }
        var ack = (body.bitlockerAck === 'true' || body.bitlockerAck === true) ? 'true' : '';
        obj.devResolveWindowsNode(nodeid, function (node) {
            // typed-name confirmation: match the given name, else the hostname (what the UI shows)
            var typed = String(body.confirm || '').trim();
            var given = (typeof node.name === 'string') ? node.name.trim() : '';
            var host = String(obj.getHostName(node) || '').trim();
            var want = given !== '' ? given : host;
            if (typed === '' || (typed.toLowerCase() !== String(want || '').toLowerCase() && (given === '' || typed.toLowerCase() !== host.toLowerCase()))) {
                return send({ error: 'Type the device name "' + (want || nodeid) + '" exactly to confirm.' });
            }
            var probe = obj.devResults[nodeid];
            var gate = obj.devModeAllowed(probe, mode, ack);
            if (!gate.allowed) { return send({ error: gate.reason }); }
            var ws = obj.meshServer.webserver;
            if (ws == null || ws.wsagents == null || ws.wsagents[nodeid] == null) { return send({ error: 'The device is offline - a reset needs a live connection.' }); }
            var r = obj.devDispatch(nodeid, 'reset', obj.devBuildResetScript(mode, ack === 'true'), { mode: mode, ack: (ack === 'true') });
            if (r.error) { return send({ error: r.error === 'offline' ? 'The device is offline.' : r.error }); }
            if (r.busy) { return send({ error: 'Another task is still running on this device - wait for it and try again.' }); }
            obj.devLog(nodeid + ' - RESET (' + mode + ') dispatched by ' + ((user && user.name) || '?') + (ack === 'true' ? ' (BitLocker recovery key confirmed)' : ''));
            obj.wgRaiseNodeEvent(nodeid, 'PC reset (' + mode + '): started by ' + ((user && user.name) || 'admin') + '.');
            send({ started: true, mode: mode });
        }, function (msg) { send({ error: msg }); });
    };
};
