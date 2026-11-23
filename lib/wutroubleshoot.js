/**
 * @file lib/wutroubleshoot.js
 * @brief Windows Update troubleshooter (issue #3, v4.6.0): per-device Diagnose and Troubleshoot for a
 * single Windows PC, built on the same transport as the OS engine (invscanner-wu- sessions, marker
 * @@INVWU@@) and applied DIRECTLY rather than through the interactive msdt.exe wizard - the built-in
 * 'Get/Invoke-TroubleshootingPack' cmdlets were removed in Windows 10 1709, so the deterministic and
 * auditable way to reproduce the troubleshooter is to run the repairs it applies.
 * 'Diagnose' is read-only: it reports the Windows Update services (state + start type), whether a
 * REBOOT is pending and WHEN Windows will perform it automatically, the size of the download cache and
 * the last WindowsUpdateClient errors. 'Troubleshoot' applies the standard WU-component reset that the
 * troubleshooter's "apply fixes" step performs: restart BITS/wuauserv/appidsvc/cryptsvc/msiserver, reset
 * the SoftwareDistribution\Download and System32\catroot2 folders and re-assert the Automatic start
 * types. A repair NEVER reboots the device on its own - but (v4.6.0 policy) it always says plainly
 * whether a reboot is pending and when it is going to happen automatically.
 * One runcommands session per agent applies here too: a device with a diagnose/repair in flight is
 * skipped by the winget/OS/deploy/reset pumps, and this engine refuses to start on a busy device.
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
    /** @brief marker of the one-line JSON answer of a diagnose/repair script. */
    obj.WU_MARKER = '@@INVWU@@';

    /** @brief session/responseid prefix of a Windows Update troubleshooter command. */
    obj.WU_SESSION_PREFIX = 'invscanner-wu-';

    /** @type {number} A diagnose is quick; a repair restarts services and renames folders (still fast). */
    obj.WU_TIMEOUT_MS = 8 * 60 * 1000;

    /** @type {Array<string>} The services the troubleshooter manages, in the order the scripts report them. */
    obj.WU_SERVICES = ['wuauserv', 'bits', 'appidsvc', 'cryptsvc', 'msiserver', 'UsoSvc'];

    /** @type {Object<string, object>} nodeid -> live { sid, kind:'diag'|'repair', since, timer }. */
    obj.wuPending = {};

    /** @type {Object<string, object>} nodeid -> last diagnose or repair record (persisted). */
    obj.wuResults = {};

    /** @brief Append a line to the troubleshooter log (rotated once at ~5 MB). */
    obj.wuLog = function (line) {
        try {
            var dir = path.dirname(obj.wuLogPath);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            try { if (fs.existsSync(obj.wuLogPath) && (fs.statSync(obj.wuLogPath).size > 5 * 1024 * 1024)) { fs.renameSync(obj.wuLogPath, obj.wuLogPath + '.old'); } } catch (e) { }
            fs.appendFileSync(obj.wuLogPath, new Date().toISOString() + ' ' + line + String.fromCharCode(10));
        } catch (e) { }
    };

    obj.wuLoadResults = function () {
        obj.wuResults = {};
        try { if (fs.existsSync(obj.wuResultsPath)) { var d = JSON.parse(fs.readFileSync(obj.wuResultsPath, 'utf8')); if (d && typeof d === 'object') { obj.wuResults = d; } } } catch (e) { obj.wuResults = {}; }
    };

    obj.wuSaveResults = function () {
        try {
            var dir = path.dirname(obj.wuResultsPath);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            fs.writeFileSync(obj.wuResultsPath, JSON.stringify(obj.wuResults));
        } catch (e) { obj.wuLog('could not save results: ' + e.message); }
    };

    /** @brief Windows-only node test (the Windows Update troubleshooter is a Windows tool). */
    obj.wuIsWindowsNode = function (node) {
        if (node == null) return false;
        return /windows/i.test(String(node.osdesc || ''));
    };

    /**
     * @brief The shared read/repair header lines + the reboot state (a single statement per line).
     * Sets $invWu (the result hashtable) and computes a pending-reboot verdict with a human note that
     * says WHEN Windows will restart the device automatically - the v4.6.0 "tell, do not forbid" policy.
     * @param {string} kind - 'diag' | 'repair' (only affects the initial hashtable).
     * @returns {Array<string>} script lines (before the feature-specific work).
     */
    obj.wuHead = function (kind) {
        var init = (kind === 'repair')
            ? "$invWu = @{ repair = $true; state = 'ok'; steps = @(); rebootTriggered = $false; rebootPending = $false; rebootSource = ''; rebootNote = ''; error = '' }"
            : "$invWu = @{ diag = $true; services = @(); swExists = $false; swBytes = 0; swFiles = 0; events = @(); winhttp = ''; rebootPending = $false; rebootSource = ''; rebootNote = ''; error = '' }";
        return [
            "$ProgressPreference = 'SilentlyContinue'",
            "$ErrorActionPreference = 'SilentlyContinue'",
            init
        ].concat(obj.psTranscriptLines('invscanner-wutroubleshoot.log'), [
            "$invWu.rebootPending = $false; $invWu.rebootSource = ''",
            "if (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired') { $invWu.rebootPending = $true; $invWu.rebootSource = 'Windows Update' }",
            "if (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending') { $invWu.rebootPending = $true; if ($invWu.rebootSource) { $invWu.rebootSource = $invWu.rebootSource + ' + CBS' } else { $invWu.rebootSource = 'CBS' } }",
            "if ($invWu.rebootPending) { $invWu.rebootNote = 'A reboot is already pending (' + $invWu.rebootSource + '). Windows will restart the device automatically - at the automatic-restart deadline / outside the active hours, or the next time an update installs. No further reboot is triggered by this run.' } else { $invWu.rebootNote = 'No reboot is pending, and this run does not trigger one.' }"
        ]);
    };

    /**
     * @brief Read-only diagnose script. Reports services, reboot state + when, the download cache size
     * and the last WindowsUpdateClient errors. Changes nothing.
     * @returns {string} The script text.
     */
    obj.wuBuildDiagnoseScript = function () {
        return obj.wuHead('diag').concat([
            "foreach ($invN in @('" + obj.WU_SERVICES.join("','") + "')) { $invS = Get-Service -Name $invN -ErrorAction SilentlyContinue; $invM = ''; try { $invM = [string](Get-CimInstance Win32_Service -Filter ('Name=' + [char]39 + $invN + [char]39)).StartMode } catch { }; $invSt = 'missing'; if ($invS) { $invSt = [string]$invS.Status }; $invWu.services += @{ name = $invN; status = $invSt; startup = $invM } }",
            "$invDl = 'C:\\Windows\\SoftwareDistribution\\Download'; $invWu.swExists = [bool](Test-Path -LiteralPath $invDl); if ($invWu.swExists) { $invF = @(Get-ChildItem -LiteralPath $invDl -Recurse -File -ErrorAction SilentlyContinue); $invWu.swFiles = [int]$invF.Count; $invWu.swBytes = [Int64](($invF | Measure-Object -Property Length -Sum).Sum); if (-not $invWu.swBytes) { $invWu.swBytes = 0 } }",
            "$invWu.events = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WindowsUpdateClient'; Level = 1, 2, 3 } -MaxEvents 5 -ErrorAction SilentlyContinue | ForEach-Object { @{ time = $_.TimeCreated.ToString('o'); id = [int]$_.Id; level = [string]$_.LevelDisplayName; msg = ($_.Message -replace '[\\r\\n]+', ' ') } })",
            "try { $invWu.winhttp = [string]((netsh winhttp show proxy) -join ' ') } catch { $invWu.winhttp = '' }",
            "$invWu | ConvertTo-Json -Compress -Depth 6 | ForEach-Object { Write-Output ('" + obj.WU_MARKER + "' + $_) }",
            "Stop-Transcript -ErrorAction SilentlyContinue | Out-Null"
        ]).join(String.fromCharCode(10));
    };

    /**
     * @brief Repair script - the fixes the troubleshooter's "apply fixes" step performs, run directly
     * and WITHOUT a reboot. wuStep() records ok/failed per step so a partial run stays honest.
     * @returns {string} The script text.
     */
    obj.wuBuildRepairScript = function () {
        return obj.wuHead('repair').concat([
            "function invWuStep([string]$invName, [scriptblock]$invBlock) { $invDet = ''; $invOK = $true; try { & $invBlock } catch { $invOK = $false; $invDet = $_.Exception.Message }; $invWu.steps += @{ name = $invName; ok = $invOK; detail = (($invDet -replace '[\\r\\n]+', ' ').Substring(0, [Math]::Min(200, ($invDet -replace '[\\r\\n]+', ' ').Length))) } }",
            "invWuStep 'stop services' { foreach ($invN in @('wuauserv', 'bits', 'appidsvc', 'cryptsvc', 'msiserver')) { try { Stop-Service -Name $invN -Force -ErrorAction Stop } catch { } }; Start-Sleep -Seconds 3 }",
            "invWuStep 'reset download folder' { $invP = 'C:\\Windows\\SoftwareDistribution\\Download'; if (Test-Path -LiteralPath $invP) { $invD = $invP + '.old-' + (Get-Date -Format 'yyyyMMddHHmmss'); Move-Item -LiteralPath $invP -Destination $invD -Force; $null = New-Item -ItemType Directory -Path $invP -Force } }",
            "invWuStep 'reset catroot2' { $invP = 'C:\\Windows\\System32\\catroot2'; if (Test-Path -LiteralPath $invP) { $invD = $invP + '.old-' + (Get-Date -Format 'yyyyMMddHHmmss'); Move-Item -LiteralPath $invP -Destination $invD -Force; $null = New-Item -ItemType Directory -Path $invP -Force } }",
            "invWuStep 'set start types' { foreach ($invN in @('wuauserv', 'bits', 'appidsvc', 'cryptsvc')) { try { Set-Service -Name $invN -StartupType Automatic -ErrorAction Stop } catch { } } }",
            "invWuStep 'start services' { foreach ($invN in @('bits', 'cryptsvc', 'appidsvc', 'wuauserv', 'UsoSvc')) { try { Start-Service -Name $invN -ErrorAction SilentlyContinue } catch { } } }",
            "$invBad = @($invWu.steps | Where-Object { -not $_.ok }); if ($invBad.Count -gt 0) { $invWu.state = 'partial' }",
            "$invLocked = $false; foreach ($invS in $invWu.steps) { if ((-not $invS.ok) -and (($invS.name -eq 'reset download folder') -or ($invS.name -eq 'reset catroot2'))) { $invLocked = $true } }",
            "$invWu.rebootTriggered = $false",
            "if ($invWu.rebootPending) { $invWu.rebootNote = 'The repair did NOT reboot the device. A reboot was already pending (' + $invWu.rebootSource + '); Windows restarts it automatically (automatic-restart deadline / outside active hours / next update install), or you can reboot now to finish applying the component reset.' } elseif ($invLocked) { $invWu.rebootNote = 'The repair did NOT reboot the device. Some update files were locked and could not be renamed - reboot the device and run the troubleshooter again (a later automatic restart applies it too).' } else { $invWu.rebootNote = 'The repair did NOT reboot the device and none is needed - the Windows Update components were reset in place.' }",
            "$invWu | ConvertTo-Json -Compress -Depth 6 | ForEach-Object { Write-Output ('" + obj.WU_MARKER + "' + $_) }",
            "Stop-Transcript -ErrorAction SilentlyContinue | Out-Null"
        ]).join(String.fromCharCode(10));
    };

    /**
     * @brief Send one diagnose/repair command to a single, online, idle Windows node. Reserves the
     * node's single runcommands session synchronously (same rule as devDispatch/wgPump/osPump).
     * @returns {object} { started } | { busy } | { error }
     */
    obj.wuDispatch = function (nodeid, kind, script) {
        try {
            var ws = obj.meshServer.webserver;
            if (!obj.routeHookInstalled) { try { obj.installRouteHook(); } catch (e) { } }
            var agent = (ws != null && ws.wsagents != null) ? ws.wsagents[nodeid] : null;
            if ((agent == null) || (typeof agent.send !== 'function')) return { error: 'offline' };
            if ((obj.wuPending[nodeid] != null) || (obj.devPending != null && obj.devPending[nodeid] != null) ||
                (obj.wgPending != null && obj.wgPending[nodeid] != null) || (obj.osPending != null && obj.osPending[nodeid] != null) ||
                (obj.swPending != null && obj.swPending[nodeid] != null)) {
                return { busy: true };
            }
            var sid = obj.WU_SESSION_PREFIX + obj.safeNodeDir(nodeid);
            var entry = { nodeid: nodeid, sid: sid, kind: kind, since: Date.now() };
            entry.timer = setTimeout(function () { obj.wuTimeout(entry); }, obj.WU_TIMEOUT_MS);
            obj.wuPending[nodeid] = entry;
            try {
                agent.send(JSON.stringify({ action: 'runcommands', type: 1, cmds: obj.wgTransport(script), runAsUser: 0, reply: true, sessionid: sid, responseid: sid }));
            } catch (ex) {
                clearTimeout(entry.timer); delete obj.wuPending[nodeid];
                return { error: 'send-failed: ' + ex.message };
            }
            return { started: true, sid: sid };
        } catch (e) { return { error: e.message }; }
    };

    /** @brief True when a node currently has a troubleshooter session in flight. */
    obj.wuIsBusy = function (nodeid) { return (nodeid != null) && (obj.wuPending != null) && (obj.wuPending[nodeid] != null); };

    /**
     * @brief Answer of one diagnose/repair session (consumed by the route hook in lib/collector.js).
     */
    obj.wuHandleResponse = function (nodeid, command) {
        var entry = obj.wuPending[nodeid];
        if (entry == null) return;
        if (entry.timer) { clearTimeout(entry.timer); }
        delete obj.wuPending[nodeid];
        var text = (typeof command.result === 'string') ? command.result : JSON.stringify(command.result || '');
        var data = obj.wgPayloadFromText(text, obj.WU_MARKER);
        if ((data == null) && (typeof entry.cbuf === 'string')) { data = obj.wgPayloadFromText(entry.cbuf, obj.WU_MARKER); }
        var s = function (v, n) { return String(v == null ? '' : v).substring(0, n); };
        var rec = { kind: entry.kind, time: new Date().toISOString() };
        if (data == null) {
            rec.state = (text.indexOf(obj.WU_MARKER) >= 0) ? 'error' : 'no-marker';
            obj.wuResults[nodeid] = rec; obj.wuLog(nodeid + ' - ' + entry.kind + ': ' + rec.state); obj.wuSaveResults();
            obj.wgRaiseNodeEvent(nodeid, 'Windows Update troubleshooter: ' + rec.state);
            return;
        }
        rec.rebootPending = data.rebootPending === true;
        rec.rebootSource = s(data.rebootSource, 40);
        rec.rebootNote = s(data.rebootNote, 500);
        if (entry.kind === 'diag') {
            rec.state = 'ok';
            rec.services = Array.isArray(data.services) ? data.services.slice(0, 20).map(function (x) { return { name: s(x && x.name, 24), status: s(x && x.status, 16), startup: s(x && x.startup, 16) }; }) : [];
            rec.swExists = data.swExists === true; rec.swBytes = (typeof data.swBytes === 'number') ? data.swBytes : 0; rec.swFiles = (typeof data.swFiles === 'number') ? data.swFiles : 0;
            rec.events = Array.isArray(data.events) ? data.events.slice(0, 5).map(function (x) { return { time: s(x && x.time, 30), id: (typeof x.id === 'number') ? x.id : null, level: s(x && x.level, 16), msg: s(x && x.msg, 300) }; }) : [];
            rec.winhttp = s(data.winhttp, 200);
            var stopped = rec.services.filter(function (x) { return x.status !== 'Running'; }).map(function (x) { return x.name; });
            obj.wuLog(nodeid + ' - diagnose: reboot=' + (rec.rebootPending ? ('pending(' + rec.rebootSource + ')') : 'no') + ' download=' + rec.swFiles + ' files' + (stopped.length ? (' - not running: ' + stopped.join(', ')) : ' - all WU services running'));
        } else {
            rec.state = (data.state === 'partial') ? 'partial' : 'ok';
            rec.rebootTriggered = data.rebootTriggered === true;
            rec.steps = Array.isArray(data.steps) ? data.steps.slice(0, 20).map(function (x) { return { name: s(x && x.name, 40), ok: (x && x.ok) === true, detail: s(x && x.detail, 200) }; }) : [];
            var okc = rec.steps.filter(function (x) { return x.ok; }).length;
            obj.wuLog(nodeid + ' - repair: ' + rec.state + ' (' + okc + '/' + rec.steps.length + ' steps ok)' + (rec.rebootPending ? ' - REBOOT PENDING: ' + rec.rebootSource : '') + ' - ' + rec.rebootNote);
            for (var i = 0; i < rec.steps.length; i++) { if (!rec.steps[i].ok) { obj.wuLog(nodeid + ' - step FAILED ' + rec.steps[i].name + (rec.steps[i].detail ? (': ' + rec.steps[i].detail) : '')); } }
        }
        obj.wuResults[nodeid] = rec; obj.wuSaveResults();
        var ev = (entry.kind === 'diag')
            ? ('Windows Update check: reboot ' + (rec.rebootPending ? 'pending (' + rec.rebootSource + ')' : 'none') + (stopped && stopped.length ? ', services stopped: ' + stopped.join(', ') : ', all WU services running'))
            : ('Windows Update repair: ' + rec.state + ' (' + okc + '/' + rec.steps.length + ' steps) - ' + rec.rebootNote);
        obj.wgRaiseNodeEvent(nodeid, ev.substring(0, 300));
    };

    /** @brief Watchdog for a diagnose/repair session that never answered. */
    obj.wuTimeout = function (entry) {
        if ((entry == null) || (obj.wuPending[entry.nodeid] !== entry)) return;
        delete obj.wuPending[entry.nodeid];
        obj.wuResults[entry.nodeid] = { kind: entry.kind, state: 'timeout', time: new Date().toISOString() };
        obj.wuLog(entry.nodeid + ' - ' + entry.kind + ': no answer within the timeout');
        obj.wgRaiseNodeEvent(entry.nodeid, 'Windows Update troubleshooter: the device did not answer within the timeout');
        obj.wuSaveResults();
    };

    /** @brief Shared validation + dispatch for one Windows device (diagnose or repair). */
    obj.wuStart = function (req, res, user, kind) {
        var send = function (o) { res.type('json'); res.json(o); };
        var nodeid = String((req.body || {}).nodeId || '');
        if (!/^node\/[^:]{1,100}$/.test(nodeid)) { return send({ error: 'Invalid node id.' }); }
        obj.db.Get(nodeid, function (err, docs) {
            if (err || !docs || !docs.length || docs[0] == null || docs[0].deleted != null) { return send({ error: 'Unknown device.' }); }
            var node = docs[0];
            if (!obj.wuIsWindowsNode(node)) { return send({ error: 'The Windows Update troubleshooter is only available on Windows devices.' }); }
            var script = (kind === 'repair') ? obj.wuBuildRepairScript() : obj.wuBuildDiagnoseScript();
            var r = obj.wuDispatch(nodeid, kind, script);
            if (r.error) { return send({ error: r.error === 'offline' ? 'The device is offline.' : r.error }); }
            if (r.busy) { return send({ error: 'Another task is still running on this device (winget, OS update, deploy, reset or another troubleshooter run) - try again later.' }); }
            obj.wuLog(nodeid + ' - ' + kind + ' dispatched by ' + ((user && user.name) || '?'));
            if (kind === 'repair') { obj.wuRaiseRepairPending(nodeid); }
            send({ started: true, kind: kind });
        });
    };

    /** @brief A device event that a repair is running (reboot, if any, stays only a pending note). */
    obj.wuRaiseRepairPending = function (nodeid) {
        try { obj.wgRaiseNodeEvent(nodeid, 'Windows Update troubleshooter: repairing the update components on this device (services restart, download and catroot2 reset; no reboot is triggered).'); } catch (e) { }
    };

    /** @brief POST wu_diag: read-only diagnose of one Windows device. */
    obj.wuDiagHandler = function (req, res, user) { obj.wuStart(req, res, user, 'diag'); };

    /** @brief POST wu_repair: run the troubleshooter repairs on one Windows device. */
    obj.wuRepairHandler = function (req, res, user) { obj.wuStart(req, res, user, 'repair'); };
};
