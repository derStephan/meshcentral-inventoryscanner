/**
 * @file lib/winget.js
 * @brief winget auto-update engine: PowerShell script builder, cmd.exe transport, device queue, agent-reply parsing, results/log persistence, day-based scheduling and the two watchdogs.
 * Verified transport (meshcore.js): {action:'runcommands', type:1 (cmd.exe), runAsUser:0, reply:true, sessionid, responseid} -> the agent answers {action:'msg', type:'runcommands', ...}, captured by this plugin's routeAgentCommand hook. One script per device does list -> filter(ignore) -> per-package upgrade -> pin sync and answers with a single @@INVWUP@@ marker line of compressed JSON.
 *
 * Part of the MeshCentral Inventory & Vulnerability Scanner plugin; see ../inventoryscanner.js
 * for the module list and the attach order. Every member is attached to the shared plugin
 * object, so cross-module calls go through obj.name(...) and stay replaceable at runtime.
 */

"use strict";

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

/**
 * @brief Attach this module's members to one plugin instance.
 * @param {object} obj - The plugin object created by the entry point.
 */
module.exports.attach = function (obj) {
    /** @type {Object<string, object>} nodeid -> in-flight run bookkeeping. */
    obj.wgPending = {};

    /** @type {Array<string>} queued node ids. */
    obj.wgQueue = [];

    /** @type {number} number of devices currently being updated. */
    obj.wgActive = 0;

    /** @type {Object} nodeid -> { time, winget, results[], error? } of the last run. */
    obj.wgResults = {};

    /** @type {boolean} true while a batch (scheduled or manual) occupies the queue. */
    obj.wgBatchRunning = false;

    /** @type {boolean} true while the running batch is a report-only dry run. */
    obj.wgBatchDry = false;

    /** @type {object|null} extra script options for the running batch: { mode, onlyId }. */
    obj.wgBatchOpts = null;

    obj.WINGET_MAX_PARALLEL = 2;

    /** @type {number} hard cap of devices per batch (pre-3.0.1 this constant was referenced but undefined). */
    obj.WINGET_MAX_DEVICES = 5000;

    obj.WINGET_RUN_TIMEOUT_MS = 2 * 60 * 60 * 1000;

    obj.WINGET_DRY_TIMEOUT_MS = 10 * 60 * 1000;

    obj.WINGET_MARKER = '@@INVWUP@@';

    obj.WINGET_ID_RE = /^[A-Za-z0-9._+-]{1,128}$/;

    /** @brief Unsigned hex of a signed win32 exit code (winget documents its codes in hex). */
    obj.wgExitHex = function (n) {
        try { return ((n | 0) >>> 0).toString(16).toUpperCase(); } catch (e) { return ''; }
    };

    /**
     * @brief Effective winget updater configuration (scanner-settings.json
     * overlay first, config.json settings.wingetUpdater second, defaults last).
     * @returns {object} <code>{ enabled, intervalHours, meshes, excludeNodes, ignorePackages, pinSync }</code>
     */
    obj.wingetConfig = function () {
        var cfg = null;
        try { cfg = obj.effectiveSectionConfig('wingetUpdater'); } catch (e) { }
        var out = { enabled: false, intervalHours: 168, meshes: null, excludeNodes: [], ignorePackages: [], pinSync: true };
        if (cfg && (typeof cfg === 'object')) {
            if (typeof cfg.enabled === 'boolean') { out.enabled = cfg.enabled; }
            if (typeof cfg.intervalHours === 'number' && cfg.intervalHours >= 1 && cfg.intervalHours <= 87600) { out.intervalHours = cfg.intervalHours; }
            if (Array.isArray(cfg.updateMeshes) && cfg.updateMeshes.length > 0) { out.meshes = cfg.updateMeshes.slice(); }
            if (Array.isArray(cfg.excludeNodes)) {
                out.excludeNodes = cfg.excludeNodes.filter(function (x) { return (typeof x === 'string') && /^node\/[^:]{1,100}$/.test(x); });
            }
            if (Array.isArray(cfg.ignorePackages)) {
                out.ignorePackages = cfg.ignorePackages.filter(function (x) { return x && (typeof x.id === 'string') && obj.WINGET_ID_RE.test(x.id); })
                    .map(function (x) { return { id: x.id, note: (typeof x.note === 'string') ? x.note.substring(0, 200) : '' }; });
            }
            if (typeof cfg.pinSync === 'boolean') { out.pinSync = cfg.pinSync; }
        }
        return out;
    };

    /**
     * @brief PowerShell lines that open the client transcript (shared by the winget and the
     * OS update scripts). Client transcript location (v3.0.1): only folders that standard users
     * cannot write to. 1) the agent folder (found via the process ancestors), 2) a dedicated
     * %ProgramData%\\InventoryScanner folder that is created with an ACL for SYSTEM +
     * Administrators only and refused when it already exists with another owner or as a
     * reparse point. Plain %ProgramData% / %TEMP% are not used (both allow file creation by
     * standard users). Without a safe folder the run continues without a transcript.
     * Sets $invTDir (safe folder or $null) and $invT (transcript file or $null).
     * @param {string} fileName - Transcript file name (fixed literal, never user input).
     * @returns {Array<string>} One statement per line.
     */
    obj.psTranscriptLines = function (fileName) {
        var fn = String(fileName).replace(/[^A-Za-z0-9._-]/g, '');
        return [
            "$invTDir = $null",
            "try { $invQ = $PID; for ($invHop = 0; $invHop -lt 4; $invHop++) { $invPP = 0; try { $invPP = (Get-CimInstance Win32_Process -Filter ('ProcessId={0}' -f $invQ) -ErrorAction Stop).ParentProcessId } catch { break }; if (-not $invPP) { break }; $invPX = $null; try { $invPX = (Get-Process -Id $invPP -ErrorAction Stop).Path } catch { break }; if ($invPX -and ((Split-Path $invPX -Leaf) -imatch '^(meshagent|meshcentral)[a-z0-9_-]*\\.exe$')) { $invTDir = Split-Path $invPX; break }; $invQ = $invPP } } catch { }",
            "if ($null -eq $invTDir) { try { $invLD = Join-Path $env:ProgramData 'InventoryScanner'; $invOK = @('S-1-5-18', 'S-1-5-32-544'); if (Test-Path -LiteralPath $invLD) { $invLI = Get-Item -LiteralPath $invLD -Force; $invOw = (Get-Acl -LiteralPath $invLD).GetOwner([System.Security.Principal.SecurityIdentifier]).Value; if (($invLI.Attributes -band [IO.FileAttributes]::ReparsePoint) -or ($invOK -notcontains $invOw)) { $invLD = $null } } else { $null = New-Item -ItemType Directory -Path $invLD -ErrorAction Stop; $invDS = New-Object System.Security.AccessControl.DirectorySecurity; $invDS.SetAccessRuleProtection($true, $false); foreach ($invS in $invOK) { $invDS.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object System.Security.Principal.SecurityIdentifier($invS)), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))) }; Set-Acl -LiteralPath $invLD -AclObject $invDS -ErrorAction Stop }; $invTDir = $invLD } catch { $invTDir = $null } }",
            "$invT = $null; if ($invTDir) { $invT = Join-Path $invTDir '" + fn + "' }",
            "if ($invT -and (Test-Path -LiteralPath $invT)) { try { $invFI = Get-Item -LiteralPath $invT -Force; if ($invFI.Attributes -band [IO.FileAttributes]::ReparsePoint) { $invT = $null } elseif ($invFI.Length -gt 5MB) { Move-Item -LiteralPath $invT ($invT + '.old') -Force } } catch { } }",
            "if ($invT) { try { '' | Out-File -FilePath $invT -Append -Encoding utf8 -ErrorAction Stop } catch { $invT = $null } }",
            "if ($invT) { try { Start-Transcript -Path $invT -Append | Out-Null } catch { } }"
        ];
    };

    /**
     * @brief Build the one-shot PowerShell script (runs as SYSTEM over the
     * agent's runcommands channel). Transport: wgTransport wraps the whole script
     * into ONE gzip+base64 line for cmd.exe, so PowerShell receives it atomically;
     * every statement is nevertheless kept on a single line (defense in depth,
     * guarded by a test).
     * @param {object} wcfg - The winget config section.
     * @param {boolean} [dry] - Dry run: list only, install/pin nothing.
     * @param {object} [opts] - { onlyId: winget id (already WINGET_ID_RE-validated) to
     *   touch exactly this package, mode: 'update' (default) | 'uninstall' }.
     *   Uninstall REQUIRES onlyId, probes existence with a case-insensitive id
     *   containment check on 'winget list --id <id> --exact' output (no reliance on
     *   exit-code or message localization) and then 'winget uninstall --id --exact
     *   --silent' (winget uninstall has NO --accept-package-agreements option - passing it
     *   aborts with "Argument name was not recognized", verified on winget 1.29),
     *   state ok/failed by exit code.
     * @returns {string} The script text.
     */
    obj.wgBuildScript = function (wcfg, dry, opts) {
        opts = opts || {};
        var mode = (opts.mode === 'uninstall') ? 'uninstall' : 'update';
        var onlyId = (typeof opts.onlyId === 'string' && obj.WINGET_ID_RE.test(opts.onlyId)) ? opts.onlyId : '';
        if (mode === 'uninstall' && onlyId === '') { throw new Error('wgBuildScript: uninstall requires a validated onlyId'); }
        var ids = [];
        for (var i = 0; i < wcfg.ignorePackages.length; i++) {
            var id = wcfg.ignorePackages[i].id;
            if (obj.WINGET_ID_RE.test(id) && (ids.indexOf(id) < 0)) { ids.push(id); }
        }
        var psList = ids.map(function (x) { return "'" + x.replace(/'/g, "''") + "'"; }).join(', ');
        var pinLines = (mode === 'update' && onlyId === '' && !dry && wcfg.pinSync && ids.length > 0) ? [
            "foreach ($pn in $invIgnore) { try { $null = (& $wg pin add --id $pn --installed --exact --accept-source-agreements --disable-interactivity) 2>&1 } catch { } }"
        ] : [];
        var dryGuard = dry
            ? "if ($invDry) { $results += @{ id = $p.id; name = $p.name; from = $p.from; to = $p.to; state = 'dry-run' }; continue };"
            : "";
        var onlyGuard = (mode === 'update' && onlyId !== '')
            ? "if ($p.id -ine $invOnly) { continue };"
            : "";
        var head = [
            "$ProgressPreference = 'SilentlyContinue'",
            "$invDry = " + (dry ? '$true' : '$false'),
            "$invMode = '" + (mode === 'uninstall' ? 'uninstall' : (dry ? 'scan' : 'update')) + "'",
            "$invOnly = '" + onlyId.replace(/'/g, "''") + "'"
        ].concat(obj.psTranscriptLines('invscanner-winget.log'), [
            "$wg = $null",
            "$invAP = $null; if (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\winget.exe') { $invAP = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\winget.exe' -ErrorAction SilentlyContinue).'(default)' }; if ($invAP -and (Test-Path $invAP)) { $wg = $invAP }",
            // Lookup order: App Paths, the admin-only WindowsApps package folder (newest first),
            // then PATH. Get-Command returns an ApplicationInfo whose location is in .Path
            // (.FullName is empty there - the pre-3.0.1 code therefore never used the PATH hit).
            "if (-not $wg) { foreach ($wc in @((Get-ChildItem ($env:ProgramFiles + \"\\WindowsApps\\Microsoft.DesktopAppInstaller_*\\winget.exe\") -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1), (Get-Command winget -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1))) { if ($null -ne $wc) { $invWP = $null; if ($wc.Path) { $invWP = [string]$wc.Path } elseif ($wc.FullName) { $invWP = [string]$wc.FullName }; if ($invWP) { $wg = $invWP; break } } } }",
            "if ($wg -eq $null) { Write-Output '" + obj.WINGET_MARKER + "{\"winget\":false}'; Stop-Transcript -ErrorAction SilentlyContinue | Out-Null; exit }",
            "$invIgnore = @(" + psList + ")",
            "$results = @()"
        ]);
        if (mode === 'uninstall') {
            // existence probe: case-insensitive containment of the id in 'winget list --id X --exact'
            // output - no exit-code mythology and no reliance on (localizable) message text.
            head.push(
                "$invProbe = ''",
                "try { $invProbe = ((& $wg list --id $invOnly --exact --accept-source-agreements --disable-interactivity) 2>&1) -join ' ' } catch { $invProbe = '' }",
                "if ($invProbe -inotmatch ([regex]::Escape($invOnly))) { $results += @{ id = $invOnly; name = ''; from = ''; to = ''; state = 'not-installed' } } else { $o = (& $wg uninstall --id $invOnly --exact --silent --accept-source-agreements --disable-interactivity) 2>&1; $code = $LASTEXITCODE; $tail = (($o | Select-Object -Last 3) -join ' '); if ($tail -isnot [string]) { $tail = [string]$tail }; if ($tail.Length -gt 400) { $tail = $tail.Substring(0,400) }; $st = 'failed'; if ($code -eq 0) { $st = 'ok' }; $results += @{ id = $invOnly; name = ''; from = ''; to = ''; state = $st; exit = $code; log = $tail } }"
            );
        } else {
            head.push(
                "$raw = ''",
                "try { $raw = ((& $wg list --upgrade-available --accept-source-agreements --disable-interactivity) 2>&1) -join [Environment]::NewLine } catch { }",
                "$rows = @()",
                // Table parser (v3.0.1): winget pads columns to a fixed width, so a full-width cell is
                // followed by ONE space only (long names, long ids, long versions, '< x.y' versions).
                // The column starts are therefore taken from the header line above the dash line
                // (language independent: only positions are used); every row is validated (dotted id,
                // non-empty versions/source) and falls back to the old two-space regex when the
                // column cut does not validate. Parsing stops at the table footer.
                "# invscanner:parse-begin",
                "$invLines = @($raw -split '[\\r\\n]+')",
                "$invH = -1; for ($invI = 1; $invI -lt $invLines.Count; $invI++) { if ($invLines[$invI] -match '^\\s*-{10,}\\s*$') { $invH = $invI - 1; break } }",
                "$invC = @(); if ($invH -ge 0) { $invC = @([regex]::Matches($invLines[$invH], '(?:^|(?<=\\s))\\S+') | ForEach-Object { $_.Index }) }",
                "$invEnd = $false; for ($invI = [Math]::Max(0, $invH + 2); ($invI -lt $invLines.Count) -and (-not $invEnd); $invI++) { $line = [string]$invLines[$invI]; $invR = $null; if (($invC.Count -eq 5) -and ($line.Length -gt $invC[4])) { $invR = @($line.Substring(0, $invC[1]).Trim(), $line.Substring($invC[1], $invC[2] - $invC[1]).Trim(), $line.Substring($invC[2], $invC[3] - $invC[2]).Trim(), $line.Substring($invC[3], $invC[4] - $invC[3]).Trim(), $line.Substring($invC[4]).Trim()) }; if (($null -eq $invR) -or ($invR[1] -notmatch '^[A-Za-z0-9._+-]+\\.[A-Za-z0-9._+-]+$') -or ($invR[2] -eq '') -or ($invR[3] -notmatch '^\\S+$') -or ($invR[4] -notmatch '^\\S+$')) { $invR = $null; if ($line -match '^(.+?)\\s{2,}([A-Za-z0-9._+-]+\\.[A-Za-z0-9._+-]+)\\s{2,}(\\S+)\\s{2,}(\\S+)\\s{2,}(\\S+)\\s*$') { $invR = @($matches[1].Trim(), $matches[2], $matches[3], $matches[4], $matches[5]) } }; if ($null -ne $invR) { $rows += [pscustomobject]@{ name = $invR[0]; id = $invR[1]; from = $invR[2]; to = $invR[3] } } elseif (($invH -ge 0) -and (($line -match '^\\s*-{10,}\\s*$') -or ($line -match '^\\s*\\d+\\s'))) { $invEnd = $true } }",
                "# invscanner:parse-end",
                "foreach ($p in $rows) { " + onlyGuard + "$skip = $false; foreach ($ig in $invIgnore) { if ($p.id -ieq $ig) { $skip = $true; break } }; if ($skip) { $results += @{ id = $p.id; name = $p.name; from = $p.from; to = $p.to; state = 'skipped-ignored' }; continue }; if ($p.to -ieq 'Unknown' -or $p.to -eq $p.from) { $results += @{ id = $p.id; name = $p.name; from = $p.from; to = $p.to; state = 'skipped-noversion' }; continue }; " + dryGuard + " $o = (& $wg upgrade --id $p.id --exact --silent --accept-package-agreements --accept-source-agreements --disable-interactivity) 2>&1; $code = $LASTEXITCODE; $tail = (($o | Select-Object -Last 3) -join ' '); if ($tail -isnot [string]) { $tail = [string]$tail }; if ($tail.Length -gt 400) { $tail = $tail.Substring(0,400) }; $st = 'failed'; if ($code -eq 0) { $st = 'ok' }; $results += @{ id = $p.id; name = $p.name; from = $p.from; to = $p.to; state = $st; exit = $code; log = $tail } }"
            );
        }
        return head.concat(pinLines, [
            "if ($null -eq $results) { $results = @() }",
            "@{ winget = $true; dry = $invDry; mode = $invMode; results = @($results) } | ConvertTo-Json -Compress -Depth 5 | ForEach-Object { Write-Output ('" + obj.WINGET_MARKER + "' + $_) }",
            "Stop-Transcript -ErrorAction SilentlyContinue | Out-Null"
        ]).join(String.fromCharCode(10));
    };

    /** @brief Append a line to the winget update log (rotated once at ~5 MB). */
    obj.wgLog = function (line) {
        try {
            var dir = path.dirname(obj.wingetLogPath);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            try { if (fs.existsSync(obj.wingetLogPath) && (fs.statSync(obj.wingetLogPath).size > 5 * 1024 * 1024)) { fs.renameSync(obj.wingetLogPath, obj.wingetLogPath + '.old'); } } catch (e) { }
            fs.appendFileSync(obj.wingetLogPath, new Date().toISOString() + ' ' + line + String.fromCharCode(10));
        } catch (e) { }
    };

    /**
     * @brief Raise a client-side event on the device's events page (MeshCentral
     *   persists DispatchEvent payloads via db.StoreEvent; visibility 'nodes' shows
     *   them to everyone with rights on that machine).
     * @param {string} nodeid - The device.
     * @param {string} msg - One-line summary.
     */
    obj.wgRaiseNodeEvent = function (nodeid, msg) {
        try {
            obj.db.Get(nodeid, function (err, nodes) {
                try {
                    if (err || !nodes || !nodes.length) return;
                    var node = nodes[0];
                    var targets = [nodeid];
                    if (node.meshid != null) { targets.push(node.meshid); }
                    obj.meshServer.DispatchEvent(targets, obj, {
                        etype: 'node', nodeid: nodeid, domain: obj.swNodeDomain(nodeid), msg: msg, visibility: 'nodes'
                    });
                } catch (e) { }
            });
        } catch (e) { }
    };

    /** @brief Load persisted last-run results (survives restarts). */
    obj.wgLoadResults = function () {
        obj.wgResults = {};
        try {
            if (fs.existsSync(obj.wingetResultsPath)) {
                var d = JSON.parse(fs.readFileSync(obj.wingetResultsPath, 'utf8'));
                if (d && (typeof d === 'object')) { obj.wgResults = d; }
            }
        } catch (e) { obj.wgResults = {}; }
    };

    /** @brief Persist results (best-effort, non-blocking errors are logged only). */
    obj.wgSaveResults = function () {
        try {
            var dir = path.dirname(obj.wingetResultsPath);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            fs.writeFileSync(obj.wingetResultsPath, JSON.stringify(obj.wgResults));
        } catch (e) { obj.wgLog('could not save results: ' + e.message); }
    };

    /**
     * @brief winget only exists on Windows. A node counts as Windows once the agent
     *   reported an OS description; nodes that never reported stay visible (unknown OS -
     *   excluding them would hide fresh installs).
     * @param {object} node - The node record.
     * @returns {boolean} true unless the node is provably non-Windows.
     */
    obj.wgIsWindowsNode = function (node) {
        if (node == null) return false;
        var o = String(node.osdesc || '');
        if (o === '') return true;
        return /windows/i.test(o);
    };

    /**
     * @brief Resolve the device list for a batch.
     * @param {boolean} onlyMeshes - restrict to the configured meshes (scheduled runs).
     * @param {function} cb - (nodeids)
     */
    obj.wgTargetNodes = function (onlyMeshes, cb) {
        try {
            var wcfg = obj.wingetConfig();
            obj.db.GetAllType('node', function (err, nodes) {
                if (err || !nodes) { return cb([]); }
                var out = [];
                for (var i = 0; i < nodes.length; i++) {
                    var n = nodes[i];
                    if ((n == null) || (n._id == null) || (n.deleted != null)) continue;
                    if (!obj.wgIsWindowsNode(n)) continue;
                    if (onlyMeshes) {
                        if (wcfg.meshes == null) continue; // scheduled: require explicit group opt-in
                        if (wcfg.meshes.indexOf(n.meshid) < 0) continue;
                    }
                    if (wcfg.excludeNodes.indexOf(n._id) >= 0) continue;
                    out.push(n._id);
                }
                cb(out);
            });
        } catch (e) { cb([]); }
    };

    /**
     * @brief Start a batch of winget updates.
     * @param {string} reason - 'scheduled' | 'manual' (logged).
     * @param {function} [done] - optional callback when the batch queue drained.
     * @returns {object} { started, nodes, busy? }
     */
    /**
     * @brief Start a batch of winget updates.
     * @param {string} reason - 'scheduled' | 'sweep' | 'connect' | 'dry-run' | 'manual'.
     * @param {function} [done] - optional callback when the batch queue drained.
     * @param {Array<string>} [nodeids] - explicit device list (skips the scope
     *   filter; used by per-device runs and the dry-run test button).
     * @param {boolean} [dry] - report only: nothing is installed or pinned.
     * @returns {object} { started, nodes, busy? }
     */
    obj.wgStartBatch = function (reason, done, nodeids, dry, opts) {
        // One agent runs ONE runcommands session at a time (meshcore.js answers "already busy"),
        // so winget batches and OS update batches never overlap (v3.5.0).
        if (obj.wgBatchRunning || obj.osBatchRunning) { return { started: false, busy: true, nodes: 0 }; }
        var wcfg = obj.wingetConfig();
        var launch = function (ids) {
            var what = (dry === true) ? 'DRY-RUN' : ((opts != null && opts.mode === 'uninstall') ? 'uninstall batch' : 'update batch');
            if (ids.length === 0) {
                obj.wgLog(what + ' (' + reason + ') - no target devices');
                if (done) done();
                return;
            }
            obj.wgBatchRunning = true;
            obj.wgBatchDry = dry === true;
            obj.wgBatchOpts = opts || null;
            obj.wgLog(what + ' (' + reason + ') starting for ' + ids.length + ' device(s)');
            obj.wgQueue = ids.slice();
            obj.wgBatchDone = done || null;
            obj.wgPump();
        };
        if (Array.isArray(nodeids) && nodeids.length > 0) { launch(nodeids.slice(0, obj.WINGET_MAX_DEVICES)); return { started: true, nodes: 0 }; }
        obj.wgTargetNodes(reason === 'scheduled' || reason === 'sweep', function (ids) {
            launch(ids);
        });
        return { started: true, nodes: 0 };
    };

    /**
     * @brief Wrap the builder script for the agent's cmd.exe runcommands channel (type 1):
     * ONE powershell -Command line carrying the whole script as base64(gzip(UTF-8)); it is
     * decompressed and run in one piece (no per-line stdin parsing, no quoting issues, the
     * line stays far below cmd's 8191 character limit).
     * @param {string} script - The raw PowerShell text from wgBuildScript.
     * @returns {string} The single-line command.
     */
    obj.wgTransport = function (script) {
        var b64 = zlib.gzipSync(Buffer.from(String(script), 'utf8')).toString('base64');
        return 'powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$d=[Convert]::FromBase64String(\'' + b64 + '\');$m=New-Object IO.MemoryStream(,$d);$g=New-Object IO.Compression.GZipStream($m,[IO.Compression.CompressionMode]::Decompress);$s=(New-Object IO.StreamReader($g,[Text.Encoding]::UTF8)).ReadToEnd();Invoke-Expression $s"';
    };

    /** @brief Feed the queue up to WINGET_MAX_PARALLEL devices. */
    obj.wgPump = function () {
        try {
            while ((obj.wgActive < obj.WINGET_MAX_PARALLEL) && (obj.wgQueue.length > 0)) {
                var nodeid = obj.wgQueue.shift();
                if (obj.wgPending[nodeid] != null) continue; // already running there
                if (obj.swPending != null && obj.swPending[nodeid] != null) continue; // a deploy script holds the single runcommands session (v4.0.0)
                var ws = obj.meshServer.webserver;
                if (!obj.routeHookInstalled) { try { obj.installRouteHook(); } catch (e) { } }
                var agent = (ws != null && ws.wsagents != null) ? ws.wsagents[nodeid] : null;
                if ((agent == null) || (typeof agent.send !== 'function')) {
                    obj.wgResults[nodeid] = { time: new Date().toISOString(), error: 'offline', results: [] };
                    obj.wgLog(nodeid + ' - skipped, agent offline');
                    obj.wgRaiseNodeEvent(nodeid, 'Winget updater: skipped, the agent was offline');
                    continue;
                }
                var sid = 'invscanner-wg-' + obj.safeNodeDir(nodeid);
                var entry = { nodeid: nodeid, sid: sid, since: Date.now() };
                entry.timer = setTimeout(function () { obj.wgTimeout(entry); }, obj.wgBatchDry === true ? obj.WINGET_DRY_TIMEOUT_MS : obj.WINGET_RUN_TIMEOUT_MS);
                obj.wgPending[nodeid] = entry;
                obj.wgActive++;
                try {
                    agent.send(JSON.stringify({ action: 'runcommands', type: 1, cmds: obj.wgTransport(obj.wgBuildScript(obj.wingetConfig(), obj.wgBatchDry === true, obj.wgBatchOpts)), runAsUser: 0, reply: true, sessionid: sid, responseid: sid }));
                    obj.wgLog(nodeid + ' - update script sent (client transcript: invscanner-winget.log next to meshagent.exe or in C:\\ProgramData)');
                } catch (ex) {
                    clearTimeout(entry.timer); delete obj.wgPending[nodeid]; obj.wgActive--;
                    obj.wgResults[nodeid] = { time: new Date().toISOString(), error: 'send-failed: ' + ex.message, results: [] };
                    obj.wgLog(nodeid + ' - send failed: ' + ex.message);
                }
            }
            if ((obj.wgActive === 0) && (obj.wgQueue.length === 0) && obj.wgBatchRunning) {
                obj.wgBatchRunning = false;
                obj.wgBatchDry = false;
                obj.wgBatchOpts = null;
                obj.wgSaveResults();
                obj.wgLog('update batch finished');
                var d = obj.wgBatchDone; obj.wgBatchDone = null;
                if (d) d();
            }
        } catch (e) { obj.wgLog('pump error: ' + e.message); }
    };

    /** @brief Watchdog for a device that never answered. */
    obj.wgTimeout = function (entry) {
        if ((entry == null) || (obj.wgPending[entry.nodeid] !== entry)) return;
        delete obj.wgPending[entry.nodeid];
        obj.wgActive--;
        obj.wgResults[entry.nodeid] = { time: new Date().toISOString(), error: 'timeout', results: [] };
        obj.wgLog(entry.nodeid + ' - no answer within the run timeout');
        obj.wgRaiseNodeEvent(entry.nodeid, 'Winget updater: the device did not answer within the timeout');
        obj.wgPump();
    };

    /**
     * @brief Extract the marker payload from an output text. The answer is ONE
     * ConvertTo-Json -Compress line, so the payload ends at the first line break
     * after the marker - anything printed afterwards (e.g. a cmd banner or a
     * transcript notice that was not silenced) cannot corrupt it, and anything
     * before it is ignored. Chunks split across packets are handled by the
     * caller feeding the accumulated buffer (wgPending entry .cbuf).
     * @param {string} text - raw agent output.
     * @returns {object|null} Parsed answer object, null when absent/unparsable.
     */
    obj.wgPayloadFromText = function (text, marker) {
        try {
            var mk = (typeof marker === 'string' && marker !== '') ? marker : obj.WINGET_MARKER;
            var idx = String(text).lastIndexOf(mk);
            if (idx < 0) return null;
            var payload = String(text).substring(idx + mk.length);
            var nl = payload.search(/[\r\n]/);
            if (nl >= 0) payload = payload.substring(0, nl);
            payload = payload.trim();
            if (payload === '' || payload.charAt(0) !== '{') return null;
            return JSON.parse(payload);
        } catch (e) { return null; }
    };

    /**
     * @brief Handle a runcommands response for one of our update sessions.
     * Extracts the marker JSON, normalizes single-element array unrolling that
     * ConvertTo-Json does, stores results and advances the queue.
     * @param {string} nodeid - device the answer came from.
     * @param {object} command - the agent message (result text).
     */
    obj.wgHandleResponse = function (nodeid, command) {
        var entry = obj.wgPending[nodeid];
        if (entry == null) return; // not ours (e.g. a browser-initiated runcommands session)
        if (entry.timer) { clearTimeout(entry.timer); }
        delete obj.wgPending[nodeid];
        obj.wgActive--;
        var text = (typeof command.result === 'string') ? command.result : JSON.stringify(command.result || '');
        var rec = { time: new Date().toISOString(), winget: false, dry: obj.wgBatchDry === true, mode: (obj.wgBatchOpts && obj.wgBatchOpts.mode) || '', results: [] };
        var data = obj.wgPayloadFromText(text);
        var hadMarker = (text.indexOf(obj.WINGET_MARKER) >= 0);
        if ((data == null) && (typeof entry.cbuf === 'string') && (entry.cbuf !== '')) { data = obj.wgPayloadFromText(entry.cbuf); hadMarker = hadMarker || (entry.cbuf.indexOf(obj.WINGET_MARKER) >= 0); } // answer line was chunk-split on the console channel
        if (data != null) {
            rec.winget = (data.winget === true);
            var rr = data.results;
            if (rr == null) { rr = []; } else if (!Array.isArray(rr)) { rr = [rr]; } // PS unwraps single-element arrays
            rec.results = rr.filter(function (x) { return x && (typeof x.id === 'string'); }).map(function (x) {
                return { id: x.id, name: (typeof x.name === 'string') ? x.name.substring(0, 200) : '', from: String(x.from == null ? '' : x.from).substring(0, 60), to: String(x.to == null ? '' : x.to).substring(0, 60), state: String(x.state || 'unknown').substring(0, 40), exit: (typeof x.exit === 'number') ? x.exit : null, log: String(x.log || '').substring(0, 500) };
            });
        } else { rec.error = hadMarker ? 'unparsable payload' : 'no marker in output'; }
        obj.wgResults[nodeid] = rec;
        var okN = 0, skipN = 0, failN = 0, wouldN = 0;
        for (var i = 0; i < rec.results.length; i++) {
            var s = rec.results[i].state;
            if (s === 'ok') okN++; else if (s === 'dry-run') wouldN++; else if (s.indexOf('skipped') === 0 || s === 'not-installed') skipN++; else failN++;
        }
        obj.wgLog(nodeid + ' - ' + (rec.dry ? '[dry-run] ' : '') + (rec.error || (rec.winget ? (rec.dry ? ('would update ' + wouldN + ', ' + skipN + ' skipped, ' + failN + ' failed') : (rec.mode === 'uninstall' ? ('done: ' + okN + ' uninstalled, ' + skipN + ' skipped/not-installed, ' + failN + ' failed') : ('done: ' + okN + ' updated, ' + skipN + ' skipped, ' + failN + ' failed'))) : 'winget not available')));
        // Per-package detail lines so failures never require opening the client transcript:
        // one FAILED line with exit code + winget's own (system) message per failed package,
        // and a WARNING when the client upgraded a package that was on the ignore list.
        var evMsg = 'Winget updater: ' + (rec.error || (rec.winget === false ? 'winget is not available on this device' : (rec.dry ? ('dry run - ' + wouldN + ' package(s) would be updated') : (rec.mode === 'uninstall' ? (okN + ' package(s) uninstalled, ' + failN + ' failed') : (okN + ' package(s) updated, ' + failN + ' failed')))));
        if (rec.error == null) {
            var ignIds = [];
            try { var igl = obj.wingetConfig().ignorePackages; for (var zi = 0; zi < igl.length; zi++) { ignIds.push({ raw: String(igl[zi].id), lc: String(igl[zi].id).toLowerCase() }); } } catch (e) { }
            var failIds = [];
            for (var fi = 0; fi < rec.results.length; fi++) {
                var fr = rec.results[fi];
                if (fr.state === 'failed') {
                    failIds.push(fr.id);
                    obj.wgLog(nodeid + ' - FAILED ' + fr.id + ' [' + fr.from + ' -> ' + fr.to + '] exit ' + (fr.exit == null ? '?' : (fr.exit + ' (0x' + obj.wgExitHex(fr.exit) + ')')) + ': ' + String(fr.log || '').replace(/[\r\n]+/g, ' ').replace(/\s+/g, ' ').trim());
                } else if (fr.state === 'ok' && rec.dry !== true && rec.mode !== 'uninstall') {
                    // An upgraded package that the ignore list should have covered is never silent:
                    // exact hits mean the script ran without the current list, near misses mean the
                    // stored id does not equal the id winget reports on this device.
                    var fid = String(fr.id).toLowerCase(), exact = false, near = null;
                    for (var qi = 0; qi < ignIds.length; qi++) {
                        var gi = ignIds[qi].lc;
                        if (gi === fid) { exact = true; break; }
                        if (gi.length > 4 && fid.length > 4 && (fid.indexOf(gi) >= 0 || gi.indexOf(fid) >= 0)) { near = ignIds[qi].raw; }
                    }
                    if (exact) { obj.wgLog(nodeid + ' - WARNING ' + fr.id + ' is on the ignore list but was upgraded anyway (it was missing from the script that ran)'); }
                    else if (near != null) { obj.wgLog(nodeid + ' - WARNING ' + fr.id + ' was upgraded although the similar ignore entry "' + near + '" exists - ids do not match exactly, fix it from the device list (+ ignore)'); }
                }
            }
            if ((!rec.dry) && failIds.length > 0) { evMsg += ' (' + failIds.slice(0, 3).join(', ') + (failIds.length > 3 ? ', ...' : '') + ')'; }
        }
        obj.wgRaiseNodeEvent(nodeid, evMsg);
        obj.wgSaveResults();
        obj.wgPump();
    };

    /** @type {string} what the UI shows instead of the removed interval setting. */
    obj.WINGET_SCHEDULING_DESC = 'daily - right after a device connects on a new calendar day, and at the latest 24 h after its previous automatic run';

    /** @type {number} sweep cadence for the due check (ms); not a user setting. */
    obj.WINGET_SWEEP_MS = 60 * 60 * 1000;

    /** @type {number} force a refresh after this much continuous uptime (ms). */
    obj.WINGET_MAX_AGE_MS = 24 * 60 * 60 * 1000;

    /**
     * @brief Two-stage automatic-update policy (replaces the old interval):
     * a device is due when it never ran, when its last run lies on an earlier
     * calendar day, or when that run is 24h+ old (long-lived connection).
     * @param {string} nodeid - Node id.
     * @param {object} [results] - override map for testing.
     * @param {number} [now] - override now (epoch ms).
     * @returns {boolean} true when an automatic batch should cover the device.
     */
    obj.wgNodeDue = function (nodeid, results, now) {
        var res = results || obj.wgResults || {};
        var t = (res[nodeid] && res[nodeid].time) ? Date.parse(res[nodeid].time) : 0;
        if (!t || isNaN(t)) return true;
        var n = now || Date.now();
        var d = new Date(t), e = new Date(n);
        if (d.getFullYear() !== e.getFullYear() || d.getMonth() !== e.getMonth() || d.getDate() !== e.getDate()) return true;
        return (n - t) >= obj.WINGET_MAX_AGE_MS;
    };

    /**
     * @brief Agent-connect / sweep entry for ONE device: runs it when enabled,
     * in scope, not excluded, due and no batch/pending run is in flight.
     * @param {string} nodeid - Node id.
     * @param {string} reason - 'connect' | 'sweep' (logged).
     */
    obj.wgQueueNode = function (nodeid, reason) {
        try {
            var wcfg = obj.wingetConfig();
            if (!wcfg.enabled) return false;
            if (wcfg.excludeNodes.indexOf(nodeid) >= 0) return false;
            if (obj.wgBatchRunning || obj.osBatchRunning || (obj.wgPending && obj.wgPending[nodeid] != null)) return false;
            if (!obj.wgNodeDue(nodeid)) return false;
            // Automatic runs need an explicit group opt-in (same rule as wgTargetNodes(true)):
            // no updateMeshes = nothing runs automatically. db.Get answers an ARRAY of documents,
            // and non-Windows devices never receive a winget script (v4.3.0 fix: before, an empty
            // group list queued every connecting device, Linux included, and a ticked group never
            // matched because node.meshid was read from the array instead of its first element).
            if (wcfg.meshes == null) return false;
            obj.db.Get(nodeid, function (err, docs) {
                try {
                    var node = (Array.isArray(docs) && docs.length > 0) ? docs[0] : null;
                    if (err || (node == null) || node.deleted != null) return;
                    if (wcfg.meshes.indexOf(node.meshid) < 0) return;
                    if (!obj.wgIsWindowsNode(node)) return;
                    if (obj.wgBatchRunning || obj.osBatchRunning) return;
                    obj.wgLog('auto-update (' + reason + ') for one device');
                    obj.wgStartBatch(reason, null, [nodeid], false);
                } catch (e) { }
            });
            return true;
        } catch (e) { return false; }
    };

    /**
     * @brief One sweep pass over scheduled-scope devices: queue the ONLINE and
     * due ones as a batch. Scheduled by scheduleWingetUpdates hourly.
     */
    obj.wgSweepOnce = function (done) {
        var wcfg = obj.wingetConfig();
        if (!wcfg.enabled) { if (done) done(); return; }
        obj.wgTargetNodes(true, function (ids) {
            var ws = obj.meshServer.webserver;
            var due = [];
            for (var i = 0; i < ids.length; i++) {
                var online = (ws != null && ws.wsagents != null && ws.wsagents[ids[i]] != null);
                if (online && obj.wgNodeDue(ids[i])) due.push(ids[i]);
            }
            if (due.length === 0) { if (done) done(); return; }
            obj.wgLog('sweep: ' + due.length + ' due device(s)');
            obj.wgStartBatch('sweep', done, due, false);
        });
    };

    /**
     * @brief Hourly sweep loop (restart-proof gen guard). Devices that
     * reconnect are covered immediately by the agent-connect hook; this loop
     * catches devices whose connection simply outlives the day boundary.
     */
    obj.scheduleWingetUpdates = function () {
        var wcfg = obj.wingetConfig();
        if (!wcfg.enabled) { return; }
        var gen = obj.timerGen;
        obj.longTimeout(function () {
            if (!obj.timerValid(gen)) { return; }
            obj.wgSweepOnce(function () { obj.scheduleWingetUpdates(); });
        }, obj.WINGET_SWEEP_MS);
    };
};
