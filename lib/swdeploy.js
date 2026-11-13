/**
 * @file lib/swdeploy.js
 * @brief Software deployment engine (v4.0.0): the install scripts (Windows PowerShell / POSIX sh), the agent dispatch (wget + runcommands), the reconnect queue with its sweep, the per-device answer handling and the admin feedback events.
 * Delivery is MeshCentral's own mechanism (verified in webserver.js handleUploadFileBatch and
 * agents/meshcore.js case 'wget'/serverFetchFile): a wget command makes the agent HTTPS-GET a
 * cookie-authenticated URL from ITS OWN server target - TLS is checked against the control-channel
 * certificate hash, so no device needs any certificate import - and write the body to a fixed path.
 * The agent answers wget with NOTHING (failures only appear as session-less console text), so the
 * install script here polls for the file and verifies the task's SHA-256 BEFORE executing anything:
 * a missing or corrupt download ends as state 'no-file', never as a silent success, and the script
 * removes the file again. Sessions use the invscanner-sw- prefix and the @@INVSWD@@ marker over the
 * same routeAgentCommand hook as the winget/OS engines; one agent runs ONE command session at a
 * time, so all three pumps skip nodes the others hold. Installs run as SYSTEM (Windows) / root
 * (Linux), silently; no device is ever rebooted (exit 3010/1641 -> ok + reboot pending). Offline
 * devices stay queued and are dispatched by the agent-connect hook or the periodic sweep.
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
    /** @type {Array<object>} dispatch queue entries { taskId, nodeid }. */
    obj.swQueue = [];
    /** @type {Object<string, object>} nodeid -> in-flight deploy session. */
    obj.swPending = {};
    /** @type {number} devices with a deploy script currently running. */
    obj.swActive = 0;

    obj.SW_MARKER = '@@INVSWD@@';
    obj.SW_SESSION_PREFIX = 'invscanner-sw-';
    obj.SW_MAX_PARALLEL = 2;
    obj.SW_RUN_TIMEOUT_MS = 2 * 60 * 60 * 1000;
    /** @type {number} minutes the on-device script waits for the wget download to land. */
    obj.SW_FILE_WAIT_MIN = 15;
    /** @type {number} hard cap of devices per task. */
    obj.SW_MAX_DEVICES = 500;
    /** @type {number} sweep cadence for the reconnect queue. */
    obj.SW_SWEEP_MS = 10 * 60 * 1000;

    // ---- scripts (one statement per line; every value is server-generated or fully quoted) ----

    /**
     * @brief Windows PowerShell script: wait for the wget file, verify SHA-256, install silently
     * (msiexec /i or /update with /qn /norestart; other types through Start-Process -Wait), clean
     * up, answer ONE marker line. Never reboots; 3010/1641 are reported as ok + reboot pending.
     * @param {object} task - Task record (stageFile/sha256/ext/args must already be validated).
     * @returns {string} The script text.
     */
    obj.swBuildWindowsScript = function (task) {
        var p = obj.swStagePaths(task);
        var args = obj.swSafeArgs(task.args || '');
        var psq = function (s) { return String(s).replace(/'/g, "''"); };
        return [
            "$ProgressPreference = 'SilentlyContinue'",
            "$invStage = '" + psq(p.winPath) + "'",
            "$invHash = '" + String(task.sha256 || '').toLowerCase().replace(/[^a-f0-9]/g, '') + "'",
            "$invExt = '" + String(task.ext || 'exe').replace(/[^a-z0-9]/g, '') + "'",
            "$invName = '" + psq(obj.swSanitizeName(task.fileName)) + "'",
            "$invArgs = '" + psq(args) + "'",
            "$invWaitMin = " + obj.SW_FILE_WAIT_MIN
        ].concat(obj.psTranscriptLines('invscanner-deploy.log'), [
            "$invGot = $false; $invDeadline = (Get-Date).AddMinutes($invWaitMin)",
            "while ((Get-Date) -lt $invDeadline) { if (Test-Path -LiteralPath $invStage) { try { $invH = (Get-FileHash -LiteralPath $invStage -Algorithm SHA256).Hash; if ($invH -and ($invH.Replace('-','') -ieq $invHash)) { $invGot = $true; break } } catch { } }; Start-Sleep -Seconds 3 }",
            "if (-not $invGot) { try { Remove-Item -LiteralPath $invStage -Force -ErrorAction SilentlyContinue } catch { }; @{ deploy=$true; state='no-file'; name=$invName; exit=$null; reboot=$false; error='the download never arrived on the device (wget failed, wrong hash, or the file is still in transit after ' + $invWaitMin + ' minutes)' } | ConvertTo-Json -Compress -Depth 3 | ForEach-Object { Write-Output ('" + obj.SW_MARKER + "' + $_) }; Stop-Transcript -ErrorAction SilentlyContinue | Out-Null; exit }",
            "$invState = 'failed'; $invExit = $null; $invErr = ''; $invReboot = $false",
            "try { if ($invExt -eq 'msi' -or $invExt -eq 'msp') { $invCL = $(if ($invExt -eq 'msp') { '/update \"' + $invStage + '\" /quiet /norestart' } else { '/i \"' + $invStage + '\" /qn /norestart' }); if ($invArgs) { $invCL = $invCL + ' ' + $invArgs }; $invP = Start-Process -FilePath 'msiexec.exe' -ArgumentList $invCL -Wait -PassThru } elseif ($invArgs) { $invP = Start-Process -FilePath $invStage -ArgumentList $invArgs -Wait -PassThru } else { $invP = Start-Process -FilePath $invStage -Wait -PassThru }; $invExit = [int]$invP.ExitCode; if ($invExit -eq 0) { $invState = 'ok' } elseif (($invExit -eq 3010) -or ($invExit -eq 1641)) { $invState = 'ok'; $invReboot = $true } else { $invState = 'failed' } } catch { $invState = 'error'; $invErr = [string]$_.Exception.Message; if ($invErr.Length -gt 300) { $invErr = $invErr.Substring(0,300) } }",
            "try { Remove-Item -LiteralPath $invStage -Force -ErrorAction SilentlyContinue } catch { }",
            "@{ deploy=$true; state=$invState; name=$invName; exit=$invExit; reboot=$invReboot; error=$invErr } | ConvertTo-Json -Compress -Depth 3 | ForEach-Object { Write-Output ('" + obj.SW_MARKER + "' + $_) }",
            "Stop-Transcript -ErrorAction SilentlyContinue | Out-Null"
        ]).join(String.fromCharCode(10));
    };

    /**
     * @brief Linux script (POSIX sh as root through osLinuxTransport): wait for the wget file,
     * verify sha256sum, install by type (dpkg -i / rpm -Uvh / sh / direct exec - arguments are
     * word-split on spaces, quotes inside them stay literal), log to /var/log/invscanner-deploy.log,
     * answer the marker via printf. Windows packages on Linux: refused, never "executed". No reboot.
     * @param {object} task - Task record (validated).
     * @returns {string} The script text.
     */
    obj.swBuildLinuxScript = function (task) {
        var p = obj.swStagePaths(task);
        var args = obj.swSafeArgs(task.args || '');
        var shq = function (s) { return String(s).split("'").join("'\\''"); };
        var ext = String(task.ext || 'bin').replace(/[^a-z0-9]/g, '');
        return [
            "F='" + shq(p.linPath) + "'",
            "HASH='" + String(task.sha256 || '').toLowerCase().replace(/[^a-f0-9]/g, '') + "'",
            "NAME='" + shq(obj.swSanitizeName(task.fileName)) + "'",
            "ARGS='" + shq(args) + "'",
            "EXT='" + ext + "'",
            "LOG=/var/log/invscanner-deploy.log",
            "[ -L \"$LOG\" ] && LOG=/dev/null",
            "if [ -f \"$LOG\" ] && [ \"$(wc -c < \"$LOG\")\" -gt 5242880 ]; then mv -f \"$LOG\" \"$LOG.old\"; fi",
            "DEADLINE=$(( $(date +%s) + " + (obj.SW_FILE_WAIT_MIN * 60) + " ))",
            "GOT=0",
            "while [ \"$(date +%s)\" -lt \"$DEADLINE\" ]; do if [ -f \"$F\" ]; then H=$(sha256sum \"$F\" 2>/dev/null | cut -d' ' -f1); if [ \"$H\" = \"$HASH\" ]; then GOT=1; break; fi; fi; sleep 2; done",
            "STATE=; EXIT=-1; NOTE=''",
            "if [ \"$GOT\" != \"1\" ]; then STATE=no-file; NOTE='the download never arrived on the device (wget failed, wrong hash, or still in transit)'; rm -f \"$F\" 2>/dev/null; else",
            "  if [ ! -x \"$F\" ] && [ \"$EXT\" != 'deb' ] && [ \"$EXT\" != 'rpm' ] && [ \"$EXT\" != 'msi' ] && [ \"$EXT\" != 'msp' ]; then chmod 700 \"$F\" 2>/dev/null; fi",
            "  export DEBIAN_FRONTEND=noninteractive",
            "  case \"$EXT\" in",
            "    deb) set -- dpkg -i \"$F\" $ARGS ;;",
            "    rpm) set -- rpm -Uvh \"$F\" $ARGS ;;",
            "    sh) set -- sh \"$F\" $ARGS ;;",
            "    bin) set -- \"$F\" $ARGS ;;",
            "    msi) STATE=failed; NOTE='this is a Windows installer and cannot be deployed to Linux';;",
            "    msp) STATE=failed; NOTE='this is a Windows installer and cannot be deployed to Linux';;",
            "    *) set -- \"$F\" $ARGS ;;",
            "  esac",
            "  if [ -z \"$STATE\" ]; then \"$@\" >> \"$LOG\" 2>&1 < /dev/null; EXIT=$?; if [ \"$EXIT\" = \"0\" ]; then STATE=ok; else STATE=failed; fi; fi",
            "  rm -f \"$F\" 2>/dev/null",
            "fi",
            "NOTE=$(printf '%s' \"$NOTE\" | tr -d '\\\\\"')",
            "TAIL=$(tail -n 4 \"$LOG\" 2>/dev/null | tr '\\n\\r\\t' '   ' | tr -d '\\000-\\037\\\\\"' | cut -c1-300)",
            "printf '%s{\"deploy\":true,\"state\":\"%s\",\"name\":\"%s\",\"exit\":%d,\"reboot\":false,\"error\":\"%s %s\"}\\n' '" + obj.SW_MARKER + "' \"$STATE\" \"$(printf '%s' \"$NAME\" | tr -d '\\\\\"')\" \"$EXIT\" \"$NOTE\" \"$TAIL\""
        ].join(String.fromCharCode(10));
    };

    // ---- dispatch ----

    /** @brief The agent wget command (shape verified in webserver.js handleUploadFileBatch). */
    obj.swWgetCommand = function (task, nodeid, platform) {
        var p = obj.swStagePaths(task);
        var c = obj.swDownloadCookie(nodeid, p.file);
        if (c == null) return null;
        var hash = null;
        try {
            if (!(obj.meshServer.args != null && obj.meshServer.args.ignoreagenthashcheck === true)) {
                var h = obj.meshServer.webserver != null ? obj.meshServer.webserver.webCertificateFullHashs : null;
                if (h != null) { hash = Buffer.from(h[obj.swNodeDomain(nodeid)] || h[''] || '', 'binary').toString('hex'); if (hash === '') hash = null; }
            }
        } catch (e) { hash = null; }
        return {
            action: 'wget', userid: 'server', username: 'inventoryscanner', remoteaddr: '', consent: 0,
            overwrite: true, createFolder: false,
            urlpath: obj.swDomainUrlPrefix(obj.swNodeDomain(nodeid)) + 'agentdownload.ashx?c=' + c,
            path: platform === 'windows' ? p.winPath : p.linPath,
            folder: platform === 'windows' ? 'C:\\Windows\\Temp' : '/var/tmp',
            servertlshash: hash
        };
    };

    /** @brief True when a device state needs no further action. */
    obj.swIsFinal = function (state) { return ['ok', 'failed', 'error', 'no-file', 'timeout', 'cancelled', 'unsupported'].indexOf(String(state)) >= 0; };

    /** @brief Queue an explicit device list of a task (used by sw_create_task / sw_retry_task). */
    obj.swEnqueueDevices = function (taskId, nodeids) {
        var task = obj.swTasks[taskId];
        if (task == null) return 0;
        for (var i = 0; i < nodeids.length; i++) {
            var nid = nodeids[i];
            task.devices[nid] = { state: 'queued', time: new Date().toISOString() };
            obj.swQueue.push({ taskId: taskId, nodeid: nid });
        }
        obj.swSaveTasks();
        if (nodeids.length > 0) { obj.swPump(); }
        return nodeids.length;
    };

    /** @brief Feed the deploy queue up to SW_MAX_PARALLEL devices; conflicting sessions requeue at the tail. */
    obj.swPump = function () {
        try {
            var waited = [];
            while ((obj.swActive < obj.SW_MAX_PARALLEL) && obj.swQueue.length > 0) {
                var job = obj.swQueue.shift();
                var task = obj.swTasks[job.taskId];
                if ((task == null) || (task.done === true)) continue;
                var dev = task.devices[job.nodeid];
                if ((dev == null) || (dev.state !== 'queued')) continue;
                if (obj.swPending[job.nodeid] != null || (obj.wgPending && obj.wgPending[job.nodeid] != null) || (obj.osPending && obj.osPending[job.nodeid] != null)) {
                    waited.push(job); // that device is busy with another engine's session
                    continue;
                }
                // Reserve BOTH the parallel slot and the node's single runcommands session NOW,
                // synchronously like wgPump/osPump do - dispatch then resolves asynchronously
                // (db.Get, staging), and the winget/OS pumps must see the node taken in that window.
                var entry = { nodeid: job.nodeid, taskId: job.taskId, sid: obj.SW_SESSION_PREFIX + obj.safeNodeDir(job.nodeid), since: Date.now() };
                entry.timer = setTimeout(function () { obj.swTimeout(entry); }, obj.SW_RUN_TIMEOUT_MS);
                obj.swPending[job.nodeid] = entry;
                obj.swActive++;
                obj.swDispatchNode(task, job.nodeid, dev, entry);
            }
            for (var i = 0; i < waited.length; i++) { obj.swQueue.push(waited[i]); }
            if (obj.swActive === 0 && obj.swQueue.length > 0 && waited.length === obj.swQueue.length) {
                // Only blocked entries are left (all parallel slots idle): stop churning -
                // the connect hook, the sweeps and every finished session pump again.
                obj.swQueue.length = 0;
                setTimeout(function () { obj.swPump(); }, 60000);
            }
        } catch (e) { obj.swLog('deploy pump error: ' + e.message); }
    };

    /**
     * @brief Release a reserved session that never reached the wire: frees the slot, closes or
     * re-queues the device. Every early path of swDispatchNode goes through here so the pump
     * accounting stays exact (one ++ in the pump, exactly one -- here or in response/watchdog).
     */
    obj.swAbortDispatch = function (entry, task, dev, state, note, requeue) {
        try {
            if (entry == null) return;
            if (entry.timer) { clearTimeout(entry.timer); }
            if (obj.swPending[entry.nodeid] === entry) { delete obj.swPending[entry.nodeid]; }
            obj.swActive--;
            if (dev != null && state != null) {
                dev.state = state; dev.time = new Date().toISOString();
                if (note) { dev.note = String(note).substring(0, 300); }
            }
            obj.swSaveTasks();
            if (task != null) { obj.swTaskDoneCheck(task); }
            if (requeue && task != null) { obj.swQueue.push({ taskId: task.id, nodeid: entry.nodeid }); }
        } catch (e) { }
        obj.swPump();
    };

    /** @brief Send wget + the install script for ONE device (slot and session ALREADY RESERVED by the pump). */
    obj.swDispatchNode = function (task, nodeid, dev, entry) {
        try {
            var ws = obj.meshServer.webserver;
            var agent = (ws != null && ws.wsagents != null) ? ws.wsagents[nodeid] : null;
            if ((agent == null) || (typeof agent.send !== 'function')) { obj.swAbortDispatch(entry, task, null); return; } // stays queued, reconnect/sweep will run it
            obj.db.Get(nodeid, function (gerr, docs) {
                try {
                    if (gerr || !docs || !docs.length || docs[0].deleted != null) {
                        obj.swLog(nodeid + ' - task ' + task.id + ' - device gone');
                        obj.swAbortDispatch(entry, task, dev, 'error', 'the device no longer exists');
                        return;
                    }
                    var node = docs[0];
                    var platform = obj.osPlatformOf(node);
                    if (platform == null) {
                        obj.swAbortDispatch(entry, task, dev, 'unsupported', 'no Windows/Linux OS reported by the agent yet');
                        return;
                    }
                    obj.swEnsureStaged(task, function (serr) {
                        try {
                            if (serr) {
                                obj.swLog(nodeid + ' - task ' + task.id + ' - staging failed: ' + serr.message);
                                obj.swAbortDispatch(entry, task, dev, 'error', serr.message);
                                return;
                            }
                            var wgetCmd = obj.swWgetCommand(task, nodeid, platform);
                            if (wgetCmd == null) {
                                obj.swLog(nodeid + ' - task ' + task.id + ' - cookie failed (encodeCookie unavailable)');
                                obj.swAbortDispatch(entry, task, dev, 'error', 'the server could not issue an agent download cookie');
                                return;
                            }
                            if (!obj.routeHookInstalled) { try { obj.installRouteHook(); } catch (e) { } }
                            entry.platform = platform;
                            var script = platform === 'windows' ? obj.swBuildWindowsScript(task) : obj.swBuildLinuxScript(task);
                            var msg = platform === 'windows'
                                ? { action: 'runcommands', type: 1, cmds: obj.wgTransport(script), runAsUser: 0, reply: true, sessionid: entry.sid, responseid: entry.sid }
                                : { action: 'runcommands', type: 3, cmds: obj.osLinuxTransport(script), runAsUser: 0, reply: true, sessionid: entry.sid, responseid: entry.sid };
                            try {
                                agent.send(JSON.stringify(wgetCmd));
                                agent.send(JSON.stringify(msg));
                                dev.state = 'running'; dev.time = new Date().toISOString(); dev.platform = platform;
                                obj.swLog(nodeid + ' - deploying ' + task.fileName + ' (' + platform + ', ' + (task.size || 0) + ' bytes, sha256 ' + String(task.sha256 || '').substring(0, 12) + '...)');
                                obj.swSaveTasks();
                            } catch (ex) {
                                obj.swLog(nodeid + ' - send failed: ' + ex.message);
                                obj.swAbortDispatch(entry, task, dev, 'queued', null, true);
                            }
                        } catch (e2) {
                            obj.swAbortDispatch(entry, task, dev, 'error', e2.message);
                        }
                    });
                } catch (ex) {
                    obj.swAbortDispatch(entry, task, dev, 'error', ex.message);
                }
            });
        } catch (ex) {
            obj.swAbortDispatch(entry, task, dev, 'error', ex.message);
        }
    };

    /** @brief Watchdog for a device whose install script never answered. */
    obj.swTimeout = function (entry) {
        if ((entry == null) || (obj.swPending[entry.nodeid] !== entry)) return;
        delete obj.swPending[entry.nodeid];
        obj.swActive--;
        var task = obj.swTasks[entry.taskId];
        var dev = (task != null) ? task.devices[entry.nodeid] : null;
        if (dev != null) { dev.state = 'timeout'; dev.time = new Date().toISOString(); dev.note = 'the device did not answer within the run timeout'; }
        obj.swLog(entry.nodeid + ' - no answer within the run timeout');
        obj.wgRaiseNodeEvent(entry.nodeid, 'Software deploy: the device did not answer within the timeout');
        obj.swSaveTasks();
        if (task != null) { obj.swTaskDoneCheck(task); }
        obj.swPump();
    };

    /** @brief Answer of one deploy session: store the outcome, log it, notify on the device, advance. */
    obj.swHandleResponse = function (nodeid, command) {
        var entry = obj.swPending[nodeid];
        if (entry == null) return;
        if (entry.timer) { clearTimeout(entry.timer); }
        delete obj.swPending[nodeid];
        obj.swActive--;
        var task = obj.swTasks[entry.taskId];
        var text = (typeof command.result === 'string') ? command.result : JSON.stringify(command.result || '');
        var data = obj.wgPayloadFromText(text, obj.SW_MARKER);
        if ((data == null) && (typeof entry.cbuf === 'string') && (entry.cbuf !== '')) { data = obj.wgPayloadFromText(entry.cbuf, obj.SW_MARKER); }
        var rec = { time: new Date().toISOString(), state: 'error', exit: null, reboot: false, note: '' };
        if (data == null) {
            rec.note = (text.indexOf(obj.SW_MARKER) >= 0) ? 'unparsable payload' : 'no marker in output';
        } else {
            var states = ['ok', 'failed', 'error', 'no-file'];
            rec.state = (states.indexOf(String(data.state)) >= 0) ? String(data.state) : 'error';
            rec.exit = (typeof data.exit === 'number') ? data.exit : null;
            rec.reboot = data.reboot === true;
            rec.note = String(data.error || '').substring(0, 300);
            if (rec.reboot && rec.state === 'ok') { rec.note = 'ok (3010/1641: a reboot is pending - the plugin never reboots)'; }
        }
        if (task != null && task.devices[nodeid] != null) {
            var dev = task.devices[nodeid];
            dev.state = rec.state; dev.time = rec.time; dev.exit = rec.exit; dev.note = rec.note; dev.platform = entry.platform; dev.reboot = rec.reboot === true;
        }
        var label = (task != null) ? task.fileName : 'task ' + entry.taskId;
        obj.swLog(nodeid + ' - ' + label + ': ' + rec.state + (rec.exit != null ? (' (exit ' + rec.exit + (rec.exit !== 0 ? ' / 0x' + obj.wgExitHex(rec.exit) + ')' : ')')) : '') + (rec.note ? (' - ' + rec.note.replace(/[\r\n]+/g, ' ')) : ''));
        obj.wgRaiseNodeEvent(nodeid, 'Software deploy: ' + label + ' - ' + rec.state + (rec.exit != null ? ' (exit ' + rec.exit + ')' : '') + (rec.reboot ? ' - REBOOT PENDING' : ''));
        obj.swSaveTasks();
        if (task != null) { obj.swTaskDoneCheck(task); }
        obj.swPump();
    };

    /** @brief When every device of a task reached a final state: close it, delete the staged copy, notify. */
    obj.swTaskDoneCheck = function (task) {
        try {
            if (task.done === true) return;
            var counts = { ok: 0, failed: 0, other: 0, open: 0 };
            for (var nid in task.devices) {
                var d = task.devices[nid];
                if (d == null) continue;
                if (d.state === 'ok') counts.ok++;
                else if (d.state === 'failed' || d.state === 'timeout' || d.state === 'no-file' || d.state === 'error') counts.failed++;
                else if (d.state === 'unsupported' || d.state === 'cancelled') counts.other++;
                else counts.open++;
            }
            if (counts.open > 0) return;
            task.done = true; task.finishTime = new Date().toISOString(); task.counts = counts;
            obj.swLog('task ' + task.id + ' (' + task.fileName + ') finished: ' + counts.ok + ' ok, ' + counts.failed + ' failed/skipped, ' + counts.other + ' cancelled/unsupported');
            obj.swDeleteStage(task);
            obj.swSaveTasks();
            obj.swPruneTasks();
            var msg = 'Software deploy "' + task.fileName + '": ' + counts.ok + ' device(s) ok, ' + counts.failed + ' failed' + (counts.other ? (', ' + counts.other + ' cancelled/not supported') : '');
            try {
                obj.meshServer.DispatchEvent(['*'], obj, { etype: 'server', action: 'msg', type: 'notify', id: Math.random(), tag: 'ServerNotify', value: msg, title: 'Software Deploy' });
            } catch (e) { }
        } catch (e) { }
    };

    // ---- reconnect queue ----

    /** @brief Agent-connect entry: run everything this device still has queued. */
    obj.swOnNodeConnect = function (nodeid) {
        try {
            var hit = 0;
            for (var tid in obj.swTasks) {
                var task = obj.swTasks[tid];
                if ((task == null) || task.done === true || task.devices == null) continue;
                var d = task.devices[nodeid];
                if (d == null) continue;
                // 'running' WITHOUT a pending session: the old connection died mid-script - queue again.
                if (d.state === 'running' && obj.swPending[nodeid] == null) { d.state = 'queued'; }
                if (d.state === 'queued') {
                    obj.swQueue.push({ taskId: tid, nodeid: nodeid });
                    hit++;
                }
            }
            if (hit > 0) { obj.swLog('device reconnected - ' + hit + ' queued deploy(s) now running'); obj.swPump(); }
            return hit;
        } catch (e) { return 0; }
    };

    /** @brief One sweep pass: dispatch queued devices whose agent is online again. */
    obj.swSweepOnce = function (done) {
        try {
            var open = [];
            for (var tid in obj.swTasks) {
                var task = obj.swTasks[tid];
                if ((task == null) || task.done === true || task.devices == null) continue;
                for (var nid in task.devices) {
                    var d = task.devices[nid];
                    if (d == null) continue;
                    if (d.state === 'running' && obj.swPending[nid] == null) { d.state = 'queued'; } // session lost
                    if (d.state === 'queued') open.push({ taskId: tid, nodeid: nid });
                }
            }
            if (open.length === 0) { if (done) done(); return; }
            var ws = obj.meshServer.webserver;
            var now = 0;
            for (var i = 0; i < open.length; i++) {
                if (ws != null && ws.wsagents != null && ws.wsagents[open[i].nodeid] != null && obj.swPending[open[i].nodeid] == null) {
                    obj.swQueue.push(open[i]); now++;
                }
            }
            if (now > 0) { obj.swLog('sweep: ' + now + ' queued device deploy(s) picked up'); obj.swPump(); }
            obj.swCleanStaleStaging();
            obj.swSaveTasks();
            if (done) done();
        } catch (e) { if (done) done(); }
    };

    /** @brief Sweep loop (restart-proof gen guard, same pattern as the winget sweep). */
    obj.scheduleSwSweep = function () {
        var gen = obj.timerGen;
        obj.longTimeout(function () {
            if (!obj.timerValid(gen)) { return; }
            obj.swSweepOnce(function () { obj.scheduleSwSweep(); });
        }, obj.SW_SWEEP_MS);
    };

    // ---- task building / UI shape ----

    /**
     * @brief Create a deploy task record (does NOT queue it - swEnqueueDevices does).
     * @param {object} src - { type:'library', fileId } or { type:'serverfile', meshId, name }.
     * @param {string} args - Raw install parameters (sanitized here).
     * @param {string} fileName - Display name.
     * @param {object} user - The creating admin (audit fields).
     * @returns {object} The task record, registered in obj.swTasks.
     */
    obj.swCreateTask = function (src, args, fileName, user) {
        var tid = obj.swRand(8);
        var ext = obj.swExtOf(fileName);
        var task = {
            id: tid,
            created: new Date().toISOString(),
            createdBy: (user && typeof user.name === 'string') ? user.name.substring(0, 100) : '',
            createdById: (user && typeof user._id === 'string') ? user._id.substring(0, 100) : '',
            source: src,
            fileName: obj.swSanitizeName(fileName),
            ext: ext,
            args: obj.swSafeArgs(args),
            stageFile: 'invsw-' + tid + '-' + obj.swRand(6) + '.' + ext,
            sha256: '', size: 0,
            done: false,
            devices: {}
        };
        obj.swTasks[tid] = task;
        return task;
    };

    /** @brief UI shape of one task: counts over ALL devices, device rows capped at 150. */
    obj.swTaskView = function (task) {
        var ids = Object.keys(task.devices || {});
        var counts = { ok: 0, failed: 0, queued: 0, running: 0, other: 0 };
        for (var i = 0; i < ids.length; i++) {
            var d = task.devices[ids[i]] || {};
            if (d.state === 'ok') counts.ok++;
            else if (['failed', 'error', 'no-file', 'timeout'].indexOf(d.state) >= 0) counts.failed++;
            else if (d.state === 'queued') counts.queued++;
            else if (d.state === 'running') counts.running++;
            else counts.other++;
        }
        var devs = ids.slice(0, 150).map(function (nid) {
            var x = task.devices[nid] || {};
            return { node: nid, state: x.state || '?', time: x.time || '', exit: (typeof x.exit === 'number') ? x.exit : null, note: String(x.note || '').substring(0, 300), platform: x.platform || '', reboot: x.reboot === true };
        });
        return {
            id: task.id, created: task.created, fileName: task.fileName, ext: task.ext, args: task.args,
            size: task.size || 0, sha256: task.sha256 || '', done: task.done === true,
            sourceType: (task.source && task.source.type) || '', createdBy: task.createdBy || '',
            counts: counts, devices: devs, total: ids.length
        };
    };
};
