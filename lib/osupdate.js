/**
 * @file lib/osupdate.js
 * @brief On-demand OS updates and OS release upgrades (v3.5.0): the same transport and marker pattern as the winget engine, separate sessions (invscanner-os-) and never a reboot.
 * 'update' = Windows: search + download + install through the built-in Windows Update agent (COM Microsoft.Update.Session); Linux: the distribution's package manager (apt-get, dnf, yum, zypper, pacman, apk).
 * 'upgrade' = only devices whose release is PROVABLY not current; 'current' comes exclusively from fresh endoflife.date data (no hard-coded fallback - it would go stale), so missing/stale data means state 'unknown' and nothing is upgraded. Outdated releases are 'urgent' when their own support ended or ends within scannerConfig().osUpgradeUrgentDays (default 365), else 'available' (v3.6.0); a fleet upgrade runs with scope 'urgent' or 'all'. Windows 10/11 use the documented TargetReleaseVersion policy (restored afterwards), Ubuntu uses dist-upgrade + do-release-upgrade.
 * runcommands type 1 = cmd.exe (Windows), type 3 = /bin/sh (Linux) - verified in meshcore.js. One agent runs one command session at a time, so OS and winget batches exclude each other.
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
    obj.osPending = {};

    obj.osQueue = [];

    obj.osActive = 0;

    obj.osResults = {};

    obj.osBatchRunning = false;

    obj.osBatchMode = '';

    obj.OS_MARKER = '@@INVOSU@@';

    obj.OS_MAX_PARALLEL = 2;

    /** @type {number} Windows Update scans/installs and release upgrades are slow. */
    obj.OS_RUN_TIMEOUT_MS = 4 * 60 * 60 * 1000;

    /** @type {number} lifecycle data older than this is not trusted to name the CURRENT release.
     *  There is deliberately NO hard-coded fallback release: any built-in value would silently go
     *  stale, so without fresh data the state is 'unknown' and nothing is upgraded. */
    obj.OS_REFERENCE_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;

    /** @brief Append a line to the OS update log (rotated once at ~5 MB). */
    obj.osLog = function (line) {
        try {
            var dir = path.dirname(obj.osLogPath);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            try { if (fs.existsSync(obj.osLogPath) && (fs.statSync(obj.osLogPath).size > 5 * 1024 * 1024)) { fs.renameSync(obj.osLogPath, obj.osLogPath + '.old'); } } catch (e) { }
            fs.appendFileSync(obj.osLogPath, new Date().toISOString() + ' ' + line + String.fromCharCode(10));
        } catch (e) { }
    };

    obj.osLoadResults = function () {
        obj.osResults = {};
        try { if (fs.existsSync(obj.osResultsPath)) { var d = JSON.parse(fs.readFileSync(obj.osResultsPath, 'utf8')); if (d && typeof d === 'object') { obj.osResults = d; } } } catch (e) { obj.osResults = {}; }
    };

    obj.osSaveResults = function () {
        try {
            var dir = path.dirname(obj.osResultsPath);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            fs.writeFileSync(obj.osResultsPath, JSON.stringify(obj.osResults));
        } catch (e) { obj.osLog('could not save results: ' + e.message); }
    };

    /**
     * @brief Shell family of a node. Unknown OS -> null: without a reported OS the right
     * shell cannot be chosen, so such devices are never touched.
     * @returns {string|null} 'windows' | 'linux' | null
     */
    obj.osPlatformOf = function (node) {
        var d = String((node && node.osdesc) || '');
        if (d === '') return null;
        if (/windows/i.test(d)) return 'windows';
        if (/android|\bios\b|ipados|mac\s?os|darwin/i.test(d)) return null;
        if (/linux|ubuntu|debian|fedora|centos|red hat|rhel|rocky|almalinux|suse|mint|alpine|arch|manjaro|raspbian|pop!_os/i.test(d)) return 'linux';
        return null;
    };

    /** @brief '23h2' -> 232 for ordering Windows releases. */
    obj.winRelNum = function (r) { var m = String(r || '').match(/^(\d{2})h([12])$/i); return m ? (parseInt(m[1], 10) * 10 + parseInt(m[2], 10)) : 0; };

    /** @brief '22.04' -> 2204 for ordering Ubuntu releases. */
    obj.ubuRelNum = function (r) { var m = String(r || '').match(/^(\d{2})\.(\d{2})$/); return m ? (parseInt(m[1], 10) * 100 + parseInt(m[2], 10)) : 0; };

    /**
     * @brief Check that the cached lifecycle data of one product can name the current release.
     * @returns {string} '' when usable, else the reason why not (shown to the admin).
     */
    obj.osReferenceProblem = function (slug, now) {
        var rec = obj.osLifecycle[slug];
        if (!obj.scannerConfig().osLifecycleEnabled) return 'fetching OS support dates is switched off (Settings tab)';
        if (!rec || !Array.isArray(rec.cycles) || rec.cycles.length === 0) return 'no endoflife.date data for "' + slug + '" yet (fetched with the next NVD refresh)';
        var t = Date.parse(rec.fetched || '');
        if (isNaN(t)) return 'endoflife.date data for "' + slug + '" has no fetch date';
        if (((now != null) ? now : Date.now()) - t > obj.OS_REFERENCE_MAX_AGE_MS) return 'endoflife.date data for "' + slug + '" is older than 30 days (last fetched ' + rec.fetched.substring(0, 10) + ')';
        return '';
    };

    /**
     * @brief Newest Windows 11 release according to the cached endoflife.date data.
     * @returns {object} { release: '25h2'-style or '', reason: '' or why it is unknown }
     */
    obj.osCurrentWindows11 = function (now) {
        var why = obj.osReferenceProblem('windows', now);
        if (why !== '') return { release: '', reason: why };
        var best = '', cy = obj.osLifecycle.windows.cycles;
        for (var i = 0; i < cy.length; i++) {
            var m = String(cy[i].cycle).toLowerCase().match(/^11-(\d{2}h[12])(?:-[we])?$/);
            if (m && obj.winRelNum(m[1]) > obj.winRelNum(best)) best = m[1];
        }
        return best ? { release: best, reason: '' } : { release: '', reason: 'the endoflife.date data lists no Windows 11 release' };
    };

    /**
     * @brief Newest Ubuntu LTS release according to the cached endoflife.date data.
     * @returns {object} { release: '24.04'-style or '', reason: '' or why it is unknown }
     */
    obj.osCurrentUbuntuLts = function (now) {
        var why = obj.osReferenceProblem('ubuntu', now);
        if (why !== '') return { release: '', reason: why };
        var best = '', cy = obj.osLifecycle.ubuntu.cycles;
        for (var i = 0; i < cy.length; i++) {
            if (cy[i].lts === true && obj.ubuRelNum(cy[i].cycle) > obj.ubuRelNum(best)) best = cy[i].cycle;
        }
        return best ? { release: best, reason: '' } : { release: '', reason: 'the endoflife.date data lists no Ubuntu LTS release' };
    };

    /**
     * @brief Support end of the INSTALLED release (osSupportState, endoflife.date, per edition) and
     * whether that makes an upgrade urgent (v3.6.0). Urgent = support already ended, or fewer than
     * scannerConfig().osUpgradeUrgentDays days are left. Without a known end date nothing is urgent:
     * the reason says that the support end is unknown (never guessed).
     * @returns {object} { urgent, eol:'YYYY-MM-DD'|'', daysLeft:number|null, ended:boolean, reason }
     */
    obj.osUrgency = function (osDesc, now) {
        var t = (now != null) ? now : Date.now();
        var days = obj.scannerConfig().osUpgradeUrgentDays;
        var st = obj.osSupportState(osDesc, t);
        if (st.state === 'eol') {
            return { urgent: true, eol: st.eol || '', daysLeft: (st.eol ? Math.floor((Date.parse(st.eol + 'T23:59:59Z') - t) / 86400000) : null), ended: true, reason: 'support ended' + (st.eol ? ' ' + st.eol : '') };
        }
        if (st.state === 'supported' && st.eol) {
            var left = Math.floor((Date.parse(st.eol + 'T23:59:59Z') - t) / 86400000);
            var u = left < days;
            return { urgent: u, eol: st.eol, daysLeft: left, ended: false, reason: 'support until ' + st.eol + ' (' + left + ' days left' + (u ? ', fewer than ' + days : '') + ')' };
        }
        if (st.state === 'supported') return { urgent: false, eol: '', daysLeft: null, ended: false, reason: 'supported, ' + (st.reason || 'no end date announced') };
        return { urgent: false, eol: '', daysLeft: null, ended: false, reason: 'support end unknown (' + (st.reason || 'no lifecycle data') + ')' };
    };

    /**
     * @brief Release state of a node's OS and whether the plugin can upgrade it (v3.6.0):
     *  'current'   = the newest release according to fresh endoflife.date data;
     *  'available' = a newer release exists, the installed one is still supported beyond the urgency window
     *                (or its support end is unknown - then the note says so, it is never called urgent);
     *  'urgent'    = a newer release exists AND the installed release is out of support or fewer than
     *                osUpgradeUrgentDays are left; also a release inside that window on a platform without
     *                a newer-release check (Windows Server, other distributions - no automatic upgrade);
     *  'unknown'   = no clean answer (release not reported, no fresh reference data, or a platform
     *                without a newer-release check that is not end of life): NEVER upgraded.
     * @param {string} osDesc - node.osdesc.
     * @returns {object} { state, outdated, urgent, method:'windows-feature'|'ubuntu-release'|null, current, target, note, eol, daysLeft, urgentReason }
     */
    obj.osUpgradeInfo = function (osDesc, now) {
        var d = String(osDesc || ''), m;
        var res = function (state, method, current, target, note, urg) {
            var outdated = (state === 'available' || state === 'urgent');
            return { state: state, outdated: outdated, urgent: state === 'urgent', method: outdated ? method : null, current: current, target: target, note: note,
                eol: urg ? urg.eol : '', daysLeft: urg ? urg.daysLeft : null, urgentReason: urg ? urg.reason : '' };
        };
        var outdatedRes = function (method, current, target, note) {
            var urg = obj.osUrgency(d, now);
            return res(urg.urgent ? 'urgent' : 'available', method, current, target, note, urg);
        };
        // Platforms without a newer-release check: only the support end of the installed release is a
        // clean answer - inside the urgency window (or ended) it is 'urgent', otherwise 'unknown'.
        var noCheck = function (label, why) {
            var urg = obj.osUrgency(d, now);
            if (urg.urgent) return res('urgent', null, label, '', why + ' - ' + (urg.ended ? 'end of life' : 'support ends soon') + ', not upgraded automatically', urg);
            return res('unknown', null, label, '', why + '; ' + urg.reason, urg);
        };
        if (/windows server/i.test(d)) return noCheck('', 'Windows Server: in-place upgrades need installation media - not offered');
        if (/windows (10|11)/i.test(d)) {
            var ref = obj.osCurrentWindows11(now);
            m = d.match(/\b(\d{2}h[12])\b/i);
            var win10 = /windows 10/i.test(d);
            var curLabel = win10 ? ('Windows 10' + (m ? ' ' + m[1].toUpperCase() : '')) : (m ? m[1].toUpperCase() : '');
            if (ref.release === '') return res('unknown', null, curLabel, '', 'current Windows 11 release unknown: ' + ref.reason, null);
            var tg = ref.release.toUpperCase();
            if (win10) return outdatedRes('windows-feature', curLabel, tg, 'Windows 10 -> Windows 11 ' + tg + ' (the hardware must meet the Windows 11 requirements)');
            if (!m) return res('unknown', null, '', tg, 'the agent did not report the installed Windows 11 release', null);
            if (obj.winRelNum(m[1]) < obj.winRelNum(ref.release)) return outdatedRes('windows-feature', curLabel, tg, '');
            return res('current', null, curLabel, tg, '', null);
        }
        if (/ubuntu/i.test(d)) {
            m = d.match(/(\d{2})\.(\d{2})/);
            var lts = obj.osCurrentUbuntuLts(now);
            if (!m) return res('unknown', null, '', lts.release, 'the agent did not report the installed Ubuntu release', null);
            var rel = m[1] + '.' + m[2];
            if (lts.release === '') return res('unknown', null, rel, '', 'current Ubuntu LTS release unknown: ' + lts.reason, null);
            if (obj.ubuRelNum(rel) < obj.ubuRelNum(lts.release)) return outdatedRes('ubuntu-release', rel, lts.release, 'do-release-upgrade moves one release step per run');
            return res('current', null, rel, lts.release, '', null);
        }
        var st = obj.osSupportState(d, now);
        if (st.state === 'unknown') return res('unknown', null, st.label || '', '', st.reason || 'release not recognized', null);
        return noCheck(st.label || '', 'a newer release is only checked for Windows 10/11 and Ubuntu');
    };

    /** @type {string} WSUS classification id of "Upgrades" (feature updates) - language independent. */
    obj.WU_UPGRADES_CATEGORY = '3689bdc8-b205-4af4-8d4a-a63924c5e9d5';

    /**
     * @brief Windows script: Windows Update agent (COM Microsoft.Update.Session) search ->
     * download -> install, as SYSTEM, without reboot. 'update' skips the "Upgrades" classification
     * (feature updates), 'upgrade' sets the documented TargetReleaseVersion policy (ProductVersion
     * 'Windows 11' + TargetReleaseVersionInfo) so Windows Update offers that release, installs it and
     * restores the previous policy values afterwards. The running wuauserv service caches the policy,
     * so it is restarted right BEFORE the search and after the restore - without that the upgrade
     * search answers "0 found" until the next scheduled scan (issue #1). One statement per line
     * (guarded by a test).
     * @param {string} mode - 'update' | 'upgrade'.
     * @param {string} [target] - Windows 11 release like '25H2' (validated; required for upgrade).
     * @returns {string} The script text.
     */
    obj.osBuildWindowsScript = function (mode, target) {
        var m = (mode === 'upgrade') ? 'upgrade' : 'update';
        var tg = (typeof target === 'string' && /^\d{2}H[12]$/i.test(target)) ? target.toUpperCase() : '';
        if (m === 'upgrade' && tg === '') { throw new Error('osBuildWindowsScript: upgrade requires a validated target release'); }
        var head = [
            "$ProgressPreference = 'SilentlyContinue'",
            "$invOsMode = '" + m + "'",
            "$invTarget = '" + tg + "'"
        ];
        var invLines = [
            "$invRes = @{ os = 'windows'; mode = $invOsMode; target = $invTarget; found = 0; installed = 0; failed = 0; reboot = $false; result = -1; updates = @(); error = '' }",
            "$invWuKey = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate'; $invPrev = $null; $invPolicyNames = @('TargetReleaseVersion', 'ProductVersion', 'TargetReleaseVersionInfo')",
            "if ($invOsMode -eq 'upgrade') { try { if (-not (Test-Path $invWuKey)) { $null = New-Item -Path $invWuKey -Force }; $invPrev = Get-ItemProperty -Path $invWuKey -ErrorAction SilentlyContinue; Set-ItemProperty -Path $invWuKey -Name 'TargetReleaseVersion' -Value 1 -Type DWord; Set-ItemProperty -Path $invWuKey -Name 'ProductVersion' -Value 'Windows 11' -Type String; Set-ItemProperty -Path $invWuKey -Name 'TargetReleaseVersionInfo' -Value $invTarget -Type String } catch { $invRes.error = 'policy: ' + $_.Exception.Message } }"
        ];
        if (m === 'upgrade') { invLines.push("try { Stop-Service -Name wuauserv -Force -ErrorAction Stop } catch { }; try { Start-Service -Name wuauserv -ErrorAction Stop } catch { }; Start-Sleep -Seconds 3"); }
        invLines.push(
            "$invSess = $null; $invFound = $null",
            "try { $invSess = New-Object -ComObject Microsoft.Update.Session; $invSess.ClientApplicationID = 'InventoryScanner'; $invSr = $invSess.CreateUpdateSearcher(); $invFound = $invSr.Search(\"IsInstalled=0 and IsHidden=0 and Type='Software'\").Updates } catch { $invFound = $null; $invRes.error = 'search: ' + $_.Exception.Message }",
            "$invColl = New-Object -ComObject Microsoft.Update.UpdateColl",
            "if ($null -ne $invFound) { foreach ($invU in $invFound) { $invIsUpg = $false; foreach ($invC in $invU.Categories) { if ($invC.CategoryID -eq '" + obj.WU_UPGRADES_CATEGORY + "') { $invIsUpg = $true } }; if ($invIsUpg -and ($invOsMode -ne 'upgrade')) { continue }; if (-not $invU.EulaAccepted) { try { $invU.AcceptEula() } catch { } }; $null = $invColl.Add($invU) } }",
            "$invRes.found = [int]$invColl.Count",
            "if ($invColl.Count -gt 0) { try { $invDl = $invSess.CreateUpdateDownloader(); $invDl.Updates = $invColl; $null = $invDl.Download(); $invIn = $invSess.CreateUpdateInstaller(); $invIn.Updates = $invColl; $invIr = $invIn.Install(); $invRes.result = [int]$invIr.ResultCode; $invRes.reboot = [bool]$invIr.RebootRequired; for ($invK = 0; $invK -lt $invColl.Count; $invK++) { $invUr = $invIr.GetUpdateResult($invK); $invSt = 'failed'; if (($invUr.ResultCode -eq 2) -or ($invUr.ResultCode -eq 3)) { $invSt = 'ok'; $invRes.installed = $invRes.installed + 1 } else { $invRes.failed = $invRes.failed + 1 }; $invTi = [string]$invColl.Item($invK).Title; if ($invTi.Length -gt 200) { $invTi = $invTi.Substring(0, 200) }; $invRes.updates += @{ title = $invTi; state = $invSt; code = [int]$invUr.ResultCode; hresult = [int]$invUr.HResult } } } catch { $invRes.error = 'install: ' + $_.Exception.Message } } elseif ($invRes.error -eq '') { $invRes.result = 0 }",
            "if (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired') { $invRes.reboot = $true }"
        );
        if (m === 'upgrade') { invLines.push("try { foreach ($invN in $invPolicyNames) { if (($null -ne $invPrev) -and ($null -ne $invPrev.$invN)) { Set-ItemProperty -Path $invWuKey -Name $invN -Value $invPrev.$invN } else { Remove-ItemProperty -Path $invWuKey -Name $invN -ErrorAction SilentlyContinue } } } catch { }; try { Stop-Service -Name wuauserv -Force -ErrorAction Stop } catch { }; try { Start-Service -Name wuauserv -ErrorAction Stop } catch { }"); }
        return head.concat(obj.psTranscriptLines('invscanner-osupdate.log'), invLines, [
            "$invRes | ConvertTo-Json -Compress -Depth 5 | ForEach-Object { Write-Output ('" + obj.OS_MARKER + "' + $_) }",
            "Stop-Transcript -ErrorAction SilentlyContinue | Out-Null"
        ]).join(String.fromCharCode(10));
    };

    /**
     * @brief Linux script (POSIX sh, runs as root through the agent). Every package manager call
     * reads /dev/null as stdin (nothing can swallow script text or wait for input) and writes to
     * the root-only /var/log/invscanner-osupdate.log; only a short tail goes back to the server.
     * 'update': apt-get update + upgrade | dnf upgrade --refresh | yum update | zypper refresh +
     * update | pacman -Syu | apk update + upgrade. 'upgrade' (Ubuntu only): apt-get dist-upgrade,
     * then do-release-upgrade -f DistUpgradeViewNonInteractive (refused by the tool while a reboot
     * is pending - reported as 'reboot-needed', the device is never rebooted).
     * @param {string} mode - 'update' | 'upgrade'.
     * @returns {string} The script text.
     */
    obj.osBuildLinuxScript = function (mode) {
        var m = (mode === 'upgrade') ? 'upgrade' : 'update';
        return [
            "MODE='" + m + "'",
            "LOG=/var/log/invscanner-osupdate.log",
            "[ -L \"$LOG\" ] && LOG=/dev/null",
            "if [ -f \"$LOG\" ] && [ \"$(wc -c < \"$LOG\")\" -gt 5242880 ]; then mv -f \"$LOG\" \"$LOG.old\"; fi",
            "export DEBIAN_FRONTEND=noninteractive",
            "export NEEDRESTART_MODE=a",
            "PM=''; RC=0; STEP=''; NOTE=''; STATE=''",
            "APTOPT='-y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold'",
            "step() { STEP=\"$1\"; shift; echo \"== $(date '+%Y-%m-%d %H:%M:%S') [$MODE] $*\" >> \"$LOG\"; \"$@\" >> \"$LOG\" 2>&1 < /dev/null; RC=$?; return $RC; }",
            "if command -v apt-get >/dev/null 2>&1; then PM=apt; elif command -v dnf >/dev/null 2>&1; then PM=dnf; elif command -v yum >/dev/null 2>&1; then PM=yum; elif command -v zypper >/dev/null 2>&1; then PM=zypper; elif command -v pacman >/dev/null 2>&1; then PM=pacman; elif command -v apk >/dev/null 2>&1; then PM=apk; fi",
            "if [ \"$(id -u)\" != \"0\" ]; then STATE=failed; NOTE='the agent does not run as root'; fi",
            "if [ -z \"$STATE\" ] && [ -z \"$PM\" ]; then STATE=unsupported; NOTE='no supported package manager found'; fi",
            "if [ -z \"$STATE\" ] && [ \"$MODE\" = 'update' ]; then",
            "  case \"$PM\" in",
            "    apt) step refresh apt-get -q update && step upgrade apt-get $APTOPT upgrade ;;",
            "    dnf) step upgrade dnf -y upgrade --refresh ;;",
            "    yum) step upgrade yum -y update ;;",
            "    zypper) step refresh zypper --non-interactive refresh && step upgrade zypper --non-interactive update ;;",
            "    pacman) step upgrade pacman -Syu --noconfirm ;;",
            "    apk) step refresh apk update && step upgrade apk upgrade ;;",
            "  esac",
            "  if [ $RC -eq 0 ]; then STATE=ok; else STATE=failed; fi",
            "fi",
            "if [ -z \"$STATE\" ] && [ \"$MODE\" = 'upgrade' ]; then",
            "  if [ \"$PM\" != 'apt' ] || ! grep -qi '^ID=ubuntu' /etc/os-release 2>/dev/null; then STATE=unsupported; NOTE='release upgrades are only automated for Ubuntu';",
            "  elif grep -qi '^Prompt=never' /etc/update-manager/release-upgrades 2>/dev/null; then STATE=failed; NOTE='Prompt=never in /etc/update-manager/release-upgrades blocks release upgrades';",
            "  else",
            "    step refresh apt-get -q update && step dist-upgrade apt-get $APTOPT dist-upgrade",
            "    if [ $RC -eq 0 ] && ! command -v do-release-upgrade >/dev/null 2>&1; then step install-tool apt-get $APTOPT install update-manager-core; fi",
            "    if [ $RC -ne 0 ]; then STATE=failed;",
            "    elif [ -f /var/run/reboot-required ]; then STATE=reboot-needed; STEP=release-upgrade; NOTE='packages were upgraded; reboot the device, then run the OS upgrade again (do-release-upgrade refuses to start while a reboot is pending)';",
            "    else step release-upgrade do-release-upgrade -f DistUpgradeViewNonInteractive; if [ $RC -eq 0 ]; then STATE=ok; else STATE=failed; fi; fi",
            "  fi",
            "fi",
            "REBOOT=false; [ -f /var/run/reboot-required ] && REBOOT=true",
            "TAIL=$(tail -n 6 \"$LOG\" 2>/dev/null | tr '\\n\\r\\t' '   ' | tr -d '\\000-\\037\\\\\"' | cut -c1-400)",
            "NOTE=$(printf '%s' \"$NOTE\" | tr -d '\\\\\"')",
            "printf '%s{\"os\":\"linux\",\"mode\":\"%s\",\"pm\":\"%s\",\"state\":\"%s\",\"exit\":%d,\"step\":\"%s\",\"reboot\":%s,\"note\":\"%s\",\"log\":\"%s\"}\\n' '" + obj.OS_MARKER + "' \"$MODE\" \"$PM\" \"$STATE\" \"$RC\" \"$STEP\" \"$REBOOT\" \"$NOTE\" \"$TAIL\""
        ].join(String.fromCharCode(10));
    };

    /**
     * @brief One-line sh transport for runcommands type 3: the script travels as base64(gzip) and is
     * run by `sh -c` with stdin from /dev/null, so neither the agent's own stdin feed nor any
     * package manager prompt can interfere.
     */
    obj.osLinuxTransport = function (script) {
        var b64 = zlib.gzipSync(Buffer.from(String(script), 'utf8')).toString('base64');
        return 'sh -c "$(echo \'' + b64 + '\' | base64 -d | gzip -dc)" invscanner < /dev/null';
    };

    /**
     * @brief Devices for an OS batch. 'update' = every Windows/Linux node. 'upgrade' = only nodes whose
     * release is PROVABLY outdated (state 'available' or 'urgent' from fresh lifecycle data) AND has an
     * upgrade method; scope 'urgent' narrows that to state 'urgent' (v3.6.0). Skipped upgrade candidates
     * are logged with the reason. Unknown-OS nodes are never targeted, the winget exclusion list applies
     * to both modes.
     * @param {string} mode - 'update' | 'upgrade'.
     * @param {function} cb - (Array<{id, platform, target}>)
     * @param {string} [scope] - upgrade only: 'urgent' | 'all' (default 'all').
     * @param {Array<string>} [onlyIds] - restrict to these node ids (logging included).
     */
    obj.osTargetNodes = function (mode, cb, scope, onlyIds) {
        try {
            var excl = obj.wingetConfig().excludeNodes;
            obj.db.GetAllType('node', function (err, nodes) {
                if (err || !nodes) { return cb([]); }
                var out = [];
                for (var i = 0; i < nodes.length; i++) {
                    var n = nodes[i];
                    if ((n == null) || (n._id == null) || (n.deleted != null) || excl.indexOf(n._id) >= 0) continue;
                    if (Array.isArray(onlyIds) && onlyIds.indexOf(n._id) < 0) continue;
                    var pf = obj.osPlatformOf(n);
                    if (pf == null) continue;
                    if (mode === 'upgrade') {
                        var ui = obj.osUpgradeInfo(n.osdesc);
                        if (ui.state === 'unknown') { obj.osLog(n._id + ' - not upgraded, no clean answer: ' + ui.note); continue; }
                        if (!ui.outdated) continue;
                        if (ui.method == null) { obj.osLog(n._id + ' - not upgraded, ' + ui.state + ' but no automatic upgrade: ' + ui.note); continue; }
                        if (scope === 'urgent' && !ui.urgent) { obj.osLog(n._id + ' - not upgraded by the urgent batch, upgrade only available: ' + ui.urgentReason); continue; }
                        out.push({ id: n._id, platform: pf, target: ui.target });
                    } else { out.push({ id: n._id, platform: pf, target: '' }); }
                }
                cb(out);
            });
        } catch (e) { cb([]); }
    };

    /**
     * @brief Start an OS batch (never while a winget or OS batch runs).
     * @param {string} mode - 'update' | 'upgrade'.
     * @param {Array<string>} [nodeids] - explicit devices (validated by the caller); the mode's
     *   target rule still applies, so a current device is never "upgraded".
     * @param {function} [done] - called when the queue drained.
     * @param {string} [scope] - upgrade only: 'urgent' | 'all' (default 'all').
     * @returns {object} { started, busy? }
     */
    obj.osStartBatch = function (mode, nodeids, done, scope) {
        if (obj.osBatchRunning || obj.wgBatchRunning) { return { started: false, busy: true }; }
        var m = (mode === 'upgrade') ? 'upgrade' : 'update';
        var sc = (m === 'upgrade' && scope === 'urgent') ? 'urgent' : 'all';
        var label = 'OS ' + m + ((m === 'upgrade') ? ' (' + sc + ')' : '');
        obj.osBatchRunning = true; // reserved now: the db lookup below is asynchronous
        obj.osBatchMode = m;
        obj.osTargetNodes(m, function (list) {
            if (list.length === 0) {
                obj.osBatchRunning = false; obj.osBatchMode = '';
                obj.osLog(label + ' batch - no target devices');
                if (done) done();
                return;
            }
            obj.osLog(label + ' batch starting for ' + list.length + ' device(s)');
            obj.osQueue = list.slice(0, obj.WINGET_MAX_DEVICES);
            obj.osBatchDone = done || null;
            obj.osPump();
        }, sc, Array.isArray(nodeids) ? nodeids : null);
        return { started: true };
    };

    /** @brief Feed the OS queue up to OS_MAX_PARALLEL devices. */
    obj.osPump = function () {
        try {
            while ((obj.osActive < obj.OS_MAX_PARALLEL) && (obj.osQueue.length > 0)) {
                var job = obj.osQueue.shift();
                var nodeid = job.id;
                if ((obj.osPending[nodeid] != null) || (obj.wgPending[nodeid] != null)) continue;
                if (obj.swPending != null && obj.swPending[nodeid] != null) continue; // a deploy script holds the single runcommands session (v4.0.0)
                var ws = obj.meshServer.webserver;
                if (!obj.routeHookInstalled) { try { obj.installRouteHook(); } catch (e) { } }
                var agent = (ws != null && ws.wsagents != null) ? ws.wsagents[nodeid] : null;
                if ((agent == null) || (typeof agent.send !== 'function')) {
                    obj.osResults[nodeid] = { time: new Date().toISOString(), mode: obj.osBatchMode, error: 'offline' };
                    obj.osLog(nodeid + ' - skipped, agent offline');
                    obj.wgRaiseNodeEvent(nodeid, 'OS ' + obj.osBatchMode + ': skipped, the agent was offline');
                    continue;
                }
                var sid = 'invscanner-os-' + obj.safeNodeDir(nodeid);
                var entry = { nodeid: nodeid, sid: sid, since: Date.now(), mode: obj.osBatchMode, platform: job.platform };
                entry.timer = setTimeout(function () { obj.osTimeout(entry); }, obj.OS_RUN_TIMEOUT_MS);
                obj.osPending[nodeid] = entry;
                obj.osActive++;
                try {
                    var msg;
                    if (job.platform === 'windows') {
                        var tg = (obj.osBatchMode === 'upgrade') ? String(job.target || '') : '';
                        msg = { action: 'runcommands', type: 1, cmds: obj.wgTransport(obj.osBuildWindowsScript(obj.osBatchMode, tg)), runAsUser: 0, reply: true, sessionid: sid, responseid: sid };
                    } else {
                        msg = { action: 'runcommands', type: 3, cmds: obj.osLinuxTransport(obj.osBuildLinuxScript(obj.osBatchMode)), runAsUser: 0, reply: true, sessionid: sid, responseid: sid };
                    }
                    agent.send(JSON.stringify(msg));
                    obj.osLog(nodeid + ' - ' + job.platform + ' OS ' + obj.osBatchMode + ' script sent' + (job.target ? (' (target ' + job.target + ')') : ''));
                } catch (ex) {
                    clearTimeout(entry.timer); delete obj.osPending[nodeid]; obj.osActive--;
                    obj.osResults[nodeid] = { time: new Date().toISOString(), mode: obj.osBatchMode, error: 'send-failed: ' + ex.message };
                    obj.osLog(nodeid + ' - send failed: ' + ex.message);
                }
            }
            if ((obj.osActive === 0) && (obj.osQueue.length === 0) && obj.osBatchRunning) {
                obj.osBatchRunning = false;
                obj.osLog('OS ' + obj.osBatchMode + ' batch finished');
                obj.osBatchMode = '';
                obj.osSaveResults();
                var d = obj.osBatchDone; obj.osBatchDone = null;
                if (d) d();
            }
        } catch (e) { obj.osLog('pump error: ' + e.message); }
    };

    /** @brief Watchdog for a device that never answered. */
    obj.osTimeout = function (entry) {
        if ((entry == null) || (obj.osPending[entry.nodeid] !== entry)) return;
        delete obj.osPending[entry.nodeid];
        obj.osActive--;
        obj.osResults[entry.nodeid] = { time: new Date().toISOString(), mode: entry.mode, error: 'timeout' };
        obj.osLog(entry.nodeid + ' - no answer within the run timeout');
        obj.wgRaiseNodeEvent(entry.nodeid, 'OS ' + entry.mode + ': the device did not answer within the timeout');
        obj.osPump();
    };

    /**
     * @brief Answer of one OS session: parse the marker JSON, store a sanitized record, log,
     * raise the device event and advance the queue.
     */
    obj.osHandleResponse = function (nodeid, command) {
        var entry = obj.osPending[nodeid];
        if (entry == null) return;
        if (entry.timer) { clearTimeout(entry.timer); }
        delete obj.osPending[nodeid];
        obj.osActive--;
        var text = (typeof command.result === 'string') ? command.result : JSON.stringify(command.result || '');
        var data = obj.wgPayloadFromText(text, obj.OS_MARKER);
        if ((data == null) && (typeof entry.cbuf === 'string')) { data = obj.wgPayloadFromText(entry.cbuf, obj.OS_MARKER); }
        var s = function (v, n) { return String(v == null ? '' : v).substring(0, n); };
        var rec = { time: new Date().toISOString(), mode: entry.mode, platform: entry.platform };
        if (data == null) { rec.error = (text.indexOf(obj.OS_MARKER) >= 0) ? 'unparsable payload' : 'no marker in output'; }
        else if (entry.platform === 'windows') {
            var ups = data.updates; if (ups == null) { ups = []; } else if (!Array.isArray(ups)) { ups = [ups]; }
            rec.found = (typeof data.found === 'number') ? data.found : 0;
            rec.installed = (typeof data.installed === 'number') ? data.installed : 0;
            rec.failed = (typeof data.failed === 'number') ? data.failed : 0;
            rec.reboot = data.reboot === true;
            rec.target = s(data.target, 10);
            rec.updates = ups.slice(0, 100).filter(function (x) { return x && typeof x.title === 'string'; }).map(function (x) {
                return { title: s(x.title, 200), state: (x.state === 'ok') ? 'ok' : 'failed', hresult: (typeof x.hresult === 'number') ? x.hresult : null };
            });
            if (data.error) { rec.note = s(data.error, 300); }
            rec.state = (rec.failed > 0 || (data.error && rec.installed === 0)) ? 'failed' : 'ok';
        } else {
            var okStates = ['ok', 'failed', 'unsupported', 'reboot-needed'];
            rec.state = (okStates.indexOf(data.state) >= 0) ? data.state : 'failed';
            rec.pm = s(data.pm, 12); rec.step = s(data.step, 30); rec.exit = (typeof data.exit === 'number') ? data.exit : null;
            rec.reboot = data.reboot === true; rec.note = s(data.note, 300); rec.log = s(data.log, 500);
        }
        obj.osResults[nodeid] = rec;
        var sum;
        if (rec.error) { sum = rec.error; }
        else if (rec.platform === 'windows') { sum = rec.state + ': ' + rec.found + ' found, ' + rec.installed + ' installed, ' + rec.failed + ' failed' + (rec.reboot ? ', REBOOT PENDING' : '') + (rec.note ? (' (' + rec.note + ')') : ''); }
        else { sum = rec.state + ' via ' + (rec.pm || '?') + (rec.step ? (' at step ' + rec.step) : '') + (rec.exit != null ? (', exit ' + rec.exit) : '') + (rec.reboot ? ', REBOOT PENDING' : '') + (rec.note ? (' - ' + rec.note) : ''); }
        obj.osLog(nodeid + ' - OS ' + entry.mode + ' ' + sum);
        if (rec.platform === 'windows' && Array.isArray(rec.updates)) {
            for (var i = 0; i < rec.updates.length; i++) { if (rec.updates[i].state === 'failed') { obj.osLog(nodeid + ' - FAILED ' + rec.updates[i].title + (rec.updates[i].hresult != null ? (' (0x' + obj.wgExitHex(rec.updates[i].hresult) + ')') : '')); } }
        } else if (rec.state === 'failed' && rec.log) { obj.osLog(nodeid + ' - output tail: ' + rec.log); }
        obj.wgRaiseNodeEvent(nodeid, 'OS ' + entry.mode + ': ' + sum.substring(0, 300));
        obj.osSaveResults();
        obj.osPump();
    };

    /**
     * @brief POST os_run: { mode: 'update'|'upgrade', scope?: 'urgent'|'all', nodeIds?: csv } - manual OS batch.
     * scope is REQUIRED for a fleet upgrade (no nodeIds) and must be absent or 'urgent'/'all' otherwise;
     * a single-device upgrade defaults to 'all' (an 'available' device may be upgraded on purpose).
     */
    obj.osRunHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        var body = req.body || {};
        if (body.mode !== 'update' && body.mode !== 'upgrade') { return send({ error: 'mode must be update or upgrade.' }); }
        var ids = null;
        if (body.nodeIds != null && body.nodeIds !== '') {
            ids = [];
            var arr = String(body.nodeIds).split(',');
            for (var i = 0; i < arr.length && ids.length < 200; i++) {
                var x = arr[i].trim();
                if (/^node\/[^:]{1,100}$/.test(x) && ids.indexOf(x) < 0) ids.push(x);
            }
            if (ids.length === 0) { return send({ error: 'Invalid nodeIds.' }); }
        }
        var scope = (body.scope == null || body.scope === '') ? '' : String(body.scope);
        if (scope !== '' && scope !== 'urgent' && scope !== 'all') { return send({ error: 'scope must be urgent or all.' }); }
        if (body.mode === 'update' && scope !== '') { return send({ error: 'scope only applies to mode upgrade.' }); }
        if (body.mode === 'upgrade' && ids == null && scope === '') { return send({ error: 'A fleet-wide OS upgrade needs scope urgent or all.' }); }
        if (body.mode === 'upgrade' && scope === '') { scope = 'all'; }
        if (obj.osBatchRunning || obj.wgBatchRunning) { return send({ started: false, busy: true }); }
        if (body.mode === 'upgrade') {
            // No guessing: without fresh reference data the "current release" is unknown, so an
            // upgrade would have no defensible target. Say so plainly instead of picking a version.
            var w11 = obj.osCurrentWindows11(), ul = obj.osCurrentUbuntuLts();
            if (w11.release === '' && ul.release === '') {
                return send({ started: false, error: 'OS Upgrade not started: the current release is unknown. Windows 11: ' + w11.reason + '. Ubuntu: ' + ul.reason + '. Refresh the OS support dates (Settings tab -> Update NVD database now) and try again.' });
            }
        }
        var r = obj.osStartBatch(body.mode, ids, null, scope);
        send({ started: !!r.started, busy: !!r.busy, mode: body.mode, scope: (body.mode === 'upgrade') ? scope : '' });
    };

    /** @brief POST os_status: every Windows/Linux node with release state, urgency and last OS run. */
    obj.osStatusHandler = function (req, res, user) {
        var send = function (o) { res.type('json'); res.json(o); };
        var excl = obj.wingetConfig().excludeNodes;
        obj.db.GetAllType('mesh', function (merr, meshes) {
            var meshNames = {};
            if (!merr && meshes) { for (var mi = 0; mi < meshes.length; mi++) { var mm = meshes[mi]; if (mm && mm._id && mm.deleted == null) meshNames[mm._id] = mm.name || mm._id; } }
            obj.db.GetAllType('node', function (nerr, nodes) {
                var ws = obj.meshServer.webserver, devices = [];
                var counts = { current: 0, available: 0, urgent: 0, unknown: 0 };
                if (!nerr && nodes) {
                    for (var i = 0; i < nodes.length; i++) {
                        var n = nodes[i];
                        if ((n == null) || (n._id == null) || (n.deleted != null)) continue;
                        var pf = obj.osPlatformOf(n);
                        if (pf == null) continue;
                        var ui = obj.osUpgradeInfo(n.osdesc);
                        if (Object.prototype.hasOwnProperty.call(counts, ui.state)) counts[ui.state]++;
                        devices.push({
                            id: n._id, host: obj.getHostName(n), given: (typeof n.name === 'string') ? n.name.trim() : '',
                            group: meshNames[n.meshid] || n.meshid || '', platform: pf, os: String(n.osdesc || '').substring(0, 120),
                            online: (ws != null && ws.wsagents != null && ws.wsagents[n._id] != null), excluded: excl.indexOf(n._id) >= 0,
                            outdated: ui.outdated, urgent: ui.urgent, releaseState: ui.state, upgradable: ui.outdated && ui.method != null,
                            target: ui.target, note: ui.note, eol: ui.eol, daysLeft: ui.daysLeft, urgentReason: ui.urgentReason,
                            last: obj.osResults[n._id] || null, pending: obj.osPending[n._id] ? { since: obj.osPending[n._id].since, mode: obj.osPending[n._id].mode } : null
                        });
                    }
                }
                devices.sort(function (a, b) { return (a.group === b.group) ? String(a.given || a.host).localeCompare(String(b.given || b.host)) : String(a.group).localeCompare(String(b.group)); });
                var w11 = obj.osCurrentWindows11(), ults = obj.osCurrentUbuntuLts();
                send({ devices: devices, counts: counts, urgentDays: obj.scannerConfig().osUpgradeUrgentDays, running: obj.osBatchRunning, mode: obj.osBatchMode, active: obj.osActive, queued: obj.osQueue.length,
                    current: { windows11: w11.release.toUpperCase(), windows11Reason: w11.reason, ubuntuLts: String(ults.release || ''), ubuntuLtsReason: ults.reason } });
            });
        });
    };
};
