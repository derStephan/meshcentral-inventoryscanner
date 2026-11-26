# Security Policy

## Supported Versions

Only the latest release on `main` receives fixes (the MeshCentral plugin installer always offers the newest
version; there are no maintained branches).

## Reporting a Vulnerability

Please report security vulnerabilities by opening an issue.

---

## Security Architecture

### Trust model
- The plugin runs inside the MeshCentral server process with the server's file-system rights and can send
  commands to every connected agent. Only **full site administrators of the default domain** can use it.
- The winget updater runs PowerShell **as SYSTEM** on Windows devices (MeshCentral `runcommands`,
  `runAsUser: 0`). It is **off by default**; automatic runs need the switch AND explicitly selected device groups.
  Manual runs (Run now, per device, per package incl. *Uninstall everywhere*) are confirmed in the browser.
- The deploy engine runs admin-chosen installers **as SYSTEM (Windows) / root (Linux)** - that is the feature
  (machine-wide installation). There is **no automation at all**: code only ever runs because a site admin created
  a task for explicitly selected devices, and what runs is always a library/server-files file the admin picked,
  never a path or command typed into the form. The package bytes are SHA-256 verified **on the device** before
  execution; a mismatch or missing download answers `no-file` and executes nothing. Since v4.3.0 the verified bytes
  are exactly the executed bytes: Windows keeps a read-only, write-locked handle on the file from the hash check
  until the installer ended, Linux executes only a re-hashed private copy in a fresh `mktemp -d` (mode 700) folder.
  Since v4.3.1 a Windows installer is never started from `C:\Windows\Temp`: it runs from a new folder with a
  SYSTEM + Administrators ACL, so no DLL planted by a standard user next to it can be loaded (CWE-427).
- **Server Files as a deploy source** are a trust decision: MeshCentral lets every user with the *server files*
  right of a device group (`MESHRIGHT_SERVERFILES`) put files into that group's folder. Deploying such a file runs
  that user's file as SYSTEM/root - check the content before you deploy it. File names from there are always
  treated as data (all PowerShell quote characters, incl. the typographic ones, are escaped since v4.3.0).

### Access control (OWASP A01)
- Every GET/POST route and the device-list toolbar hook require `user.siteadmin === 0xFFFFFFFF` **and**
  `user.domain === ''` (`obj.isAuthorizedAdmin`). The plugin reads all devices of all domains, so sub-domain
  administrators of a multi-tenant server are refused (since v3.0.1).
- **Cross-site request guard:** MeshCentral authenticates `pluginadmin.ashx` by session cookie only (no CSRF
  token). Every POST must therefore carry the header `X-InvScanner-Request: 1`, which only the plugin's own page
  sends (a foreign site cannot add a custom header without a CORS preflight, which MeshCentral never permits);
  otherwise the answer is 403 (since v3.0.1). Since v5.5.1 the same applies to the one GET that is an ACTION - a live
  scan (`action=scan` without `cached=1`) queries every device of the selected locations, so a foreign link or
  `<img src>` could otherwise start a fleet pass in the admin's name. The remaining GETs (panel, cached scan, reports,
  CSV) only read. The gate (401 non-admin, 401 sub-domain admin, 403 no header, 400 non-object body) is pinned by a
  test for ALL POST actions.
- Toolbar exports accept only well-formed node ids (`node/<domain>/<id>`), because MeshCentral does not
  rights-check the top-level `selectedDevices` list it passes to plugins.
- Server notifications (scan results, NVD stale, deploy summary) carry `domain: ''`: MeshCentral subscribes every
  site admin - also those of sub-domains - to `'*'` and filters only by the event's domain (since v4.3.0).
- Automatic winget runs need the switch **and** at least one ticked device group, and only reach Windows devices
  (the agent-connect path ignored both rules before v4.3.0).

### Injection (OWASP A03)
- **Agent scripts:** every package id that reaches PowerShell matches `^[A-Za-z0-9._+-]{1,128}$` and is embedded
  in single quotes with quote doubling; invalid ids are dropped (ignore list) or reduce the run to a no-op
  (`$invOnly = ''`). The script travels as one base64(gzip) line, so no shell metacharacters are interpreted.
- **Deploy scripts (v4.0.0):** file names go through `swSanitizeName` (basename, hostile chars removed), only
  `SW_EXTS` types run, extensions/hashes/ids in the scripts are server-generated regex-cleaned values, and command
  arguments lose all control characters (`swSafeArgs`, ≤500 chars) before being embedded **single-quoted with
  complete shell quoting** (PowerShell: `'` and the typographic quotes `‘ ’ ‚ ‛` doubled - PowerShell treats all
  five as quote characters; POSIX `'\''`). Tests assert the quoting, run the hostile case through PowerShell and
  check that a hostile args/name string can never produce a second command on a script line (plus the real
  PowerShell/sh parsers run over the
  generated scripts). The staged file names are `invsw-<16hex>-<12hex>.<ext>` from a CSPRNG, so no name can be
  pre-created in advance; the name is not secret on the device once the task runs (it is part of the agent's
  command), which is why the integrity rests on the hash-and-lock step described above, not on the name. The
  download ticket (`tmpdl` cookie) is bound to one node, one file and 5 minutes, and it is minted per dispatch.
- **CSV formula injection** (CWE-1236): values starting with `= + - @ tab CR` are prefixed with `'`.
- **HTML:** the views use only escaped Handlebars output (`{{...}}`, never `{{{...}}}`); the panel script
  escapes every dynamic value with `esc()` before inserting HTML. The panel's own inline `<script>` is a static
  file (no interpolation), and the verification tool that extracts it (`tools/check.js`) matches the tag
  case-insensitively and with attributes (also on the end tag, e.g. `</script >`, since v4.3.1) and checks EVERY
  script block of every view, failing when an opening tag has no extracted block (since v4.3.0/4.3.1), so no
  variant of the tag can hide a block from the syntax check.
- **Ids:** CVE ids `CVE-\d{4}-\d{4,}`, `WINDOWS-UPDATES` or `OS-EOL`; mesh ids `^mesh/[^:]+$` (prevents key poisoning in
  `assessments.json`) on every write and on the scan query; node ids `^node/[^:]{1,100}$` for the updater. Where a
  mesh id becomes a PATH (Server Files deploy) both parts are validated separately since v5.5.1 - the group part as
  MeshCentral generates it (base64 with `@`/`$`), the domain part as a plain name - and the resulting folder is
  prefix-checked against `<filespath>` (before, `mesh/a\..\..\x/g` passed the generic id check and resolved
  outside it). Node ids become a folder name only through `safeNodeDir`, which can no longer return `.`/`..`.

### Integrity of downloaded data (OWASP A08)
- NVD feeds and the mapping table are fetched over HTTPS only; table redirects must stay on HTTPS and are capped
  at 2 MB.
- Every mapping regex (remote table, license table and custom entries) passes `isSafeTableRegex`: a repeated group
  must not contain a quantifier or an alternation at ANY depth, and backreferences (numbered and named) are rejected,
  because one catastrophic-backtracking pattern would stall the server for every scan (CWE-1333). Hardened in v5.5.1:
  the earlier check missed `((a+))+$` (measured 45 s on 29 characters) and `(a|a)+$` (72 s).
- NVD `.meta` SHA-256 mismatches are logged as warnings (NVD serves stale `.meta` files); the feed content itself
  is only trusted as public data.
- OS lifecycle data (endoflife.date) is size-capped (512 KB per product - actually applied since v5.5.1; before, the
  2 MB table cap was used), every field is type-checked and cycle
  names are whitelisted before use. A wrong date could only change the support state shown for distribution
  packages; it can never cause commands on devices. Without data the state is *unknown*, never *supported*.

### Agent-side safety
- The client transcript (`invscanner-winget.log`) is written only next to `meshagent.exe` or into
  `%ProgramData%\InventoryScanner`, which the script creates with a protected ACL (SYSTEM + Administrators).
  An existing folder with another owner, or a reparse point, is refused; then the run continues without a
  transcript. User-writable locations (plain `%ProgramData%`, `%TEMP%`) are not used (since v3.0.1).
- winget is resolved from HKLM App Paths, then the admin-only WindowsApps package folder, then PATH.
- **Reboot policy (since v4.6.0, two paths since v4.7.0).** A reboot is no longer forbidden outright - it must
  be EXPLICIT and ANNOUNCED. The winget / OS update / OS upgrade / deploy / Windows-Update-troubleshooter
  engines emit no reboot command at all (`--allow-reboot` is never used; the per-script
  `!/Restart-Computer|shutdown/i` assertions stay and also cover the troubleshooter scripts), and a pending
  reboot is always *reported* (exit 3010/1641 "ok, reboot pending"; WU troubleshooter Diagnose/Repair report
  whether a reboot is pending and when Windows performs it automatically). Only TWO features restart a device,
  both per-device, manual and typed-name confirmed, never a batch, never scheduled, never automatic: the
  **PC Reset** (via the built-in `systemreset`; "Remove everything" hard-blocked while BitLocker protection is
  on/unknown until the recovery key is confirmed) and the **Force Restart** (via the OS `shutdown`, with a
  grace period).
- The **Force restart / user notice** message is sanitized (control chars and the shell/PowerShell quoting
  chars `` ` $ " \ `` removed, length-capped) and travels base64, decoded on the device and used ONLY as a
  single quoted argument to `msg`/`wall`/`shutdown` - a crafted message can never inject a command. It is
  gated on a full site admin + the request-origin header; `reboot_now` also needs the device name typed.
- The **Windows Update troubleshooter repairs** (v4.6.0) are the deterministic, auditable form of the built-in
  troubleshooter's "apply fixes" step (the `TroubleshootingPack` cmdlets were removed in Windows 10 1709): they
  restart the WU services and reset `SoftwareDistribution\Download` + `catroot2`. They deliberately do NOT run
  `netsh winsock reset` or `winhttp reset proxy` (invasive / would break managed devices - the proxy is only
  reported) and trigger no reboot.
- Deploy transcripts (Windows `invscanner-deploy.log`, Linux `/var/log/invscanner-deploy.log`) land only in the
  same protected/checked locations as the updater transcripts; the staged copy under `<filespath>/tmp` is deleted
  when the task closes, and stale copies are swept after 24 h. Server Files sources resolve strictly inside
  `<filespath>/domain[-x]/mesh-<group>` (mesh ids from the DB, names re-validated, traversal rejected - tested).
- The inventory collector asks agents with the minimum rights value (8) needed for the read; uninstall
  requests are never sent through the inventory channel.

### Data protection
- **By default no inventory data leaves the server.** Outbound requests: `nvd.nist.gov` (feeds),
  `raw.githubusercontent.com` (mapping table; configurable, https only) and `endoflife.date` (OS support dates,
  since 3.1.0; a fixed list of ~15 product names, configurable, https only). No NVD API and no CPE dictionary API is
  queried at runtime.
- **The one deliberate exception (v5.0.0, issue #5): the optional asset-management connector.** It can push the
  lists this plugin already aggregates (hardware, software, vulnerabilities) to an external REST system. It is
  **disabled by default**, there is **no automatic push** unless an interval is set (also 0 by default), and it
  only runs for full site admins who configure a target and switch it on - the panel states plainly that this is
  the only place where data leaves the server, and every push asks for confirmation. Controls: the endpoint must
  be **https** (rejected otherwise, also at request-build time); credentials are stored in
  `scanner-settings.json` on this server, are **never returned to the browser in the clear** (masked, with an
  explicit "clear" action; since v5.5.1 this includes the literal values of the generic target's extra headers, which
  often carry an API key - they were returned in the clear before) and are **never written to a log**; the log records only device, HTTP status and an
  external id - **never a request/response body**. The push is entirely server-side from stored inventory: it
  sends **no agent command**, so it cannot reach a device and does not touch the one-session-per-agent rule.
  What is sent is the same data the admin could already export as CSV. Because the destination is
  admin-configured, it inherits the same trust model as the other admin-configurable URLs (SSRF is bounded by
  "a full site admin chose this https host"); the generic body template is JSON **data** only - placeholders are
  substituted as values and the template is never evaluated as code.
  Hardened in v5.0.1: a custom header name must be an RFC 7230 token and a header value must not contain control
  characters (checked for the auth header and for every generic extra header), so no header injection/request
  smuggling is possible; enabling a target requires the matching credential to actually exist (bearer token,
  basic user/password, header name+value), so a configuration that could only ever answer 401 cannot be saved;
  a push answers immediately and runs in the background with bounded parallelism (4) and a 10-minute watchdog
  that unlocks the connector, so a hung target can neither time out the admin's request nor block the feature;
  redirects are deliberately NOT followed (an answered 3xx is a failure), which keeps the Authorization header
  from ever being replayed to another host.
- Ratings, comments and mappings are stored locally under `<datapath>/nvd/` and
  `<datapath>/plugins/inventoryscanner/`; comments are stored raw and escaped on output.
- **License keys (v4.8.0)** are treated as sensitive: collection is **opt-in (default off)** and the extraction
  script is **read-only** (registry GetValue / file read /
  CIM property - the rule table has no "run command" type, so a tampered table cannot execute). The values are
  written **only** to `<datapath>/plugins/inventoryscanner/data/<node>/license.json` on this server, never sent
  off-server and never written to a log (the log records counts, not keys); they appear only in the admin's own
  software-CSV export. Remote/custom rules pass the same regex-safety and field-validation gate as the CPE table.
  **Per-user reads (v5.5.0)** stay inside the same guarantee: user discovery enumerates SIDs and profile dirs from
  `ProfileList` read-only; a per-user registry rule reads only **already-loaded** hives (`HKEY_USERS\<SID>` of
  logged-on users) - offline hives are **never** mounted (`reg load`/`LoadKey` are rejected by the script-shape
  test), because mounting a hive is a system modification. A per-user file rule reads only existing profile
  directories. The well-known service accounts (LocalSystem, LocalService, NetworkService) are never treated as users. Wildcards are capped (20 registry subkeys, 5 file candidates, 20 user profiles per run). The only
  per-user datum that leaves the device is the profile leaf NAME in the answer's `user` field (and thereby in the
  CSV's License Source, e.g. `registry (user: alice)`) - a name, not a secret; the key itself is stored server-side
  as before.
  **Trigger (v5.2.0):** by default the collection runs **only on demand** (an admin presses *Collect*). An
  automatic schedule can be enabled in the Settings (`licenseCollectIntervalHours`, default **0 = off**) and needs
  the master switch as well; it runs the identical read-only script on every **online Windows** device, skips
  devices that hold another agent session (the one-session-per-agent rule is unchanged), never writes to a device
  and never reboots one. The schedule does not widen what leaves the server: the keys still stay local - the only
  off-server path remains the separately opt-in asset-management connector.
  **Microsoft license metadata (v5.6.0)** widens what is READ on the device but not what is secret: the same single
  `Get-CimInstance SoftwareLicensingProduct` call now also returns the edition (`Name`/`LicenseFamily`), the key
  channel (`ProductKeyChannel`: Retail / OEM:DM / OEM:NONSLP / Volume:MAK / Volume:KMSCLIENT), the activation state
  (`LicenseStatus`), the remaining grace minutes, an evaluation end date and the application id. These are
  configuration facts about the installation, not credentials, and they are what makes an unlicensed machine visible.
  **The key material is unchanged: only `PartialProductKey` (the last five characters) is ever read.** The plugin
  deliberately does NOT decode `DigitalProductId`, does NOT read the firmware-embedded
  `SoftwareLicensingService.OA3xOriginalProductKey` and does NOT call `slmgr` or any activation path - a full product
  key is a usable secret, reconstructing one is what the AV-flagged key-finder tools do, and the read-only guarantee
  above would no longer be the whole story. A script-shape test pins all four absences. On the way to the browser the
  partial key is dropped as well: `dev_details` reports the Microsoft entries as metadata plus counts
  (`msSummary.licensed` / `notLicensed` / `unknown`) and `lic_status` reports counts only, so no key fragment reaches
  a page, a log or the asset push. A missing `LicenseStatus` counts as `unknown`, never as a violation - the plugin
  does not accuse a device on the basis of an unreadable value.
  **The curated `licenseType`** (v5.6.0, in `cpe-table.json`) is public product information - an SPDX identifier or
  Proprietary / Freeware / Freeware (non-commercial). It is derived from no device data at all, contains nothing about
  your fleet, and is sanitized (`obj.sanitizeLicenseType`: 80 characters, `[A-Za-z0-9.+()\- ]` only) before it reaches
  a CSV cell or an HTML attribute, because it is rendered into both.

### Input validation
- Severity values whitelisted (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN); numeric settings range-checked
  (scan interval 0-87600 h, feed refresh 1-87600 h, collection 0-525600 min, license and asset schedules 0-8760 h,
  urgency window 0-3650 days); comments ≤ 1000 characters; ignore list ≤ 500 entries.
- Deploy: extensions whitelisted (msi/msp/exe/deb/rpm/sh/bin), upload chunks 48 KiB below the server's 100 kb
  body limit, files ≤ 2 GiB, ≤ 500 devices per task, ≤ 100 stored tasks, ids regexed before any object lookup
  or path join.

### Defaults
| Setting | Default |
|---|---|
| Scheduled scans | every 24 h |
| Notifications | on, threshold HIGH |
| Inventory collection | daily and on agent connect |
| NVD feed refresh | every 168 h |
| Version-less CVE suppression | older than 5 years |
| winget updater | **off** |
| Software deploy | manual-only, no automation exists |
| License collection | **off**; when switched on: on demand, schedule 0 (= off) |
| Asset-management connector | **off**, automatic push interval 0 (= off) |
| OS updates / upgrades, PC reset, restart, Windows Update repair | manual only, no automation exists |

### Known limitations (accepted)
- The read-only GET endpoints (reports, CSV export, the cached scan) can be opened by any page the admin visits, like
  every MeshCentral page; the browser's same-origin policy prevents a foreign page from reading the answer. Building a
  report or an export still walks the fleet on the server (paced) - a foreign page can cause that load, not read it.
- Response headers (CSP, `X-Frame-Options: sameorigin`, `nosniff`, `Referrer-Policy`) come from MeshCentral's
  global middleware, which also covers `pluginadmin.ashx` (verified in webserver.js). Its CSP allows
  `'unsafe-inline'` scripts, which the panel needs; XSS protection therefore relies on output escaping.
- The winget script travels as ONE cmd.exe line; an ignore list of more than roughly 150-200 entries exceeds
  cmd's 8191-character limit and the run then ends visibly as "no marker in output". Keep the list short.
- Generated scripts are executed by tests only partially: the deploy flow was run end to end on Windows 11 and
  with a POSIX shell during audit 3; audit 4 ran the winget dry run, the winget uninstall of a non-existent package
  and the license extraction (machine, per-user registry wildcard, per-user file) through the real cmd.exe transport
  on Windows 11; the CI runs one live Linux `.sh` deploy. For v5.6.0 the license script was again built by the real
  module and **executed on a real Windows 11** (read-only): the PowerShell parser reported 0 errors, the corrected
  Office rule fell through from the empty `ProductKeys` to `ProductReleaseIds`, and the three
  `SoftwareLicensingProduct` entries came back with family, channel, status, grace, evaluation date and application id
  - which is how the audit machine's Office edition in notification mode became visible. Windows Update installs,
  real winget upgrades and `dpkg`/`rpm`/`apt` are verified against their documentation and by syntax parsers, not
  executed by CI.

---

## Audit History

| Date | Auditor | Model | Scope | Result |
|------|---------|-------|-------|--------|
| 2026-11-06 | AI (opencode) | NVIDIA Nemotron 3 550B A55B | Formal & functional verification (v2.x) | 1 bug fixed, dead code removed |
| 2026-11-11 | AI (opencode) | Claude Opus 5.5 | Independent full audit of v3.0.0: server, agent scripts, update/uninstall, OWASP Top 10, texts, docs, tests | 17 findings, all fixed in v3.0.1 |
| 2026-11-13 | GitHub Code Scanning (CodeQL, javascript-typescript) | - | Whole JS tree of v4.2.1 | 1 alert (`js/bad-tag-filter`, tools/check.js) - fixed in v4.2.2 |
| 2026-11-14 | AI (opencode) | Claude Opus 5.5 | Independent full audit of v4.2.2: server, agents, winget/OS/deploy scripts (Windows + Linux), OWASP Top 10, tests, GitHub Actions, texts, docs | 10 findings + 7 test/CI + 10 text, all fixed in v4.3.0 |
| 2026-11-14 | Follow-up (Claude Opus 5.5) + GitHub Code Scanning | - | DLL planting next to the deploy installer; CodeQL `js/bad-tag-filter` #3 in tools/check.js | both fixed in v4.3.1 |
| 2026-11-25 | AI (opencode) | Claude Opus 5.5 | Independent full audit of v5.5.0: server, agent scripts (executed on Windows 11), update/uninstall/delete paths, OWASP Top 10, texts, docs, the test suite itself | 5 functional + 4 security + 2 hardening findings, all fixed in v5.5.1 |

See [AUDIT.md](AUDIT.md) for the detailed reports in chronological order.

---

## Transparency Note

This plugin was originally created with the assistance of **Qwen 3.6 27B** and **Qwen 3.8 Flash Next** (AI coding
assistants). The 2026-11-06 audit was performed by **NVIDIA Nemotron 3 550B A55B**, the 2026-11-11, 2026-11-14 and
2026-11-25 audits by **Claude Opus 5.5**, all via the opencode agent.
