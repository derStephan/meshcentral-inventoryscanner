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
  otherwise the answer is 403 (since v3.0.1). GET routes do not change state.
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
  case-insensitively and with attributes and checks EVERY script block of every view (since v4.3.0), so no
  variant of the tag can hide a block from the syntax check.
- **Ids:** CVE ids `CVE-\d{4}-\d{4,}`, `WINDOWS-UPDATES` or `OS-EOL`; mesh ids `^mesh/[^:]+$` (prevents key poisoning in
  `assessments.json`) on every write and on the scan query; node ids `^node/[^:]{1,100}$` for the updater.

### Integrity of downloaded data (OWASP A08)
- NVD feeds and the mapping table are fetched over HTTPS only; table redirects must stay on HTTPS and are capped
  at 2 MB.
- Every mapping regex (remote table and custom entries) passes `isSafeTableRegex`: nested quantifiers and
  backreferences are rejected, because one catastrophic-backtracking pattern would stall the server for every
  scan (CWE-1333).
- NVD `.meta` SHA-256 mismatches are logged as warnings (NVD serves stale `.meta` files); the feed content itself
  is only trusted as public data.
- OS lifecycle data (endoflife.date) is size-capped (512 KB per product), every field is type-checked and cycle
  names are whitelisted before use. A wrong date could only change the support state shown for distribution
  packages; it can never cause commands on devices. Without data the state is *unknown*, never *supported*.

### Agent-side safety
- The client transcript (`invscanner-winget.log`) is written only next to `meshagent.exe` or into
  `%ProgramData%\InventoryScanner`, which the script creates with a protected ACL (SYSTEM + Administrators).
  An existing folder with another owner, or a reparse point, is refused; then the run continues without a
  transcript. User-writable locations (plain `%ProgramData%`, `%TEMP%`) are not used (since v3.0.1).
- winget is resolved from HKLM App Paths, then the admin-only WindowsApps package folder, then PATH.
- No reboot is ever triggered (`--allow-reboot` is never used); the deploy scripts likewise carry no reboot command
  (exit 3010/1641 is *reported* as "ok, reboot pending", asserted by the tests).
- Deploy transcripts (Windows `invscanner-deploy.log`, Linux `/var/log/invscanner-deploy.log`) land only in the
  same protected/checked locations as the updater transcripts; the staged copy under `<filespath>/tmp` is deleted
  when the task closes, and stale copies are swept after 24 h. Server Files sources resolve strictly inside
  `<filespath>/domain[-x]/mesh-<group>` (mesh ids from the DB, names re-validated, traversal rejected - tested).
- The inventory collector asks agents with the minimum rights value (8) needed for the read; uninstall
  requests are never sent through the inventory channel.

### Data protection
- **No inventory data leaves the server.** Outbound requests: `nvd.nist.gov` (feeds),
  `raw.githubusercontent.com` (mapping table; configurable, https only) and `endoflife.date` (OS support dates,
  since 3.1.0; a fixed list of ~15 product names, configurable, https only). No NVD API and no CPE dictionary API is
  queried at runtime.
- Ratings, comments and mappings are stored locally under `<datapath>/nvd/` and
  `<datapath>/plugins/inventoryscanner/`; comments are stored raw and escaped on output.

### Input validation
- Severity values whitelisted (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN); numeric settings range-checked
  (e.g. intervals 0-87600 h); comments ≤ 1000 characters; ignore list ≤ 500 entries.
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

### Known limitations (accepted)
- GET endpoints (reports, CSV export) can be opened by any page the admin visits, like every MeshCentral page; the
  browser's same-origin policy prevents a foreign page from reading the answer.
- Response headers (CSP, `X-Frame-Options: sameorigin`, `nosniff`, `Referrer-Policy`) come from MeshCentral's
  global middleware, which also covers `pluginadmin.ashx` (verified in webserver.js). Its CSP allows
  `'unsafe-inline'` scripts, which the panel needs; XSS protection therefore relies on output escaping.
- The winget script travels as ONE cmd.exe line; an ignore list of more than roughly 150-200 entries exceeds
  cmd's 8191-character limit and the run then ends visibly as "no marker in output". Keep the list short.
- Generated scripts are executed by tests only partially: the deploy flow was run end to end on Windows 11 and
  with a POSIX shell during audit 3, the CI runs one live Linux `.sh` deploy; Windows Update, winget runs and
  `dpkg`/`rpm`/`apt` are verified against their documentation and by syntax parsers, not executed by CI.

---

## Audit History

| Date | Auditor | Model | Scope | Result |
|------|---------|-------|-------|--------|
| 2026-11-06 | AI (opencode) | NVIDIA Nemotron 3 550B A55B | Formal & functional verification (v2.x) | 1 bug fixed, dead code removed |
| 2026-11-11 | AI (opencode) | Claude Opus 5.5 | Independent full audit of v3.0.0: server, agent scripts, update/uninstall, OWASP Top 10, texts, docs, tests | 17 findings, all fixed in v3.0.1 |
| 2026-11-13 | GitHub Code Scanning (CodeQL, javascript-typescript) | - | Whole JS tree of v4.2.1 | 1 alert (`js/bad-tag-filter`, tools/check.js) - fixed in v4.2.2 |
| 2026-11-14 | AI (opencode) | Claude Opus 5.5 | Independent full audit of v4.2.2: server, agents, winget/OS/deploy scripts (Windows + Linux), OWASP Top 10, tests, GitHub Actions, texts, docs | 10 findings + 7 test/CI + 10 text, all fixed in v4.3.0 |

See [AUDIT.md](AUDIT.md) for the detailed reports in chronological order.

---

## Transparency Note

This plugin was originally created with the assistance of **Qwen 3.6 27B** and **Qwen 3.8 Flash Next** (AI coding
assistants). The 2026-11-06 audit was performed by **NVIDIA Nemotron 3 550B A55B**, the 2026-11-11 and 2026-11-14
audits by **Claude Opus 5.5**, all via the opencode agent.
