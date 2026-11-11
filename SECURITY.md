# Security Policy

## Supported Versions

Only the latest release on `main` receives fixes (the MeshCentral plugin installer always offers the newest
version; there are no maintained branches).

| Version | Supported          |
| ------- | ------------------ |
| 3.0.x   | :white_check_mark: |
| < 3.0   | :x:                |

## Reporting a Vulnerability

Please report security vulnerabilities by opening a private GitHub Security Advisory:

1. Go to the **Security** tab of this repository
2. Click **Report a vulnerability**
3. Fill in the details

We will acknowledge receipt within 48 hours and provide a timeline for fixes.

---

## Security Architecture

### Trust model
- The plugin runs inside the MeshCentral server process with the server's file-system rights and can send
  commands to every connected agent. Only **full site administrators of the default domain** can use it.
- The winget updater runs PowerShell **as SYSTEM** on Windows devices (MeshCentral `runcommands`,
  `runAsUser: 0`). It is **off by default**; automatic runs need the switch AND explicitly selected device groups.
  Manual runs (Run now, per device, per package incl. *Uninstall everywhere*) are confirmed in the browser.

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

### Injection (OWASP A03)
- **Agent scripts:** every package id that reaches PowerShell matches `^[A-Za-z0-9._+-]{1,128}$` and is embedded
  in single quotes with quote doubling; invalid ids are dropped (ignore list) or reduce the run to a no-op
  (`$invOnly = ''`). The script travels as one base64(gzip) line, so no shell metacharacters are interpreted.
- **CSV formula injection** (CWE-1236): values starting with `= + - @ tab CR` are prefixed with `'`.
- **HTML:** the views use only escaped Handlebars output (`{{...}}`, never `{{{...}}}`); the panel script
  escapes every dynamic value with `esc()` before inserting HTML.
- **Ids:** CVE ids `CVE-\d{4}-\d{4,}` or `WINDOWS-UPDATES`; mesh ids `^mesh/[^:]+$` (prevents key poisoning in
  `assessments.json`) on every write and on the scan query; node ids `^node/[^:]{1,100}$` for the updater.

### Integrity of downloaded data (OWASP A08)
- NVD feeds and the mapping table are fetched over HTTPS only; table redirects must stay on HTTPS and are capped
  at 2 MB.
- Every mapping regex (remote table and custom entries) passes `isSafeTableRegex`: nested quantifiers and
  backreferences are rejected, because one catastrophic-backtracking pattern would stall the server for every
  scan (CWE-1333).
- NVD `.meta` SHA-256 mismatches are logged as warnings (NVD serves stale `.meta` files); the feed content itself
  is only trusted as public data.

### Agent-side safety
- The client transcript (`invscanner-winget.log`) is written only next to `meshagent.exe` or into
  `%ProgramData%\InventoryScanner`, which the script creates with a protected ACL (SYSTEM + Administrators).
  An existing folder with another owner, or a reparse point, is refused; then the run continues without a
  transcript. User-writable locations (plain `%ProgramData%`, `%TEMP%`) are not used (since v3.0.1).
- winget is resolved from HKLM App Paths, then the admin-only WindowsApps package folder, then PATH.
- No reboot is ever triggered (`--allow-reboot` is never used).
- The inventory collector asks agents with the minimum rights value (8) needed for the read; uninstall
  requests are never sent through the inventory channel.

### Data protection
- **No inventory data leaves the server.** Outbound requests: `nvd.nist.gov` (feeds) and
  `raw.githubusercontent.com` (mapping table; configurable, https only). No NVD API and no CPE dictionary API is
  queried at runtime.
- Ratings, comments and mappings are stored locally under `<datapath>/nvd/` and
  `<datapath>/plugins/inventoryscanner/`; comments are stored raw and escaped on output.

### Input validation
- Severity values whitelisted (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN); numeric settings range-checked
  (e.g. intervals 0-87600 h); comments ≤ 1000 characters; ignore list ≤ 500 entries.

### Defaults
| Setting | Default |
|---|---|
| Scheduled scans | every 24 h |
| Notifications | on, threshold HIGH |
| Inventory collection | daily and on agent connect |
| NVD feed refresh | every 168 h |
| Version-less CVE suppression | older than 5 years |
| winget updater | **off** |

### Known limitations (accepted)
- GET endpoints (reports, CSV export) can be opened by any page the admin visits, like every MeshCentral page; the
  browser's same-origin policy prevents a foreign page from reading the answer.
- Response headers (CSP, `X-Frame-Options: sameorigin`, `nosniff`, `Referrer-Policy`) come from MeshCentral's
  global middleware, which also covers `pluginadmin.ashx` (verified in webserver.js). Its CSP allows
  `'unsafe-inline'` scripts, which the panel needs; XSS protection therefore relies on output escaping.

---

## Audit History

| Date | Auditor | Model | Scope | Result |
|------|---------|-------|-------|--------|
| 2026-11-06 | AI (opencode) | NVIDIA Nemotron 3 550B A55B | Formal & functional verification (v2.x) | 1 bug fixed, dead code removed |
| 2026-11-11 | AI (opencode) | Claude Opus 5.5 | Independent full audit of v3.0.0: server, agent scripts, update/uninstall, OWASP Top 10, texts, docs, tests | 17 findings, all fixed in v3.0.1 |

See [AUDIT.md](AUDIT.md) for the detailed reports in chronological order.

---

## Transparency Note

This plugin was originally created with the assistance of **Qwen 3.6 27B** and **Qwen 3.8 Flash Next** (AI coding
assistants). The 2026-11-06 audit was performed by **NVIDIA Nemotron 3 550B A55B**, the 2026-11-11 audit by
**Claude**, both via the opencode agent.
