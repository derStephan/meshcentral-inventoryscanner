# Audit Reports

This file contains every audit of the plugin in **chronological order**. Each audit is kept unchanged as it was
written; later audits refer back to earlier ones instead of rewriting them.

| # | Date | Auditor / model | Plugin version audited | Result |
|---|------|-----------------|------------------------|--------|
| 1 | 2026-11-06 | AI (opencode), NVIDIA Nemotron 3 550B A55B | 2.x (pre-3.0) | 1 bug fixed, dead code removed |
| 2 | 2026-11-11 | AI (opencode), Claude Opus 5.5 | 3.0.0 | 17 findings, all fixed -> **3.0.1** |
| 3 | 2026-11-14 | AI (opencode), Claude Opus 5.5 | 4.2.2 | 2 high, 4 medium, 4 low + tests/CI/texts, all fixed -> **4.3.0**; 2 follow-up fixes -> **4.3.1** |

Between audit 1 and audit 2 the plugin grew from ~3,000 to ~4,900 lines (v2.1 - v3.0.0: winget updater with
per-package update/uninstall, remote CPE table, automatic product matching, driver/firmware category, hot reload).
Audit 1 therefore did not cover most of the code that runs on the agents.

Between audit 2 and audit 3 (v3.0.1 -> v4.2.2) the code was split into 23 `lib/` modules (v3.5.1) and three new
agent-facing features were added: OS updates / OS release upgrades (v3.5.0, v3.6.0), **software deployment** with
upload, staging and agent `wget` (v4.0.0), plus a GitHub Actions workflow with a live MeshCentral server and agent.
Audit 3 is the first audit of that code.

---

# Audit 1 - 2026-11-06 - Formal & Functional Verification

> Original text, unchanged. Notes from audit 2 on its statements are collected in section
> "Audit 2 / Re-check of audit 1" further below.


**Repository**: meshcentral-inventoryscanner  
**Commit**: Post-audit (changes committed)  
**Date**: 2026-11-06  
**Auditor**: AI (opencode)  
**Model**: NVIDIA Nemotron 3 550B A55B  
**Scope**: Complete plugin codebase (`inventoryscanner/`), Handlebars views, test suite (`tools/`)

> **Transparency Note**: This plugin was originally created with the assistance of **Qwen 3.6 27B** and **Qwen 3.8 Flash Next** (AI coding assistants). This audit was performed by **NVIDIA Nemotron 3 550B A55B** via the opencode agent.

---

## Executive Summary

| Metric | Result |
|--------|--------|
| **Overall Status** | ✅ PASS |
| **Tests Passing** | 78/78 (72 behavioral + 6 view render) |
| **Critical Bugs** | 1 fixed |
| **High Issues** | 0 |
| **Medium Issues** | 0 |
| **Dead Code Removed** | ~466 lines (13% reduction) |
| **Security Issues** | 0 (all verified secure) |

---

## Audit Methodology

### 1. Static Analysis
- `node --check` on main plugin file
- Handlebars inline script extraction + syntax check
- JSON validity of config files
- Render name ↔ view file name matching (case-sensitive)
- Stray `{{` detection in panel inline script

### 2. Behavioral Testing (tools/test-plugin.js)
72 assertions against mocked MeshCentral server:
- Report building: locations, counting semantics, coverage %, manual rating override, host names
- Scan aggregation: multi-mesh, mixed/uniform logic, flagged findings
- POST routes: save/flag/unflag assessments, validation (key poisoning, bogus CVE IDs)
- GET routes: scan, report, deviceReport, show, export, CPE table, settings
- Admin gating: 401 for non-admins
- CSV exports: headers, BOM, filename, column order
- Long timers: chunking, restart-proof scheduling, generation bump
- Notifications: new/open/never modes, threshold filtering
- NVD status: file-mtime based (restart-proof)
- Settings overlay: file > config.json > defaults, revert, timer gen bump
- Collector: per-cycle effective interval, 0 stops chain

### 3. View Render Testing (tools/test-views.js)
- All 3 views compile and render with data + empty data
- HTML escaping verified (hostile names, comments)
- Device report uses host names (not display names)

### 4. Manual Code Review
- Security controls verification
- Dead code identification
- Configuration consistency
- Documentation accuracy

---

## Findings

### 🔴 Critical: `anyCveMaxAgeYears` Bypasses Settings Overlay
**Location**: `inventoryscanner.js:1527-1535`  
**Issue**: Function read directly from `obj.meshServer.config.settings.vulnerabilityScanner` instead of `obj.effectiveSectionConfig('vulnerabilityScanner')`.  
**Impact**: UI changes in Settings tab had no effect on ancient CVE suppression.  
**Fix**: Changed to use `effectiveSectionConfig()` — now respects `scanner-settings.json` overrides.  
**Test**: Existing overlay tests cover this (pass).

---

### 🟡 Dead Code Removal (~466 lines)

| Component | Lines | Reason |
|-----------|-------|--------|
| CPE API lookup (`cpeTokenCache`, `cpeTokenPending`, `queryCpeTokenExists`, `resolveCpeToken`, `deriveCpeTokenCandidate`, `loadCpeTokenCache`, `saveCpeTokenCache`) | ~300 | Abandoned approach — plugin uses curated CPE table only |
| Publisher-based vendor normalization (`PUBLISHER_CPE_VENDOR`, `normalizeVendor`, `GENERIC_CPE_TOKENS`, `bestProductForVendor`) | ~100 | Part of abandoned multi-strategy matching |
| `vendorHasAnyEntry()` | ~30 | Unused helper |
| `cpeTokensPath` variable + `loadCpeTokenCache()` call in `server_startup()` | ~10 | Dead config |
| German comments | ~20 | Translated to English |

**Verification**: All tests pass after removal. No functionality lost — the "curated table only" strategy was already the implemented behavior (see `deriveCpeProduct` returning only `matchKnownProduct` results).

---

### 🟢 Security Verification (All PASS)

| Control | Status | Evidence |
|---------|--------|----------|
| Admin gating on all endpoints | ✅ | `user.siteadmin !== 0xFFFFFFFF` → 401 |
| CSV formula injection (CWE-1236) | ✅ | `formatCsvField()` prefixes `' ` for `= + - @ tab CR` |
| Key poisoning protection | ✅ | `parseMeshIds()` validates `^mesh\/[^:]+$` |
| CVE ID format validation | ✅ | `isFindingId()` regex `^(CVE-\d{4}-\d{4,}\|WINDOWS-UPDATES)$` |
| Input validation (all POST) | ✅ | Numeric ranges, severity whitelist, comment length |
| Output HTML escaping | ✅ | Handlebars `{{...}}` only, no `{{{...}}}` |
| Comments stored raw, escaped at render | ✅ | No double-escaping |
| Settings never write `config.json` | ✅ | Overlay in `scanner-settings.json` only |

---

### 🟢 Configuration Consistency (All PASS)

| Setting | Config Key | Settings Tab | Overlay Works | Revert Works | Test Coverage |
|---------|------------|--------------|---------------|--------------|---------------|
| scanIntervalHours | vulnerabilityScanner | ✅ | ✅ | ✅ | ✅ |
| scanMeshes | vulnerabilityScanner | ✅ | ✅ | ✅ | ✅ |
| notifyOnScan | vulnerabilityScanner | ✅ | ✅ | ✅ | ✅ |
| notifyThreshold | vulnerabilityScanner | ✅ | ✅ | ✅ | ✅ |
| notifyUnratedRepeat | vulnerabilityScanner | ✅ | ✅ | ✅ | ✅ |
| notify (per-group) | vulnerabilityScanner | ✅ | ✅ | ✅ | ✅ |
| updateHours | vulnerabilityScanner | ✅ | ✅ | ✅ | ✅ |
| anyCveMaxAgeYears | vulnerabilityScanner | ✅ | ✅** | ✅ | ✅ |
| collectIntervalMinutes | inventoryScanner | ✅ | ✅ | ✅ | ✅ |
| collectOnAgentConnect | inventoryScanner | ✅ | ✅ | ✅ | ✅ |

**Fixed in this audit**

---

### 🟢 Functional Completeness

| Feature | Implemented | Tested |
|---------|-------------|--------|
| Hardware CSV export | ✅ | ✅ |
| Software CSV export | ✅ | ✅ |
| Vulnerabilities CSV export | ✅ | ✅ |
| Offline NVD CVE scan | ✅ | ✅ (stubbed) |
| Assessment panel (multi-location) | ✅ | ✅ |
| Group-wide ratings + mandatory comment | ✅ | ✅ |
| False positive flag/unflag | ✅ | ✅ |
| Vulnerability report (overview + per-location) | ✅ | ✅ |
| Device report (host names, per-location) | ✅ | ✅ |
| CPE coverage % in reports | ✅ | ✅ |
| Scheduled scans (restart-proof) | ✅ | ✅ |
| Notifications (new + repeat-unrated) | ✅ | ✅ |
| Live inventory collection | ✅ | ✅ (stubbed) |
| CPE mapping UI (custom overrides) | ✅ | ✅ |
| Settings tab (live, no restart) | ✅ | ✅ |

---

## Code Quality Metrics

| Metric | Before | After | Change |
|--------|--------|-------|--------|
| Lines of code | 3,527 | 3,061 | -466 (-13%) |
| Functions | ~85 | ~75 | -10 |
| Dead code blocks | 4 | 0 | -4 |
| German comments | 6 | 0 | -6 |
| Test coverage | 78/78 | 78/78 | = |

---

## Recommendations

### Immediate (Done)
1. ✅ Fix `anyCveMaxAgeYears` settings overlay bug
2. ✅ Remove dead CPE API code
3. ✅ Remove dead publisher-based matching code
4. ✅ Translate German comments

### Future Considerations
1. **Add integration tests** with real MeshCentral instance (currently unit tests only)
2. **Consider TypeScript** for better type safety on complex objects (assessments, scan results, report shapes)
3. **Add ESLint/Prettier** for consistent formatting
4. **Document NVD feed download retry logic** in README (currently only in code comments)

---

## Sign-off

**Auditor**: AI (opencode)  
**Date**: 2026-11-06  
**Status**: ✅ APPROVED — All tests pass, security verified, dead code removed, bug fixed.

---

## Appendix: Test Suite Output

```
PASS inventoryscanner.js exists
PASS inventoryscanner.js syntax
PASS assessment.handlebars has an inline <script>
PASS panel script: no stray {{ (only {{shortName}})
PASS panel inline script syntax
PASS valid JSON: inventoryscanner\config.json
PASS valid JSON: package.json
PASS render('assessment') has exactly views/assessment.handlebars
PASS render('report') has exactly views/report.handlebars
PASS render('deviceReport') has exactly views/deviceReport.handlebars
PASS view assessment.handlebars is used by a render call
PASS view deviceReport.handlebars is used by a render call
PASS view report.handlebars is used by a render call

check: OK
PASS report: no error
PASS report: locations array sorted by name
PASS report: locationCount
PASS report: HQ occurrences (2 devices x 3 CVEs)
PASS report: manual rating overrides NVD severity in counting
PASS report: finding devices are host names
PASS report: flagged occurrences excluded but counted as FP
PASS report: flagged finding effectiveSeverity
PASS report: totals 10 findings / 2 FP / 3 unique
PASS report: rname preferred, name fallback
PASS report: coverage 12 programs, 8 assessable (67%)
PASS report: internal findingsById removed
PASS scan: 3 unique findings
PASS scan: partly flagged => mixed, anyFlagged
PASS scan: fully unrated => NOT mixed, no assessment
PASS scan: partly rated => mixed
PASS scan: meshes resolved by name
PASS route save_assessment: stores for all meshIds
PASS route flag: succeeds with NO comment
PASS route save: empty comment still rejected
PASS route unflag: removes flags for all meshes
PASS validation: colon-bearing meshId rejected (key poisoning)
PASS validation: bogus cveId rejected
PASS WINDOWS-UPDATES is flaggable/rateable
PASS route scan: multi-mesh json contract
PASS route report: renders report with locations
PASS route deviceReport: renders deviceReport
PASS route show: renders assessment, deleted meshes hidden
PASS route unknown GET action -> 404
PASS non-admin GET -> 401
PASS non-admin POST -> 401
PASS export: CSV body with BOM + vulns columns
PASS export: attachment filename
PASS export hardware: header line
PASS export: invalid type -> 400
PASS export: default type = vulns
PASS get_cpe_table: built-in rows visible
PASS get_cpe_table: custom rows visible
PASS delete_cpe_table removes custom entry
PASS built-in cannot be deleted via API
PASS csv: built
PASS csv: Comment directly after Manual Rating
PASS csv: flagged WINDOWS-UPDATES shows false positive
PASS longTimeout: first chunk clamped to 32-bit max
PASS longTimeout: remainder as second chunk
PASS longTimeout: fires exactly once after total elapsed
PASS longTimeout: short path = single setTimeout
PASS scheduleScans: restart-proof residual delay (~20 days)
PASS scheduleScans: no prior scan -> baseline run ~1 min after start
PASS notify: single dispatch with notify type
PASS notify repeat mode: old unrated finding re-listed as open
PASS notify repeat mode: appeared finding marked new
PASS notify: rated finding never repeated
PASS notify: below threshold excluded
PASS notify: lastScan updated
PASS notify once mode: no open entries
PASS nvd status: no feed files -> lastUpdate=null ("not downloaded")
PASS nvd status: feeds on disk -> real timestamp (restart-proof)
PASS loadScans: restores lastScan from newest snapshot
PASS overlay: file beats config.json, untouched keys come from config.json
PASS overlay: without file, config.json applies
PASS save_settings: returns effective settings
PASS save_settings: persisted to file
PASS save_settings: bumped timer generation + rescheduled
PASS get_settings: source marking file vs config.json
PASS revert_setting: falls back to config.json value
PASS save_settings: rejects non-numeric interval
PASS save_settings: rejects invalid severity
PASS timers: stale chain discarded after generation bump
PASS timers: current chain runs
PASS collector: per-cycle effective interval (7 min)
PASS collector: interval 0 stops the chain

test-plugin: ALL PASSED
PASS assessment (data) renders (51234 chars)
PASS assessment (empty) renders (50932 chars)
PASS report (data) renders (11812 chars)
PASS report (empty) renders (8483 chars)
PASS deviceReport (data) renders (9128 chars)
PASS deviceReport (empty) renders (7019 chars)
PASS report escapes location names
PASS report escapes comments
PASS device report shows host names, not given names

test-views: ALL PASSED
```

---

# Audit 2 - 2026-11-11 - Independent full audit of v3.0.0 (result: v3.0.1)

**Repository**: meshcentral-inventoryscanner  
**Version audited**: 3.0.0 -> fixes released as **3.0.1**  
**Date**: 2026-11-11  
**Auditor**: AI (opencode), model: Claude Opus 5.5
**Scope**: server code (`inventoryscanner.js`, 4,933 lines), all three views incl. the panel script, the PowerShell
scripts sent to agents, the update/uninstall paths, `cpe-table.json`, the test suite (`tools/`), README, AGENTS.md,
SECURITY.md, CONTRIBUTING.md. Also: re-check of every statement of audit 1.

## Method

Nothing was taken on trust - not the plugin's own tests, not AGENTS.md ("verified" claims), not audit 1.

1. **Line-by-line review** of the complete server code, the panel script and both report views.
2. **Upstream verification** against the current MeshCentral source (master, v1.3.1, fetched 2026-11-11):
   `webserver.js` (pluginadmin routes, session cookie, security headers, `routeAgentCommand`), `pluginHandler.js`
   (installer, upgrade, remove, hook dispatch), `meshuser.js` (`uicustomevent`, `software`), `meshagent.js`,
   `agents/meshcore.js` (`runcommands`, `console`, `software`, `winupdates`) and the git history of meshcore.js.
3. **Real execution on Windows 11 with winget 1.29.380**: the generated PowerShell scripts were parsed with the
   PowerShell parser AND executed (dry run; uninstall against a non-existent package id - nothing was changed on
   the machine). Every winget option used by the plugin was checked against `winget <cmd> --help`.
4. **NVD verification** of every `vendor:product` pair in `cpe-table.json` with the NVD CVE API 2.0
   (`virtualMatchString`), plus keyword searches to find the real names; an end-to-end check fed real NVD CVE
   records into the plugin's own indexer and scanner.
5. **Simulation of the real MeshCentral installer flow** for upgrades (cached `require`, new instance, `server_startup`).
6. **Test-suite review**: what the tests assert, what they miss, and whether all steps actually run.

## Summary

| Severity | Count | Fixed in 3.0.1 |
|---|---|---|
| High | 5 | 5 |
| Medium | 7 | 7 |
| Low | 5 | 5 |
| Documentation / text | 12 | 12 |

`npm test`: before 233 assertions (all green), after **261 assertions, 55 steps, all green** + check.js + view tests.
`npm audit`: 0 vulnerabilities (only dev dependency: handlebars 4.7.10).

The most important outcome: **three functions of the winget updater did not work as documented although every test
was green** - the tests asserted the shape of the generated text, never what winget does with it.

## Findings

### High

**H1 - "Uninstall everywhere" never uninstalled anything** (agent / delete path)  
`wgBuildScript` passed `--accept-package-agreements` to `winget uninstall`. That option does not exist for
`uninstall` (`winget uninstall --help`); winget aborts with *"Argument name was not recognized"*, exit
`0x8A150002`. Verified on the audit machine. Every package uninstall since v3.0.0 therefore ended as `failed`.  
*Fix*: option removed; a test asserts it is absent from the uninstall line and still present for `upgrade`.

**H2 - winget found through PATH was never used** (agent)  
The lookup read `.FullName` of the `Get-Command` result. `Get-Command winget` returns an `ApplicationInfo`, whose
location is in `.Path`; `.FullName` is empty (verified). Without an App Paths entry (the audit machine has none)
the script reported `winget:false`.  
*Fix*: `.Path` is used (`.FullName` as fallback); the admin-only WindowsApps package folder is tried before PATH.

**H3 - Many updates were silently skipped** (agent / update path)  
The parser for `winget list --upgrade-available` required at least two spaces between columns. winget pads to fixed
column widths, so a cell that fills its column is followed by **one** space. On the audit machine 5 of 13 updates
were dropped: Microsoft OneDrive, both VC++ redistributables, .NET Desktop Runtime and TortoiseSVN (`< 1.15...`
version). Those packages were never updated and never shown in the dry run.  
*Fix*: column start positions are taken from the header line (language independent), every row is validated, the
old regex stays as fallback, parsing stops at the footer. A test runs the real PowerShell parser block against the
real winget table (13/13 rows).

**H4 - Client transcript written by SYSTEM into user-writable folders** (agent, OWASP A01/A04, CWE-379/59)  
Fallbacks were `C:\ProgramData\invscanner-winget.log` and `%TEMP%`. Standard users can create files in
`C:\ProgramData` (ACL `BUILTIN\Users: Write`, verified). A file or link prepared there by a local user would be
written to by a SYSTEM process.  
*Fix*: only the agent folder or `%ProgramData%\InventoryScanner`, created with a protected ACL (SYSTEM +
Administrators, inheritance off); an existing folder with a different owner or a reparse point is refused, as is a
log file that is a reparse point. No safe folder -> no transcript, the update still runs. Verified on the machine:
folder created with exactly these two ACEs.

**H5 - Plugin upgrade without restart did not load the new code** (update path)  
The installer re-requires the plugin; Node returns the cached old module and the installer creates a new instance
from it. Each instance read its version from `config.json` on disk, so the new instance of the old code reported
the **new** version and the hot-reload check never triggered. Reproduced with a simulation of
`pluginHandler.installPlugin`. The existing test set the version by hand and therefore could not see this.  
*Fix*: the code version is read once at module load (`MODULE_CODE_VERSION`). Instances replaced by the installer
now stop their own timer chains (process-wide instance generation, `obj.timerValid`); before, two instances could
run scheduled scans, collections and winget sweeps in parallel. New test reproduces the real installer flow.

### Medium

**M1 - Cross-site requests could trigger state-changing actions** (OWASP A01, CWE-352)  
`pluginadmin.ashx` is authenticated by session cookie only, there is no CSRF token (verified in webserver.js). The
cookie defaults to `SameSite=lax`, which blocks cross-site POSTs - but `sessionsamesite` is a server option and can
be set to `none`. Then a foreign page could have started winget runs (incl. uninstall) in an admin's name.  
*Fix*: every POST must carry `X-InvScanner-Request: 1` (sent only by the panel's `fetch`; a foreign page cannot add
a custom header without a CORS preflight, which MeshCentral never permits), else 403.

**M2 - Multi-tenant servers: sub-domain admins saw all tenants** (OWASP A01)  
The gate was `siteadmin === 0xFFFFFFFF` only, but sub-domain admins have that value too, and the plugin reads all
devices of all domains (and stores ratings/settings server-wide).  
*Fix*: `obj.isAuthorizedAdmin` additionally requires `user.domain === ''` (default domain). Single-domain servers
are unaffected.

**M3 - Toolbar export had no permission check** (OWASP A01)  
MeshCentral calls `uiCustomEvent` of every plugin for every `uicustomevent` of any logged-in user and does not
rights-check the top-level `selectedDevices` (verified in meshuser.js). The plugin trusted both; any user could
have received hardware/software/CVE CSV data of arbitrary node ids. AGENTS.md wrongly stated the list was
"already rights-validated".  
*Fix*: `isAuthorizedAdmin(myparent.user)` check, only well-formed and unique node ids are looked up.

**M4 - Inventory collection breaks with current agents** (agent)  
MeshCentral commit `cdc9582ada` (2026-11-09) makes agents refuse `software` commands that carry no numeric
`rights` field. The plugin sent none -> every new agent answers `Denied`, and (see M5) the stored lists were then
overwritten with empty ones.  
*Fix*: the request carries `rights: 8` (the least value that permits the inventory read; uninstall types stay
refused by the agent). The pending flag now also expires after 2 minutes.

**M5 - Error answers wiped good inventories; foreign replies were stored** (data integrity)  
Any reply while a request was pending was stored, also replies addressed to an admin's Software tab and error
answers (`{"error":...}`) - the latter replaced the list with an empty one ("not collected" looks like "nothing
installed"). Our own replies were also broadcast to every user session with rights on the node.  
*Fix*: only session-less replies are ours (the plugin sends no sessionid; the agent echoes it); they are consumed.
Error answers keep the last good list. Lists are capped at 20,000 entries.

**M6 - Winget hook could take over other sessions' output** (agent routing)  
While a run was pending, any `runcommands` reply or console text of the node was treated as ours - also those of an
admin's own session.  
*Fix*: foreign session ids are never consumed; console text is buffered only when session-less (that is how the
agent echoes runcommands output, verified in meshcore.js) or on our own session.

**M7 - Wrong or missing NVD names in the mapping table: programs were silently never checked**  
Every pair was queried against the NVD. Wrong, with 0 CVEs: `notepad++` (the feeds store `notepad\+\+`; verified
end-to-end: 0 -> 14 CVEs for an old version), `sumrapdf` (-> `sumatrapdfreader`, 0 -> 13), `sourceforge:keepass`
(-> `keepass:keepass`), `filezilla_project:filezilla` (-> `filezilla-project:filezilla_client` / `_server`),
`audacity` (-> `audacityteam`), `electron` (-> `electronjs`), `securepoint:securepoint` (-> `openvpn-client`),
`microsoft:powerbi` (-> only *Power BI Report Server* has CVEs). Removed because no NVD product exists:
`google:chromium`, `pcvisit:pcvisit`. Publisher map: `securepoint -> secpoint` and
`document foundation -> documentfoundation` (both vendors do not exist in the dictionary) corrected.
Remaining zero-hit pair: `microsoft:edge_webview2` (no NVD entry; WebView2 CVEs are filed under Edge/`edge_chromium`).
Kept deliberately so the runtime is not reported with browser CVEs; it shows as "no CVE for edge_webview2" -
accepted limitation, listed under remaining risks.  
*Fix*: `cpe-table.json` and the built-in seed corrected; tests pin the verified names.

### Low

**L1 - Regex denial of service through the mapping table** (OWASP A08, CWE-1333) - remote table and custom
entries were compiled without any check; one catastrophic-backtracking pattern would stall the server on every
scan. *Fix*: `isSafeTableRegex` rejects nested quantifiers and backreferences (all 68 shipped entries pass).

**L2 - `WINGET_MAX_DEVICES` undefined** - `slice(0, undefined)` happened to work. *Fix*: constant defined.

**L3 - Unvalidated mesh ids in the scan query and finding id in unflag** - harmless today (lookup only / `delete`
of a flagged key) but inconsistent with every other route. *Fix*: same validation as the write paths.

**L4 - Relative redirect resolution of the table download** was done by string concatenation. *Fix*: `new URL()`.

**L5 - Side-by-side runtimes collapsed** - VC++ 2008 + 2015 and .NET 8 + 10 were merged into one row by the
pruning step because the side-by-side list used other tokens than the mapping produces (`.net`,
`visual_c\+\+`); the older runtime was never scanned. *Fix*: tokens added, test added.

### Documentation, texts, language

| # | File | Problem | Fix |
|---|------|---------|-----|
| D1 | README | "site-administr rights" | corrected |
| D2 | README | "only outbound requests go to nvd.nist.gov (feeds and the mapping table)" - the table comes from raw.githubusercontent.com | corrected (also in requirements and feature list) |
| D3 | README | "nothing happens until you turn it on and tick a group" - manual runs work without both | clarified: applies to automatic runs |
| D4 | README | uninstall instructions: MeshCentral already deletes the plugin folder | corrected, client leftovers named |
| D5 | Panel | "plugin v3.0.0 · plugin v3.0.0" shown twice | once |
| D6 | Panel | Updates tab text and two confirm dialogs said "in-scope" for manual runs that cover every non-excluded device | corrected |
| D7 | AGENTS.md | two broken sentences (version normalization, pageTitle/Handlebars) | rewritten |
| D8 | AGENTS.md | wrong facts: WindowsApps "not enumerable", ProgramData/TEMP fallback, selectedDevices "rights-validated", revert key list incomplete, 233 assertions | corrected |
| D9 | SECURITY.md | supported version "1.0.x", "NVD CPE dictionary API queries" (removed code) | rewritten |
| D10 | inventoryscanner.js | German comments ("Produkte", "bekannte Tools", "Kollaboration", "Platinen"), typo "distrol", mojibake in a comment | translated / fixed; the file is now pure ASCII |
| D11 | inventoryscanner.js | doc comments describing an obsolete transport (type 2, UTF-16, "line-interactive") | corrected |
| D12 | package.json | version 1.0.0 | 3.0.1 |

## Test suite review

| Problem | Effect | Fix |
|---|---|---|
| The runner sat in the middle of `test-plugin.js`; the last steps ran only because an earlier step happened to be asynchronous | a change to that step would silently skip tests | runner moved to the end, prints the number of registered steps |
| Script tests only compared text (`indexOf`) | H1, H2, H3 were invisible | PowerShell parser block is now executed against a real winget table; CLI options pinned |
| Upgrade test set `PLUGIN_VERSION` by hand | H5 invisible | real installer flow simulated |
| No test for the toolbar permission, foreign agent replies, error answers, origin header, sub-domain admin | M1-M6 invisible | 28 new assertions, 2 rewritten |
| Mapping table never compared with NVD | M7 invisible | verified names pinned in tests (NVD itself cannot be queried offline) |
| Two tests asserted the unsafe ProgramData/TEMP fallback as correct | contract change | rewritten to assert the protected folder |

Not covered by automated tests (cannot be without a live system): a real MeshCentral server and real agents.
The agent-side parts were verified by executing the generated scripts on Windows 11 as described above.

## Re-check of audit 1

| Audit 1 statement | Result of audit 2 |
|---|---|
| anyCveMaxAgeYears reads the settings overlay | confirmed |
| CPE API code removed, "curated table only" | removed: confirmed. "Curated only" is no longer true - automatic product matching was added later (v2.x), documented in AGENTS.md |
| German comments translated | not complete - 5 German comments remained (D10) |
| "Security issues: 0, all verified secure" | not tenable for 3.0.0: M1-M3 and H4 are access-control/agent-side issues in code that partly did not exist yet in audit 1; M1 and M3 already existed then |
| "Rights come from MeshCentral's own checks" for device selections | wrong (M3) |
| Test count 78/78 | historic; now 261 + 14 + 9 |

## OWASP Top 10 (2021) - status after 3.0.1

| Category | Status |
|---|---|
| A01 Broken Access Control | fixed: M1, M2, M3; every route + hook gated |
| A02 Cryptographic Failures | n/a (no secrets stored; HTTPS for all downloads) |
| A03 Injection | OK: ids whitelisted before reaching PowerShell, CSV formula prefix, escaped HTML output (re-verified) |
| A04 Insecure Design | fixed: H4 (privileged writes into user-writable folders) |
| A05 Security Misconfiguration | OK: MeshCentral's middleware sets CSP, X-Frame-Options, nosniff for plugin pages (verified) |
| A06 Vulnerable Components | OK: no runtime dependencies; `npm audit` clean |
| A07 Identification & Authentication | delegated to MeshCentral session; plugin adds no own auth |
| A08 Software & Data Integrity | improved: L1 regex check, https-only table with size cap; NVD `.meta` mismatch remains a warning by design |
| A09 Logging & Monitoring | OK: winget runs logged server-side and as device events; ratings carry user and timestamp |
| A10 SSRF | OK: only the admin-configured https table URL is fetched |

## Remaining risks (accepted, documented in SECURITY.md)

- The updater runs as SYSTEM by design; it is off by default and every manual run is confirmed.
- GET pages (reports, CSV) can be opened cross-site like every MeshCentral page; the response cannot be read by
  a foreign page.
- `pluginadmin.ashx` inherits MeshCentral's CSP with `'unsafe-inline'`; XSS protection relies on escaping.
- NVD `.meta` checksum mismatches are logged, not fatal (the plugin's verified NVD behaviour).
- WebView2 has no NVD product of its own; the mapping yields "no CVE" (see M7).

**Sign-off**: all findings fixed in 3.0.1; `npm test` green; generated scripts parse and run on PowerShell 5.1 with
winget 1.29.380.

---

# Audit 3 - 2026-11-14 - Independent full audit of v4.2.2 (result: v4.3.0)

**Version audited**: 4.2.2 -> fixes released as **4.3.0**  
**Date**: 2026-11-14  
**Auditor**: AI (opencode), model: Claude Opus 5.5 (also the auditor of audit 2)  
**Scope**: the complete current tree - entry + 23 `lib/` modules, the three views incl. the panel script, every
script sent to agents (winget, OS update/upgrade Windows + Linux, software deploy Windows + Linux), the test
suite (`tools/`), the GitHub Actions workflow + integration script, README, AGENTS.md, SECURITY.md.

Audit 2 findings were re-checked (section "Re-check of audit 2"), but this audit is **not** limited to them:
everything added since v3.0.1 was reviewed for the first time.

## Method

Nothing was taken on trust - not the plugin's own tests, not the "verified" notes in AGENTS.md, not audit 2.

1. **Line-by-line review** of the server modules, all generated agent scripts and the panel script (the panel
   XSS sweep and the test/CI review were done by two parallel sub-agents and every reported finding was
   re-verified by hand before it was accepted).
2. **Upstream verification** against current MeshCentral `master` (fetched 2026-11-14): `agents/meshcore.js`
   (`runcommands`, `wget`/`serverFetchFile`, `software` rights check), `webserver.js` (`handleAgentDownloadFile`,
   `handleUploadFileBatch`, `getServerFilePath`, the `pluginadmin.ashx` body parser, `obj.subscribe`),
   `meshuser.js` (`HandleEvent` domain filter), `meshcentral.js` (`DispatchEvent`, domain url), `common.js`
   (`IsFilenameValid`), MeshAgent `service-manager.js`.
3. **Real execution on Windows 11 / PowerShell 5.1** (audit machine, standard admin, medium integrity): the deploy
   script end to end through the real `cmd.exe` + gzip/base64 transport (good hash -> runs, wrong hash ->
   `no-file`, nothing executed), PowerShell quote handling, file-lock semantics, ACLs of `C:\Windows\Temp`,
   `msiexec /a` with an open read handle.
4. **Real execution of the Linux deploy script** with busybox-w32 `sh` (good hash / wrong hash), and `sh -n` on
   every generated Linux script (deploy for all 5 types, OS update, OS upgrade). busybox-w32 is not a Linux system:
   `dpkg`/`rpm`/`apt` themselves were NOT executed (see "Not verified").
5. **Targeted reproductions** with throw-away Node scripts against the real modules (library rescan, winget
   auto-queue, command-line length of the transports).
6. **Test-suite / CI review**: fault injection (a step that never calls `next()`, a PowerShell parse error) to
   see whether the suite really fails.

## Summary

| Severity | Count | Fixed in 4.3.0 |
|---|---|---|
| High | 2 | 2 |
| Medium | 4 | 4 |
| Low | 4 | 4 |
| Tests / CI | 7 | 7 |
| Documentation / texts | 10 | 10 |

`npm test` equivalent (run here without npm, see Method): before 419 assertions / 71 steps (2 SKIP), after
**431 assertions / 72 steps, 0 FAIL, 0 SKIP** (with a POSIX shell present) + `check.js` OK + 11 view checks OK.
Handlebars 4.7.10 and its 5 dependencies were installed from the `package-lock.json` URLs and verified against
the lockfile integrity hashes.

## Findings

### High

**A1 - Script injection into the SYSTEM deploy script via typographic quotes** (agent, OWASP A03, CWE-94)  
`swBuildWindowsScript` embedded the file name and the command-line arguments in PowerShell single-quoted
literals and doubled only the ASCII `'`. PowerShell treats `U+2018 U+2019 U+201A U+201B` as single quotes as
well. Verified on PS 5.1: `$invName = 'abc’; Write-Output INJECTED; ‘'` runs `Write-Output INJECTED`. File names
come from an upload (`swSanitizeName` keeps those characters) or from a MeshCentral **Server Files** folder of a
device group - and those folders are writable by every user with the group's server-files right, not only by site
admins. A crafted file name therefore turned into code that runs as SYSTEM on every target of the task, beyond
what the admin selected.  
*Fix*: `obj.swPsQuote` doubles all five quote characters. Verified: the same hostile name now stays data through
the real `cmd.exe` transport (`"name":"who's; Write-Output INJ; 'x.exe"`, no injected output). The winget script
is not affected (its ids pass `WINGET_ID_RE`, ASCII only). Test: `audit3 A1` (text + real PowerShell run).

**A2 - Time-of-check/time-of-use between SHA-256 check and execution** (agent, CWE-367)  
Both deploy scripts hashed the downloaded file in a shared temp folder (`C:\Windows\Temp`, `/var/tmp`) and then
executed it **by path**. Verified: a standard user can create files in `C:\Windows\Temp` (ACL: create allowed,
listing denied); `/var/tmp` is world-writable (sticky bit). The staged name is not secret on the device (it is in
the agent's command line / `wget` message). Between the hash check and `Start-Process` / `sh "$F"` the file could
be replaced, so the "SHA-256 verified before execution" guarantee did not hold.  
*Fix (Windows)*: the file is opened with `FileShare.Read`, hashed **through that handle**
(`Get-FileHash -InputStream`) and the handle stays open until the installer has finished - write/rename/delete are
then impossible (verified: all three refused while the handle is open, while `Start-Process` and `msiexec` still
run the file). *Fix (Linux)*: a matching download is copied into a fresh `mktemp -d` directory (mode 700,
`umask 077`), hashed **again** there, and only that private copy is executed; symlinked downloads are refused.
Verified with busybox `sh`: good hash -> `ok`, package ran with its arguments; wrong hash -> `no-file`, the package
did not run; download and private folder are removed in both cases. Test: `audit3 A2 win/linux`.

### Medium

**A3 - Automatic winget updates ran without the documented group opt-in, also on Linux** (agent)  
`wgQueueNode` (agent-connect hook) started a batch for EVERY connecting device whenever the switch was on but no
group was ticked - contrary to the README/AGENTS.md rule "empty updateMeshes means nothing runs" - and without the
Windows check, so Linux agents received a cmd/PowerShell script. With groups ticked the hook never worked: it read
`node.meshid` from the `db.Get` result, which is an **array** (verified in db.js), so no device ever matched.
Reproduced with the real module (Linux node received `runcommands`; Windows node in a ticked group received
nothing).  
*Fix*: no `updateMeshes` -> `false`; the document is `docs[0]`; non-Windows nodes and a running OS batch are
skipped. Test: `audit3 A3` (three cases).

**A4 - Every "Rescan" re-imported the whole library and renamed the display names** (server)  
`swRescanLibraryHandler` built its "already indexed" set from `obj.swFiles[id].id`, a field that does not exist,
so every stored `<id>.<ext>` file looked new: on each rescan it was hashed again, renamed to a new id, its display
name became `<oldid>.exe`, and the old entry was dropped. Tasks referencing the old id then failed. Reproduced:
second rescan `added 1, removed 1`, name `53f1a08c5b9e.exe`. The existing test only ran one rescan.  
*Fix*: the set is built from the map key. Test: `audit3 A4` (two rescans, same id and name).

**A5 - Notifications reached sub-domain administrators** (server, OWASP A01)  
Scan, NVD-stale and deploy toasts were dispatched to `['*']` without a `domain`. `webserver.js obj.subscribe`
subscribes every user with `siteadmin == 0xFFFFFFFF` (also sub-domain admins) to `'*'`, and `meshuser.js
HandleEvent` only filters by `event.domain` when it is set. On multi-tenant servers, tenant admins therefore saw
group names and CVE ids of other tenants - the plugin itself refuses them since v3.0.1.  
*Fix*: `domain: ''` on all three server notifications, the node domain on device events. Test: `audit3 A5`.

**A6 - Tests could pass with steps that never ran** (test infrastructure)  
A step whose callback never fires ended `test-plugin.js` with **exit 0** and no summary (verified by injection) -
every later step silently skipped, CI green. *Fix*: per-step 120 s watchdog (exit 1, verified: `FAIL runner: step
72 did not call next()`), plus an exit guard comparing completed and registered steps.

### Low

| # | Finding | Fix |
|---|---|---|
| A7 | PowerShell parse/runtime errors in the three PowerShell-based tests were reported as `SKIP ... PowerShell not available` (`execFileSync` throws on any non-zero exit) | `runPs()` returns null ONLY for ENOENT; everything else is a FAIL |
| A8 | The "no module-level state" guard checked 4-space-indented locals inside `attach` and missed real column-0 state | new column-0 check (only `const x = require(...)` allowed), the old check kept as documented |
| A9 | `tools/check.js` syntax-checked only the FIRST `<script>` of the panel | all script blocks of all views; report views must contain none |
| A10 | Upload retry counter in the panel was incremented twice per error (`retries++` on two lines) -> 3 instead of 6 retries; `r.variedVersions.length` without a null guard | fixed |

### Tests / CI (workflow `.github/workflows/meshcentral-integration.yml`)

| # | Finding | Fix |
|---|---|---|
| C1 | `permissions: actions: write` for every job incl. pull requests - not needed (actions/cache uses the runner token) | removed, `contents: read` only |
| C2 | actions pinned by mutable tag (`@v4`) | pinned to commit SHAs (resolved via the GitHub API 2026-11-14), tag kept as comment |
| C3 | `${{ steps.rel.outputs.tag }}` (data from api.github.com) pasted into a `run:` script | passed as `env:` |
| C4 | scheduled run skipped when the MeshCentral tag was verified once, even after plugin changes | cache key = release tag **+ commit sha** |
| C5 | `test-views.js` exited 0 ("SKIP") when handlebars was missing, also in CI | FAIL when `CI` is set |
| C6 | `sh -n` and PowerShell checks only run where the shell exists; on the Linux runner the PowerShell parser checks are skipped | documented (not fixable without a Windows runner) |
| C7 | the live CI run uses the `plugins.list` dev loader: the web-installer path (ZIP, DB record, hot swap) is never exercised live | documented as known gap |

### Documentation, texts

| # | Where | Problem | Fix |
|---|---|---|---|
| T1 | panel, Settings hint | "Updates tab, OS section" - the OS engine has its own tab since v4.1.0 | "OS Updates tab" |
| T2 | panel, Deploy info + upload fallback list | listed MSI/EXE/DEB/RPM/shell only; MSP and BIN are accepted | all seven types |
| T3 | panel, Deploy info | promised "ok - reboot pending" text that was never rendered (only a colour) | the device row now shows it |
| T4 | panel, args placeholder | "passed to the program for other types" - .deb/.rpm args go to dpkg/rpm | corrected |
| T5 | panel, library delete confirm | "Running tasks keep their staged copy" - the server refuses the delete instead | corrected |
| T6 | panel, retry confirm | did not say that cancelled/unsupported devices are retried as well | corrected |
| T7 | panel, Updates info | contradicted the device-list hint about excluded devices | aligned |
| T8 | panel | wgMsg/osMsg/swMsg/settingsMsg had no success/error styling | CSS added |
| T9 | AGENTS.md / SECURITY.md / README | deploy TOCTOU guarantee, auto-update opt-in, notification scope, test counts | updated |
| T10 | inventoryscanner.js header | audit list ended at audit 2 | updated |

No German or other non-English text and no spelling mistakes were found in code, views or docs (British spellings
such as "honoured" are consistent and were left).

## Verified and found correct (selection)

- Access control: every GET/POST route and the toolbar hook use `isAuthorizedAdmin` (full site admin, default
  domain); every POST needs `X-InvScanner-Request: 1` (the panel's single `post()` helper sends it). MeshCentral
  never answers CORS preflights (no `Access-Control-Allow-*` anywhere in webserver.js, re-verified).
- Panel XSS: every `innerHTML` sink passes `esc()` (escapes `& < > " '`); the only data-built `href` is regex-gated
  to `CVE-\d{4}-\d{4,}`; report views use only `{{ }}`.
- Server-side paths: upload ids, file ids, task ids validated before any lookup or `path.join`; Server Files paths
  resolved under `<filespath>/domain[-x]/mesh-<group>` with a `path.resolve` prefix check; staged names
  server-generated from a CSPRNG; `agentdownload.ashx` serves only `<filespath>/tmp` with a 5-minute node-bound
  cookie (re-verified upstream).
- Agent transport: wget shape and `servertlshash` match upstream `handleUploadFileBatch`; runcommands types 1/3
  match meshcore.js; one session per agent is honoured by all three pumps; the deploy (2.5 KB) and OS (3.0 KB)
  command lines stay far below cmd.exe's 8191-character line limit (limit re-verified here: an 8,300-character
  line is refused with "command line too long"); the winget line can exceed it with a very long ignore list
  (see remaining risks).
- OS scripts: TargetReleaseVersion policy restored, wuauserv restarted around the search (issue #1), never a
  reboot; Linux scripts read `/dev/null`, refuse a symlinked log.
- CSV formula neutralization, regex-DoS guard (all 103 table regexes pass), https-only downloads with size caps,
  settings validation incl. URL patterns.

## OWASP Top 10 (2021) - status after 4.3.0

| Category | Status |
|---|---|
| A01 Broken Access Control | OK; A5 fixed (cross-tenant notifications) |
| A02 Cryptographic Failures | OK: SHA-256 end to end, CSPRNG names, TLS pinned to the control-channel certificate for wget |
| A03 Injection | A1 fixed (typographic quotes); all other script values regex-cleaned or fully quoted (re-verified) |
| A04 Insecure Design | A2 fixed (check-then-use); A3 fixed (automatic runs without opt-in) |
| A05 Security Misconfiguration | OK (MeshCentral headers); CI least privilege (C1) |
| A06 Vulnerable Components | OK: no runtime dependencies; dev deps integrity-verified; actions SHA-pinned (C2) |
| A07 Identification & Authentication | delegated to MeshCentral |
| A08 Software & Data Integrity | improved by A2 and C2/C4; NVD `.meta` mismatch stays a warning by design |
| A09 Logging & Monitoring | OK: deploy/winget/OS logs, device events, creator recorded per task |
| A10 SSRF | OK: only admin-configured https URLs (table, lifecycle) and the fixed NVD host |

## Not verified (honest limits of this audit)

- No real Linux machine: `dpkg -i`, `rpm -Uvh`, `apt-get`, `do-release-upgrade` were not executed; the Linux scripts
  were syntax-checked and the deploy flow executed with busybox-w32 `sh` only.
- No real MeshCentral agent was attached during this audit; agent behaviour was verified against upstream source.
  The CI workflow (live server + Linux agent + `.sh` deploy) could not be run here.
- Windows Update COM and the TargetReleaseVersion upgrade were not executed (they would change the audit machine).

## Remaining risks (accepted, documented in SECURITY.md)

- Deploy and the updaters run as SYSTEM/root by design; a site admin can run any installer.
- **Server Files as a deploy source**: those folders can be filled by any user with the server-files right of the
  group. A site admin who deploys such a file runs *that user's* file as SYSTEM - the content check is the admin's
  job (A1 removed the name-based escalation, not this trust decision). Documented in SECURITY.md.
- winget: an ignore list of more than roughly 150-200 entries makes the one-line cmd transport exceed cmd.exe's
  8191-character limit (measured 8.6 KB at 200, 15.8 KB at 500 random ids; cmd refuses such a line with "command
  line too long", verified). The device run then ends as "no marker in output" - visible, never silent. Keep the
  ignore list short (the UI accepts up to 500).
- The PowerShell parser checks do not run on the Linux CI runner; no automated test executes a script on Windows.
- busybox-w32 used for this audit is not code-signed; it was used only as a local test tool and is not part of the
  repository.

## Re-check of audit 2

| Audit 2 finding | Status in 4.2.2 |
|---|---|
| H1 winget uninstall option | still fixed (no `--accept-package-agreements` on uninstall) |
| H2 winget via PATH `.Path` | still fixed |
| H3 winget table parser | still fixed; its PowerShell test could however report a failure as SKIP (A7, fixed) |
| H4 protected transcript folder | still fixed, now shared by the OS and deploy scripts (`psTranscriptLines`) |
| H5 hot reload | still fixed, also for `lib/` modules |
| M1 request header | still fixed, all new deploy/OS POSTs covered |
| M2 default-domain gate | still fixed for routes - but notifications leaked across domains (A5, fixed) |
| M3 toolbar export rights | still fixed |
| M4/M5 collector rights + error answers | still fixed |
| M6 session ownership | still fixed, extended correctly to `invscanner-os-` / `invscanner-sw-` |
| M7 mapping names | table now the only copy (103 rows), all regexes pass the safety check |
| L1-L5 | still fixed |

**Sign-off**: all findings above fixed in 4.3.0; full suite green locally (431 assertions, 72 steps, 0 SKIP with a
POSIX shell; check.js; view tests). The deploy scripts were executed end to end on Windows 11 (real cmd.exe
transport) and with busybox `sh`.

### Follow-up fixes after audit 3 (v4.3.1)

Two issues found after the 4.3.0 sign-off; fixed in 4.3.1. This is not a separate audit.

**F1 - DLL planting next to the SYSTEM installer** (agent, Windows, CWE-427). Found by the auditor of audit 3 while
re-checking A2. The 4.3.0 fix locked the verified file, but the installer was still *started* from
`C:\Windows\Temp`. Standard users can create files there (verified, see A2). Windows looks for DLLs in the
started program's own folder first, so a DLL with a matching name planted next to `setup.exe` would be loaded by
the installer and run as SYSTEM. The SHA-256 check covers the installer, not its neighbours.  
*Fix*: the verified bytes are copied into a new folder `invsw-run-<guid>`, created in one step with a protected
ACL (SYSTEM + Administrators only, no inheritance). The copy is hashed again through a write-locked handle and
started from that folder, which is also the working directory (`msiexec` gets the same path). A folder that
already existed or does not carry exactly that ACL is refused, the device answers `error` and nothing runs.
Verified on Windows 11: the program really runs from the run folder, and the folder is removed afterwards; when
the copy into the folder fails (reproduced: a test user outside the folder ACL), the device answers `error` with
"nothing was executed". Tests: two text checks plus a real run on Windows (the program writes its own working
directory).

**F2 - CodeQL `js/bad-tag-filter` #3** (`tools/check.js`, test tool only, not shipped behaviour). The extraction
regex did not match end tags such as `</script >`. *Fix*: the end tag accepts `\b[^>]*`, and a new check fails
when the number of opening `<script` tags differs from the number of extracted blocks, so no form of end tag can
hide a block from the syntax checks.
