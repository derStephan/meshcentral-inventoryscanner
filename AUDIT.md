# Audit Reports

This file contains every audit of the plugin in **chronological order**. Each audit is kept unchanged as it was
written; later audits refer back to earlier ones instead of rewriting them.

| # | Date | Auditor / model | Plugin version audited | Result |
|---|------|-----------------|------------------------|--------|
| 1 | 2026-11-06 | AI (opencode), NVIDIA Nemotron 3 550B A55B | 2.x (pre-3.0) | 1 bug fixed, dead code removed |
| 2 | 2026-11-11 | AI (opencode), Claude Opus 5.5 | 3.0.0 | 17 findings, all fixed -> **3.0.1** |

Between audit 1 and audit 2 the plugin grew from ~3,000 to ~4,900 lines (v2.1 - v3.0.0: winget updater with
per-package update/uninstall, remote CPE table, automatic product matching, driver/firmware category, hot reload).
Audit 1 therefore did not cover most of the code that runs on the agents.

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
