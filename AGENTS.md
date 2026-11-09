# AGENTS.md — MeshCentral Inventory & Vulnerability Scanner Plugin

Guide for AI agents working on this repository. Everything stated here was verified against the running code and
the test suite in `tools/`; trust the code and these notes over assumptions.

Repository: https://github.com/derStephan/meshcentral-inventoryscanner

## Repository layout

```
FLAT layout - required by the MeshCentral web installer: it unpacks the repository ZIP into
<datapath>/plugins/inventoryscanner/ after removing exactly ONE top path element, so the plugin files
MUST stay at repository root (never re-nest them in a folder - that silently breaks the installer).

  inventoryscanner.js          server code + browser-exported functions (module.exports.inventoryscanner(parent))
  config.json                  plugin manifest: installer metadata (and MeshCentral-side config file)
  cpe-table.json               THE maintained mapping table: downloaded by running servers, edit = no release needed
  views/assessment.handlebars  admin panel (incl. its inline <script> - the panel logic lives HERE)
  views/report.handlebars      printable vulnerability report (overview + one page per location)
  views/deviceReport.handlebars printable device inventory report (host names, one page per location)
tools/                         self-contained verification for agents (no MeshCentral server needed)
  check.js                     node --check on JS, inline-script extraction check, JSON validity, render-name match
  test-plugin.js               behavioral tests against the real plugin module with mocked MeshCentral
  test-views.js                compiles+renders all three views with Handlebars (needs `npm install`)
  coverage-benchmark.js        read-only mapping audit against the top NVD products by CVE count (run server-side with --nvd <datapath>/nvd)
README.md                      user-facing documentation
package.json                   repo metadata; `npm test` runs tools/check.js + tools/test-plugin.js + tools/test-views.js
```

## What the plugin does

Pure admin tool for MeshCentral (all endpoints gated on full site admin, `user.siteadmin === 0xFFFFFFFF`):

1. **Device-list toolbar CSV exports** (hardware / software) and a **panel-open button** (`assessment`),
   all on the device-list toolbar auto-injected by the exported `onWebUIStartupEnd` browser hook (no server
   config) → `uiCustomEvent(command, myparent)` → CSV pushed over the websocket →
   browser `saveAs()` via the exported `inventoryCsv` function. Whole-inventory CSV downloads additionally exist as
   plain URLs (`action=export&type=...`), linked in the panel top nav and suitable for bookmarks (MeshCentral has no config-driven main-menu links).
2. **Offline CVE scan** against locally cached NVD 2.0 feeds (`<datapath>/nvd/`): curated CPE table + automatic
   evidence matcher (name tokens validated against the NVD product index, publisher -> vendor).
3. **Assessment panel** (`pluginadmin.ashx?pin=inventoryscanner&action=show`): multi-location CVE review, group-wide
   ratings (mandatory comment), false-positive flags (optional comment), filter/sort, CPE Mapping management tab, and a **Settings tab** for
   all scanner/collection options (overrides config.json, applies without restart).
4. **Printable reports** (`action=report`, `action=deviceReport`): overview page + one page per location, with a
   stated **CPE coverage percentage** so findings-only views can't be misread as "all clean".
5. **Scheduled scans + notifications** (server-side Node timers, restart-proof, monthly-capable) with per-group
   severity thresholds and an optional repeat-until-rated mode.

## Verified API facts (do not guess)

Based on official MeshCentral source (`pluginHandler.js`, `webserver.js`, `db.js`, `meshcentral.js`).

- **Plugin entry:** `module.exports.inventoryscanner = function (parent)`; `parent.parent` = meshcentral server
  object; `obj.db = obj.meshServer.db`.
- **Folder/shortName must be alphanumeric only** (`/^[A-Za-z0-9]+$/`, no `_`/`-`), else `pluginadmin.ashx?pin=`
  returns 401. Here: `inventoryscanner`.
- **Web installer (supported install path):** `settings.plugins.enabled=true` is the only required manual
  config. pluginHandler loads plugins from the DB UNLESS `settings.plugins.list` is set - that dev branch
  bypasses the DB loader and UI enable/disable, so the README explicitly forbids `list` for installs.
  The installer validates the root config.json via `isValidConfig` (name, shortName, version, description,
  hasAdminPanel:boolean, homepage, changelogUrl, configUrl, repository.type/.url, meshCentralCompat - all
  required; plus downloadUrl for the ZIP), stores it in the DB (status 0 = disabled), then downloads
  downloadUrl and unpacks into plugins/<shortName>/ with exactly one path element removed (=> flat layout).
  Loading newly enabled plugins needs a server restart. Update detection = refetch configUrl and compare
  the version field (NO tags needed). versionHistoryUrl is intentionally absent: no downgrade picker.
- **`pluginadmin.ashx` GET** → `handleAdminReq(req,res,user)`, `POST` (urlencoded body → `req.body`) →
  `handleAdminPostReq`. Session auth only — the plugin does its own siteadmin gate.
- **Views:** `res.render('<name>', data)` ↔ `views/<name>.handlebars` — **case-sensitive** on Linux.
  Only core Handlebars helpers exist (`each if unless with @index @last @key`); no `Object.keys`, no custom helpers.
- **Device-list buttons:** MeshCentral has no plugin API for buttons and no `mainmenuicons` key (verified
  against upstream `views/default.handlebars`; the only consumed `customui` keys are devicesbarbuttons,
  desktopbuttons, terminalbuttons, filesbuttons). This plugin therefore does NOT rely on customui config:
  the exported browser hook `onWebUIStartupEnd` (client fires `pluginHandler.callHook('onWebUIStartupEnd')`
  once after UI startup) appends its three buttons to the static `<span id="devsCustomUIBar">` slot IF that
  slot is still empty (filled = admin-configured buttons; then no injection, no duplicates). The click
  handler replicates `customUIAction`: `defaultValue.substring(6)` of each checked `.DeviceCheckbox`, sent as
  `{action:'uicustomevent', section:'devicesbarbuttons', element:'0', selectedDevices:[...], logmsg:<type>}`
  on the TOP level (NOT `command.src`). customui-fired buttons without a `selection` field fire with an empty
  list, and `uiCustomEvent` is called on every plugin for every event. `tools/test-plugin.js` simulates the
  whole injection.
- **Browser functions:** listed in `obj.exports`; pluginHandler stringifies them via `Function.toString()` into
  a standalone browser namespace (`obj.<plugin>.<method>`) whose root has NO server properties - exported
  function bodies must therefore never reference `obj.*` (embed literals like the shortName in URLs!).
  Server pushes `{action:'plugin', plugin:'inventoryscanner', method:'inventoryCsv'|'openAssessment', ...}`
  and the front-end calls the exported function. `tools/test-plugin.js` guards this invariant.
- **DB ids:** node `_id` = `node/<domain>/<id>`; sysinfo = `'si' + node._id` (doc under `rec.doc`);
  mesh `_id` = `mesh/<domain>/<name>`.
- **OS fields:** there is **no** `node.os`/`node.platform`. Use `node.osdesc` (display string) and
  `doc.hardware.windows.osinfo.BuildRevision` (Windows build number; `BuildNumber` as fallback).
- **Sysinfo structure** (verified against meshagent.js): hardware lives under `doc.hardware` —
  `identifiers.{cpu_name,gpu_name[],bios_*,board_*,product_name,chassis_*,storage_devices[]}`,
  `windows.memory[]`, `tpm`, `network.dns[]`.
- **Software & Windows updates are NOT in any MeshCentral DB** (meshagent.js has an open TODO for it). The plugin
  runs its own collector: it sends `{action:'software',type:'installedapps'}` and the console command
  `winupdates` (unique `invscanner-*` sessionid) to online agents via `webserver.wsagents[nodeid]`, capturing the
  replies server-side by wrapping `webserver.routeAgentCommand`. Stored per node under
  `<datapath>/plugins/inventoryscanner/data/<nodeid>/{software,windowsupdates}.json`.
  Only Critical/Important pending updates count towards the `WINDOWS-UPDATES` finding.
- **Notifications:** `obj.meshServer.DispatchEvent(['*'], obj, {type:'notify', ...})` — ephemeral browser toast for
  logged-in admins + entry in the server event log. No built-in email.

## Plugin routes & data contracts (current state)

GET `pluginadmin.ashx?pin=inventoryscanner`:

| `action` | Handler | Result |
|---|---|---|
| `show` | `showAssessmentPanel` | renders `assessment` with `{shortName, meshList, lastUpdate, lastScan, scanIntervalHours, totalCves, version}` (version from the manifest beside the plugin file) |
| `scan` | `assessmentScan` | JSON via `scanMultiMeshCves(meshIds)`; `?mesh=<id>,<id>,...` (comma-separated) |
| `report` | `vulnerabilityReport` | renders `report` with `{shortName, report: buildOverallReport(), totalCves, lastUpdate}` |
| `deviceReport` | `deviceReport` | renders `deviceReport`, same data |
| `export` | `exportCsv` | streams a CSV **attachment** for ALL non-deleted nodes (`type=hardware|software|vulns`, default vulns; invalid → 400). UTF-8 BOM, `Content-Disposition: attachment; filename=<Base>_<timestamp>.csv`; built with the same `buildCsvForNodes` as the toolbar exports. Intended for bookmarks and the panel top nav. |

POST body `action=`:

| action | Keys | Notes |
|---|---|---|
| `save_assessment` | `meshId` or `meshIds` (comma list), `cveId`, `assessment`, `comment` | comment **mandatory**; id must match `CVE-\d{4}-\d{4,}` or be `WINDOWS-UPDATES`; mesh ids validated `^mesh/[^:]+$`; comment trimmed, ≤1000 chars, stored **raw** |
| `flag_false_positive` | `meshId(s)`, `cveId`, `comment?` | comment **optional** (empty stays empty); sets `assessment:'UNKNOWN', flagged:true` |
| `unflag_false_positive` | `meshId(s)`, `cveId` | deletes flagged entries for all given meshes |
| `get_cpe_table` | — | `{entries:[{match,vendor,product,source:'built-in'|'remote'|'custom'}], cpeTable:{source,updated,url,enabled,entries}}` |
| `delete_cpe_table` | `match`,`vendor`,`product` | custom entries only (built-ins can be shadowed, not deleted) |
| `add_cpe` | `match`,`vendor`,`product` | regex validated via `new RegExp`; custom wins over built-in |
| `wg_get_config` | — | effective wingetUpdater config + per-key sources + queue state |
| `wg_save_config` | enabled, updateMeshes(csv), excludeNodes(csv), ignorePackages(JSON), pinSync (intervalHours accepted but ignored) | validates EVERYTHING, writes overlay, `rescheduleAll()` |
| `wg_run` | optional `nodeIds`(csv; overrides scope+exclusions), `dry`('true') | manual batch; per-device or dry test runs; {busy} while one runs |
| `wg_status` | — | every non-deleted WINDOWS node (`wgIsWindowsNode`: reported `osdesc` must contain 'windows'; no osdesc yet = kept; phones/Linux hidden). Each row: `host` (rname-first) + `given` (admin name, used for labels/sort); malformed records tolerated |
| `get_log` | `type` = nvd\|winget | whitelisted log tail (last 300 lines) |
| `update_nvd` | — | starts `runNvdUpdate(true)` (background) and answers {started:true} / {alreadyRunning:true}; concurrent runs skip via the `nvdUpdateRunning` flag |
| `get_nvdlog` | — | `{lines:[...last 200 of nvd-download.log], size, file}`; `note` if file missing |
| `get_locations` | — | all non-deleted meshes `{locations:[{id,name}]}` (also feeds the Settings tab group table) |
| `remove_cpe` | `index` | legacy index-based removal |
| `get_settings` | — | `{settings:{...effective...}, sources:{key:'file'|'config.json'|'default', notifyPerGroup:{meshId:src}, revertAllowed:{key:bool}}}` |
| `save_settings` | full form field set (see `saveSettingsHandler`) | validates everything, writes `scanner-settings.json`, runs `rescheduleAll()`, answers with the `get_settings` payload; `reset=true` clears all overrides |
| `revert_setting` | one key of `revertScanIntervalHours`/`revertScanMeshes`/`revertNotifyOnScan`/`revertNotifyThreshold`/`revertNotifyUnratedRepeat`/`revertNotify`/`revertUpdateHours`/`revertAnyCveMaxAgeYears`/`revertAutoProductMatch`/`revertCollectIntervalMinutes`/`revertCollectOnAgentConnect` = 'true' | removes that single override so config.json/default applies again |

Assessments persist in `<datapath>/nvd/assessments.json`, key `"<meshId>:<cveId>"` →
`{meshId, cveId, assessment, comment, lastModified, assessedBy, assessedById, flagged?}`.
Scheduled results in `<datapath>/nvd/scans.json` → `meshId -> {time, cves:[{cve, severity, ...}]}`.
Remote CPE table: repo `cpe-table.json` → fetched when stale at startup and after every NVD download cycle, cached at
`<datapath>/plugins/inventoryscanner/cpe-table.json`. `activeSoftwareTable()` = remote entries when a valid table was
applied, else `SOFTWARE_CPE_TABLE`; custom (UI) entries always first. Entry regexes compile with the `i` flag ONLY;
bad JSON/regex → payload rejected, current table keeps running. Keys: `cpeTableEnabled`/`cpeTableUrl` (Settings tab).

UI-managed scanner settings in `<datapath>/plugins/inventoryscanner/scanner-settings.json` →
`{vulnerabilityScanner:{...}, inventoryScanner:{...}}`, merged over `config.settings` by
`obj.effectiveSectionConfig(section)` (file wins per key). **The plugin never writes config.json.**

**`scan` response shape** (drives the panel JS):
`{ meshes:[{id,name}], cves:[{cve, severity, cvss, description, software, version,
locations:[{meshId,name,devices:[hostnames]}], assessments:{meshId:rec|null}, assessment:rec|null,
mixed:bool, anyFlagged:bool}], flaggedCount, totalCves, lastUpdate }`.
**Unknown installed version:** version strings first pass `normalizeCveVersion`: Debian epochs stripped
  (`1:2.3.4-3ubuntu1` -> `2.3.4`), numeric cores without distro decoration (`22.04.0-1build1` -> `22.04.0`),
  snap/DEB wrapper strings that contain no program version (`1:1snap1-0ubuntu5`) -> `''`. An empty version
  asserts ONLY `kind:'any'` `assessment` is set only when
uniform across ALL affected locations; a fully unrated finding is `mixed:false, assessment:null`.

**`buildOverallReport()` shape** (drives both report views):
`{ generated, totalSystems, totalPrograms, assessablePrograms, notAssessablePrograms, coveragePercent,
totalCves, falsePositiveCves, severityCounts{CRITICAL..UNKNOWN}, uniqueCves, locationCount,
locations:[{ id, name, totalSystems, totalPrograms, assessablePrograms, notAssessablePrograms, coveragePercent,
totalCves, falsePositiveCves, severityCounts, uniqueCves, findings:[{cve, severity, cvss, software, version,
description, assessment, comment, flagged, effectiveSeverity, devices:[hostnames]}], devices:[deviceRec] }],
devices:[deviceRec] }` with `deviceRec = {hostName, name, group, os, programs, programsAssessable,
programsNotAssessable, cveCount, critical..unknown}`. `locations` is an **array** (views iterate it with
`{{@index}}` anchors); `findingsById`/`uniqueCveIds` internals: `findingsById` is deleted before returning.

Counting semantics: `totalCves`/`severityCounts` = device×CVE **occurrences**; a false-positive-flagged occurrence
moves to `falsePositiveCves` and is excluded from severity counting; a group rating **overrides** the NVD severity
for counting (`effectiveSeverity`); `WINDOWS-UPDATES` occurrences count like normal findings.

## Panel behavior (views/assessment.handlebars inline JS)

- Auto-scan on load; location selection = floating DIV (checkbox per mesh + "All locations"), persisted in
  `localStorage` key `invscanner_locations`; toggle button fixed top-right.
- Sortable columns (`data-key`, click toggles asc/desc, default cvss desc) + filters (text, effective severity,
  status: CVE/false positive/rated/unrated).
- Save/flag/unflag post the **meshIds of all affected selected locations** in one request; after success the row
  state is patched client-side (no rescan).
- All dynamic values rendered via `esc()` (comments stored raw → escape at output; never double-escape).
- The page heading (`h1#pageTitle`) follows the active tab (titles map in the tab click handler); the (Handlebars would consume it) except the intended `'{{shortName}}'` token.
  `tools/check.js` enforces both this and `node --check` on the extracted script.

- Settings tab: fetches `get_settings` + `get_locations` on load; each numeric field carries a source select
  ("set in plugin settings" / "from config.json" / "built-in default") offering `revert_setting` when overridden;
  Save posts the full field set, "Reset all" posts `reset=true`. The group table is filled client-side from
  `get_locations`; all-checked or none-checked is sent as an empty list = "all groups".

## Software-list pruning (verified)

- `obj.getStoredSoftware` returns `pruneSuperseded(list)`: rows are grouped by resolved vendor|product
  (curated table -> auto matcher, else version/arch/locale-stripped name token + publisher-vendor map,
  needs no NVD index) and by version group: default the WHOLE product is one group (newest wins -
  fixes Firefox-2008-CVE noise from registry leftovers); `jre/jdk/java/net_framework/dotnet/vc++` key
  on major, `python` on major.minor (real side-by-side installs). Unversioned rows never supersede.

## Winget auto-update engine (verified contracts)

- Transport (verified in MeshCentral `agents/meshcore.js`): the server sends
  `{action:'runcommands', type:2, cmds:<powershell>, runAsUser:0, reply:true, sessionid, responseid}`
  (type 2 = PowerShell via stdin, runAsUser 0 = the agent's SYSTEM context); the agent answers
  `{action:'msg', type:'runcommands', result, sessionid, responseid}`, captured by the same
  `routeAgentCommand` hook as the inventory collector. Sessions are identified by the
  `invscanner-wg-<node>` sessionid prefix; foreign sessions are never consumed.
- The per-device PowerShell script (single round trip): existence probe (`Get-Command winget`),
  `winget list --upgrade-available --accept-source-agreements --disable-interactivity`, a strict regex
  per table line (name / dotted id / version / available / source), skip-if-ignored (case-insensitive id
  match), `(& $wg) upgrade --id <id> --exact --silent --accept-package-agreements --accept-source-agreements
  --disable-interactivity` per remaining package, best-effort `winget pin add --id <id> --installed --exact`
  for ignore entries (pinSync), and ONE answer line `@@INVWUP@@{json}`. `ConvertTo-Json` unwraps
  single-element arrays - the parser rewraps them. Anything unparsable is recorded as an error, never as
  a silent success.
- Automatic scheduling is two-stage, no interval: `wgNodeDue` = never ran OR last run on an earlier
  calendar day OR >=24 h old; the agent-connect hook queues a due single device (after `staggerDelay`),
  `wgSweepOnce` (hourly, gen-guarded) catches devices whose connection outlived the day boundary.
  Per-device manual/dry runs pass explicit ids to `wgStartBatch(reason, done, nodeids, dry)`.
  `wgTargetNodes` applies the same Windows rule (no agent traffic to phones/Linux ever).
  Package states: `ok`/`failed`/`skipped-ignored`/`skipped-noversion`/`dry-run` (dry JSON carries `dry:true`).
  Watchdogs: 2h real batches, 10min dry runs (`WINGET_DRY_TIMEOUT_MS`, chosen via `wgBatchDry`).
  `msg/console` packets carrying an `invscanner-wg-` sessionid (e.g. the agent's 'already busy' note,
  meshcore.js breaks WITHOUT a runcommands reply in that case) are mirrored into winget-update.log.
  Answers that carry NEITHER sessionid NOR responseid (some agent builds) are still consumed when a
  wgPending entry exists for that node; marker text on the console channel is captured the same way.
  installRouteHook self-retries every 2s until routeAgentCommand exists, wgPump calls it defensively.
  `wg_status` devices[] carry `pending:{since}` while a script awaits its answer.
  Every script self-logs on the client: Start/Stop-Transcript around the run, file
  next to the agent binary (Get-CimInstance Win32_Process parent id - PS 5.1 has no .Parent). Candidates
  agent-folder -> ProgramData -> TEMP are chosen by an Out-File -Append write probe, because
  Start-Transcript on a blocked file reports success while writing NOTHING (rotates once at 5MB).
  `hook_agentCoreIsStable` additionally queues the device through `wgQueueNode` (stagger-delayed, so the
  collector settles first; disabled/excluded/not-due devices short-circuit without any agent traffic).
- Batching: queue with 2 devices in parallel (`WINGET_MAX_PARALLEL`), 2 h watchdog per device, results in
  `winget-results.json`, log `winget-update.log` (rotates ~5 MB). Scheduled batches require explicit
  `updateMeshes`; manual "Run Now" covers every non-excluded desktop node. No reboots are ever triggered
  (`--allow-reboot` is never used).

## Design decisions (with reasons)

1. **Two-stage matching (Dependency-Check style, fully offline):** custom entries + curated `SOFTWARE_CPE_TABLE`
   first (exact vendor+product); then `obj.autoMatchProductTokens` derives candidate product tokens from the display
   name (arch/language/edition/version/year noise stripped) and accepts one ONLY if the token exists in
   `obj.cpeProductTokens` (product tokens actually present in the loaded CVE feeds). Publisher keywords map to
   vendors via `obj.PUBLISHER_VENDOR_MAP` (word-boundary); candidate vendor evidence must not contradict the
   index. Ambiguous multi-vendor tokens without vendor evidence need `isTrustworthyProductToken` (multi-word or
   long, not in `GENERIC_PRODUCT_TOKENS`). CVE version ranges are always re-checked, so a token hit on a patched
   version degrades to "no CVE for <product>", never to a false finding. Setting `autoProductMatch` (default true)
   disables only the auto stage. No CPE dictionary API exists anywhere.
2. **Coverage honesty:** `buildOverallReport` classifies every installed program by its scan row status
   (`assessable` vs `not assessable`, deduped by name+version) and both reports publish `coveragePercent` —
   a small finding count must not read as "everything clean".
3. **Reports split by document, grouped by location:** vulnerability report has NO device list; the device
   report shows **host names** (`node.rname` preferred via `getHostName`). One print page per location.
4. **Group-wide ratings:** mitigations are decided per location; one UI action writes all affected selected
   locations. Multi-location keys make the panel/rating flow click-light (original user requirement).
5. **False positives:** `flagged:true` + rating UNKNOWN, comment optional; excluded from every count/notification;
   CSV status `false positive`. Undo removes the whole assessment entry.
6. **Comments stored raw**, escaped at render; validation (trim/length) still server-side.
7. **NVD status derives from feed file mtimes** (`loadNvdFromAllFiles`), so it's truthful after restarts; the
   views only say "not downloaded" when `totalCves === 0`. Never reintroduce a download-only timestamp.
8. **Scheduling beyond 24.8 days:** Node clamps `setTimeout` ms > 2³¹−1 to **1 ms** (hot loop!). Use
   `obj.longTimeout(fn, ms)` (chunked, wall-clock based) for every long timer. The scan schedule is
   **restart-proof**: next delay = `interval − (now − lastScan)` from the persisted timestamp; no prior scan →
   ~1 min after startup (baseline run).
9. **Notification modes:** default = once per CVE (marked `(SEVERITY, new)`); `notifyUnratedRepeat:true` adds
   everything still unrated as `(SEVERITY, open)` on every run — the monthly to-do list. Rated/flagged → never again.
10. **Security:** CSV formula-injection neutralized in `formatCsvField`; strict id validation on writes
    (key-poisoning guard); rights come from MeshCentral's own checks; everything admin-gated.
11. **Settings precedence & live application:** writing MeshCentral's config.json from a plugin is dangerous
    (comments lost, server may not boot, core reads it only at startup). The Settings tab therefore persists to
    `scanner-settings.json`; `scannerConfig()`/`collectorConfig()`/`scheduleUpdate()`/`anyCveMaxAgeYears()` read
    through `effectiveSectionConfig()`. `obj.timerGen` + `rescheduleAll()` invalidate chained scan/collection
    timers on save, and `collectAndReschedule()` (no arguments!) re-reads its interval every cycle.

## Configuration keys & precedence

**Primary place to change them: the Settings tab of the panel** (`scanner-settings.json`, effective immediately,
never touches config.json). The config.json keys below remain the fallback/seed:

- `plugins.enabled: true` - REQUIRED (the only mandatory manual config edit). Do NOT set `plugins.list`:
  it switches pluginHandler to the development loader and ignores DB-installed plugins (web installer).
- `vulnerabilityScanner`: `autoProductMatch` (default true; automatic evidence matcher, see design decisions),
  `cpeTableEnabled`/`cpeTableUrl` (remote curated table; default = this repo's cpe-table.json on main),
  `scanIntervalHours` (720 = monthly OK), `scanMeshes`, `notifyOnScan`, `notifyThreshold`,
  `notifyUnratedRepeat`, `notify` (per-group), `updateHours`, `anyCveMaxAgeYears` (suppresses ancient version-less
  `kind:"any"` CVE matches).
- `inventoryScanner` (note: one letter less than the section above): `collectIntervalMinutes`, `collectOnAgentConnect`.
- `wingetUpdater` (sibling section, own Updates-tab form): `enabled` (default **false**), `intervalHours` (deprecated, ignored),
  `updateMeshes` (array; scheduled batches ONLY run on these - empty means NOTHING runs on purpose),
  `excludeNodes` (node ids), `ignorePackages` ([{id,note}] - never upgraded, additionally `winget pin add
  --installed` on the clients when `pinSync` true), `pinSync` (true). All ids validated against
  `WINGET_ID_RE` before anything reaches the agent shell.

**When adding a setting key, update all of:** `scannerConfig`/`collectorConfig`, `getSettingsHandler` (value +
sources + revertAllowed), `saveSettingsHandler` (+ `SETTING_MAP` for revert), the Settings tab form, the README
table, and a test assertion. Partial updates are a contract break the tests catch.

## Testing before committing changes

```bash
npm install        # once (dev dependency: handlebars)
npm test           # = tools/check.js && tools/test-plugin.js && tools/test-views.js
```

- `tools/check.js`: `node --check` on the plugin, inline-script syntax/`{{`-hazard check, JSON validity of
  config files, and view-name↔render-name consistency. Must run anywhere (no dependencies).
- `tools/test-plugin.js`: 174 behavioral assertions against the real module (mocked MeshCentral DB/webserver):
  locations grouping & counting, manual-rating severity override, FP exclusion, host-name preference, coverage
  numbers, multi-mesh scan/`mixed` logic, all POST handlers incl. validation/rejections, routes, admin gating
  (401), CPE table add/delete, vulns CSV header/content, toolbar button injection (simulated browser DOM), remote CPE table apply/cache/fetch/settings, NVD download-log tailing, manual NVD update trigger + concurrency guard, unknown-version matching rules, winget updater (builder/parser/queue/routes), `longTimeout` chunking, restart-proof schedule delays,
  scheduled-scan notification content in repeat and once mode, NVD-status derivation, settings overlay priority,
  save/revert/reset roundtrips incl. validation rejections, timer-generation invalidation, per-cycle collector config.
- `tools/test-views.js`: compiles all three views and renders them with mock data **and empty data**.

If you change data shapes, UPDATE these tests — they are the contract.

## Maintenance pitfalls

- `scanDeviceSoftware` is **async** (per-item loop; the CPE-API candidate path was removed — pure local now);
  always use its callback, never a returned value.
- `getMeshAssessment(meshId, cveId)` — single point where the stored rating/flag is applied; keep counting logic
  (panel aggregation, `buildOverallReport`, scheduled notifications) consistent with it.
- Handlebars views are plain HTML+core helpers; no layout engine, no `{{{ }}}`, no helpers; anchors via `{{@index}}`.
- `res.render('deviceReport')` ↔ file `deviceReport.handlebars`: the capital **R** must match exactly (Linux FS).
- After editing the inline panel script, re-run `npm test` (the extraction check is strict on purpose).
- **Version bumps must hit both places**: `version` in config.json (what the installer/DB and the update check
  compare) and the `@version` line in the inventoryscanner.js file header. No CHANGELOG.md file - changelogUrl
  points at the GitHub commits page on purpose (commit messages ARE the changelog); the field itself is
  REQUIRED by isValidConfig even when it links to commits. versionHistoryUrl/downgrades are not offered.
- The panel auto-scans ALL locations on load — cheap locally (no network) but DB-heavy on huge fleets; if that ever
  matters, make the initial scan opt-in rather than removing the floating selector.
- NVD feed download: go through `obj.runNvdUpdate(force, cb)` (the only sanctioned entry - it holds the nvdUpdateRunning guard); A stale-looking `.meta` mismatch is
  a warning, not an error (verified NVD behavior). Never treat `.json.gz` presence alone as "feed exists" — the
  decompressed `.json` is what `loadNvdFromAllFiles` reads.

## Current verified state (last known-good)

All of the above implemented and green: `node --check` OK; panel inline JS parses; 3 views render with and without
data; full logic suite passes (see `tools/test-plugin.js`), including the monthly-scheduling and notification-mode
tests. UI flow: floating location picker → one aggregated sortable/filterable table → one-click multi-location
rating/FP → CPE Mapping tab with built-in table visibility + overrides, Settings tab (scanner/collection options, per-key override of
config.json) → two printable reports with navigation and
per-location pages → scheduled monthly scans with toast/event-log notifications that re-list open findings.
