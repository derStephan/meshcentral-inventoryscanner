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

Pure admin tool for MeshCentral (all endpoints and the toolbar hook gated by `obj.isAuthorizedAdmin`: full site
admin `user.siteadmin === 0xFFFFFFFF` of the DEFAULT domain `user.domain === ''` - the plugin is server-wide, so
sub-domain admins of a multi-tenant server are refused since v3.0.1):

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
  `handleAdminPostReq`. Session auth only (cookie `xid`, SameSite from `sessionsamesite`, default `lax`; no CSRF
  token, verified in webserver.js) — the plugin does its own admin gate AND requires the header
  `X-InvScanner-Request: 1` on every POST (`obj.isSameOriginRequest`, 403 otherwise; a cross-site page cannot set
  a custom header without a CORS preflight, which MeshCentral never answers). Host/Origin are not compared on
  purpose (reverse proxies rewrite Host).
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
  on the TOP level (NOT `command.src`). MeshCentral rights-checks only `command.src.selectedDevices`, NOT the
  top-level list (verified in meshuser.js `case 'uicustomevent'`), and calls `uiCustomEvent` on every plugin for
  every event from ANY logged-in user - so `uiCustomEvent` itself checks `isAuthorizedAdmin(myparent.user)` and
  accepts only well-formed, de-duplicated `node/<domain>/<id>` strings. `tools/test-plugin.js` simulates the
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
  runs its own collector: it sends `{action:'software',type:'installedapps',rights:8}` (no sessionid; since
  MeshCentral commit cdc9582ada, 2026-11-09, the agent refuses software commands without a numeric `rights`
  field - 8 = Remote Control is the least value that permits the read, uninstall types stay refused) and the
  console command `winupdates` (unique `invscanner-*` sessionid) to online agents via `webserver.wsagents[nodeid]`,
  capturing the replies server-side by wrapping `webserver.routeAgentCommand`. A software reply is taken only
  while a request is pending AND it carries no sessionid (a reply with sessionid belongs to a browser's Software
  tab); it is then consumed (not broadcast). Error answers (`{error:...}`) never overwrite the last good list.
  Stored per node under `<datapath>/plugins/inventoryscanner/data/<nodeid>/{software,windowsupdates}.json`.
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
| `get_cpe_table` | — | `{entries:[{match,vendor,product,source:'built-in'|'remote'|'custom'}], cpeTable:{source,updated,url,enabled,entries}}`; a `kind`
    (driver/firmware) table row is shown as `vendor:'-', product:'excluded: <kind>'` instead of a CPE pair |
| `delete_cpe_table` | `match`,`vendor`,`product` | custom entries only (built-ins can be shadowed, not deleted) |
| `add_cpe` | `match`,`vendor`,`product` | regex validated via `new RegExp`; custom wins over built-in |
| `wg_get_config` | — | effective wingetUpdater config + per-key sources + queue state |
| `wg_save_config` | enabled, updateMeshes(csv), excludeNodes(csv), ignorePackages(JSON), pinSync (intervalHours accepted but ignored) | validates EVERYTHING, writes overlay, `rescheduleAll()`; the panel calls it automatically on EVERY Updates-tab change (switches, groups, ignore add/remove, exclusions, "+ ignore" buttons) - no manual-save footgun since v2.7.0 |
| `wg_run` | optional `nodeIds`(csv; overrides scope+exclusions), `dry`('true'), `pkgId` + `mode`('update'\|'uninstall') | manual batch; per-device or dry test runs; {busy} while one runs. With `pkgId` the whole batch runs restricted to that ONE package (`$invOnly` guard in the script) - `mode:'uninstall'` needs a valid `pkgId`, is never a dry run and never without one (rejected). Scope without `nodeIds` = `wgTargetNodes`: `updateMeshes` gates
    scheduled/sweep runs ONLY, every manual and package run covers ALL non-excluded Windows nodes |
| `wg_status` | — | every non-deleted WINDOWS node (`wgIsWindowsNode`: reported `osdesc` must contain 'windows'; no osdesc yet = kept; phones/Linux hidden). Each row: `host` (rname-first) + `given` (admin name, used for labels/sort); malformed records tolerated. `last.rows:[{id,name,from,to,state,exit,log}]` = EVERY package of the last run
    (dry or real, ≤200) - the panel's row expander shows them with the outcome (failed rows carry exit code
    incl. hex + winget's own message), "+ ignore" pushes one onto `ignorePackages` and saves immediately;
    failed packages additionally get one `FAILED` line per package in `winget-update.log`, and upgraded
     packages that match (exactly or as substring) an ignore entry raise a `WARNING` line there |
| `wg_programs` | — | the PACKAGES view (v3.0.0): aggregates `wgResults` per package id -> `{packages:[{id,name,ready,ok,failed,skipped,devices:[{node,label,state,from,to,time,dry}]}],note}` (≤400 packages, ≤200 devices each, sorted by ready+failed). `label` = admin given name first, then host name, then id; results of deleted devices are dropped; `not-installed` counts into `skipped` |
| `get_log` | `type` = nvd\|winget | whitelisted log tail (last 300 lines) |
| `update_nvd` | — | starts `runNvdUpdate(true)` (background) and answers {started:true} / {alreadyRunning:true}; concurrent runs skip via the `nvdUpdateRunning` flag |
| `get_nvdlog` | — | `{lines:[...last 200 of nvd-download.log], size, file}`; `note` if file missing |
| `get_locations` | — | all non-deleted meshes `{locations:[{id,name}]}` (also feeds the Settings tab group table) |
| `remove_cpe` | `index` | legacy index-based removal |
| `get_settings` | — | `{settings:{...effective...}, sources:{key:'file'|'config.json'|'default', notifyPerGroup:{meshId:src}, revertAllowed:{key:bool}}}` |
| `save_settings` | full form field set (see `saveSettingsHandler`) | validates everything, writes `scanner-settings.json`, runs `rescheduleAll()`, answers with the `get_settings` payload; `reset=true` clears all overrides |
| `revert_setting` | one key of `revertScanIntervalHours`/`revertScanMeshes`/`revertNotifyOnScan`/`revertNotifyThreshold`/`revertNotifyUnratedRepeat`/`revertNotify`/`revertUpdateHours`/`revertAnyCveMaxAgeYears`/`revertAutoProductMatch`/`revertCpeTableEnabled`/`revertCpeTableUrl`/`revertCollectIntervalMinutes`/`revertCollectOnAgentConnect` = 'true' | removes that single override so config.json/default applies again |

Every POST: 401 unless `isAuthorizedAdmin`, 403 without header `X-InvScanner-Request: 1`, 400 without an object body.
GET also knows `show_cpe` (legacy JSON list of custom entries with index, used by nothing in the panel).
`save_assessment`/`flag_false_positive`/`unflag_false_positive` all validate the finding id (unflag since v3.0.1);
`scan` validates every mesh id with the same `^mesh/[^:]+$` rule (since v3.0.1, ≤1000 ids).
`add_cpe` rejects regexes failing `isSafeTableRegex` and vendor/product longer than 200 characters.

Assessments persist in `<datapath>/nvd/assessments.json`, key `"<meshId>:<cveId>"` →
`{meshId, cveId, assessment, comment, lastModified, assessedBy, assessedById, flagged?}`.
Scheduled results in `<datapath>/nvd/scans.json` → `meshId -> {time, cves:[{cve, severity, ...}]}`.
Remote CPE table: repo `cpe-table.json` → the installer unpacks it into `<datapath>/plugins/inventoryscanner/`, which is
**exactly `obj.cpeTablePath`** - so on an installed server the maintained table is live from the first second without
any download, and a refresh (`fetchCpeTable`, at startup when stale and after every NVD cycle, https only) rewrites
that SAME file in place; a plugin upgrade re-unpacks the shipped copy (the newer shipped table then wins until the
next refresh). `loadRemoteCpeTable()` therefore tries the cache path first and `path.join(__dirname, 'cpe-table.json')`
second (the second entry only matters in dev `plugins.list` layouts/tests where code and datapath differ);
`SOFTWARE_CPE_TABLE` stays as last-resort seed and the two lists are NOT kept in sync by hand - adding a mapping is a
PR on the JSON file only (process + validation: CONTRIBUTING.md), no plugin version bump. `cpeTableStatus().origin`
reports where the live file came from ('downloaded' | 'cache' | 'bundled'); `activeSoftwareTable()` = remote entries
when a valid table was applied, else `SOFTWARE_CPE_TABLE`; custom (UI) entries always first. Entry regexes compile with the `i` flag ONLY;
bad JSON/regex → payload rejected, current table keeps running. Keys: `cpeTableEnabled`/`cpeTableUrl` (Settings tab).
A table row may replace `vendor`/`product` with **`kind:'driver'|'firmware'`** (out-of-NVD-scope marker, see below);
`applyCpeTableText` validates that shape and `matchTableEntry` returns it, kind rows win over the name heuristics.

UI-managed scanner settings in `<datapath>/plugins/inventoryscanner/scanner-settings.json` →
`{vulnerabilityScanner:{...}, inventoryScanner:{...}}`, merged over `config.settings` by
`obj.effectiveSectionConfig(section)` (file wins per key). **The plugin never writes config.json.**

**`scan` response shape** (drives the panel JS):
`{ meshes:[{id,name}], cves:[{cve, severity, cvss, description, software, version, deviceList:[{name,software,version}],
locations:[{meshId,name,devices:[device labels - admin given name first, rname/_id fallback], deviceList:[...]}], assessments:{meshId:rec|null}, assessment:rec|null,
mixed:bool, anyFlagged:bool}], flaggedCount, totalCves, lastUpdate }`.
**Honest aggregation (v2.8.0):** software/version are PER-DEVICE attributes - `obj.summarizeDeviceSwVer` runs
over the merged `deviceList` (also inside `buildOverallReport` findings): uniform → single value shown;
differing → `versionVaried`/`softwareVaried` + `variedVersions`/`variedSoftware` and `version` becomes '' -
a row must NEVER show one arbitrary device's version as truth for all (the v2.7.1 "1.2.6.0 vs 2.3.3.0" bug).
**Unknown installed version:** version strings first pass `normalizeCveVersion`: Debian epochs stripped
  (`1:2.3.4-1` -> `2.3.4`), numeric cores without distro decoration (`22.04.0-1build1` -> `22.04.0`),
  any distro decoration (ubuntu/dfsg/+exp/bzr/~/debN/repack) and snap/DEB wrapper strings that contain no
  program version (`1:1snap1-0ubuntu5`) -> `''`. An empty version asserts ONLY `kind:'any'` definitions
  (age-filtered by `anyCveMaxAgeYears`).
**Aggregated rating:** `assessment` is set only when it is uniform across ALL affected locations; a fully
unrated finding is `mixed:false, assessment:null`.

**`buildOverallReport()` shape** (drives both report views):
`{ generated, totalSystems, totalPrograms, assessablePrograms, notAssessablePrograms, outOfScopePrograms,
coverageBase, coveragePercent, totalCves, falsePositiveCves, severityCounts{CRITICAL..UNKNOWN}, uniqueCves, locationCount,
locations:[{ id, name, totalSystems, totalPrograms, assessablePrograms, notAssessablePrograms, outOfScopePrograms,
coverageBase, coveragePercent, totalCves, falsePositiveCves, severityCounts, uniqueCves, findings:[{cve, severity, cvss, software, version,
description, assessment, comment, flagged, effectiveSeverity, devices:[hostnames]}], devices:[deviceRec] }],
devices:[deviceRec] }` with `deviceRec = {hostName, name, group, os, programs, programsAssessable,
programsNotAssessable, programsOutOfScope, cveCount, critical..unknown}`. `locations` is an **array** (views iterate it with
`{{@index}}` anchors); `findingsById`/`uniqueCveIds` internals: `findingsById` is deleted before returning.
**`coverageBase` exists because Handlebars cannot add** - the reports must print `assessable/coverageBase`, never
`assessable/totalPrograms` (drivers would silently deflate the percentage).

Counting semantics: `totalCves`/`severityCounts` = device×CVE **occurrences**; a false-positive-flagged occurrence
moves to `falsePositiveCves` and is excluded from severity counting; a group rating **overrides** the NVD severity
for counting (`effectiveSeverity`); `WINDOWS-UPDATES` occurrences count like normal findings.

## Panel behavior (views/assessment.handlebars inline JS)

- Auto-scan on load; location selection = floating DIV (checkbox per mesh + "All locations"), persisted in
  `localStorage` key `invscanner_locations`; toggle button fixed top-right.
- Sortable columns (`data-key`, click toggles asc/desc, default cvss desc) + filters (text, effective severity,
  status: CVE/false positive/rated/unrated). Since v2.7.1 seven columns: CVE, Severity, CVSS, **Software & Version**
  (merged), Status, Affected Locations/Devices (device labels = given name first), **Manual Rating & Comment**
  (select + comment input + Save/False-positive buttons in one cell; sorted by the rating). The save/flag handlers
  find their controls via `tr.querySelector('.rating-sel'/'.comment-inp')` - never by cell index.
- Save/flag/unflag post the **meshIds of all affected selected locations** in one request; after success the row
  state is patched client-side (no rescan).
- All dynamic values rendered via `esc()` (comments stored raw → escape at output; never double-escape).
- The page heading (`h1#pageTitle`) follows the active tab (titles map in the tab click handler).
- The inline script must not contain `{{` (Handlebars would consume it) except the intended `'{{shortName}}'` token;
  `tools/check.js` enforces both this and `node --check` on the extracted script.
- Every POST sends the header `X-InvScanner-Request: 1` (see Security below); a new fetch path must keep it.

- Settings tab: fetches `get_settings` + `get_locations` on load; each numeric field carries a source select
  ("set in plugin settings" / "from config.json" / "built-in default") offering `revert_setting` when overridden;
  Save posts the full field set, "Reset all" posts `reset=true`. The group table is filled client-side from
  `get_locations`; all-checked or none-checked is sent as an empty list = "all groups".

## Upgrade path (verified; user decision: NO polling)

- The swap lives INSIDE server_startup (event-driven, called by MeshCentral after installPlugin);
  there is deliberately no timer/watchdog checking the disk. If a MeshCentral build never calls
  server_startup again, the upgrade lands on the next restart - accepted trade-off, documented.
- Node events: DispatchEvent(ids, source, event) persists via db.StoreEvent (meshcentral.js);
  wg runs raise per-device events (etype 'node', visibility 'nodes', targets [nodeid, meshid])
  so results show on the device's events page (viewmode 16).
- fixOwnPluginUrl() rewrites the stored plugin doc url to /pluginadmin.ashx?pin=...&action=show,
  because MeshCentral's generic configure link (?viewmode=43) 404s for this plugin.
- normalizeCveVersion: ANY distro decoration (ubuntu/dfsg/+exp/bzr/~ /debN/snap wrapper) -> ''
  (unknown) - Debian/Ubuntu patch fixes into identical upstream versions; plain '-1' suffixes
  and epochs-without-decoration still extract their numeric core.

## Install, first start and file layout (support facts moved out of the README)

- **ZIP extraction is slow and alphabetical**: files land root-files-first, `tools/`+`views/` LAST, so
  `inventoryscanner.js` briefly exists as a 0-byte file and the Plugins page keeps showing **Disabled** until the
  archive is fully unpacked (slower on small VMs / with antivirus scanning). Never restart or re-install in that
  phase; the Plugins page shows no progress at all (MeshCentral UI limitation) and can print the OLD version until
  the page is refreshed. The plugin's own log line on a successful hot swap is
  `upgrade detected ... reloading without server restart` / `hot reload complete`.
- First start downloads ALL NVD years (10-60 min typical) and then runs a baseline scan of every location; until
  the feeds are indexed the panel says "not downloaded" and no CVE can be reported.
- An **empty software list means "not collected yet"**, never "clean"; offline devices keep their last cached
  inventory (check inventory age before trusting a device row).
- Files written by the plugin (all under the MeshCentral datapath):

```
<nvd>/nvdcve-2.0-<year>.json       feed cache (matching is offline against these)
<nvd>/assessments.json             group ratings + false-positive flags
<nvd>/scans.json                   scheduled scan snapshots
<nvd>/nvd-download.log             feed download log (tailed by the Settings tab)
<plugins/inventoryscanner>/custom-cpe.json       UI-added mappings
<plugins/inventoryscanner>/cpe-table.json        the maintained table itself: the installer unpacks the repo copy
                                  here and every refresh rewrites it in place (see the CPE table paragraph)
<plugins/inventoryscanner>/scanner-settings.json Settings-tab overrides (never config.json)
<plugins/inventoryscanner>/winget-results.json   last run per device (drives wg_status/wg_programs)
<plugins/inventoryscanner>/winget-update.log     batch log, rotated at ~5 MB
<plugins/inventoryscanner>/data/<nodeid>/        collected software + windowsupdates JSON per device
```
- On the client the updater writes `invscanner-winget.log` next to `meshagent.exe` (fallback: the protected
  `C:\ProgramData\InventoryScanner` folder; no transcript when neither is safe). While a device
  is busy with another command session the agent answers 'already busy' on its **console only** (no runcommands
  reply), which the plugin mirrors into `winget-update.log`; the watchdog (10 min dry / 2 h real) closes it.
- Group ids are mesh `_id`s `mesh/<domain>/<name>` (default domain: `mesh//Server1`); easiest lookup is the
  checkbox values in the panel or the `meshes` collection.

## Software-list pruning (verified)

- `obj.getStoredSoftware` returns `pruneSuperseded(list)`: rows are grouped by resolved vendor|product
  (curated table -> auto matcher, else version/arch/locale-stripped name token + publisher-vendor map,
  needs no NVD index) and by version group: default the WHOLE product is one group; `jre/jdk/java/
  net_framework/dotnet/vc++` key on major, `python` on major.minor (real side-by-side installs).
  **Within a group, a row only supersedes another with the SAME arch-aware name key**
  (`pruneNameKey` = token with the vendor's own name word stripped + `pruneArchSig`): registry leftovers
  ("Mozilla Firefox 3.6" vs "Firefox 121", "Java 8 Update NNN" chain, "(Machine)" vs "(Machine - MSI)")
  collapse newest-wins, while DISTINCT installs that merely share a CPE mapping (Edge + Edge WebView2,
  VC++ x86 + x64) always coexist - v2.7 and earlier silently dropped them (fleet case: the plugin list
  was shorter than MeshCentral's own software tab). Unversioned rows never supersede.

## Plugin upgrade path (verified against MeshCentral 1.3.1 pluginHandler/meshagent)

- pluginHandler.installPlugin unzips then ends with a bare require(): after an UPGRADE Node
  returns the CACHED old module and builds a NEW instance from the OLD code (verified in pluginHandler.js).
  Routes/hooks dispatch dynamically via obj.plugins[name][fn], therefore the plugin self-heals:
  server_startup compares config.json on disk with `MODULE_CODE_VERSION` - read ONCE at module load, so it is
  the version of the code actually running (pre-3.0.1 the version was read per instance, the cached code then
  reported the new version and the swap never happened; verified with a simulated installer flow, now a test).
  On mismatch it busts the require cache for `__dirname + path.sep`, creates a fresh instance, swaps it into
  parent.plugins/exports. Every instance gets a process-wide generation (`global.__inventoryscannerInstanceGen`);
  `obj.timerValid(gen)` lets only the NEWEST instance act on its timer chains, so instances replaced by the
  installer stop by themselves. The routeAgentCommand monkey-patch resolves the current instance per call.
  An already-open browser page keeps running old inline JS until reloaded - HTML/exports are
  re-rendered fresh on every request, there is no server push channel to plugin pages.

## Winget auto-update engine (verified contracts)

- runcommands mechanics (verified in MeshCentral `agents/meshcore.js`): type 1 = cmd.exe line reader,
  type 2 = PowerShell via stdin; runAsUser 0 = the agent's SYSTEM context; reply:true makes the agent
  answer
  `{action:'msg', type:'runcommands', result, sessionid, responseid}`, captured by the same
  `routeAgentCommand` hook as the inventory collector. Sessions are identified by the
  `invscanner-wg-<node>` sessionid prefix; foreign sessions are never consumed.
- Transport (verified end-to-end on PS 5.1): runcommands TYPE 1 (cmd.exe) with ONE line:
  `powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$d=FromBase64String(
  b64(gzip(script)));…GZipStream…;Invoke-Expression $s"` - cmd's stdin reader has no PSReadLine
  trouble, PS gets the whole script atomically (exit/transcript reliable), gzip keeps the line at
  ~2KB vs cmd's 8191 limit. PowerShell is NEVER fed line-interactive anymore.
  The builder still keeps one statement per line anyway (defense in depth, guarded by a test).
  winget is located via HKLM App Paths, then the admin-only `%ProgramFiles%\WindowsApps\Microsoft.DesktopAppInstaller_*`
  folder (newest first; enumerable for SYSTEM via the wildcard), then PATH - a `Get-Command` hit is an
  ApplicationInfo whose location is `.Path` (`.FullName` is EMPTY there; pre-3.0.1 code read FullName and never
  used the PATH hit - verified on Windows 11 / winget 1.29).
  The client transcript goes ONLY to folders standard users cannot write to: the agent folder, else
  `%ProgramData%\InventoryScanner` (created with a protected ACL for SYSTEM + Administrators, refused if it already
  exists with another owner or as a reparse point; the log file itself is refused when it is a reparse point).
  Plain `%ProgramData%` and `%TEMP%` are no longer used (v3.0.1): both let standard users pre-create files that a
  SYSTEM process would then write through. No safe folder -> run continues without a transcript.
  Existence probe:
  `winget list --upgrade-available --accept-source-agreements --disable-interactivity`; the table is parsed by the
  column START positions of the header line above the dash line (language independent; winget separates a
  full-width cell by ONE space, which the old `\s{2,}` regex missed - OneDrive, VC++ redistributables, .NET
  runtimes and `< x.y` versions were silently never updated before v3.0.1), each row validated (dotted id,
  non-empty versions/source) with the old regex as fallback, parsing stops at the footer. Then skip-if-ignored
  (case-insensitive id match), `(& $wg) upgrade --id <id> --exact --silent --accept-package-agreements
  --accept-source-agreements --disable-interactivity` per remaining package, best-effort
  `winget pin add --id <id> --installed --exact` for ignore entries (pinSync), and ONE answer line
  `@@INVWUP@@{json}`. `winget uninstall` has NO `--accept-package-agreements` option - passing it makes winget
  abort with "Argument name was not recognized" (exit 0x8A150002); the uninstall line omits it since v3.0.1
  (verified on winget 1.29, the v3.0.0 "Uninstall everywhere" therefore never removed anything).
  `ConvertTo-Json` unwraps single-element arrays - the parser rewraps them. Anything unparsable is recorded as an
  error, never as a silent success.
- Automatic scheduling is two-stage, no interval: `wgNodeDue` = never ran OR last run on an earlier
  calendar day OR >=24 h old; the agent-connect hook queues a due single device (after `staggerDelay`),
  `wgSweepOnce` (hourly, gen-guarded) catches devices whose connection outlived the day boundary.
  Per-device manual/dry runs pass explicit ids to `wgStartBatch(reason, done, nodeids, dry, opts)`; `opts`
  (`{mode:'update'|'uninstall', onlyId:<winget id>}`) is kept for the whole batch in `obj.wgBatchOpts` and reaches
  `wgBuildScript` per device: the script then carries `$invMode`/`$invOnly` and either handles only that one id in the
  upgrade loop (`onlyGuard`: `if ($p.id -ine $invOnly) { continue }`) or skips the loop entirely and runs
  `winget list --id <only> --exact` + `winget uninstall --id <only> --exact --silent` (an uninstall of a package that
  is not installed answers `not-installed`, never `failed`; `onlyId` always goes through `WINGET_ID_RE`, so a bad id
  degrades to `$invOnly = ''` instead of injecting shell text).
  `wgTargetNodes` applies the same Windows rule (no agent traffic to phones/Linux ever).
  Package states: `ok`/`failed`/`skipped-ignored`/`skipped-noversion`/`dry-run`/`not-installed` (dry JSON carries
  `dry:true`, single-package runs carry `mode`). `wg_status`/`wg_programs` count `not-installed` as skipped.
  Watchdogs: 2h real batches, 10min dry runs (`WINGET_DRY_TIMEOUT_MS`, chosen via `wgBatchDry`).
  `msg/console` packets carrying an `invscanner-wg-` sessionid (e.g. the agent's 'already busy' note,
  meshcore.js breaks WITHOUT a runcommands reply in that case) are mirrored into winget-update.log.
  Answers that carry NEITHER sessionid NOR responseid (some agent builds) are still consumed when a
  wgPending entry exists for that node - but a reply WITH a foreign sessionid (a browser session) never is;
  console-channel text is buffered only when it is session-less (meshcore.js echoes runcommands output via
  `sendConsoleText` without a sessionid) or on our own wg session, accumulates on the pending entry (`.cbuf`,
  capped) and is consumed ONLY once the marker payload actually parses — partial chunks must never end
  a session (the runcommands reply or the watchdog finishes it). The payload is read up to the first
  line break after the marker (ConvertTo-Json -Compress is one line), so trailing console text cannot
  corrupt it; both Stop-Transcript calls pipe to `| Out-Null` because the cmd transport makes
  Stop-Transcript print its notice AFTER the answer line (the v2.5.1 'unparsable payload' bug).
  installRouteHook self-retries every 2s until routeAgentCommand exists, wgPump calls it defensively.
  `wg_status` devices[] carry `pending:{since}` while a script awaits its answer.
  Every script self-logs on the client: Start/Stop-Transcript (both silenced via `| Out-Null`) around
  the run. The agent folder is found by walking up to FOUR process ancestors (Get-CimInstance
  Win32_Process - with the cmd transport the DIRECT parent is cmd.exe/System32, the agent is the
  grandparent; matched by leaf name `meshagent|meshcentral...exe`), else the protected
  `%ProgramData%\InventoryScanner` folder (see above); the log rotates once at 5MB.
  `hook_agentCoreIsStable` additionally queues the device through `wgQueueNode` (stagger-delayed, so the
  collector settles first; disabled/excluded/not-due devices short-circuit without any agent traffic).
- Batching: queue with 2 devices in parallel (`WINGET_MAX_PARALLEL`), 2 h watchdog per device, results in
  `winget-results.json`, log `winget-update.log` (rotates ~5 MB). Scheduled batches require explicit
  `updateMeshes`; manual "Run Now" covers every non-excluded Windows node (unknown-OS nodes included). No reboots are ever triggered
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
 2. **Coverage honesty:** `buildOverallReport` classifies every installed program by its scan row status,
    deduped by name+version, into THREE categories: `assessable` (a proven CPE was checked), `not assessable`
    (a real application with no proven CPE - the blind spot) and `out of scope` (`driver`/`firmware` rows -
    the NVD application data never covered them, hardware vendor + Windows Update do). The machine status stays
    `driver`/`firmware` (row.status + outOfScope:true), the vulns CSV prints the self-explanatory text
    `drivers are not covered by CVE data` / `firmware is not covered by CVE data` instead.
    `coveragePercent = assessable / (assessable + notAssessable)`, drivers/firmware are NOT in the denominator:
    a driver-heavy fleet must neither look clean nor look broken. Both reports publish all three numbers.
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
10. **Security:** CSV formula-injection neutralized in `formatCsvField`; strict id validation on writes AND on the
    scan query (key-poisoning guard); `isAuthorizedAdmin` on every route and the toolbar hook; the
    `X-InvScanner-Request` header on every POST (cross-site request guard); table/custom regexes pass
    `isSafeTableRegex` (no nested quantifiers/backreferences - one bad regex would stall the event loop for every
    scan); https-only table download with RFC 3986 redirect resolution; client transcript only in admin-only folders.
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

**Key -> default -> Settings-tab control** (the user-facing table; kept here because the README deliberately no
longer duplicates it - drift between the two files was the reason for the move):

| Key (under `settings.<section>`) | Default | Settings/Updates tab control |
|---|---|---|
| `vulnerabilityScanner.scanIntervalHours` | `24` | Scan interval in hours (`0` = off); timed from the END of the last scan, restart-proof |
| `vulnerabilityScanner.scanMeshes` | all | Group table "Scan" checkboxes (empty selection = all groups) |
| `vulnerabilityScanner.notifyOnScan` | `true` | "Notify admins after scans" |
| `vulnerabilityScanner.notifyThreshold` | `"HIGH"` | Global notify threshold (CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN) |
| `vulnerabilityScanner.notify` (`meshId` -> severity) | - | Group table per-group threshold (empty = global) |
| `vulnerabilityScanner.notifyUnratedRepeat` | `false` | "Repeat unrated findings every scan" (`open` instead of only `new`) |
| `vulnerabilityScanner.updateHours` | `168` | NVD feed refresh in hours (also paces the CPE table re-download) |
| `vulnerabilityScanner.autoProductMatch` | `true` | "Auto-map" - automatic evidence matching for names without a table entry |
| `vulnerabilityScanner.cpeTableEnabled` | `true` | Re-download the maintained table with every NVD refresh |
| `vulnerabilityScanner.cpeTableUrl` | (this repo's `cpe-table.json`) | https URL of the maintained table (own fork allowed) |
| `vulnerabilityScanner.anyCveMaxAgeYears` | `5` | "Suppress version-less CVEs older than N years" (`0` = never) |
| `inventoryScanner.collectIntervalMinutes` | `1440` | Collect inventory every N minutes (`0` = off) |
| `inventoryScanner.collectOnAgentConnect` | `true` | "Collect when an agent connects" |
| `wingetUpdater.enabled` | `false` | Automatic winget updates on/off (Updates tab) |
| `wingetUpdater.updateMeshes` | none | Device groups that receive AUTOMATIC updates (a package/manual run ignores this list, exclusions still apply) |
| `wingetUpdater.excludeNodes` | none | Node ids permanently excluded from every batch |
| `wingetUpdater.ignorePackages` | none | `[{id, note}]` package ids never upgraded (also client-pinned) |
| `wingetUpdater.pinSync` | `true` | Keep the client-side pins in sync with the ignore list |
| `wingetUpdater.intervalHours` | - | DEPRECATED, read and ignored (two-stage day-based scheduling replaced it) |

`vulnerabilityScanner` and `inventoryScanner` are **siblings of `plugins`** directly under `settings`; the two
names differ by one letter and a typo silently keeps defaults. Settings-tab changes need no restart, config.json
changes need a server restart (+ Ctrl+F5, the browser caches the UI scripts).

**When adding a setting key, update all of:** `scannerConfig`/`collectorConfig`, `getSettingsHandler` (value +
sources + revertAllowed), `saveSettingsHandler` (+ `SETTING_MAP` for revert), the Settings tab form, the table
above, and a test assertion. Partial updates are a contract break the tests catch.

## Testing before committing changes

```bash
npm install        # once (dev dependency: handlebars)
npm test           # = tools/check.js && tools/test-plugin.js && tools/test-views.js
```

Data dumps from support sessions (CSV exports, browser output TXTs) live OUTSIDE the repo (they sit in the
MeshCentral install folder) and root `/*.txt` + `/*.csv` are gitignored as a guard - never copy them in.
- `tools/check.js`: `node --check` on the plugin, inline-script syntax/`{{`-hazard check, JSON validity of
  config files, and view-name↔render-name consistency. Must run anywhere (no dependencies).
- `tools/test-plugin.js`: 261 behavioral assertions (55 steps) against the real module (mocked MeshCentral DB/webserver):
  locations grouping & counting, manual-rating severity override, FP exclusion, host-name preference, coverage
  numbers, multi-mesh scan/`mixed` logic, all POST handlers incl. validation/rejections, routes, admin gating
  (401), CPE table add/delete, vulns CSV header/content, toolbar button injection (simulated browser DOM), remote CPE table apply/cache/fetch/settings, NVD download-log tailing, manual NVD update trigger + concurrency guard, unknown-version matching rules, winget updater (builder/parser/queue/routes, incl. single-package update/uninstall runs + `wg_programs`), driver/firmware classification & coverage denominator, honest CVE aggregation (`deviceList`/`versionVaried`), coexistence-aware pruning, `longTimeout` chunking, restart-proof schedule delays,
  scheduled-scan notification content in repeat and once mode, NVD-status derivation, settings overlay priority,
  save/revert/reset roundtrips incl. validation rejections, timer-generation invalidation, per-cycle collector config.
  Two structural guards run with them: a `mockRes` object must be answered **exactly once** and every step must call
  `next()` **exactly once** - a handler that answers twice (e.g. an exception escaping a synchronous nested test chain
  into the route's `try/catch`) would otherwise silently replay the rest of the suite. The package run is verified
  end to end (the real runcommands payload is gunzipped back and the whole queue drained), and every emitted
  PowerShell comparison operator is asserted to exist - a nonexistent `-notimatch` once made the uninstall script
  fail parsing on the client while every server-side test stayed green. Verify generated scripts with the PS
  parser when you touch `wgBuildScript`:
  `[System.Management.Automation.Language.Parser]::ParseFile(<script.ps1>, [ref]$t, [ref]$e)`.
  The winget table parser is additionally EXECUTED by PowerShell against a real winget 1.29 table (block between
  the `# invscanner:parse-begin/-end` markers; skipped where PowerShell is missing). The runner is the LAST
  statement of the file and prints `registered steps: N` - new steps must be pushed above it.
  Requests in tests carry `headers: XHDR` (the panel header); the test admin has `domain: ''`.
- `tools/test-views.js`: compiles all three views and renders them with mock data **and empty data**.

If you change data shapes, UPDATE these tests — they are the contract.

## Commit messages (= the changelog)

EVERY version gets a commit message, written in this established style (since v2.5.2) - commit messages ARE
the changelog (changelogUrl points at the commits page), so a user must understand each release from the
message alone, without the diff:

- Subject: `v<MAJOR.MINOR.PATCH>: <short imperative summary>` - the version the commit sets; after the
  colon lowercase, one line, says what the release does.
- Blank line, then one `-` bullet per logical change (fix / hardening / behavior / tests / docs): WHAT
  changed and WHY, self-contained English prose of 2-4 lines, naming the involved functions/markers.
- Always include a `Tests:` bullet (assertion count + covered areas) and a closing `Version bumped`
  bullet (config.json + file header).
- Repo-maintenance-only edits (docs/AGENTS.md/tooling without plugin behavior change) do NOT get a
  version bump, but still follow the bullet style with the actual version in the subject.

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
Since v3.0.0 also: drivers/firmware as their own out-of-scope category (kind rows in the table + name heuristics,
excluded from the coverage denominator) and the Updates tab's Packages view with per-package update/uninstall
across the whole fleet (`$invOnly` restricted script runs).
v3.0.1 (second audit, see AUDIT.md): request-header guard on POST, default-domain admin gate incl. toolbar hook,
working winget uninstall/PATH lookup/table parsing, protected client transcript folder, NVD-verified mapping
table, safe-regex check, agent-reply ownership checks, rights field for agents >= 2026-11-09.
