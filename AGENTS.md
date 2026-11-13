# AGENTS.md — MeshCentral Inventory & Vulnerability Scanner Plugin

Guide for AI agents working on this repository. Everything stated here was verified against the running code and
the test suite in `tools/`; trust the code and these notes over assumptions.

Repository: https://github.com/derStephan/meshcentral-inventoryscanner

## Repository layout

```
FLAT layout - required by the MeshCentral web installer: it unpacks the repository ZIP into
<datapath>/plugins/inventoryscanner/ after removing exactly ONE top path element, so the plugin files
MUST stay at repository root (never re-nest them in a folder - that silently breaks the installer).
Sub-folders INSIDE the repository (views/, tools/, lib/) are unpacked as-is and are fine.

  inventoryscanner.js          ENTRY POINT only: identity, file layout, module wiring (~175 lines)
  lib/<module>.js              the actual functionality, one module per feature area, see "Architecture" below
  config.json                  plugin manifest: installer metadata (and MeshCentral-side config file)
  cpe-table.json               THE maintained mapping table: downloaded by running servers, edit = no release needed
  views/assessment.handlebars  admin panel (incl. its inline <script> - the panel logic lives HERE)
  views/report.handlebars      printable vulnerability report (overview + one page per location)
  views/deviceReport.handlebars printable device inventory report (host names, one page per location)
tools/                         self-contained verification for agents (no MeshCentral server needed)
  check.js                     node --check on entry+lib/*, wiring (every module attached, no orphan), thin entry,
                               no __dirname in lib/ (obj.pluginDir), inline-script extraction check,
                               JSON validity, render-name match over the WHOLE JS tree
  test-plugin.js               behavioral tests against the real plugin module with mocked MeshCentral
  test-views.js                compiles+renders all three views with Handlebars (needs `npm ci`)
  coverage-benchmark.js        read-only mapping audit against the top NVD products by CVE count (run server-side with --nvd <datapath>/nvd)
README.md                      user-facing documentation
package.json                   repo metadata; `npm test` runs tools/check.js + tools/test-plugin.js + tools/test-views.js
package-lock.json              committed on purpose: pins the dev dependency tree (handlebars) so `npm ci` gives every
                               contributor the same, audited versions; the plugin itself has NO runtime dependencies
.gitignore                     node_modules/ (would otherwise be shipped to every server by the ZIP installer),
                               npm debug logs, root /*.txt and /*.csv support dumps
```

## Architecture: the lib/ modules (v3.5.1)

Until v3.5.0 everything lived in one 6,000-line `inventoryscanner.js`. It is now split by
**functionality** into `lib/`, one concern per file (100-600 lines each), with the entry file reduced
to wiring. No behaviour, no route, no data shape changed - the split is purely structural.

**The pattern (attach/mixin, deliberately not `module.exports = {fn}`):** every module exports
`attach(obj)` and assigns its functions, constants and mutable state onto the shared per-instance
`obj`. The entry calls them in order:

```js
module.exports.inventoryscanner = function (parent) {
    var obj = {};                     // identity, paths, generations  (entry file)
    modules.forEach(function (name) { // ['lifecycle','settings',...]  (entry file, in load order)
        require(path.join(obj.pluginDir, 'lib', name + '.js')).attach(obj);
    });
    return obj;
};
```

Consequences an agent must respect:

- **Cross-module calls are always `obj.name(...)`.** Never cache another module's member in a local
  (`var f = obj.searchCves`): the test suite replaces members such as `obj.scanDeviceSoftware`,
  `obj.scanDeviceOs`, `obj.saveAssessments`, `obj.saveCustomCpe` at runtime and that only works while
  every call site reads the member off `obj` at call time.
- **State lives on `obj`, read at call time.** A module must not keep module-level `var`s - module
  files are cached per process and shared by ALL instances, so module-level state would leak across
  plugin instances (and survive a hot reload). `tools/test-plugin.js` asserts that no lib file declares
  a local at the top of its `attach` body (4-space indented `var`/`let`/`const`); top-level `require`s at
  column 0 are allowed (they hold no state). `tools/check.js` does NOT check this.
- **`obj.pluginDir` - not `__dirname`.** Inside `lib/`, `__dirname` is the `lib` folder. The entry sets
  `obj.pluginDir = __dirname` (the plugin root) and everything file-related (`config.json` version read,
  `cpe-table.json` fallback, the hot-swap `require()`) resolves against it. `node tools/check.js` fails
  on any `__dirname` inside `lib/`.
- **The only `__dirname` user allowed is `inventoryscanner.js` itself**, and `MODULE_CODE_VERSION` is
  read there once at module load (the hot-swap check depends on it - see "Plugin upgrade path").
- **Attach order is wiring, not logic.** Nothing is called at attach time (the factory body of every
  module contains only assignments), so the order in `modules` only documents layering: lifecycle →
  settings/assessments → data (nvd, nvdindex, cpetable, matching, oslifecycle, osscan, inventory) →
  collectors/engines (collector, scheduling, winget, winget-handlers, osupdate, swstore, swdeploy,
  swdeploy-handlers) → output (reports, csv, nodes) → routes → browser.
- **Functions that were local helpers are now members too** (`obj.formatCsvField`, `obj.timestamp`,
  `obj.parseMeshIds`, `obj.isFindingId`, `obj.boolSetting`, `obj.safeNodeDir`, `obj.fetchSysinfo`,
  `obj.httpGetToFile`, `obj.winRelNum`, `obj.ubuRelNum`, `obj.MAX_TIMEOUT_MS`) - same reason: they are
  used from several modules. Keep new shared helpers on `obj` as well.
- **`lib/browser.js` is special:** its three `obj.exports` members (`inventoryCsv`, `openAssessment`,
  `onWebUIStartupEnd`) are serialized into the browser and must not contain a single `obj.` reference;
  `uiCustomEvent` in the same file is server-side and may. The existing test asserts the invariant.

**Module ownership** (`grep` the entry's `modules` list for the current order):

| File | Owns (functions/state of that area) |
|---|---|
| `lib/lifecycle.js` | `server_startup` (incl. the code hot-swap), `fixOwnPluginUrl`, NVD timer self-heal + stale notification |
| `lib/settings.js` | `effectiveSectionConfig`, the `scanner-settings.json` overlay, `rescheduleAll`, `get/save/revert_setting` handlers |
| `lib/assessments.js` | `assessments` store, `getMeshAssessment`, `save_assessment` / `flag_false_positive` / `unflag_false_positive` handlers, `isFindingId` |
| `lib/nvd.js` | feed download + `.meta` check, `runNvdUpdate`, `ensureNvdData`, `scheduleUpdate`, feed loading, `nvdLog`, NVD log tailing |
| `lib/nvdindex.js` | `processNvdData`, `productIndex`/`cpeProductTokens`/`cpeVendorTokens`/`allCves`, `compareCpeVersions`, `normalizeCveVersion`, `defMatches`, `searchCves*`, the `anyCveMaxAgeYears` age rule |
| `lib/cpetable.js` | `SOFTWARE_CPE_TABLE` (seed), remote table apply/fetch/cache (`cpe-table.json`), custom UI entries, `isSafeTableRegex`, the CPE-tab handlers |
| `lib/matching.js` | `classifySoftware`, `matchTableEntry`, `guessDriverFirmware`, `cpeTokenize`, `autoMatchProductTokens`, publisher→vendor evidence, `scanDeviceSoftware` |
| `lib/oslifecycle.js` | endoflife.date cache + sanitizer, `osReleaseOf`, `osSupportState`, `isDistroPackage`/`isDistroMaintained`, `osEolFinding` |
| `lib/osscan.js` | `OS_CPE_TABLE`, `mapOsToCpe`, `windowsOsTarget`, `searchOsCves`, `scanDeviceOs` |
| `lib/inventory.js` | stored software/patch maps, `pruneSuperseded` (+ `pruneNameKey`/`pruneArchSig`/`pruneNameToken`), `getStoredSoftware`, `getWindowsUpdates` |
| `lib/collector.js` | agent software/`winupdates` requests, `installRouteHook`, `onAgentResponse` reply ownership, per-node JSON cache, collection schedule, `hook_agentCoreIsStable` |
| `lib/scheduling.js` | `scannerConfig`, `runScheduledScans`, `notifyAdmins`, `scheduleScans`, `load/saveScans`, `SEVERITY_RANK`, `longTimeout` |
| `lib/winget.js` | `wgBuildScript`/`wgTransport`/queue/pump/watchdogs, results+log persistence, `wgNodeDue`/`wgSweepOnce`/`scheduleWingetUpdates`, `psTranscriptLines`, `wingetConfig` |
| `lib/winget-handlers.js` | `wg_get_config`, `wg_save_config`, `wg_run`, `wg_status`, `wg_programs` handlers |
| `lib/osupdate.js` | OS batch engine: `osBuildWindowsScript`, `osBuildLinuxScript`, `osLinuxTransport`, targeting/`osUpgradeInfo`/`osUrgency`, `os_run` + `os_status` handlers |
| `lib/swstore.js` | deploy foundation: installer library index/folders, resumable upload parts, task store load/save/prune, staging into `<filespath>/tmp`, `swDownloadCookie` (agentdownload), name/args/extension sanitizers, `swEnsureStaged` |
| `lib/swdeploy.js` | deploy engine: `swBuildWindowsScript`/`swBuildLinuxScript`, `swWgetCommand`, queue/pump/`swDispatchNode`/`swHandleResponse`/watchdogs, `swOnNodeConnect`/`swSweepOnce`/`scheduleSwSweep`, `swTaskDoneCheck`, `swCreateTask`/`swTaskView` |
| `lib/swdeploy-handlers.js` | `sw_files`, `sw_upload`, `sw_delete_file`, `sw_rescan_library`, `sw_serverfiles`, `sw_devices`, `sw_create_task`, `sw_status`, `sw_retry_task`, `sw_cancel_task` handlers |
| `lib/reports.js` | `scanMeshCves`, `scanMultiMeshCves`, `assessmentScan` (the `action=scan` route), `summarizeDeviceSwVer`, `buildOverallReport`, `vulnerabilityReport`, `deviceReport` |
| `lib/csv.js` | CSV formatting helpers, `buildCsvForNodes`, the `action=export` route |
| `lib/nodes.js` | `fetchSysinfo`, `scanNodeSoftware`, `getGroupName`, `getHostName`, `windowsUpdatesFinding` |
| `lib/routes.js` | `handleAdminReq`/`handleAdminPostReq` dispatch, `isAuthorizedAdmin`, `isSameOriginRequest`, panel render, `get_locations`, `get_log`, `parseMeshIds` |
| `lib/browser.js` | `uiCustomEvent` (server-side) + the three browser-exported functions |

**Adding or moving functionality:** put the code in the module that owns the area (create a new
`lib/<name>.js` with the same `attach(obj)` shape only if nothing fits), add its name to the entry's
`modules` list, and keep `check.js` green - it fails if a file and the list disagree. A new route
handler belongs to its domain module and is only *dispatched* by `lib/routes.js`.

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
6. **Software deployment** (Deploy tab, v4.0.0): install an MSI/EXE/MSP/DEB/RPM/SH package on explicitly chosen
   devices or whole locations - package from the browser-uploaded library, from MeshCentral's Server Files or from
   the plugin's server folder; optional command-line arguments; offline devices are QUEUED and install on reconnect;
   every delivery is SHA-256 verified on the device before it runs; results per device (state + exit code) plus
   toast/event-log feedback. Nothing ever installs on its own - a task exists only because an admin created it.

## Verified API facts (do not guess)

Based on official MeshCentral source (`pluginHandler.js`, `webserver.js`, `db.js`, `meshcentral.js`).

- **Plugin entry:** `module.exports.inventoryscanner = function (parent)`; `parent.parent` = meshcentral server
  object; `obj.db = obj.meshServer.db`. Since v3.5.1 that function lives in `inventoryscanner.js` and only
  creates `obj`, declares the file layout and calls `require('./lib/<module>.js').attach(obj)` for every
  feature module - see "Architecture". The entry point MeshCentral sees does not change.
- **Folder/shortName must be alphanumeric only** (`/^[A-Za-z0-9]+$/`, no `_`/`-`), else `pluginadmin.ashx?pin=`
  returns 401. Here: `inventoryscanner`.
- **Web installer (supported install path):** `settings.plugins.enabled=true` is the only required manual
  config. pluginHandler loads plugins from the DB UNLESS `settings.plugins.list` is set - that dev branch
  bypasses the DB loader and UI enable/disable, so the README explicitly forbids `list` for installs.
  The installer validates the root config.json via `isValidConfig` (name, shortName, version, description,
  hasAdminPanel:boolean, homepage, changelogUrl, configUrl, repository.type/.url, meshCentralCompat - all
  required; plus downloadUrl for the ZIP), stores it in the DB (status 0 = disabled), then downloads
  downloadUrl and unpacks into plugins/<shortName>/ with exactly one path element removed (=> flat layout,
  sub-folders such as lib/, views/ and tools/ are unpacked with their contents).
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
  `doc.hardware.windows.osinfo.BuildRevision` = `Version + '.' + UBR`, e.g. `10.0.26200.9711` (verified in
  agents/modules_meshcore/computer-identifiers.js; `BuildNumber` = bare `26200` as fallback). Only the full form
  can be compared with the NVD Windows ranges (see the OS matching paragraph below).
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
- **Server → device file delivery (v4.0.0, verified in webserver.js `handleUploadFileBatch` +
  `handleAgentDownloadFile` and agents/meshcore.js `case 'wget'`/`serverFetchFile`):** a message
  `{action:'wget', overwrite:true, createFolder, urlpath:'/<domainurl>agentdownload.ashx?c='+cookie, path, folder,
  servertlshash}` sent over the agent's websocket makes the agent HTTPS-GET that URL **from its own server target**
  (`getServerTargetUrlEx('*/')` → `mesh.ServerUrl`) and stream the body to `path`. The URL is served WITHOUT a
  session: `agentdownload.ashx` requires `?c=` = `parent.encodeCookie({a:'tmpdl', d:domainId, nid:nodeid, f:file},
  parent.loginCookieEncryptionKey)` and then serves `<filespath>/tmp/<f>` (`f` through `common.IsFilenameValid`);
  the cookie is decoded with a **5-minute** timeout → mint it at dispatch time, never earlier. TLS is trusted by
  comparing the server certificate to the control-channel hash (`servertlshash` = hex of
  `webserver.webCertificateFullHashs[domain]`, unless `args.ignoreagenthashcheck`) — no certificate import on
  devices. **wget answers NOTHING to the server** (failures surface only as session-less console text), and a
  non-`overwrite` wget silently skips an existing file → the deploy engine always uses `overwrite:true` + a unique
  random file name and lets the install script verify the SHA-256 before executing. Upstream batch upload sends
  wget only to agents connected to THIS server (its own `TODO: peer servers`) — same limitation here.
- **MeshCentral's file layout (verified `getServerFilePath`/`handleUploadFileBatch`):** server files live under
  `parent.filespath` (= `<install>/meshcentral-files` or `settings.filespath`) as
  `domain[-<x>]/mesh-<group>` (Server Files of a device group) and `domain[-<x>]/user-<id>` (My Files);
  the agent-download staging area is the fixed `<filespath>/tmp` folder.

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
| `save_assessment` | `meshId` or `meshIds` (comma list), `cveId`, `assessment`, `comment` | comment **mandatory**; id must match `CVE-\d{4}-\d{4,}` or be `WINDOWS-UPDATES` / `OS-EOL`; mesh ids validated `^mesh/[^:]+$`; comment trimmed, ≤1000 chars, stored **raw** |
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
| `get_log` | `type` = nvd\|winget\|os\|deploy | whitelisted log tail (last 300 lines) |
| `sw_files` | — | installer library `{files:[{id,name,ext,size,sha256,time,by}], parts:[{uploadId,bytes}], limits:{chunkBytes,maxBytes,exts}, note}` |
| `sw_upload` | `uploadId` (hex 8..40), `name`, `index`, `data` (base64url ≤ `chunkBytes` raw), `last` | chunked upload into `software/parts/<id>.part`; `{ok,next}`, order-error `{error,next,have}` or `{done,file}` (hash computed, committed as immutable `<newid>.<ext>`) |
| `sw_delete_file` | `fileId` | removes an unused library entry + its file; refused (error) while a NOT-done task references it |
| `sw_rescan_library` | — | indexes files placed in `software/files/` on the server (renamed to `<id>.<ext>`, display name kept), drops vanished entries; `{added,removed,failed,files}` |
| `sw_serverfiles` | — | MeshCentral Server Files listing `{folders:[{meshId,name,files:[{name,size,time}]}], note}` from `<filespath>/domain[-x]/mesh-<grp>`, dot-files/invalid names hidden |
| `sw_devices` | — | every non-deleted node `{devices:[{id,host,given,group,meshid,online,platform:'windows'\|'linux'\|'other',os}]}` (platform via `osPlatformOf`) |
| `sw_create_task` | `source` ('library'\|'serverfile'), `fileId` or (`meshId`+`fileName`), `args?`, `nodeIds`(csv) and/or `meshIds`(csv) | validates everything (ids, name, ext ∈ SW_EXTS, args via `swSafeArgs`), expands locations, caps at `SW_MAX_DEVICES` (500), creates the task and queues all devices → `{taskId, devices, note}`; offline devices stay 'queued' until connect/sweep |
| `sw_status` | — | `{tasks:[{id,created,fileName,ext,args,size,sha256,done,sourceType,createdBy,counts:{ok,failed,queued,running,other},devices:[≤150 {node,state,time,exit,note,platform,reboot}],total}], active, queued, running}` (open tasks first, ≤60) |
| `sw_retry_task` | `taskId` (hex-validated, hasOwnProperty), optional `nodeIds` | re-queues not-ok devices (default: everything but ok/running) → `{success, devices}` |
| `sw_cancel_task` | `taskId` | queued devices → 'cancelled' (running sessions finish normally), queue entries dropped → `{success, cancelled, note}` |
| `os_run` | `mode` = update\|upgrade, optional `nodeIds` (csv) | v3.5.0 manual OS batch (`osStartBatch`); `update` = every non-excluded node with `osPlatformOf` windows\|linux, `upgrade` = only nodes where `osUpgradeInfo` says outdated AND has a method; explicit ids are filtered by the same rule; {busy} while a winget or OS batch runs |
| `os_status` | — | every Windows/Linux node: `platform, os, online, excluded, outdated, upgradable, target, note, last, pending` + `running, mode, active, queued, current:{windows11, ubuntuLts}` |
| `update_nvd` | — | starts `runNvdUpdate(true)` (background) and answers {started:true} / {alreadyRunning:true}; concurrent runs skip via the `nvdUpdateRunning` flag |
| `get_nvdlog` | — | `{lines:[...last 200 of nvd-download.log], size, file}`; `note` if file missing |
| `get_locations` | — | all non-deleted meshes `{locations:[{id,name}]}` (also feeds the Settings tab group table) |
| `remove_cpe` | `index` | legacy index-based removal |
| `get_settings` | — | `{settings:{...effective...}, sources:{key:'file'|'config.json'|'default', notifyPerGroup:{meshId:src}, revertAllowed:{key:bool}}}` |
| `save_settings` | full form field set (see `saveSettingsHandler`); `osUpgradeUrgentDays` optional (0..3650, absent/empty keeps a saved value) | validates everything, writes `scanner-settings.json`, runs `rescheduleAll()`, answers with the `get_settings` payload; `reset=true` clears the overrides of THIS tab (`vulnerabilityScanner` + `inventoryScanner`). Save and reset keep every other section of the file, notably `wingetUpdater` (up to v3.5.1 both replaced the whole file and dropped it) |
| `revert_setting` | one key of `revertScanIntervalHours`/`revertScanMeshes`/`revertNotifyOnScan`/`revertNotifyThreshold`/`revertNotifyUnratedRepeat`/`revertNotify`/`revertUpdateHours`/`revertAnyCveMaxAgeYears`/`revertAutoProductMatch`/`revertCpeTableEnabled`/`revertCpeTableUrl`/`revertDistroManaged`/`revertOsLifecycleEnabled`/`revertOsLifecycleUrl`/`revertOsUpgradeUrgentDays`/`revertCollectIntervalMinutes`/`revertCollectOnAgentConnect` = 'true' | removes that single override so config.json/default applies again |

Every POST: 401 unless `isAuthorizedAdmin`, 403 without header `X-InvScanner-Request: 1`, 400 without an object body.
GET also knows `show_cpe` (legacy JSON list of custom entries with index, used by nothing in the panel).
`save_assessment`/`flag_false_positive`/`unflag_false_positive` all validate the finding id (`CVE-...`,
`WINDOWS-UPDATES`, `OS-EOL`; unflag since v3.0.1);
`scan` validates every mesh id with the same `^mesh/[^:]+$` rule (since v3.0.1, ≤1000 ids).
`add_cpe` rejects regexes failing `isSafeTableRegex` and vendor/product longer than 200 characters.

Assessments persist in `<datapath>/nvd/assessments.json`, key `"<meshId>:<cveId>"` →
`{meshId, cveId, assessment, comment, lastModified, assessedBy, assessedById, flagged?}`.
Scheduled results in `<datapath>/nvd/scans.json` → `meshId -> {time, cves:[{cve, severity, ...}]}`.
Remote CPE table: repo `cpe-table.json` → the installer unpacks it into `<datapath>/plugins/inventoryscanner/`, which is
**exactly `obj.cpeTablePath`** - so on an installed server the maintained table is live from the first second without
any download, and a refresh (`fetchCpeTable`, at startup when stale and after every NVD cycle, https only) rewrites
that SAME file in place; a plugin upgrade re-unpacks the shipped copy (the newer shipped table then wins until the
next refresh). `loadRemoteCpeTable()` therefore tries the cache path first and `path.join(obj.pluginDir, 'cpe-table.json')`
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
distroManagedPrograms, distroEolPrograms, distroUnknownPrograms, coverageBase, coveragePercent, totalCves, falsePositiveCves, severityCounts{CRITICAL..UNKNOWN}, uniqueCves, locationCount,
locations:[{ id, name, totalSystems, totalPrograms, assessablePrograms, notAssessablePrograms, outOfScopePrograms,
distroManagedPrograms, distroEolPrograms, distroUnknownPrograms, coverageBase, coveragePercent, totalCves, falsePositiveCves, severityCounts, uniqueCves, findings:[{cve, severity, cvss, software, version,
description, assessment, comment, flagged, effectiveSeverity, devices:[hostnames]}], devices:[deviceRec] }],
devices:[deviceRec] }` with `deviceRec = {hostName, name, group, os, programs, programsAssessable,
programsNotAssessable, programsOutOfScope, programsDistroManaged, osSupport, cveCount, critical..unknown}`
(`osSupport` = 'supported'|'eol'|'unknown'; distro counts are NEVER part of `coverageBase`). `locations` is an **array** (views iterate it with
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

- Deploy tab (v4.0.0): library table + `<input type=file>` upload (FileReader chunks → `sw_upload`, sequential
  POSTs with resume-on-gap, progress text), source switch plugin-library ⇄ MeshCentral Server Files (two selects,
  filled by `sw_files` / `sw_serverfiles`), arguments input, location+device picker from `get_locations` +
  `sw_devices` (offline flagged, non-Windows/Linux disabled), and the task list from `sw_status` with per-row
  expander (device state, decimal+hex exit code, note) plus Retry-open / Cancel buttons. Uploads and tasks poll
  every 10 s while anything is open. The tab MUST keep sending the `X-InvScanner-Request` header on every POST
  (the shared `post()` helper does - a new fetch path must use it).

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

- **ZIP extraction is slow and alphabetical**: files land root-files-first, `lib/`+`tools/`+`views/` LAST, so
  `inventoryscanner.js` briefly exists as a 0-byte file and the Plugins page keeps showing **Disabled** until the
  archive is fully unpacked (slower on small VMs / with antivirus scanning). Never restart or re-install in that
  phase; the Plugins page shows no progress at all (MeshCentral UI limitation) and can print the OLD version until
  the page is refreshed. The plugin's own log line on a successful hot swap is
  `upgrade detected ... reloading without server restart` / `hot reload complete`.
  Since v3.5.1 this is even more important: the entry `require`s its `lib/` modules, so a tree that is only
  partially unpacked makes plugin loading fail with a visible `Cannot find module ...lib/<name>.js` - which
  means "wait for the extraction, then enable/upgrade again", never "the plugin is broken".
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
<plugins/inventoryscanner>/os-lifecycle.json     cached endoflife.date support dates (v3.1.0)
<plugins/inventoryscanner>/winget-results.json   last run per device (drives wg_status/wg_programs)
<plugins/inventoryscanner>/winget-update.log     batch log, rotated at ~5 MB
<plugins/inventoryscanner>/os-results.json       last OS update/upgrade run per device (drives os_status)
<plugins/inventoryscanner>/os-update.log         OS batch log, rotated at ~5 MB
<plugins/inventoryscanner>/software.json         deploy: installer library index (v4.0.0)
<plugins/inventoryscanner>/software/files/       stored installers <id>.<ext> (immutable ids)
<plugins/inventoryscanner>/software/parts/       in-progress chunked uploads <uploadId>.part
<plugins/inventoryscanner>/deploy-tasks.json     deploy tasks + per-device states (drives sw_status)
<plugins/inventoryscanner>/software-deploy.log   deploy log, rotated at ~5 MB
<datapath>/../meshcentral-files/tmp/invsw-*.ext   staging for the agent wget (MeshCentral's own temp area;
                                  swept after task close and >24 h; NOT under the plugin folder, because
                                  agentdownload.ashx serves exclusively from <filespath>/tmp)
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
  On mismatch it busts the require cache for `obj.pluginDir + path.sep` - which since v3.5.1 also covers every
  `lib/*.js` module (the entry requires them by `obj.pluginDir`, never by a module's own `__dirname`, so the new
  folder's code is what gets loaded; a test asserts the re-required lib files come from the new directory).
  `MODULE_CODE_VERSION` is read in the ENTRY file only, so it always describes the code that is really running -
  lib modules read `obj.PLUGIN_VERSION`. A fresh instance swaps it into
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

## OS update / upgrade engine (v3.5.0, urgency since v3.6.0, verified contracts)

- runcommands type 1 = cmd.exe (Windows), **type 3 = /bin/sh (Linux)**; on non-Windows agents type 1/2 do nothing
  (verified in MeshCentral `agents/meshcore.js`). One agent runs ONE runcommands session at a time, so
  `wgStartBatch`/`wgRunHandler`/`wgQueueNode` refuse while `osBatchRunning` and vice versa.
- Sessions use the `invscanner-os-<node>` prefix and the marker `@@INVOSU@@`; `onAgentResponse` checks the OS session
  BEFORE the winget one, with the same ownership rules (foreign session ids never consumed, session-less answers only
  while `osPending[node]` exists, console chunks buffered on `.cbuf`). Watchdog `OS_RUN_TIMEOUT_MS` = 4 h,
  `OS_MAX_PARALLEL` = 2, results `os-results.json`, log `os-update.log`.
- Targeting: `osPlatformOf` needs a reported osdesc (unknown OS / macOS / mobile = never touched); the winget
  `excludeNodes` list applies. "Current" = newest `11-<rel>` cycle / newest Ubuntu LTS in the endoflife.date cache -
  and NOTHING else: there is deliberately no hard-coded fallback release (it would go stale). Data that is missing,
  switched off or older than `OS_REFERENCE_MAX_AGE_MS` (30 days) gives `osUpgradeInfo(...).state = 'unknown'` with the
  reason in `note`; such devices are never upgraded (logged per device), and `os_run mode=upgrade` is refused with an
  explicit error when neither reference is known. Windows 10 counts as outdated only when the Windows 11 reference is
  known. Windows Server and
  non-Ubuntu distributions are never upgraded (method null).
- Release state (v3.6.0, `osUpgradeInfo(osdesc, now)` -> `state`): `current` | `available` | `urgent` | `unknown`
  (`outdated` = available or urgent, `urgent` boolean, plus `eol`, `daysLeft`, `urgentReason`). The urgency comes from
  `osUrgency`, i.e. `osSupportState` of the INSTALLED release (endoflife.date cycle incl. edition: Home/Pro `-w`,
  Enterprise/Education `-e`): support ended, or fewer than `scannerConfig().osUpgradeUrgentDays` days left (default
  365, 0..3650, Settings tab) = `urgent`; an outdated release without a known end date stays `available` with
  "support end unknown" - never guessed as urgent. Platforms without a newer-release check (Windows Server, every
  distribution except Ubuntu) are `urgent` when their own support ended / ends inside the window, else `unknown`;
  they never get a method. The fleet upgrade takes `scope`: `urgent` = state `urgent` + method, `all` = `available`
  or `urgent` + method; the panel has one button per scope, the per-device button always uses `all`.
- Windows script (`osBuildWindowsScript`, transported by `wgTransport`): COM `Microsoft.Update.Session` search
  `IsInstalled=0 and IsHidden=0 and Type='Software'` -> download -> install. Mode update skips the "Upgrades"
  classification (`WU_UPGRADES_CATEGORY`, language independent); mode upgrade sets `TargetReleaseVersion=1`,
  `ProductVersion='Windows 11'`, `TargetReleaseVersionInfo=<rel>` under `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`
  and restores/removes them afterwards. The target is validated `^\d{2}H[12]$` (throws otherwise). Shared transcript
  helper `psTranscriptLines` (same protected folders as winget, file `invscanner-osupdate.log`).
- Linux script (`osBuildLinuxScript`, transported by `osLinuxTransport` = `sh -c "$(echo b64 | base64 -d | gzip -dc)"
  < /dev/null`): every package manager call reads /dev/null and logs to `/var/log/invscanner-osupdate.log` (symlink
  refused). States `ok | failed | unsupported | reboot-needed`. Upgrade = Ubuntu only: dist-upgrade, then
  `do-release-upgrade -f DistUpgradeViewNonInteractive`; with `/var/run/reboot-required` present it stops with
  `reboot-needed` (the tool refuses to run then). `Prompt=never` is reported, never changed.
- Never any reboot (asserted by tests).

## Software deploy engine (v4.0.0, verified contracts)

- Three modules: `swstore` (library + task store + staging + cookie), `swdeploy` (scripts, dispatch,
  reconnect queue), `swdeploy-handlers` (routes). State: `obj.swFiles/swTasks/swUploads/swQueue/swPending/swActive`.
- **Delivery is MeshCentral's own batch-upload mechanism** (see the verified API fact): stage to
  `<filespath>/tmp/invsw-<16hex>-<12hex>.<ext>` (one copy per TASK, hashed ASYNC from the copy), then per device
  and per attempt: send `{action:'wget', overwrite:true, urlpath:'/<domainurl>agentdownload.ashx?c='+cookie(nid,f),
  path, folder, servertlshash}` followed by a runcommands script on the SAME agent socket (wget starts instantly,
  the script polls). Cookies are minted PER DISPATCH (5-minute decode timeout) - also for retries.
- **Scripts** (`swBuildWindowsScript`/`swBuildLinuxScript`, one statement per line, PS parser + `sh -n` asserted):
  wait up to `SW_FILE_WAIT_MIN` (15 min) for the file, verify SHA-256 (`Get-FileHash ... -ieq` / `sha256sum`),
  NOTHING runs before the check passes; then `msiexec /i "..." /qn /norestart <args>` (`/update ... /quiet` for .msp),
  `Start-Process -FilePath <file> -ArgumentList <args> -Wait` (exe/bin), or `dpkg -i` / `rpm -Uvh` / `sh` (Linux,
  `DEBIAN_FRONTEND=noninteractive`, stdin `< /dev/null`, output to `/var/log/invscanner-deploy.log`), delete the
  staged file, answer `@@INVSWD@@{json}` with `state ok|failed|error|no-file`, `exit`, `reboot`, `name`. Windows
  transcript via `psTranscriptLines('invscanner-deploy.log')` (protected folders, same as winget). Exit 3010/1641 =
  ok + reboot pending; **a reboot is never triggered**. A .msi/.msp on Linux answers failed ('Windows installer')
  without executing.
- **Sessions**: `invscanner-sw-<node>` on the shared routeAgentCommand hook (`onAgentResponse` checks sw → os → wg;
  session-less answers are only taken while `swPending[node]` exists; console text accumulates on `.cbuf` and is
  consumed only when the marker parses; console lines of an sw session are mirrored into software-deploy.log).
  Watchdog 2 h (`SW_RUN_TIMEOUT_MS`), parallel `SW_MAX_PARALLEL = 2`. The winget/OS pumps skip nodes with an sw
  session and vice versa (one runcommands session per agent, verified in meshcore.js).
- **Reconnect queue**: every queued device of a task is re-tried by `hook_agentCoreIsStable` →
  `obj.swOnNodeConnect(nodeid)` (staggered like collection) and by `swSweepOnce` every `SW_SWEEP_MS` (10 min,
  gen-guarded chain via `scheduleSwSweep`, also invoked from `rescheduleAll`). A device still 'running' but with NO
  pending session (socket died mid-script) is reset to 'queued' on load, connect and sweep - nothing is ever lost
  to a restart (`swLoadTasks` does the same after a server crash).
- **Task states**: `queued → running → ok | failed | error | no-file | timeout | unsupported | cancelled`
  (final set `swIsFinal`); when no device is open, `swTaskDoneCheck` closes the task, deletes the staged copy,
  logs a summary and raises the admin toast; every device also gets the node event (`wgRaiseNodeEvent`, reused
  intentionally - the message text is 'Software deploy: ...').
- **Library**: `software.json` index + immutable `software/files/<id>.<ext>` + resumable `software/parts/<uid>.part`
  (parts reload into `obj.swUploads` so an interrupted upload can resume; its display name is re-adopted from the
  next chunk's `name` field). `sw_rescan_library` indexes manually placed files under THEIR name and renames them
  to `<id>.<ext>`. Server-side deletions are visible via the rescan button.
- **Validation**: file ids `^[a-f0-9]{12}$`, task ids `^[a-f0-9]{8,32}$` (+ hasOwnProperty lookup), upload ids
  `^[a-f0-9]{8,40}$`, extensions must be in `SW_EXTS`, node/mesh ids as everywhere, args through `swSafeArgs`
  (control chars → spaces, ≤500), names through `swSanitizeName` (basename, ≤200); the server-file path is derived
  ONLY from DB mesh ids + listed names and re-validated against `<filespath>/domain.../mesh-...` at dispatch
  (traversal impossible); every staged name is server-generated. Agents scripts contain zero caller-typed text
  beyond the quoted args/name fields.
- **Limits**: `SW_CHUNK_BYTES 49152` raw per POST (base64url stays below body-parser's 100kb urlencoded default -
  the pluginadmin route does NOT raise it, verified in webserver.js), `SW_MAX_FILE_BYTES` 2 GB, `SW_MAX_DEVICES`
  500/task, `SW_MAX_TASKS` 100 (pruned finished-first by creation date), staged files older than a day are swept
  (`swCleanStaleStaging` at startup and per sweep) unless an open task names them.
- **No configuration section, no automation**: a deploy NEVER runs by itself - tasks exist only because an admin
  created them. The winget `excludeNodes` list is intentionally NOT consulted (the admin selects targets
  explicitly; the device picker shows the flag). Multi-server peering: like upstream batch upload, only agents
  connected to THIS server get wget (`wsagents`), peers stay queued.

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
12. **Distribution packages are judged by the OS lifecycle, not by NVD ranges (v3.1.0):** distributions backport
    fixes into the same upstream version (`2.4.4-2ubuntu17.6` is a patched 2.4.4), so a range check only produces
    false positives (measured: 3,696 CVE rows from `python3-*` libraries alone, all wrong) and misses distro-only
    fixes. `isDistroPackage` (agent row `location` dpkg|rpm|pacman|apk, verified in linux-info.js, or a maintainer
    `Name <mail@host>` publisher) + `isDistroMaintained` (maintainer domain of the distribution itself,
    `DISTRO_MAINTAINER_DOMAINS`; third-party repos such as docker.com/nvidia.com are still CVE-checked) -> status
    `distro-managed` | `distro-eol` | `distro-unknown` from `osSupportState(osdesc)`. Support dates come from
    endoflife.date (`maybeFetchOsLifecycle`, one https GET per slug in `OS_LIFECYCLE_SLUGS`, cached in
    `os-lifecycle.json`, refreshed with the NVD cycle, sanitized by `sanitizeLifecycleCycles`); nothing is
    hard-coded. No data = `unknown`, never `supported`. An end-of-life release raises one synthetic finding
    `OS-EOL` per device (`osEolFinding`, CRITICAL; ratable/flaggable like `WINDOWS-UPDATES`). Windows cycles are
    `<10|11>-<release>-<w|e>` (Pro/Home = w, Enterprise/Education = e). Distro packages never enter `coverageBase`.
13. **Windows OS matching (v3.1.0):** `windowsOsTarget` maps Windows 10/11 to the release CPE
    (`windows_11_25h2`, from the `25H2` in osdesc) and Server 2016+ to `windows_server_<year>`, and only
    `kind:'range'` definitions are evaluated against `BuildRevision` (`10.0.<build>.<UBR>`). The generic
    `windows_11`/`windows_10` CPEs hold almost only early all-version entries and matched EVERY machine identically
    (568 findings per Windows 11 PC before v3.1.0). No full build -> no OS assertion. Older Windows keeps the
    previous path (`mapOsToCpe`).
14. **Big NVD feeds (v3.1.0):** a feed above `NVD_WHOLE_PARSE_MAX` (256 MB) is split by
    `splitNvdVulnerabilities` (byte-level scanner over the `vulnerabilities` array, one JSON.parse per CVE). The
    2026 feed is ~520 MB, above V8's 512 MB string limit: `readFileSync(..,'utf8')` threw and the whole year was
    silently missing. Load errors are now written to nvd-download.log.
15. **Publisher evidence (v3.1.0):** `deriveVendorFromPublisher` falls back to `vendorFromPublisherIndex`: the
    publisher without legal forms is accepted as vendor ONLY when that exact token is an application vendor in the
    loaded feeds (`cpeVendorTokens`); the product still has to be proven by the token matcher.
16. **Deploy delivery through the agent's own wget (v4.0.0):** alternatives were considered and rejected - chunking
    a binary through runcommands lines (8 KiB/cmd, seconds per MB, no integrity) and an HTTPS URL the script fetches
    (would need the OS to trust the MeshCentral certificate). `wget` + the `agentdownload.ashx` cookie is the exact
    mechanism MeshCentral's own batch upload uses (verified end-to-end in upstream source), it works on every agent
    platform and every port/mTLS setup without touching devices' certificate stores. Because wget answers nothing,
    the SHA-256 check inside the install script is the ack: no file, no match -> `no-file`, nothing executed.
    Files stage in MeshCentral's `<filespath>/tmp` (the ONLY folder agentdownload serves) and are deleted with the
    task; the library itself lives in the plugin folder so an uninstall removes it (documented).
17. **Deploy is never automatic (v4.0.0):** unlike the winget updater there is no enable-switch and no schedule -
    a task exists only because an admin created it with explicit packages and explicit targets. Offline devices
    queue (that is the user requirement "install when the device is back"); the winget exclusion list is
    deliberately not consulted (selection IS the opt-in, and silent de-selection would be dishonest feedback -
    the picker shows the flag instead).

## Configuration keys & precedence

**Primary place to change them: the Settings tab of the panel** (`scanner-settings.json`, effective immediately,
never touches config.json). The config.json keys below remain the fallback/seed:

- `plugins.enabled: true` - REQUIRED (the only mandatory manual config edit). Do NOT set `plugins.list`:
  it switches pluginHandler to the development loader and ignores DB-installed plugins (web installer).
- `vulnerabilityScanner`: `autoProductMatch` (default true; automatic evidence matcher, see design decisions),
  `cpeTableEnabled`/`cpeTableUrl` (remote curated table; default = this repo's cpe-table.json on main),
  `scanIntervalHours` (720 = monthly OK), `scanMeshes`, `notifyOnScan`, `notifyThreshold`,
  `notifyUnratedRepeat`, `notify` (per-group), `updateHours`, `anyCveMaxAgeYears` (suppresses ancient version-less
  `kind:"any"` CVE matches), `distroManaged` (default true), `osLifecycleEnabled` (default true),
  `osLifecycleUrl` (default `https://endoflife.date/api/`, https, must end with `/`), `osUpgradeUrgentDays`
  (default 365, integer 0..3650; outside that range the default applies).
- `inventoryScanner` (note: one letter less than the section above): `collectIntervalMinutes`, `collectOnAgentConnect`.
- **Software deploy has NO settings keys (v4.0.0) by design**: no switch, no schedule, no mesh list - a task
  exists only because an admin created it on the Deploy tab. Its limits are constants in `lib/swstore.js` /
  `lib/swdeploy.js` (SW_*). Do not "helpfully" add a `softwareDeploy` section without updating this paragraph.
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
| `vulnerabilityScanner.distroManaged` | `true` | "Linux distribution packages: trust the distribution while the OS is supported" |
| `vulnerabilityScanner.osLifecycleEnabled` | `true` | "Fetch OS support dates" (endoflife.date; off = support state unknown, no OS-EOL) |
| `vulnerabilityScanner.osLifecycleUrl` | `https://endoflife.date/api/` | "Lifecycle API URL" (mirror only) |
| `vulnerabilityScanner.osUpgradeUrgentDays` | `365` | "OS upgrade is urgent this many days before support ends" (0 = only after support ended; drives `urgent` vs `available` in the Updates tab) |
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
npm ci             # once (dev dependency: handlebars, pinned by package-lock.json)
npm test           # = tools/check.js && tools/test-plugin.js && tools/test-views.js
```

Data dumps from support sessions (CSV exports, browser output TXTs) live OUTSIDE the repo (they sit in the
MeshCentral install folder) and root `/*.txt` + `/*.csv` are gitignored as a guard - never copy them in.
- `tools/check.js`: `node --check` on the entry AND on every `lib/*.js`, the module wiring (each lib file is in the
  entry's `modules` list and vice versa, no orphan), the module rules (no `__dirname` in `lib/`, entry stays thin),
  inline-script syntax/`{{`-hazard check, JSON validity of config files, and view-name↔render-name consistency over
  the WHOLE JS tree (the `res.render()` calls live in `lib/routes.js`/`lib/reports.js` since v3.5.1).
  Must run anywhere (no dependencies).
- `tools/test-plugin.js`: 417 behavioral assertions (71 steps) against the real module (mocked MeshCentral DB/webserver):
  the module wiring itself (every lib file attaches, a fresh instance exposes the same function surface, no
  module-level locals in `lib/`), locations grouping & counting, manual-rating severity override, FP exclusion, host-name preference, coverage
  numbers, multi-mesh scan/`mixed` logic, all POST handlers incl. validation/rejections, routes, admin gating
  (401), CPE table add/delete, vulns CSV header/content, toolbar button injection (simulated browser DOM), remote CPE table apply/cache/fetch/settings, NVD download-log tailing, manual NVD update trigger + concurrency guard, unknown-version matching rules, winget updater (builder/parser/queue/routes, incl. single-package update/uninstall runs + `wg_programs`), driver/firmware classification & coverage denominator, honest CVE aggregation (`deviceList`/`versionVaried`), coexistence-aware pruning, `longTimeout` chunking, restart-proof schedule delays,
  scheduled-scan notification content in repeat and once mode, NVD-status derivation, settings overlay priority,
  save/revert/reset roundtrips incl. validation rejections (and that a Settings-tab save/reset keeps the
  `wingetUpdater` section), timer-generation invalidation, per-cycle collector config, OS update/upgrade engine
  (scripts, targeting, release state `current|available|urgent|unknown` incl. the urgency window boundary, fleet
  upgrade `scope`, `os_status`), and the v4.0.0 software deploy engine (script builders incl. PS/sh syntax parsers,
  chunked/resumable upload, staging + per-dispatch cookie, wget/runcommands shapes, ok/failed/no-file/console
  answers, watchdog, reconnect queue, retry/cancel, server-files listing + traversal rejection, delete guard,
  platform gate, args-quote invariant, 401/403 on the new actions, restart reset of orphaned 'running').
  The winget `due:` fixtures pin `now` to local noon - with bare Date.now() they failed when the suite ran
  between 00:00 and 02:00 (found while extending the suite for v4.0.0).
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
  Tests that assert on emitted CODE TEXT use `pluginSrc()` (entry + all `lib/*.js` concatenated) - never read
  `inventoryscanner.js` alone, that file has no implementation any more. The upgrade test copies the whole
  plugin tree including `lib/`, exactly like the installer unpacks it.
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
- **Modules (v3.5.1):** a new function is a member of the shared `obj` (`obj.x = function ...` inside the module
  that owns the area) - a bare `function x()` in a `lib/` file is invisible to every other module and to the
  tests. Same for shared helpers: expose them on `obj` instead of exporting them from the module.
- **Never introduce module-level state** in `lib/` (`var cache = {}` next to `attach`): the file is cached per
  process, so it is shared by all instances AND survives a hot reload. Put it on `obj` (or on `global` with an
  explicit generation check, like `global.__inventoryscannerInstanceGen`).
- Keep a file near the 600-line mark in mind: if a module grows past it, split that area further rather than
  moving code back into the entry - the entry must stay wiring only (`check.js` fails above 300 lines).

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
v3.1.0 (matching rework, measured on a 39-device fleet, see AUDIT.md): NVD feeds > 256 MB are split instead of
parsed whole (the 2026 feed was never loaded), distro-managed packages + OS lifecycle from endoflife.date + OS-EOL
finding, Windows OS matching by release CPE + full build, NVD-verified publisher->vendor evidence, 35 new verified
table rows, python/Teams/Nextcloud mis-mappings fixed.
v3.5.0: on-demand OS updates (Windows Update agent / distribution package manager) and OS release upgrades for
outdated releases (Windows 10/11 via TargetReleaseVersion, Ubuntu via do-release-upgrade), see the OS engine section.
v3.5.1: STRUCTURE only - the 6,010-line `inventoryscanner.js` became a ~175-line entry plus 20
`lib/` modules by feature area (see "Architecture"); behaviour, routes, data shapes and generated agent scripts
are unchanged, which is exactly what the (unchanged, then extended) test suite proves. check.js and the upgrade
test now understand the module tree.
v3.6.0: OS upgrade urgency - release state `current|available|urgent|unknown` from the support end
of the installed release (endoflife.date, per edition) and the new setting `osUpgradeUrgentDays` (default 365); two
fleet buttons "force OS Upgrade (urgent)" / "(all)" (`os_run scope`, required for a fleet upgrade). Fix: the
Settings tab's save/reset no longer wipes the `wingetUpdater` section of `scanner-settings.json`.
v4.0.0 (this release): software deployment (Deploy tab) - install MSI/MSP/EXE/DEB/RPM/SH on chosen devices or whole
locations, packages from chunked browser upload, from MeshCentral Server Files or from the plugin's server folder;
optional command-line arguments; delivery via the agent's own wget + agentdownload cookie (MeshCentral's own
batch-upload transport, verified in upstream source), SHA-256 verified on the device BEFORE execution; offline
devices queue and install on reconnect (agent-connect hook + 10 min sweep); results per device (state, decimal+hex
exit code, note), device event + admin toast + software-deploy.log. Never automatic, never a reboot. New modules
swstore/swdeploy/swdeploy-handlers; the winget and OS pumps now also honour `swPending` (one runcommands session
per agent). Test suite: 417 assertions in 71 steps (the winget `due:` fixtures got the midnight fix described in
the Testing section).
