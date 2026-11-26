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

  inventoryscanner.js          ENTRY POINT only: identity, file layout, module wiring (~235 lines; check.js fails above 300)
  lib/<module>.js              the actual functionality, one module per feature area, see "Architecture" below
  config.json                  plugin manifest: installer metadata (and MeshCentral-side config file)
  cpe-table.json               THE maintained mapping table: downloaded by running servers, edit = no release needed
  views/assessment.handlebars  admin panel SHELL (v5.3.0): head/CSS, two-layer nav, container, the toast
                               (#invFloat), the hover help box (#helpBox) and the IIFE brackets of the inline <script>; every panel and every
                               JS area is a partial included from views/partials/
  views/partials/panels/*.handlebars  one file per panel (assessment, settings, cpe, nvd, license, devicelist,
                               swlist, asset, updates, deploy, reset) - included as {{> panels/<name> }}
  views/partials/js/*.handlebars      one file per JS area (prelude, core, state, nav, winget, os, deploy,
                               locations, scan, findings, filters, cpe, settings, reset, license, devicelist,
                               swlist, asset, help, init) - included INSIDE the shell's IIFE, so the closure and all
                               its helpers stay exactly as they were; each fragment holds complete declarations
                               only and is syntax-checked on its own by tools/check.js
  views/partials/probe.handlebars     the canary that proves partials resolve on a real server (CI asserts its
                               marker in the panel response); renders as an HTML comment only
  views/report.handlebars      printable vulnerability report (overview + one page per location)
  views/deviceReport.handlebars printable device inventory report (host names, one page per location)
tools/                         self-contained verification for agents (no MeshCentral server needed)
  check.js                     node --check on entry+lib/*, wiring (every module attached, no orphan), thin entry,
                               no __dirname in lib/ (obj.pluginDir), inline-script extraction check,
                               JSON validity, render-name match over the WHOLE JS tree
  test-plugin.js               behavioral tests against the real plugin module with mocked MeshCentral
  test-views.js                compiles+renders all three views with Handlebars (needs `npm ci`)
  coverage-benchmark.js        read-only mapping audit against the top NVD products by CVE count (run server-side with --nvd <datapath>/nvd)
  gen-license-meta.js          evidence tool for the curated `licenseType` field of cpe-table.json (v5.6.0): reads the
                               winget community manifests (microsoft/winget-pkgs, MIT) through the LOCAL winget client
                               (`winget show --id <id> --exact --locale en-US`) and reports drift between the evidence
                               and the curated value; `--write` refreshes the table, `--json` is machine-readable, and
                               on a machine without winget it prints SKIP and changes nothing. Normalization is an
                               explicit map (NORMALIZE) - an unmapped upstream string is reported, never written.
  winget-ids.json              the evidence linkage for that tool: `ids` maps a cpe-table row (keyed by its `match`
                               regex, so edition-specific rows get their own package) to a winget package id, and
                               `overrides` lists the rows whose curated value DELIBERATELY differs from the upstream
                               wording, each with its reason (winget's License field names the copyright TERMS, this
                               table answers "does a license have to be bought?"). Not part of `npm test`.
  workdir.js                   shared working-directory policy for every tool here (v5.6.0): `install()` redirects all
                               scratch paths to `INVSCANNER_WORKDIR` when that variable is set (unset = `os.tmpdir()`,
                               which is what CI uses), registers every directory/file the suite creates and removes
                               them on exit. Required by test-plugin.js, test-views.js, check.js and
                               coverage-benchmark.js - without it the suite left its scratch behind (see Testing).
README.md                      user-facing documentation
package.json                   repo metadata; `npm test` runs tools/check.js + tools/test-plugin.js + tools/test-views.js
package-lock.json              committed on purpose: pins the dev dependency tree (handlebars) so `npm ci` gives every
                               contributor the same, audited versions; the plugin itself has NO runtime dependencies
.gitignore                     node_modules/ (would otherwise be shipped to every server by the ZIP installer),
                               npm debug logs, root /*.txt and /*.csv support dumps
```

## Architecture: the lib/ modules (v3.5.1)

Until v3.5.0 everything lived in one 6,000-line `inventoryscanner.js`. It is now split by
**functionality** into `lib/`, one concern per file (roughly 100-650 lines each), with the entry file reduced
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
- **ONE collection, many consumers (v5.1.0 - a hard rule).** A device's inventory is collected in exactly
  one place: `obj.fetchNodeSoftware(node, cb)` returns the raw software rows (plugin store AND sysinfo doc)
  and `obj.collectNodeInventory(node, cb)` returns the whole canonical record - identity, `hardwareSummary`,
  the raw rows, the output projection (`softwareProjection`), the per-software scan rows, the FULL findings
  list (software CVEs + OS CVEs + `WINDOWS-UPDATES` + `OS-EOL`) and the counts. **Never** re-implement that
  chain (`fetchSysinfo` → `getStoredSoftware` → `scanNodeSoftware` → OS findings) in a consumer, and
  **never** hand the matcher a reduced projection of the rows: `isDistroPackage`/`isDistroMaintained` read
  `location`/`installLocation`, so projecting before scanning silently turns distribution packages into
  false-positive CVEs. Consumers are `csv.js` (all three exports), `reports.js` (both scan paths),
  `fleetindex.js` (browser lists) and `assetmgmt.js` (the push); `license.js` uses `fetchNodeSoftware` for
  its rule matching. This is what makes the browser, the CSV and the push show the SAME device facts -
  `tools/test-plugin.js` pins it with the "1:1" assertions (same finding ids in CSV, report, fleet index and
  push payload; same program list; same hardware serial/CPU).
- **Functions that were local helpers are now members too** (`obj.formatCsvField`, `obj.csvCellCompare`, `obj.csvRowCompare`, `obj.pacedEach`, `obj.timestamp`,
  `obj.parseMeshIds`, `obj.isFindingId`, `obj.boolSetting`, `obj.safeNodeDir`, `obj.fetchSysinfo`,
  `obj.httpGetToFile`, `obj.winRelNum`, `obj.ubuRelNum`, `obj.MAX_TIMEOUT_MS`) - same reason: they are
  used from several modules. Keep new shared helpers on `obj` as well.
- **`lib/browser.js` is special:** its three `obj.exports` members (`inventoryCsv`, `openAssessment`,
  `onWebUIStartupEnd`) are serialized into the browser and must not contain a single `obj.` reference;
  `uiCustomEvent` in the same file is server-side and may. The existing test asserts the invariant.

**Module ownership** (`grep` the entry's `modules` list for the current order):

| File | Owns (functions/state of that area) |
|---|---|
| `lib/lifecycle.js` | `server_startup` (incl. the code hot-swap), `fixOwnPluginUrl`, `upgradeTreeReady` (since v5.3.0 also requires every REFERENCED handlebars partial to exist and be non-empty - the installer unpacks alphabetically with `views/` last, and an unresolved partial is a render error), `checkAndRepairNvdTimer` (v5.2.0: REPORTS a stale feed + notifies admins, arms no timer itself - the due-aware `scheduleUpdate()` from `server_startup` does that once) |
| `lib/settings.js` | `effectiveSectionConfig`, the `scanner-settings.json` overlay, `rescheduleAll` (v5.2.0: also re-arms the NVD feed timer and the license schedule - the generation bump invalidates them), `get/save/revert_setting` handlers |
| `lib/assessments.js` | `assessments` store, `getMeshAssessment`, `save_assessment` / `flag_false_positive` / `unflag_false_positive` handlers, `isFindingId` |
| `lib/nvd.js` | feed download + `.meta` check, `runNvdUpdate` (`nvdUpdateRunning` guard), `ensureNvdData`, `scheduleUpdate` (**due-aware since v5.2.0**: the delay is measured from `lastUpdate`, a stale/missing feed runs after `NVD_MIN_DELAY_MS` (60 s) and a FAILED run retries after `NVD_RETRY_MS` (6 h) - never a tight loop against the rate-limited NVD), feed loading, `nvdLog`, NVD log tailing |
| `lib/nvdindex.js` | `processNvdData`, `productIndex`/`cpeProductTokens`/`cpeVendorTokens`/`allCves`, `compareCpeVersions`, `normalizeCveVersion`, `defMatches`, `searchCves*`, the `anyCveMaxAgeYears` age rule |
| `lib/cpetable.js` | maintained table apply/fetch/cache (`cpe-table.json` - the ONLY curated copy since v4.2.0, the old in-code seed is gone), custom UI entries, `isSafeTableRegex`, `sanitizeLicenseType` (v5.6.0: the optional `licenseType` annotation of a row - SPDX id or Proprietary/Freeware/Freeware (non-commercial), capped at 80, charset-restricted, NEVER lowercased, dropped when unusable so a bad annotation cannot cost CVE coverage), the CPE handlers |
| `lib/matching.js` | `classifySoftware`, `matchTableEntry`, `licenseTypeFor` (v5.6.0: the curated license annotation of a display name - custom row first, then the table, `''` when nothing matches; deliberately NOT derived from the auto token matcher, which proves a CPE product and says nothing about licensing), `guessDriverFirmware`, `cpeTokenize`, `autoMatchProductTokens`, publisher→vendor evidence, `scanDeviceSoftware` |
| `lib/oslifecycle.js` | endoflife.date cache + sanitizer, `osReleaseOf`, `osSupportState`, `isDistroPackage`/`isDistroMaintained`, `osEolFinding` |
| `lib/osscan.js` | `OS_CPE_TABLE`, `mapOsToCpe`, `windowsOsTarget`, `searchOsCves`, `scanDeviceOs` |
| `lib/inventory.js` | stored software/patch maps, `pruneSuperseded` (+ `pruneNameKey`/`pruneArchSig`/`pruneNameToken`), `getStoredSoftware`, `getWindowsUpdates` |
| `lib/collector.js` | agent software/`winupdates` requests, `installRouteHook`, `onAgentResponse` reply ownership, per-node JSON cache, collection schedule, `hook_agentCoreIsStable` |
| `lib/scheduling.js` | `scannerConfig`, `runScheduledScans`, `notifyAdmins`, `scheduleScans`, `load/saveScans`, `SEVERITY_RANK`, `longTimeout` |
| `lib/winget.js` | `wgBuildScript`/`wgTransport`/queue/pump/watchdogs, results+log persistence, `wgNodeDue`/`wgSweepOnce`/`scheduleWingetUpdates`, `psTranscriptLines`, `wingetConfig` |
| `lib/winget-handlers.js` | `wg_get_config`, `wg_save_config`, `wg_toggle_exclude` + `wg_toggle_ignore` (v5.4.0: the atomic single-key routes - see the "never save a whole config form from another view" rule), `wg_run`, `wg_status`, `wg_programs` handlers |
| `lib/osupdate.js` | OS batch engine: `osBuildWindowsScript`, `osBuildLinuxScript`, `osLinuxTransport`, targeting/`osUpgradeInfo`/`osUrgency`, `os_run` + `os_status` handlers |
| `lib/devreset.js` | per-device Windows PC reset (v4.5.0, one of the TWO rebooting features - the other is `lib/devreboot.js`): `devBuildProbeScript`/`devBuildResetScript`, `devDispatch`, `devModeAllowed`/`devProbeFresh`/`devBitlockerState` gates, `devHandleResponse`/`devResetTimeout`, `dr_status`/`dr_probe`/`dr_reset` handlers, `device-reset.json` + `device-reset.log` |
| `lib/wutroubleshoot.js` | per-device Windows Update troubleshooter (v4.6.0): `wuBuildDiagnoseScript`/`wuBuildRepairScript`/`wuHead`, `wuDispatch`, `wuHandleResponse`/`wuTimeout`, reboot-state reporting, `wu_diag`/`wu_repair` handlers, `wu-troubleshoot.json` + `wu-troubleshoot.log` |
| `lib/devreboot.js` | per-device force restart + user notice (v4.7.0): `rbBuild*Script`/`rbBuildScript`/`rbProbeLines`/`rbCleanMessage`/`rbB64`, `rbDispatch`, `rbHandleResponse`/`rbTimeout`, `reboot_now`/`reboot_notify` handlers, `device-reboot.json` + `device-reboot.log` |
| `lib/license.js` | license keys/info in the software CSV (v4.8.0): curated `license-table.json` + remote fetch + custom rules (`applyLicenseTableText`/`sanitizeLicenseRules`/`licenseRulesForApp`), read-only `licenseBuildScript`, `licenseAppRules(rows)` (since v5.1.0 fed by `obj.fetchNodeSoftware`, so a program that only exists in the sysinfo doc is matched too - it used to see fewer programs than the CSV listed), `licDispatch`/`licHandleResponse`/`licTimeout`, `licSweepOnce` (one pass over all online Windows devices - used by BOTH the `all=true` route and the scheduler, v5.2.0), `scheduleLicenseCollection` (only when the master switch is on AND `licenseCollectIntervalHours` > 0; default 0 = on demand only), per-node `data/<node>/license.json`, `lic_status`/`lic_collect`/`get_license_table`/`add_license`/`remove_license`, `license-collection.log`. Since v5.5.0 (issue #10) rules may carry `perUser:true` (registry path written `HKCU:\...` read from every ALREADY-LOADED hive `Registry::HKEY_USERS\<SID>`; file path with a `{{profile}}` placeholder per profile dir) and ONE `*` wildcard (registry subkey segment enumerated, <=20 matches; file leaf pattern, <=5 files); users come read-only from ProfileList, capped at `LIC_MAX_USERS` (20); offline hives are NEVER loaded (`reg load`/`LoadKey` are rejected by the script-shape test); answer items carry `user`; `licenseMapForNode` is FIRST-OK-WINS (the old last-wins let a failing rule mask a found value) and puts the user into the source string (`registry (user: alice)`) for the CSV. Since v5.6.0 the `SoftwareLicensingProduct` read also returns the license TYPE and activation state of every Microsoft license (`Name`/`LicenseFamily` edition, `ProductKeyChannel`, `LicenseStatus`, `GracePeriodRemaining`, `EvaluationEndDate`, `ApplicationID`), translated server-side by `MS_LICENSE_STATUS`/`msLicenseStatusText`/`msLicenseChannelType` and counted by `msLicenseSummary` (a MISSING status counts as `unknown`, never as a violation); still only the last five characters of a key - no `DigitalProductId` decode, no `OA3xOriginalProductKey`, no `slmgr` (pinned by a test) |
| `lib/fleetindex.js` | READ-ONLY fleet index for the two unified views (v4.9.5, issue #8): `buildFleetIndex` walks `obj.collectNodeInventory` **via `obj.pacedEach`** (v5.4.2 - a bare loop hogged the event loop and unrelated requests died at the proxy with 502) and **coalesces parallel builds** (`_fleetIndexWaiters`, v5.4.2) so two views opening at once walk the fleet once; joins `wgResults` (updatable) + `licenseMapForNode`; `swFleetHandler` (POST `sw_fleet`, 60 s in-memory cache, `?refresh=1`). Since v5.4.0 it also owns the two on-demand detail routes `devDetailsHandler` (`dev_details`) and `swDetailsHandler` (`sw_details`, own 60 s cache per name) - both read-only, both built on `collectNodeInventory`, both reporting license COUNTS/presence and never a value. Per-software CVE attribution uses the software findings only (OS-level findings belong to the device, not to a program); the device badge counts `uniqueFindingIds` = the same distinct ids the CSV/report show. No agent command, no outbound request. |
| `lib/assetmgmt.js` | OPTIONAL outbound asset-management connector (v5.0.0, issue #5): `assetConfig`, `asBuildRequests` (generic JSON body template with `{{placeholders}}` + Jira and Snipe-IT presets, create-or-update via a stored external id), `asExternalId`, `assetHttp` (https-only, injectable), `asCollectDeviceRecord` (since v5.1.0 a thin shaping of `obj.collectNodeInventory` - the push therefore carries the SAME findings/hardware/software as the CSV: `vulnerabilities` = every finding with an id, `coverage` = the blind-spot rows), `asSendDevice`/`asPushHandler`/`asTestHandler`, `asStatusHandler`, `asGetConfigHandler`/`asSaveConfigHandler` (own `assetManagement` settings section, secrets masked + blank-keeps + `__AS_CLEAR__`), `asLog` (status only, never a payload/secret), `scheduleAssetSync` (off unless enabled AND interval > 0), `asset-sync.json` + `asset-sync.log` |
| `lib/swstore.js` | deploy foundation: installer library index/folders, resumable upload parts, task store load/save/prune, staging into `<filespath>/tmp`, `swDownloadCookie` (agentdownload), name/args/extension sanitizers, `swEnsureStaged` |
| `lib/swdeploy.js` | deploy engine: `swBuildWindowsScript`/`swBuildLinuxScript`, `swWgetCommand`, queue/pump/`swDispatchNode`/`swHandleResponse`/watchdogs, `swOnNodeConnect`/`swSweepOnce`/`scheduleSwSweep`, `swTaskDoneCheck`, `swCreateTask`/`swTaskView` |
| `lib/swdeploy-handlers.js` | `sw_files`, `sw_upload`, `sw_delete_file`, `sw_rescan_library`, `sw_serverfiles`, `sw_devices`, `sw_create_task`, `sw_status`, `sw_retry_task`, `sw_cancel_task` handlers |
| `lib/reports.js` | `scanMeshCves`, `scanMultiMeshCves`, `assessmentScan` (the `action=scan` route), `summarizeDeviceSwVer`, `buildOverallReport`, `vulnerabilityReport`, `deviceReport` - both scan paths read `obj.collectNodeInventory` (v5.1.0), no own collection |
| `lib/csv.js` | CSV formatting helpers (`formatCsvField`, `csvCellCompare`, `csvRowCompare`), `buildCsvForNodes` (all three types generated from `obj.collectNodeInventory`, v5.1.0; the software export's columns are `... Software Install Date, License Type, License, License Source` since v5.6.0 - License Type is curated and needs no collection run), `formatBytes`, the `action=export` route |
| `lib/nodes.js` | **THE canonical per-device collection (v5.1.0)**: `fetchNodeSoftware` (the one way to get a device's raw software rows - plugin store AND sysinfo doc) and `collectNodeInventory` (identity + `hardwareSummary` + raw rows + projection + `softwareFindings` + the FULL `findings` list + counts). Plus `fetchSysinfo`, `scanNodeSoftware`, `getGroupName`, `getHostName`, `windowsUpdatesFinding`, `hardwareSummary`, `softwareProjection` (since v5.6.0 it also resolves `licenseType` per row via `obj.licenseTypeFor`, so the CSV, the fleet index, both detail views and the asset push report the SAME curated type without re-deriving it). Every consumer (CSV, both reports, fleet index, asset push, license rules) reads this one record - see the "One collection, many consumers" rule below. |
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
   ratings (mandatory comment), false-positive flags (optional comment), filter/sort, and a **Settings tab** for
   all scanner/collection options (overrides config.json, applies without restart); the CPE mapping table has its own
   page under Vulnerabilities > CPE table since v4.9.0.
4. **Printable reports** (`action=report`, `action=deviceReport`): overview page + one page per location, with a
   stated **CPE coverage percentage** so findings-only views can't be misread as "all clean".
5. **Scheduled scans + notifications** (server-side Node timers, restart-proof, monthly-capable) with per-group
   severity thresholds and an optional repeat-until-rated mode.
6. **Software deployment** (Deploy tab, v4.0.0): install an MSI/EXE/MSP/DEB/RPM/SH package on explicitly chosen
   devices or whole locations - package from the browser-uploaded library, from MeshCentral's Server Files or from
   the plugin's server folder; optional command-line arguments; offline devices are QUEUED and install on reconnect;
    every delivery is SHA-256 verified on the device before it runs; results per device (state + exit code) plus
    toast/event-log feedback. Nothing ever installs on its own - a task exists only because an admin created it.
 7. **Windows PC reset** (Devices > PC reset, v4.5.0, issue #4): reset ONE chosen Windows device with the built-in
    `systemreset` tool, "Keep my files" or "Remove everything". One of the two features that reboot a device (a reset
    runs in Windows RE, not inside the booted OS), so it is strictly manual and per-device: a read-only Check must
    pass, the exact device name has to be typed to confirm, and "Remove everything" is blocked while BitLocker
    protection is on until the recovery key is confirmed. Never scheduled, never a fleet action.
 8. **Windows Update troubleshooter** (Devices > Device list, v4.6.0, issue #3; an "OS Updates tab" until v5.4.0): per-Windows-device *Diagnose*
    (read-only: WU services, whether a reboot is pending and when Windows will restart, download-cache size,
    last `WindowsUpdateClient` errors) and *Troubleshoot* (the repairs the built-in troubleshooter applies -
    restart the update services, reset `SoftwareDistribution\Download` + `catroot2`, re-assert start types).
    Runs as SYSTEM through the agent; **it never reboots** and reports any pending reboot instead.
9. **Force restart + user notice** (Devices > Device list, v4.7.0, issue #6; an "OS Updates tab" until v5.4.0): per-Windows/Linux *Notify user*
   (send a message to the logged-on user via `msg`/`wall`, no reboot) and *Restart* (reboot after a grace,
   messaging the user through the OS shutdown banner) - for before/after an upgrade. The second explicit
   reboot path: per-device, manual, device name typed, never automatic, never a batch or schedule.
 10. **License keys in the software CSV** (Software > License keys, v4.8.0, panel regrouped in v4.9.0, issue #7): a curated + remote +
   custom rule table maps a program name to where its license lives (registry value / file regex/JSON/line /
   WMI property); an OPT-IN, on-demand read-only collection per Windows device adds License + License Source
   columns to the software-inventory CSV for asset management. Microsoft keys via the SoftwareLicensingProduct
    WMI class. Nothing is sent off-server. On demand by default; since v5.2.0 an automatic schedule can be
    enabled (`licenseCollectIntervalHours`, default 0 = off) - same read-only script, online Windows devices only.
11. **Two-layer navigation** (v4.9.0, issue #8): the panel is reorganised under four main sections -
    Devices, Software, Vulnerabilities, Settings - each with its own row of sub-tabs, replacing the old flat
    tab strip so related functionality is grouped instead of grown side by side. This is presentation only:
    the same panels, routes, ids and handlers, no behaviour or data changed (see Panel behavior below).
12. **Optional push to an external asset-management system** (v5.0.0, issue #5): the three lists this plugin
    already aggregates (hardware, software, vulnerabilities) can be transferred to a REST asset system -
    **generic** (an admin-authored JSON body template with `{{placeholders}}`, which reaches any REST API) plus
    first-class presets for **Jira** (one issue per device, created then updated) and **Snipe-IT** (one hardware
    asset per device, created then patched). OFF by default, https only, no automatic push unless an interval is
    set, credentials managed in Settings and never displayed or logged again. It is the plugin's ONE deliberate
    off-server exit and is documented as such in SECURITY.md.

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
- **Handlebars PARTIALS work for plugin views (verified v5.3.0, proven live in CI).** `pluginHandler.handleAdminReq`
  does `serv.app.set('views', <pluginPath>/<pin>/views)` before calling the plugin, and `webserver.js` creates the
  engine with `exphbs.engine({ defaultLayout: false })` - i.e. WITHOUT a `partialsDir`. `express-handlebars@8.0.5`
  derives it **per render** from the views path Express resolved:
  `this.partialsDir = this.config.partialsDir || path.join(viewsPath, "partials/")`, and `_getDir` globs
  `**/*.handlebars` (posix) with `_getTemplateName` stripping only the extension - so sub-folders become
  namespaces: `views/partials/panels/x.handlebars` is `{{> panels/x }}`. Two consequences an agent must respect:
  (1) `_getDir` RETHROWS glob errors, so `views/partials/` must exist - `upgradeTreeReady` therefore checks every
  REFERENCED partial (not just the files on disk) before an upgrade restart is triggered; (2) partials are cached
  in `_fsCache`/the Express view cache, so a partial change needs the same restart as a view change (unchanged
  behaviour). The CI container test asserts the `inv-partial-probe` marker in the real panel response.
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
- **Notifications:** `obj.meshServer.DispatchEvent(['*'], obj, {type:'notify', domain:'', ...})` — ephemeral browser toast for
   logged-in admins + entry in the server event log. No built-in email. `domain:''` is REQUIRED (v4.3.0):
   webserver.js `obj.subscribe` puts every `siteadmin == 0xFFFFFFFF` user - sub-domain admins too - on `'*'`, and
   meshuser.js `HandleEvent` filters only by `event.domain`; without it tenant admins received our scan toasts.
   Device events (`wgRaiseNodeEvent`) carry the node's own domain.
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
| `show` (or no `action`, v4.3.2 - the plugin list link) | `showAssessmentPanel` | renders `assessment` with `{shortName, meshList, lastUpdate, lastScan, scanIntervalHours, totalCves, version}` (version from the manifest beside the plugin file) |
| `scan` | `assessmentScan` | JSON via `scanMultiMeshCves(meshIds, cb, opts)`; `?mesh=<id>,<id>,...` (comma-separated). `?cached=1` answers **only** from the stored snapshot `obj.scanResults` (no device is touched; payload carries `cached:true`, `cacheTime`, `missing:[meshIds]`, and `scanning:true` when a live pass is running) - that is what opening the page does since v4.4.0. Without it the devices are really scanned (`opts.store` writes the new snapshot); a second live request with the same sorted mesh set **joins** the running one (`obj.scanInFlight`) instead of doubling the work. |
| `report` | `vulnerabilityReport` | renders `report` with `{shortName, report: buildOverallReport(), totalCves, lastUpdate}` |
| `deviceReport` | `deviceReport` | renders `deviceReport`, same data |
| `export` | `exportCsv` | streams a CSV **attachment** for ALL non-deleted nodes (`type=hardware|software|vulns`, default vulns; invalid → 400). UTF-8 BOM, `Content-Disposition: attachment; filename=<Base>_<timestamp>.csv`; built with the same `buildCsvForNodes` as the toolbar exports - **sorted column by column, left to right** (Group, Host Name, then the rest) since v4.4.0. Intended for bookmarks and the panel top nav. |

POST body `action=`:

| action | Keys | Notes |
|---|---|---|
| `save_assessment` | `meshId` or `meshIds` (comma list), `cveId`, `assessment`, `comment` | comment **mandatory**; id must match `CVE-\d{4}-\d{4,}` or be `WINDOWS-UPDATES` / `OS-EOL`; mesh ids validated `^mesh/[^:]+$`; comment trimmed, ≤1000 chars, stored **raw** |
| `flag_false_positive` | `meshId(s)`, `cveId`, `comment?` | comment **optional** (empty stays empty); sets `assessment:'UNKNOWN', flagged:true` |
| `unflag_false_positive` | `meshId(s)`, `cveId` | deletes flagged entries for all given meshes |
| `get_cpe_table` | — | `{entries:[{match,vendor,product,licenseType,source:'remote'|'custom'}], cpeTable:{source:'remote'|'none',updated,url,enabled,entries}}`; a `kind`
    (driver/firmware) table row is shown as `vendor:'-', product:'excluded: <kind>'` instead of a CPE pair; `licenseType` is always a
    string and is `''` when the row carries no curated annotation (v5.6.0); `source:'none'`
    means NO table file could be loaded - the curated stage is then empty (there is no in-code fallback list since v4.2.0) |
| `delete_cpe_table` | `match`,`vendor`,`product` | custom entries only (table rows live in cpe-table.json and can be shadowed, not deleted) |
| `add_cpe` | `match`,`vendor`,`product`, optional `licenseType` | regex validated via `new RegExp`; custom wins over the maintained table; `licenseType` goes through `sanitizeLicenseType` and an unusable value is dropped while the mapping is still saved (v5.6.0) |
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
| `get_log` | `type` = nvd\|winget\|os\|deploy\|reset\|wu\|reboot\|license\|asset | whitelisted log tail (last 300 lines) |
| `sw_files` | — | installer library `{files:[{id,name,ext,size,sha256,time,by}], parts:[{uploadId,bytes}], limits:{chunkBytes,maxBytes,exts}, note}` |
| `sw_upload` | `uploadId` (hex 8..40), `name`, `index`, `data` (base64url ≤ `chunkBytes` raw), `last` | chunked upload into `software/parts/<id>.part`; `{ok,next}`, order-error `{error,next,have}` or `{done,file}` (hash computed, committed as immutable `<newid>.<ext>`) |
| `sw_delete_file` | `fileId` | removes an unused library entry + its file; refused (error) while a NOT-done task references it |
| `sw_rescan_library` | — | indexes NEW files placed in `software/files/` on the server (renamed to `<id>.<ext>`, display name kept; files that already are `<id>.<ext>` of an index entry are left alone - before v4.3.0 every rescan re-imported and renamed them), drops vanished entries; `{added,removed,failed,files}` |
| `sw_serverfiles` | — | MeshCentral Server Files listing `{folders:[{meshId,name,files:[{name,size,time}]}], note}` from `<filespath>/domain[-x]/mesh-<grp>`, dot-files/invalid names hidden |
| `sw_devices` | — | every non-deleted node `{devices:[{id,host,given,group,meshid,online,platform:'windows'\|'linux'\|'other',os}]}` (platform via `osPlatformOf`) |
| `sw_create_task` | `source` ('library'\|'serverfile'), `fileId` or (`meshId`+`fileName`), `args?`, `nodeIds`(csv) and/or `meshIds`(csv) | validates everything (ids, name, ext ∈ SW_EXTS, args via `swSafeArgs`), expands locations, caps at `SW_MAX_DEVICES` (500), creates the task and queues all devices → `{taskId, devices, note}`; offline devices stay 'queued' until connect/sweep |
| `sw_status` | — | `{tasks:[{id,created,fileName,ext,args,size,sha256,done,sourceType,createdBy,counts:{ok,failed,queued,running,other},devices:[≤150 {node,state,time,exit,note,platform,reboot}],total}], active, queued, running}` (open tasks first, ≤60) |
| `sw_retry_task` | `taskId` (hex-validated, hasOwnProperty), optional `nodeIds` | re-queues not-ok devices (default: everything but ok/running) → `{success, devices}` |
| `sw_cancel_task` | `taskId` | queued devices → 'cancelled' (running sessions finish normally), queue entries dropped → `{success, cancelled, note}` |
| `os_run` | `mode` = update\|upgrade, optional `nodeIds` (csv) | v3.5.0 manual OS batch (`osStartBatch`); `update` = every non-excluded node with `osPlatformOf` windows\|linux, `upgrade` = only nodes where `osUpgradeInfo` says outdated AND has a method; explicit ids are filtered by the same rule; {busy} while a winget or OS batch runs |
| `os_status` | — | every Windows/Linux node: `platform, os, online, excluded, outdated, upgradable, target, note, last, pending` + `running, mode, active, queued, current:{windows11, ubuntuLts}` |
| `dr_status` | — | (v4.5.0) every Windows node `{devices:[{id,host,given,group,os,online,excluded,probe,hasProbe,modes:{clean,keepfiles},last,pending}], minBuild, pending:[nodeids]}` - cached probe + last reset, no agent command sent |
| `dr_probe` | `nodeId` | (v4.5.0) dispatches the read-only probe on `invscanner-dr-<node>` (runcommands type 1); {started} or {error} (offline / non-Windows / a busy session). The answer arrives on the route hook |
| `dr_reset` | `nodeId`, `mode` (`clean`\|`keepfiles`), `confirm` (typed device name), `bitlockerAck` (`true` for a clean reset past BitLocker) | (v4.5.0) one of the TWO rebooting actions (the other is `reboot_now`): gated on a fresh passing probe + a correctly typed name + (clean) BitLocker ack, then dispatches `systemreset -cleanpc/-keepfiles -noUI`; {started,mode} or {error}. The device restarts into WinRE, so the reply is often replaced by the offline transition |
| `wu_diag` | `nodeId` | (v4.6.0, issue #3) dispatches the read-only Windows Update diagnose on `invscanner-wu-<node>` (runcommands type 1): WU services + start types, whether a reboot is pending + when Windows will restart automatically, the download-cache size and the last `WindowsUpdateClient` errors. {started} or {error} (offline / non-Windows / busy). Changes nothing on the device |
| `wu_repair` | `nodeId` | (v4.6.0) applies the troubleshooter's "fix" steps DIRECTLY (the `Get/Invoke-TroubleshootingPack` cmdlets are gone since Win10 1709): restart BITS/wuauserv/appidsvc/cryptsvc/msiserver, reset `SoftwareDistribution\Download` + `System32\catroot2`, re-assert Automatic start types. {started} or {error}. **Never reboots** - the answer reports `rebootTriggered=false` and any pending reboot with when Windows handles it; a locked file shows as a `partial` step |
| `reboot_notify` | `nodeId`, `message` | (v4.7.0, issue #6) sends a message to the logged-on user of a Windows/Linux device WITHOUT rebooting (Windows `msg *`, Linux `wall`); also reports whether a reboot is already pending and who is logged on. {started} or {error} (offline / macOS or no reported OS / busy). Message is sanitized (control chars + quoting chars stripped, ≤200) and travels base64 |
| `reboot_now` | `nodeId`, `secs` (0..3600, default 60 grace), `message`, `confirm` (typed device name) | (v4.7.0) the SECOND explicit reboot path: after a typed-name confirm, restarts one Windows/Linux device with a grace period, messaging the user through the OS shutdown banner (`shutdown /r /t` / `shutdown -r +m`, plus a `msg`/`wall` heads-up). {started,platform,secs} or {error}. Never batched/scheduled; abort within the grace with `shutdown /a` (Win) / `shutdown -c` (Linux) is noted in the result |
| `lic_status` | — | (v4.8.0, issue #7) Windows devices `{devices:[{id,host,given,group,os,online,collected:{time,found,ms,apps,error,msLicensed,msNotLicensed,msUnknown}|null,pending}], enabled, running}` - collected license summary per device, no command sent. The three `ms*` counters (v5.6.0) come from `msLicenseSummary` and report the ACTIVATION state of the Microsoft licenses; a missing status code counts as `msUnknown`, never as a violation. No value, no key, no edition string. |
| `lic_collect` | `nodeId` OR `all:'true'` | (v4.8.0) runs the READ-ONLY license extraction (registry value / file regex-jsonfield-line / WMI property) built from the curated+custom rule table on one (or all online) Windows device(s). Refused while `licenseCollectionEnabled` is off (default). {started} / {started,devices} or {error}; the marker answer is stored in `data/<node>/license.json` |
| `get_license_table` | — | (v4.8.0) the full license rule table `{entries:[{match,label,rules,source:'table'|'custom'}], licenseTable:{source,origin,updated,url,tableEnabled,entries,custom}}` |
| `add_license` / `remove_license` | match, label, rules (JSON array) / index | (v4.8.0) custom rule editor; every field validated (`isSafeTableRegex`, type ∈ registry/file/wmi, lengths, ≤8 rules) before storing to `license-custom.json`; custom wins over the table |
| `sw_fleet` | `refresh` (optional '1') | (v4.9.5, issue #8) READ-ONLY fleet index that powers the two unified views: `{devices, software:[{name, version, versions, publisher, deviceCount, vulnerable, cve, maxSeverity, updatable, hasLicense, licenseType}], byDevice:{<nodeId>:{cve, maxSeverity}}, generated}`. Built only from data already on the server (stored software + the report/CSV matcher + winget results + local license maps); sends nothing to any agent and makes no new outbound request. Cached ~60 s so switching between the two views does not re-scan. `licenseType` (v5.6.0) is the curated annotation and is independent of `hasLicense` (a collected VALUE) - a known type never pretends a key was read. |
| `dev_details` | `nodeId` | (v5.4.0, issue #9) READ-ONLY everything stored about ONE device, fetched on demand by the Device list's *Details* button: identity + `hardwareSummary` + the installed programs (each with its curated `licenseType`, v5.6.0) + the FULL `findings` (shaped like the CSV rows) + the `coverage` rows + counts, plus the last run of every engine (`winget.rows`, `os`, `wu`, `rb`, `reset` probe/modes/last) and the license block `{enabled, found, ms, msSummary:{total,licensed,notLicensed,unknown}, msLicenses:[{product,family,channel,channelType,status,statusText,grace,evalEnd}], time, pending}`. Built from `obj.collectNodeInventory` - never a second collection. Contains NO license value and sends NO agent command: `msLicenses` is the Microsoft license METADATA with the partial key deliberately removed on the way out (v5.6.0, pinned by a test). |
| `sw_details` | `name`, optional `pkgId` | (v5.4.0, issue #9) READ-ONLY everything stored about ONE installed program across the fleet: `devices` (with version, capped 300), `versions`, `cves` (capped 200), `coverage` statuses, `licenseDevices` (a COUNT - never a value), `licenseType` (the curated annotation for that name, v5.6.0) and the `winget` aggregate for that package (ready/ok/failed/skipped + per-device rows + whether it is ignored). Paced walk over `collectNodeInventory`, cached ~60 s per name. |
| `wg_toggle_exclude` | `nodeId`, `excluded` ('true'/'false') | (v5.4.0, issue #9) puts ONE device on the winget exclusion list or takes it off, changing ONLY that key server-side. Exists because `wg_save_config` reads the whole form from the Updates-tab DOM - calling it from another view would have saved `enabled:false` with empty `updateMeshes`/`ignorePackages`. Keys that came from config.json are not copied into the plugin file. |
| `wg_toggle_ignore` | `pkgId`, `ignore` ('true'/'false'), optional `note` | (v5.4.0, issue #9) the same for ONE package id on the ignore list (validated against `WINGET_ID_RE`, list capped at 500). Used by the Software list's *Ignore* button. |
| `as_get_config` / `as_save_config` | full asset-management form | (v5.0.0, issue #5) the connector configuration in its OWN `assetManagement` section of scanner-settings.json (so the Settings-tab save/reset cannot wipe it and vice versa). Since v5.5.1 the literal values of the generic `headersJson` are masked on the way out like every other secret (`asMaskHeadersJson`; placeholder values stay visible) and a masked value on save keeps the stored one. Validated: https-only endpoint, method whitelist, JSON headers + JSON body template, Jira needs a project key, enabling needs a URL. Secrets (token/password/header value) are NEVER returned in the clear - the GET answers with a mask + `has*` flags; on save a blank secret KEEPS the stored value and `__AS_CLEAR__` erases it. |
| `as_status` | - | (v5.0.0) `{devices:[{id,host,given,group,last:{time,status,httpCode,externalId,error}|null}], running, config}` - the masked config summary plus the last push per device. |
| `as_test` | - | (v5.0.0) sends ONE synthetic sample record to the configured target and reports `{ok, httpCode}` - verifies URL/auth/mapping without pushing the fleet. |
| `as_push` | `nodeIds` (csv, optional; absent = all devices) | (v5.0.0) pushes the aggregated hardware/software/vulnerability record of each device to the target (Jira issue, Snipe-IT hardware asset, or the generic template). Refused while disabled. Server-side only: **no agent command is sent**. Create on the first push, update on later ones via the stored external id. Result per device goes to `asset-sync.json`; the log records status only. |
| `update_nvd` | — | starts `runNvdUpdate(true)` (background) and answers {started:true} / {alreadyRunning:true}; concurrent runs skip via the `nvdUpdateRunning` flag |
| `get_nvdlog` | — | `{lines:[...last 200 of nvd-download.log], size, file}`; `note` if file missing |
| `get_locations` | — | all non-deleted meshes `{locations:[{id,name}]}` (also feeds the Settings tab group table) |
| `remove_cpe` | `index` | legacy index-based removal |
| `get_settings` | — | `{settings:{...effective...}, sources:{key:'file'|'config.json'|'default', notifyPerGroup:{meshId:src}, revertAllowed:{key:bool}}}` |
| `save_settings` | full form field set (see `saveSettingsHandler`); `osUpgradeUrgentDays` optional (0..3650, absent/empty keeps a saved value) | validates everything, writes `scanner-settings.json`, runs `rescheduleAll()`, answers with the `get_settings` payload; `reset=true` clears the overrides of THIS tab (`vulnerabilityScanner` + `inventoryScanner`). Save and reset keep every other section of the file, notably `wingetUpdater` (up to v3.5.1 both replaced the whole file and dropped it) |
| `revert_setting` | one key of `revertScanIntervalHours`/`revertScanMeshes`/`revertNotifyOnScan`/`revertNotifyThreshold`/`revertNotifyUnratedRepeat`/`revertNotify`/`revertUpdateHours`/`revertAnyCveMaxAgeYears`/`revertAutoProductMatch`/`revertCpeTableEnabled`/`revertCpeTableUrl`/`revertDistroManaged`/`revertOsLifecycleEnabled`/`revertOsLifecycleUrl`/`revertOsUpgradeUrgentDays`/`revertCollectIntervalMinutes`/`revertCollectOnAgentConnect` = 'true' | removes that single override so config.json/default applies again |

Every POST: 401 unless `isAuthorizedAdmin`, 403 without header `X-InvScanner-Request: 1`, 400 without an object body
(pinned for ALL POST actions by the audit-4 gate matrix in tools/test-plugin.js, incl. a sub-domain full admin).
**A LIVE scan (`GET action=scan` without `cached=1`) needs the same header since v5.5.1** (403 otherwise): it queries
every device of the selected locations, so a foreign link or `<img src>` must not be able to start it. The panel's
`get()` helper sends the header; the cached read and the report/CSV GETs stay plain GETs.
GET also knows `show_cpe` (legacy JSON list of custom entries with index, used by nothing in the panel).
`save_assessment`/`flag_false_positive`/`unflag_false_positive` all validate the finding id (`CVE-...`,
`WINDOWS-UPDATES`, `OS-EOL`; unflag since v3.0.1);
`scan` validates every mesh id with the same `^mesh/[^:]+$` rule (since v3.0.1, ≤1000 ids).
`add_cpe` rejects regexes failing `isSafeTableRegex` and vendor/product longer than 200 characters.

Assessments persist in `<datapath>/nvd/assessments.json`, key `"<meshId>:<cveId>"` →
`{meshId, cveId, assessment, comment, lastModified, assessedBy, assessedById, flagged?}`.
Scheduled results in `<datapath>/nvd/scans.json` → `meshId -> {time, cves:[{cve, severity, ...}]}`.
Maintained CPE table: repo `cpe-table.json` → the installer unpacks it into `<datapath>/plugins/inventoryscanner/`, which is
**exactly `obj.cpeTablePath`** - so on an installed server the maintained table is live from the first second without
any download, and a refresh (`fetchCpeTable`, at startup when stale and after every NVD cycle, https only) rewrites
that SAME file in place; a plugin upgrade re-unpacks the shipped copy (the newer shipped table then wins until the
next refresh). `loadRemoteCpeTable()` therefore tries the cache path first and `path.join(obj.pluginDir, 'cpe-table.json')`
second (the second entry only matters in dev `plugins.list` layouts/tests where code and datapath differ).
**Since v4.2.0 this file is the ONLY curated table** - the duplicated seed array (`SOFTWARE_CPE_TABLE`) that used to sit
in `lib/cpetable.js` was removed; adding a mapping is a PR on the JSON file only (process + validation: CONTRIBUTING.md),
never a code change. If neither file loads, `activeSoftwareTable()` is EMPTY (custom entries + the auto matcher still
work, the panel says so loudly) - deliberately no hidden fallback list. `cpeTableStatus().origin`
reports where the live file came from ('downloaded' | 'cache' | 'bundled'); custom (UI) entries always come first.
Entry regexes compile with the `i` flag ONLY;
bad JSON/regex → payload rejected, current table keeps running. Keys: `cpeTableEnabled`/`cpeTableUrl` (Vulnerabilities > Reports, NVD & CPE table).
A table row may replace `vendor`/`product` with **`kind:'driver'|'firmware'`** (out-of-NVD-scope marker, see below);
`applyCpeTableText` validates that shape and `matchTableEntry` returns it, kind rows win over the name heuristics.
Since v5.6.0 a CPE row may ALSO carry **`licenseType`** (optional, additive, no effect on matching): an SPDX identifier
(`MIT`, `Apache-2.0`, `GPL-2.0-only`, `curl`, ...) or one of exactly three descriptors - `Proprietary` (closed source, a
license must be bought), `Freeware` (closed source, free of charge, incl. hardware/OS-bundled vendor tools),
`Freeware (non-commercial)`. `obj.sanitizeLicenseType` caps it at 80 characters, restricts the charset to
`[A-Za-z0-9.+()\- ]` (it lands in a CSV cell and an HTML attribute) and keeps the CASE (SPDX ids are case-sensitive);
an unusable value is dropped and the mapping row still applies. `kind` rows never carry it. `obj.licenseTypeFor(name)`
is the single resolver (custom row first, then the table, `''` when nothing matches) and `obj.softwareProjection` calls
it once per program, so the software CSV column `License Type`, the Software list, `dev_details`/`sw_details`,
`sw_fleet` and the asset push all report the same value without re-deriving it. **It describes the SOFTWARE license,
never the purchase model of one installation** - Retail/OEM/Volume and the activation state are per-device facts from
`SoftwareLicensingProduct` (see the license engine), and seats/expiry belong to the asset system. Evidence, the
closed vocabulary, the `overrides` mechanism and the regeneration tool are documented in CONTRIBUTING.md
(`tools/gen-license-meta.js` + `tools/winget-ids.json`).

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

- **View composition (v5.3.0):** the panel is no longer one 3,240-line file. `views/assessment.handlebars` is a
  ~173-line SHELL (head/CSS, the two-layer nav, the container, `#invFloat`, the hover help box `#helpBox` - the floating
  location panel of v5.3.0 was removed in v5.4.0 - and the
  `(function () { … })();` brackets) that includes 11 panel partials and 20 JS partials (19 at v5.3.0, `js/help` was added in v5.4.0). The JS fragments are
  included **inside** the IIFE, so there is still exactly ONE closure and every helper (`$`, `esc`, `post`,
  `showMsg`, `selectSub`, …) resolves exactly as before - no namespace object, no global leak, no reordering.
  Rules for editing: a JS fragment must contain **complete declarations only** (never an unbalanced brace - the
  brackets belong to the shell), each fragment keeps its `// ---------- area ----------` banner, and no fragment
  may contain a literal `{{` (Handlebars would eat it) except `{{shortName}}`; `tools/check.js` syntax-checks
  every fragment on its own AND the composed script (it inlines the partials itself, so it still needs no
  dependency). The rendered output is unchanged: the split was proven by rendering the old and the new shell with
  the same data and comparing the static id set (205), the composed script text, all 47 info/hint help blocks and
  all report/export links.
- **Frozen panel inventory (`tools/fixtures/panel-inventory.json`):** every static element id, every info/hint
  help text, every report/export link and every `data-main`/`data-sub` panel of the rendered page is listed there,
  and `tools/test-views.js` asserts all of them are still present. This is the guard against the v4.9.6 class of
  bug (a restructure silently dropped id-less help prose). Removing something **on purpose** (e.g. issue #9 drops
  a column) means regenerating the fixture in the same commit - `node tools/gen-panel-inventory.js` - so the loss
  is a visible, reviewed diff instead of a silent one.

- **No scan on load (v4.4.0)**: opening the page (and *Apply* in the location panel) calls
  `scan&cached=1`, which reads the stored snapshot - instant, no device traffic - and says whose result it
  is ("Cached result of <time>"). **Scan & Review** is the only button that touches the devices; while it
  runs the rest of the server still answers (paced), and a second panel joins the running pass.
  Location selection = floating DIV (checkbox per mesh + "All locations"), persisted in
  `localStorage` key `invscanner_locations`; since v5.4.0 an inline row above the table (the floating panel and its
  toggle button are gone).
- Sortable columns (`data-key`, click toggles asc/desc, default EFFECTIVE severity desc since v5.4.0 with CVSS as the tiebreaker) + filters (text, effective severity,
  status: CVE/false positive/rated/unrated). Since v2.7.1 seven columns: CVE, Severity, CVSS, **Software & Version**
  (merged), Status, Affected Locations/Devices (device labels = given name first), **Manual Rating & Comment**
  (select + comment input + Save/False-positive buttons in one cell; sorted by the rating). The save/flag handlers
  find their controls via `tr.querySelector('.rating-sel'/'.comment-inp')` - never by cell index.
- Save/flag/unflag post the **meshIds of all affected selected locations** in one request; after success the row
  state is patched client-side (no rescan).
- All dynamic values rendered via `esc()` (comments stored raw → escape at output; never double-escape).
- The page heading (`h1#pageTitle`) follows the active tab (titles map in the tab click handler).
- The status line under the heading is tab-aware (v4.2.0): the NVD-feed/scan-schedule part (`span#statusMeta`) is
  shown only on the Assessment and Settings tabs (the tab click handler toggles it); every tab still ends with
  `plugin v{{version}}` (stale-deploy detection).
- The findings table's CVE column shows a ~85-character headline of the CVE description under the id
  (`cveNote()`, full text in the `title` tooltip, v4.2.0) - ratings should be possible without opening nvd.nist.gov.
- All buttons share one height (v4.2.0): `button` and `button.small` both compute to 32px (line-height 18px +
  6px vertical padding; `.small` only reduces font-size and horizontal padding), and text inputs/selects match it.
  A new control must NOT introduce different vertical padding.
- The inline script must not contain `{{` (Handlebars would consume it) except the intended `'{{shortName}}'` token;
  `tools/check.js` enforces both this and `node --check` on the extracted script.
- Every POST sends the header `X-InvScanner-Request: 1` (see Security below); a new fetch path must keep it.

- Settings tab (LAST nav button since v4.2.0): fetches `get_settings` + `get_locations` on load; each numeric
  field carries a source select
  ("set in plugin settings" / "from config.json" / "built-in default") offering `revert_setting` when overridden;
  Save posts the full field set, "Reset all" posts `reset=true`. The group table is filled client-side from
   `get_locations`; all-checked or none-checked is sent as an empty list = "all groups". Since v4.9.0 the CPE
   table, the NVD update + download log and the license-key config that used to live at the bottom of this tab
   are now sub-panels under Vulnerabilities and Software; they are the SAME fields (ids unchanged), and this
   tab's Save still writes them (the relocated panels reuse one shared `doSaveSettings` path).
   The group table's **Source column is never blank** (v5.4.1): `set here` / `from config.json` when a per-group
   notify threshold override exists, otherwise the pale `global threshold` - an empty cell was reported as
   confusing. The panel explains in one hint block what the per-group threshold does (it overrides the global
   severity floor for notifications from that group only).

- Navigation is TWO LAYERS with DEEP LINKS (v4.9.0, reworked by issue #9 in v5.4.0): FIVE main sections in the top
  bar (Devices | Software | Vulnerabilities | Exports | Settings) and a second row of sub-tabs that changes with the
  selected section. Each panel is tagged `data-main`/`data-sub` and `selectSub(main, sub)` shows exactly one, builds
  the sub-tab row, moves `#pageTitle`/`#statusMeta` and runs only that panel's loader. The URL hash carries
  `#<main>/<sub>`: the anchors hold the real hash and are NOT prevented, so the `hashchange` event is the single
  driver (`applyHash`) - a copied link restores the view and the browser back button walks through the visited
  views. An unknown or missing hash lands on `vulns/assessment` (the default since v4.9.0).
    Devices -> Device list (`loadDeviceList`), PC reset (`loadDrStatus`), Device report (ONE-CLICK link);
    Software -> Software list (`loadSwFleet`), Software updates (`loadWgTab`, the winget CONFIGURATION),
      Deployment (`loadSwTab`), License keys (`loadLicenseSection`, configuration + rules);
    Vulnerabilities -> Assessment (the findings table + the inline location row, the default landing),
      Vulnerability report (ONE-CLICK link), CPE table (`loadCpeTable`), NVD database (`loadNvdLog`);
    Exports -> NO panel at all (v5.4.1): the section is the row of the three bookmarkable CSV links;
    Settings -> General (scan/collection/lifecycle/notify options + device groups), Asset management
      (the optional external connector: target, credentials, mapping, test/push, last push per device, log).
  Entries that are really a DOCUMENT (the two printable reports, the three CSV files) are external links in the
  sub-nav row (one click, new tab, `class="subtab ext"` with a corner marker) instead of panels that only held a
  link button - the second click was pure friction, and their explanation moved into the hover help of the nav
  button (`nav.devreport`, `nav.vulnreport`, `nav.exphw/expsw/expvulns`). A link-only main section is resolved by
  `selectLinksMain(main)`, which paints the link row and KEEPS the active panel; the hash for it is `#exports`.
  Hover help (v5.4.1) is on the nav buttons as well, not only on action buttons.
  The issue-#9 rework removed the per-device/per-package TABLES that duplicated the unified views: the winget
  device table and the "Packages across all devices" table are gone (their content lives in the Device list and the
  Software list), the whole `OS updates & reboot` register is gone (its per-device actions, its fleet buttons, its
  reference line and its log all live in the Device list), and the license device table is gone (the Device list
  shows the collected count, collects for the ticked devices, and its Details view collects for one device). The
  old `Reports, NVD & CPE table` panel was split into three sub-tabs plus the new Exports section, and the Device
  report moved under Devices.
- **One action, one definition (issue #9).** The Device list does NOT re-implement the engine actions: its buttons
  call the functions that own them - `wgRunOne` (winget, dry or real), `osDeviceUpdate`/`osDeviceUpgrade`/
  `osFleetUpdates`/`osUpgradeFleet`, `wuDiag`/`wuDeviceRepair`, `rbNotify`/`rbRestart` (the typed-name confirm),
  `licCollectOne`, all defined in `js/winget`, `js/os` and `js/license`. `osRefresh()` is the single "the OS state
  changed, re-read it" hook and points at `loadDeviceList`, because the device list is the OS view now. The old
  `renderOsDevices`/`loadOsStatus`/`loadOsLog`/`renderWgDevices`/`renderWgPackages`/`renderLicDevices` and
  `wgToggleExclude` are gone with their tables.
- **Never save a whole config form from another view.** `wg_save_config` builds its body from the Software-updates
  DOM (`$('wgEnabled')`, the group checkboxes, `wgApp.cfg`), so calling it from a view that never loaded that panel
  would have saved `enabled:false` with EMPTY `updateMeshes`/`ignorePackages` - silently switching the automatic
  updater off. The single-key routes `wg_toggle_exclude` and `wg_toggle_ignore` exist for exactly that reason: they
  change ONE key server-side and copy the rest of the existing `wingetUpdater` section untouched (so keys that came
  from config.json are not pinned into the plugin file). Use them for per-device/per-package toggles.
- **Hover help (issue #9):** every action button carries `data-help="<key>"`; one delegated `mouseover` listener
  (`bindHelpBox`) shows `HELP[key]` in the fixed box at the lower right (`#helpBox`). The texts are the per-action
  breakdown of the info boxes, so the explanation is where the hand is. A new action button must add its key.
- **No double documentation (v5.4.1):** an info box at the top of a panel carries only what NO button hover can
  say (what the page is for, safety disclosures, cross-references); everything a specific button does lives in
  `HELP` only. When a control moves or is removed, its prose moves with it into the hover help - the inventory
  fixture makes the moved text visible in review.
- **On-demand details are cached (v5.4.1):** `dev_details` / `sw_details` answers are stored in
  `dlApp.details[id]` / `swfApp.details[name]` for the lifetime of the open page. Re-renders (sorting, filtering,
  the status poll) inject the cache and do NOT refetch; only the *Refresh details* button inside the block
  re-reads the server (`dlLoadDetails(id, true)` / `swfLoadDetails(..., true)`). Without that cache every poll
  looked like a stuck request loop (reported by the user).
- **Detail rows are keyed by NAME, and rows are found by walking up to the `<tr>` (v5.4.2):** a row index breaks
  as soon as a filter or a re-render shifts rows, and a `parentNode.parentNode` chain breaks the moment a button
  gets a wrapper (`.cellacts`) - both happened and made "Details" silently do nothing (no request at all). Use
  `rowOf(el)` (climb until `tagName === 'TR'`) and `swfKey(name)`/the `dld-<safeid>` ids for the detail cell.
- **Background polls belong to the open view only (v5.4.2):** every poller checks `currentSub` before scheduling
  (`dlPollIfBusy` -> 'devicelist', `wgPollState` -> 'updates', the license poll -> 'license', `drPollTimer` ->
  'reset', `swPollTasks` -> 'deploy', `asPollStatus` -> its generation token `asPollGen` plus 'asset'), and
  `selectSub` calls `stopViewPolls()` first. Polls for a hidden panel were pure traffic - and while a heavy
  fleet-index build occupied the server they were exactly the requests that came back as proxy 502s.
- **One calm button language in table rows (v5.4.1):** `button.rowbtn` (neutral grey-blue, same box height as
  `button.small`) for looking/configuring, `rowbtn act` (the single accent blue) for buttons that START something
  on a device, `rowbtn warn` (white with red outline) only for the reboot path; disabled states stay pale grey.
  Row action cells wrap in `<div class="cellacts">` (flex-wrap, max-width) instead of `white-space:nowrap` - a
  nowrap action column forced horizontal table scrolling (reported by the user). Fleet/toolbar buttons outside
  rows keep the classic green/red/purple semantics.

- Deploy tab (v4.0.0): library table + `<input type=file>` upload (FileReader chunks → `sw_upload`, sequential
  POSTs with resume-on-gap, progress text), source switch plugin-library ⇄ MeshCentral Server Files (two selects,
  filled by `sw_files` / `sw_serverfiles`), arguments input, location+device picker from `get_locations` +
  `sw_devices` (offline flagged, non-Windows/Linux disabled), and the task list from `sw_status` with per-row
  expander (device state, decimal+hex exit code, note) plus Retry-open / Cancel buttons. Uploads and tasks poll
   every 10 s while anything is open. The tab MUST keep sending the `X-InvScanner-Request` header on every POST
   (the shared `post()` helper does - a new fetch path must use it).

- PC Reset tab (v4.5.0): one row per **Windows** device from `dr_status` (Check result column = the cached probe
  facts, Last reset column = `devLast`). *Check* posts `dr_probe`; the reset buttons post `dr_reset` only after
  `window.confirm` and then a `window.prompt` that must match the device name (the server re-checks it, so a
  bypassed prompt is still refused). *Remove everything* first asks for the BitLocker recovery key when the probe
  says protection is on/unknown and sends `bitlockerAck=true`. The info box states explicitly that this is the
  one feature that restarts the device. It polls `dr_status` every 5 s only while a check/reset is in flight.

## Upgrade path (verified; user decision: NO polling)

- The swap/restart lives INSIDE server_startup (event-driven, called by MeshCentral after installPlugin);
  there is deliberately no timer/watchdog checking the disk. If a MeshCentral build never calls
  server_startup again, the upgrade lands on the next restart - accepted trade-off, documented.
  (The short `upgradeTreeReady` poll of v4.3.2 only runs AFTER server_startup detected an upgrade.)
- Node events: DispatchEvent(ids, source, event) persists via db.StoreEvent (meshcentral.js);
  wg runs raise per-device events (etype 'node', visibility 'nodes', targets [nodeid, meshid])
  so results show on the device's events page (viewmode 16).
- fixOwnPluginUrl() rewrites the stored plugin doc url to /pluginadmin.ashx?pin=...&action=show.
  The plugin list's name link does NOT use that url (it calls goPlugin -> `?pin=` only), which is why
  handleAdminReq treats a missing action as `show` since v4.3.2.
- normalizeCveVersion: ANY distro decoration (ubuntu/dfsg/+exp/bzr/~ /debN/snap wrapper) -> ''
  (unknown) - Debian/Ubuntu patch fixes into identical upstream versions; plain '-1' suffixes
  and epochs-without-decoration still extract their numeric core.

## Install, first start and file layout (support facts moved out of the README)

- **ZIP extraction is slow and alphabetical**: files land root-files-first, `lib/`+`tools/`+`views/` LAST, so
  `inventoryscanner.js` briefly exists as a 0-byte file and the Plugins page keeps showing **Disabled** until the
  archive is fully unpacked (slower on small VMs / with antivirus scanning). Never restart or re-install in that
  phase; the Plugins page shows no progress at all (MeshCentral UI limitation) and can print the OLD version until
  the page is refreshed. The plugin's own log lines on an upgrade (v4.3.2: in `nvd/nvd-download.log`, the
  "Plugin & NVD feed log" of the Settings tab - before they went to winget-update.log) are
  `upgrade detected ... restarting the MeshCentral server to load it` / `restarting MeshCentral now ...` (launcher
  present) or `... reloading without server restart` / `hot reload complete` (hot-swap fallback).
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
- **v4.3.2: restart instead of hot swap when possible.** Under MeshCentral's launcher (`meshServer.args.launch`
  set - the normal `node meshcentral` start forks the real server as a `--launch` child; verified in
  meshcentral.js `launchChildServer`) the detected mismatch calls `obj.scheduleUpgradeRestart(diskVer)`
  instead: timers of the old instance stop (`timerGen++`, `__superseded`), it waits `UPGRADE_RESTART_DELAY_MS`
  (5 s - installPlugin's `db.updatePlugin` with the new manifest runs right after server_startup) and polls
  `upgradeTreeReady` (new version in config.json, entry + every lib/*.js + assessment view non-empty, max
  2 min), raises a default-domain admin toast, prints `Server restart...` and exits 0 via `obj.exitProcess`.
  That stdout line sets `childProcess.xrestart = 1` in the launcher, which relaunches the server - exactly
  MeshCentral's own `resetserver` console command. Reason: the hot swap kept running on a process whose UI
  showed the old version and users clicked Upgrade twice. Without a launcher (`--launch` absent, e.g. some
  service wrappers/dev runs) an exit would STOP the server, so the hot swap remains the fallback.
- **Plugin list link:** MeshCentral's `goPlugin()` (views/default.handlebars) opens
  `/pluginadmin.ashx?pin=<shortName>` WITHOUT `action`; up to v4.3.1 `handleAdminReq` answered 404 there
  ("Not Found" when clicking the plugin name). A missing/empty action now means `show`.

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
  collector settles first; disabled/excluded/not-due devices short-circuit without any agent traffic). Since v4.3.0
  `wgQueueNode` follows the same opt-in as the scheduled batches: no `updateMeshes` -> nothing; the node document is
  `docs[0]` of the `db.Get` ARRAY (pre-4.3.0 it read `meshid` off the array and never matched, and an empty group
  list queued EVERY connecting device incl. Linux); non-Windows nodes (`wgIsWindowsNode`) are skipped.
- **cmd.exe line limit**: `wgTransport` produces ONE line; cmd refuses lines > 8191 characters ("command line too
  long", verified). Deploy (~2.5 KB) and OS (~3 KB) scripts are far below it; the winget script grows with the
  ignore list (measured 8.6 KB at 200 ids, 15.8 KB at 500) - such a run ends as "no marker in output".
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
   and restores/removes them afterwards. The target is validated `^\d{2}H[12]$` (throws otherwise). The running
   `wuauserv` caches the policy, so the upgrade mode restarts the service (`Stop-Service`/`Start-Service`, errors
   swallowed) right before the search and again after the restore - without that the search answers
   "ok: 0 found" until the next scheduled scan (issue #1, fixed in v4.2.2). Shared transcript
   helper `psTranscriptLines` (same protected folders as winget, file `invscanner-osupdate.log`).
- Linux script (`osBuildLinuxScript`, transported by `osLinuxTransport` = `sh -c "$(echo b64 | base64 -d | gzip -dc)"
  < /dev/null`): every package manager call reads /dev/null and logs to `/var/log/invscanner-osupdate.log` (symlink
  refused). States `ok | failed | unsupported | reboot-needed`. Upgrade = Ubuntu only: dist-upgrade, then
  `do-release-upgrade -f DistUpgradeViewNonInteractive`; with `/var/run/reboot-required` present it stops with
   `reboot-needed` (the tool refuses to run then). `Prompt=never` is reported, never changed.
- **apt repository errors (issue #2, v4.3.4):** one broken third-party repository (the reported case: an unsigned
  `dl.google.com/linux/chrome` InRelease) makes `apt-get update` exit non-zero even though every distribution
  repository downloaded fine. The old `step refresh apt-get -q update && step upgrade ...` chain therefore failed the
  WHOLE device for both modes. `aptrefresh()` now runs the refresh, and on a non-zero exit looks whether
  `/var/lib/apt/lists` got fresh `*Packages` files (GNU `find -mmin -60`; when `find` cannot answer, the run
  continues): yes -> `RC=0` and the last `W:`/`E:` line of the log goes to the device note as
  "apt-get update reported a repository problem: ... (the other repositories worked)"; no -> the install step is
  skipped (`APFAIL=1`), the non-zero exit stands and the note says "refreshed no repository at all". Used by BOTH
  modes (update before `apt-get upgrade`, upgrade before `dist-upgrade`/`do-release-upgrade`). A repository warning
  is never a failed device, and a device that only has stale lists is never reported ok.
- **Reboot policy (since v4.6.0, replaces the old absolute "never reboot" rule).** A reboot is no longer
  forbidden outright - it must be EXPLICIT and ANNOUNCED. Concretely: the winget / OS update / OS upgrade /
  deploy / Windows-Update-troubleshooter engines NEVER issue a reboot command themselves; when something
  needs a restart they report it (per device, and in the result) together with when Windows will perform it
  automatically (the automatic-restart deadline / outside active hours / next update install). TWO features
  restart a device on purpose, both per-device, manual and typed-name confirmed: the **PC Reset** (v4.5.0,
  via `systemreset`) and the **Force Restart** (v4.7.0, via the OS `shutdown`, which also messages the
  logged-on user first). The per-script `!/Restart-Computer|shutdown/i` assertions stay on the winget / OS /
  deploy / troubleshooter scripts (they prove those emit no reboot command); the only reboots are those two
  announced paths, never a batch, never a schedule, never automatic. See "PC Reset engine", "Windows Update
  troubleshooter" and "Force restart engine" below.

## Software deploy engine (v4.0.0, verified contracts)

- Three modules: `swstore` (library + task store + staging + cookie), `swdeploy` (scripts, dispatch,
  reconnect queue), `swdeploy-handlers` (routes). State: `obj.swFiles/swTasks/swUploads/swQueue/swPending/swActive`.
- **Delivery is MeshCentral's own batch-upload mechanism** (see the verified API fact): stage to
  `<filespath>/tmp/invsw-<16hex>-<12hex>.<ext>` (one copy per TASK, hashed ASYNC from the copy), then per device
  and per attempt: send `{action:'wget', overwrite:true, urlpath:'/<domainurl>agentdownload.ashx?c='+cookie(nid,f),
  path, folder, servertlshash}` followed by a runcommands script on the SAME agent socket (wget starts instantly,
  the script polls). Cookies are minted PER DISPATCH (5-minute decode timeout) - also for retries.
- **Scripts** (`swBuildWindowsScript`/`swBuildLinuxScript`, one statement per line, PS parser + `sh -n` asserted):
  wait up to `SW_FILE_WAIT_MIN` (15 min) for the file, verify SHA-256, NOTHING runs before the check passes, and
  (v4.3.0) **the verified bytes are the executed bytes**: Windows opens the staged file with `FileShare.Read`,
  hashes THROUGH that handle (`Get-FileHash -InputStream`) and keeps it open until the installer returned (write,
  rename and delete are refused meanwhile - verified on Windows 11, `Start-Process` and `msiexec` still read it);
  Linux copies a matching, non-symlinked download into `mktemp -d /var/tmp/invsw-run.XXXXXXXX` (mode 700,
  `umask 077`), re-hashes the copy and executes ONLY that private copy `"$P"`. Reason: `C:\Windows\Temp` lets
  standard users create files and `/var/tmp` is world-writable, so path-based check-then-run was a TOCTOU.
  v4.3.1: the Windows installer is NOT started from `C:\Windows\Temp` (DLL search order, CWE-427): the verified
  bytes are copied into `invsw-run-<guid>` (created atomically via `[IO.Directory]::CreateDirectory(path, acl)`
  with a protected SYSTEM + Administrators ACL, refused when it existed or the ACL differs), re-hashed through a
  write-locked handle, started from there with `-WorkingDirectory` = that folder, and the folder is removed after
  the run. If it cannot be prepared the device answers `error` and nothing runs.
  PowerShell literals go through `obj.swPsQuote`, which doubles `'` AND `U+2018 U+2019 U+201A U+201B` -
  PowerShell treats all five as single quotes (verified; doubling only `'` allowed injection by file name).
  Then `msiexec /i "..." /qn /norestart <args>` (`/update ... /quiet` for .msp),
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
- **Download ticket lifetime (v4.3.3)**: wget answers NOTHING, so a device that only waits used to be blind for
  `SW_FILE_WAIT_MIN` (15 min) and then said "no-file" with three guesses. Two changes:
  1. `swWgetRetry(entry, deadline)` re-sends the SAME wget with a FRESH cookie every `SW_WGET_RETRY_MS` (90 s) while
     the session is pending and the device is 'running' - the `tmpdl` ticket lives only 5 minutes
     (`decodeCookie(.., 5)`), and an agent-side wget can be dropped by its own 4-request cap or a proxy hop.
     Capped at `SW_WGET_RETRIES_MAX` = 4 re-sends (an agent keys its downloader by urlpath - piling up tickets
     forever could jam it); it calls `swEnsureStaged` first, because a swept stage file would answer 404 for the
     whole remaining lifetime of the task. The timer is `entry.dlTimer` and is cleared with the session
     (`swHandleResponse` / `swTimeout` / `swAbortDispatch`).
  2. `swWgetCrumbs(cbuf)` distils the agent's session-less console text (meshcore prints
     "Batch upload failed, because the server replied with HTTP nnn", a 'BadCert' or a socket error there) and a
     `no-file`/download-`error` answer carries it - or, when the device printed nothing at all, the hint that the
     agent never reached `/agentdownload.ashx` (its MeshServer URL / a proxy in front of the server).
     The scripts themselves distinguish the two physical cases: "nothing ever appeared at <stage>" vs
     "a file appeared but its SHA-256 never matched (last seen <16 hex>*)" (Windows `$invSaw`/`$invSeen`/`$invWhy`,
     Linux `SAW`/`SEEN`/`NOTE`). A re-send never renews `SW_FILE_WAIT_MIN`.
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
  (traversal impossible) - since v5.5.1 by ONE function, `obj.swServerFilesDir(meshId)`, used by the listing, by
  `sw_create_task` and by the dispatch: the group part matches `SW_GROUP_ID_RE` (`[A-Za-z0-9@$._-]` - real MeshCentral
  mesh ids are base64 with `@` and `$`; v5.5.0 refused every real group), the DOMAIN part `SW_DOMAIN_ID_RE` (it was
  not validated at all - `mesh/a\..\..\x/g` resolved outside `<filespath>`), and the folder is prefix-checked
  against `<filespath>`; every staged name is server-generated. Agent scripts contain zero caller-typed text
  beyond the quoted args/name fields.
- **Limits**: `SW_CHUNK_BYTES 49152` raw per POST (base64url stays below body-parser's 100kb urlencoded default -
  the pluginadmin route does NOT raise it, verified in webserver.js), `SW_MAX_FILE_BYTES` 2 GB, `SW_MAX_DEVICES`
  500/task, `SW_MAX_TASKS` 100 (pruned finished-first by creation date), staged files older than a day are swept
  (`swCleanStaleStaging` at startup and per sweep) unless an open task names them.
- **No configuration section, no automation**: a deploy NEVER runs by itself - tasks exist only because an admin
  created them. The winget `excludeNodes` list is intentionally NOT consulted (the admin selects targets
  explicitly; the device picker shows the flag). Multi-server peering: like upstream batch upload, only agents
  connected to THIS server get wget (`wsagents`), peers stay queued.

## PC Reset engine (v4.5.0, issue #4, verified contracts)

- One module `devreset.js`, one tab "PC Reset". Resets a **single Windows** device with the built-in
  `systemreset` tool. State: `obj.devPending` (live `probe`/`reset` sessions), `obj.devResults`
  (cached **probe** per node, the gate), `obj.devLast` (last **reset** record per node), persisted to
  `device-reset.json` (`devLoadResults`/`devSaveResults`); audit `device-reset.log` (`devLog`, ~5 MB
  rotate). No config section, **no automation**: a reset only happens because an admin typed the
  device name of a specific online device.
- **The announced reboot**: under the reboot policy a PC Reset is one of the two explicit restart paths
  (the other is the Force Restart, v4.7.0) - it restarts because a Windows reset cannot run inside the
  booted OS. Its reboot command is `systemreset
  -cleanpc|-keepfiles -noUI` (PowerShell `Start-Process`); the generated scripts never contain
  `Restart-Computer`/`shutdown`, so the per-engine "emits no reboot command" assertions of the
  winget/OS/deploy/troubleshooter scripts stay valid, and a test pins that `devStartBatch`/
  `scheduleDevReset`/`devPump` do not exist (no fleet reset, no scheduled reset).
- **Two scripts**: `devBuildProbeScript()` (read-only: `systemreset.exe` present, `BuildNumber`
  (fallback registry `CurrentBuildNumber`), the `-cleanpc`/`-keepfiles` switches by parsing
  `systemreset /?` AND the documented build gate `DEV_MIN_BUILD = 17763`, `reagentc /info` -> WinRE,
  `Get-BitLockerVolume` (fallback `manage-bde -status`) ProtectionStatus of `$env:SystemDrive`,
  `Win32_ComputerSystem.PartOfDomain`/`.UserName`, `Win32_Battery` (BatteryStatus 2 = on AC)); and
  `devBuildResetScript(mode, ack)` which **re-checks the facts on the device** (a probe can be
  stale), prints the marker line BEFORE `Start-Process` (the reboot wins the race), and refuses if a
  re-check fails (missing tool, old build, WinRE disabled, or "clean" while BitLocker protection is
  not `Off` and `ack` is false). Both go through `wgTransport` (base64+gzip, runcommands type 1) and
  answer one `@@INVDR@@{json}` line; both wrap `psTranscriptLines('invscanner-devreset.log')`.
- **Server-side gates** (`devModeAllowed` + `devResetHandler`): a fresh probe (`devProbeFresh`,
  `DEV_PROBE_MAX_AGE_MS` 6 h) whose `state` is `ok`, `systemreset` true, the mode supported, WinRE not
  `disabled`; for `clean`, BitLocker `off` **or** `bitlockerAck='true'` (an `unknown` state blocks -
  fail-safe); the typed `confirm` must equal the device name (given name, else host) case-insensitive;
  the device must be online and idle. Every rejection answers a specific `error`, never a silent no.
- **Session + mutual exclusion**: `invscanner-dr-<node>` on the shared `routeAgentCommand` hook,
  consumed first in the runcommands branch (`drOurs`) and buffered on `.cbuf` in the console branch
  (same ownership rules as sw/os/wg). `devDispatch` reserves the node synchronously and refuses when
  `devPending`/`wgPending`/`osPending`/`swPending` already holds it; the three pumps were extended to
  skip nodes with a `devPending` entry (one runcommands session per agent).
- **Answering and the watchdog** (`DEV_RESET_TIMEOUT_MS` 15 min, `DEV_PROBE_TIMEOUT_MS` 2 min): a
  reset usually has NO runcommands reply (the machine is already restarting), so `devResetTimeout`
  decides by presence - offline means `resetting` (as expected), still-online means `no-answer` (it
  did not start). A marker with `result:starting` is confirmed `resetting`; `result:refused` stores
  the device's own reason. Every outcome writes `devLast`, `device-reset.log` and a device event.
- Routes: `dr_status` / `dr_probe` / `dr_reset` (all `isAuthorizedAdmin` + the origin header); the
  `get_log` whitelist gained `reset`.

## Windows Update troubleshooter (v4.6.0, issue #3, verified contracts)

- One module `wutroubleshoot.js`, surfaced as two per-Windows-device buttons (originally **in the OS Updates tab**, since v5.4.0 in the device list)
  (no new tab, it belongs to the Windows Update story). State: `obj.wuPending` (live `diag`/`repair`
  sessions), `obj.wuResults` (last result per node, persisted to `wu-troubleshoot.json` via
  `wuLoadResults`/`wuSaveResults`); audit `wu-troubleshoot.log` (`wuLog`, ~5 MB rotate). `os_status`
  carries the cached `wu` record per device (no extra route).
- **Repairs, not msdt**: the `Get/Invoke-TroubleshootingPack` cmdlets were REMOVED in Windows 10 1709 and
  `msdt.exe /id WindowsUpdateDiagnostic` is an interactive wizard (invisible as SYSTEM, headless behaviour
  version-dependent), so the deterministic, auditable choice is to run the repairs the troubleshooter's
  "apply fixes" step performs. `wuBuildDiagnoseScript()` is read-only (services + start types, reboot
  state, download-cache size, last `Microsoft-Windows-WindowsUpdateClient` errors, `winhttp show proxy`);
  `wuBuildRepairScript()` restarts BITS/wuauserv/appidsvc/cryptsvc/msiserver, renames
  `SoftwareDistribution\Download` and `System32\catroot2` (timestamped, recreated empty), re-asserts the
  Automatic start types and starts the services - through an `invWuStep` harness so a partial run is honest.
- **Deliberately NOT done**: no `netsh winsock reset` (invasive, LSP-wide, needs a reboot), no
  `winhttp reset proxy` (would break managed devices - proxy is only reported), no SFC/DISM, and **no
  reboot** (`$invWu.rebootTriggered = $false`). Every script wraps `psTranscriptLines('invscanner-wutroubleshoot.log')`,
  answers one `@@INVWU@@{json}` line and emits no `Restart-Computer`/`shutdown`.
- **Reboot is reported, not triggered** (the v4.6.0 policy): both scripts read
  `WindowsUpdate\Auto Update\RebootRequired` + `Component Based Servicing\RebootPending` and write a plain
  `rebootNote` saying whether a reboot is pending and when Windows will restart the device automatically
  (automatic-restart deadline / outside active hours / next install); the repair additionally flags a locked
  folder as `rebootNote` "reboot and run again".
- Sessions/exclusion: `invscanner-wu-<node>` on the shared hook (consumed first in the runcommands branch,
  `.cbuf` buffering in the console branch); `wuDispatch` reserves the node and refuses if
  `wu/dev/wg/os/sw Pending` already holds it, and the four pumps skip a node with a `wuPending` entry.
  Watchdog `WU_TIMEOUT_MS` 8 min (`wuTimeout` -> state `timeout`). Routes `wu_diag` / `wu_repair`
  (`isAuthorizedAdmin` + origin header); the `get_log` whitelist gained `wu`.

## Force restart engine (v4.7.0, issue #6, verified contracts)

- One module `devreboot.js`, surfaced as **Notify user** + **Restart** buttons on every Windows AND Linux row
  of the OS Updates tab. State: `obj.rbPending` (live `reboot`/`notify` sessions), `obj.rbResults` (last
  restart/notice per node, `device-reboot.json` via `rbLoadResults`/`rbSaveResults`); audit
  `device-reboot.log` (`rbLog`). The SECOND explicit reboot path (after PC Reset) and the feature that can
  warn a user before a reboot.
- **User messaging** (the issue's "inform if possible"): the admin message is sanitized (`rbCleanMessage` -
  control chars and the `` ` $ " \ `` quoting chars removed, collapsed, ≤200) and travels base64 (`rbB64`) so
  it can never inject - decoded on the device and used ONLY as a single quoted argument. Windows: `msg '*' $m`
  pops a box for the interactive user (Pro/Enterprise; on Home it fails and is reported `not-delivered`).
  Linux: `wall "$m"` (reaches terminal users; GUI desktops may not see it - stated honestly). Both also
  surface `pendingReboot`/`source` and the logged-on `users` (Windows `Win32_ComputerSystem.UserName`,
  Linux `who` + `/var/run/reboot-required`).
- **Restart** = `shutdown` with a grace (`secs`, default 60, 0..3600) and the message in the OS banner:
  Windows `shutdown /r /t <secs> /c "$m"` (abort `shutdown /a`), Linux `shutdown -r +<ceil(secs/60)> "$m"`
  or `now` (abort `shutdown -c`). It runs `msg`/`wall` first, then `shutdown`. The reply arrives during the
  grace; with `secs:0` the machine may go down before it, so `rbTimeout` reads presence - offline =
  `rebooted` (coming back), still-online = `no-answer`.
- **Guard**: per-device, manual, `reboot_now` needs the device name typed (same confirm rule as PC Reset);
  `reboot_notify` does not (it changes nothing). Platform via `osPlatformOf` (windows/linux only - macOS and
  unknown OS refused). Online + idle only - `rbDispatch` reserves the node and refuses on any
  `rb/wu/dev/wg/os/sw` pending session, and all five pumps skip a node with an `rbPending` entry. No batch,
  no schedule (a test pins `rbStartBatch`/`scheduleReboot`/`rbPump`/`rbTargetNodes` absent).
- Routes `reboot_now` / `reboot_notify` (`isAuthorizedAdmin` + origin header); `os_status` carries each
  device's `rb` record + `rbPending`; the `get_log` whitelist gained `reboot`.

## License collection engine (v4.8.0, issue #7, verified contracts)

- One module `license.js`, a sub-panel under Software (a Settings section until the v4.9.0 nav regroup). The
  asset-management counterpart of the CPE table:
  a rule maps an installed-software NAME to WHERE its license is stored. Three rule types only, each with data
  fields and NO command: `{type:'registry', path, value}` (read with `Get-Item .GetValue`), `{type:'file', path,
  regex|jsonfield|line}` (read the file and extract), `{type:'wmi', class, property, filter}` (read one CIM
  property). Microsoft keys come separately from the `SoftwareLicensingProduct` WMI class (`PartialProductKey`).
- **Sources, custom wins** (mirrors cpe-table): curated `license-table.json` shipped in the repo + re-downloaded
  from `licenseTableUrl` (`fetchLicenseTable`/`licenseHttpGet`, https-only, size-capped), cached under the
  datapath, plus admin `license-custom.json` edited in the UI (`add_license`/`remove_license`). Every `match`
  and every file `regex` passes `obj.isSafeTableRegex`; fields length-capped; ≤8 rules/app, ≤60 apps/run
  (`sanitizeLicenseRules`, `licenseAppRules`).
- **Opt-in, on-demand, read-only, never sent anywhere**: `licenseCollectionEnabled` defaults OFF and there is
  no scheduler by default (an OPTIONAL schedule exists since v5.2.0, `licenseCollectIntervalHours`, default 0) - `lic_collect` refuses while it is off. The script only reads (GetValue /
  Get-Content / Get-CimInstance) and emits no write or reboot command (a test asserts this). The collected
  values are secrets: they are stored ONLY on this server under `data/<node>/license.json` (never in a log,
  never exported anywhere but the admin's own software CSV). `licenseLog` records counts, not the keys.
- **Per-user reads + wildcards (v5.5.0, issue #10):** rules may carry `perUser:true`. A per-user REGISTRY rule is
  written `HKCU:\...` and applied as `Registry::HKEY_USERS\<SID>\...` for every **already-loaded** hive (logged-on
  users; `Test-Path` on the hive decides) - offline hives are NEVER mounted: `reg load`/`reg save`/`LoadKey` are
  rejected by the script-shape test, because mounting a hive is a system modification and the issue rules it out.
  A per-user FILE rule replaces the `{{profile}}` placeholder with each existing profile directory (`{{profile}}`
  without `perUser` is refused). Exactly ONE `*` per path: in a registry path it must be one whole subkey segment
  (enumerated via `Get-ChildItem`, ≤20 matches, first non-empty value wins - the VMware `License.ws.*` case), in a
  file path a leaf pattern (≤5 candidate files, e.g. `*.mountainducklicense`); `*` in a registry VALUE is refused,
  as is `perUser` on wmi. Users are discovered read-only from
  `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList` (SID + `ProfileImagePath`, machine env expanded),
  capped at `LIC_MAX_USERS` (20); only profiles with a loaded hive (registry) or an existing directory (files) take
  part. **Every profile is probed inside its own `try` (v5.5.1)**: on a real Windows 11 `Test-Path` on the profile
  of `S-1-5-18` (systemprofile) throws "access denied", and in v5.5.0 one `try` around the whole loop ended the
  discovery there - NO user was ever found and every per-user rule failed silently (measured in audit 4). The
  service SIDs `S-1-5-18/19/20` are skipped (no users, they must not use up the cap). Every answer item carries the `user` (the profile leaf name) it came from.
- **First-ok-wins mapping (v5.5.0):** `licenseMapForNode` used to let the LAST item per name win, so a later failing
  rule masked a value an earlier rule had found; now the first `ok:true` item with a non-empty license wins (a test
  pins both directions), and the CSV's `License Source` shows `registry (user: alice)` style attribution. `add_license`
  accepts a `perUser` flag from the editor checkbox and stamps it onto every registry/file rule of the payload;
  `sanitizeLicenseRules` remains the single gate for table, remote and custom rules.
- **Transport + exclusion**: `invscanner-lic-<node>` runcommands type 1 on the shared hook (`.cbuf` console
  buffering); `licDispatch` reserves the node and refuses if any `lic/rb/wu/dev/wg/os/sw` session holds it,
  and all pumps skip a node with a `licPending` entry. Watchdog `LIC_TIMEOUT_MS` 6 min.
- **Microsoft license TYPE + activation state (v5.6.0, verified by running the real script on a real Windows 11):**
  the `SoftwareLicensingProduct` read used to take only `Description` + `PartialProductKey` and threw the rest away,
  although that class carries exactly the asset-management answer. It now also reads `Name` (product/edition),
  `LicenseFamily` (e.g. `Office19Professional2019R_OEM_Perp`), `ProductKeyChannel` (`Retail`, `OEM:DM`, `OEM:NONSLP`,
  `Volume:MAK`, `Volume:KMSCLIENT`, ...), `LicenseStatus`, `GracePeriodRemaining`, `EvaluationEndDate` and
  `ApplicationID`. The device reports NUMBERS and raw strings only; the server translates them
  (`MS_LICENSE_STATUS` + `msLicenseStatusText`, `msLicenseChannelType`) so the wording can be corrected without ever
  touching a device again, and `msLicenseSummary` counts `licensed` / `notLicensed` / `unknown` - a MISSING status code
  is `unknown`, never a violation. Measured effect on the audit machine: an Office edition in status 5
  ("notification mode (not activated)") became visible; before it was hidden behind `Description`.
  **Deliberately still NOT done:** no full product key. `PartialProductKey` (the last five characters) stays the only
  key material - no `DigitalProductId` decode, no `SoftwareLicensingService.OA3xOriginalProductKey`, no `slmgr` call,
  no activation change (all pinned by a script-shape test). Rationale: a full key is a usable secret, decoding one is
  what the AV-flagged key-finder tools do, and osquery (Apache-2.0) has no product-key table for the same reason.
- **CSV**: the `software` export gains two columns, `License` and `License Source` (`obj.licenseMapForNode`
  joins the collected value to each app by lower-cased name); the toolbar export and `action=export&type=software`
  both use the same builder. Since v5.6.0 it also carries `License Type` (curated, from the mapping table, therefore
  present WITHOUT any collection run) - column order is
  `... Software Install Date, License Type, License, License Source`. Routes
  `lic_status`/`lic_collect`/`get_license_table`/`add_license`/`remove_license`; `get_log` accepts `license`.

## Design decisions (with reasons)

1. **Two-stage matching (Dependency-Check style, fully offline):** custom entries + the curated `cpe-table.json`
   first (exact vendor+product; the table is ONLY that file since v4.2.0 - no code copy to drift); then `obj.autoMatchProductTokens` derives candidate product tokens from the display
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
   ~1 min after startup (baseline run). **The next run is armed only when the running pass has FINISHED**
   (`runScheduledScans(done)`, v5.5.1): before, `scheduleScans()` ran right after the asynchronous pass STARTED, while
   `lastScan` was still old, so the 60 s floor applied and a new full fleet pass started every minute until the first
   one ended (audit 4 measured 6 overlapping passes for a 5-minute scan). A watchdog plans the next run after one
   interval if a pass never finishes.
9. **Notification modes:** default = once per CVE (marked `(SEVERITY, new)`); `notifyUnratedRepeat:true` adds
   everything still unrated as `(SEVERITY, open)` on every run — the monthly to-do list. Rated/flagged → never again.
10. **Security:** CSV formula-injection neutralized in `formatCsvField`; strict id validation on writes AND on the
    scan query (key-poisoning guard); `isAuthorizedAdmin` on every route and the toolbar hook; the
    `X-InvScanner-Request` header on every POST (cross-site request guard); table/custom regexes pass
    `isSafeTableRegex` (since v5.5.1 a small scanner: a group repeated by `+ * {..}` must not contain a quantifier or an
    alternation at ANY depth, and numbered/named backreferences are refused - the v3.0.1 one-line regex missed
    `((a+))+$` (45 s on 29 characters) and `(a|a)+$` (72 s); one bad regex would stall the event loop for every
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
18. **License information is split into three layers, each with its own source and its own honesty rule (v5.6.0).**
    (a) **What a product IS licensed under** - curated once in `cpe-table.json` as `licenseType` (SPDX id or
    Proprietary / Freeware / Freeware (non-commercial)), evidence = the winget community manifest (MIT) or the
    project's own LICENSE, re-verifiable with `tools/gen-license-meta.js`. It is device-independent, needs no
    collection run, and an empty value means "no verified statement" - omitting is allowed, guessing is not (a row
    without a value must carry `_licenseNote`, asserted by the suite). (b) **What one installation holds** - measured
    on the device from `SoftwareLicensingProduct` (key channel Retail/OEM/Volume, edition family, activation status);
    this is the only layer that can say "not activated", and it exists only for Microsoft products because only they
    expose it. (c) **What was purchased** - seats, expiry, price: NOT on any device, so the plugin does not invent it;
    it belongs to the asset system the connector pushes to. Mixing the layers was the trap: a static field cannot say
    "Subscription" for Office (the same product is sold both ways), and a per-device channel cannot say "MIT" for
    Firefox. Rejected alternatives: a generic registry value-name sweep (measured on a real Windows 11: 16 candidates
    at depth <= 3 under SOFTWARE, almost all noise - Windows `ProductId`, IE registration, `Schema Library` - so
    auto-detection would fill the License column with garbage) and per-device `winget show` calls (2.5 s per package,
    NO JSON output in winget 1.29, and localized labels - the server-side manifest route is both cheaper and stable).
    Also rejected: decoding full product keys (`DigitalProductId`, `OA3xOriginalProductKey`) - see the license engine.

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

| Key (under `settings.<section>`) | Default | Settings/Updates/OS tab control |
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
| `vulnerabilityScanner.osUpgradeUrgentDays` | `365` | "OS upgrade is urgent this many days before support ends" (0 = only after support ended; drives `urgent` vs `available` in the OS Updates tab) |
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

**The suite must not fill the disk (v5.6.0, was a real 47.9 GB incident).** Two rules a new step has to follow:
1. **Never let a step call the real `server_startup()` without seeding a 0-CVE feed first** - call
   `seedEmptyNvd(inst, datapath)` before it. Otherwise `ensureNvdData()` downloads the COMPLETE NVD feed set
   (~2.8 GB) into the step's temporary datapath, and `scheduleUpdate()` can arm a second download 60 s later.
   This is the same trick the CI container test uses; with it a full run takes ~13 s instead of minutes.
2. **Create scratch space through `tools/workdir.js`**, never by hand: `fs.mkdtempSync` is wrapped and cleaned up
   automatically, and a self-built timestamped path must go through `workdir.tmpDir(name)` / `workdir.tmpFile(name)`
   so it is registered too. Before v5.6.0 every directory survived the run - 12,821 of them had piled up
   (47.9 GB, ~8-9 GB per run). `INVSCANNER_WORKDIR` redirects all of it out of the system temp folder onto a
   dedicated working directory; unset (the default, and CI) keeps `os.tmpdir()`, so CI behaviour is unchanged.
   A generated agent script in a test must never hard-code `%TEMP%` and then read the file back via `os.tmpdir()` -
   those two diverge as soon as the base is redirected (the v4.3.1 dll step did exactly that); use one resolved
   path on both sides, quoted, so a working folder with spaces works too.


CI (`.github/workflows/meshcentral-integration.yml`, pure administration - it never touches plugin code
or releases): `npm test` on every push/PR (node 18 + 24), plus a live-container run: the current
`meshcentral/meshcentral` Docker image with the plugin installed flat under `<datapath>/plugins/inventoryscanner`
(`plugins.list` loader, a 0-CVE NVD feed file so startup never downloads gigabytes) driven by
`.github/integration/meshcentral-server-test.sh`, which calls the core pluginadmin.ashx routes (auth gates, scan, reports, CSV, settings, CPE, winget/OS status, deploy, logs - NOT the device-changing engine routes wg_run/os_run/dr_*/wu_*/reboot_*/lic_collect/as_*, which the mocked suite covers) AND a **live
linux agent**: a Debian-variant container downloads the agent binary (`/meshagents?id=6`) and its install
material (`/meshsettings?id=`, both without login, exactly like the real installers) from the server, so the
collector round trip, the CSV/report views over a genuinely collected software list and one end-to-end .sh
deploy (sw_upload -> task -> agent wget + SHA-256 check + runcommands -> state ok, exit code 0, marker file
verified inside the agent container) are proven, not mocked. Auth model of the CI server: `ciadmin` created by
MeshCentral's own `--createaccount`/`--adminaccount` one-shot CLIs, session auto-established via `--user ciadmin`
(a dotted cert name + `agentaliasdns` are required, otherwise MeshCentral silently drops to LAN mode and agents
get MeshServer=local). The daily schedule re-runs the container test only when Ylianst/MeshCentral published a
release that is not yet marked verified for THIS commit (cache key = release tag + `github.sha`, v4.3.0 - before,
a tag verified once skipped every later plugin change on the schedule); `workflow_dispatch` runs it on demand,
optionally against the `master` image. Workflow hardening (v4.3.0): `permissions: contents: read` only (the cache
actions use the runner token, `actions: write` was unnecessary), every action pinned by commit SHA (tag in a
comment), step outputs reach shell scripts as `env:` never as `${{ }}` inside `run:`. Known gaps: the live run
uses the `plugins.list` dev loader (the web-installer ZIP/DB/hot-swap path is not exercised live), no Windows
runner (PowerShell checks skip on Linux), Docker images are not digest-pinned (deliberate: the point is testing
the CURRENT release).

Data dumps from support sessions (CSV exports, browser output TXTs) live OUTSIDE the repo (they sit in the
MeshCentral install folder) and root `/*.txt` + `/*.csv` are gitignored as a guard - never copy them in.
- `tools/check.js`: `node --check` on the entry AND on every `lib/*.js`, the module wiring (each lib file is in the
  entry's `modules` list and vice versa, no orphan), the module rules (no `__dirname` in `lib/`, entry stays thin),
  inline-script syntax/`{{`-hazard check over EVERY `<script>` block of every view (v4.3.0; the report views must
  contain none), JSON validity of config files, and view-name↔render-name consistency over
  the WHOLE JS tree (the `res.render()` calls live in `lib/routes.js`/`lib/reports.js` since v3.5.1).
  Must run anywhere (no dependencies).
  Since v5.3.0 it also owns the view-modularisation guards, still without any dependency: every `{{> partial }}`
  reference resolves to a file in `views/partials/` and no partial file is an unreferenced orphan (the same
  symmetry rule as `lib/` ↔ the modules list; handlebars comments are stripped first, because documentation
  legitimately quotes the partial syntax), each `js/*` fragment is `node --check`ed **on its own** (wrapped in a
  function) and screened for a stray `{{`, and the composed panel script is checked by INLINING the partials
  itself - so the combined-syntax guard survived the split without needing handlebars.
- `tools/test-plugin.js`: 793 behavioral assertions at v5.6.0 (105 steps; 790 PASS + 3 SKIP on Windows without a POSIX shell) against the real module (mocked MeshCentral DB/webserver):
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
  Runner guards (v4.3.0, audit 3): every step has a 120 s watchdog and an exit guard compares completed with
  registered steps - before, a step that never called `next()` ended the process with exit 0 and silently
  skipped everything after it. PowerShell-based checks go through `runPs()`, which returns null (SKIP) ONLY when
  PowerShell is not installed (ENOENT); a parse error or exception is a FAIL (before, every failure was printed
  as "SKIP ... PowerShell not available"). On the Linux CI runner the PowerShell checks are skipped, on a machine
  without a POSIX shell the two `sh -n` checks are: the assertion count therefore depends on the platform
  (793 on Windows with both shells present at v5.6.0; the v4.3.1 real-run deploy check runs on Windows only).
  The module-state guard checks COLUMN-0 declarations in `lib/` (only `const x = require(...)` allowed) and
  additionally that the `attach` bodies hold no 4-space-indented locals.
  Requests in tests carry `headers: XHDR` (the panel header); the test admin has `domain: ''`.
  Tests that assert on emitted CODE TEXT use `pluginSrc()` (entry + all `lib/*.js` concatenated) - never read
  `inventoryscanner.js` alone, that file has no implementation any more. The upgrade test copies the whole
  plugin tree including `lib/`, exactly like the installer unpacks it.
  **An assertion inside a `mockRes` callback must NEVER throw (v5.6.0, learned the hard way).** The route's own
  `try/catch` answers a second time, so instead of one readable FAIL the suite prints
  `FAIL response object answered 2x, payload={"error":"Cannot read properties of undefined ..."}` - and because the
  callbacks are nested on ONE synchronous stack, a throw three levels deep produces three of those lines and the step
  never calls `next()` (the 120 s watchdog then fails the run). Guard every lookup before indexing it
  (`var row = pick(entries, m) || {}`, `(rec && rec.ms) || []`) and assert on the guard. Two more traps of the same
  family: `show_cpe` is a **GET** action (posting it answers an error, not a list - call `obj.showCustomCpe` directly),
  and the license rules travel in a **plain base64** blob INSIDE the script while `wgTransport` gzips the whole script,
  so reading the rule values back needs two decode steps, not one.
- `tools/test-views.js`: compiles all three views and renders them with mock data **and empty data**; without
  handlebars it SKIPs locally but FAILS when the `CI` environment variable is set (v4.3.0). Since v5.3.0 it
  registers `views/partials/**` with the express-handlebars naming rule before rendering, asserts the panel
  resolves a partial at all, and checks the rendered page against the frozen inventory
  `tools/fixtures/panel-inventory.json` (every static id, every info/hint help text, every report/export link,
  every `data-main`/`data-sub` panel). Regenerate that fixture with `node tools/gen-panel-inventory.js` whenever
  something is removed ON PURPOSE, and commit both together.

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
- The panel does NOT scan on load since v4.4.0 (it reads the snapshot, `scan&cached=1`); the device work
  happens only on "Scan & Review" and on the scheduled runs. Keep it that way - a page open that scans a
  few hundred devices made the whole server unresponsive. Every path that iterates devices (scanMeshCves,
  buildOverallReport, buildCsvForNodes) must therefore go through `obj.pacedEach`, never a bare forEach.
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
rating/FP → Settings tab (scanner/collection options, per-key override of
config.json, incl. the maintained CPE table with overrides) → two printable reports with navigation and
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
v4.0.0: software deployment (Deploy tab) - install MSI/MSP/EXE/DEB/RPM/SH on chosen devices or whole
locations, packages from chunked browser upload, from MeshCentral Server Files or from the plugin's server folder;
optional command-line arguments; delivery via the agent's own wget + agentdownload cookie (MeshCentral's own
batch-upload transport, verified in upstream source), SHA-256 verified on the device BEFORE execution; offline
devices queue and install on reconnect (agent-connect hook + 10 min sweep); results per device (state, decimal+hex
exit code, note), device event + admin toast + software-deploy.log. Never automatic, never a reboot. New modules
swstore/swdeploy/swdeploy-handlers; the winget and OS pumps now also honour `swPending` (one runcommands session
per agent). Test suite: 417 assertions in 71 steps (the winget `due:` fixtures got the midnight fix described in
the Testing section).
v4.1.0: UI structure only - the overloaded Updates tab is split into three one-feature tabs with
their own nav buttons: **Updates** (winget updater), **OS Updates** (the v3.5.0/v3.6.0 OS engine, previously an
`<h2>` section inside Updates) and **Deploy** (already separate since v4.0.0). No route, no handler, no data
shape and no element id changed; only the HTML moved and the tab-open handlers were separated.
v4.2.0: panel review + maintenance. The CVE column shows the description headline under the id
(`cveNote()`, tooltip = full text); the NVD/scan part of the status line is tab-aware (Assessment + Settings only,
`plugin v` everywhere); the CPE Mapping tab became a section of the Settings tab, which is now the LAST nav button;
all buttons share one height. Maintenance: the duplicated mapping table (`SOFTWARE_CPE_TABLE` in
`lib/cpetable.js`) is GONE - `cpe-table.json` is the only curated copy; with no table file the curated stage is
empty (custom + auto matcher still work, the UI says so). No POST action, route or agent script changed; the
`get_cpe_table` `source` values are now 'remote'/'custom' (plus `cpeTable.source` 'remote'|'none'). Test suite:
418 assertions in 71 steps - the CPE steps now pin the single-source invariant and the matching tests
load the bundled table exactly like a real `server_startup` does.
v4.2.1: table layout fixes, no behaviour change. winget Packages view: Package+Id merged (id under
the name), the four count columns merged into one `N ready, N ok, N failed, N skipped` cell, Actions stacked
vertically - the table finally fits the screen. winget Devices view: Device/Group/Online/Excluded/Actions get
fixed compact widths so `Last run` takes the remaining width (that is where the interesting text is). Deploy:
the location/device picker wraps (flex) instead of scrolling sideways, and the selection summary (and the create
confirm) count devices inside an already-ticked location as part of that location ("1 whole location(s) + 2
additional device(s)") - the old "1 device(s) + 1 whole location(s)" double count is gone; the POST body still
 sends every ticked id (the server task store keys by node id, so duplicates were and are harmless).
v4.2.2: fix for issue #1 - the OS release upgrade ended in "ok: 0 found" because the running
wuauserv cached the TargetReleaseVersion policy and only re-reads it on a service restart; the upgrade script
now restarts wuauserv right before the search and again after the policy restore (update mode never touches it).
Security: the CodeQL `js/bad-tag-filter` alert on tools/check.js is fixed - the inline-<script> extraction regex
is now case-insensitive and tolerates tag attributes (`/<script\b[^>]*>([\s\S]*?)<\/script>/i`).
v4.3.0 (audit 3 - details in AUDIT.md): deploy scripts quote all five PowerShell quote characters
(`swPsQuote`) and execute exactly the verified bytes (Windows: hash through a held `FileShare.Read` handle; Linux:
re-hashed private `mktemp -d` copy); `wgQueueNode` honours the group opt-in, reads `docs[0]` and skips non-Windows
nodes; `sw_rescan_library` no longer re-imports indexed files; server notifications carry `domain:''`. Tests: per-step
watchdog + exit guard, `runPs()` (failures no longer SKIP), column-0 module-state check, check.js over all script
blocks, test-views FAILS in CI without handlebars, 431 assertions / 72 steps. CI: least-privilege permissions,
SHA-pinned actions, env-passed step outputs, cache key with the commit sha. Panel texts corrected (see AUDIT.md T1-T8).
v4.3.1: follow-up fixes. The Windows deploy script no longer starts the installer from
`C:\Windows\Temp` (a standard user could plant a DLL next to it, CWE-427): it runs from a fresh
`invsw-run-<guid>` folder with a protected SYSTEM + Administrators ACL. CodeQL `js/bad-tag-filter` #3 in
tools/check.js fixed (end tags like `</script >`, plus an opener/block count check). Shorter plugin description.
Test suite: 434 assertions / 72 steps on Windows.
v4.3.2: plugin list + upgrade fixes. Clicking the plugin name on My Server -> Plugins opened
`pluginadmin.ashx?pin=inventoryscanner` without `action` and got 404 - a missing action now renders the panel.
An Upgrade now restarts MeshCentral by itself (launcher restart signal, see "Plugin upgrade path") instead of the
hot swap that left users clicking Upgrade twice; the hot swap stays as fallback without a launcher. The
"never rebooted" note was removed from the plugin description (config.json/package.json). Upgrade/restart/hot-reload
lines moved from winget-update.log to nvd-download.log (Settings tab, heading now "Plugin & NVD feed log"). CI: the
container test opens the panel without action and asserts the `--launch` child. Tests: +7 assertions,
+1 step: 441 / 73 on Windows with PowerShell + POSIX shell (verified run without sh: 439 PASS + 2 SKIP).
v4.3.3: deploy is no longer blind while a device waits for its installer (field report: a 7-Zip .exe
ended in "no-file - the download never arrived (wget failed, wrong hash, or the file is still in transit after
15 minutes)" with no way to tell which). A waiting device now gets its agentdownload wget RE-SENT with a fresh cookie
every 90 s, max 4 times (`swWgetRetry`; the tmpdl ticket lives only 5 minutes and an agent can drop the request), and
the staged copy is re-checked before every re-send (a swept file would answer 404 forever). The answer now carries the
agent's own console words when there are any (`swWgetCrumbs`: "the server replied with HTTP 404", 'BadCert', socket
errors) or the explicit hint that the agent never reached /agentdownload.ashx; the scripts separate "nothing ever
appeared at ..." from "a file appeared but its SHA-256 never matched (last seen ...)". Tests: +10 assertions, +1 step:
451 / 74 on Windows with PowerShell (the two sh -n checks skip here, CI runs them).
v4.3.4: issue #2 - one broken third-party apt repository no longer fails a whole OS update/upgrade.
`apt-get update` exits non-zero when ANY source is unusable (reported: `W: GPG error` from dl.google.com/linux/chrome)
even though all distribution repositories downloaded, and the `step refresh apt-get -q update && step upgrade ...`
chain aborted the device on that - in BOTH modes. New `aptrefresh()` checks `/var/lib/apt/lists` for fresh
`*Packages` (GNU `find -mmin -60`, continues when `find` cannot answer): refreshed -> `RC=0` and the last `W:`/`E:`
line becomes the device note ("reported a repository problem ... the other repositories worked"); not refreshed ->
`APFAIL=1`, the install/dist-upgrade step is SKIPPED and the failure stands with the note "refreshed no repository at
all". A warning is never a failed device, and a device with only stale lists is never reported ok. Tests: new step 75
runs the generated `aptrefresh()` in a REAL POSIX shell with `apt-get`/`find` shims (3 assertions there, SKIP without
sh), the script checks pin both call sites, and sh -n now parses the update AND the upgrade script:
452 PASS + 3 SKIP / 75 steps locally.
v4.4.0: the panel stops scanning on every page open, and nothing blocks the server any more.
- Panel: opening the page and Apply in the location panel now read the stored snapshot (action=scan&cached=1 - no device
  is touched, answer carries cached:true/cacheTime/missing, scanning:true while a live pass runs); Scan & Review is
  the only button that queries devices, and a second one joins the running pass (obj.scanInFlight) instead of
  doubling the work. A live scan also updates the snapshot.
- Server stays usable: obj.pacedEach (scheduling.js, SCAN_PARALLEL 4, at most one batch per event-loop turn) now
  drives scanMeshCves, buildOverallReport and buildCsvForNodes - the old firehose forEach over hundreds of devices
  was one long synchronous turn that starved every other request (the reported 15 s of unreachable tabs).
- CSV: hardware/software/vulns exports are sorted column by column left to right (csvCellCompare = empty first,
  case-insensitive NATURAL order so Firefox 9 < Firefox 121; escaping happens after the sort, so the formula
  guard is untouched). The toolbar exports share the builder, so they are sorted too.
- Tests: +15 assertions, +2 steps (467 / 77): cached read never calls scanMeshCves, current ratings applied to a
  stored snapshot, missing locations reported, one pass answering two panels, snapshot stored, pacedEach yields
  to the event loop and never exceeds SCAN_PARALLEL, both CSV orderings.
v4.5.0: issue #4 - reset a Windows PC. New module `lib/devreset.js`, new "PC Reset"
tab, new routes `dr_status` / `dr_probe` / `dr_reset`, new state `device-reset.json` + audit log
`device-reset.log`. It resets ONE online Windows device with the built-in `systemreset` tool, "Keep my
files" or "Remove everything". **This is the documented exception to the "never reboot" invariant** - a
reset restarts the machine into Windows RE on purpose - so it is strictly per-device, manual and never
scheduled/batched, the exact device name has to be typed, and a read-only **Check** (systemreset, build
>= 17763, WinRE, BitLocker, domain, battery, logged-on user) is required first and re-checked on the
device. "Remove everything" is hard-blocked while BitLocker protection is on/unknown until the recovery
key is confirmed. Same transport as the OS engine (invscanner-dr- sessions, @@INVDR@@ marker,
wgTransport); the winget/OS/deploy pumps now also skip a node with a reset in flight; the timeout tells
"resetting" (device went offline into WinRE, the normal path) from "no answer" (still online).
Tests: +26 assertions, +3 steps (496 / 80, i.e. 493 PASS + 3 sh -n SKIP on Windows): probe/reset script shape and
the never-reboot token scan with the systemreset-only exception, every mode gate (BitLocker on/unknown,
stale/missing probe, WinRE off, unsupported build), the typed-name + ack + busy + offline route paths,
the console-channel probe answer, and both timeout verdicts.
v4.6.0: issue #3 - Windows Update troubleshooter, and the "never reboot" rule becomes a
"reboot is explicit + announced" policy.
- New module `lib/wutroubleshoot.js`, surfaced as **Diagnose** / **Troubleshoot** buttons on every Windows
  row of the OS Updates tab (no new tab). Because the `Get/Invoke-TroubleshootingPack` cmdlets were removed
  in Win10 1709 and `msdt.exe /id WindowsUpdateDiagnostic` is an interactive wizard, the troubleshooter is
  implemented as the REPAIRS IT APPLIES: Diagnose reads the WU services + start types, whether a reboot is
  pending (and when Windows restarts automatically), the download-cache size and the last
  `WindowsUpdateClient` errors (read-only); Troubleshoot restarts BITS/wuauserv/appidsvc/cryptsvc/msiserver,
  resets `SoftwareDistribution\Download` + `System32\catroot2` and re-asserts Automatic - through a per-step
  ok/fail harness so a partial run stays honest. No winsock/proxy reset, no SFC/DISM, and **no reboot**.
- Policy change: a reboot is no longer forbidden outright, it must be explicit and announced. The update /
  deploy / troubleshoot engines emit no reboot command (the `!/Restart-Computer|shutdown/i` assertions stay
  and now also cover the troubleshooter) and always report a pending reboot with when Windows handles it;
  the only feature that restarts a device is still the manual per-device PC Reset. The reworded test now
  pins "only PC Reset reboots, the troubleshooter adds no reboot path, no batch/scheduled repair".
- Wiring: `invscanner-wu-` sessions on the shared hook (runcommands + console buffering); `wuPending` added
  to the mutual-exclusion of the winget/OS/deploy/reset pumps and dispatches; `os_status` carries each
  device's last `wu` record; `get_log` accepts `wu`; state in `wu-troubleshoot.json`, log `wu-troubleshoot.log`.
- Tests: +15 assertions, +3 steps (511 / 83, 508 PASS + 3 sh -n SKIP on Windows): diagnose read-only shape,
  repair step-harness shape + no reboot/winsock/proxy, PS parser, the busy/offline/non-Windows route gates,
  diagnose + partial-repair answers consumed and stored with the reboot note surfaced, os_status carries it,
  the get_log route, the pump-exclusion wiring and the timeout. Version 4.5.0 -> 4.6.0.
v4.7.0: issue #6 - force restart a device + inform its user, and the reboot policy now names
its two explicit paths.
- New module `lib/devreboot.js`, surfaced as **Notify user** + **Restart** on every Windows AND Linux row of
  the OS Updates tab. Useful before/after an upgrade.
- **Notify user** sends the admin's message to the logged-on user WITHOUT rebooting (Windows `msg`, Linux
  `wall`) and reports whether a reboot is already pending and who is logged on. **Restart** reboots after a
  grace (default 60s, 0..3600) carrying the same message in the OS shutdown banner (`shutdown /r /t` on
  Windows with a `shutdown /a` abort hint, `shutdown -r +m` on Linux). The message is sanitized and base64
  -wrapped so it can never inject; it is only ever used as a quoted argument.
- Reboot policy wording: PC Reset (v4.5.0) and Force Restart (v4.7.0) are the ONLY two things that restart a
  device; both are manual, per-device and typed-name confirmed, never a batch, never scheduled, never
  automatic. The troubleshooter and the update/deploy engines still emit no reboot command.
- Wiring: `invscanner-rb-` sessions (runcommands type 1 Windows / type 3 Linux) on the shared hook; `rbPending`
  added to the mutual exclusion of all five pumps and the dispatches; `os_status` carries each device's `rb`
  record; `get_log` accepts `reboot`; state in `device-reboot.json`, audit in `device-reboot.log`. macOS /
  unknown-OS and offline/busy devices are refused. Routes `reboot_now` (typed-name confirm) / `reboot_notify`.
- Tests: +21 assertions, +3 steps (532 / 86, 529 PASS + 3 sh -n SKIP on Windows): the sanitizer strips shell /
  PowerShell metachars + caps, the four scripts' shapes (msg/wall/shutdown/grace, marker, no literal message),
  PS parser, windows(type 1)+linux(type 3) dispatch, the typed-name/offline/busy/unsupported-OS gates, a
  scheduled answer with a pending reboot + user surfaced, os_status carrying `rb`, the get_log route, both
  timeout verdicts and the "only PC Reset + Force Restart reboot, no batch/schedule" policy test.
  Version 4.6.0 -> 4.7.0 (config.json + package.json + @version); plugin description unchanged.
v4.8.0: issue #7 - software license keys / info in the inventory CSV (asset management).
- New module `lib/license.js` + a "License keys" section in the Settings tab. Like the CPE table, a curated
  `license-table.json` (shipped, re-downloaded from its URL, cached) + admin custom rules map an installed
  program name to WHERE its license is stored, via three data-only rule types: a registry value, a file
  (regex group 1 / JSON field / line number / raw), or a WMI class property - no command rule, so the table
  can never run code. Microsoft keys come from the SoftwareLicensingProduct class behind a switch.
- OPT-IN and on-demand: `licenseCollectionEnabled` defaults OFF, there is no scheduler, and the script is
  READ-ONLY (GetValue / Get-Content / Get-CimInstance; a test asserts no write and no reboot). The collected
  keys are secrets kept ONLY on this server (`data/<node>/license.json`), logged as counts not values, and
  added to the software CSV as the `License` + `License Source` columns (toolbar and export use the same
  builder). `lic_status` / `lic_collect` (one device or all online Windows) + the custom-rule editor routes.
- Wiring: `invscanner-lic-` sessions on the shared hook; `licPending` added to the mutual exclusion of all
  five pumps and every dispatch busy check; `get_log` accepts `license`. Rules/regexes pass isSafeTableRegex.
- Tests: +23 assertions, +2 steps (555 / 88, 552 PASS + 3 sh -n SKIP on Windows): opt-in default-off + no
  scheduler, table apply + regex-safety + rule-type/field sanitization, custom-wins resolution, the read-only
  script shape (base64 rules, no literal path, no write/reboot) + PS parser, collect refused off/non-Windows/
  offline/busy, dispatch consumed + stored + `licenseMapForNode` + `data/<node>/license.json`, add_license /
  remove_license / a rejected unknown type, lic_status summary, get_log, the pump-exclusion wiring, and the
  two new License columns actually appearing in the software CSV. Version 4.7.0 -> 4.8.0.
v4.9.0: issue #8 - two-layer navigation, panels regrouped by topic.
- The old flat tab strip (Assessment | Updates | OS Updates | Deploy | PC Reset | Settings, plus a line of
  report/export links) became two layers: four MAIN sections Devices | Software | Vulnerabilities | Settings,
  each with its own row of SUB-tabs built on demand (`navTree` + `renderSubnav` + `selectSub(main, sub)`).
  Devices -> Software updates / OS updates & reboot / PC reset. Software -> Deployment / License keys.
  Vulnerabilities -> Assessment (default landing, with the location panel) / Reports, NVD & CPE table.
  Settings -> General. The report + CSV-export links and the NVD update + download log + CPE table moved out of
  the Settings tab and the top bar into the Vulnerabilities sub-panel; the License keys section out of Settings
  into Software. Their config inputs (setUpdateHours, setCpeTable*, setLic*) keep the SAME ids so loadSettings
  and the save form still work; the relocated panels reuse one shared `doSaveSettings` save path.
- PRESENTATION ONLY: no route, no handler, no engine, no data file changed; every existing element id and all
  one-runcommands-session-per-agent / reboot-policy invariants are untouched. Each `.tab-content` is now tagged
  `data-main`/`data-sub` and the controller shows panels by those attributes (not by id) so it never guesses.
- Deferred out of this release (then shipped in v4.9.5): the two NEW views asked for in issue #8 - one unified
  per-device action list with option checkboxes, and one fleet-wide software list. v4.9.0 only regroups what exists.
- Tests: +8 render assertions in tools/test-views.js (four main sections, sub-nav container, old navtab markup
  gone, the two new panels exist once, the extracted blocks carry main+sub tags, the moved config ids appear
  exactly once - no collision, and the shared save path). check.js still node --check's the inline script.
  test-plugin unchanged (552 PASS + 3 SKIP / 88 steps, no server-logic change). Version 4.8.0 -> 4.9.0.
v4.9.5: issue #8 (second half) - the two unified views.
- `lib/fleetindex.js` (new): a READ-ONLY `sw_fleet` route + `buildFleetIndex`. It walks every node and joins
  data that is already on the server (the collector's stored software, the same `scanNodeSoftware` matcher the
  CSV export and the printable reports use, the last `wgResults` for "update available", and the locally
  collected `licenseMapForNode`) into a distinct-software table (name, versions, publisher, deviceCount,
  vulnerable, cve, maxSeverity, updatable, hasLicense) and a per-device CVE count. It sends NO agent command,
  makes no new outbound request, defines no scheduler/pump and reboots nothing - a test pins all of that.
  The result is cached ~60 s in memory (never persisted) so the two views do not re-scan the fleet on toggling.
- Devices > Device list (`loadDeviceList`): one row per device merged live from `os_status` + `wg_status` +
  `dr_status` + `lic_status` + `sw_fleet` (app updates / OS state / reboot pending / reset readiness /
  vulnerability count / collected licenses). Check devices and run ONE non-destructive operation over them
  via the existing routes (`wg_run`/`os_run` update|upgrade / `lic_collect` / `wu_repair`). Restart and Reset
  are NOT batched - each row's button opens the sub-panel that does the per-device typed-name confirmation, so
  the reboot policy is unchanged (the views add a way in, not a new way to reboot).
- Software > Software list (`loadSwFleet`): the fleet-wide distinct-software table with per-row flags and an
  "Update everywhere" that calls `wg_run {pkgId}` (needs the winget id; rows without one are inert), reusing
  `wg_programs` for the name-to-id map. Vulnerability/license cells link to their existing panels.
- This is the only server-side addition in the v4.9.x UI work; v4.9.0 was presentation-only, v4.9.5 adds just
  the read-only aggregate. Every v4.9.0 invariant (ids, routes, session-per-agent, opt-in gates, reboot policy)
  still holds.
- Tests: +11 `sw_fleet` assertions + 1 step (read-only sends nothing, device/version/CVE counts, updatable +
  license flags, byDevice per-device CVE, the 60 s cache and the force rebuild, and the no-scheduler/
  no-command policy guard). +5 render assertions in tools/test-views.js (the two new sub-tabs + panels and the
  two loaders). Suite: 563 PASS + 3 SKIP / 89 steps. check.js still node --check's the inline script.
  Version 4.9.0 -> 4.9.5.
v4.9.6: completeness audit of the v4.9.x issue-#8 UI work - restore help text the move dropped.
- Checked the v4.9.0 regroup and the v4.9.5 unified views against the last pre-refactor state (v4.8.0, commit
  343df129). Every control survived: 0 element ids removed, 0 JS id-references broken, 0 ids that used to be
  wired now unwired, 0 duplicate static ids, the five engine panels (assessment/updates/os/deploy/reset) are
  byte-identical in content, and the report + CSV-export links all still resolve. Nothing functional was lost.
- The audit did find that moving the CPE table and the License keys section OUT of the Settings tab had also
  dropped their long explanatory `<div class="info">` help blocks (id-less prose an id-diff cannot see): the
  "what is a CPE / Regex / Vendor / Remote vs Custom / Fix a wrong row" text and the "asset management CSV
  columns / extraction-rule types / read-only + nothing sent / Rules JSON examples" text. Both are restored
  into their new panels (CPE under Vulnerabilities > Reports, NVD & CPE table; License under Software > License
  keys), with their cross-references corrected for the new layout (the Auto-map switch now reads "under
  Settings", the license switches "above" - which is true inside the moved panel).
- Tests: +2 render assertions in tools/test-views.js pin the restored CPE + License help text so a future
  regroup cannot silently drop them. Suite unchanged otherwise. Version 4.9.5 -> 4.9.6.
v5.0.0: issue #5 - optional connector to an external asset-management system.
- New module `lib/assetmgmt.js` + a new **Settings > Asset management** sub-tab. It transfers the three lists
  the plugin already aggregates (hardware inventory, software inventory, vulnerabilities) to an external REST
  system. Designed GENERIC first, with two first-class presets:
    generic  - the admin writes a JSON body template whose values may contain {{placeholders}} resolved against
               the aggregated record (device.*, hardware.*, software[], vulnerabilities[], counts.*). A
               placeholder alone in a value injects the whole typed value (array/number); inside text it is
               inserted as text. Extra headers are a JSON object. This reaches any REST API (GLPI, NetBox,
               ServiceNow, Device42, Freshservice, ManageEngine, Lansweeper, ...).
    jira     - one issue per device: POST /rest/api/3/issue on the first push (project key + issue type + label +
               an Atlassian-Document-Format description carrying all three lists), PUT /rest/api/3/issue/<id>
               afterwards, so nothing is duplicated.
    snipeit  - one hardware asset per device: POST /api/hardware, then PATCH /api/hardware/<id>.
  The external id is read back from the answer (Jira id/key, Snipe-IT payload.id/id, or for a generic target the
  admin-configured `externalIdPath`, e.g. "id" or "data.asset.id") and stored per device in `asset-sync.json`.
- Data protection: this is the plugin's ONE deliberate off-server exit, so it is **disabled by default**, there
  is **no automatic push** unless `intervalHours` > 0 (default 0), and only a full site admin can configure it.
  The endpoint must be **https** (rejected when saving AND when building a request). Credentials live in the
  `assetManagement` section of scanner-settings.json, are **never returned to the browser in the clear** (masked
  + `has*` flags; a blank field KEEPS the stored secret, `__AS_CLEAR__` erases it) and are **never logged**. The
  log records device + HTTP status + external id only - never a request/response body. The push reads stored
  inventory and sends **no agent command**, so it never touches a device and does not interact with the
  one-runcommands-session-per-agent rule. The body template is JSON data only: placeholders are substituted as
  values, the template is never evaluated as code. SECURITY.md documents all of this.
- Own settings section on purpose: `assetManagement` sits beside `vulnerabilityScanner`/`inventoryScanner`/
  `wingetUpdater`, so the Settings-tab save/reset (which owns only the first two) and the winget save cannot wipe
  the connector config - and vice versa (a test pins that the other sections survive an asset save).
- UI: Settings > Asset management with the target/auth/mapping form, a prominent disclosure that this is the only
  place data leaves the server, "Send a test request" (one synthetic sample), "Push all devices now" and a
  per-device "Push" in the last-push table - each push asks for explicit confirmation. Devices > Device list also
  gained a "Push to asset system" batch action for the selected devices (same confirmation).
- Routes: `as_get_config`, `as_save_config`, `as_status`, `as_test`, `as_push`; `get_log` accepts `asset`.
  `rescheduleAll` + server_startup now also call `scheduleAssetSync` (which does nothing while disabled).
- Tests: +2 steps / +33 assertions (598 PASS + 3 SKIP / 91 steps): OFF by default and no agent-facing pump,
  push refused while disabled, https-only endpoint, enable-needs-URL, Jira-needs-project, invalid JSON template
  rejected BEFORE storing, other settings sections survive, the secret is stored but never returned in the clear,
  blank keeps / sentinel clears, all three request builders (create + update, auth headers, template filling with
  typed array injection), no-agent-command during a real push, one https request per device with the filled body,
  the external id stored for create-or-update, the log contains neither credential nor payload, "only vulnerable"
  skips a clean device and RECORDS the skip, as_test, the scheduler registers nothing while disabled/interval 0
  and only then, and get_log/as_status. Plus 7 render assertions for the panel, its disclosure text, the as_*
  routes, password fields with an explicit clear, and the per-push consent. Version 4.9.6 -> 5.0.0.
v5.0.1: full source review of the #5 connector - six real defects found and fixed.
- **Linux distribution packages were mis-scanned before being pushed** (the most serious one): the record
  collector handed the matcher a reduced projection ({name,version,publisher}) instead of the RAW stored rows,
  so `location`/`installLocation` (dpkg, rpm, apk, pacman) was lost. `isDistroPackage`/`isDistroMaintained`
  need exactly that field, so distro packages would have been judged by NVD version ranges and pushed as
  FALSE-POSITIVE vulnerabilities. Fixed: the matcher now receives the raw rows (like the CSV path does), and the
  pushed software list keeps name/version/publisher and additionally `location`. Pinned by a test that asserts
  the raw rows (with location) reach `scanNodeSoftware`.
- **`jiraVulnIssues` was a dead option**: stored, returned by the API and described in the UI, but never used by
  the builder. Now implemented: one additional Jira issue per finding, each tracked by its OWN stored id
  (`asResults[node].vulnIssues[cve]`) so a later push UPDATES it instead of duplicating every run, capped at
  `AS_MAX_VULN_ISSUES` (100) per device. Requests now carry an `idSlot` ('device' or 'cve:<CVE>') that tells
  `asSendDevice` where a returned id belongs.
- **`as_push` blocked the HTTP request until every device was done** - on a large fleet that runs into a proxy/
  browser timeout. Now it answers IMMEDIATELY (`{started, devices, background:true}`) and runs in the background
  exactly like `wg_run`/`os_run`; the panel polls `as_status` every 3 s until `running` is false and then reports
  ok/error/skipped counts.
- **No watchdog and no pacing**: a callback that never fired left `asPushing = true` forever (every later push
  refused as "busy" until a server restart), and all devices were fired in parallel. Now the loop uses the shared
  `pacedEach` with `AS_PUSH_PARALLEL` (4), and `AS_PUSH_MAX_MS` (10 min) unlocks the connector and logs an
  ABORTED line. `assetHttp` also wraps `https.request` in try/catch and answers through a once-guard, so an
  invalid header can neither throw into the push loop nor double-call the callback.
- **Header hardening**: a custom header name must be an RFC 7230 token and a value must not contain control
  characters (checked for the auth header AND for every entry of the generic `headersJson`) - a CRLF would allow
  header injection, and an invalid name would have failed obscurely at request time.
- **Smaller correctness/robustness fixes**: enabling a target now validates the EFFECTIVE credential (bearer
  needs a token, basic needs user and/or password, header mode needs name+value) so a config that could only ever
  answer 401 cannot be saved; clearing a secret while enabled+bearer is refused with a clear message (disable or
  change the auth mode first). The push/status node filter no longer requires `n.name != null` (a device without
  a name was silently skipped - other engines never required it). Results of deleted devices are pruned during a
  full push so `asset-sync.json` cannot grow forever; a corrupt/array-shaped file is ignored instead of becoming
  the result map; `as_status` no longer ships the internal per-CVE id map to the browser (a count instead).
- Tests: +3 steps / +21 assertions (619 PASS + 3 SKIP / 94 steps) pinning every fix above, including the
  background-answer + watchdog-unlock behaviour and the raw-rows contract. Version 5.0.0 -> 5.0.1.
v5.1.0: refactor - ONE canonical inventory collection, so browser, CSV, reports and push agree 1:1.
- User-visible problem: the same device could show different information depending on where you looked. The
  reason was that "collect a device" had been implemented FIVE times: `reports.js` twice, `csv.js` once,
  `fleetindex.js` once and `assetmgmt.js` once. The copies had drifted:
    * `assetmgmt.js` dropped the OS findings entirely - a push contained only software CVE rows, never the OS
      CVEs, never `WINDOWS-UPDATES`, never `OS-EOL`, and it reduced the hardware to a handful of fields. The
      CSV and the report showed all of them for the same device.
    * `fleetindex.js` called `getStoredSoftware(node, {})` - without the sysinfo document - and counted only
      software CVEs, so the browser's device badge could disagree with the CSV.
    * `license.js` also read `getStoredSoftware(node, {})`, so a program that only exists in the sysinfo doc
      was listed by the CSV but never got a license rule matched.
    * `assetmgmt.js` handed the matcher a reduced projection, dropping `location`/`installLocation` (fixed in
      5.0.1, but the same class of drift).
- The fix is structural, not per-symptom: `lib/nodes.js` now owns the collection - `fetchNodeSoftware(node, cb)`
  (the one way to get the raw rows: plugin store AND sysinfo doc) and `collectNodeInventory(node, cb)` (identity,
  `hardwareSummary`, raw rows, `softwareProjection`, `softwareFindings`, the FULL `findings` list and the counts,
  incl. `uniqueFindingIds` and `maxSeverity`). `hardwareSummary` is the single derivation of the hardware facts
  (CPU, GPUs, memory banks + total, storage, BIOS, board, chassis/system, TPM, network/DNS, best-effort serial),
  pre-formatted with `formatBytes` so no consumer formats it a second, slightly different way.
- All five consumers were migrated onto it: `csv.js` (hardware rows are now generated FROM the canonical
  summary - byte-identical output, verified by the existing CSV tests), `reports.js` (both scan paths; the
  coverage categories now come from `inv.softwareFindings`, the findings from `inv.findings`), `fleetindex.js`
  (device badge = `uniqueFindingIds`, software rows from the canonical projection), `assetmgmt.js` (the record
  is a shaping of the canonical one: `vulnerabilities` = every finding with an id, `coverage` = the blind-spot
  rows, `hardware` = flat convenience fields kept for existing templates PLUS the full canonical detail) and
  `license.js` (`licenseAppRules(rows)`, fed by `fetchNodeSoftware`; the "all online Windows" path became a
  paced async loop like the other bulk paths).
- AGENTS.md gained a hard rule: never re-implement the collection chain in a consumer and never hand the
  matcher a projection (the distro-package detection needs `location`).
- Behaviour changes an admin can see: the asset push now contains the OS findings and the full hardware detail
  (and a `coverage` array), and the browser's per-device vulnerability badge counts the same distinct findings
  the CSV lists (it used to count software CVEs only). The CSV and the printable reports are unchanged.
- Tests: +2 steps / +18 assertions (637 PASS + 3 SKIP / 96 steps). The new "1:1" step builds one device with a
  software CVE, an OS CVE, `WINDOWS-UPDATES`, `OS-EOL`, a distro-managed row and a not-assessable row, then
  asserts the SAME finding-id set appears in the vulnerability CSV, the push payload, the fleet index and the
  report count; that CSV/push/fleet-index list the same programs; that the hardware serial + CPU are identical
  in the hardware CSV and the push; and that a sysinfo-only program reaches both the software CSV and the
  license run. These assertions fail on any future drift between the views. Version 5.0.1 -> 5.1.0.
v5.2.0: optional license collection schedule + the NVD feed timer actually runs.
- **License collection can now run automatically** (requested): a new `licenseCollectIntervalHours` setting
  (0..8760, **default 0 = off**, on demand only as before) in the `inventoryScanner` section, editable in
  Software > License keys with the usual source select + revert. It needs the existing master switch
  (`licenseCollectionEnabled`) as well, so nothing changes for anyone who does not turn it on. The run is the
  IDENTICAL read-only script (registry GetValue / file read / CIM property - no write, no reboot), on **online
  Windows** devices only, skipping devices that hold another agent session (the one-session-per-agent rule is
  untouched); the keys stay on this server and are never logged. `licSweepOnce(by, cb)` is the ONE
  implementation of that pass - the `all=true` route and the scheduler both call it (no copy, per the v5.1.0
  lesson). `scheduleLicenseCollection` follows the standard timerGen + longTimeout pattern and is armed from
  `server_startup` and `rescheduleAll`. The field is OPTIONAL in `save_settings`: an absent/empty value keeps
  the stored one instead of failing the whole save, so an older cached panel page cannot be locked out.
  SECURITY.md/README/the panel text no longer claim "no background scheduler" - they state the default and the
  opt-in schedule honestly.
- **NVD feed updates never ran on a restarting server (a real outage, found from the user's log).** Two bugs:
  (1) `scheduleUpdate()` always waited a FULL interval regardless of how old the feeds were, so the self-heal -
  which correctly detected "lastUpdate is 285h old (max 168h)" - merely postponed the run by another 168h. A
  server that restarts more often than the interval therefore reset the clock every time and NEVER updated
  (exactly the reported 285h -> 309h with no update). (2) `rescheduleAll()` bumps `timerGen`, which invalidates
  the armed NVD timer, but it never re-armed it - so any settings save (Settings, winget or asset config)
  silently stopped the feed updates until the next server start.
  Fixed: `scheduleUpdate(opts)` is now DUE-AWARE - the delay is `interval - age(lastUpdate)`, a missing or
  unparseable `lastUpdate` (never downloaded) is due immediately, and everything is floored at
  `NVD_MIN_DELAY_MS` (60 s) so a multi-GB download does not start in the middle of the boot. A FAILED run is
  retried after `NVD_RETRY_MS` (6 h) instead of immediately, because nvd.nist.gov is rate-limited - no retry
  storm. `rescheduleAll()` re-arms the feed timer. `checkAndRepairNvdTimer()` now only REPORTS staleness (log +
  admin notification) and returns the flag; it no longer arms a second timer next to the one from
  `server_startup`, and its log line says the run is due instead of the misleading "scheduling update".
- Tests: +2 steps / +19 assertions (656 PASS + 3 SKIP / 98 steps): the 285h-stale case is fetched within a
  minute and NOT postponed 168h, a fresh feed waits the remaining interval, a missing lastUpdate is due
  immediately, a failed run retries after 6h (no tight loop), a successful run returns to the normal cycle,
  rescheduleAll re-arms the feed timer, the self-heal reports but arms nothing; the license scheduler arms
  nothing while the master switch is off or the interval is 0 and exactly one cycle when both are set, the
  sweep sends only to the online Windows device (not offline, not Linux, not a device busy with another
  engine) with the same read-only script and a redacted log line, and the settings round trip stores/keeps/
  validates/reverts the new interval. Plus 2 render assertions for the new field and its honest description.
  The old "license is never scheduled" assertion was deliberately replaced (the invariant changed by request).
  Version 5.1.0 -> 5.2.0.
v5.3.0: the panel view is modularised - STRUCTURE ONLY, no behaviour change. Preparation for
issue #9, which restructures the navigation and would otherwise mean editing one 3,240-line file.
- Verified first (upstream sources, then proven live): MeshCentral's `pluginHandler.handleAdminReq` does
  `serv.app.set('views', <pluginPath>/<pin>/views)` per request and `webserver.js` builds the engine with
  `exphbs.engine({ defaultLayout: false })` - no `partialsDir`; `express-handlebars@8.0.5` derives it PER RENDER
  as `path.join(viewsPath, "partials/")` and globs `**/*.handlebars` with posix paths, so sub-folders become
  namespaces. A spike commit (probe partial + a CI container assertion on its marker) proved it against a real
  server BEFORE this split relied on it: `PASS the panel resolves a handlebars partial from views/partials/`.
- `views/assessment.handlebars` went from 3,240 lines to a ~165-line SHELL (head/CSS, two-layer nav, container,
  `#invFloat`, the floating location panel, the `<script>` + IIFE brackets). It now includes 11 panel partials
  (`views/partials/panels/*`) and 19 JS partials (`views/partials/js/*`). The split was done MECHANICALLY by a
  script that copies verbatim line ranges (panels delimited by their 8-space `<div class="tab-content">` block,
  JS by the existing `// ---------- area ----------` banners) - no line was rewritten by hand.
- The JS fragments are included INSIDE the one IIFE, so there is still exactly ONE closure: every helper (`$`,
  `esc`, `post`, `showMsg`, `selectSub`, ...) resolves as before, there is no namespace object and no global
  leak, and no declaration order changed. Each fragment holds complete declarations only (the brackets stay in
  the shell), so it is independently parseable.
- Proven equivalent, not assumed: the pre-split file and the new shell were rendered with the same data and
  compared - identical static id set (205, none missing, none added), the composed inline script text identical
  after whitespace normalisation, no leftover partial tag in the output, all 47 info/hint help blocks present,
  all report/export links present, and the WHOLE document equal after whitespace normalisation.
- `upgradeTreeReady` hardened: it now requires every REFERENCED partial to exist and be non-empty before an
  upgrade restart is triggered. Walking the disk cannot detect that (it only sees what already exists) and the
  installer unpacks alphabetically with `views/` LAST, so the shell could be complete while a partial it
  references is still missing - an unresolved partial is a render error, i.e. a dead panel. Handlebars comments
  are stripped before collecting references, because the probe partial documents the syntax in a comment.
- Tooling (still dependency-free where it must be): `check.js` gained the partial symmetry guard (every
  reference resolves, no orphan file), a per-fragment `node --check` (wrapped in a function) plus a per-fragment
  stray-`{{` screen, and it composes the panel script by INLINING the partials itself so the combined-syntax
  guard survived without needing handlebars. New `tools/gen-panel-inventory.js` writes the frozen inventory
  `tools/fixtures/panel-inventory.json` (ids, help texts, links, nav panels) that `test-views.js` now asserts -
  the permanent guard against the v4.9.6 class of silent loss. Removing something on purpose means
  regenerating the fixture in the same commit.
- Tests: check.js 242 PASS (30 partials x 3 checks + the symmetry guards), test-plugin 661 PASS + 3 SKIP / 98
  steps (+4 for the partial-aware upgrade gate: complete tree ready, empty partial not ready, MISSING partial
  not ready, restored ready - the "missing" case is what caught the disk-walk flaw), test-views 40 PASS
  (+6: partials registered, the probe resolves, and the four inventory guards). No route, handler, engine,
  data shape or agent script changed. Version 5.2.0 -> 5.3.0.
v5.4.0: issue #9 - the UI rework on the modular base.
- **Deep links:** the URL hash carries `#<main>/<sub>`; the nav anchors hold the real hash and are not prevented, so
  `hashchange` (`applyHash`) is the single driver. Copying the address of any view and pasting it restores that view,
  and the browser back button walks through the visited views. An unknown/missing hash lands on `vulns/assessment`.
- **Sorting bug fixed:** the findings table defaulted to `sortKey:'cvss'`, and `sortValue('cvss')` returns the RAW
  NVD score - so a finding rated LOW (or flagged false positive) with CVSS 9.8 stayed at the top and the manual
  rating appeared to do nothing. The default is now `severity`, which sorts by `effSeverity()` (rating wins, false
  positives sink via `SEV_RANK`), with the higher CVSS as the tiebreaker inside one severity and then the CVE id for
  a stable order. The CVSS column stays freely sortable.
- **The floating location selector is gone** (its look & feel was never repeated anywhere else and it covered the
  table): the selection is now an inline row of checkboxes above the findings table, with the same ids
  (`locationPanel`/`locList`/`locAll`/`locApply`/`locCountTxt`), the same localStorage persistence and the same
  "Apply only re-reads the stored snapshot" behaviour.
- **Hover help:** a fixed box at the lower right (`#helpBox`) shows the explanation of whichever action button the
  pointer is on (`data-help` key -> `HELP` registry, one delegated listener). The texts are the per-action breakdown
  of the info boxes, so the explanation is where the hand is.
- **New navigation:** five main sections. Devices -> Device list, PC reset, Device report. Software -> Software
  list, Software updates (the winget configuration), Deployment, License keys. Vulnerabilities -> Assessment,
  Vulnerability report, CPE table, NVD database. Exports (NEW) -> choose hardware/software/vulnerabilities.
  Settings -> General, Asset management. The old `Reports, NVD & CPE table` panel was split accordingly.
- **Device list** is now the device hub: sortable columns, a filter, and per-row Software (Dry run / Update /
  Exclude|Include), OS (OS updates / OS Upgrade) and Troubleshoot (Diagnose / Troubleshoot / Reboot - renamed from
  "Restart" - / Notify user) buttons, plus **Details**, which fetches `dev_details` on demand (hardware, programs,
  findings + coverage, the last run of every engine, the license counts) so the table itself stays compact. The
  fleet OS buttons, the upgrade-reference line and the OS update log moved here with the OS register. The Reboot and
  Reset columns and the row Reset button were removed as requested - a reset stays on its own PC reset page.
- **Software list** gained the winget package aggregate (ready/ok/failed/skipped from the stored last runs) in place
  of the old "Update" column, and every row carries Ignore / Update everywhere / Uninstall everywhere / Details
  (`sw_details`: devices, versions, findings, license presence, the per-device winget rows). Rows without a winget
  package id show those three buttons DISABLED with the reason - winget manages ids, not display names.
- **Removed as duplicates** (their content lives in the unified views now): the winget device table and the
  "Packages across all devices" table, the whole `OS updates & reboot` register, the license device table, and the
  CSV links on the device list. Nothing was dropped without a new home - see the audit below.
- **Two atomic winget routes** (`wg_toggle_exclude`, `wg_toggle_ignore`) instead of reusing `wg_save_config`: that
  handler builds its body from the Updates-tab DOM, so calling it from the device list before the tab was ever
  loaded would have saved `enabled:false` with EMPTY `updateMeshes`/`ignorePackages` - silently switching the
  automatic updater off and wiping its scope. The new routes change one key and copy the rest of the section
  untouched (keys that came from config.json are not pinned into the plugin file).
- **One action, one definition:** the device list calls `wgRunOne`, `osDeviceUpdate`/`osDeviceUpgrade`/
  `osFleetUpdates`/`osUpgradeFleet`, `wuDiag`/`wuDeviceRepair`, `rbNotify`/`rbRestart` and `licCollectOne` - the
  functions that own those actions, with their existing confirmations (including the typed-name restart confirm, so
  the reboot policy is unchanged). `osRefresh()` is the single re-read hook and points at `loadDeviceList`. The
  table renderers that belonged to the removed panels (`renderOsDevices`, `renderWgDevices`, `renderWgPackages`,
  `renderLicDevices`, `loadOsStatus`, `loadOsLog`, `loadWgPackages`, `wgToggleExclude`, `dlGo`) are gone.
- **Completeness audit against v5.3.0** (the same method as v4.9.6, now automated by the inventory fixture): 20 ids
  disappeared and every one has a replacement (`osUpdBtn`->`dlOsUpdAllBtn`, `osLog`->`dlOsLog`,
  `osCurrentInfo`+`osUrgentDaysInfo`->`dlOsRefInfo`, `wgDevBody`->the device rows, `wgPkgBody`->the software rows,
  `licDeviceBody`->the License column + Details, `locationToggle`/`locClose`->the inline row, `tab-os`/
  `tab-vulndata`->the new sub-tabs); all 13 removed `data-*act` actions map to a new one; no link was lost. The audit
  also caught TWO real losses that were fixed before shipping: the OS batch-running indicator had no home (now
  `dlOsRunState`) and two sentences of the winget explanation ("devices without winget are reported per run; offline
  devices are skipped", "a full log with one line per package") had been dropped while rewriting (restored). The
  per-device license collect would have been lost with the license table, so it moved into the device Details view.
- **README + plugin description rewritten for administrators** (as the issue asked): the README is now task-oriented
  around the five sections, with reference tables for the finding statuses, the OS release states and the supported
  distributions, and the implementation internals (policy mechanics, transport details, command-line limits) are
  referred to AGENTS.md instead of being duplicated. The manifest description is one human sentence pair.
- Tests: +18 assertions in test-plugin (679 PASS + 3 SKIP / 99 steps) - the atomic toggles keep every other winget
  key, `dev_details` returns the FULL finding list (software CVE + OS CVE + WINDOWS-UPDATES + OS-EOL) and the
  coverage rows, both detail routes are read-only (no agent command) and never contain a license VALUE, invalid ids
  are refused; +9 render assertions in test-views (49 PASS) for the five sections, the deep-link machinery, the
  severity-default sort and its tiebreaker, the inline location row, the help box and registry, and the Exports
  selector. The inventory fixture was regenerated in the same commit (206 ids, 65 help texts, 6 links, 14 panels) -
  the diff shows exactly which controls were removed on purpose. Version 5.3.0 -> 5.4.0.
v5.4.1: UI polish round on the #9 rework - seven reported defects, no server logic touched.
- **Double documentation removed:** the per-action explanations sat both in the info box at the top of a panel AND
  in the hover help, wasting space. Info boxes now carry only what no button hover can say (page purpose, safety
  disclosures, cross-references); everything button-specific lives in `HELP` alone. The reference semantics that
  left the device-list info box (OS upgrade targeting rules, unknown-state behaviour, apt repository warnings,
  per-package outcome columns) were absorbed into the hover texts of exactly those buttons/columns.
- **Documents are one click now:** Device report, Vulnerability report and the three CSV downloads were panels
  that held nothing but a link button (two clicks). They are external links in the sub-nav row
  (`class="subtab ext"`, new tab), explained by the hover help of the nav button; the Exports main section has NO
  panel at all (`selectLinksMain` paints its link row and keeps the active panel, hash `#exports`).
- **Calm row buttons:** one language in table rows - `rowbtn` (neutral, same box height as `button.small`),
  `rowbtn act` (the single accent blue for actions that start something on a device), `rowbtn warn` (red outline
  only for the reboot path), pale grey when disabled. The previous green/red/purple/grey mix per cell was
  reported as restless and hard to tell apart.
- **No horizontal scroll in the software list:** the action cell wrapped its four buttons in nowrap, forcing
  sideways scrolling; actions now wrap inside `.cellacts` (flex-wrap, max-width) in both unified tables.
- **The details request loop is gone:** every re-render (sorting, filtering, the 10 s status poll) refetched the
  open `dev_details`/`sw_details` blocks, which looked like a stuck loop. Answers are now cached per device /
  program for the lifetime of the open page; re-renders inject the cache, and a *Refresh details* button inside
  the block is the only way to re-read the server.
- **Settings group table:** the per-group notify threshold is explained in a hint block (it overrides the global
  severity floor for notifications from that group only), and the Source column is never blank any more -
  `set here` / `from config.json` / pale `global threshold` when no per-group override exists (the empty cell was
  the reported confusion).
- Tests: +4 render assertions in test-views (55 PASS) pinning the one-click document links + their hover help, the
  details cache, the rowbtn/.cellacts styling and the group-table explanation; the inventory fixture was
  regenerated in the same commit (201 ids, 63 help texts, 5 links, 11 panels - the removed link panels and the
  export chooser are the visible diff). test-plugin unchanged (679 PASS + 3 SKIP / 99 steps): no route, handler,
  engine or data shape moved. Version 5.4.0 -> 5.4.1.
v5.4.2: two reported defects fixed - details did nothing, and four requests died with 502.
- **Software list > Details did nothing and sent no request.** Two compounding causes, both structural: the
  detail cell id was the ROW INDEX (`swfd-<i>`), which no longer matches after any filter or re-render, and the
  row lookup used `b.parentNode.parentNode` - a chain that silently landed on the `<td>` instead of the `<tr>`
  once the v5.4.1 `.cellacts` wrapper went around the buttons, so `detail` became a table cell, the id lookup
  returned null and the load aborted before posting. Fixed: detail cells are keyed by the program NAME
  (`swfKey`), and rows are resolved by climbing to the `<tr>` via the new shared `rowOf(el)` (used by both
  unified lists). Pinned by render assertions (name-keyed cells, no index-keyed cell left, rowOf used twice).
- **Four 502s on page load** (`get_license_table`, `lic_status`, `get_locations`, `os_status`). The fleet index
  walked ALL devices in a bare `for` loop whose worker callbacks run synchronously (the matcher is sync per
  program) - one long event-loop turn that starved every other socket, so the requests in flight while a list
  opened died at the proxy; leftover background pollers of the PREVIOUS view kept adding traffic into exactly
  that window. Two fixes: (1) `buildFleetIndex` now iterates via `obj.pacedEach` (parallelism 2, yields between
  devices - the project rule for every device walk, which this path had violated since v4.9.5) and COALESCES
  parallel builds (`_fleetIndexWaiters`), so opening two views at once walks the fleet once; (2) every poller
  only schedules while its own page is open (`currentSub` guards on the device-list, winget, license, reset,
  deploy and asset polls) and `selectSub` stops the polls of the view being left (`stopViewPolls`, `asPollGen`
  for the asset poll). Pinned by a coalescing test (async db, two parallel `sw_fleet` POSTs -> the matcher sees
  every program exactly once and both answers are the same object) and a source-level pin that the walk uses
  `pacedEach` (the bare loop is gone).
- No route response shape, engine, agent script or data file changed. What users see: Details works with one
  click, and switching pages no longer produces background requests (or 502s) for the page that was left.
- Tests: +1 step / +3 assertions in test-plugin (682 PASS + 3 SKIP / 100 steps), +4 render assertions in
  test-views (59 PASS). check.js unchanged green (246). Version 5.4.1 -> 5.4.2.
v5.5.0: issue #10 - per-user license rules (HKU hives / profile files) + one subkey/leaf wildcard,
plus the curated table and the CONTRIBUTING process for it.
- **Rule schema (backward compatible, all optional, still data-only):** `perUser:true` on a registry rule means the
  path is written `HKCU:\...` and read from every ALREADY-LOADED user hive (`Registry::HKEY_USERS\<SID>\...`, gated
  by `Test-Path` on the hive); `perUser:true` on a file rule allows the `{{profile}}` placeholder, replaced per
  existing profile directory; exactly ONE `*` per path - a whole registry subkey segment enumerated with
  `Get-ChildItem` (<=20 matches, first non-empty value wins; the VMware `License.ws.*` case incl. a WOW6432Node
  twin rule) or a file leaf pattern (<=5 candidate files, e.g. `*.mountainducklicense`). `sanitizeLicenseRules`
  refuses: `perUser` on an HKLM registry path or on wmi, `{{profile}}` without `perUser`, more than one `*`, and a
  `*` inside a registry value. Users are discovered read-only from ProfileList (SID + ProfileImagePath, machine env
  expanded), capped at `LIC_MAX_USERS` = 20. **Offline hives are never mounted** - `reg load`/`reg save`/`LoadKey`
  are rejected by the script-shape test, so the read-only guarantee of v4.8.0 stands (the issue demanded exactly
  this). Every answer item carries the `user` (profile leaf name); `licHandleResponse` stores it capped at 100.
- **`licenseMapForNode` first-ok-wins (the masking bug the issue named):** the last item per name used to overwrite,
  so a later failing rule hid a value an earlier rule had found; now the first `ok:true` item with a non-empty
  license wins, and the source string gains the attribution - the software CSV's License Source shows e.g.
  `registry (user: alice)`. Pinned by tests in both directions (fail-then-ok, ok-then-ok, all-fail).
- **Script:** two single-line read helpers (`invRegVal`, `invFileVal`) and one per-rule target loop replacing the
  old fixed single-path read; the marker line, the base64 rule blob and the item caps are unchanged. The generated
  script passes the PowerShell parser and the one-statement-per-line check (a missing closing brace in the two
  perUser branches was caught by the parser test during development and fixed).
- **UI:** the custom-rule editor gained an "apply these rules per user" checkbox (`add_license` stamps `perUser`
  onto every registry/file rule of the payload), the info block documents per-user reads, the placeholder, the
  wildcard caps and the never-loaded offline hives, the custom-rule table shows `(per user)` per rule, and the
  hover help covers the checkbox.
- **Curated `license-table.json`:** `_comment` now documents the whole schema incl. the v5.5.0 extensions, the caps,
  first-ok-wins and the CSV attribution; two entries added, BOTH with a `_source` citation in the file: VMware
  Workstation (serial in the version-dependent `License.ws.*` subkey, Broadcom KB 342831 + fleet measurement; the
  WOW6432Node twin covers older installs) and Mountain Duck (per-user `*.mountainducklicense` in the application
  support folder, docs.mountainduck.io + fleet measurement). gpg4o and PL/SQL Developer are NOT in the table: the
  issue documents only "a per-user license file in the gpg4o user directory" and "registration under
  HKCU\Software\Allround Automations\..." without the file/value names - adding guessed segments would violate the
  table's honesty rule; both are now expressible by an admin custom rule (documented in CONTRIBUTING.md and the
  panel help). The vendor-encrypted non-goals (Adobe/Foxit/PDF-XChange, Total Commander) are named in the comment.
- **CONTRIBUTING.md:** a full "License-mapping contributions" section parallel to the CPE one - evidence rule
  (documented path + citation, never guess; encrypted blobs are non-goals), the data-only rule types, the per-user
  and wildcard syntax with its caps, order/first-hit-wins, the safety gate, validation commands, and what the file
  is not (no key dumps, no MS keys, no single-machine paths).
- **Docs:** README license paragraphs (per-user + wildcard + never-loaded hives + CSV attribution), SECURITY.md
  (the per-user read scope stays inside the read-only guarantee; the only per-user datum that leaves the device is
  the profile NAME in the CSV source), AGENTS.md (module row + engine section).
- Tests: +1 step / +26 assertions in test-plugin (705 PASS + 3 SKIP / 101 steps): schema accept/refuse matrix,
  script shape (ProfileList discovery + cap, loaded-hives-only, placeholder replacement, wildcard caps, NEVER a
  hive mount, still no write/reboot, base64 blob, one statement per line, PS parser), a dispatched per-user collect
  whose answer stores `user` per item, first-ok-wins + source attribution + all-fail-empty, the CSV carrying
  `registry (user: alice)`, the shipped table applying with 4 entries and both new entries well-formed with cited
  sources, and `add_license` stamping/refusing perUser. +3 render assertions in test-views (62 PASS) for the editor
  checkbox, the panel explanation and the hover help. The inventory fixture was regenerated (202 ids). check.js
  green. (Correction by audit 4: the live CI integration does NOT call lic_collect - the per-user read path was only
  covered by the mocked suite, which is why its real-Windows failure went unnoticed.) Version 5.4.2 -> 5.5.0.
v5.5.1: audit 4 - independent full audit of v5.5.0 by Claude Opus 5.5 (details: AUDIT.md, "Audit 4").
- **Per-user license reads never worked on a real Windows 11 (B1, high).** `licenseBuildScript` discovered the users
  inside ONE `try` around the whole ProfileList loop; `Test-Path` on the profile of `S-1-5-18` throws "access denied",
  so the loop ended at its first entry and no user was found - every per-user rule (and the shipped Mountain Duck rule)
  failed silently. Each profile now has its own `try`, service SIDs 18/19/20 are skipped. Verified by running the real
  script through the real cmd.exe transport: registry wildcard + per-user file rules now return values with the user.
- **Mountain Duck rule pointed at a folder that does not exist (B5).** The vendor documents `%AppData%\Cyberduck` (per
  user) and `C:\ProgramData\Cyberduck` (machine-wide); the key file is an XML plist, the rule now extracts the
  `Transaction` id instead of returning the whole signed file. Verified against a real installation.
- **Server Files deploy refused every real device group (B2) + domain traversal.** Mesh ids are base64 with `@`/`$`;
  the group regex allowed neither. The domain part was never validated (`mesh/a\..\..\x/g` resolved outside
  `<filespath>`). One function `swServerFilesDir` now validates both parts and prefix-checks the folder.
- **ReDoS gate bypass (B3).** `isSafeTableRegex` is a small scanner now (nested quantifiers at any depth, alternation
  under a quantifier, numbered and named backreferences); every shipped regex still passes.
- **Scheduled scans overlapped (B4).** The next run is armed after the pass finished, not after it started.
- **Live scan by GET without the header (S1)**, **unmasked generic extra headers (S2)**, **programs named
  `__proto__`/`constructor` vanished from the fleet views (S3)**, **the 512 KB lifecycle cap was never applied (S4)**,
  `safeNodeDir('node//..')` returned `..`, the license table was only refreshed at server start (now with the NVD
  cycle as documented), the per-device asset push asked no confirmation, double-answer guards in the HTTP getters.
- Texts: duplicate help keys, a duplicated device-list info box, stale "Settings tab"/"OS Updates tab"/"floating
  panel" references in UI messages, panels and comments, "the one feature that restarts" on the PC reset page,
  101 mojibake sequences in this file.
- Tests: realistic 64-character mesh/node ids for the new paths, a gate matrix over ALL 53 POST actions (401 non-admin,
  401 sub-domain admin, 403 no header, 400 non-object body), direct tests for formatCsvField/safeNodeDir/rbCleanMessage/
  swPsQuote, the removed-marker blind spot of five "marker before Stop-Transcript" checks fixed (`markerBeforeStop`),
  two tautologies removed, the prose inventory now also checks the block length. 732 PASS + 3 SKIP / 102 steps on
  Windows without a POSIX shell. The new suite was also run against the UNFIXED v5.5.0 code: every regression test of
  a fixed finding (B1-B5, S1-S4, safeNodeDir, domain traversal) FAILS there; the tests that pin behaviour that was
  already correct (gate matrix, CSV/quote helpers) pass on both, as they should.
- CI: `persist-credentials: false`, live scans send the header, a 403 check for a header-less live scan, a Server
  Files listing with the REAL CI group id, `grep -F` for the version check. Version 5.5.0 -> 5.5.1.

v5.6.0 (this release): license information as three honest layers - the curated license TYPE of a product, the
measured license type + activation state of a Microsoft installation, and the fix of a rule that never matched.
- **`licenseType` in `cpe-table.json` (requested: "so it does not have to be re-derived every time").** A CPE row may
  now carry an optional `licenseType`: an SPDX identifier (`MIT`, `Apache-2.0`, `MPL-2.0`, `GPL-2.0-only`,
  `LGPL-2.1-only`, `AGPL-3.0-only`, `PSF-2.0`, `MS-PL`, `MS-RL`, `PHP-3.01`, `curl`, ...) or one of exactly three
  descriptors - `Proprietary` (closed source, a license must be bought), `Freeware` (closed source, free of charge,
  including hardware/OS-bundled vendor tools), `Freeware (non-commercial)`. All 124 product rows are filled; the 16
  `kind` (driver/firmware) rows carry none on purpose (exclusion markers have no product identity), and the single
  omission (`winpcap`) documents why in a `_licenseNote` - the suite asserts "filled, or documented", not a count.
  `obj.sanitizeLicenseType` caps it at 80 characters, restricts the charset (it lands in a CSV cell and an HTML
  attribute) and keeps the case (SPDX ids are case-sensitive); an unusable value is dropped and the MAPPING row still
  applies, so a bad annotation can never cost CVE coverage. `obj.licenseTypeFor(name)` is the one resolver (custom row
  first, then the table, `''` when nothing matches) and is deliberately NOT fed by the automatic token matcher: that
  stage proves a CPE product for CVE lookup, which is no evidence about licensing.
- **One resolver, many consumers (the v5.1.0 rule applied to the new field):** `obj.softwareProjection` resolves the
  type once per program, so the software CSV's new `License Type` column, the Software list column, `dev_details`,
  `sw_details`, `sw_fleet` and the asset push all report the same value - and it is available WITHOUT any collection
  run, unlike `License`/`License Source`. `licenseType` and `hasLicense` stay separate facts: a curated type never
  pretends a key was read.
- **Edition splits use the table's own ordering rule:** `^intellij idea.*community` and `^pycharm.*community`
  (Apache-2.0) now sit BEFORE the generic IDE rows (Proprietary), so the free Community Edition is no longer reported
  with the commercial licence of its product family.
- **Evidence is reproducible, not remembered: `tools/gen-license-meta.js` + `tools/winget-ids.json` (new).** The values
  were read from the winget community manifests (`microsoft/winget-pkgs`, **MIT** - compatible with this project's MIT,
  unlike the GPL/AGPL inventory projects whose DATA MODEL was studied but whose code was not) via
  `winget show --id <id> --exact --locale en-US`; `--locale` matters because the field can come back translated
  (measured: TeamViewer reported `Proprietäre`). The tool re-reads that evidence and reports drift, `--write` refreshes
  the table, and on a machine without winget it prints SKIP and changes nothing. Normalization is an explicit map - an
  unmapped upstream string is reported `UNMAPPED` and never written. Rows whose curated value deliberately differs from
  the upstream wording are listed in `overrides` WITH their reason (winget names the copyright TERMS, this table answers
  "does a license have to be bought?"), and are reported as `override` instead of drift. Current state: 69 confirmed,
  7 documented overrides, 0 drift, 1 documented omission. The tool found a real mistake during its first run (the two
  Community Edition rows had been filled with the family's commercial value).
- **Microsoft licenses: type and activation state instead of a description (verified by running the real script on a
  real Windows 11).** `licenseBuildScript` read only `Description` + `PartialProductKey` from
  `SoftwareLicensingProduct` and threw away the fields that actually answer the question. It now also reads `Name`,
  `LicenseFamily` (edition, e.g. `Office19Professional2019R_OEM_Perp`), `ProductKeyChannel` (`Retail`, `OEM:DM`,
  `OEM:NONSLP`, `Volume:MAK`, `Volume:KMSCLIENT`), `LicenseStatus`, `GracePeriodRemaining`, `EvaluationEndDate` and
  `ApplicationID`. The device reports numbers and raw strings; the SERVER translates them (`MS_LICENSE_STATUS`,
  `msLicenseStatusText`, `msLicenseChannelType`) so wording can be fixed without touching a device again, and
  `msLicenseSummary` counts licensed / notLicensed / unknown - a MISSING status counts as unknown, never as a
  violation. Measured effect: an Office edition in status 5 ("notification mode (not activated)") became visible on the
  audit machine; before it hid behind `Description`. The Device list now counts not-activated licenses per device and
  its Details view lists edition, channel and state.
- **Still no full product key, on purpose.** `PartialProductKey` (last five characters) remains the only key material:
  no `DigitalProductId` decode, no firmware `OA3xOriginalProductKey`, no `slmgr`, no activation change - all pinned by
  a script-shape test. A full key is a usable secret, and decoding one is what the AV-flagged key-finder tools do
  (osquery, Apache-2.0, has no product-key table for the same reason). The partial key is additionally stripped
  server-side before `dev_details` answers, so the metadata reaches the browser without it.
- **Fixed a curated rule that never matched (same class as audit 4 / B5).** The Office row read
  `...\ClickToRun\Configuration\ProductIds`; a recursive read of every value name under `ClickToRun` on a real Office
  2019 ClickToRun installation found NO `ProductIds` anywhere - the values are `ProductReleaseIds` (measured
  `Professional2019Retail`, i.e. product + Retail/Volume channel) and `ProductKeys`. The entry now tries `ProductKeys`
  first and falls back to `ProductReleaseIds`, with the measurement in `_source`. Verified end to end by running the
  real script on that machine: the first rule returns empty, first-ok-wins falls through, the second returns the value.
- **Rejected after measurement (documented so nobody re-does it):** a generic registry value-name sweep to raise the
  detection rate automatically - on a real Windows 11 it yielded 16 candidates at depth <= 3 under SOFTWARE and almost
  all were noise (Windows `ProductId`, IE registration, `Schema Library\ActionsPane3`), so it would have filled the
  License column with garbage; and per-device `winget show` calls - 2.5 s per package, NO JSON output in winget 1.29
  (`--output` is rejected) and localized labels, where the server-side manifest route is cheaper and stable.
- Docs: CONTRIBUTING.md gained a full `licenseType` section (closed vocabulary, evidence rule, the tool, overrides,
  "omit rather than guess", edition splits) and the license section now names the Microsoft fields plus the
  measure-don't-guess lesson; README explains the three layers and where each comes from; SECURITY.md states the
  partial-key-only rule and that the new browser-visible Microsoft data is metadata; AGENTS.md module rows, route
  contracts, the CPE-table paragraph, design decision 18 and the testing traps.
- Tests: +3 steps / +58 assertions (790 PASS + 3 SKIP / 105 steps on Windows without a POSIX shell): the sanitizer
  accept/refuse matrix incl. cap and case, apply keeps a valid annotation and drops a bad one WITHOUT losing the row,
  kind rows carry none, `licenseTypeFor` precedence (custom wins) + empty-is-never-guessed + the Community/Ultimate
  split, the shipped-table invariants (vocabulary, documented omission, row order, the `_licenseNote` vocabulary text),
  `add_cpe`/`get_cpe_table`/`show_cpe` round trips, the status/channel/summary helpers incl. the missing-status case,
  the script shape (reads the type fields, never a full key, still read-only, one statement per line, PS parser, the
  msKeys gate travels in the blob), the corrected Office rule shipped AND dispatched (decoded through both base64
  layers), a realistic answer whose first-ok-wins fall-through and translated fields are stored and persisted, the
  redacted log line naming the not-activated count, `lic_status` counters, the CSV header order + types present with NO
  collection run, `sw_fleet`/`sw_details`/`dev_details` carrying the type, `dev_details` dropping the partial key, and
  the push carrying the type but no value. +9 render assertions in test-views (71 PASS): the CPE column + editor field +
  vocabulary prose, the software list column + hover help + widened colspans (which caught a stale `colspan="9"` in the
  panel's Loading row), the license panel's Microsoft disclosure, the device-list not-activated rendering, and the
  asset placeholder doc. The panel inventory fixture was regenerated in the same commit (203 ids).
- Version bumped in config.json and the inventoryscanner.js `@version` header. Version 5.5.1 -> 5.6.0.
