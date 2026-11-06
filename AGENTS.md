# AGENTS.md — MeshCentral Inventory & Vulnerability Scanner Plugin

Guide for AI agents working on this repository. Everything stated here was verified against the running code and
the test suite in `tools/`; trust the code and these notes over assumptions.

Repository: https://github.com/derStephan/meshcentral-inventoryscanner

## Repository layout

```
inventoryscanner/              the deployable plugin (this exact folder is copied to <datapath>/plugins/)
  inventoryscanner.js          server code + browser-exported functions (module.exports.inventoryscanner(parent))
  config.json                  MeshCentral plugin manifest (shortName, hasAdminPanel)
  views/assessment.handlebars  admin panel (incl. its inline <script> — the panel logic lives HERE)
  views/report.handlebars      printable vulnerability report (overview + one page per location)
  views/deviceReport.handlebars printable device inventory report (host names, one page per location)
tools/                         self-contained verification for agents (no MeshCentral server needed)
  check.js                     node --check on JS, inline-script extraction check, JSON validity, render-name match
  test-plugin.js               behavioral tests against the real plugin module with mocked MeshCentral
  test-views.js                compiles+renders all three views with Handlebars (needs `npm install`)
README.md                      user-facing documentation
package.json                   repo metadata; `npm test` runs tools/check.js + tools/test-plugin.js + tools/test-views.js
```

## What the plugin does

Pure admin tool for MeshCentral (all endpoints gated on full site admin, `user.siteadmin === 0xFFFFFFFF`):

1. **Device-list toolbar CSV exports** (hardware / software / vulns) via MeshCentral Custom UI
   (`customui.devicesbarbuttons`) → `uiCustomEvent(command, myparent)` → CSV pushed over the websocket → browser
   `saveAs()` via the exported `inventoryCsv` function.
2. **Offline CVE scan** against locally cached NVD 2.0 feeds (`<datapath>/nvd/`), conservative curated CPE matching.
3. **Assessment panel** (`pluginadmin.ashx?pin=inventoryscanner&action=show`): multi-location CVE review, group-wide
   ratings (mandatory comment), false-positive flags (optional comment), filter/sort, CPE Mapping management tab.
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
- **`pluginadmin.ashx` GET** → `handleAdminReq(req,res,user)`, `POST` (urlencoded body → `req.body`) →
  `handleAdminPostReq`. Session auth only — the plugin does its own siteadmin gate.
- **Views:** `res.render('<name>', data)` ↔ `views/<name>.handlebars` — **case-sensitive** on Linux.
  Only core Handlebars helpers exist (`each if unless with @index @last @key`); no `Object.keys`, no custom helpers.
- **Device-list actions:** the built-in action menu is NOT plugin-extensible; Custom UI
  `devicesbarbuttons` (`action:'event'`, `logmsg`, `selection:'one'|'many'`) is the sanctioned way. Selected node
  ids arrive on the **top level** as `command.selectedDevices` (NOT `command.src`); `uiCustomEvent` is called on
  every plugin for every Custom UI event.
- **Browser functions:** listed in `obj.exports`, serialized into `/pluginHandler.js`; server pushes
  `{action:'plugin', plugin:'inventoryscanner', method:'inventoryCsv'|'openAssessment', ...}` and the front-end
  calls `obj.<method>(server, message)`.
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
| `show` | `showAssessmentPanel` | renders `assessment` with `{shortName, meshList, lastUpdate, lastScan, scanIntervalHours, totalCves}` |
| `scan` | `assessmentScan` | JSON via `scanMultiMeshCves(meshIds)`; `?mesh=<id>,<id>,...` (comma-separated) |
| `report` | `vulnerabilityReport` | renders `report` with `{shortName, report: buildOverallReport(), totalCves, lastUpdate}` |
| `deviceReport` | `deviceReport` | renders `deviceReport`, same data |

POST body `action=`:

| action | Keys | Notes |
|---|---|---|
| `save_assessment` | `meshId` or `meshIds` (comma list), `cveId`, `assessment`, `comment` | comment **mandatory**; id must match `CVE-\d{4}-\d{4,}` or be `WINDOWS-UPDATES`; mesh ids validated `^mesh/[^:]+$`; comment trimmed, ≤1000 chars, stored **raw** |
| `flag_false_positive` | `meshId(s)`, `cveId`, `comment?` | comment **optional** (empty stays empty); sets `assessment:'UNKNOWN', flagged:true` |
| `unflag_false_positive` | `meshId(s)`, `cveId` | deletes flagged entries for all given meshes |
| `get_cpe_table` | — | `{entries:[{match,vendor,product,source:'built-in'|'custom'}]}` |
| `delete_cpe_table` | `match`,`vendor`,`product` | custom entries only (built-ins can be shadowed, not deleted) |
| `add_cpe` | `match`,`vendor`,`product` | regex validated via `new RegExp`; custom wins over built-in |
| `get_locations` | — | all non-deleted meshes `{locations:[{id,name}]}` (API only; panel renders `meshList` server-side) |
| `remove_cpe` | `index` | legacy index-based removal |

Assessments persist in `<datapath>/nvd/assessments.json`, key `"<meshId>:<cveId>"` →
`{meshId, cveId, assessment, comment, lastModified, assessedBy, assessedById, flagged?}`.
Scheduled results in `<datapath>/nvd/scans.json` → `meshId -> {time, cves:[{cve, severity, ...}]}`.

**`scan` response shape** (drives the panel JS):
`{ meshes:[{id,name}], cves:[{cve, severity, cvss, description, software, version,
locations:[{meshId,name,devices:[hostnames]}], assessments:{meshId:rec|null}, assessment:rec|null,
mixed:bool, anyFlagged:bool}], flaggedCount, totalCves, lastUpdate }`.
`mixed` = at least one but not all affected locations carry (differing) assessments; `assessment` is set only when
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
- The inline JS must contain **no `{{`** (Handlebars would consume it) except the intended `'{{shortName}}'` token.
  `tools/check.js` enforces both this and `node --check` on the extracted script.

## Design decisions (with reasons)

1. **Conservative matching:** curated `SOFTWARE_CPE_TABLE` (+`custom-cpe.json`) only; no token guessing, no
   publisher/vendor guessing, no cross-vendor matches. False negatives acceptable, false positives not.
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

## Configuration keys (server config.json → settings)

The README contains a fully annotated `config.json` example — keep it in sync when adding/renaming keys.

- `plugins.list: ["inventoryscanner"]` — enables the plugin (local-copy installs don't appear in the plugin store UI).
- `domains.""-customui.devicesbarbuttons` — toolbar buttons, see README.
- `vulnerabilityScanner`: `scanIntervalHours` (720 = monthly OK), `scanMeshes`, `notifyOnScan`, `notifyThreshold`,
  `notifyUnratedRepeat`, `notify` (per-group), `updateHours` (feed refresh), `anyCveMaxAgeYears` (default 5;
  suppresses ancient `kind:'any'` version-less CVE matches).
- `inventoryScanner`: `collectIntervalMinutes` (default 1440, 0=off), `collectOnAgentConnect` (default true).

## Testing before committing changes

```bash
npm install        # once (dev dependency: handlebars)
npm test           # = tools/check.js && tools/test-plugin.js && tools/test-views.js
```

- `tools/check.js`: `node --check` on the plugin, inline-script syntax/`{{`-hazard check, JSON validity of
  config files, and view-name↔render-name consistency. Must run anywhere (no dependencies).
- `tools/test-plugin.js`: ~55 behavioral assertions against the real module (mocked MeshCentral DB/webserver):
  locations grouping & counting, manual-rating severity override, FP exclusion, host-name preference, coverage
  numbers, multi-mesh scan/`mixed` logic, all POST handlers incl. validation/rejections, routes, admin gating
  (401), CPE table add/delete, vulns CSV header/content, `longTimeout` chunking, restart-proof schedule delays,
  scheduled-scan notification content in repeat and once mode, NVD-status derivation.
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
- The panel auto-scans ALL locations on load — cheap locally (no network) but DB-heavy on huge fleets; if that ever
  matters, make the initial scan opt-in rather than removing the floating selector.
- NVD feed download: sequential per year with retries and pauses (rate limits). A stale-looking `.meta` mismatch is
  a warning, not an error (verified NVD behavior). Never treat `.json.gz` presence alone as "feed exists" — the
  decompressed `.json` is what `loadNvdFromAllFiles` reads.

## Current verified state (last known-good)

All of the above implemented and green: `node --check` OK; panel inline JS parses; 3 views render with and without
data; full logic suite passes (see `tools/test-plugin.js`), including the monthly-scheduling and notification-mode
tests. UI flow: floating location picker → one aggregated sortable/filterable table → one-click multi-location
rating/FP → CPE Mapping tab with built-in table visibility + overrides → two printable reports with navigation and
per-location pages → scheduled monthly scans with toast/event-log notifications that re-list open findings.
