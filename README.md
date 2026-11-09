# MeshCentral Inventory & Vulnerability Scanner Plugin

> **Transparency**: Created with **Qwen 3.6 27B** & **Qwen 3.8 Flash Next** • Audited by **NVIDIA Nemotron 3 550B A55B** (2026-11-06)

A [MeshCentral](https://github.com/Ylianst/MeshCentral) plugin that turns your MeshCentral server into an offline
software/vulnerability inventory: CSV exports for audits, an NVD-based CVE scanner that works without sending any
inventory data to the internet, a group-wide vulnerability assessment panel, printable audit reports and automatic
scheduled scans with admin notifications.

**Audience:** MeshCentral site administrators who need to know *which software is installed where, which of it has
known CVEs, which findings have already been assessed by the team, and what is left to do* — without buying a
commercial vulnerability scanner.

---

## Features

### 1. Inventory CSV exports

Two ways to export, depending on what you need:

* **Device-list toolbar** — appears automatically, nothing to configure; select devices in any group and export exactly those:

  | Button (`logmsg`) | Result |
  |---|---|
  | **Hardware Inventory** (`hardware`) | CSV: CPU, GPU, memory (banks), disks, network, BIOS/UEFI, mainboard, chassis, TPM — from the stored sysinfo, so it works offline |
  | **Software Inventory** (`software`) | CSV: one row per installed application: name, version, publisher, location, install date |
  | **Vulnerability Assessment** (`assessment`) | Opens the assessment panel in a new tab (no CSV) — works without any device selection |

* **Direct links (all devices, no selection needed)** — in the panel navigation, as bookmarks, or via the
  always-enabled **Vulnerability Assessment** toolbar button:

  ```
  /pluginadmin.ashx?pin=inventoryscanner&action=export&type=hardware|software|vulns
  ```

  The `vulns` export has one row per software/OS finding with a `Status` column:
  `CVE`, `no CVE for <product>`, `not assessable` or `false positive`.

    Software entries without a version number (hotfixes, add-ons) are handled conservatively: only
    CVEs applying to ALL versions are asserted for them, so historical version-bounded findings never
    flood the list.

CSVs are Excel-safe (UTF-8 BOM) and neutralized against CSV formula injection (CWE-1236).

### 2. Offline CVE scanner (NVD 2.0)
* The plugin downloads the public NVD JSON feeds (all years, ~2002 to current) **once** into `<datapath>/nvd/`, verifies SHA-256 against the official `.meta` files and refreshes the current year weekly.
* CVE matching is **fully local** — no inventory data ever leaves your server. Only the public feed is fetched.
* Matching works on two levels, both fully offline: a curated CPE table (built-in entries for common products,
  your own additions) maps tricky display names exactly; everything else is mapped by an **automatic evidence
  matcher** - display names are normalized and only accepted when the resulting CPE product token provably
  exists in the downloaded NVD data, the publisher resolves the vendor, and every version is re-checked
  against the CVE range. This mirrors how OWASP Dependency-Check matches evidence to CPEs, just without any
  API call or configuration. Names that prove nothing stay `not assessable` - no guessing, so false
  positives stay rare while coverage rises; the blind spot is quantified in every report (CPE coverage %). software is only checked if a curated, NVD-feed-verified CPE mapping exists (built-in table for ~50 common products + your own additions). Everything else is honestly reported as `not assessable` instead of being guessed — so you get almost no false positives, and the blind spot is quantified in every report (CPE coverage %).
* Windows clients (10/11) have no OS CVEs in the NVD; for Windows devices the plugin instead collects the **number of missing Critical/Important updates** from each agent and reports a pending-update state as a `WINDOWS-UPDATES` critical finding.

### 3. Vulnerability assessment panel
Open `https://<server>/pluginadmin.ashx?pin=inventoryscanner&action=show`:

* **Floating location selector** — check the device groups (locations) you want to work on; the selection persists per browser. No click-through per group anymore.
* One aggregated, **sortable and filterable** table of all unique findings across the selected locations (click any column header to sort; text + severity + status filters).
* Rate a CVE (Critical/High/Medium/Low/Unknown) **once** — the rating is saved for *every selected location where the finding occurs* (stored per location, because mitigations are a group decision). A comment is mandatory for ratings.
* **Mark as false positive** (no comment required) — the finding stops counting everywhere (panel, reports, scheduled notifications, CSV shows `false positive`). Undo restores normal counting.
* **Affected locations and devices (host names)** are shown per finding; a *mixed* badge marks findings whose locations carry different ratings.
* **CPE Mapping tab** - the table actually in use is visible in the UI: the mapping table maintained in this
  repository (`cpe-table.json`, auto-refreshed) or its built-in fallback, plus your custom entries (always
  checked first). Improving a mapping is a one-line repository change - no plugin release, no server edit.
* **Updates tab** - winget auto-update control: groups, ignore list, Windows device dropdown (given names first),
  per-device exclusion, single-device runs and dry runs, results table and full log.
* **Settings tab** - configure everything from the UI: scan interval, which groups are scanned, notification threshold (global + per group), notify mode, feed refresh and inventory collection. Saved to `scanner-settings.json`, effective **immediately without a restart**, and these values **override the same keys in config.json** — the plugin never writes config.json, it only reads it as fallback.

### 4. Printable audit reports (HTML, Print/Save-as-PDF)
A top navigation connects all pages (Assessment Panel / Settings / CPE Mapping / Updates / Vulnerability
Report / Device Report). Both reports start with an overview page, then **one page per location** (real page breaks for printing), and state their own blind spot (**CPE coverage**) so a low finding count can never be misread as "everything is clean".

* **Vulnerability Report** (`action=report`) — executive summary KPIs, severity distribution, per-location findings (CVE, severity, CVSS, software, version, rating, comment, affected devices). No device list — that is in the Device Report.
* **Device Report** (`action=deviceReport`) — device inventory per location with **host names** (not display names), OS, program counts and per-severity finding counts.

### 5. Scheduled scans with notifications (server-side, no browser needed)
On a configurable interval (e.g. monthly) the server re-scans all groups, stores the result in `<datapath>/nvd/scans.json` and notifies all full site admins via a MeshCentral toast + the server event log listing findings **at or above a per-group severity threshold**:

* Newly appeared findings are marked `(SEVERITY, new)`.
* With "Repeat unrated findings every scan" enabled (`notifyUnratedRepeat`) everything still **without a rating** is repeated every run as `(SEVERITY, open)` — the notification becomes a recurring to-do list that shrinks as you work it.
* Findings with a group rating (or false-positive flag) are never reported again.
* Scheduling is restart-proof (computed from the persisted last-scan timestamp) and safe for intervals beyond 24.8 days.

---

### 6. Automatic software updates via winget (opt-in)

The plugin can keep Windows endpoints patched through the official **winget** package manager -
automatically or on demand from the panel's **Updates** tab. It is completely opt-in: nothing runs until you
enable it *and* tick at least one device group. Browsing devices, editing exclusions and running dry
runs works with the switch off - only actual upgrades require it.

* **Two-phase per device, package by package**: one script run lists everything with an available upgrade
  (`winget list --upgrade-available`), then upgrades the applicable ones individually
  (`winget upgrade --id <id> --exact --silent --accept-package-agreements ...`). No `--all` is ever
  issued, so nothing outside the plan gets touched. Installers run silently; a device is never rebooted.
* **Ignore list (license protection)**: package ids you add (e.g. `Adobe.Acrobat.Reader.64-bit`) are
  skipped in every batch - and additionally pinned on the client with `winget pin add --installed`, so
  even a manual `winget upgrade --all` by a user leaves the licensed version in place. Remove an entry
  from the list to let updates flow again.
* **Per-device control**: the device dropdown holds every machine (sorted by location, then name).
  *Exclude* keeps a device out of every automatic and manual batch (kiosk PCs, presentation laptops),
  *Include again* puts it back, *Update this device now* patches exactly that one machine.
  A dry run shows what would happen first, without touching anything.
* **Scheduling without intervals**: a device is updated as soon as it connects on a calendar day it has
  not been updated on yet - and at the latest 24 h after its previous run if the connection never dropped.
  Batches run two devices in parallel; offline devices are simply picked up at the next connect.
* **Full audit trail**: every batch is logged line by line (`winget-update.log`, tailable in the UI), and
  the per-device result table shows which package went from which version to which - or why it failed
  (exit code + last installer output).
* **Requirements on the client**: Windows 10 1809+/11 with winget available (App Installer). Devices
  without it are reported as such per run - nothing else about the batch changes.

## Requirements

* MeshCentral (any current release; tested against 1.x). Works in Docker and bare-metal installs.
* **Full site administrator** (`siteadmin`) — every plugin endpoint is gated; there is no viewer role.
* Outbound HTTPS to `nvd.nist.gov` for the initial feed download (then weekly, current year only). All matching runs offline.
* Disk space for the NVD feed data under `<datapath>/nvd/` (several GB uncompressed).
* Agents connected at least once so software/Windows-update inventory can be collected (the plugin queries online agents and caches results per device; offline devices keep their last known state).

## Installation

The plugin installs from this repository directly in the MeshCentral web UI. The one and only manual file
edit is enabling plugins itself - without it MeshCentral does not show a plugin page at all:

1. **Enable plugins (one time)** - add under `"settings"` in `<datapath>/config.json`:

   ```json
   "settings": { "plugins": { "enabled": true } }
   ```

   Do **not** add a `"list"` here: that is MeshCentral's development mode and it ignores DB-installed
   plugins. Restart the server once (`docker compose restart meshcentral`).

2. **Add the plugin** - log in as full administrator, go to **My Server -> Plugins**, click **Download
   plugin** and paste exactly this URL:

   ```
   https://raw.githubusercontent.com/derStephan/meshcentral-inventoryscanner/main/config.json
   ```

3. **Install it** - the plugin appears in the list below, still disabled. Enable it there; MeshCentral
   downloads the files into `<datapath>/plugins/inventoryscanner/` (data volume - survives MeshCentral
   updates) and registers them in its database. Obey the yellow restart notice and restart the server
   once more - that is all.

4. **Hard-reload the browser** (Ctrl+F5). Done: the toolbar buttons above the device list appear
   automatically (the plugin injects them itself), the assessment panel opens, and first run starts the
   NVD feed download (all years, several GB - the panel Settings tab tails `nvd-download.log` live, no shell needed). Scanning and
   reports work as soon as the feeds are indexed.

Updates appear on the same **Plugins** page without any release ceremony: bump the version in
this repository's config.json and push - every server checks that file and offers an update
(the install always pulls the current downloadUrl ZIP). Git tags are not used; a "downgrade to a
specific version" picker is deliberately not offered.

### Install & startup timings (what to expect)

Installation and the first start are **asynchronous** - a freshly installed plugin can look "incomplete"
for a while, and that is normal:

1. **ZIP extraction** (seconds to a few minutes - slower on small VMs or with aggressive antivirus
   scanning): files land in alphabetical order, so the root files appear first and `tools/` + `views/`
   **last**. While extraction is still running, `inventoryscanner.js` may briefly exist as a 0-byte file
   and the Plugins page still shows **Disabled** - the status flips to Enabled only once the archive is
   completely unpacked. Do not inspect, restart or re-install during this phase.
2. **Server restart** (the yellow notice): the plugin code is loaded with the server, not before.
3. **NVD feed download on first start**: all years, several GB - typically 10-60 minutes depending on
   the connection. The Settings tab shows the tail of `<datapath>/nvd/nvd-download.log` (last 200

   lines, refresh button), so no server shell is needed. Until the feeds are indexed, the panel
   shows "NVD database: not downloaded yet" and scans cannot report CVEs. The first full scan of all
   locations runs automatically right after (baseline).
4. **Inventory collection**: software lists and the Windows-update state arrive per device when the
   agent connects (default) and on the collection interval. A device that never reported shows an
   empty software list - that means "not collected yet", **not** "clean". Offline devices keep their
   last cached inventory.

Reports, CSVs and coverage numbers are only meaningful after steps 3 and 4 have completed at least once.

## Configuration

**Everything is configured in the panel Settings tab** - no file editing, and changes take effect immediately
without a restart. Values are stored in `<datapath>/plugins/inventoryscanner/scanner-settings.json` and
**override the same keys in `config.json`** (which the plugin never writes). Per-field "revert to config.json"
and a global "Reset all" hand control back to the file.

The Settings tab covers: scan interval + which device groups are scanned, notification switch, threshold
(global and per group) and repeat mode, NVD feed refresh (+ "Update NVD database now" button; progress in the download
log below), suppression of ancient "any version" CVEs, and the
inventory collection interval / on-connect behavior, the automatic CPE-matching switch and the repository

### config.json (optional)

Only the `plugins` block is required (see [Installation](#installation)). The scanner keys are a fallback for
file-based setups or unattended installs - MeshCentral supports `//` comments. Anything saved in the Settings
tab wins over these values until you revert it.

| Key (under `settings.vulnerabilityScanner`) | Default | Equivalent in the Settings tab |
|---|---|---|
| `scanIntervalHours` | `24` | Scan interval in hours (`0` = off); timed from the end of the last scan, restart-proof |
| `scanMeshes` | all | Group table "Scan" checkboxes (empty selection = all groups) |
| `notifyOnScan` | `true` | "Notify admins after scans" |
| `notifyThreshold` | `"HIGH"` | Global notify threshold (CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN) |
| `notify` (`meshId` -> severity) | - | Group table per-group threshold (empty = global) |
| `notifyUnratedRepeat` | `false` | "Repeat unrated findings every scan" (`open` instead of only `new`) |
| `updateHours` | `168` | NVD feed refresh in hours |
| `autoProductMatch` | `true` | Automatic evidence matching for names without a table entry (Settings: "Auto-map") |
| `cpeTableEnabled` | `true` | Re-download the curated table from the repository with every NVD refresh |
| `cpeTableUrl` | (this repo's `cpe-table.json`) | https URL of the maintained table (own fork/copy allowed) |
| `anyCveMaxAgeYears` | `5` | "Suppress version-less CVEs older than N years" (`0` = never) |
| `collectIntervalMinutes` (*`inventoryScanner`* section) | `1440` | Collect inventory every N minutes (`0` = off) |
| `collectOnAgentConnect` (*`inventoryScanner`* section) | `true` | "Collect when an agent connects" |
| `enabled` (*`wingetUpdater`* section) | `false` | Automatic winget updates on/off (Updates tab) |
| `updateMeshes` (*`wingetUpdater`* section) | none | Device groups that receive automatic updates |
| `excludeNodes` (*`wingetUpdater`* section) | none | Node ids permanently excluded from batches |
| `ignorePackages` (*`wingetUpdater`* section) | none | `[{id, note}]` package ids never upgraded (also client-pinned) |
| `pinSync` (*`wingetUpdater`* section) | `true` | Keep the client-side pins in sync with the ignore list |

Group ids are MeshCentral mesh `_id`s formatted `mesh/<domain>/<name>` - in the default domain that means a
double slash, e.g. `mesh//Server1`. Easiest lookup: the checkbox `value`s in the panel (view page source) or
the `meshes` collection in the database.

### Maintaining the CPE mapping table

The curated display-name-to-CPE table is maintained in **this repository** as [cpe-table.json](cpe-table.json).
Every server running the plugin re-downloads it with each NVD feed refresh (and at startup when stale) and caches
it locally - so a new or corrected mapping shows up everywhere without shipping a new plugin version.

```json
{ "entries": [ { "match": "^Example App", "vendor": "example", "product": "example_app" } ] }
```

* `match` is a JavaScript regex matched case-insensitively against the display name; `vendor`/`product` must be
  real CPE codes from the NVD. Invalid entries or a broken file are rejected - the previous table stays active.
* Air-gapped servers keep working on the built-in fallback table; the CPE Mapping tab always states which table
  is in force and when it was last fetched.
* Want your own table? Set the URL in the Settings tab (https only) or turn the auto-update off there.

### Toolbar buttons (recap)

The plugin adds its three buttons to MeshCentral's own device-list button slot (`devsCustomUIBar`) when the
page finishes loading - no configuration, and nothing to keep in sync. The click handlers mirror the built-in
behavior: checked devices are collected from the list and handed to the plugin's server code; without a
selection the CSV buttons ask for one and the assessment button opens the panel anyway. If a slot shows
another plugin's buttons, ours are left out (no duplicates).

### Notes

* `vulnerabilityScanner` and `inventoryScanner` are **siblings of `plugins`** directly under `settings`. The two
  section names differ by one letter; a typo silently keeps defaults.
* Settings-tab changes need **no restart**; `config.json` changes need a server restart (and Ctrl+F5, the
  browser caches the UI scripts).
* Ratings, comments, CPE mappings and UI settings live under `<datapath>/nvd/` and
  `<datapath>/plugins/inventoryscanner/` - see [Data written](#data-written-by-the-plugin).
* Stale registry duplicates: when the same program appears twice (upgrader leftovers like a
  "Firefox 3.6.24" row next to "Firefox 121.0.1", or a chain of "Java 8 Update NNN" rows), only the
  newest version per product is scanned - years-old CVEs are not reported against patched software.
  Products that genuinely install side by side (Java major releases, Python/.NET minors, VC++
  runtimes) are kept separate on purpose.

## URLs

| Page | URL |
|---|---|
| Assessment panel | `/pluginadmin.ashx?pin=inventoryscanner&action=show` |
| Vulnerability report | `/pluginadmin.ashx?pin=inventoryscanner&action=report` |
| Device report | `/pluginadmin.ashx?pin=inventoryscanner&action=deviceReport` |
| CSV download (all devices) | `/pluginadmin.ashx?pin=inventoryscanner&action=export&type=hardware` (or `software`, `vulns`) |

## Data written by the plugin

```
<datapath>/nvd/nvdcve-2.0-<year>.json      NVD feed cache (offline matching)
<datapath>/nvd/assessments.json            group ratings + false-positive flags
<datapath>/nvd/scans.json                  scheduled scan snapshots
<datapath>/nvd/nvd-download.log            feed download log
<datapath>/plugins/inventoryscanner/custom-cpe.json      your CPE mappings
<datapath>/plugins/inventoryscanner/cpe-table.json       cached copy of the repository CPE table
<datapath>/plugins/inventoryscanner/scanner-settings.json  values saved in the Settings tab
<datapath>/plugins/inventoryscanner/winget-results.json        last winget batch result per device
<datapath>/plugins/inventoryscanner/winget-update.log          winget batch log (rotated at ~5 MB)
<datapath>/plugins/inventoryscanner/data/<nodeid>/       collected software + Windows-update state per device
```

## Privacy & security

* No inventory data is ever transmitted anywhere — the only outbound request is the public NVD feed.
  The automatic CPE matching runs entirely against the already-downloaded feed data; no dictionary API exists.
* Full-site-admin only; all endpoints re-check `user.siteadmin` on the server.
* Device selection for exports uses MeshCentral's own rights-validated node ids.
* Output hardening: HTML escaping at render time, CSV formula-injection neutralization, strict id validation on
  write endpoints (key-poisoning guard for `assessments.json`).

## Known limitations (by design)

* **Windows clients 10/11:** the NVD carries no OS CVEs for them — the missing-updates count is the indicator instead.
* **Coverage:** software is CVE-checked when a curated/custom mapping matches or the automatic evidence matcher
  proves a real NVD product; OEM drivers/utilities usually stay `not assessable` (they are patched via vendor
  channels, not NVD/MSRC). Every report states its CPE coverage percentage.
* **Linux snap/DEB wrapper versions:** strings like '1:1snap1-0ubuntu5' contain no upstream version (the real
  Firefox lives inside the snap), so such rows are treated as unknown-version and only carry
  all-version, age-filtered findings. Ordinary DEB versions (epochs and '-1ubuntu2' suffixes)
  are parsed down to their numeric core. For snap apps run 'snap list' on the box if you need the exact release.
* **Offline devices** show their last collected state; check the inventory age before trusting a device row.
* The toast notification is ephemeral — if no admin is logged in at scan time, read it in **My Server → Events**
  (event retention applies, default ~30 days).

## Troubleshooting

* **Panel/reports say "NVD database: not downloaded"** with 0 indexed CVEs → the feed download failed; inspect
  `<datapath>/nvd/nvd-download.log` (rate limits, proxy) and restart the server to retry.
* **HTTP 401 on the admin panel** → `shortName`/folder must be alphanumeric (`inventoryscanner`), and you must be a
  full site admin.
* **Toolbar buttons missing** — plugins are not enabled (Installation step 1), the server was not
  restarted, or the browser cached the UI scripts: hard-reload (Ctrl+F5).
* **Empty software lists** → agents were never online since installation, or collection is disabled
  (`inventoryScanner.collectIntervalMinutes: 0` + connect-time collection).

## Development / testing

`tools/` contains dependency-light checks for the repo itself:

```bash
npm install          # pulls handlebars (dev dependency) for the view tests
npm test             # node --check + logic tests + view render tests
```

See [AGENTS.md](AGENTS.md) for the full technical description aimed at AI agents.

## Security & Audit

- **Security Policy**: See [SECURITY.md](SECURITY.md) for supported versions, reporting, and architecture.
- **Audit Report**: Full formal & functional verification in [AUDIT.md](AUDIT.md) (2026-11-06).
- **Changelog**: the [commit history](https://github.com/derStephan/meshcentral-inventoryscanner/commits/main) - every change is described there.

Latest audit: **78/78 tests pass**, 1 critical bug fixed (`anyCveMaxAgeYears` settings overlay), ~466 lines dead code removed, all security controls verified.

## License

MIT — see [LICENSE](LICENSE).
