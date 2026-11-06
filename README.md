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

CSVs are Excel-safe (UTF-8 BOM) and neutralized against CSV formula injection (CWE-1236).

### 2. Offline CVE scanner (NVD 2.0)
* The plugin downloads the public NVD JSON feeds (all years, ~2002 to current) **once** into `<datapath>/nvd/`, verifies SHA-256 against the official `.meta` files and refreshes the current year weekly.
* CVE matching is **fully local** — no inventory data ever leaves your server. Only the public feed is fetched.
* Matching is deliberately **conservative**: software is only checked if a curated, NVD-feed-verified CPE mapping exists (built-in table for ~50 common products + your own additions). Everything else is honestly reported as `not assessable` instead of being guessed — so you get almost no false positives, and the blind spot is quantified in every report (CPE coverage %).
* Windows clients (10/11) have no OS CVEs in the NVD; for Windows devices the plugin instead collects the **number of missing Critical/Important updates** from each agent and reports a pending-update state as a `WINDOWS-UPDATES` critical finding.

### 3. Vulnerability assessment panel
Open `https://<server>/pluginadmin.ashx?pin=inventoryscanner&action=show`:

* **Floating location selector** — check the device groups (locations) you want to work on; the selection persists per browser. No click-through per group anymore.
* One aggregated, **sortable and filterable** table of all unique findings across the selected locations (click any column header to sort; text + severity + status filters).
* Rate a CVE (Critical/High/Medium/Low/Unknown) **once** — the rating is saved for *every selected location where the finding occurs* (stored per location, because mitigations are a group decision). A comment is mandatory for ratings.
* **Mark as false positive** (no comment required) — the finding stops counting everywhere (panel, reports, scheduled notifications, CSV shows `false positive`). Undo restores normal counting.
* **Affected locations and devices (host names)** are shown per finding; a *mixed* badge marks findings whose locations carry different ratings.
* **CPE Mapping tab** — the complete built-in + custom software-to-CPE table is visible in the UI. Add new mappings, or override any built-in row (custom entries always win). Stored in `custom-cpe.json`, no source edits needed.
* **Settings tab** - configure everything from the UI: scan interval, which groups are scanned, notification threshold (global + per group), notify mode, feed refresh and inventory collection. Saved to `scanner-settings.json`, effective **immediately without a restart**, and these values **override the same keys in config.json** — the plugin never writes config.json, it only reads it as fallback.

### 4. Printable audit reports (HTML, Print/Save-as-PDF)
A top navigation connects all pages (Assessment Panel / Vulnerability Report / Device Report). Both reports start with an overview page, then **one page per location** (real page breaks for printing), and state their own blind spot (**CPE coverage**) so a low finding count can never be misread as "everything is clean".

* **Vulnerability Report** (`action=report`) — executive summary KPIs, severity distribution, per-location findings (CVE, severity, CVSS, software, version, rating, comment, affected devices). No device list — that is in the Device Report.
* **Device Report** (`action=deviceReport`) — device inventory per location with **host names** (not display names), OS, program counts and per-severity finding counts.

### 5. Scheduled scans with notifications (server-side, no browser needed)
On a configurable interval (e.g. monthly) the server re-scans all groups, stores the result in `<datapath>/nvd/scans.json` and notifies all full site admins via a MeshCentral toast + the server event log listing findings **at or above a per-group severity threshold**:

* Newly appeared findings are marked `(SEVERITY, new)`.
* With "Repeat unrated findings every scan" enabled (`notifyUnratedRepeat`) everything still **without a rating** is repeated every run as `(SEVERITY, open)` — the notification becomes a recurring to-do list that shrinks as you work it.
* Findings with a group rating (or false-positive flag) are never reported again.
* Scheduling is restart-proof (computed from the persisted last-scan timestamp) and safe for intervals beyond 24.8 days.

---

## Requirements

* MeshCentral (any current release; tested against 1.x). Works in Docker and bare-metal installs.
* **Full site administrator** (`siteadmin`) — every plugin endpoint is gated; there is no viewer role.
* Outbound HTTPS to `nvd.nist.gov` for the initial feed download (then weekly, current year only). All matching runs offline.
* Disk space for the NVD feed data under `<datapath>/nvd/` (several GB uncompressed).
* Agents connected at least once so software/Windows-update inventory can be collected (the plugin queries online agents and caches results per device; offline devices keep their last known state).

## Installation

1. **Copy the plugin folder `inventoryscanner`** into the MeshCentral data path (folder name = shortName, alphanumeric):

   ```
   <datapath>/plugins/inventoryscanner/
     inventoryscanner.js
     config.json
     views/assessment.handlebars
     views/report.handlebars
     views/deviceReport.handlebars
   ```

   Docker example — get the source and copy the plugin folder into the running container:

   ```bash
   git clone https://github.com/derStephan/meshcentral-inventoryscanner.git
   cd meshcentral-inventoryscanner
   docker cp inventoryscanner meshcentral:/opt/meshcentral/meshcentral-data/plugins/
   ```

   The data volume survives MeshCentral updates/reinstalls.

2. **Enable the plugin** (required) - add this under `"settings"` in `<datapath>/config.json`:

   ```json
   "settings": {
     "plugins": { "enabled": true, "list": ["inventoryscanner"] }
   }
   ```

3. **That is all `config.json` needs.** The three toolbar buttons above the device list (Hardware Inventory,
   Software Inventory, Vulnerability Assessment) are injected by the plugin itself into MeshCentral's own
   button slot when the page loads - no further server configuration.

   The plugin works without them too: everything is reachable via URLs and bookmarks, and the panel links
   every page (reports, CSV exports) from its top navigation.

   Scanner and collection settings are managed in the panel's [Settings tab](#configuration) (effective
   immediately, no restart); the file keys there are optional fallbacks only.

4. **Restart** the server (`docker compose restart meshcentral`) and hard-reload the admin UI (Ctrl+F5).

On first start the plugin downloads the NVD feeds (all years — this can take a while, watch `<datapath>/nvd/nvd-download.log`). Panel and reports work as soon as the feeds are indexed.

## Configuration

**Everything is configured in the panel Settings tab** - no file editing, and changes take effect immediately
without a restart. Values are stored in `<datapath>/plugins/inventoryscanner/scanner-settings.json` and
**override the same keys in `config.json`** (which the plugin never writes). Per-field "revert to config.json"
and a global "Reset all" hand control back to the file.

The Settings tab covers: scan interval + which device groups are scanned, notification switch, threshold
(global and per group) and repeat mode, NVD feed refresh, suppression of ancient "any version" CVEs, and the
inventory collection interval / on-connect behavior.

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
| `anyCveMaxAgeYears` | `5` | "Suppress version-less CVEs older than N years" (`0` = never) |
| `collectIntervalMinutes` (*`inventoryScanner`* section) | `1440` | Collect inventory every N minutes (`0` = off) |
| `collectOnAgentConnect` (*`inventoryScanner`* section) | `true` | "Collect when an agent connects" |

Group ids are MeshCentral mesh `_id`s formatted `mesh/<domain>/<name>` - in the default domain that means a
double slash, e.g. `mesh//Server1`. Easiest lookup: the checkbox `value`s in the panel (view page source) or
the `meshes` collection in the database.

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
  browser caches the UI scripts).* Ratings, comments, CPE mappings and UI settings live under `<datapath>/nvd/` and
  `<datapath>/plugins/inventoryscanner/` - see [Data written](#data-written-by-the-plugin).

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
<datapath>/nvd/cpe-tokens.json             CPE dictionary lookup cache
<datapath>/nvd/nvd-download.log            feed download log
<datapath>/plugins/inventoryscanner/custom-cpe.json      your CPE mappings
<datapath>/plugins/inventoryscanner/scanner-settings.json  values saved in the Settings tab
<datapath>/plugins/inventoryscanner/data/<nodeid>/       collected software + Windows-update state per device
```

## Privacy & security

* No inventory data is ever transmitted anywhere — the only outbound request is the public NVD feed (and the
  public NVD **CPE dictionary API**, once per unknown product token, cached).
* Full-site-admin only; all endpoints re-check `user.siteadmin` on the server.
* Device selection for exports uses MeshCentral's own rights-validated node ids.
* Output hardening: HTML escaping at render time, CSV formula-injection neutralization, strict id validation on
  write endpoints (key-poisoning guard for `assessments.json`).

## Known limitations (by design)

* **Windows clients 10/11:** the NVD carries no OS CVEs for them — the missing-updates count is the indicator instead.
* **Coverage:** only software with a curated/own CPE mapping is CVE-checked; OEM drivers/utilities are `not assessable`
  (they are patched via vendor channels, not NVD/MSRC). Every report states its CPE coverage percentage.
* **Offline devices** show their last collected state; check the inventory age before trusting a device row.
* The toast notification is ephemeral — if no admin is logged in at scan time, read it in **My Server → Events**
  (event retention applies, default ~30 days).

## Troubleshooting

* **Panel/reports say "NVD database: not downloaded"** with 0 indexed CVEs → the feed download failed; inspect
  `<datapath>/nvd/nvd-download.log` (rate limits, proxy) and restart the server to retry.
* **HTTP 401 on the admin panel** → `shortName`/folder must be alphanumeric (`inventoryscanner`), and you must be a
  full site admin.
* **Toolbar buttons missing** — plugins are not enabled (Installation step 2), the server was not
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
- **Changelog**: Version history in [CHANGELOG.md](CHANGELOG.md).

Latest audit: **78/78 tests pass**, 1 critical bug fixed (`anyCveMaxAgeYears` settings overlay), ~466 lines dead code removed, all security controls verified.

## License

MIT — see [LICENSE](LICENSE).
