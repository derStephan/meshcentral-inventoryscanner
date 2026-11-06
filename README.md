# MeshCentral Inventory & Vulnerability Scanner Plugin

A [MeshCentral](https://github.com/Ylianst/MeshCentral) plugin that turns your MeshCentral server into an offline
software/vulnerability inventory: CSV exports for audits, an NVD-based CVE scanner that works without sending any
inventory data to the internet, a group-wide vulnerability assessment panel, printable audit reports and automatic
scheduled scans with admin notifications.

**Audience:** MeshCentral site administrators who need to know *which software is installed where, which of it has
known CVEs, which findings have already been assessed by the team, and what is left to do* — without buying a
commercial vulnerability scanner.

---

## Features

### 1. Inventory CSV exports (device-list toolbar)
Select devices in any group and export via new toolbar buttons:

| Export | Content |
|---|---|
| **Hardware** | CPU, GPU, memory (banks), disks, network, BIOS/UEFI, mainboard, chassis, TPM — from the stored sysinfo, so it works offline |
| **Software** | One row per installed application: name, version, publisher, location, install date |
| **Vulnerability Scan** | One row per software/OS finding, with a `Status` column: `CVE`, `no CVE for <product>`, `not assessable` or `false positive` |

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

### 4. Printable audit reports (HTML, Print/Save-as-PDF)
A top navigation connects all pages (Assessment Panel / Vulnerability Report / Device Report). Both reports start with an overview page, then **one page per location** (real page breaks for printing), and state their own blind spot (**CPE coverage**) so a low finding count can never be misread as "everything is clean".

* **Vulnerability Report** (`action=report`) — executive summary KPIs, severity distribution, per-location findings (CVE, severity, CVSS, software, version, rating, comment, affected devices). No device list — that is in the Device Report.
* **Device Report** (`action=deviceReport`) — device inventory per location with **host names** (not display names), OS, program counts and per-severity finding counts.

### 5. Scheduled scans with notifications (server-side, no browser needed)
On a configurable interval (e.g. monthly) the server re-scans all groups, stores the result in `<datapath>/nvd/scans.json` and notifies all full site admins via a MeshCentral toast + the server event log listing findings **at or above a per-group severity threshold**:

* Newly appeared findings are marked `(SEVERITY, new)`.
* With `notifyUnratedRepeat: true` everything still **without a rating** is repeated every run as `(SEVERITY, open)` — the notification becomes a recurring to-do list that shrinks as you work it.
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

2. **Configure it** in `<datapath>/config.json`. The only mandatory part is enabling the plugin:

   ```json
   "settings": {
     "plugins": { "enabled": true, "list": ["inventoryscanner"] }
   }
   ```

   Everything else (toolbar buttons, scan scheduling, notifications, collection) is optional and
   explained in the [complete annotated example below](#complete-example).

3. **Restart** the server (`docker compose restart meshcentral`) and hard-reload the admin UI (Ctrl+F5).

On first start the plugin downloads the NVD feeds (all years — this can take a while, watch `<datapath>/nvd/nvd-download.log`). Panel and reports work as soon as the feeds are indexed.

## Configuration reference

All plugin settings live in the server's `config.json`. MeshCentral **allows `//` comments** in that file, so the
annotated example below can be adopted as-is — merge it into your existing config, delete what you do not need and
remove or keep the comments. Every key is optional unless stated otherwise; the shown values are the defaults.

### Complete example

```jsonc
{
  "settings": {
    // ... your existing MeshCentral settings (cert, port, TLS, ...) ...

    // (1) Enable the plugin. Required.
    "plugins": {
      "enabled": true,
      "list": ["inventoryscanner"]
    },

    // (2) Vulnerability scanner & scheduled scans (section name is "vulnerabilityScanner")
    "vulnerabilityScanner": {

      // How often the automatic scans run, in HOURS measured from the END of the last
      // successful scan (not a calendar day - it simply keeps the rhythm; restart-proof:
      // after a server reboot the remaining time is recomputed from the stored timestamp).
      // 24 = daily, 168 = weekly, 720 = monthly. 0 = disable scheduled scans entirely
      // (panel/CSV/reports still work on demand).
      "scanIntervalHours": 24,

      // Which device groups to scan: list of MeshCentral mesh ids, e.g. ["mesh//Server1"].
      // Empty list or omitted = ALL groups. See the note below on how to find a group's id.
      "scanMeshes": [],

      // Send a notification to all full site admins after each scheduled scan
      // (MeshCentral toast + entry under My Server -> Events).
      "notifyOnScan": true,

      // Minimum severity a finding must have to appear in a notification:
      // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN". This is the global fallback.
      "notifyThreshold": "HIGH",

      // Notification mode:
      // false = each CVE is reported once when it first appears ("(SEVERITY, new)"), then silence.
      // true  = additionally every finding that STILL has no group rating is repeated on every
      //         scan ("(SEVERITY, open)"). This turns the monthly notification into a to-do list
      //         that shrinks as you rate/flag findings. Never for rated/flagged ones.
      "notifyUnratedRepeat": false,

      // Per-group threshold overrides (optional). Key = mesh id, value = severity string.
      // Groups listed here use their own threshold, all others use "notifyThreshold".
      "notify": {
        "mesh//Server1": "MEDIUM",
        "mesh//Lab": "CRITICAL"
      },

      // NVD feed refresh interval in hours (feeds are downloaded weekly by default;
      // the initial download of all years happens automatically on first start).
      "updateHours": 168,

      // CVEs whose CPE entry applies to ALL versions ("*") and are older than N years are
      // suppressed (they would match every installed version - ancient noise). 0 = disabled.
      "anyCveMaxAgeYears": 5
    },

    // (3) Inventory collection (section name is "inventoryScanner" - one 'l' less than (2)!)
    //     MeshCentral does not store installed software; this plugin asks the online agents
    //     itself and caches the results per device (this is what the CVE scan reads).
    "inventoryScanner": {
      // Query all online agents every N minutes for installed software and the
      // Windows-update status. 1440 = daily. 0 = no periodic collection (the panel would
      // then only know agents that connected since the last server start).
      "collectIntervalMinutes": 1440,
      // Also collect shortly after each agent (re)connect - staggered randomly between
      // 5 s and 5 min so a fleet reconnecting after a reboot does not cause a load spike.
      "collectOnAgentConnect": true
    }
  },

  "domains": {
    // "" = the default domain. If your MeshCentral uses named domains, repeat the block
    // per domain or set it only where the buttons should appear.
    "": {
      // Buttons in the device-list toolbar. Appears when devices are checked; each button
      // downloads a CSV for the selected devices ("assessment" opens the panel instead).
      // selection: "many" = works with 1+ devices, "one" = exactly one device.
      "customui": {
        "devicesbarbuttons": [
          { "name": "Hardware Inventory",        "selection": "many", "action": "event", "logmsg": "hardware" },
          { "name": "Software Inventory",        "selection": "many", "action": "event", "logmsg": "software" },
          { "name": "Vulnerability Raw Data",    "selection": "many", "action": "event", "logmsg": "vulns" },
          { "name": "Vulnerability Assessment",  "selection": "many", "action": "event", "logmsg": "assessment" }
        ]
      }
    }
  }
}
```

### Finding a group id (mesh id)

`scanMeshes` and the `notify` map use MeshCentral's mesh `_id`, formatted `mesh/<domain>/<groupname>` — in the
default domain that is a **double slash**, e.g. `mesh//Server1`. Easiest ways to look it up:

* Open the assessment panel, use the browser's "View Page Source" and search for `class="loc-cb"` — every
  checkbox of the floating Locations panel carries the group id in its `value` attribute.
* Or look at the `meshes` collection in MeshCentral's database (the `_id` field).

### Notes

* `vulnerabilityScanner` and `inventoryScanner` are **siblings of `plugins`** directly under `settings` — not
  inside the `plugins` block. The two section names differ by one letter; a typo here silently keeps defaults.
* After every config change: restart the server; after `customui` changes also hard-reload the browser (Ctrl+F5).
* Ratings/comments/mappings you enter in the UI are stored outside `config.json` under `<datapath>/nvd/` and
  `<datapath>/plugins/inventoryscanner/` — see [Data written](#data-written-by-the-plugin).

## URLs

| Page | URL |
|---|---|
| Assessment panel | `/pluginadmin.ashx?pin=inventoryscanner&action=show` |
| Vulnerability report | `/pluginadmin.ashx?pin=inventoryscanner&action=report` |
| Device report | `/pluginadmin.ashx?pin=inventoryscanner&action=deviceReport` |

## Data written by the plugin

```
<datapath>/nvd/nvdcve-2.0-<year>.json      NVD feed cache (offline matching)
<datapath>/nvd/assessments.json            group ratings + false-positive flags
<datapath>/nvd/scans.json                  scheduled scan snapshots
<datapath>/nvd/cpe-tokens.json             CPE dictionary lookup cache
<datapath>/nvd/nvd-download.log            feed download log
<datapath>/plugins/inventoryscanner/custom-cpe.json      your CPE mappings
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
* **Toolbar buttons missing** → `customui.devicesbarbuttons` configured and UI hard-reloaded (Ctrl+F5).
* **Empty software lists** → agents were never online since installation, or collection is disabled
  (`inventoryScanner.collectIntervalMinutes: 0` + connect-time collection).

## Development / testing

`tools/` contains dependency-light checks for the repo itself:

```bash
npm install          # pulls handlebars (dev dependency) for the view tests
npm test             # node --check + logic tests + view render tests
```

See [AGENTS.md](AGENTS.md) for the full technical description aimed at AI agents.

## License

MIT — see [LICENSE](LICENSE).
