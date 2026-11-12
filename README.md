# MeshCentral Inventory & Vulnerability Scanner Plugin

> **Transparency**: Created with **Qwen 3.6 27B** & **Qwen 3.8 Flash Next** • Audited by **NVIDIA Nemotron 3 550B A55B** (2026-11-06) and **Claude Opus 5.5** (2026-11-11, v3.0.1) - see [AUDIT.md](AUDIT.md)

Turns your MeshCentral server into a software inventory and vulnerability scanner that works **offline**: CSV
exports for audits, an NVD-based CVE scan of everything your devices have installed, a shared assessment panel
where the team rates findings per location, printable audit reports, scheduled scans with notifications - and an
opt-in software updater based on the official **winget** package manager.

**Who it is for:** MeshCentral site administrators who need to answer *which software is installed where, what has
known CVEs, what has the team already reviewed, and what is left to do* - without buying a commercial scanner and
without sending inventory data to anyone.

---

## What you get

* **Inventory exports** - hardware and software lists as Excel-safe CSV, for selected devices or for the whole
  fleet with one bookmarkable URL.
* **Offline CVE scan** - matches installed software against the public NVD feeds stored on your server. No
  inventory data leaves the machine; the server only downloads the feeds, the mapping table and OS support dates.
* **Honest coverage numbers** - every report says how much of the inventory could actually be checked, and names
  the two reasons it could not: no verified CPE mapping (*not assessable*) or out of scope by nature
  (**drivers and firmware** are patched by the hardware vendor and Windows Update, not by NVD application data -
  they are reported in their own category and do not distort the coverage percentage).
* **Linux packages handled honestly** - packages of the distribution itself (Ubuntu, Debian, Red Hat, ...) get
  their fixes as backports into the same upstream version, so an NVD version check would only raise false alarms.
  They are reported as *patched by the distribution* while the OS release still receives security updates, and the
  device gets an **OS-EOL** finding once it does not. The support dates are downloaded from the public
  [endoflife.date](https://endoflife.date) API (nothing hard-coded); packages from third-party repositories (Docker,
  NVIDIA, ...) are still checked against the NVD.
* **Windows OS findings by exact build** - the OS check uses the release-specific NVD product (e.g. Windows 11 25H2)
  and the installed build including the update revision, so a patched machine shows no OS CVEs and an unpatched one
  shows exactly what its missing cumulative updates fix.
* **Assessment panel** - one sortable table of all findings across selected locations; a rating (with comment) is
  saved per location, false positives stop counting everywhere.
* **Printable reports** - vulnerability report and device report, one page per location, ready for Print/Save-as-PDF.
* **Scheduled scans** - monthly (or any interval) with admin notifications that list what is new and, if you want,
  everything still unrated.
* **Software updates via winget** - opt-in, dry runs first, per device or per package across the whole fleet,
  with an ignore list for licensed packages and a full audit trail.
* **OS updates and OS upgrades on demand** - *force OS updates* installs pending Windows updates (built-in Windows
  Update agent) or runs the Linux package manager upgrade; *force OS Upgrade* brings outdated releases (e.g.
  Windows 11 23H2, Ubuntu 22.04) to the current one, marked *urgent* when the installed release runs out of support.
  Never reboots a device.

## Requirements

* MeshCentral 1.x (Docker or bare metal).
* You must be a **full site administrator** of the default domain - every screen and endpoint is admin-only (on
  multi-domain servers, administrators of sub-domains are refused because the plugin covers all devices).
* Outbound HTTPS to `nvd.nist.gov` (feed download, then roughly weekly), `raw.githubusercontent.com` (the
  maintained mapping table) and `endoflife.date` (OS support dates). All matching runs locally.
* Several GB of free disk under `<datapath>/nvd/` for the feed data.
* Agents that have been online at least once, so their software list can be collected.

## Installation

1. **Enable plugins (one time)** - in `<datapath>/config.json`, under `"settings"`:

   ```json
   "settings": { "plugins": { "enabled": true } }
   ```

   Do **not** add a `"list"` there - that is MeshCentral's development mode and it ignores installed plugins.
   Restart the server once.
2. **Add the plugin** - **My Server → Plugins → Download plugin** and paste:

   ```
   https://raw.githubusercontent.com/derStephan/meshcentral-inventoryscanner/main/config.json
   ```
3. **Enable it** in the plugin list, then obey the restart notice and restart once more.
4. **Hard-reload the browser** (Ctrl+F5). The toolbar buttons above the device list appear by themselves, and the
   first NVD download starts in the background (several GB - watch the tail of the download log in the Settings
   tab, no shell needed).

Updates need no ceremony: push a new version here and every server offers **Upgrade** on the Plugins page.
Uninstall: remove the plugin on that page - MeshCentral deletes `<datapath>/plugins/inventoryscanner/` including the
collected inventory, settings and update results. The NVD feeds, ratings and scan history stay in `<datapath>/nvd/`;
delete that folder too if you want them gone. On clients, an updater transcript may remain next to `meshagent.exe`
or in `C:\ProgramData\InventoryScanner`.

## Day-to-day use

**Panel** - `My Server → Plugins → Inventory & Vulnerability Scanner`, or the *Vulnerability Assessment* toolbar
button. Pick the locations you work on (floating *Locations* button, remembered per browser), then use one
aggregated table of unique findings: sort by any column, filter by text/severity/status, rate a finding for all
affected locations in one action, or mark it a false positive (with undo). The **Settings**, **CPE Mapping** and
**Updates** tabs live on the same page.

**A finding never claims a version that is not on every device.** If the affected machines run different
versions, the row shows *varies (N)* and the per-device truth is one hover away - the exact per-device list is
always the software/vulnerability CSV.

**CSV exports** - tick devices and use the toolbar buttons, or export everything with a URL you can bookmark:

```
/pluginadmin.ashx?pin=inventoryscanner&action=export&type=hardware   (or: software, vulns)
```

The `vulns` export carries one row per finding with a `Status` column: `CVE`, `no CVE for <product>`,
`not assessable`, `drivers are not covered by CVE data`, `firmware is not covered by CVE data`,
`patched by the distribution (OS supported)`, `distribution package - OS end of life`,
`distribution package - OS support unknown` or `false positive`. Two synthetic findings exist besides real CVEs:
`WINDOWS-UPDATES` (missing Critical/Important updates) and `OS-EOL` (operating system release out of support).
Software entries without a version number are handled conservatively: only CVEs that apply to *all* versions are
asserted, so historical findings never flood the list.

**Reports** - *Vulnerability Report* (findings per location, no device list) and *Device Report* (device inventory
with host names, OS, program and finding counts). Both state their own blind spot, so a low finding count can
never be misread as "everything is clean".

**Scheduled scans** - set the interval and the notification threshold in the Settings tab. After each run all
site admins get a toast plus a server event listing findings at or above the threshold, marked `new`; with
*Repeat unrated findings* enabled, everything still unrated is repeated every time, so the notification works as
a to-do list that shrinks as you rate. Rated and false-positive findings are never reported again.

**Software updates (Updates tab)** - completely opt-in: nothing runs **automatically** until you turn it on *and*
tick at least one device group. The manual buttons (Run now, Dry run, per device, per package) act on demand on
every non-excluded Windows device. Two views on the same fleet:

* **By device** - every Windows machine with its last result; per row *Dry run*, *Update now*, *Exclude*/*Include*,
  and a *list* button that opens **every package with its outcome** (failed rows show the exit code and winget's own
  message, plus a one-click *+ ignore*).
* **By package** - every package your devices reported, aggregated across the fleet, with two fleet-wide actions:
  **Update everywhere** and **Uninstall everywhere** (both ask for confirmation and only ever touch that one
  package id; a device that does not have it reports *not installed* instead of failing).

Ignored packages are skipped in every run and pinned on the client, so even a user's own
`winget upgrade --all` leaves a licensed version alone. Offline devices are picked up when they connect;
a device is never rebooted.

**OS updates (Updates tab, section *Operating system updates*)** - three manual buttons, all with confirmation,
plus *OS updates* / *OS Upgrade* per device row:

* **force OS updates** - every non-excluded Windows and Linux device. Windows: the built-in Windows Update agent
  searches, downloads and installs all pending updates (feature upgrades excluded). Linux: `apt-get update` +
  `apt-get upgrade`, or `dnf upgrade --refresh`, `yum update`, `zypper update`, `pacman -Syu`, `apk upgrade`.
* **force OS Upgrade (urgent)** / **force OS Upgrade (all)** - only devices whose release is provably not current.
  "Current" comes exclusively from the endoflife.date data (newest Windows 11 release, newest Ubuntu LTS) - there is
  no built-in fallback version. If that data is missing, switched off or older than 30 days, the release state is
  shown as **unknown** together with the reason, and nothing is upgraded. Windows 10/11: Windows Update is pointed at
  the current release with the documented `TargetReleaseVersion` policy and installs it; the previous policy values
  are restored afterwards. Ubuntu: `apt-get dist-upgrade`, then `do-release-upgrade` (one release step per run; if a
  reboot is pending first, the device reports *reboot-needed* - reboot, then run it again). Other distributions and
  Windows Server are shown in the table but not upgraded automatically.

**Release state per device** - the *Release state* column shows one of four states:

| State | Meaning | force OS Upgrade (urgent) | force OS Upgrade (all) / per device |
|---|---|---|---|
| **current** | the newest release | - | - |
| **Upgrade available** | a newer release exists; the installed one is still supported for longer than the urgency window | no | yes |
| **Upgrade urgent** | a newer release exists and the installed release is out of support, or its support ends within the urgency window | yes | yes |
| **unknown** | no clean answer (release not reported, no fresh endoflife.date data) - the reason is shown | no | no |

* The **urgency window** is set in the Settings tab ("OS upgrade is urgent this many days before support ends";
  default **365 days**, 0 = only after support ended). The support end is that of the *installed* release and
  edition at endoflife.date: Windows Home/Pro and Enterprise/Education releases have different end dates.
* Windows 11 Home/Pro releases get 24 months of support. With the default 365 days a Pro release therefore becomes
  *urgent* about a year after it came out - e.g. on 2026-11-12, Windows 11 Pro 25H2 (support until 2027-10-12) is
  urgent, the same release on Enterprise (until 2028-10-10) is only *available*. Lower the window if that is too early.
* An outdated release whose support end is not known is shown as *available* with "support end unknown" - it is
  never called urgent on a guess.
* Windows Server and distributions other than Ubuntu have no newer-release check: they show *Upgrade urgent* when
  their own support has ended or ends within the window, otherwise *unknown*, and are never upgraded automatically.

No device is ever rebooted; a pending reboot is shown per device. Results go to the device table, the device's event
list and `os-update.log`; the clients log to `invscanner-osupdate.log` (Windows: next to `meshagent.exe` or in
`C:\ProgramData\InventoryScanner`, Linux: `/var/log/`). OS and winget batches never run at the same time, and the
winget exclusion list applies to both.

**Which Linux distributions are supported?** The script picks the package manager it finds on the device, not the
distribution name:

| Distribution (examples) | force OS updates | force OS Upgrade |
|---|---|---|
| Ubuntu and its official flavors (Kubuntu, Xubuntu, Ubuntu Server, ...) | `apt-get update` + `apt-get upgrade` | yes: `dist-upgrade`, then `do-release-upgrade` |
| Debian, Linux Mint, Raspberry Pi OS, Pop!_OS and other apt-based systems | `apt-get update` + `apt-get upgrade` | no |
| Fedora, RHEL 8+, Rocky Linux, AlmaLinux, CentOS Stream | `dnf upgrade --refresh` | no |
| CentOS 7 / RHEL 7 (no dnf) | `yum update` | no |
| openSUSE Leap, SLES | `zypper refresh` + `zypper update` | no |
| Arch Linux, Manjaro | `pacman -Syu` | no |
| Alpine | `apk update` + `apk upgrade` | no |

* **force OS updates** installs the pending package updates *within* the installed release on every distribution
  in the table. A device without any of these package managers reports *unsupported*.
* **force OS Upgrade** (new release) is automated for **Ubuntu only**: the device must report `ID=ubuntu` in
  `/etc/os-release`. Derivatives with their own ID (Linux Mint, Pop!_OS, elementary OS, ...) report *unsupported*,
  because `do-release-upgrade` is not their upgrade path. For every other distribution a release upgrade needs its
  own tool and manual steps (e.g. `dnf system-upgrade` on Fedora, editing the sources and `apt full-upgrade` on
  Debian, `zypper dup` on openSUSE), so the plugin does not try it. Such a release is shown as *Upgrade urgent* once
  its support has ended or ends within the urgency window, but it is never upgraded automatically.
* Rolling distributions (Arch, Manjaro, openSUSE Tumbleweed) have no releases to upgrade to; *force OS updates* is
  the regular way to keep them current. On Tumbleweed the plugin runs `zypper update`, not the recommended
  `zypper dup`, so run `zypper dup` yourself from time to time.
* Requirements on every Linux device: the MeshCentral agent runs as root (the default installation), the device has
  network access to its package repositories, and `base64` and `gzip` are installed (present on all distributions
  above).

## Settings

Everything is configured in the **Settings tab** - no file editing, effective immediately without a restart. The
values are stored in the plugin's own folder and **override the same keys in `config.json`**, which the plugin
only reads (it never writes it). Per field you can revert to the `config.json` value, and *Reset all* hands
control of the Settings-tab values back to the file completely. The configuration of the Updates tab (winget
switch, groups, ignore list, exclusions) is not touched by *Save Settings* or *Reset all*.

File-based fallback keys (for unattended setups) are listed in [AGENTS.md](AGENTS.md) under
*Configuration keys & precedence*. Group ids look like `mesh/<domain>/<name>` - in the default domain that is
`mesh//YourServerName`; the easiest lookup is the *Locations* picker in the panel.

## Improving the software mapping

The name-to-CPE table that drives matching is maintained in this repository as
[cpe-table.json](cpe-table.json). Every server re-downloads it with each feed refresh, so a new or corrected
mapping reaches you **without a plugin update** (and a fresh install already ships the current copy). Rows can
also mark a name as a driver or firmware component. Contributions are pull requests that touch only that file -
the rules (including how to verify a CPE against the NVD, because guessing is not allowed) are in
[CONTRIBUTING.md](CONTRIBUTING.md). Your own entries added in the CPE Mapping tab always win, and the tab states
which table is in force.

## Privacy & security

* No inventory data is ever transmitted anywhere; the only outbound requests go to `nvd.nist.gov` (feeds),
  `raw.githubusercontent.com` (mapping table - https only, size-capped, every regex checked before use) and
  `endoflife.date` (public OS support dates - a fixed list of product names is requested, nothing about your devices).
* Admin-only: every endpoint and the toolbar export re-check your site-administrator rights server-side; every
  changing request must come from the plugin's own page (request-header check against cross-site requests).
* The updater writes its client transcript only to folders that standard users cannot write to.
* Output is hardened: HTML escaping on render, CSV formula-injection neutralization, strict id validation on
  every write.
* The updater runs one self-logging PowerShell script per device; every run ends up in a server-side log and in the
  device's own event list in MeshCentral.

## Troubleshooting

* **"NVD database: not downloaded"** - the feed download failed (rate limit or proxy). Look at the download log in
  the Settings tab, then restart the server to retry.
* **401 on the panel** - you need full site-admin rights, and the plugin folder/shortName must stay
  `inventoryscanner` (letters and digits only).
* **No toolbar buttons** - plugins are not enabled, the server was not restarted, or your browser cached the UI:
  hard-reload with Ctrl+F5.
* **Empty software lists** - the device has not been online since installation, or collection is switched off in
  the Settings tab. An empty list means *not collected*, never *clean*.
* **A device row stays "waiting for answer"** - another command session on that machine (a MeshCentral terminal,
  another script) has the agent busy; the run closes with an explicit timeout instead of hanging forever. The
  device also keeps a transcript of every updater run next to `meshagent.exe` (or in the admin-only folder
  `C:\ProgramData\InventoryScanner`) - that is the place to look when the server side stays silent.
* **Reports look wrong** - check the inventory age first: offline devices show their last collected state.

## Known limitations

* **Windows OS CVEs need the full build** (`10.0.26200.9711`, reported by current MeshCentral agents). Without it no
  OS CVE is asserted; the count of missing Critical/Important Windows updates remains the indicator.
* **Coverage is never 100%** by design: a program is only checked when a verified mapping exists. Unknown names
  stay *not assessable* instead of being guessed, which keeps false positives rare - the percentage in every
  report tells you how much was actually looked at.
* **Linux distribution packages are trusted while the OS release is supported** (see above). This assumes the
  machine actually installs its updates - check that with the distribution's own tools (e.g. `apt list --upgradable`).
  Without lifecycle data (offline, switched off) their state is shown as *unknown*, never as safe. Software installed
  outside the package manager is matched like on Windows.
* **Duplicate leftovers** from upgraders ("Firefox 3.6" next to "Firefox 121") are collapsed to the newest row, so
  years-old CVEs are not reported against patched software. Programs that genuinely coexist (Edge and the WebView2
  runtime, VC++ x86 and x64, side-by-side Java/Python versions) stay separate.
* **Notifications** are a toast plus a server event; there is no built-in email. If no admin is logged in during a
  scan, read it under **My Server → Events**.

## Development

```bash
npm ci         # dev dependency: handlebars (for the view tests), exact versions from package-lock.json
npm test       # syntax/consistency checks + behavioral tests + view render tests
```

The server code is split by feature: `inventoryscanner.js` is the entry (identity, file layout, module
wiring) and `lib/` holds one module per area - NVD feeds and CVE index, CPE mapping tables, matching,
the collector, the winget and OS update engines, scheduling, reports, CSV, routes and the browser
exports. [AGENTS.md](AGENTS.md) maps every file to its responsibility.

Agents and contributors: [AGENTS.md](AGENTS.md) documents the verified contracts, and
[CONTRIBUTING.md](CONTRIBUTING.md) the mapping-table process.

## Security & Audit

* **Security Policy**: [SECURITY.md](SECURITY.md)
* **Audit Report**: [AUDIT.md](AUDIT.md) (first audit 2026-11-06, second audit 2026-11-11)
* **Changelog**: the [commit history](https://github.com/derStephan/meshcentral-inventoryscanner/commits/main) -
  every version is described there in full.

## License

MIT — see [LICENSE](LICENSE).
