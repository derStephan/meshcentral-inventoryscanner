# MeshCentral Inventory & Vulnerability Scanner

One admin panel for MeshCentral that answers three questions about your fleet: **what is installed**, **what is
vulnerable**, and **what needs updating**. It collects the hardware and software inventory of every device, matches
the installed programs against the public NVD vulnerability feeds **offline on your server**, lets you rate findings
per location, prints audit-ready reports, exports CSV lists - and can, if you want it to, install updates and
software for you.

Everything is opt-in and admin-only. Nothing runs on a device unless you start it.

---

## What you get

* **Inventory** - hardware (CPU, memory, disks, BIOS, TPM, network) and installed software per device, collected
  through the agent you already have. No extra software on the devices.
* **Vulnerability scan** - matches installed programs and operating systems against the NVD feeds stored on your
  server. Ratings and false-positive flags per location, one click for all affected locations.
* **Honest coverage numbers** - every report says how much of the inventory could actually be checked, and names
  the two reasons it could not: no verified mapping (*not assessable*) or out of scope by nature (drivers/firmware).
  A low finding count can never be misread as "everything is clean".
* **Reports and exports** - a printable vulnerability report and a printable device inventory report (one page per
  location), plus hardware / software / vulnerability CSV for all devices or for the ones you ticked.
* **Scheduled scans with notifications** - a toast and a server event for the full site administrators of the default
  domain; optionally repeated
  until a finding is rated, so the notification works as a to-do list.
* **Updates** - Windows software updates via the official **winget** package manager, and operating-system updates
  and release upgrades for Windows and Linux. Dry runs first, per device or fleet-wide.
* **Software deployment** - install an MSI/MSP/EXE/DEB/RPM/shell/BIN package on chosen devices or whole locations.
  Offline devices are queued and install as soon as they reconnect.
* **Windows Update troubleshooter** - a read-only diagnose and the repairs the built-in troubleshooter applies,
  for machines whose update service is stuck.
* **Restart and PC reset** - restart a device with a message to its user, or reset a Windows PC to factory state.
  Both are per device, both need the device name typed to confirm, and neither ever happens automatically.
* **License keys** - optionally read the license of a program from the registry, a file or WMI, so the software
  export carries a `License` column for asset management.
* **Asset-management connector** - optionally push the three lists to an external REST system (generic mapping, or
  presets for **Jira** and **Snipe-IT**). Off by default; the only feature that ever sends data off the server.

---

## Requirements

* MeshCentral 1.x (Docker or bare metal).
* You must be a **full site administrator** of the default domain. Every screen and endpoint is admin-only; on a
  multi-domain server, sub-domain administrators are refused because the plugin covers all devices.
* Outbound HTTPS to `nvd.nist.gov` (the feeds), `raw.githubusercontent.com` (the maintained mapping table) and
  `endoflife.date` (public OS support dates). All matching itself runs locally. Optionally - only if you configure
  and enable it - outbound HTTPS to **your own** asset-management system.
* Several GB of free disk under `<datapath>/nvd/` for the feed data.
* Agents that have been online at least once, so their inventory could be collected.
* For deploying software: nothing to open or install on the devices. The package travels over the agent's existing
  connection to the server, so the agent only needs to reach the server's own web port - which it already does.

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
3. **Enable it** in the plugin list, then follow the restart notice and restart once more.
4. **Hard-reload the browser** (Ctrl+F5). The toolbar buttons above the device list appear by themselves, and the
   first NVD download starts in the background (several GB - watch its progress under
   **Vulnerabilities → NVD database**, no shell needed).

**Updates** need no ceremony: when a new version is published, the Plugins page offers **Upgrade**. One click is
enough - the plugin notices the new files and restarts MeshCentral by itself (an admin toast announces it). This
needs MeshCentral's normal launcher (`node meshcentral` starts the server as a `--launch` child, which is also how the
official Docker image runs); without it the new code is hot-swapped in instead and a later restart completes the upgrade.

**Uninstall**: remove the plugin on that page. MeshCentral deletes `<datapath>/plugins/inventoryscanner/` including
the collected inventory, the settings, the update results and the deploy library. The NVD feeds, your ratings and
the scan history stay in `<datapath>/nvd/` - delete that folder too if you want them gone. On the devices, an
updater transcript may remain next to `meshagent.exe` or in `C:\ProgramData\InventoryScanner`.

---

## The panel

Open it with **My Server → Plugins → Inventory & Vulnerability Scanner**, or with the *Vulnerability Assessment*
button above the device list.

There are five sections, each with its own sub-pages. **The address bar shows which page you are on** (`#devices/devicelist`
and so on), so you can copy a link to a view and paste it later - and the browser's back button walks back through
the pages you visited. Hovering a button - including the navigation itself - shows what it does in a box at the
lower right corner. Documents (the two printable reports, the three CSV files) open **directly from the navigation**
in a new tab, with one click.

### Devices

**Device list** - one row per device with everything the server already knows: online state, operating system and
release state, pending software updates, findings, collected licenses. Click a column header to sort, filter by
name/group/OS, and tick several devices to run one operation on all of them.

Per device you can: run a **dry run** or the real **software update**, **exclude**/**include** it from the automatic
batches, run **OS updates** or an **OS upgrade**, **diagnose** or **repair** Windows Update, send a **message to the
user**, and **reboot** it. **Details** opens everything stored about that machine on demand - hardware, installed
programs, its findings, the last run of every engine and the license state. Details are fetched once and kept
while the page is open (sorting, filtering and status updates do not re-fetch them); a button inside refreshes.

Fleet-wide buttons (*force OS updates*, *force OS Upgrade (urgent/all)*) act on every non-excluded device with a
reported Windows or Linux OS - the upgrade buttons only on devices that are provably outdated and have an upgrade path
(the urgent one only on the urgent ones). The OS update log is at the bottom of the page.

**PC reset** - reset one chosen Windows machine with the built-in `systemreset` tool, keeping or removing the user
files. A read-only **Check** must pass first (tool present, build new enough, recovery environment enabled,
BitLocker state; it also reports whether the device runs on battery), you must type the device name, and "Remove
everything" is blocked while BitLocker is on until you confirm that the recovery key is available.

**Device report** - the printable device inventory: host names, operating system and its support state, program and
finding counts, one page per location.

### Software

**Software list** - every distinct program across the fleet: how many devices have it, which versions, which
findings matched it, whether a license was collected, and what the last winget run reported. Per row: **Ignore**
(never upgrade it automatically), **Update everywhere**, **Uninstall everywhere** and **Details** (devices,
versions, findings, license, the per-device winget results). The three package actions need a winget package id -
rows without one show them disabled, because winget manages ids and not display names.

**Software updates** - the winget configuration: the master switch, the device groups that are updated
automatically, the ignore list and the run log. Nothing runs automatically until you enable it **and** tick at least
one group. Keep the ignore list reasonably short (a few dozen entries).

**Deployment** - upload an installer into the plugin's library, pick one from MeshCentral's Server Files, or place a
file in the plugin's `software/files/` folder and rescan. Then tick devices or **whole locations**, add command-line
parameters if the installer needs them, and confirm. The package is verified by SHA-256 **on the device** before
anything runs. Offline devices queue and install when they reconnect. Each device shows its state and the
installer's exit code in decimal and hex (3010 = "ok, but a reboot is pending" - the plugin never reboots for you).
A file from Server Files can have been placed there by any user with that group's *server files* right - check it
before you deploy it to other machines. Server Files work with every device group (real group ids contain `@` and `$`;
versions before 5.5.1 refused them).

**License keys** - the rule table that maps a program name to where its license lives (a registry value, a file, or
a WMI property), your own rules, the collection log and the schedule. Rules can also reach **per-user** storage
(a registry path written as `HKCU:` is read from every loaded user hive; a file path may use the profile-directory
placeholder - per-user reads work since 5.5.1, in 5.5.0 they found no user on a real Windows 11) and **version-dependent subkeys** (one `*` wildcard per path) - but hives of logged-off users are never
loaded, so the extraction stays strictly read-only. Reading is **read-only**, the keys stay on
this server and are **never displayed in the panel** - they appear only in the software CSV export, whose License
Source column names the rule type and the user a value came from. Off by default;
you can collect on demand, on a schedule, per device from the device list, or for all online Windows devices here.

### Vulnerabilities

**Assessment** - the findings table. Tick the locations to assess in the row above the table (remembered per
browser), then sort, filter and rate. Opening the page reads the **stored** result, so it is instant and touches no
device; **Scan & Review** is the only button that queries the machines. A rating needs a comment and applies to
every selected location that has the finding; a false positive needs no comment and disappears from the counts
(and can be undone). The table is sorted by **effective severity**, so your own ratings decide the order - inside
one severity the higher CVSS comes first.

**Vulnerability report** - the printable findings report: an overview page plus one page per location, with the
coverage percentage stated.

**CPE table** - the dictionary that maps an installed program name to the technical product code the NVD uses.
The maintained table is downloaded with every feed refresh, so a corrected mapping reaches you without a plugin
update; your own entries always win. Programs with no mapping are still matched automatically against the product
names that really exist in the feeds - and only if that proves nothing are they listed as *not assessable*.

**NVD database** - the feed refresh interval, an "update now" button and the download log. A feed older than the
interval is fetched shortly after the next server start; a failed download is retried after six hours rather than
hammering the rate-limited source.

### Exports

Three links - **hardware**, **software** and **vulnerabilities** - download the CSV for all devices with one click. Every export is
sorted column by column, so a device block stays together and versions read in natural order (Firefox 9 before
Firefox 121). For a **selection** of devices use the hardware/software buttons on MeshCentral's own device list
toolbar - same columns, only the ticked machines.

### Settings

**General** - scan interval, which locations are scanned, notification threshold and mode, inventory collection
interval, the OS-support data source, the urgency window for OS upgrades, and the device-group table with
per-group thresholds. Every value shows where it comes from (your setting, `config.json`, or the built-in default)
and can be reverted individually; *Reset all* hands control back to `config.json`. Changes apply immediately, no
restart, and the plugin never writes MeshCentral's `config.json`.

**Asset management** - the optional connector that pushes your aggregated lists to an external system. Choose
**Generic** and describe the request yourself (method, headers and a JSON body template with placeholders such as
the device name, the serial, the software list and the findings) - that reaches GLPI, NetBox, ServiceNow, Device42,
Freshservice, ManageEngine, Lansweeper or anything else with a REST API - or use the presets for **Jira** (one issue
per device) and **Snipe-IT** (one hardware asset per device). Both create on the first push and **update** on later
pushes, so nothing is duplicated. A *test request* verifies the target without pushing the fleet.

---

## Reference

### What a finding's status means

The panel and the vulnerability CSV use the same vocabulary:

| Status | Meaning |
|---|---|
| `CVE` | a real vulnerability matched by a verified product code and version range |
| `WINDOWS-UPDATES` | this Windows device is missing Critical/Important updates |
| `OS-EOL` | the operating-system release is out of support and gets no security fixes any more |
| `no CVE for <product>` | the product is known, but no vulnerability matches this version |
| `not assessable` | a real program with no proven mapping - the honest blind spot, **not** "clean" |
| `drivers are not covered by CVE data` | out of scope by nature: the vendor and Windows Update patch these |
| `firmware is not covered by CVE data` | same, for firmware |
| `patched by the distribution (OS supported)` | a Linux distribution package - your distribution backports the fix into the same version, so a version check would only produce false alarms |
| `distribution package - OS end of life` | the same package, but the release no longer gets fixes |
| `false positive` | you flagged it; it is excluded from every count and notification |

A finding never claims a version that is not on every affected device: if the machines differ, the row shows
*varies* and the per-device truth is in the CSV. Programs without a version number are handled conservatively -
only vulnerabilities that apply to *all* versions are asserted.

### Operating-system release states

| State | Meaning | Upgrade (urgent) | Upgrade (all) / per device |
|---|---|---|---|
| **current** | the newest release | - | - |
| **Upgrade available** | a newer release exists; yours is still supported longer than the urgency window | no | yes |
| **Upgrade urgent** | a newer release exists and yours is out of support, or its support ends within the window | yes | yes |
| **unknown** | no clean answer (release not reported, or no fresh support data) - the reason is shown | no | no |

"Current" comes exclusively from the endoflife.date data (newest Windows 11 release, newest Ubuntu LTS); there is no
built-in fallback version, and without fresh data nothing is upgraded. The urgency window is set in Settings
(default **365 days** before support ends, 0 = only after it ended). Windows Home/Pro and Enterprise/Education have
different support ends - with the default window, a Pro release becomes *urgent* about a year after release while
the same Enterprise release is only *available*. A release whose support end is unknown is never called urgent on a
guess. Windows Server and distributions other than Ubuntu are shown but never upgraded automatically.

### Which Linux distributions are handled

The script uses the package manager it finds on the device, not the distribution name:

| Distribution (examples) | OS updates | OS upgrade |
|---|---|---|
| Ubuntu and its official flavors | `apt-get update` + `apt-get upgrade` | yes: `dist-upgrade`, then `do-release-upgrade` (one release per run) |
| Debian, Linux Mint, Raspberry Pi OS, Pop!_OS and other apt systems | `apt-get update` + `apt-get upgrade` | no |
| Fedora, RHEL 8+, Rocky, AlmaLinux, CentOS Stream | `dnf upgrade --refresh` | no |
| CentOS 7 / RHEL 7 | `yum update` | no |
| openSUSE Leap, SLES | `zypper refresh` + `zypper update` | no |
| Arch, Manjaro | `pacman -Syu` | no |
| Alpine | `apk update` + `apk upgrade` | no |

A device without any of these reports *unsupported*. Rolling distributions have no release to upgrade to -
*OS updates* is the regular way to keep them current (on openSUSE Tumbleweed run `zypper dup` yourself from time to
time). One **broken third-party repository does not fail the run**: the device continues with the refreshed lists and
the repository warning appears in its note; it is only reported as failed when no package list could be refreshed at
all. Requirements: the agent runs as root (the default), the device reaches its repositories, and `base64` and
`gzip` are installed (they are on all of the above).

### Reboots

Update, upgrade, deployment and troubleshooter runs **never reboot** a device. If a restart is needed, it is
reported per device and Windows performs it at its own automatic-restart deadline. Exactly two things restart a
machine on purpose - the **Reboot** button on a device row and the **PC reset** - and both are per device, manual
and need the device name typed to confirm. A reboot also messages the logged-on user (message box / `wall` plus the
shutdown banner); a PC reset does not - it restarts into Windows RE right away, so warn the user yourself. Never a batch, never a schedule.

---

## Improving the software mapping

The name-to-product table is maintained in this repository as [cpe-table.json](cpe-table.json) and re-downloaded
with every feed refresh, so a new or corrected mapping reaches you **without a plugin update**. Contributions are
pull requests that touch only that file; the rules (including how to verify a mapping against the NVD, because
guessing is not allowed) are in [CONTRIBUTING.md](CONTRIBUTING.md). Your own entries in **Vulnerabilities → CPE
table** always win over it.

## Privacy & security

* **By default no inventory data leaves your server.** The outbound requests go to `nvd.nist.gov` (feeds),
  `raw.githubusercontent.com` (the mapping table, https only, size-capped, every pattern checked before use) and
  `endoflife.date` (public OS support dates - a fixed list of product names, nothing about your devices).
* **The one deliberate exception:** the optional asset-management connector. It is off by default, https only, has
  no schedule unless you set one, sends no command to any agent, and every push you start asks for confirmation. Credentials
  (including the values of extra headers, since 5.5.1) are stored on this server, never shown again in the clear and
  never written to a log; the log records the device,
  the HTTP status and an external id - never a request or response body. Collected **license keys never ride along**
  in a push.
* License keys are treated as secrets: read-only collection, stored only in
  `<datapath>/plugins/inventoryscanner/data/<node>/license.json`, never logged, never displayed - they appear only
  in your own software CSV export.
* Admin-only everywhere: every endpoint re-checks your site-administrator rights server-side, and every changing
  request - including a live *Scan & Review* - must come from the plugin's own page (a cross-site request is refused).
* Deployed packages are verified by SHA-256 on the device before they run, and the verified bytes are the executed
  bytes. Installers run as SYSTEM/root because machine-wide installation is the use case - and a task only exists
  because an admin created it.
* Output is hardened: HTML escaping on render, CSV formula-injection neutralisation, strict validation of every id.

## Troubleshooting

* **"NVD database: not downloaded"** - the feed download failed (rate limit or proxy). Look at the download log
  under **Vulnerabilities → NVD database**; a stale feed is fetched automatically shortly after the next server
  start, or press *Update NVD database now*.
* **401 on the panel** - you need full site-admin rights, and the plugin folder/shortName must stay
  `inventoryscanner` (letters and digits only).
* **No toolbar buttons** - plugins are not enabled, the server was not restarted, or your browser cached the UI:
  hard-reload with Ctrl+F5.
* **Empty software lists** - the device has not been online since installation, or collection is switched off in
  Settings. An empty list means *not collected*, never *clean*.
* **A device stays "waiting for answer"** - another command session on that machine (a MeshCentral terminal, another
  script) has the agent busy; the run ends with an explicit timeout instead of hanging forever. The device also keeps
  a transcript of every updater run next to `meshagent.exe` (or in `C:\ProgramData\InventoryScanner`) - that is where
  to look when the server side stays silent.
* **Reports look wrong** - check the inventory age first: offline devices show their last collected state.
* **A deploy task stays "queued (waiting for connect)"** - the device has not been online since the task was
  created. The queue is server-side and survives restarts. The device's `invscanner-deploy.log` (Windows: next to
  `meshagent.exe` or `C:\ProgramData\InventoryScanner`; Linux: `/var/log/`) has the client-side view.
* **A deploy says *no-file*** - the script ran but the installer never reached the device, and the message names the
  actual cause: *nothing ever appeared* (the agent never fetched it - usually the agent's server URL or a proxy in
  front of `/agentdownload.ashx`) versus *a file appeared but its SHA-256 never matched* (a partial or replaced
  download - retry the device). While a device waits, its download ticket is re-sent a few times, because that ticket
  is only valid for five minutes.
* **The panel looks stale after an upgrade** - hard-reload (Ctrl+F5). An already-open page keeps running the old
  script until you reload it.

## Known limitations

* **Windows OS vulnerabilities need the full build number** (`10.0.26200.9711`, reported by current agents). Without
  it no OS finding is asserted; the count of missing Critical/Important updates remains the indicator.
* **Coverage is never 100%** by design: a program is only checked when a verified mapping exists. Unknown names stay
  *not assessable* instead of being guessed, which keeps false positives rare - the percentage in every report tells
  you how much was actually looked at.
* **Linux distribution packages are trusted while the release is supported.** That assumes the machine really
  installs its updates - check with the distribution's own tools (e.g. `apt list --upgradable`). Without support
  data their state is *unknown*, never "safe". Software installed outside the package manager is matched like on
  Windows.
* **Duplicate leftovers** from upgraders ("Firefox 3.6" next to "Firefox 121") are collapsed to the newest row, so
  years-old findings are not reported against patched software. Programs that genuinely coexist (Edge and its WebView2
  runtime, VC++ x86 and x64, side-by-side Java/Python) stay separate.
* **Notifications** are a toast plus a server event; there is no built-in e-mail. If no admin is logged in during a
  scan, read it under **My Server → Events**.

---

## Where the technical detail lives

This README is deliberately for administrators. The internals - every route and its contract, the module layout, the
generated device scripts, the verified MeshCentral API facts, the scheduling and upgrade mechanics - are documented
in **[AGENTS.md](AGENTS.md)**. Security policy and threat model: **[SECURITY.md](SECURITY.md)**. Audit reports:
**[AUDIT.md](AUDIT.md)**. The mapping-table process: **[CONTRIBUTING.md](CONTRIBUTING.md)**. The changelog is the
[commit history](https://github.com/derStephan/meshcentral-inventoryscanner/commits/main) - every version is
described there in full.

```bash
npm ci         # dev dependency only (handlebars, for the view tests)
npm test       # consistency checks + behavioural tests + view render tests
```

## License

MIT - see [LICENSE](LICENSE).
