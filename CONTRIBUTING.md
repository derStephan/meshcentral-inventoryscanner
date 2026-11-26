# Contributing

## Mapping contributions: `cpe-table.json` (no release needed)

The software-name → CPE mapping table is `cpe-table.json` in this repository root - since v4.2.0 it is the
**only** curated table (the code holds no second copy). A pull request that improves coverage **must touch only
this file** - every running server picks the change up automatically (fetched at startup and after each NVD
download cycle, and Vulnerabilities > CPE table shows where the active table came from). No plugin
version bump, no new release.

### How to add a mapping (the verified process)

1. **Find unmapped programs.** In the panel or via a **vulnerability CSV export**
   (`action=export&type=vulns`), filter the rows with status `not assessable` - these are entries the
   curated table and the automatic evidence matcher could not resolve. Collect the distinct `Software`
   display names (grouped by how often they appear - map the frequent ones first). Names with status
   `no CVE for <product>` are already mapped; leave them alone.
2. **Verify vendor + product against the live NVD.** Do not guess or invent CPE names:
   * CPE dictionary search (human): <https://nvd.nist.gov/products/cpe/search/results?namingFormat=2.3&keyword=...>
   * CVE API 2.0 (machine): `https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:a:<vendor>:<product>` -
     a `totalResults > 0` proves the pair exists and carries CVEs (unauthenticated rate limit: 5 req/30 s).
     Note that `+` cannot be queried through this parameter (rejected as malformed) - confirm such products
     from the `cpeMatch.criteria` of a CVE that mentions the product instead.
   * Special characters are **escaped inside feed criteria** (`cpe:2.3:a:microsoft:visual_c\+\+`). The plugin
     indexes the raw criteria token, so the table `product` must copy it exactly (`"visual_c\\+\\+"` in JSON) -
     check a real criteria string before mapping a name containing `+ * ? \ : /`.
   * No CPE in the dictionary → the entry stays `not assessable`, which is the honest label. Do not map it.
3. **Edit `cpe-table.json`:**
   * Entries are matched **in order, first hit wins** - put the more specific regex before existing broader
     ones (e.g. `webview2` before `microsoft edge`, `asp\.net core` before `\.net framework` never, but
     keep any specific variant ahead of the generic one it is a substring of).
   * `match` is a JavaScript regex source (the plugin compiles it with the `i` flag only) and may match a
     substring of the display name; anchor with `^` when needed. Keep it short and readable.
   * Bump the `updated` field to the day of the change.
4. **Validate the JSON before submitting** - the plugin hard-rejects an unparsable payload and keeps the old
   table running, so a broken PR silently helps nobody. Use an external validator (e.g.
   <https://jsonformatter.org/json-parser>, <https://jsonlint.com/> or any other JSON linter you trust) or
   `node -e "JSON.parse(require('fs').readFileSync('cpe-table.json','utf8'))"`, and confirm every `match`
   compiles: `node -e "JSON.parse(require('fs').readFileSync('cpe-table.json','utf8')).entries.forEach(e=>new RegExp(e.match,'i'))"`.
5. **Submit a PR** touching only `cpe-table.json`. Put in the description: sample display names from the
   `not assessable` list and, per entry, the NVD evidence link (dictionary search or CVE API query).

### License types: the optional `licenseType` field (v5.6.0, no release needed either)

A CPE row may carry one more field, `licenseType`, which states how the matched product is **licensed**. It exists so an
asset report does not have to re-derive the answer per device: the value is curated once, travels with the same
downloaded table, and reaches the software CSV (`License Type` column), the Software list, the device/software *Details*
views and the optional asset-management push.

```json
{ "match": "mozilla firefox", "vendor": "mozilla", "product": "firefox", "licenseType": "MPL-2.0" }
```

**The vocabulary is closed.** Either an **SPDX license identifier** (`MIT`, `Apache-2.0`, `MPL-2.0`, `GPL-2.0-only`,
`GPL-3.0-or-later`, `LGPL-2.1-only`, `AGPL-3.0-only`, `PSF-2.0`, `MS-PL`, `MS-RL`, `PHP-3.01`, `curl`, …) or exactly one
of these three descriptors:

| Value | Meaning |
|---|---|
| `Proprietary` | closed source, and using it **requires a purchased license** |
| `Freeware` | closed source, **free of charge** - this includes hardware/OS-bundled vendor tools (the Dell, Intel, Lenovo, Logitech, Epson, NVIDIA, APC and NETGEAR companions) |
| `Freeware (non-commercial)` | free only for private, non-commercial use - a business fleet needs a paid license (e.g. IrfanView) |

The field is capped at 80 characters and restricted to `[A-Za-z0-9.+()\- ]` (it lands in a CSV cell and an HTML
attribute); an unusable value is dropped by `obj.sanitizeLicenseType` and the **mapping row still applies** - a bad
annotation must never cost CVE coverage. It is kept **verbatim, never lowercased** (SPDX ids are case-sensitive).

**What the field is NOT:** it describes the *software* license, never the purchase model of one installation. Whether a
specific machine holds a Retail, OEM or Volume key, and whether that license is activated, is measured **on the device**
from `SoftwareLicensingProduct` (`ProductKeyChannel`, `LicenseFamily`, `LicenseStatus` - see the license section below),
and seats / expiry / purchase data are not on a device at all: they belong to the asset-management system
(Settings › Asset management). Do not put `Subscription`, `OEM` or `Perpetual` into this field - a product can be sold
both ways.

**Evidence rule (same spirit as the license table):** cite where the statement comes from. The primary source is the
**winget community manifest** of the product (`microsoft/winget-pkgs`, MIT licensed, so its data is compatible with this
MIT project) read as `winget show --id <id> --exact --locale en-US` → its `License:` field; the second is the project's
own `LICENSE` statement. `--locale en-US` matters: without it the field can come back translated (measured: TeamViewer
reported `Proprietäre`).

`tools/gen-license-meta.js` does exactly that and is the way to fill or re-verify the field:

```bash
node tools/gen-license-meta.js            # report: evidence vs. curated value (drift, unmapped, missing)
node tools/gen-license-meta.js --write    # refresh cpe-table.json from the evidence
node tools/gen-license-meta.js --json     # machine-readable
```

It needs winget installed (on any other machine it prints `SKIP` and changes nothing) and reads the package id per row
from `tools/winget-ids.json`, keyed by the row's `match` regex so edition-specific rows map to their own package. Two
behaviours are deliberate:

* **Normalization is explicit.** Only strings listed in the tool's `NORMALIZE` map are translated (`GPLv3` →
  `GPL-3.0-or-later`, `Commercial` → `Proprietary`, `Proprietary (Freeware)` → `Freeware`, …); anything else is reported
  `UNMAPPED` and **never written**. Extend `NORMALIZE` first, don't let the tool invent a value.
* **Documented overrides.** Where the rule above and the upstream wording disagree on purpose (winget writes
  `Proprietary` for anything closed source, while this table answers "does a license have to be bought?"), the row is
  listed in `tools/winget-ids.json` → `overrides` **with its reason**. The tool then reports `override` instead of
  `DRIFT`. This is not a loophole: an override whose value does not match the curated one is reported as drift, which is
  how the tool caught two JetBrains *Community Edition* rows that had been filled with the commercial value of their
  product family.

**Omit rather than guess.** A row without evidence carries no `licenseType` at all and **must** say why in a
`_licenseNote` field on that entry (`npm test` asserts this). The UI then shows `unknown`, which is honest; a wrong
value in an asset report is not. `kind` (driver/firmware) rows never carry the field - they are exclusion markers
without a product identity.

Edition splits are legitimate and use the table's normal ordering rule: a more specific row **before** the generic one,
same `vendor`/`product`, different `licenseType` - e.g. `^intellij idea.*community` (Apache-2.0) ahead of
`^intellij idea` (Proprietary), so the free Community Edition is not reported as the commercial Ultimate.

### What this file is not

* Not for Linux distribution packages (`openssh-server`, `python3-six`, `libcurl4t64`, ...). Since v3.1.0 the
  scanner reports packages of the distribution as *patched by the distribution* while the OS release is supported
  (backported fixes keep the upstream version, so NVD ranges would only raise false alarms). A table row would be
  ignored for them anyway; do not add one. Packages from third-party repositories (Docker, NVIDIA, ...) are
  matched normally and may get rows.
* Regexes must match the Windows display name narrowly: a broad `^python` once swallowed every `python3-*` library
  package and reported the interpreter's CVEs against them. Anchor (`^`) and include a distinguishing word or
  version pattern.
* Not the place for pretending that OEM components have an NVD product. A driver/firmware display name
  ("Realtek Audio Driver", "ACME BIOS Update") that shows up as `not assessable` is still NOT a CPE mapping
  candidate - if you are sure it is a driver or firmware, add `{"match":"^Realtek Audio Driver$","kind":"driver"}`
  (or `"kind":"firmware"`) instead: the scanner then reports it in its own honest out-of-scope category, which
  needs no vendor/product verification. Never mark an application as `kind` - that would hide real CVEs.
* Do not add `inventoryScanner`/`vulnerabilityScanner`/`wingetUpdater` config here; settings live in the
  panel (see README).
* Changes to any other file (plugin code, views, this guide) go through the normal code path:
  `npm test` must pass and the version is bumped in `config.json` **and** the `@version` header of
  `inventoryscanner.js` together.

## License-mapping contributions: `license-table.json` (no release needed)

The program-name → license-location table is `license-table.json` in this repository root. Like the CPE table it is
shipped inside the plugin **and** re-downloaded by running servers (at server start and with every NVD refresh cycle since v5.5.1 - before only at
server start; https only), so a
pull request that improves it **may touch only this file** - no version bump, no release. The panel section
*Software → License keys* shows where the active table came from, and admin-custom rules always win over it.

### How to add a license rule (the verified process)

1. **Find the storage location from documentation or a measured install - never guess.** A rule is only as honest
   as its source: cite the vendor article / knowledge-base number / admin manual in the entry's `_source` field and
   in the PR description. Entries without a documented path are rejected. If the vendor stores the key **encrypted**
   (Adobe, Foxit, PDF-XChange's `Tracker Software\Vault`, ...) or as a **binary blob** (Total Commander's
   `wincmd.key`), do NOT add an entry - a rule that extracts ciphertext would look like a license and is not one.
   The same holds for anything you could only "confirm" by reading a value whose meaning is undocumented.
2. **Express it with the data-only rule types.** `{type:'registry', path, value}`, `{type:'file', path,
   regex|jsonfield|line}` (regex group 1 is the key; without an extractor the trimmed file content is used, capped
   at 512 characters), `{type:'wmi', class, property, filter}`. There is deliberately **no command type** - the
   table can never execute anything on a device.
3. **Use the per-user / wildcard extensions (v5.5.0) when the product stores per user or per version:**
   * `"perUser": true` on a **registry** rule: write the path as `HKCU:\Software\...`; it is then read from every
     *already-loaded* user hive (`HKEY_USERS\<SID>`). Hives of logged-off users are **never** loaded (`reg load`
     would modify the system), so such keys stay uncovered - say so in the PR instead of faking it.
   * `"perUser": true` on a **file** rule: the placeholder `{{profile}}` in the path becomes each user's profile
     directory (e.g. `{{profile}}\AppData\Roaming\Product\key.lic`). The placeholder without `perUser` is rejected.
   * Exactly **one `*`** per path: in a registry path one whole subkey segment that is enumerated (version-dependent
     subkeys such as `License.ws.*`; at most 20 matches, first non-empty value wins), in a file path a leaf pattern
     (at most 5 candidate files, e.g. `*.mountainducklicense`). More than one `*` is rejected.
   * At most 20 user profiles are considered per run; keep rule lists at ≤ 8 rules per entry.
4. **Edit `license-table.json`:** entries are matched **in order, first hit wins** (custom rules of an admin win
   over all of them), `match` is a JavaScript regex source compiled with the `i` flag only, and every `match` and
   every file `regex` passes the same safety gate as the CPE table (a repeated group must contain no quantifier and no
   `|` at any depth, no backreferences - since v5.5.1; `node tools/test-plugin.js` checks every shipped regex against it).
   Bump the `updated` field to the day of the change. The answer for a found key carries the user it came from, and
   the software CSV's *License Source* column shows e.g. `registry (user: alice)`.
5. **Validate before submitting:** `node -e "JSON.parse(require('fs').readFileSync('license-table.json','utf8'))"`,
   every `match` compiles (`...entries.forEach(e=>new RegExp(e.match,'i'))`), and every rule survives the plugin's
   own sanitizer - the cheapest check is `npm test`, whose license steps apply the shipped table exactly like a
   running server does.
6. **Submit a PR** touching only `license-table.json`, with the `_source` citation per entry and, where possible,
   the display name as it appears in a software CSV export.

### What this file is not

* Not a key dump: values are read on the device and stay there (`data/<node>/license.json` on the server); the
  table holds only *where to look*, never keys.
* Not for Microsoft product keys or Microsoft license types - those come from the `SoftwareLicensingProduct` WMI class
  behind the "include Microsoft keys" switch, not from a rule. Since v5.6.0 that read also returns the license TYPE and
  the activation state (`ProductKeyChannel` → Retail / OEM:DM / OEM:NONSLP / Volume:MAK / Volume:KMSCLIENT,
  `LicenseFamily` → the edition, `LicenseStatus` → licensed / grace / notification / unlicensed, plus grace minutes and
  an evaluation end date), translated to words server-side. Do not write a rule that reaches for the same class, and do
  not add a rule that reads a **full** product key (`DigitalProductId`, `OA3xOriginalProductKey`): the plugin reports the
  last five characters on purpose - a full key is a usable secret, and decoding one is what the AV-flagged key-finder
  tools do. A rule that would do that is rejected in review.
* Not for paths that only exist on one machine of the author. A curated row ships to every server; if the location
  differs per install, it belongs in the admin's custom rules instead.
* Not for a value name you have only seen mentioned somewhere. **Measure it** - the Office row shipped since v4.8.0 read
  `...\ClickToRun\Configuration\ProductIds`, and a recursive read of every value name under `ClickToRun` on a real Office
  2019 installation found no `ProductIds` anywhere: the value is `ProductReleaseIds` (with `ProductKeys` beside it), so
  the rule had never returned anything. A one-line `Get-ChildItem -Recurse` over the product's key, or
  `(Get-Item '<path>').Property`, turns a plausible rule into a working one; put what you measured into `_source`.

## Code contributions

* Run `npm test` (requires `npm ci` once; needs handlebars for the view tests). `tools/` is the
  verification suite for this repository - the plugin itself must keep working without it.
* Never commit exported inventories, CSV/TXT dumps from support sessions or anything from a MeshCentral
  datapath - the repo root gitignores `/*.txt` and `/*.csv` as a guard; keep such files outside the tree.
* Respect the documented data contracts in `AGENTS.md`; if you change a data shape, change its tests.
