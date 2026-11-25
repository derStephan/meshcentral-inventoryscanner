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
* Not for Microsoft product keys - those come from the `SoftwareLicensingProduct` WMI class behind the
  "include Microsoft keys" switch, not from a rule.
* Not for paths that only exist on one machine of the author. A curated row ships to every server; if the location
  differs per install, it belongs in the admin's custom rules instead.

## Code contributions

* Run `npm test` (requires `npm ci` once; needs handlebars for the view tests). `tools/` is the
  verification suite for this repository - the plugin itself must keep working without it.
* Never commit exported inventories, CSV/TXT dumps from support sessions or anything from a MeshCentral
  datapath - the repo root gitignores `/*.txt` and `/*.csv` as a guard; keep such files outside the tree.
* Respect the documented data contracts in `AGENTS.md`; if you change a data shape, change its tests.
