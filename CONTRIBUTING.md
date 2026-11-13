# Contributing

## Mapping contributions: `cpe-table.json` (no release needed)

The software-name → CPE mapping table is `cpe-table.json` in this repository root - since v4.2.0 it is the
**only** curated table (the code holds no second copy). A pull request that improves coverage **must touch only
this file** - every running server picks the change up automatically (fetched at startup and after each NVD
download cycle, and the CPE section of the Settings tab shows where the active table came from). No plugin
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

## Code contributions

* Run `npm test` (requires `npm ci` once; needs handlebars for the view tests). `tools/` is the
  verification suite for this repository - the plugin itself must keep working without it.
* Never commit exported inventories, CSV/TXT dumps from support sessions or anything from a MeshCentral
  datapath - the repo root gitignores `/*.txt` and `/*.csv` as a guard; keep such files outside the tree.
* Respect the documented data contracts in `AGENTS.md`; if you change a data shape, change its tests.
