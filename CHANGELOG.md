# Changelog

All notable changes to this plugin are documented in this file.

## 1.1.0

* CPE mapping coverage greatly increased: installed-software names are matched automatically against the
  CPE product tokens present in the NVD data (evidence-based, fully offline, no configuration needed;
  vendor evidence comes from the publisher, CVE version ranges are always re-checked). Switch:
  "Auto-map" in the Settings tab.
* The curated mapping table moved out of the plugin source into `cpe-table.json` in this repository.
  Every server re-downloads it with its NVD refresh cycle; improved mappings no longer need a plugin
  release. The built-in table remains as offline fallback; the CPE Mapping tab shows which table is
  active and when it was last fetched.
* README documents install and first-start timings (extraction order, status flip, NVD download,
  inventory collection).
* Panel: merged the second navigation level into the top bar.

## 1.0.0

* Initial release: hardware/software/vulnerability CSV exports with self-injecting toolbar buttons,
  offline NVD 2.0 CVE scanner, multi-location assessment panel (ratings, false positives, settings
  tab), printable reports with CPE coverage, scheduled scans with severity notifications, web-UI
  installable via this repository's config.json.
