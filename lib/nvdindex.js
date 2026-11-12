/**
 * @file lib/nvdindex.js
 * @brief The in-memory CVE index built from the feeds: CPE criteria extraction, vendor/product token sets, version comparison, the age rule for version-less CVEs and the CVE search every scanner path uses.
 *
 * Part of the MeshCentral Inventory & Vulnerability Scanner plugin; see ../inventoryscanner.js
 * for the module list and the attach order. Every member is attached to the shared plugin
 * object, so cross-module calls go through obj.name(...) and stay replaceable at runtime.
 */

"use strict";

/**
 * @brief Attach this module's members to one plugin instance.
 * @param {object} obj - The plugin object created by the entry point.
 */
module.exports.attach = function (obj) {
    /**
     * @brief In-memory NVD product index.
     * @type {Object<string, Array<object>>}
     * Maps <code>"vendor|product"</code> (lower-cased) to an array of CPE match
     * definitions. Each definition has the shape
     * <code>{ part, kind:'any'|'exact'|'range', version, startInc, startExc, endInc, endExc, cves }</code>.
     */
    obj.productIndex = {};

    /** @type {Object<string, Array<object>>} Secondary index by product name only.
     * Maps <code>"product"</code> (lower-cased) to an array of
     * <code>{ vendor, defs }</code> so CVEs can be searched by product name alone,
     * independent of the (often unreliable) vendor guess. */
    obj.productIndexByProduct = {};
/** @type {Object<string, number>} Set of all real CPE product tokens present in the

     * loaded NVD index (lower-cased). Used to check whether a candidate product token
     * derived from an installed-software name actually exists before searching. */
    obj.cpeProductTokens = {};

    /** @type {Object<string, number>} CPE vendor tokens of APPLICATION entries in the loaded feeds (v3.1.0). */
    obj.cpeVendorTokens = {};

    /** @type {Array<object>} All CVE records loaded from the NVD feeds. */
    obj.allCves = [];

    /**
     * @brief Index a list of NVD vulnerability objects into <code>productIndex</code>.
     * @param {Array<object>} vulnerabilities - The <code>vulnerabilities[]</code> array from an NVD feed.
     */
    obj.processNvdData = function (vulnerabilities) {
        for (var i = 0; i < vulnerabilities.length; i++) {
            var cveData = vulnerabilities[i] && vulnerabilities[i].cve;
            if (!cveData || !cveData.id) continue;

            var cveRecord = {
                id: cveData.id,
                published: cveData.published || '',
                description: '',
                cvss: null,
                severity: 'UNKNOWN',
                references: []
            };

            if (Array.isArray(cveData.descriptions)) {
                for (var d = 0; d < cveData.descriptions.length; d++) {
                    if (cveData.descriptions[d] && cveData.descriptions[d].lang === 'en' && cveData.descriptions[d].value) {
                        cveRecord.description = cveData.descriptions[d].value;
                        break;
                    }
                }
            }

            // Prefer CVSS v3.1, then v3.0, then v2.
            if (cveData.metrics) {
                var cvssSources = [cveData.metrics.cvssMetricV31, cveData.metrics.cvssMetricV30, cveData.metrics.cvssMetricV2];
                for (var c = 0; c < cvssSources.length; c++) {
                    if (Array.isArray(cvssSources[c]) && cvssSources[c].length > 0 && cvssSources[c][0].cvssData) {
                        cveRecord.cvss = cvssSources[c][0].cvssData.baseScore || 0;
                        cveRecord.severity = cvssSources[c][0].cvssData.baseSeverity || 'UNKNOWN';
                        break;
                    }
                }
            }

            if (Array.isArray(cveData.references)) {
                for (var r = 0; r < cveData.references.length; r++) {
                    if (cveData.references[r] && cveData.references[r].url) { cveRecord.references.push(cveData.references[r].url); }
                }
            }

            // Index vulnerable CPEs from configurations[].nodes[].cpeMatch[].
            if (Array.isArray(cveData.configurations)) {
                var defs = obj.extractCpeDefsFromConfig(cveData.configurations);
                for (var p = 0; p < defs.length; p++) {
                    var def = defs[p];
                    var key = def.vendor + '|' + def.product;
                    if (!obj.productIndex[key]) { obj.productIndex[key] = []; }
                    def.cves = [cveRecord];
                    obj.productIndex[key].push(def);

                    // Build the product-only index (sorted at load time) so CVEs can
                    // be searched by product name alone, independent of vendor.
                    var pkey = def.product;
                    obj.cpeProductTokens[pkey] = 1;
                    if (def.part === 'a') { obj.cpeVendorTokens[def.vendor] = 1; }
                    if (!obj.productIndexByProduct[pkey]) { obj.productIndexByProduct[pkey] = []; }
                    var vendors = obj.productIndexByProduct[pkey];
                    var vfound = null;
                    for (var vi = 0; vi < vendors.length; vi++) {
                        if (vendors[vi].vendor === def.vendor) { vfound = vendors[vi]; break; }
                    }
                    if (!vfound) { vfound = { vendor: def.vendor, defs: [] }; vendors.push(vfound); }
                    vfound.defs.push(def);
                }
            }

            obj.allCves.push(cveRecord);
        }
    };

    /**
     * @brief Extract CPE match definitions from an NVD 2.0 configurations structure.
     * Includes applications (CPE part <code>'a'</code>) and operating systems
     * (CPE part <code>'o'</code>).
     * @param {Array<object>} config - The <code>configurations[]</code> array.
     * @returns {Array<object>} An array of CPE match definitions.
     */
    obj.extractCpeDefsFromConfig = function (config) {
        var defs = [];
        /**
         * @brief Recursively process a configurations node.
         * @param {object} node - A node within the configurations tree.
         */
        function processNode(node) {
            if (!node) return;
            if (Array.isArray(node.cpeMatch)) {
                for (var i = 0; i < node.cpeMatch.length; i++) {
                    var cm = node.cpeMatch[i];
                    if (!cm || (cm.vulnerable !== true) || !cm.criteria) continue;
                    var parts = String(cm.criteria).split(':');
                    if (parts.length < 5) continue;
                    var part = parts[2];
                    if ((part !== 'a') && (part !== 'o')) continue;
                    var vendor = String(parts[3] || '').toLowerCase();
                    var product = String(parts[4] || '').toLowerCase();
                    if (!vendor || !product) continue;

                    var criteriaVersion = parts[5] || '';
                    var hasRange = (cm.versionStartIncluding != null) || (cm.versionStartExcluding != null) ||
                                  (cm.versionEndIncluding != null) || (cm.versionEndExcluding != null);

                    var def;
                    if (hasRange) {
                        def = {
                            part: part, kind: 'range', vendor: vendor, product: product,
                            startInc: cm.versionStartIncluding != null ? String(cm.versionStartIncluding) : null,
                            startExc: cm.versionStartExcluding != null ? String(cm.versionStartExcluding) : null,
                            endInc: cm.versionEndIncluding != null ? String(cm.versionEndIncluding) : null,
                            endExc: cm.versionEndExcluding != null ? String(cm.versionEndExcluding) : null,
                            cves: []
                        };
                    } else if ((criteriaVersion === '*') || (criteriaVersion === '-')) {
                        def = { part: part, kind: 'any', vendor: vendor, product: product, cves: [] };
                    } else {
                        def = { part: part, kind: 'exact', vendor: vendor, product: product, version: criteriaVersion, cves: [] };
                    }
                    defs.push(def);
                }
            }
            if (Array.isArray(node.nodes)) {
                for (var j = 0; j < node.nodes.length; j++) { processNode(node.nodes[j]); }
            }
        }
        for (var k = 0; k < config.length; k++) { processNode(config[k]); }
        return defs;
    };

    /**
     * @brief Compare two CPE version strings segment-by-segment.
     * Numeric segments are compared numerically, otherwise lexically. A missing
     * segment sorts before a present one.
     * @param {string} a - First version.
     * @param {string} b - Second version.
     * @returns {number} -1, 0 or 1 depending on comparison.
     */
    obj.compareCpeVersions = function (a, b) {
        if (a === b) return 0;
        var sa = String(a).split('.');
        var sb = String(b).split('.');
        var len = Math.max(sa.length, sb.length);
        for (var i = 0; i < len; i++) {
            var pa = (i < sa.length) ? sa[i] : '';
            var pb = (i < sb.length) ? sb[i] : '';
            if (pa === pb) continue;
            if (pa === '') return -1;
            if (pb === '') return 1;
            var na = parseInt(pa, 10), nb = parseInt(pb, 10);
            if ((!isNaN(na)) && (!isNaN(nb))) {
                if (na < nb) return -1;
                if (na > nb) return 1;
                continue;
            }
            if (pa < pb) return -1;
            if (pa > pb) return 1;
        }
        return 0;
    };

    /**
     * @brief Test whether a CPE match definition covers an installed version.
     * @param {object} def - A CPE match definition.
     * @param {string} version - The installed version.
     * @returns {boolean} True if the definition matches the version.
     */
    /**
     * @brief Extract a comparable version core from an inventory version string.
     * Debian epochs ("1:1snap1-0ubuntu5") are stripped; a real numeric core is
     * returned without distro decoration ("22.04.0-1build1" -> "22.04.0",
     * "3.0~beta2-2" -> "3.0"). Wrapper versions that carry NO usable program
     * version (snap builds such as "1:1snap1-0ubuntu5" where the real Firefox
     * version lives inside the snap, not in dpkg) return '' - which routes the
     * row through the unknown-version logic in defMatches (only all-version
     * definitions, age-filtered) instead of comparing "parseInt('1:1snap1...')"
     * (=1) against fifteen-year-old ranges.
     * @param {string} v - Raw installed version.
     * @returns {string} numeric core, possibly empty = unknown.
     */
    obj.normalizeCveVersion = function (v) {
        var s = String(v == null ? '' : v).trim();
        if (s === '') return '';
        if (/^\d+:/.test(s)) { s = s.replace(/^\d+:/, ''); }
        var hasDot = /\d\.\d/.test(s);
        if (/ubuntu|dfsg|\+exp|bzr|deb\d|repack|~/.test(s)) {
            // Debian/Ubuntu patch upstream fixes into the SAME upstream version -
            // the NVD range check would report CVEs that the distro already fixed.
            // Without OVAL data the honest answer is: version not assessable.
            return '';
        }
        if (!hasDot && /(snap|ubuntu|deb\d|dfsg|ds|build|repack)/i.test(s) && /\d+[a-z]/i.test(s)) { return ''; }
        var m = s.match(/^\d+(?:\.\d+)*/);
        return (m ? m[0] : '');
    };

    obj.defMatches = function (def, version) {
        if (version == null) version = '';
        version = obj.normalizeCveVersion(version);
        if (version === '') {
            // Unknown installed version (entries without DisplayVersion): bounded definitions
            // cannot be asserted. An empty version sorts below every upper bound, so without
            // this guard EVERY historical CVE with an end boundary would match such software.
            // Only "applies to all versions" definitions stay reportable (age-filtered).
            return (def.kind === 'any');
        }
        if (def.kind === 'any') return true;
        if (def.kind === 'exact') {
            var dv = def.version;
            if ((dv === '*') || (dv === '-')) return true;
            return (dv === version);
        }
        if (def.startInc != null) { if (obj.compareCpeVersions(version, def.startInc) < 0) return false; }
        if (def.startExc != null) { if (obj.compareCpeVersions(version, def.startExc) <= 0) return false; }
        if (def.endInc != null) { if (obj.compareCpeVersions(version, def.endInc) > 0) return false; }
        if (def.endExc != null) { if (obj.compareCpeVersions(version, def.endExc) >= 0) return false; }
        return true;
    };

    /**
     * @brief Return the maximum age (in years) for which a CVE with an "any" version
     * (i.e. a CPE definition that applies to ALL versions) is still reported. Older
     * "any"-version CVEs are skipped because they are almost always historical and not
     * relevant to current software versions (they would otherwise match every installed
     * version). Configurable via <code>settings.vulnerabilityScanner.anyCveMaxAgeYears</code>;
     * a value of 0 disables the filter (keep all any-version CVEs). Respects the UI
     * settings overlay (scanner-settings.json overrides config.json).
     * @returns {number} The maximum age in years, or 0 to keep all.
     */
    obj.anyCveMaxAgeYears = function () {
        try {
            var cfg = obj.effectiveSectionConfig('vulnerabilityScanner');
            if (cfg && (typeof cfg.anyCveMaxAgeYears === 'number') && (cfg.anyCveMaxAgeYears >= 0)) {
                return cfg.anyCveMaxAgeYears;
            }
        } catch (e) { }
        return 5; // default: suppress any-version CVEs older than 5 years
    };

    /**
     * @brief Check whether a version-less ("any") CPE definition's CVE is too old to
     * report. An "any"-version definition matches every installed version; if its CVE
     * is older than <code>anyCveMaxAgeYears</code>, it is considered historical noise
     * and should be skipped for current software.
     * @param {object} def - A CPE match definition (<code>kind === 'any'</code>).
     * @param {object} cve - The CVE record (has <code>published</code>).
     * @returns {boolean} True if the CVE should be suppressed because it is too old.
     */
    obj.anyCveTooOld = function (def, cve) {
        if ((def == null) || (def.kind !== 'any') || (cve == null)) return false;
        var maxAge = obj.anyCveMaxAgeYears();
        if (maxAge <= 0) return false; // filter disabled
        var pub = (cve.published != null) ? String(cve.published) : '';
        var year = parseInt(pub.substring(0, 4), 10);
        if (!isNaN(year)) {
            return (obj.currentYear() - year) > maxAge;
        }
        return false;
    };

    /**
     * @brief Search the index for CVEs matching a product/version.
     * @param {string} vendor - The CPE vendor (lower-cased internally).
     * @param {string} product - The CPE product (lower-cased internally).
     * @param {string} version - The installed version.
     * @param {string} [partFilter] - CPE part filter: 'a' (default) or 'o'.
     * @returns {Array<object>} Matching CVE records, deduplicated and sorted by CVSS descending.
     */
    obj.searchCves = function (vendor, product, version, partFilter) {
        if (!vendor || !product) return [];
        var wantPart = partFilter || 'a';
        var defs = obj.productIndex[String(vendor).toLowerCase() + '|' + String(product).toLowerCase()];
        if (!defs || defs.length === 0) return [];

        var results = [];
        for (var i = 0; i < defs.length; i++) {
            if (defs[i].part !== wantPart) continue;
            if (obj.defMatches(defs[i], version)) {
                // Suppress historical "any"-version CVEs for current software.
                var dl = defs[i].cves || [];
                for (var d = 0; d < dl.length; d++) {
                    if (!obj.anyCveTooOld(defs[i], dl[d])) { results.push(dl[d]); }
                }
            }
        }
        var seen = {}, unique = [];
        for (var j = 0; j < results.length; j++) {
            if (results[j] && !seen[results[j].id]) { seen[results[j].id] = true; unique.push(results[j]); }
        }
        unique.sort(function (a, b) { return (b.cvss || 0) - (a.cvss || 0); });
        return unique;
    };

    /**
     * @brief Search the index for CVEs by product name alone, across all vendors.
     * Uses the pre-sorted product index (built at NVD load time) so this is a
     * fast lookup per product, independent of the vendor. Matches CPE application
     * parts only.
     * @param {string} product - The CPE product name (lower-cased).
     * @param {string} version - The installed version.
     * @returns {Array<object>} Matching CVE records, deduplicated and sorted by CVSS descending.
     */
    obj.searchCvesByProduct = function (product, version) {
        if (!product) return [];
        var pkey = String(product).toLowerCase();
        var vendors = obj.productIndexByProduct[pkey];
        if (!vendors || vendors.length === 0) return [];

        var results = [];
        for (var v = 0; v < vendors.length; v++) {
            var defs = vendors[v].defs;
            if (!defs) continue;
            for (var i = 0; i < defs.length; i++) {
                if (defs[i].part !== 'a') continue;
                if (obj.defMatches(defs[i], version)) {
                    // Suppress historical "any"-version CVEs for current software.
                    var dl = defs[i].cves || [];
                    for (var d = 0; d < dl.length; d++) {
                        if (!obj.anyCveTooOld(defs[i], dl[d])) { results.push(dl[d]); }
                    }
                }
            }
        }
        var seen = {}, unique = [];
        for (var j = 0; j < results.length; j++) {
            if (results[j] && !seen[results[j].id]) { seen[results[j].id] = true; unique.push(results[j]); }
        }
        unique.sort(function (a, b) { return (b.cvss || 0) - (a.cvss || 0); });
        return unique;
    };
};
