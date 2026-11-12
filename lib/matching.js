/**
 * @file lib/matching.js
 * @brief Resolves an installed program to a CPE: custom entries, then the curated/remote table, then the automatic product-token matcher that only accepts a token the NVD index proves - and the per-device software scan on top of it.
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
     * @brief First table hit for a display name (custom entries win, then the active
     * curated table, first match). Returns { vendor, product } for a CPE mapping row
     * or { kind } for a driver/firmware exclusion row - the FIRST hit is final, so an
     * exclusion placed before a broader CPE row suppresses it on purpose.
     * @param {string} name - The software display name.
     * @returns {object|null} { vendor, product } | { kind } | null.
     */
    obj.matchTableEntry = function (name) {
        if (!name) return null;
        var custom = obj.compiledCustomCpe();
        for (var c = 0; c < custom.length; c++) {
            if (custom[c].match.test(name)) { return { vendor: custom[c].vendor, product: custom[c].product }; }
        }
        var table = obj.activeSoftwareTable();
        for (var i = 0; i < table.length; i++) {
            var e = table[i];
            if (e.match.test(name)) { return (e.kind != null) ? { kind: e.kind } : { vendor: e.vendor, product: e.product }; }
        }
        return null;
    };

    /**
     * @brief Map a display name to a known CPE vendor/product via the curated table
     * (kind/exclusion hits deliberately return null - use obj.matchTableEntry/classifySoftware).
     * @param {string} name - The software display name.
     * @returns {object|null} <code>{ vendor, product }</code>, or null.
     */
    obj.matchKnownProduct = function (name) {
        var ent = obj.matchTableEntry(name);
        if (ent == null || ent.kind != null) return null;
        return { vendor: ent.vendor, product: ent.product };
    };

    /** @brief Conservative name rule for clearly driver/firmware software - only consulted
     *  AFTER curated+auto matching proved there is no CPE for the row, and never for
     *  driver TOOLs (booster/wizard/... are applications about drivers, not drivers). */
    obj.DRIVERTOOL_RE = /\b(booster|commander|genius|hub|wizard|assistant|studio|sdk|installer|pack(age)?s?)\b/i;

    obj.guessDriverFirmware = function (name) {
        var n = String(name || '');
        if (n === '' || obj.DRIVERTOOL_RE.test(n)) return null;
        if (/\b(firmware|bios|uefi)\b/i.test(n)) return 'firmware';
        if (/\b(drivers?|treiber)\b/i.test(n)) return 'driver';
        return null;
    };

    /**
     * @brief Full classification of one installed-software row.
     * Order: table hit (CPE or explicit kind exclusion) -> automatic evidence matcher ->
     * conservative driver/firmware name guess (only when nothing else matched).
     * @param {string} name - Display name.
     * @param {string} publisher - Publisher.
     * @returns {object} {} | { search: {vendor,product,...} } | { kind: 'driver'|'firmware' }.
     */
    obj.classifySoftware = function (name, publisher) {
        var ent = obj.matchTableEntry(name);
        if (ent != null) {
            if (ent.kind != null) return { kind: ent.kind };
            return { search: { vendor: ent.vendor, product: ent.product, viaCurated: true } };
        }
        try {
            if (obj.scannerConfig().autoProductMatch !== false) {
                var auto = obj.autoMatchProductTokens(publisher, name);
                if (auto != null) return { search: auto };
            }
        } catch (ex) { }
        var g = obj.guessDriverFirmware(name);
        if (g != null) return { kind: g };
        return {};
    };

    /**
     * @brief Map a software display name + publisher to a CPE { vendor, product } target.
     * Matching order (most to least precise): custom entries, curated table (CPE rows),
     * then the automatic evidence matcher - the latter can be switched off with the
     * vulnerabilityScanner setting autoProductMatch (default: on). A table KIND hit is an
     * explicit exclusion and yields null here (classifySoftware reports the kind).
     * @param {string} publisher - The software publisher (vendor evidence).
     * @param {string} name - The software display name (product evidence).
     * @returns {object|null} <code>{ vendor, product, viaCurated|viaAuto }</code> or null.
     */
    obj.deriveCpeProduct = function (publisher, name) {
        if (!name) return null;
        var ent = obj.matchTableEntry(name);
        if (ent != null) { return (ent.kind != null) ? null : { vendor: ent.vendor, product: ent.product, viaCurated: true }; }
        try {
            if (obj.scannerConfig().autoProductMatch !== false) {
                var auto = obj.autoMatchProductTokens(publisher, name);
                if (auto) return auto;
            }
        } catch (ex) { }
        return null;
    };

    // ---- Automatic product-token matching (offline, no configuration) ----
    // Same principle as OWASP Dependency-Check's evidence matching: vendor/product
    // evidence is derived from the installed-software entry, and a CPE product is only
    // accepted when the token provably occurs in the loaded NVD CVE data
    // (obj.cpeProductTokens / obj.productIndexByProduct, built at feed load time).
    // CVE version ranges are always re-checked by the search itself, so a token hit on
    // a patched version reports "no CVE for <product>" instead of a finding. The NVD's
    // CPE dictionary API is never called.

    /** @type {Object<string, string>} Publisher keyword -> CPE vendor (word-boundary match). */
    obj.PUBLISHER_VENDOR_MAP = {
        'adobe': 'adobe', 'microsoft': 'microsoft', 'google': 'google', 'mozilla': 'mozilla',
        'videolan': 'videolan', 'oracle': 'oracle', 'ibm': 'ibm', 'sap': 'sap',
        'vmware': 'vmware', 'citrix': 'citrix', 'cisco': 'cisco',
        'zoom video communications': 'zoom', 'teamviewer': 'teamviewer', 'anydesk': 'anydesk',
        'fortinet': 'fortinet', 'kaspersky': 'kaspersky', 'eset': 'eset', 'avast': 'avast',
        'avg': 'avg', 'bitdefender': 'bitdefender', 'mcafee': 'mcafee', 'symantec': 'symantec',
        'trend micro': 'trend_micro', 'f secure': 'f-secure', 'sophos': 'sophos',
        'malwarebytes': 'malwarebytes', 'piriform': 'piriform', 'foxit': 'foxit',
        'autodesk': 'autodesk', 'solidworks': 'solidworks', 'corel': 'corel', 'nitro': 'nitro',
        'opera software': 'opera', 'brave software': 'brave', 'vivaldi': 'vivaldi',
        'libreoffice': 'libreoffice', 'document foundation': 'libreoffice',
        'python software foundation': 'python', 'eclipse foundation': 'eclipse', 'eclipse adoptium': 'eclipse',
        'adoptium': 'eclipse', 'node js': 'nodejs', 'docker': 'docker', 'git scm': 'git',
        'github': 'github', 'slack technologies': 'slack', 'realvnc': 'realvnc', 'turbovnc': 'turbovnc',
        'tightvnc': 'tightvnc', 'ultravnc': 'ultravnc', 'openvpn': 'openvpn', 'tailscale': 'tailscale',
        'dropbox': 'dropbox', 'logmein': 'logmein', 'securepoint': 'securepoint',
        'palo alto networks': 'paloaltonetworks'
    };

    /** @type {Object<string, 1>} Single-word tokens too generic for vendor-less searching. */
    obj.GENERIC_PRODUCT_TOKENS = {
        'client': 1, 'server': 1, 'agent': 1, 'agents': 1, 'service': 1, 'services': 1,
        'update': 1, 'updates': 1, 'updater': 1, 'driver': 1, 'drivers': 1, 'plugin': 1,
        'plugins': 1, 'extension': 1, 'extensions': 1, 'add-in': 1, 'addin': 1, 'tools': 1,
        'tool': 1, 'viewer': 1, 'player': 1, 'editor': 1, 'manager': 1, 'runtime': 1,
        'framework': 1, 'engine': 1, 'connector': 1, 'component': 1, 'library': 1, 'suite': 1,
        'software': 1, 'installer': 1, 'program': 1, 'desktop': 1, 'app': 1, 'apps': 1,
        'sync': 1, 'link': 1, 'pro': 1, 'plus': 1, 'core': 1, 'pack': 1, 'data': 1
    };

    /** @type {RegExp} Architecture / language suffix noise in display names. */
    obj.NAME_ARCH_LANG_RE = /\b(?:x[ -]?(?:64|86)|amd64|arm64|aarch64|32[- ]bit|64[- ]bit|(?:de|en|es|fr|it|nl|pl|ru|ja|zh|ko|pt|sv|tr)[-_](?:de|us|gb|fr|es|it|nl|pl|ru|jp|kr|br|se|tr|cn|tw)|multi[- ]?language|german|english|french|spanish|italian)\b/gi;

    /** @type {RegExp} Edition/installer noise in display names. */
    obj.NAME_EDITION_RE = /\b(?:installer|setup|program|version|build|edition|community|professional|enterprise|standard|home|education|student|trial|preview|insider|beta|alpha|lts)\b/gi;

    /** @type {RegExp} Version-number and year noise in display names. */
    obj.NAME_VERSION_RE = /\b(?:v?\d+[.,]\d+[\d.]*|\b(?:19|20)\d\d\b|update\s?\d+)\b/gi;

    /**
     * @brief Lower-case a display name into a CPE-style product token: parenthesized
     * parts are dropped, non-alphanumerics collapse to '_', '+' and '.' are kept.
     * @param {string} s - The raw display name.
     * @returns {string} The token (possibly empty).
     */
    obj.cpeTokenize = function (s) {
        var t = String(s || '').toLowerCase().replace(/\([^)]*\)/g, ' ');
        t = t.replace(/[^a-z0-9+._]+/g, '_').replace(/^_+|_+$/g, '').replace(/_{2,}/g, '_');
        return t;
    };

    /**
     * @brief Derive a CPE vendor from a publisher display name using word-boundary
     * keywords. Unmapped publishers yield '' (no vendor evidence).
     * @param {string} publisher - The publisher display name.
     * @returns {string} A vendor token or ''.
     */
    obj.deriveVendorFromPublisher = function (publisher) {
        var p = String(publisher || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
        if (!p) return '';
        var padded = ' ' + p + ' ';
        for (var key in obj.PUBLISHER_VENDOR_MAP) {
            if (padded.indexOf(' ' + key + ' ') >= 0) { return obj.PUBLISHER_VENDOR_MAP[key]; }
        }
        return obj.vendorFromPublisherIndex(publisher);
    };

    /** @type {RegExp} legal-form and filler words removed from publisher names. */
    obj.PUBLISHER_NOISE_RE = /\b(inc|incorporated|corp|corporation|co|company|gmbh|ag|ltd|limited|llc|s\s?r\s?o|kg|sa|bv|srl|plc|oy|ab|se|pty|technologies|technology|software|systems|international|group|the)\b/g;

    /**
     * @brief Generic publisher -> CPE vendor evidence (v3.1.0): the publisher, stripped of legal
     * forms, is accepted as vendor ONLY when exactly that token exists as a vendor in the loaded
     * NVD data ("JetBrains s.r.o." -> jetbrains, "Apache Friends" -> apache_friends,
     * "Nero AG" -> nero). It never invents a vendor; the product must still be proven by
     * autoMatchProductTokens. Maintainer e-mail publishers (Linux packages) are ignored.
     * @param {string} publisher - Publisher display name.
     * @returns {string} vendor token or ''.
     */
    obj.vendorFromPublisherIndex = function (publisher) {
        var raw = String(publisher || '');
        if (raw === '' || /@/.test(raw)) return '';
        if (obj.cpeVendorTokens == null || Object.keys(obj.cpeVendorTokens).length === 0) return '';
        var w = raw.toLowerCase().replace(/\(.*?\)/g, ' ').replace(/[,.&]/g, ' ').replace(obj.PUBLISHER_NOISE_RE, ' ').split(/[^a-z0-9+-]+/).filter(Boolean);
        if (w.length === 0) return '';
        var cands = [w.join('_'), w.join(''), w.join('-'), w[0]];
        for (var i = 0; i < cands.length; i++) {
            var c = cands[i];
            if (c && c.length >= 3 && !obj.GENERIC_PRODUCT_TOKENS[c] && obj.cpeVendorTokens[c] === 1) return c;
        }
        return '';
    };

    /** @brief True if a token is specific enough to be searched across all vendors. */
    obj.isTrustworthyProductToken = function (token) {
        if (!token || (token.length < 3)) return false;
        if (token.indexOf('_') >= 0) return true;
        return (token.length >= 6) && !obj.GENERIC_PRODUCT_TOKENS[token];
    };

    /**
     * @brief Automatic evidence matching (see block comment above). Candidate tokens:
     * the noise-stripped name, the raw name, the version-stripped name, and the name
     * minus a leading vendor word. Candidates are validated against the real product
     * tokens of the loaded NVD data; vendor evidence must not contradict them.
     * @param {string} publisher - Vendor evidence (may be empty).
     * @param {string} name - Product evidence (display name).
     * @returns {object|null} <code>{ vendor, product, viaAuto: true }</code> or null.
     */
    obj.autoMatchProductTokens = function (publisher, name) {
        var vendor = obj.deriveVendorFromPublisher(publisher);
        var raw = obj.cpeTokenize(name);
        if (!raw) return null;
        var semi = name.replace(obj.NAME_ARCH_LANG_RE, ' ').replace(obj.NAME_EDITION_RE, ' ');
        var light = obj.cpeTokenize(semi);
        var heavy = obj.cpeTokenize(semi.replace(obj.NAME_VERSION_RE, ' ').replace(/(?:\s|^)\d{1,4}(?=\s|$)/g, ' '));
        var cands = [];
        var push = function (t) { if (t && (t.length >= 3) && (cands.indexOf(t) < 0)) cands.push(t); };
        push(light); push(raw); push(heavy);
        if (vendor) {
            if ((light.indexOf(vendor + '_') === 0) && (light.length > vendor.length + 1)) push(light.substring(vendor.length + 1));
            if ((heavy.indexOf(vendor + '_') === 0) && (heavy.length > vendor.length + 1)) push(heavy.substring(vendor.length + 1));
        }
        for (var c = 0; c < cands.length; c++) {
            var token = cands[c];
            if (!obj.cpeProductTokens[token]) continue;
            var vendors = obj.productIndexByProduct[token];
            if (!vendors || (vendors.length === 0)) continue;
            if (vendor) {
                for (var v = 0; v < vendors.length; v++) {
                    if (vendors[v].vendor === vendor) { return { vendor: vendor, product: token, viaAuto: true }; }
                }
                continue;
            }
            if (vendors.length === 1) { return { vendor: vendors[0].vendor, product: token, viaAuto: true }; }
            if (obj.isTrustworthyProductToken(token)) { return { vendor: '', product: token, viaAuto: true }; }
        }
        return null;
    };


/**

     * @brief Scan a software inventory list for CVE matches.
     * Searches by product name only (independent of vendor) against the NVD index.
     * Products with a curated CPE mapping but no CVE match are reported as "no CVE for <product>".
     * Products proven by neither table nor automatic matching are reported as "not assessable".
     * @param {Array<object>} softwareList - The installed software list (from the plugin DB).
     * @param {function} callback - Called with <code>(deviceVulns)</code>.
     * @param {object} [ctx] - { osDesc } of the device (v3.1.0): enables the distro-managed rule.
     */
    obj.scanDeviceSoftware = function (softwareList, callback, ctx) {
        var deviceVulns = [];
        if (!Array.isArray(softwareList)) { if (callback) callback(deviceVulns); return; }
        var osState = null;
        var distroRule = obj.scannerConfig().distroManaged !== false;

        // Sequential processing to keep API load low and respect NVD rate limits.
        var idx = 0;
        var nextEntry = function () {
            if (idx >= softwareList.length) { if (callback) callback(deviceVulns); return; }
            var sw = softwareList[idx++];
            if (!sw) { nextEntry(); return; }
            var name = sw.name || sw.Name || sw.displayName || sw.DisplayName || '';
            var version = sw.version || sw.Version || '';
            var publisher = sw.publisher || sw.Publisher || sw.vendor || sw.Vendor || '';
            if (!name) { nextEntry(); return; }

            // Packages of the distribution itself: patched by its security team (backports into the
            // same upstream version), so an NVD version check would only produce false positives.
            // Judged by the support state of the OS release instead (see osSupportState).
            if (distroRule && obj.isDistroPackage(sw) && obj.isDistroMaintained(sw)) {
                if (osState == null) { osState = obj.osSupportState(ctx && ctx.osDesc); }
                var st = osState.state;
                deviceVulns.push({
                    status: (st === 'supported') ? 'distro-managed' : (st === 'eol' ? 'distro-eol' : 'distro-unknown'),
                    distro: st, isCve: false, cve: '', severity: '', cvss: '',
                    description: (st === 'supported')
                        ? ('Package of ' + osState.label + ' - patched by the distribution (' + osState.reason + '); NVD version ranges do not apply to backported distribution builds.')
                        : (st === 'eol'
                            ? ('Package of ' + osState.label + ' - the release no longer receives security updates (' + osState.reason + '); fixes are missing, upgrade the release.')
                            : ('Package of ' + (osState.label || 'an unrecognized OS') + ' - support state unknown (' + osState.reason + '); not checked against the NVD.')),
                    software: name, version: version, published: '', references: []
                });
                nextEntry();
                return;
            }

            // Map the display name to a CPE { vendor, product } target. When a vendor is
            // known (curated table or publisher), the CVE search is exact (vendor+product)
            // and cannot produce cross-vendor false positives. Only for product-only
            // matches (no vendor derivable) do we fall back to a search across all vendors.
            // classifySoftware additionally honours table kind rows and reports clearly
            // driver/firmware software as such (out of NVD application scope, see report).
            var classHit = obj.classifySoftware(name, publisher);
            var searchResult = classHit.search;

            if (searchResult) {
                var cves = [];
                if (searchResult.vendor) {
                    cves = obj.searchCves(searchResult.vendor, searchResult.product, version);
                } else {
                    cves = obj.searchCvesByProduct(searchResult.product, version);
                }
                if (cves.length > 0) {
                    // Real CVE matches: no API lookup needed (the token is already known).
                    for (var j = 0; j < cves.length; j++) {
                        deviceVulns.push({
                            status: 'CVE',
                            isCve: true,
                            cve: cves[j].id, severity: cves[j].severity, cvss: cves[j].cvss,
                            description: cves[j].description, software: name, version: version,
                            published: cves[j].published, references: cves[j].references
                        });
                    }
                    nextEntry();
                    return;
                }
            }

            // No CVE match in the curated list. If the product is known via the curated
            // table but has no CVEs in the NVD list -> "no CVE".
            // If neither curated table nor automatic token matching prove a real CPE
            // product -> "not assessable" (no API calls). Unknown/OEM/driver software is handled via Windows
            // Update / vendor channels and is transparently reported as such.
            if (searchResult) {
                deviceVulns.push({
                    status: 'no CVE for ' + searchResult.product,
                    isCve: false,
                    cve: '', severity: '', cvss: '',
                    description: 'CPE product "' + searchResult.vendor + '/' + searchResult.product + '" exists, but no matching CVE was found in the NVD list.' + (version === '' ? ' The installed version is unknown, so version-bounded CVEs were not asserted - only all-version entries were checked.' : ''),
                    software: name, version: version,
                    published: '', references: []
                });
            } else if (classHit.kind != null) {
                // Honest third category: drivers/firmware are patched via vendor tools and Windows
                // Update; the NVD application (part "a") data this scanner uses does not cover them.
                deviceVulns.push({
                    status: classHit.kind, outOfScope: true, isCve: false,
                    cve: '', severity: '', cvss: '',
                    description: (classHit.kind === 'driver'
                        ? 'Windows drivers are not covered by the NVD CVE application data - they are patched via the hardware vendor and Windows Update.'
                        : 'Firmware/BIOS is not covered by the NVD CVE application data this scan evaluates - updates come from the hardware vendor.'),
                    software: name, version: version,
                    published: '', references: []
                });
            } else {
                deviceVulns.push({
                    status: 'not assessable',
                    isCve: false,
                    cve: '', severity: '', cvss: '',
                    description: 'No verified CPE entry for "' + name + '". Patching/updates are not covered by the NVD CVE database.',
                    software: name, version: version,
                    published: '', references: []
                });
            }
            nextEntry();
        };
        nextEntry();
    };
};
