/**
 * @file lib/osscan.js
 * @brief Operating system -> CPE mapping and the OS CVE scan: Windows 10/11 by release CPE (windows_11_25h2) evaluated against the FULL build incl. UBR, Windows Server by release year, older systems by the legacy table.
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
     * @brief Curated OS description -> OS CPE mapping table.
     * @type {Array<object>}
     * Each entry: <code>{ match: RegExp, vendor, product }</code>.
     */
    obj.OS_CPE_TABLE = [
        { match: /windows server 2022/i, vendor: 'microsoft', product: 'windows_server_2022' },
        { match: /windows server 2019/i, vendor: 'microsoft', product: 'windows_server_2019' },
        { match: /windows server 2016/i, vendor: 'microsoft', product: 'windows_server_2016' },
        { match: /windows server 2012 r2/i, vendor: 'microsoft', product: 'windows_server_2012_r2' },
        { match: /windows server 2012/i, vendor: 'microsoft', product: 'windows_server_2012' },
        { match: /windows server 2008 r2/i, vendor: 'microsoft', product: 'windows_server_2008_r2' },
        { match: /windows server 2008/i, vendor: 'microsoft', product: 'windows_server_2008' },
        { match: /windows server/i, vendor: 'microsoft', product: 'windows_server' },
        { match: /windows 11/i, vendor: 'microsoft', product: 'windows_11' },
        { match: /windows 10/i, vendor: 'microsoft', product: 'windows_10' },
        { match: /windows 8\.1/i, vendor: 'microsoft', product: 'windows_8.1' },
        { match: /windows 8/i, vendor: 'microsoft', product: 'windows_8' },
        { match: /windows 7/i, vendor: 'microsoft', product: 'windows_7' },
        { match: /ubuntu/i, vendor: 'canonical', product: 'ubuntu_linux' },
        { match: /debian/i, vendor: 'debian', product: 'debian_linux' },
        { match: /centos/i, vendor: 'centos', product: 'centos' },
        { match: /red hat enterprise linux|^red hat/i, vendor: 'redhat', product: 'enterprise_linux' },
        { match: /fedora/i, vendor: 'fedora', product: 'fedora' },
        { match: /opensuse leap/i, vendor: 'opensuse', product: 'leap' },
        { match: /opensuse tumbleweed/i, vendor: 'opensuse', product: 'tumbleweed' },
        { match: /suse linux enterprise server/i, vendor: 'suse', product: 'linux_enterprise_server' },
        { match: /alpine/i, vendor: 'alpinelinux', product: 'alpine' },
        { match: /rocky linux/i, vendor: 'rocky', product: 'rocky_linux' },
        { match: /oracle linux/i, vendor: 'oracle', product: 'linux' },
        { match: /linux mint/i, vendor: 'linuxmint', product: 'linuxmint' },
        { match: /macos/i, vendor: 'apple', product: 'macos' },
        { match: /os x/i, vendor: 'apple', product: 'mac_os_x' }
    ];

    /**
     * @brief macOS version codenames -> numeric version.
     * @type {Object<string, string>}
     */
    obj.MACOS_CODENAME = {
        'sonoma': '14', 'ventura': '13', 'monterey': '12', 'big sur': '11',
        'catalina': '10.15', 'mojave': '10.14', 'high sierra': '10.13', 'sierra': '10.12',
        'el capitan': '10.11', 'yosemite': '10.10', 'mavericks': '10.9', 'mountain lion': '10.8',
        'lion': '10.7', 'snow leopard': '10.6', 'leopard': '10.5', 'tiger': '10.4', 'panther': '10.3'
    };

    /**
     * @brief Map an OS description (+ optional Windows build number) to an OS CPE target.
     * Windows uses the build number as the CPE version; macOS uses its codename; Linux
     * distros use major.minor.
     * @param {string} osDesc - The <code>node.osdesc</code> value.
     * @param {string} windowsBuild - The Windows build number, if known.
     * @returns {object|null} <code>{ vendor, product, version, versionKnown }</code>, or null if unrecognized.
     */
    obj.mapOsToCpe = function (osDesc, windowsBuild) {
        if (!osDesc) return null;
        for (var i = 0; i < obj.OS_CPE_TABLE.length; i++) {
            var entry = obj.OS_CPE_TABLE[i];
            if (entry.match.test(osDesc)) {
                var vendor = entry.vendor, product = entry.product, version = '', versionKnown = false;
                if (vendor === 'microsoft') {
                    version = windowsBuild || '';
                    versionKnown = !!version;
                } else if (vendor === 'apple') {
                    var lower = osDesc.toLowerCase();
                    for (var cn in obj.MACOS_CODENAME) {
                        if (lower.indexOf(cn) >= 0) { version = obj.MACOS_CODENAME[cn]; versionKnown = true; break; }
                    }
                    if (!versionKnown) {
                        var am = osDesc.match(/(\d+(?:\.\d+){1,2})/);
                        if (am) { version = am[1]; versionKnown = true; }
                    }
                } else {
                    var lm = osDesc.match(/(\d+)\.(\d+)/);
                    if (lm) { version = lm[1] + '.' + lm[2]; versionKnown = true; }
                    else {
                        var lm2 = osDesc.match(/(\d+)/);
                        if (lm2) { version = lm2[1] + '.0'; versionKnown = true; }
                    }
                }
                return { vendor: vendor, product: product, version: version, versionKnown: versionKnown };
            }
        }
        return null;
    };

    /**
     * @brief Search the index for OS (part 'o') CVE matches.
     * @param {string} vendor - The OS vendor.
     * @param {string} product - The OS product.
     * @param {string} version - The OS version.
     * @param {boolean} anyOnly - If true, only match definitions that explicitly apply to all versions ('any').
     * @returns {Array<object>} Matching CVE records.
     */
    obj.searchOsCves = function (vendor, product, version, anyOnly, boundedOnly) {
        var defs = obj.productIndex[String(vendor).toLowerCase() + '|' + String(product).toLowerCase()];
        if (!defs || defs.length === 0) return [];
        var results = [];
        for (var i = 0; i < defs.length; i++) {
            var def = defs[i];
            if (def.part !== 'o') continue;
            if (boundedOnly && def.kind !== 'range') continue; // only build-bounded definitions can be asserted
            if (anyOnly) {
                // Version-less OS match: apply the same historical "any"-CVE suppression
                // so ancient any-version OS CVEs do not appear on current OSes.
                if (def.kind === 'any') {
                    var dl = def.cves || [];
                    for (var d = 0; d < dl.length; d++) {
                        if (!obj.anyCveTooOld(def, dl[d])) { results.push(dl[d]); }
                    }
                }
                continue;
            }
            if (obj.defMatches(def, version)) {
                var dl2 = def.cves || [];
                for (var e = 0; e < dl2.length; e++) {
                    if (!obj.anyCveTooOld(def, dl2[e])) { results.push(dl2[e]); }
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
     * @brief Scan an operating system (from <code>node.osdesc</code>) for CVE matches.
     * @param {string} osDesc - The OS description.
     * @param {string} windowsBuild - The Windows build number, if known.
     * @returns {Array<object>} OS-level CVE findings.
     */
    /**
     * @brief Windows 10/11 and Server 2016+ target: release-specific CPE product + full build.
     * The release comes from osdesc ("... - 25H2/26200"), the build from the agent's
     * osinfo.BuildRevision ("10.0.26200.9711" = Version + "." + UBR, verified in MeshCentral
     * agents/modules_meshcore/computer-identifiers.js). A bare build number ("26200") is not
     * enough for the ranges and yields build ''.
     * @param {string} osDesc - node.osdesc.
     * @param {string} windowsBuild - osinfo.BuildRevision || osinfo.BuildNumber.
     * @returns {object|null} { product, build } or null when not Windows 10/11/Server 2016+.
     */
    obj.windowsOsTarget = function (osDesc, windowsBuild) {
        var d = String(osDesc || '');
        var b = String(windowsBuild || '').trim();
        var build = /^10\.0\.\d{4,5}\.\d+$/.test(b) ? b : '';
        var m;
        if ((m = d.match(/windows server (2016|2019|2022|2025)\b/i))) { return { product: 'windows_server_' + m[1], build: build }; }
        if ((m = d.match(/windows (10|11)\b/i))) {
            var rel = d.match(/\b(\d{2}h\d|1[5-9]\d\d|20\d\d)\b/i);
            if (rel == null) { return { product: 'windows_' + m[1], build: build }; }
            return { product: 'windows_' + m[1] + '_' + rel[1].toLowerCase(), build: build };
        }
        return null;
    };

    obj.scanDeviceOs = function (osDesc, windowsBuild) {
        var osVulns = [];
        var win = obj.windowsOsTarget(osDesc, windowsBuild);
        if (win != null) {
            // Windows 10/11/Server 2016+ (v3.1.0): the NVD keeps the version-bounded data under the
            // release-specific CPE (windows_11_25h2, windows_server_2019, ...) with ranges on the full
            // build "10.0.<build>.<UBR>". The generic windows_11/windows_10 CPEs carry mostly
            // "all versions" entries from early releases and matched EVERY machine (568 identical
            // findings per Windows 11 PC before v3.1.0). Without a full build no assertion is made.
            if (win.build === '') { return osVulns; }
            var wc = obj.searchOsCves('microsoft', win.product, win.build, false, true);
            for (var w = 0; w < wc.length; w++) {
                osVulns.push({ cve: wc[w].id, severity: wc[w].severity, cvss: wc[w].cvss, description: wc[w].description, software: 'Operating System', version: osDesc + ' (' + win.build + ')', published: wc[w].published, references: wc[w].references });
            }
            return osVulns;
        }
        var target = obj.mapOsToCpe(osDesc, windowsBuild);
        if (!target) return osVulns;

        var cves = [];
        if (target.versionKnown) {
            cves = obj.searchOsCves(target.vendor, target.product, target.version, false);
            if (cves.length === 0) { cves = obj.searchOsCves(target.vendor, target.product, '*', false); }
        } else {
            cves = obj.searchOsCves(target.vendor, target.product, '', true);
        }

        for (var j = 0; j < cves.length; j++) {
            osVulns.push({
                cve: cves[j].id, severity: cves[j].severity, cvss: cves[j].cvss,
                description: cves[j].description, software: 'Operating System', version: osDesc,
                published: cves[j].published, references: cves[j].references
            });
        }

        return osVulns;
    };
};
