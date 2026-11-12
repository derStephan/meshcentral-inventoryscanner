/**
 * @file lib/oslifecycle.js
 * @brief Linux distribution packages judged by the OS lifecycle instead of NVD ranges, with the support dates from endoflife.date.
 * Distributions backport security fixes into the SAME upstream version ("2.4.4-2ubuntu17.6" is a patched 2.4.4), so an NVD comparison only produces false positives and misses distro-only fixes. While the release still receives security updates its package manager is responsible; once it is end-of-life nothing patches it any more - that raises the OS-EOL finding.
 * Support dates are fetched from https://endoflife.date (public, no key), cached on disk and refreshed with the NVD cycle; nothing is hard-coded, no data means 'unknown', never 'supported'.
 *
 * Part of the MeshCentral Inventory & Vulnerability Scanner plugin; see ../inventoryscanner.js
 * for the module list and the attach order. Every member is attached to the shared plugin
 * object, so cross-module calls go through obj.name(...) and stay replaceable at runtime.
 */

"use strict";

const fs = require('fs');
const path = require('path');

/**
 * @brief Attach this module's members to one plugin instance.
 * @param {object} obj - The plugin object created by the entry point.
 */
module.exports.attach = function (obj) {
    /** @type {string} default API base (product slug is appended + '.json'). */
    obj.OS_LIFECYCLE_DEFAULT_URL = 'https://endoflife.date/api/';

    /** @type {object} slug -> { fetched, cycles:[{cycle, eol, support, extendedSupport, lts, releaseLabel, latest}] } */
    obj.osLifecycle = {};

    /** @type {Array<string>} products fetched (the slugs the OS detector can produce). */
    obj.OS_LIFECYCLE_SLUGS = ['ubuntu', 'debian', 'rhel', 'centos', 'centos-stream', 'almalinux', 'rocky-linux', 'fedora', 'linux-mint', 'opensuse', 'sles', 'alpine', 'windows', 'windows-server', 'macos'];

    /** @type {number} hard cap per lifecycle payload. */
    obj.OS_LIFECYCLE_MAX_BYTES = 512 * 1024;

    /** @brief Lifecycle status for the Settings tab. */
    obj.osLifecycleStatus = function () {
        var out = { products: 0, fetched: '', enabled: obj.scannerConfig().osLifecycleEnabled };
        for (var k in obj.osLifecycle) { if (Object.prototype.hasOwnProperty.call(obj.osLifecycle, k)) { out.products++; if (obj.osLifecycle[k].fetched > out.fetched) { out.fetched = obj.osLifecycle[k].fetched; } } }
        return out;
    };

    /** @brief Load the cached lifecycle data (silent). */
    obj.loadOsLifecycle = function () {
        obj.osLifecycle = {};
        try {
            if (fs.existsSync(obj.osLifecyclePath)) {
                var d = JSON.parse(fs.readFileSync(obj.osLifecyclePath, 'utf8'));
                if (d && typeof d === 'object') {
                    for (var k in d) {
                        if (Object.prototype.hasOwnProperty.call(d, k) && obj.OS_LIFECYCLE_SLUGS.indexOf(k) >= 0 && d[k] && Array.isArray(d[k].cycles)) {
                            obj.osLifecycle[k] = { fetched: String(d[k].fetched || ''), cycles: obj.sanitizeLifecycleCycles(d[k].cycles) };
                        }
                    }
                }
            }
        } catch (e) { obj.osLifecycle = {}; }
    };

    /** @brief Keep only the fields used, with strict types (the payload is external data). */
    obj.sanitizeLifecycleCycles = function (arr) {
        var out = [];
        var dateOrBool = function (v) { return (typeof v === 'boolean') ? v : ((typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v)) ? v : null); };
        for (var i = 0; i < arr.length && out.length < 500; i++) {
            var c = arr[i];
            if (!c || (typeof c.cycle !== 'string' && typeof c.cycle !== 'number')) continue;
            var cy = String(c.cycle);
            if (!/^[A-Za-z0-9._-]{1,40}$/.test(cy)) continue;
            out.push({
                cycle: cy, eol: dateOrBool(c.eol), support: dateOrBool(c.support), extendedSupport: dateOrBool(c.extendedSupport),
                lts: c.lts === true, releaseLabel: (typeof c.releaseLabel === 'string') ? c.releaseLabel.substring(0, 60) : '',
                latest: (typeof c.latest === 'string') ? c.latest.substring(0, 40) : ''
            });
        }
        return out;
    };

    /** @brief HTTP GET JSON for one lifecycle product (https only, size-capped; test indirection). */
    obj.osLifecycleHttpGet = function (url, callback) { obj.cpeTableHttpGet(url, callback); };

    /**
     * @brief Refresh the lifecycle cache when enabled and older than the NVD cycle. One request
     * per product, sequential; a failing product keeps its cached data.
     */
    obj.maybeFetchOsLifecycle = function (callback) {
        var scfg = obj.scannerConfig();
        if (!scfg.osLifecycleEnabled) { if (callback) callback(null, { skipped: 'disabled' }); return; }
        var uh = 168;
        try { var ec = obj.effectiveSectionConfig('vulnerabilityScanner'); if (ec && (typeof ec.updateHours === 'number') && (ec.updateHours >= 1)) { uh = ec.updateHours; } } catch (e) { }
        var now = Date.now(), due = [];
        for (var i = 0; i < obj.OS_LIFECYCLE_SLUGS.length; i++) {
            var s = obj.OS_LIFECYCLE_SLUGS[i], rec = obj.osLifecycle[s];
            var age = (rec && rec.fetched) ? (now - Date.parse(rec.fetched)) : Infinity;
            if (!(age < uh * 3600 * 1000)) { due.push(s); }
        }
        if (due.length === 0) { if (callback) callback(null, { skipped: 'fresh' }); return; }
        var base = scfg.osLifecycleUrl, ok = 0, failed = 0;
        var next = function (k) {
            if (k >= due.length) {
                if (ok > 0) {
                    try { fs.mkdirSync(path.dirname(obj.osLifecyclePath), { recursive: true }); fs.writeFileSync(obj.osLifecyclePath, JSON.stringify(obj.osLifecycle)); } catch (e) { }
                }
                obj.nvdLog('OS lifecycle data: ' + ok + ' product(s) refreshed, ' + failed + ' failed (source ' + base + ')');
                if (callback) callback(null, { ok: ok, failed: failed });
                return;
            }
            obj.osLifecycleHttpGet(base + due[k] + '.json', function (err, text) {
                var arr = null;
                if (!err) { try { arr = JSON.parse(text); } catch (e) { arr = null; } }
                if (Array.isArray(arr) && arr.length > 0) {
                    obj.osLifecycle[due[k]] = { fetched: new Date().toISOString(), cycles: obj.sanitizeLifecycleCycles(arr) };
                    ok++;
                } else { failed++; }
                next(k + 1);
            });
        };
        next(0);
    };

    /**
     * @brief Identify the OS release of a node for the lifecycle lookup.
     * @param {string} osDesc - node.osdesc ("Ubuntu 24.04.5 LTS", "Microsoft Windows 11 Pro - 25H2/26200", ...).
     * @returns {object|null} { slug, cycles:[candidate cycle names, most specific first], label }.
     */
    obj.osReleaseOf = function (osDesc) {
        var d = String(osDesc || ''), m;
        var ver = function (re) { var x = d.match(re); return x ? x : null; };
        if (/ubuntu/i.test(d) && (m = ver(/(\d{2})\.(\d{2})/))) return { slug: 'ubuntu', cycles: [m[1] + '.' + m[2]], label: 'Ubuntu ' + m[1] + '.' + m[2] };
        if (/linux mint/i.test(d) && (m = ver(/(\d+)(?:\.(\d+))?/))) return { slug: 'linux-mint', cycles: m[2] != null ? [m[1] + '.' + m[2], m[1]] : [m[1]], label: 'Linux Mint ' + m[0] };
        if (/debian/i.test(d) && (m = ver(/(\d+)/))) return { slug: 'debian', cycles: [m[1]], label: 'Debian ' + m[1] };
        if (/centos stream/i.test(d) && (m = ver(/(\d+)/))) return { slug: 'centos-stream', cycles: [m[1]], label: 'CentOS Stream ' + m[1] };
        if (/centos/i.test(d) && (m = ver(/(\d+)/))) return { slug: 'centos', cycles: [m[1]], label: 'CentOS ' + m[1] };
        if (/red hat|rhel/i.test(d) && (m = ver(/(\d+)/))) return { slug: 'rhel', cycles: [m[1]], label: 'RHEL ' + m[1] };
        if (/almalinux/i.test(d) && (m = ver(/(\d+)/))) return { slug: 'almalinux', cycles: [m[1]], label: 'AlmaLinux ' + m[1] };
        if (/rocky/i.test(d) && (m = ver(/(\d+)/))) return { slug: 'rocky-linux', cycles: [m[1]], label: 'Rocky Linux ' + m[1] };
        if (/fedora/i.test(d) && (m = ver(/(\d+)/))) return { slug: 'fedora', cycles: [m[1]], label: 'Fedora ' + m[1] };
        if (/suse linux enterprise|sles/i.test(d) && (m = ver(/(\d+)(?:\s*SP(\d+)|\.(\d+))?/i))) { var sp = m[2] || m[3]; return { slug: 'sles', cycles: sp != null ? [m[1] + '.' + sp] : [m[1] + '.0'], label: 'SLES ' + m[0] }; }
        if (/opensuse/i.test(d) && (m = ver(/(\d+\.\d+)/))) return { slug: 'opensuse', cycles: [m[1]], label: 'openSUSE ' + m[1] };
        if (/alpine/i.test(d) && (m = ver(/(\d+)\.(\d+)/))) return { slug: 'alpine', cycles: [m[1] + '.' + m[2]], label: 'Alpine ' + m[1] + '.' + m[2] };
        if (/windows server/i.test(d) && (m = ver(/(20\d\d)(\s*r2)?/i))) return { slug: 'windows-server', cycles: [m[1] + (m[2] ? '-r2' : '')], label: 'Windows Server ' + m[1] + (m[2] ? ' R2' : '') };
        if (/windows (10|11)/i.test(d) && (m = ver(/windows (10|11)/i))) {
            var rel = d.match(/\b(\d{2}h\d|\d{4})\b(?!\d)/i), ed = /enterprise|education/i.test(d) ? 'e' : 'w';
            if (rel) { var r = rel[1].toLowerCase(); return { slug: 'windows', cycles: [m[1] + '-' + r + '-' + ed, m[1] + '-' + r], label: 'Windows ' + m[1] + ' ' + r.toUpperCase() }; }
            return { slug: 'windows', cycles: [], label: 'Windows ' + m[1] };
        }
        if (/windows 7/i.test(d)) return { slug: 'windows', cycles: ['7-sp1'], label: 'Windows 7' };
        if (/windows 8\.1/i.test(d)) return { slug: 'windows', cycles: ['8.1'], label: 'Windows 8.1' };
        return null;
    };

    /**
     * @brief Support state of a node's OS release.
     * @param {string} osDesc - node.osdesc.
     * @param {number} [now] - epoch ms (tests).
     * @returns {object} { state:'supported'|'eol'|'unknown', label, eol, source, reason }.
     *   'unknown' = release not identified or no lifecycle data (offline / disabled).
     */
    obj.osSupportState = function (osDesc, now) {
        var rel = obj.osReleaseOf(osDesc);
        if (rel == null) return { state: 'unknown', label: String(osDesc || ''), eol: '', reason: 'OS release not recognized' };
        var data = obj.osLifecycle[rel.slug];
        if (!data || !Array.isArray(data.cycles) || data.cycles.length === 0) return { state: 'unknown', label: rel.label, eol: '', reason: 'no lifecycle data (endoflife.date not fetched yet or disabled)' };
        var hit = null;
        for (var i = 0; i < rel.cycles.length && hit == null; i++) {
            for (var j = 0; j < data.cycles.length; j++) { if (data.cycles[j].cycle.toLowerCase() === rel.cycles[i]) { hit = data.cycles[j]; break; } }
        }
        if (hit == null) return { state: 'unknown', label: rel.label, eol: '', reason: 'release cycle not listed at endoflife.date' };
        var t = (now != null) ? now : Date.now();
        var end = hit.eol;
        if (end === false) return { state: 'supported', label: rel.label, eol: '', reason: 'no end-of-life date announced' };
        if (end === true) return { state: 'eol', label: rel.label, eol: '', reason: 'end of life' };
        if (typeof end === 'string') {
            var supported = (Date.parse(end + 'T23:59:59Z') >= t);
            return { state: supported ? 'supported' : 'eol', label: rel.label, eol: end, reason: (supported ? 'security updates until ' : 'security updates ended ') + end };
        }
        return { state: 'unknown', label: rel.label, eol: '', reason: 'no end-of-life date in the lifecycle data' };
    };

    /**
     * @brief True when an inventory row was reported by a Linux package manager. The MeshCentral
     * agent tags these rows with location 'dpkg'|'rpm'|'pacman'|'apk' (verified in
     * agents/modules_meshcore/linux-info.js); older inventories without that field are
     * recognized by the Debian/RPM maintainer format "Name &lt;mail@host&gt;" in the publisher.
     * @param {object} sw - inventory row.
     * @returns {boolean}
     */
    obj.isDistroPackage = function (sw) {
        if (sw == null) return false;
        var loc = String(sw.location || sw.installLocation || '').toLowerCase();
        if (loc === 'dpkg' || loc === 'rpm' || loc === 'pacman' || loc === 'apk') return true;
        return /<[^<>@\s]+@[^<>\s]+>\s*$/.test(String(sw.publisher || sw.Publisher || ''));
    };

    /**
     * @brief Third-party repositories (Docker, NVIDIA, Google, ...) also install through the
     * package manager, but they are NOT patched by the distribution's security team. Rows whose
     * maintainer address belongs to the distribution itself are distro-managed; others stay
     * subject to the normal CVE check.
     * @param {object} sw - inventory row (isDistroPackage === true).
     * @returns {boolean}
     */
    obj.isDistroMaintained = function (sw) {
        var p = String(sw.publisher || sw.Publisher || '').toLowerCase();
        var m = p.match(/@([^<>\s]+)>\s*$/);
        if (!m) return String(sw.location || '').toLowerCase() === 'apk' || String(sw.location || '').toLowerCase() === 'pacman';
        return obj.DISTRO_MAINTAINER_DOMAINS.test(m[1]);
    };

    /** @type {RegExp} mail domains of distribution package maintainers (the distribution itself). */
    obj.DISTRO_MAINTAINER_DOMAINS = /(^|\.)(ubuntu\.com|canonical\.com|debian\.org|redhat\.com|fedoraproject\.org|centos\.org|almalinux\.org|rockylinux\.org|suse\.(com|de)|opensuse\.org|alpinelinux\.org|archlinux\.org|linuxmint\.com)$/;

    /**
     * @brief Finding for a device whose OS release is end of life (v3.1.0, id OS-EOL): its
     * distribution packages / OS no longer get security fixes. Only raised when the lifecycle
     * data proves it (state 'eol'); unknown states never create a finding.
     * @param {object} node - node record.
     * @returns {object|null}
     */
    obj.osEolFinding = function (node) {
        if (obj.scannerConfig().osLifecycleEnabled === false) return null;
        var s = obj.osSupportState(node && node.osdesc);
        if (s.state !== 'eol') return null;
        return {
            cve: 'OS-EOL', isOsEol: true, severity: 'CRITICAL', cvss: 10,
            description: s.label + ' is end of life (' + s.reason + ', source endoflife.date): the operating system and its packages receive no security updates any more.',
            software: 'Operating System lifecycle', version: s.label, published: '', references: []
        };
    };
};
