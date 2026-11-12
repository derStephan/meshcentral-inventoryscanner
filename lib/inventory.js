/**
 * @file lib/inventory.js
 * @brief The stored software/patch inventory and the coexistence-aware pruning of superseded rows: registry leftovers collapse newest-wins while genuinely parallel installs (Edge + WebView2, VC++ x86 + x64, side-by-side Java/Python) stay.
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
    /** @type {Object<string, object>} In-memory software inventory per node id. */
    obj.softwareInventory = {};

    /** @type {Object<string, object>} In-memory Windows-updates state per node id.
     * <code>{ time, count, updates }</code> where <code>count</code> is the number of
     * missing (pending) Windows updates. */
    obj.windowsUpdates = {};

    /**
     * @brief Superseded-row pruning for the software list. Two registry rows
     * that resolve to the SAME CPE product AND the SAME arch-aware display name
     * are one program with a leftover uninstall entry (classic: "Mozilla Firefox
     * 3.6.24 (x86 de-DE)" still listed next to "Firefox 121.0.1", or a chain of
     * "Java 8 Update NNN" rows); the newer version wins. Rows that merely share
     * a CPE product mapping but differ in display name or architecture are
     * DISTINCT installs and always coexist (verified on a real fleet:
     * "Microsoft Edge" vs "Microsoft Edge WebView2-Laufzeit", VC++ 2008 x64 vs
     * x86 - silently merging them drops inventory rows the agent really
     * reported and attributes CVEs to the wrong product). Python / .NET-style
     * products key on major(.minor) because they genuinely install side by
     * side. Rows with an unknown version are never treated as superseded.
     * @param {Array<object>} softwareList - raw rows ({ name, version, publisher }).
     * @returns {Array<object>} pruned list; input is not modified.
     */
    /**
     * @brief Architecture signature of a display name ('64' / '32' / '' when
     *   not stated or both mentioned). Kept out of the name token on purpose:
     *   the token strips arch noise, the sig restores the distinction for the
     *   supersede check so x86 and x64 installs never merge.
     * @param {string} name - Display name.
     * @returns {string} The signature.
     */
    obj.pruneArchSig = function (name) {
        var n = String(name).toLowerCase();
        var b64 = /(x64|amd64|arm64|aarch64|64[ -]?bit)/.test(n);
        var b32 = /(x86|i386|32[ -]?bit)/.test(n);
        return (b64 && !b32) ? '64' : ((b32 && !b64) ? '32' : '');
    };

    /** @brief Name token with the vendor's own leading name word stripped, so the
     *  same product labeled "Mozilla Firefox" / "Firefox" still compares equal. */
    obj.pruneNameKey = function (name, vendor) {
        var tok = obj.pruneNameToken(name);
        var words = String(vendor || '').toLowerCase().replace(/[_+]+/g, ' ').split(' ');
        var changed = true;
        while (changed) {
            changed = false;
            for (var wi = 0; wi < words.length; wi++) {
                var w = words[wi];
                if (w !== '' && tok.indexOf(w + ' ') === 0) { tok = tok.substring(w.length + 1); changed = true; }
            }
        }
        return tok;
    };

    /**
     * @brief Version/arch/locale-stripped lowercase name token for the prune
     *   grouping key when no CPE mapping resolves; needs no NVD index.
     * @param {string} name - Display name.
     * @returns {string} The token.
     */
    obj.pruneNameToken = function (name) {
        return String(name).toLowerCase()
            .replace(/\(.*?\)/g, ' ')
            .replace(/\b\d+(?:[._-]\d+)*\b/g, ' ')
            .replace(/\b(x86|x64|arm64?|arm|64[ -]?bit|32[ -]?bit|[a-z][a-z][-_][A-Za-z]{2,4}|update|edition|beta|rc)\b/gi, ' ')
            .replace(/[^a-z0-9+.#]+/g, ' ')
            .replace(/\s+/g, ' ').trim().toLowerCase();
    };

    obj.pruneSuperseded = function (softwareList) {
        if (!Array.isArray(softwareList)) return [];
        // Products that genuinely install side by side, keyed by the CPE product token the mapping
        // actually produces (v3.0.1: '.net', 'visual_c\\+\\+' and friends were missing, so VC++ 2008 /
        // 2015 and .NET 8 / 10 runtimes collapsed into one row and the older one was never scanned).
        var SIDE_BY_SIDE = { jre: 1, jdk: 1, java: 1, net_framework: 1, '.net_framework': 1, '.net': 1, '.net_core': 1, 'asp.net_core': 1, dotnet: 1, python: 2, visual_c: 1, 'visual_c\\+\\+': 1, 'visual_c++': 1, 'visual_c\\+\\+_redistributable': 1, 'visual_c++_redistributable': 1, vcredist: 1 };
        var groups = {}, drop = {};
        for (var i = 0; i < softwareList.length; i++) {
            var sw = softwareList[i];
            if (sw == null) { drop[i] = true; continue; }
            var name = String(sw.name || sw.Name || sw.displayName || sw.DisplayName || '');
            var version = String(sw.version != null ? sw.version : (sw.Version != null ? sw.Version : ''));
            var vm = String(obj.normalizeCveVersion(version) || version).trim().match(/^(?:0?v|v)?(\d+)(?:[._](\d+))?/);
            var key = null, tok = '', arch = '';
            if (name !== '' && vm != null) {
                var pub = String(sw.publisher || sw.Publisher || '');
                var mapped = null;
                try { mapped = obj.deriveCpeProduct(pub, name); } catch (e) { }
                var product, vendor;
                if (mapped != null) { product = mapped.product; vendor = mapped.vendor; tok = obj.pruneNameKey(name, mapped.vendor); }
                else {
                    product = obj.pruneNameToken(name);
                    vendor = null;
                    try { vendor = obj.deriveVendorFromPublisher(pub); } catch (e2) { }
                    if (vendor == null) { vendor = '?'; }
                    else if (product.indexOf(vendor + ' ') === 0) { product = product.substring(vendor.length + 1); }
                    // "Mozilla Firefox 3.6" (unmapped form) vs "Firefox 121" is ONE program:
                    // the coexistence token must ignore the vendor's own leading name word too.
                    tok = obj.pruneNameKey(name, vendor);
                }
                var mode = SIDE_BY_SIDE[String(product).toLowerCase()] || 0;
                var grp = mode === 1 ? vm[1] : (mode === 2 ? (vm[2] != null ? vm[1] + '.' + vm[2] : vm[1]) : 'all');
                key = (vendor || '?') + '|' + String(product).toLowerCase() + '@' + grp;
                arch = obj.pruneArchSig(name);
            }
            if (key == null) continue; // unversioned / nameless rows are never treated as superseded
            var g = groups[key] || (groups[key] = []);
            var keep = true;
            for (var gi = 0; gi < g.length; gi++) {
                var e3 = g[gi];
                if (e3.tok !== tok || e3.arch !== arch) continue; // different install variant - coexists
                var cv = 0;
                try { cv = obj.compareCpeVersions(version, e3.version); } catch (e4) { cv = 0; }
                if (cv > 0) { drop[e3.i] = true; g.splice(gi, 1); gi--; } // newer leftover-free row wins
                else { keep = false; break; } // an equal-or-newer row of the same program already survives
            }
            if (keep) { g.push({ i: i, version: version, tok: tok, arch: arch }); } else { drop[i] = true; }
        }
        var out = [];
        for (var oi = 0; oi < softwareList.length; oi++) { if (!drop[oi]) out.push(softwareList[oi]); }
        return out;
    };

    /**
     * @brief Return the collected software list for a node.
     * Prefers the plugin's own database; falls back to the sysinfo <code>apps</code>
     * field if present (e.g. agents that do embed it).
     * @param {object} node - The node record.
     * @param {object} doc - The sysinfo document (may be empty).
     * @returns {Array<object>} The installed software list.
     */
    obj.getStoredSoftware = function (node, doc) {
        var key = obj.safeNodeDir(node && node._id);
        var entry = obj.softwareInventory[key];
        if (entry && Array.isArray(entry.apps) && entry.apps.length > 0) { return obj.pruneSuperseded(entry.apps); }
        var docApps = (doc != null) ? (doc.apps || doc.Apps || doc.software || doc.installedApps) : null;
        if (Array.isArray(docApps)) { return obj.pruneSuperseded(docApps); }
        return [];
    };

    /**
     * @brief Return the collected patch list for a node.
     * Prefers the plugin's own database; falls back to the sysinfo <code>qfe</code>/
     * <code>packages</code> fields if present.
     * @param {object} node - The node record.
     * @param {object} doc - The sysinfo document (may be empty).
     * @returns {Array<object>} The installed patch / package list.
     */
    obj.getWindowsUpdates = function (node) {
        var key = obj.safeNodeDir(node && node._id);
        var entry = obj.windowsUpdates[key];
        if (entry && (typeof entry.count === 'number')) {
            return { count: entry.count || 0, updates: Array.isArray(entry.updates) ? entry.updates : [] };
        }
        return null;
    };
};
