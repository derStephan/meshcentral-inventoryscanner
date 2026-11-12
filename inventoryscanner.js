/**
 * @file inventoryscanner.js
 * @brief MeshCentral Inventory & Vulnerability Scanner plugin - ENTRY POINT.
 *
 * Provides:
 *  - CSV exports of hardware, software and patch inventory via the device-list
 *    toolbar (Custom UI <code>devicesbarbuttons</code>) for the selected devices;
 *  - an offline NVD 2.0 CVE scanner;
 *  - a per-device-group vulnerability assessment admin panel
 *    (<code>pluginadmin.ashx?pin=inventoryscanner&action=show</code>) where the
 *    administrator rates every CVE found in a group. The rating is **group-wide**
 *    (applies to all devices in the group) and requires a mandatory comment.
 *  - printable reports, scheduled scans with notifications, a winget software
 *    updater and OS update/upgrade batches - implemented in lib/, see below.
 *
 * Only existing MeshCentral plugin/DB APIs are used. All actions are gated on a
 * full site administrator (<code>user.siteadmin === 0xFFFFFFFF</code>, i.e.
 * SITERIGHT_ADMIN). No inventory data ever leaves the server; only the public
 * NVD feed is downloaded.
 *
 * @author derStephan
 * @version 3.5.1
 *
 * Transparency: This plugin was created with the assistance of Qwen 3.6 27B and Qwen 3.8 Flash Next.
 * Audits: 2026-11-06 (NVIDIA Nemotron 3 550B A55B) and 2026-11-11 (Claude, v3.0.1) via opencode - see AUDIT.md.
 */

"use strict";

const fs = require('fs');
const path = require('path');

/**
 * Version of the CODE in this module, read ONCE when Node loads the module (v3.0.1).
 * pluginHandler.installPlugin re-requires the plugin after an upgrade, gets the CACHED old
 * module and creates a new instance from it; reading config.json per instance (pre-3.0.1)
 * made that instance report the new version, so the stale code was never noticed or reloaded.
 * This file stays the only reader of the manifest version: lib/ modules must use obj.PLUGIN_VERSION.
 */
var MODULE_CODE_VERSION = 'unknown';
try { MODULE_CODE_VERSION = JSON.parse(fs.readFileSync(path.join(__dirname, 'config.json'), 'utf8')).version || 'unknown'; } catch (ex) { }

/**
 * ARCHITECTURE (v3.5.1) - this file is ONLY the entry point: plugin identity, the on-disk
 * file layout and the wiring. Every feature area lives in its own lib/ module (one concern
 * per file, all of them small enough to read and review in one sitting):
 *
 *   lib/lifecycle.js        server_startup, plugin hot-swap after an upgrade, NVD self-heal
 *   lib/settings.js         settings overlay (scanner-settings.json) + Settings-tab handlers
 *   lib/assessments.js      group ratings + false-positive flags, their store and write handlers
 *   lib/nvd.js              NVD feed download/cache/load + download log
 *   lib/nvdindex.js         CVE index built from the feeds, CPE criteria parsing, version compare
 *   lib/cpetable.js         name -> CPE tables: built-in seed, remote maintained table, custom UI rows
 *   lib/matching.js         software name -> CPE resolution incl. automatic product-token matching
 *   lib/oslifecycle.js      distro packages judged by the OS lifecycle (endoflife.date) + OS-EOL
 *   lib/osscan.js           OS -> CPE mapping and the OS CVE scan (Windows release CPEs + build)
 *   lib/inventory.js        stored software/patches + coexistence-aware pruning
 *   lib/collector.js        live inventory collection from agents via the routeAgentCommand hook
 *   lib/scheduling.js       scheduled group scans, notifications, long-timeout helper
 *   lib/winget.js           winget engine: script builder, transport, queue, replies, scheduling
 *   lib/winget-handlers.js  winget POST handlers (config, batch run, device status, packages)
 *   lib/osupdate.js         OS update / OS release upgrade engine + its handlers
 *   lib/reports.js          panel scan aggregation + buildOverallReport + the two report routes
 *   lib/csv.js              CSV helpers, the shared node CSV builder, the export route
 *   lib/nodes.js            node/sysinfo helpers (fetch, group/host names, synthetic findings)
 *   lib/routes.js           pluginadmin.ashx GET/POST dispatch + admin/origin gate + log tailing
 *   lib/browser.js          functions exported to the browser + the device-list toolbar hook
 *
 * Each module exports <code>attach(obj)</code> and puts its functions, constants and state on
 * the shared plugin object, so:
 *  - every cross-module call is <code>obj.name(...)</code> and stays monkey-patchable
 *    (tools/test-plugin.js replaces members like obj.scanDeviceSoftware on purpose);
 *  - state is ALWAYS read from obj at call time - a module must never cache another module's
 *    member in a local variable;
 *  - the attach order below only matters for values read AT attach time (none do today);
 *  - lib/ modules must not use their own __dirname (it points at lib/) - use obj.pluginDir.
 */
const modules = [
    'lifecycle', 'settings', 'assessments', 'nvd', 'nvdindex', 'cpetable', 'matching', 'oslifecycle',
    'osscan', 'inventory', 'collector', 'scheduling', 'winget', 'winget-handlers', 'osupdate',
    'reports', 'csv', 'nodes', 'routes', 'browser'
];

/**
 * @brief Plugin entry point.
 *
 * MeshCentral invokes this with the pluginHandler instance as <code>parent</code>.
 * <code>parent.parent</code> is the meshcentral server object.
 *
 * @param {object} parent - The pluginHandler instance.
 * @returns {object} The plugin object exposing MeshCentral hooks.
 */
module.exports.inventoryscanner = function (parent) {
    var obj = {};
    /** @type {object} Reference to the pluginHandler instance. */
    obj.parent = parent;
    /** @type {object} Reference to the meshcentral server object. */
    obj.meshServer = parent.parent;
    /** @type {object} Reference to the MeshCentral database. */
    obj.db = obj.meshServer.db;
    /** @type {function} MeshCentral debug logger. */
    obj.debug = obj.meshServer.debug;
    /** @type {string} Plugin short name used in the pluginadmin.ashx?pin= URL. */
    obj.shortName = 'inventoryscanner';
    /** @type {string} Folder this plugin is installed in; lib/, cpe-table.json and the plugin's
     *  data files live under it. lib/ modules must use this instead of their own __dirname. */
    obj.pluginDir = __dirname;
    /** @type {string} Version from the manifest beside this file - shown in the panel so stale
     *  deploys (new view, old server code) are visible at a glance. */
    obj.PLUGIN_VERSION = MODULE_CODE_VERSION;
    /** @type {number} Process-wide instance generation (shared across module reloads via global):
     *  only the newest instance may act on its timers - pluginHandler replaces instances on
     *  install/upgrade without telling the old one, whose timer chains would otherwise keep running. */
    global.__inventoryscannerInstanceGen = (global.__inventoryscannerInstanceGen || 0) + 1;
    obj.instanceGen = global.__inventoryscannerInstanceGen;
    /** @brief True while this object is the newest plugin instance in the process. */
    obj.isCurrentInstance = function () { return obj.instanceGen === global.__inventoryscannerInstanceGen; };
    /** @type {number} Timer generation; incremented on every settings save so old chained timers stop themselves. */
    obj.timerGen = 0;
    /** @brief A chained timer started under generation <code>gen</code> may still run. */
    obj.timerValid = function (gen) { return (gen === obj.timerGen) && obj.isCurrentInstance(); };

    /**
     * @brief Functions exported to the web UI (serialized into /pluginHandler.js).
     * @type {Array<string>}
     */
    obj.exports = ['inventoryCsv', 'openAssessment', 'onWebUIStartupEnd'];

    /** @type {number} First year of NVD coverage. */
    obj.FIRST_YEAR = 2002;

    // ---- File layout (the plugin's on-disk contract; everything below the MeshCentral datapath) ----
    /** @type {string} Directory for NVD data under the meshcentral datapath (survives restarts). */
    obj.nvdDataPath = path.join(obj.meshServer.datapath, 'nvd');
    /**
     * @brief Directory for the plugin's own live-collected inventory database.
     * Installed software and patch lists are NOT part of the MeshCentral sysinfo
     * document (meshagent.js leaves "save software into database" as an open TODO),
     * so this plugin collects them directly from the agents and stores them here.
     * Lives under the plugin folder inside the datapath, so it survives MeshCentral
     * updates and is fully independent of the core server.
     * @type {string}
     */
    obj.inventoryDataPath = path.join(obj.meshServer.datapath, 'plugins', 'inventoryscanner', 'data');
    /** @type {string} Path to the persisted group-wide assessment ratings file. */
    obj.assessmentsPath = path.join(obj.nvdDataPath, 'assessments.json');
    /** @type {string} Path to the persisted scheduled scan results file. */
    obj.scansPath = path.join(obj.nvdDataPath, 'scans.json');
    /** @type {string} Path to the user-customized CPE mapping entries (plugins/inventoryscanner/custom-cpe.json).
     * Entries added via the admin UI are persisted here and survive MeshCentral updates. */
    obj.customCpePath = path.join(obj.meshServer.datapath, 'plugins', 'inventoryscanner', 'custom-cpe.json');
    /** @type {string} Path to the UI-managed scanner settings (plugins/inventoryscanner/scanner-settings.json).
     * Keys saved from the panel's Settings tab are persisted here and OVERRIDE the same keys in the
     * server's config.json; they take effect without a restart. config.json is never written by the plugin. */
    obj.pluginSettingsPath = path.join(obj.meshServer.datapath, 'plugins', 'inventoryscanner', 'scanner-settings.json');
    /** @type {string} Cache of the remotely maintained CPE mapping table (plugins/inventoryscanner/cpe-table.json). */
    obj.cpeTablePath = path.join(obj.meshServer.datapath, 'plugins', 'inventoryscanner', 'cpe-table.json');
    /** @type {string} on-disk cache of the lifecycle data (lib/oslifecycle.js). */
    obj.osLifecyclePath = path.join(obj.meshServer.datapath, 'plugins', 'inventoryscanner', 'os-lifecycle.json');
    /** @type {string} latest winget run results per node (state file, lib/winget.js). */
    obj.wingetResultsPath = path.join(obj.meshServer.datapath, 'plugins', 'inventoryscanner', 'winget-results.json');
    /** @type {string} append-only winget update log (shown in the UI, rotated at ~5 MB). */
    obj.wingetLogPath = path.join(obj.meshServer.datapath, 'plugins', 'inventoryscanner', 'winget-update.log');
    /** @type {string} last OS run per node (state file, lib/osupdate.js). */
    obj.osResultsPath = path.join(obj.meshServer.datapath, 'plugins', 'inventoryscanner', 'os-results.json');
    /** @type {string} OS update log (shown in the UI, rotated at ~5 MB). */
    obj.osLogPath = path.join(obj.meshServer.datapath, 'plugins', 'inventoryscanner', 'os-update.log');

    // ---- Feature modules (the list at the top of this file documents who does what) ----
    modules.forEach(function (name) {
        require(path.join(obj.pluginDir, 'lib', name + '.js')).attach(obj);
    });

    return obj;
};
