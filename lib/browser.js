/**
 * @file lib/browser.js
 * @brief Functions exported to the browser (obj.exports) and the device-list toolbar hook that injects the buttons.
 * NEVER reference obj inside an exported function - pluginHandler serializes them into a namespace without server properties, so literals are embedded instead. tools/test-plugin.js guards that invariant.
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
     * @brief MeshCentral device-list toolbar hook.
     * Called for every plugin when a device-list toolbar button fires: a
     * customui.devicesbarbuttons button or one of the toolbar buttons this plugin
     * injects itself (see the exported onWebUIStartupEnd browser hook).
     * <code>command.selectedDevices</code> holds the selected node ids on the TOP level of the
     * command - MeshCentral does NOT rights-check that list (verified in meshuser.js), so this
     * handler validates every id itself. The export type is taken from
     * <code>command.logmsg</code>. The resulting CSV is pushed to the browser via
     * <code>myparent.send()</code>.
     * @param {object} command - The parsed websocket command.
     * @param {object} myparent - The MeshUser websocket session object (has <code>.send()</code>).
     */
    obj.uiCustomEvent = function (command, myparent) {
        if ((command == null) || (myparent == null) || (myparent.send == null)) return;
        if (command.section !== 'devicesbarbuttons') return;
        // Same gate as every HTTP route (v3.0.1): only full site administrators get CSV data.
        // myparent is the MeshUser session; its .user is the authenticated account (meshuser.js).
        if (!obj.isAuthorizedAdmin(myparent.user)) return;
        // The front-end sends selectedDevices on the top level of the uicustomevent
        // command (default.handlebars customUIAction), never under command.src.
        var type = (typeof command.logmsg === 'string') ? command.logmsg : 'hardware';
        if (['hardware', 'software', 'vulns', 'assessment'].indexOf(type) < 0) { type = 'hardware'; }

        // "Vulnerability Assessment" opens the admin panel in a new browser tab
        // instead of producing a CSV download. No device records are needed - and
        // toolbar buttons may fire with an empty selection (the injected buttons, and
        // customui entries without "selection"), so the check below must come after it.
        if (type === 'assessment') {
            try { myparent.send({ action: 'plugin', plugin: obj.shortName, method: 'openAssessment' }); } catch (ex) { }
            return;
        }

        // Only well-formed node ids are looked up (the top-level selectedDevices list is NOT
        // rights-checked by MeshCentral, verified in meshuser.js); capped and de-duplicated.
        var nodeIds = [];
        if (Array.isArray(command.selectedDevices)) {
            for (var si = 0; (si < command.selectedDevices.length) && (nodeIds.length < 5000); si++) {
                var sid = command.selectedDevices[si];
                if ((typeof sid === 'string') && /^node\/[^\/:]*\/[^\/:]{1,128}$/.test(sid) && (nodeIds.indexOf(sid) < 0)) { nodeIds.push(sid); }
            }
        }
        if (nodeIds.length === 0) return;

        // Load the node records for the selected ids.

        var nodes = [];
        var pending = nodeIds.length;
        nodeIds.forEach(function (nodeId) {
            obj.db.Get(nodeId, function (err, docs) {
                if (!err && docs && docs.length > 0) { nodes.push(docs[0]); }
                if (--pending === 0) {
                    obj.buildCsvForNodes(nodes, type, function (err, csvContent, base) {
                        if (err || !csvContent) { return; }
                        var filename = base + '_' + obj.timestamp() + '.csv';
                        myparent.send({ action: 'plugin', plugin: obj.shortName, method: 'inventoryCsv', data: csvContent, filename: filename });
                    });
                }
            });
        });
    };

    /**
     * @brief Browser-side function (exported via <code>exports</code>).
     * Called by the front-end websocket dispatcher when the server replies with
     * <code>{ action:'plugin', plugin:'inventoryscanner', method:'inventoryCsv', data, filename }</code>.
     * Triggers a CSV download via the global <code>saveAs</code> helper.
     * @param {object} server - The meshserver websocket object.
     * @param {object} message - The reply message containing <code>data</code> and <code>filename</code>.
     */
    obj.inventoryCsv = function (server, message) {
        try {
            if ((typeof saveAs !== 'function') || (message == null) || (message.data == null)) return;
            var bytes = (typeof message.data === 'string') ? message.data : JSON.stringify(message.data);
            saveAs(new Blob(['\uFEFF' + bytes], { type: 'text/csv;charset=utf-8' }), message.filename || 'inventory.csv');
        } catch (e) { }
    };

    /**
     * @brief Browser-side function (exported via <code>exports</code>).
     * Opens the Vulnerability Assessment admin panel in a new browser tab.
     * Called when the device-list toolbar's "Vulnerability Assessment" button fires
     * (<code>{ action:'plugin', plugin:'inventoryscanner', method:'openAssessment' }</code>).
     * @param {object} server - The meshserver websocket object.
     * @param {object} message - The (unused) reply message.
     */
    obj.openAssessment = function (server, message) {
        try {
            if (typeof window === 'undefined') return;
            // IMPORTANT: exported functions are serialized via Function.toString() into
            // the browser's pluginHandler namespace, which has no server-scope properties -
            // never reference them here, embed literals instead.
            window.open('/pluginadmin.ashx?pin=inventoryscanner&action=show', '_blank');
        } catch (e) { }
    };

    /**
     * @brief Browser hook dispatched by pluginHandler.callHook('onWebUIStartupEnd')
     * once the MeshCentral web UI has finished loading. Injects this plugin's toolbar
     * buttons into MeshCentral's own device-list button slot (the static
     * <span id="devsCustomUIBar"> element in the main view), so the buttons need no
     * server-side customui configuration. If the slot is already filled (an admin
     * defined customui.devicesbarbuttons entries), injection is skipped - no duplicates.
     * The click handlers replicate customUIAction semantics: node ids are collected
     * from the checked .DeviceCheckbox elements and sent as a uicustomevent command.
     * @param {object} server - The meshserver websocket object (unused, the global is used).
     */
    obj.onWebUIStartupEnd = function (server) {
        try {
            if (typeof document === 'undefined' || typeof meshserver === 'undefined') return;
            var bar = document.getElementById('devsCustomUIBar');
            if (bar == null || bar.innerHTML !== '') return;
            var defs = [['Hardware Inventory', 'hardware'], ['Software Inventory', 'software'], ['Vulnerability Assessment', 'assessment']];
            for (var i = 0; i < defs.length; i++) {
                (function (def) {
                    var b = document.createElement('input');
                    b.type = 'button';
                    b.value = def[0];
                    b.style.margin = '0 4px';
                    b.title = (def[1] === 'assessment') ? 'Open the vulnerability assessment panel in a new browser tab' : 'Export the checked devices as CSV';
                    b.onclick = function () {
                        try {
                            var elements = document.getElementsByClassName('DeviceCheckbox'), selectedDevices = [];
                            for (var k = 0; k < elements.length; k++) { if (elements[k].checked === true) { selectedDevices.push(elements[k].defaultValue.substring(6)); } }
                            if (selectedDevices.length === 0 && def[1] !== 'assessment') { if (typeof alert === 'function') alert('Select at least one device first.'); return; }
                            meshserver.send({ action: 'uicustomevent', section: 'devicesbarbuttons', element: '0', selectedDevices: selectedDevices, logmsg: def[1] });
                        } catch (ex) { }
                    };
                    bar.appendChild(b);
                })(defs[i]);
            }
        } catch (ex) { }
    };
};
