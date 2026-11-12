/**
 * @file lib/nodes.js
 * @brief Shared node/sysinfo access: sysinfo fetch, group and host-name resolution, the per-node software scan entry point and the WINDOWS-UPDATES finding.
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
    // ---- Shared node/sysinfo collection ----

    /**
     * @brief Fetch the sysinfo record for a node.
     * Sysinfo <code>_id</code> is <code>"si" + node._id</code>.
     * @param {object} node - The node record.
     * @param {function} callback - Called with <code>(err, sysinfoRecord|null)</code>.
     */
    obj.fetchSysinfo = function (node, callback) {
        if ((node == null) || (node._id == null)) { callback(null, null); return; }
        obj.db.Get('si' + node._id, function (err, docs) {
            if (err || !docs || docs.length === 0) { callback(null, null); return; }
            callback(null, docs[0]);
        });
    };

    /**
     * @brief Build a vulnerability finding for a node whose Windows is missing
     * pending updates. Used only for Windows devices with <code>count > 0</code>.
     * @param {number} count - The number of missing updates.
     * @returns {object} A critical finding record.
     */
    /**
     * @brief Scan the software of ONE node with its OS context (distro-managed rule needs the
     * OS release). Every report/scan/export path goes through here (v3.1.0).
     */
    obj.scanNodeSoftware = function (node, softwareList, callback) {
        obj.scanDeviceSoftware(softwareList, callback, { osDesc: (node && node.osdesc) || '' });
    };

    obj.windowsUpdatesFinding = function (count) {
        return {
            cve: 'WINDOWS-UPDATES',
            isWindowsUpdates: true,
            severity: 'CRITICAL',
            cvss: 10,
            description: 'Windows is not up to date: ' + count + ' critical/important update(s) pending.',
            software: 'Windows Updates',
            version: count + ' pending',
            published: '',
            references: []
        };
    };

    /**
     * @brief Resolve the human-readable device group (mesh) name for a node.
     * Prefers the live mesh record, falls back to the last segment of the mesh id.
     * @param {object} node - The node record.
     * @returns {string} The group name (may be empty).
     */
    obj.getGroupName = function (node) {
        try {
            if (node && node.meshid) {
                // Mesh records live on the webserver object, keyed by mesh _id
                // (mesh/<domain>/<name>), with a human-readable 'name' field.
                var meshes = null;
                try { meshes = obj.meshServer.webserver.meshes; } catch (e) { }
                if (!meshes) { try { meshes = obj.meshServer.meshes; } catch (e) { } }
                if (meshes && meshes[node.meshid] && meshes[node.meshid].name) {
                    return meshes[node.meshid].name;
                }
                // Fallback: derive the group name from the last segment of the mesh id.
                var parts = String(node.meshid).split('/');
                return parts[parts.length - 1] || '';
            }
        } catch (e) { }
        return '';
    };

    /**
     * @brief Return the device host name.
     * Uses the node "real name" (hostname), falling back to the display name.
     * @param {object} node - The node record.
     * @returns {string} The host name (may be empty).
     */
    obj.getHostName = function (node) {
        if (node == null) return '';
        if (node.rname) return node.rname;
        if (node.name) return node.name;
        return '';
    };
};
