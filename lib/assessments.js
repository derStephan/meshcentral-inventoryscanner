/**
 * @file lib/assessments.js
 * @brief Group-wide CVE ratings and false-positive flags: the persisted store, the single point where a stored rating is applied (getMeshAssessment) and the write handlers of the panel.
 *
 * Part of the MeshCentral Inventory & Vulnerability Scanner plugin; see ../inventoryscanner.js
 * for the module list and the attach order. Every member is attached to the shared plugin
 * object, so cross-module calls go through obj.name(...) and stay replaceable at runtime.
 */

"use strict";

const fs = require('fs');

/**
 * @brief Attach this module's members to one plugin instance.
 * @param {object} obj - The plugin object created by the entry point.
 */
module.exports.attach = function (obj) {
    /**
     * @brief Persisted group-wide assessment ratings.
     * @type {Object<string, object>}
     * Maps <code>"meshId:cveId"</code> (a rating applies to every device in the
     * group) to <code>{ meshId, cveId, assessment, comment, lastModified, assessedBy, assessedById }</code>.
     */
    obj.assessments = {};

    // ---- Assessment persistence ----

    /**
     * @brief Load manual assessments from disk into memory.
     * On parse error, resets the in-memory store to an empty object.
     */
    obj.loadAssessments = function () {
        try {
            if (fs.existsSync(obj.assessmentsPath)) {
                obj.assessments = JSON.parse(fs.readFileSync(obj.assessmentsPath, 'utf8'));
                obj.debug('plugin:inventory_scanner', 'Loaded', Object.keys(obj.assessments).length, 'assessments');
            } else { obj.assessments = {}; }
        } catch (err) {
            obj.debug('plugin:inventory_scanner', 'Error loading assessments:', err.message);
            obj.assessments = {};
        }
    };

    /**
     * @brief Persist the in-memory assessment overrides to disk.
     * @param {function} [callback] - Called with <code>null</code> on success or an Error.
     */
    obj.saveAssessments = function (callback) {
        try {
            fs.writeFileSync(obj.assessmentsPath, JSON.stringify(obj.assessments, null, 2));
            if (callback) callback(null);
        } catch (err) {
            obj.debug('plugin:inventory_scanner', 'Error saving assessments:', err.message);
            if (callback) callback(err);
        }
    };

    /**
     * @brief Look up a persisted group-wide assessment for a mesh/CVE pair.
     * @param {string} meshId - The mesh id (<code>mesh/&lt;domain&gt;/&lt;name&gt;</code>).
     * @param {string} cveId - The CVE id.
     * @returns {object|null} The assessment record, or null.
     */
    obj.getMeshAssessment = function (meshId, cveId) {
        var key = meshId + ':' + cveId;
        return obj.assessments[key] || null;
    };

    /**
     * @brief Validate a finding id: a real CVE id (CVE-YYYY-NNNNN) or the built-in
     * Windows-updates finding (<code>WINDOWS-UPDATES</code>).
     * @param {string} cveId - The finding id.
     * @returns {boolean} True when the id is valid.
     */
    obj.isFindingId = function (cveId) {
        return /^(CVE-\d{4}-\d{4,}|WINDOWS-UPDATES|OS-EOL)$/.test(cveId);
    };

    /**
     * @brief Save a group-wide assessment rating for one or more location/CVE pairs.
     * Enforces a mandatory, non-empty comment and a valid rating. The same rating is stored
     * for every given location (mesh), so a finding that affects several locations can be
     * assessed in a single step. Persists to <code>assessments.json</code>.
     * @param {object} req - The Express request (urlencoded <code>meshId</code> or
     * <code>meshIds</code> (comma-separated), <code>cveId</code>, <code>assessment</code>, <code>comment</code>).
     * @param {object} res - The Express response.
     * @param {object} user - The authenticated user.
     */
    obj.saveAssessmentHandler = function (req, res, user) {
        var meshIds = obj.parseMeshIds(req.body.meshId || req.body.meshIds);
        var cveId = String(req.body.cveId || '');
        var assessment = String(req.body.assessment || '').toUpperCase();
        var comment = String(req.body.comment || '');

        var validRatings = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
        if ((meshIds.length === 0) || !cveId || (validRatings.indexOf(assessment) < 0)) {
            res.type('json'); res.json({ error: 'Missing or invalid fields.' }); return;
        }
        if (!comment.trim()) {
            res.type('json'); res.json({ error: 'A comment is required to rate a vulnerability.' }); return;
        }
        if (!obj.isFindingId(cveId)) {
            res.type('json'); res.json({ error: 'Invalid CVE-ID format.' }); return;
        }

        // Sanitize comment: trim and limit length (stored raw, escaped when rendered).
        comment = comment.trim();
        if (comment.length > 1000) {
            res.type('json'); res.json({ error: 'Comment exceeds maximum length (1000 characters).' }); return;
        }

        for (var i = 0; i < meshIds.length; i++) {
            var key = meshIds[i] + ':' + cveId;
            obj.assessments[key] = {
                meshId: meshIds[i],
                cveId: cveId,
                assessment: assessment,
                comment: comment,
                lastModified: new Date().toISOString(),
                assessedBy: (user != null && user.name != null) ? user.name : '',
                assessedById: (user != null && user._id != null) ? user._id : ''
            };
        }
        obj.saveAssessments(function (err) {
            if (err) { res.type('json'); res.json({ error: err.message }); }
            else { res.type('json'); res.json({ success: true }); }
        });
    };

    /**
     * @brief Mark location/CVE findings as false positives (not applicable). Sets the effective
     * rating to UNKNOWN and adds the <code>flagged: true</code> marker so the finding is
     * excluded from vulnerability counts (in the printable reports and panel aggregation).
     * The comment is optional and may be left empty. Applies to every given location (mesh).
     * @param {object} req - The Express request (urlencoded <code>meshId</code> or
     * <code>meshIds</code> (comma-separated), <code>cveId</code>, optional <code>comment</code>).
     * @param {object} res - The Express response.
     * @param {object} user - The authenticated user.
     */
    obj.flagFalsePositiveHandler = function (req, res, user) {
        var meshIds = obj.parseMeshIds(req.body.meshId || req.body.meshIds);
        var cveId = String(req.body.cveId || '');
        var comment = String(req.body.comment || '');
        if ((meshIds.length === 0) || !cveId) {
            res.type('json'); res.json({ error: 'Missing mesh or CVE.' }); return;
        }
        if (!obj.isFindingId(cveId)) {
            res.type('json'); res.json({ error: 'Invalid CVE-ID format.' }); return;
        }
        comment = comment.trim();
        if (comment.length > 1000) {
            res.type('json'); res.json({ error: 'Comment exceeds maximum length (1000 characters).' }); return;
        }

        for (var i = 0; i < meshIds.length; i++) {
            var key = meshIds[i] + ':' + cveId;
            var existing = obj.assessments[key] || {};
            obj.assessments[key] = {
                meshId: meshIds[i],
                cveId: cveId,
                assessment: 'UNKNOWN',
                comment: comment,
                flagged: true,
                lastModified: new Date().toISOString(),
                assessedBy: (user != null && user.name != null) ? user.name : (existing.assessedBy || ''),
                assessedById: (user != null && user._id != null) ? user._id : (existing.assessedById || '')
            };
        }
        obj.saveAssessments(function (err) {
            if (err) { res.type('json'); res.json({ error: err.message }); }
            else { res.type('json'); res.json({ success: true, flagged: true }); }
        });
    };

    /**
     * @brief Remove the false-positive flag from location/CVE findings, restoring the NVD-based
     * effective rating (the assessment entry is removed so the finding is counted again).
     * @param {object} req - The Express request (urlencoded <code>meshId</code> or
     * <code>meshIds</code> (comma-separated), <code>cveId</code>).
     * @param {object} res - The Express response.
     * @param {object} user - The authenticated user.
     */
    obj.unflagFalsePositiveHandler = function (req, res, user) {
        var meshIds = obj.parseMeshIds(req.body.meshId || req.body.meshIds);
        var cveId = String(req.body.cveId || '');
        if ((meshIds.length === 0) || !cveId) {
            res.type('json'); res.json({ error: 'Missing mesh or CVE.' }); return;
        }
        if (!obj.isFindingId(cveId)) {
            res.type('json'); res.json({ error: 'Invalid CVE-ID format.' }); return;
        }
        for (var i = 0; i < meshIds.length; i++) {
            var key = meshIds[i] + ':' + cveId;
            if (obj.assessments[key] && obj.assessments[key].flagged) {
                delete obj.assessments[key];
            }
        }
        obj.saveAssessments(function (err) {
            if (err) { res.type('json'); res.json({ error: err.message }); }
            else { res.type('json'); res.json({ success: true, flagged: false }); }
        });
    };
};
