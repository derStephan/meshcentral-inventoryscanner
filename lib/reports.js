/**
 * @file lib/reports.js
 * @brief Panel scan aggregation (scanMultiMeshCves with the honest per-device software/version summary) and buildOverallReport, which drives both printable reports including the three coverage categories.
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
     * @brief Honest display values for a CVE row aggregated over devices.
     * Software display name and installed version are PER-DEVICE attributes, so an
     * aggregated row must never claim one arbitrary device's version as the truth
     * for all of them (that made the panel disagree with the per-device CSV).
     * Uniform values are kept; when they differ the row gets the flags
     * <code>softwareVaried</code>/<code>versionVaried</code> + the variant lists,
     * and <code>version</code> becomes '' (unknown-looking beats wrong-looking -
     * the UI renders "varies" with the full per-device breakdown).
     * @param {object} entry - CVE row with deviceList:[{name, software, version}].
     * @returns {object} The same entry, annotated.
     */
    obj.summarizeDeviceSwVer = function (entry) {
        var dl = Array.isArray(entry.deviceList) ? entry.deviceList : [];
        if (dl.length === 0) { entry.softwareVaried = false; entry.versionVaried = false; return entry; }
        var names = {}, vers = {}, nUn = 0, vUn = 0;
        for (var i = 0; i < dl.length; i++) {
            var nm = String(dl[i].software || ''), vr = String(dl[i].version || '');
            if (!Object.prototype.hasOwnProperty.call(names, nm)) { names[nm] = 1; nUn++; }
            if (!Object.prototype.hasOwnProperty.call(vers, vr)) { vers[vr] = 1; vUn++; }
        }
        entry.softwareVaried = nUn > 1;
        entry.versionVaried = vUn > 1;
        if (entry.softwareVaried) { entry.variedSoftware = Object.keys(names); entry.software = String(dl[0].software || ''); }
        if (entry.versionVaried) { entry.variedVersions = Object.keys(vers); entry.version = ''; }
        return entry;
    };

    /**
     * @brief Aggregate the unique CVEs found across all devices of a mesh.
     * Each CVE carries the mesh-wide assessment (if any).
     * @param {string} meshId - The mesh id to scan.
     * @param {function} callback - Called with <code>(err, cveList)</code> where
     * each entry is <code>{ cve, severity, cvss, description, software, version, assessment,
     * devices, deviceList }</code> - <code>devices</code> = device labels (admin given name
     * first, host name / id as fallback), <code>deviceList</code> = per-device
     * <code>{ name, software, version }</code> (the truth behind the aggregated display).
     */
    obj.scanMeshCves = function (meshId, callback) {
        obj.meshServer.db.GetAllType('node', function (err, nodes) {
            if (err) { if (callback) callback(err, []); return; }
            var meshNodes = [];
            if (nodes) {
                for (var i = 0; i < nodes.length; i++) {
                    var n = nodes[i];
                    if (n && (n.meshid === meshId) && (n.deleted == null)) { meshNodes.push(n); }
                }
            }
            if (meshNodes.length === 0) { if (callback) callback(null, []); return; }

            var found = {}; // cveId -> aggregated entry
            var pending = meshNodes.length;

            meshNodes.forEach(function (node) {
                // Admin labels in the panel read the given (renamed-by-admin) name first - same
                // rule as the wg_status table; printable reports intentionally keep host names.
                var deviceName = (typeof node.name === 'string' && node.name.trim() !== '') ? node.name.trim() : (obj.getHostName(node) || node._id);
                obj.fetchSysinfo(node, function (err, sysinfoRecord) {
                    var doc = sysinfoRecord ? (sysinfoRecord.doc || sysinfoRecord) : {};
                    var windowsBuild = '';
                    if (doc && doc.hardware && doc.hardware.windows && doc.hardware.windows.osinfo) { windowsBuild = doc.hardware.windows.osinfo.BuildRevision || doc.hardware.windows.osinfo.BuildNumber || ''; }
                    obj.scanNodeSoftware(node, obj.getStoredSoftware(node, doc), function (softwareVulns) {
                        var deviceVulns = softwareVulns.concat(obj.scanDeviceOs(node.osdesc || '', windowsBuild));
                        // Windows-only: missing updates are treated as a critical finding.
                        var wu = obj.getWindowsUpdates(node);
                        if (wu && wu.count > 0) { deviceVulns.push(obj.windowsUpdatesFinding(wu.count)); }
                        var eolF = obj.osEolFinding(node); if (eolF != null) { deviceVulns.push(eolF); }

                        for (var j = 0; j < deviceVulns.length; j++) {
                            var v = deviceVulns[j];
                            if (!v.cve) continue;
                            if (!found[v.cve]) {
                                var assessment = obj.getMeshAssessment(meshId, v.cve);
                                found[v.cve] = {
                                    cve: v.cve,
                                    severity: v.severity,
                                    cvss: v.cvss,
                                    description: v.description,
                                    software: v.software,
                                    version: v.version,
                                    assessment: assessment,
                                    devices: [],
                                    deviceList: []
                                };
                            }
                            if (found[v.cve].devices.indexOf(deviceName) < 0) {
                                found[v.cve].devices.push(deviceName);
                                found[v.cve].deviceList.push({ name: deviceName, software: String(v.software || ''), version: String(v.version || '') });
                            }
                        }
                        if (--pending === 0) {
                            var list = [];
                            for (var c in found) { list.push(obj.summarizeDeviceSwVer(found[c])); }
                            list.sort(function (a, b) { return (b.cvss || 0) - (a.cvss || 0); });
                            if (callback) callback(null, list);
                        }
                    });
                });
            });
        });
    };

    /**
     * @brief Aggregate the unique CVEs found across a set of locations (meshes).
     * Each CVE carries the list of affected locations (with their affected device labels -
     * given names first, falling back to host name then id) and
     * the per-location assessments. When every affected location has the same assessment,
     * <code>assessment</code> holds it; otherwise <code>mixed</code> is true.
     * @param {Array<string>} meshIds - The mesh ids to scan.
     * @param {function} callback - Called with <code>(err, { meshes, cves })</code> where
     * each CVE entry is <code>{ cve, severity, cvss, description, software, version,
     * locations, assessments, assessment, mixed, anyFlagged }</code>.
     */
    obj.scanMultiMeshCves = function (meshIds, callback) {
        obj.meshServer.db.GetAllType('mesh', function (meshErr, meshes) {
            var names = {};
            if (!meshErr && meshes) {
                for (var i = 0; i < meshes.length; i++) {
                    var m = meshes[i];
                    if (m && m._id) { names[m._id] = m.name || m._id; }
                }
            }
            var found = {};
            var meshList = [];
            var pending = meshIds.length;
            if (pending === 0) { if (callback) callback(null, { meshes: [], cves: [] }); return; }

            meshIds.forEach(function (meshId) {
                obj.scanMeshCves(meshId, function (err, list) {
                    var meshName = names[meshId] || obj.getGroupName({ meshid: meshId }) || meshId;
                    meshList.push({ id: meshId, name: meshName });
                    if (!err && list) {
                        for (var j = 0; j < list.length; j++) {
                            var e = list[j];
                            if (!e || !e.cve) continue;
                            var r = found[e.cve];
                            if (!r) {
                                r = found[e.cve] = {
                                    cve: e.cve,
                                    severity: e.severity,
                                    cvss: e.cvss,
                                    description: e.description,
                                    software: e.software,
                                    version: e.version,
                                    locations: [],
                                    assessments: {},
                                    deviceList: []
                                };
                            }
                            r.locations.push({ meshId: meshId, name: meshName, devices: e.devices || [], deviceList: e.deviceList || [] });
                            if (e.deviceList) { r.deviceList = r.deviceList.concat(e.deviceList); }
                            r.assessments[meshId] = e.assessment || null;
                        }
                    }
                    if (--pending === 0) {
                        var out = [];
                        for (var c in found) {
                            if (!Object.prototype.hasOwnProperty.call(found, c)) continue;
                            var entry = found[c];
                            var uniform = true, firstA = null, any = false, anyFlagged = false;
                            for (var k = 0; k < entry.locations.length; k++) {
                                var a = entry.assessments[entry.locations[k].meshId];
                                if (!a) { uniform = false; continue; }
                                any = true;
                                if (a.flagged) { anyFlagged = true; }
                                if (firstA == null) { firstA = a; }
                                else if ((a.assessment !== firstA.assessment) || (!!a.flagged !== !!firstA.flagged)) { uniform = false; }
                            }
                            // "mixed" only when some (but not all) locations share the same assessment;
                            // a completely unrated finding is simply unrated.
                            entry.mixed = any && !uniform;
                            entry.assessment = (any && uniform) ? firstA : null;
                            entry.anyFlagged = anyFlagged;
                            // Recompute the software/version display from the FULL merged
                            // device list (across all locations), not the first mesh's row.
                            obj.summarizeDeviceSwVer(entry);
                            out.push(entry);
                        }
                        out.sort(function (a, b) { return (Number(b.cvss) || 0) - (Number(a.cvss) || 0) || String(a.cve).localeCompare(String(b.cve)); });
                        meshList.sort(function (a, b) { return String(a.name).localeCompare(String(b.name)); });
                        if (callback) callback(null, { meshes: meshList, cves: out });
                    }
                });
            });
        });
    };

    /**
     * @brief Return the aggregated CVEs of the selected locations as JSON for the assessment panel.
     * @param {object} req - The Express request (expects the <code>mesh</code> query param with a
     * comma-separated list of mesh ids; empty selects nothing).
     * @param {object} res - The Express response.
     * @param {object} user - The authenticated user.
     */
    obj.assessmentScan = function (req, res, user) {
        var meshParam = String(req.query.mesh || req.query.meshes || '');
        var meshIds = obj.parseMeshIds(meshParam).slice(0, 1000); // same validation as every write path
        if (meshIds.length === 0) { res.type('json'); res.json({ error: 'No locations selected.' }); return; }
        obj.scanMultiMeshCves(meshIds, function (err, result) {
            if (err) { res.type('json'); res.json({ error: err.message }); return; }
            // Count findings flagged as false positives (excluded from the real vulnerability count).
            var flaggedCount = 0;
            for (var i = 0; i < result.cves.length; i++) {
                if (result.cves[i].assessment && result.cves[i].assessment.flagged) { flaggedCount++; }
            }
            res.type('json');
            res.json({
                meshes: result.meshes,
                cves: result.cves,
                flaggedCount: flaggedCount,
                totalCves: obj.allCves.length,
                lastUpdate: obj.lastUpdate || ''
            });
        });
    };

    /**
     * @brief Aggregate vulnerability data across ALL clients (all meshes) for the printable reports.
     * Iterates every node, runs the software/OS/update scan, and produces summary statistics.
     * The result is grouped by <b>location</b> (device group / mesh): <code>report.locations</code>
     * is an array of location records with their own KPIs, a deduplicated findings list and the
     * location's devices. <code>report.devices</code> holds the flat device list (used by the
     * separate device report). For severity counting, the manual (group) assessment rating is
     * used whenever one exists; otherwise the NVD severity. Findings flagged as false positives
     * are excluded from the counts and tracked separately.
     * @param {function} callback - Called with <code>(err, report)</code>.
     */
    obj.buildOverallReport = function (callback) {
        obj.meshServer.db.GetAllType('node', function (err, nodes) {
            if (err) { if (callback) callback(err, null); return; }
            var liveNodes = [];
            if (nodes) {
                for (var i = 0; i < nodes.length; i++) {
                    var n = nodes[i];
                    if (n && (n._id != null) && (n.deleted == null)) { liveNodes.push(n); }
                }
            }

            var report = {
                generated: new Date().toISOString(),
                totalSystems: liveNodes.length,
                totalPrograms: 0,
                assessablePrograms: 0,
                notAssessablePrograms: 0,
                outOfScopePrograms: 0,
                distroManagedPrograms: 0,
                distroEolPrograms: 0,
                distroUnknownPrograms: 0,
                coverageBase: 0,
                coveragePercent: 0,
                totalCves: 0,
                falsePositiveCves: 0,
                severityCounts: { 'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0 },
                uniqueCves: 0,
                uniqueCveIds: {},
                locations: [],
                devices: []
            };

            if (liveNodes.length === 0) { if (callback) callback(null, report); return; }

            // Group everything by location (device group / mesh), one report section per location.
            var locationsById = {};
            var getLocation = function (meshId) {
                var id = meshId || '';
                if (locationsById[id] == null) {
                    locationsById[id] = {
                        id: id,
                        name: obj.getGroupName({ meshid: id }) || '(ungrouped)',
                        totalSystems: 0,
                        totalPrograms: 0,
                        assessablePrograms: 0,
                        notAssessablePrograms: 0,
                        outOfScopePrograms: 0,
                        distroManagedPrograms: 0,
                        distroEolPrograms: 0,
                        distroUnknownPrograms: 0,
                        coverageBase: 0,
                        coveragePercent: 0,
                        totalCves: 0,
                        falsePositiveCves: 0,
                        severityCounts: { 'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0 },
                        uniqueCves: 0,
                        uniqueCveIds: {},
                        findingsById: {},
                        devices: []
                    };
                }
                return locationsById[id];
            };

            var pending = liveNodes.length;
            liveNodes.forEach(function (node) {
                var hostName = obj.getHostName(node) || node.name || node._id;
                var loc = getLocation(node.meshid);
                loc.totalSystems++;
                var deviceRec = {
                    hostName: hostName,
                    name: node.name || '',
                    group: loc.name,
                    os: node.osdesc || '',
                    programs: 0,
                    cveCount: 0,
                    critical: 0, high: 0, medium: 0, low: 0, unknown: 0,
                    severities: {}
                };
                obj.fetchSysinfo(node, function (err2, sysinfoRecord) {
                    var doc = sysinfoRecord ? (sysinfoRecord.doc || sysinfoRecord) : {};
                    var windowsBuild = '';
                    if (doc && doc.hardware && doc.hardware.windows && doc.hardware.windows.osinfo) { windowsBuild = doc.hardware.windows.osinfo.BuildRevision || doc.hardware.windows.osinfo.BuildNumber || ''; }

                    var softwareList = obj.getStoredSoftware(node, doc);
                    deviceRec.programs = softwareList.length;
                    loc.totalPrograms += softwareList.length;
                    report.totalPrograms += softwareList.length;

                    obj.scanNodeSoftware(node, softwareList, function (softwareVulns) {
                        var deviceVulns = softwareVulns.concat(obj.scanDeviceOs(node.osdesc || '', windowsBuild));
                        var wu = obj.getWindowsUpdates(node);
                        if (wu && wu.count > 0) { deviceVulns.push(obj.windowsUpdatesFinding(wu.count)); }
                        var eolF = obj.osEolFinding(node); if (eolF != null) { deviceVulns.push(eolF); }

                        // CPE coverage: classify every installed program by its scan status row.
                        // assessable = a verified CPE mapping was checked against the NVD;
                        // notAssessable = a real program with no proven CPE (the honest blind spot);
                        // outOfScope = driver/firmware - not a program the NVD application data can
                        // ever cover, so it is reported separately and EXCLUDED from the coverage
                        // denominator instead of dragging it down.
                        var progSeen = {};
                        var devOK = 0, devNA = 0, devX = 0, devDM = 0, devDE = 0, devDU = 0;
                        for (var sk = 0; sk < softwareVulns.length; sk++) {
                            var sv = softwareVulns[sk];
                            var skey = (sv.software || '') + '@@' + (sv.version || '');
                            if (progSeen[skey]) continue;
                            progSeen[skey] = 1;
                            // Distribution packages are a separate, transparent category (v3.1.0): never in
                            // the coverage denominator - their patch state is the distribution's job.
                            if (sv.distro === 'supported') { devDM++; }
                            else if (sv.distro === 'eol') { devDE++; }
                            else if (sv.distro === 'unknown') { devDU++; }
                            else if (sv.outOfScope) { devX++; }
                            else if (sv.status === 'not assessable') { devNA++; }
                            else { devOK++; }
                        }
                        deviceRec.programsAssessable = devOK;
                        deviceRec.programsNotAssessable = devNA;
                        deviceRec.programsOutOfScope = devX;
                        deviceRec.programsDistroManaged = devDM + devDE + devDU;
                        deviceRec.osSupport = obj.osSupportState(node.osdesc).state;
                        loc.assessablePrograms += devOK;
                        loc.notAssessablePrograms += devNA;
                        loc.outOfScopePrograms += devX;
                        loc.distroManagedPrograms += devDM; loc.distroEolPrograms += devDE; loc.distroUnknownPrograms += devDU;
                        report.assessablePrograms += devOK;
                        report.notAssessablePrograms += devNA;
                        report.outOfScopePrograms += devX;
                        report.distroManagedPrograms += devDM; report.distroEolPrograms += devDE; report.distroUnknownPrograms += devDU;

                        // Deduplicate CVEs per device.
                        var seen = {};
                        for (var j = 0; j < deviceVulns.length; j++) {
                            var v = deviceVulns[j];
                            if (!v.cve) continue;
                            if (seen[v.cve]) continue;
                            seen[v.cve] = true;

                            // Effective severity: manual (group) assessment wins over NVD severity.
                            var assessment = obj.getMeshAssessment(node.meshid, v.cve);

                            // Unique finding record per location (deduplicated across devices).
                            var finding = loc.findingsById[v.cve];
                            if (finding == null) {
                                var effSev = (assessment && assessment.assessment) ? String(assessment.assessment).toUpperCase() : String(v.severity || 'UNKNOWN').toUpperCase();
                                finding = loc.findingsById[v.cve] = {
                                    cve: v.cve,
                                    severity: v.severity || 'UNKNOWN',
                                    cvss: (v.cvss != null) ? v.cvss : '',
                                    software: v.software || '',
                                    version: v.version || '',
                                    description: v.description || '',
                                    assessment: (assessment && assessment.assessment) ? assessment.assessment : '',
                                    comment: (assessment && assessment.comment) ? assessment.comment : '',
                                    flagged: !!(assessment && assessment.flagged),
                                    effectiveSeverity: (assessment && assessment.flagged) ? 'false positive' : effSev,
                                    devices: [],
                                    deviceList: []
                                };
                            }
                            if (finding.devices.indexOf(hostName) < 0) {
                                finding.devices.push(hostName);
                                finding.deviceList.push({ name: hostName, software: String(v.software || ''), version: String(v.version || '') });
                            }

                            // A finding flagged as false positive is not counted as a vulnerability
                            // (excluded from total findings and the severity distribution).
                            if (assessment && assessment.flagged) {
                                report.falsePositiveCves++;
                                loc.falsePositiveCves++;
                                continue;
                            }

                            deviceRec.cveCount++;
                            report.totalCves++;
                            loc.totalCves++;

                            var effSeverity = (assessment && assessment.assessment) ? assessment.assessment : (v.severity || 'UNKNOWN');
                            effSeverity = String(effSeverity).toUpperCase();
                            if (!report.severityCounts[effSeverity]) { report.severityCounts[effSeverity] = 0; }
                            report.severityCounts[effSeverity]++;
                            if (!loc.severityCounts[effSeverity]) { loc.severityCounts[effSeverity] = 0; }
                            loc.severityCounts[effSeverity]++;
                            if (!deviceRec.severities[effSeverity]) { deviceRec.severities[effSeverity] = 0; }
                            deviceRec.severities[effSeverity]++;

                            if (report.uniqueCveIds[v.cve] == null) { report.uniqueCveIds[v.cve] = 1; }
                            else { report.uniqueCveIds[v.cve]++; }
                            if (loc.uniqueCveIds[v.cve] == null) { loc.uniqueCveIds[v.cve] = 1; }
                            else { loc.uniqueCveIds[v.cve]++; }
                        }
                        deviceRec.critical = deviceRec.severities['CRITICAL'] || 0;
                        deviceRec.high = deviceRec.severities['HIGH'] || 0;
                        deviceRec.medium = deviceRec.severities['MEDIUM'] || 0;
                        deviceRec.low = deviceRec.severities['LOW'] || 0;
                        deviceRec.unknown = deviceRec.severities['UNKNOWN'] || 0;

                        loc.devices.push(deviceRec);
                        report.devices.push(deviceRec);
                        if (--pending === 0) {
                            for (var id in locationsById) {
                                if (!Object.prototype.hasOwnProperty.call(locationsById, id)) continue;
                                var L = locationsById[id];
                                L.uniqueCves = Object.keys(L.uniqueCveIds).length;
                                var fl = [];
                                for (var c in L.findingsById) {
                                    if (Object.prototype.hasOwnProperty.call(L.findingsById, c)) { fl.push(obj.summarizeDeviceSwVer(L.findingsById[c])); }
                                }
                                fl.sort(function (a, b) { return (Number(b.cvss) || 0) - (Number(a.cvss) || 0) || String(a.cve).localeCompare(String(b.cve)); });
                                L.findings = fl;
                                delete L.findingsById;
                                L.devices.sort(function (a, b) { return String(a.hostName).localeCompare(String(b.hostName)); });
                                var lDenom = L.assessablePrograms + L.notAssessablePrograms; // drivers/firmware excluded
                                L.coverageBase = lDenom;
                                L.coveragePercent = lDenom > 0 ? Math.round((L.assessablePrograms / lDenom) * 100) : 0;
                                report.locations.push(L);
                            }
                            report.locations.sort(function (a, b) { return String(a.name).localeCompare(String(b.name)); });
                            report.locationCount = report.locations.length;
                            report.devices.sort(function (a, b) { return (b.cveCount - a.cveCount) || String(a.hostName).localeCompare(String(b.hostName)); });
                            report.uniqueCves = Object.keys(report.uniqueCveIds).length;
                            var rDenom = report.assessablePrograms + report.notAssessablePrograms; // drivers/firmware excluded
                            report.coverageBase = rDenom;
                            report.coveragePercent = rDenom > 0 ? Math.round((report.assessablePrograms / rDenom) * 100) : 0;
                            if (callback) callback(null, report);
                        }
                    });
                });
            });
        });
    };

    /**
     * @brief Render the printable HTML vulnerability report for all clients.
     * @param {object} req - The Express request.
     * @param {object} res - The Express response.
     * @param {object} user - The authenticated user.
     */
    obj.vulnerabilityReport = function (req, res, user) {
        obj.buildOverallReport(function (err, report) {
            if (err || !report) { res.sendStatus(500); return; }
            res.render('report', {
                shortName: obj.shortName,
                report: report,
                totalCves: obj.allCves.length,
                lastUpdate: obj.lastUpdate || ''
            });
        });
    };

    /**
     * @brief Render the printable HTML device inventory report for all clients.
     * @param {object} req - The Express request.
     * @param {object} res - The Express response.
     * @param {object} user - The authenticated user.
     */
    obj.deviceReport = function (req, res, user) {
        obj.buildOverallReport(function (err, report) {
            if (err || !report) { res.sendStatus(500); return; }
            res.render('deviceReport', {
                shortName: obj.shortName,
                report: report,
                totalCves: obj.allCves.length,
                lastUpdate: obj.lastUpdate || ''
            });
        });
    };
};
