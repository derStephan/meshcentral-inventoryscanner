# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

Please report security vulnerabilities by opening a private GitHub Security Advisory:

1. Go to the **Security** tab of this repository
2. Click **Report a vulnerability**
3. Fill in the details

We will acknowledge receipt within 48 hours and provide a timeline for fixes.

---

## Security Architecture

This plugin is designed with the following security principles:

### Access Control
- **All endpoints require full site admin** (`user.siteadmin === 0xFFFFFFFF`)
- No viewer/read-only roles exist - plugin is admin-only by design
- MeshCentral's built-in node rights validation used for device selections

### Data Protection
- **No inventory data leaves the server** - only public NVD feeds are downloaded
- NVD CPE dictionary API queries only individual product tokens (cached, deduplicated)
- Ratings, comments, CPE mappings stored locally under `<datapath>/plugins/inventoryscanner/` and `<datapath>/nvd/`

### Input Validation
- **CVE ID format enforced**: `CVE-\d{4}-\d{4,}` or `WINDOWS-UPDATES`
- **Mesh ID format enforced**: `^mesh\/[^:]+$` (prevents key poisoning in `assessments.json`)
- **Severity values whitelisted**: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
- **Numeric ranges validated** on all settings (interval hours 0-87600, etc.)
- **Comment length limited** to 1000 characters (stored raw, escaped at render)

### Output Hardening
- **CSV formula injection neutralized** (CWE-1236): values starting with `= + - @ tab CR` prefixed with `'`
- **HTML escaping**: Handlebars `{{...}}` used exclusively (no `{{{...}}}`)
- **UTF-8 BOM** included in CSV downloads for Excel compatibility

### Secure Defaults
- Scheduled scans: **enabled** (24h interval)
- Notifications: **enabled** (HIGH threshold)
- Inventory collection: **enabled** (daily, on agent connect)
- NVD feed updates: **weekly** (168h)
- Ancient "any-version" CVE suppression: **5 years**

---

## Audit History

| Date | Auditor | Model | Scope | Findings |
|------|---------|-------|-------|----------|
| 2026-11-06 | AI (opencode) | NVIDIA Nemotron 3 550B A55B | Full formal & functional verification | 1 bug fixed, ~466 lines dead code removed, all tests pass |

See [AUDIT.md](AUDIT.md) for detailed audit report.

---

## Transparency Note

This plugin was originally created with the assistance of **Qwen 3.6 27B** and **Qwen 3.8 Flash Next** (AI coding assistants). The 2026-11-06 security audit was performed by **NVIDIA Nemotron 3 550B A55B** via the opencode agent.