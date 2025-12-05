# Security Scan Analysis - December 5, 2025

## DAST Results (OWASP ZAP Full Scan)

### Scan Overview
- **Total URLs scanned**: 5
- **Scan target**: http://localhost:5000
- **URLs tested**:
  - http://localhost:5000
  - http://localhost:5000/
  - http://localhost:5000/favicon.ico
  - http://localhost:5000/robots.txt
  - http://localhost:5000/sitemap.xml

### Results Summary

| Result Type | Count |
|------------|-------|
| **High severity** | 0 |
| **Medium severity** | 3 |
| **Low severity** | 4 |
| **Informational** | 6 |
| **Total findings** | 13 |

### Detailed Findings Breakdown

#### Medium Severity Issues (3)

1. **Content Security Policy (CSP) Header Not Set** - Alert ID: 10038
   - **Risk Level**: Medium
   - **Instances**: 5
   - **CWE ID**: 693
   - **Impact**: Vulnerable to XSS and data injection attacks
   - **Affected URLs**: All scanned endpoints
   - **Solution**: Configure web server to set Content-Security-Policy header

2. **HTTP Only Site** - Alert ID: 10106
   - **Risk Level**: Medium
   - **Instances**: 1
   - **CWE ID**: 311
   - **Impact**: Traffic not encrypted, vulnerable to man-in-the-middle attacks
   - **Affected URL**: http://localhost:5000
   - **Solution**: Configure SSL/TLS (HTTPS) for the application

3. **Missing Anti-clickjacking Header** - Alert ID: 10020
   - **Risk Level**: Medium
   - **Instances**: 2
   - **CWE ID**: 1021
   - **Impact**: Vulnerable to clickjacking attacks
   - **Affected URLs**: http://localhost:5000, http://localhost:5000/
   - **Solution**: Add X-Frame-Options or Content-Security-Policy with frame-ancestors directive

#### Low Severity Issues (4)

1. **Insufficient Site Isolation Against Spectre Vulnerability** - Alert ID: 90004
   - **Risk Level**: Low
   - **Instances**: 6
   - **CWE ID**: 693
   - **Impact**: Side-channel attack vulnerability
   - **Solution**: Set Cross-Origin-Resource-Policy headers appropriately

2. **Permissions Policy Header Not Set** - Alert ID: 10063
   - **Risk Level**: Low
   - **Instances**: 5
   - **CWE ID**: 693
   - **Impact**: Unauthorized access to browser features possible
   - **Solution**: Configure Permissions-Policy header

3. **Server Leaks Version Information** - Alert ID: 10036
   - **Risk Level**: Low
   - **Instances**: 5
   - **CWE ID**: 497
   - **Evidence**: `Werkzeug/2.0.1 Python/3.9.25`
   - **Impact**: Information disclosure aids attackers
   - **Solution**: Configure server to suppress or genericize Server header

4. **X-Content-Type-Options Header Missing** - Alert ID: 10021
   - **Risk Level**: Low
   - **Instances**: 2
   - **CWE ID**: 693
   - **Impact**: MIME-sniffing attacks possible
   - **Solution**: Set X-Content-Type-Options header to 'nosniff'

#### Informational Findings (6)

1. **Modern Web Application** - Alert ID: 10109
   - Instances: 2
   - Note: Detected JavaScript-based application using async/await and fetch API

2. **Sec-Fetch-Dest Header is Missing** - Alert ID: 90005
   - Instances: 3

3. **Sec-Fetch-Mode Header is Missing** - Alert ID: 90005
   - Instances: 3

4. **Sec-Fetch-Site Header is Missing** - Alert ID: 90005
   - Instances: 3

5. **Sec-Fetch-User Header is Missing** - Alert ID: 90005
   - Instances: 3

6. **Storable and Cacheable Content** - Alert ID: 10049
   - Instances: 5
   - CWE ID: 524
   - Note: Content may be cached, review if sensitive data is involved

---

## SCA Results (OWASP Dependency-Check)

### Scan Overview
- **Project name**: calculator-app
- **Scan date**: 2025-12-05T02:15:52Z
- **Tool version**: dependency-check 12.1.9

### Results Summary

| Severity Level | Count |
|---------------|-------|
| **Critical** | 0 |
| **High** | 0 |
| **Medium** | 0 |
| **Low** | 0 |
| **Total vulnerabilities** | 0 |

### Analysis Notes

**Important Finding**: The OWASP Dependency-Check scan reported **0 dependencies scanned** and **0 vulnerabilities found**.

**Root Cause Analysis**:
- The application uses `flask==2.0.1` and `werkzeug==2.0.1` (intentionally outdated versions)
- OWASP Dependency-Check may have failed to detect Python dependencies properly
- Possible reasons:
  1. Dependencies were not installed in the scanning environment
  2. The tool scanned before `pip install` was executed
  3. Dependency-Check's Python analyzer may need additional configuration

**Expected Findings** (based on known CVEs for these versions):
- Flask 2.0.1 has known vulnerabilities (CVE-2023-30861, CVE-2024-38528)
- Werkzeug 2.0.1 has known vulnerabilities (CVE-2023-25577, CVE-2024-34069)
- Both libraries have critical and high severity CVEs

**Recommendation**:
- Review the SCA workflow configuration in `.github/workflows/2-sca-only.yml`
- Ensure dependencies are installed before scanning
- Consider using additional SCA tools like:
  - `pip-audit` (Python-specific)
  - `safety` (Python-specific)
  - Snyk
  - GitHub Dependabot

---

## SAST Results (CodeQL)

### Scan Overview
- **Tool**: GitHub CodeQL
- **Language**: Python
- **Query suite**: security-extended

### Results Summary

**Note**: CodeQL results are typically found in the GitHub Security tab. Based on the simple calculator application code:

**Expected Findings**:
- The calculator application has relatively clean code
- No obvious code injection vulnerabilities
- Proper input validation for division by zero
- Uses Flask's built-in JSON parsing (safe from injection)

**Potential CodeQL Alerts**:
- **Debug mode enabled** in production (`debug=True` in app.py line 199)
  - Severity: Medium
  - Impact: Information disclosure, potential code execution
  - Solution: Set `debug=False` for production deployment

---

## Severity Analysis

### Overall Risk Profile

| Severity | SAST | SCA | DAST | Total |
|----------|------|-----|------|-------|
| Critical | 0 | 0 | 0 | 0 |
| High | 0 | 0 | 0 | 0 |
| Medium | 1* | 0** | 3 | 4 |
| Low | 0 | 0 | 4 | 4 |
| Info | 0 | 0 | 6 | 6 |

\* Debug mode enabled (if detected by CodeQL)
\*\* Expected vulnerabilities not detected due to scanning issue

### Risk Distribution

```
Medium (4):  ████████████░░░░░░░░ 30.8%
Low (4):     ████████████░░░░░░░░ 30.8%
Info (6):    ████████████████████ 38.4%
```

---

## Recommendations

### Priority 1 - Immediate Action Required (Medium Severity)

1. **Add Security Headers** (DAST findings)
   - Implement Content-Security-Policy
   - Add X-Frame-Options: DENY or SAMEORIGIN
   - Set X-Content-Type-Options: nosniff

   **Implementation** (add to app.py):
   ```python
   @app.after_request
   def set_security_headers(response):
       response.headers['Content-Security-Policy'] = "default-src 'self'"
       response.headers['X-Frame-Options'] = 'DENY'
       response.headers['X-Content-Type-Options'] = 'nosniff'
       response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
       return response
   ```

2. **Enable HTTPS** (DAST finding)
   - For production: Configure SSL/TLS certificate
   - For development: Use Flask-Talisman or similar middleware

3. **Disable Debug Mode** (SAST finding)
   - Change `debug=True` to `debug=False` in production
   - Use environment variables to control debug mode

4. **Fix SCA Scanning** (SCA issue)
   - Review workflow to ensure dependencies are installed before scanning
   - Consider alternative Python-specific tools

### Priority 2 - Medium Term (Low Severity)

1. **Suppress Server Version Information**
   - Configure Flask to not expose Werkzeug version
   - Add custom Server header

2. **Implement Cross-Origin Policies**
   - Set Cross-Origin-Resource-Policy header
   - Configure CORS appropriately

3. **Add Cache-Control Headers**
   - Review caching requirements
   - Set appropriate Cache-Control directives

### Priority 3 - Long Term (Informational)

1. **Review Sec-Fetch Headers**
   - These are browser-set headers, low priority for server-side fixes

2. **Monitor for Future Vulnerabilities**
   - Set up automated dependency updates
   - Subscribe to security advisories

---

## Testing Evidence

### DAST Test Coverage

**Endpoints Tested**:
- ✅ Root endpoint (/)
- ✅ Calculator interface
- ✅ Standard web files (favicon.ico, robots.txt, sitemap.xml)

**Attack Types Performed**:
- Passive baseline scan (no active attacks)
- Full scan with active testing
- Header analysis
- Security misconfiguration detection

### Scan Artifacts Location

- **SCA Reports**: `extracted-reports/sca/`
  - dependency-check-report.html
  - dependency-check-report.json
  - dependency-check-report.xml

- **DAST Reports**:
  - Baseline: `extracted-reports/zap-baseline/report_html.html`
  - Full scan: `extracted-reports/zap-fullscan/report_md.md`

---

## Conclusion

### Key Findings

1. **DAST scans were successful** and identified 13 findings (3 medium, 4 low, 6 info)
2. **SCA scanning failed** to detect dependencies (0 vulnerabilities found vs expected multiple critical/high CVEs)
3. **SAST scanning** likely identified debug mode as a concern
4. **No critical vulnerabilities** were found in running application testing

### Security Posture

**Current Status**: 🟡 **MODERATE RISK**

The application has several medium-severity security misconfigurations primarily related to missing HTTP security headers. However, no critical vulnerabilities requiring immediate patching were detected in the DAST scan.

**Main Concerns**:
1. Missing security headers (CSP, X-Frame-Options)
2. HTTP-only deployment (no HTTPS)
3. SCA tool not detecting vulnerable dependencies
4. Debug mode potentially enabled in production

### Next Steps

1. ✅ Complete remaining exercises (3, 4, 5)
2. ⚠️ Fix SCA scanning workflow
3. ⚠️ Implement security headers
4. ⚠️ Disable debug mode for production
5. ⚠️ Plan HTTPS implementation
6. ⚠️ Update dependencies to latest versions (after fixing SCA scanning)

---

**Report Generated**: December 5, 2025
**Analyzed By**: DevOps Security Team
**Review Cycle**: Initial Assessment
