# Security Policy


## Security Scanning Tools

### 1. SAST (Static Application Security Testing) with CodeQL

**Purpose**: Analyzes source code for security vulnerabilities without executing the application.

**Tool**: [GitHub CodeQL](https://codeql.github.com/)

**What it Scans**:
- Code injection vulnerabilities (SQL injection, XSS, command injection)
- Hardcoded secrets and credentials
- Insecure coding patterns
- Data flow vulnerabilities
- OWASP Top 10 issues
- Python-specific security anti-patterns

**When it Runs**:
- On every push to `main` branch
- On pull requests to `main` branch
- Uses `security-extended` query suite for comprehensive coverage

**Where to Find Results**:
- **GitHub Security Tab** → Code scanning alerts
- Results automatically categorized by severity (Critical, High, Medium, Low)
- Provides line-level code references and remediation guidance

**Workflow File**: [`.github/workflows/1-sast-only.yml`](.github/workflows/1-sast-only.yml)

**Expected Runtime**: 2-5 minutes

---

### 2. SCA (Software Composition Analysis) with OWASP Dependency-Check

**Purpose**: Scans project dependencies for known security vulnerabilities (CVEs).

**Tool**: [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)

**What it Scans**:
- Python packages in `requirements.txt`
- Known CVEs in dependencies
- Outdated libraries with security patches
- Transitive dependencies (dependencies of dependencies)
- License compliance issues

**When it Runs**:
- On every push to `main` branch
- On pull requests to `main` branch
- After SAST completes successfully

**Severity Threshold**:
- Fails build on CVSS score ≥ 7.0 (HIGH severity or above)
- Configure via `--failOnCVSS` parameter in workflow

**Where to Find Results**:
- **GitHub Actions** → Artifacts → `sca-reports`
- Download reports in multiple formats:
  - `dependency-check-report.html` - Detailed web view
  - `dependency-check-report.json` - Machine-readable
  - `dependency-check-report.xml` - CI/CD integration
  - `dependency-check-report.sarif` - GitHub Security tab upload

**Workflow File**: [`.github/workflows/2-sca-only.yml`](.github/workflows/2-sca-only.yml)

**Expected Runtime**: 3-5 minutes (first run ~15 minutes for NVD database download)

**Known Issue**: Current scan may not detect Python dependencies properly. See [SCAN_ANALYSIS.md](../SCAN_ANALYSIS.md) for details and alternative tools.

---

### 3. DAST (Dynamic Application Security Testing) with OWASP ZAP

**Purpose**: Tests the running application by simulating real-world attacks.

**Tool**: [OWASP ZAP (Zed Attack Proxy)](https://www.zaproxy.org/)

**What it Scans**:
- SQL injection attempts
- Cross-site scripting (XSS) vulnerabilities
- Security misconfigurations
- Missing HTTP security headers
- SSL/TLS configuration
- Authentication and session management issues
- CSRF vulnerabilities

**Scan Types**:

1. **Baseline Scan** (`zaproxy/action-baseline@v0.14.0`)
   - Passive scan only (no active attacks)
   - Safe for production
   - Runtime: 5-10 minutes
   - Detects: Missing headers, information disclosure

2. **Full Scan** (`zaproxy/action-full-scan@v0.12.0`)
   - Active penetration testing
   - **Use only on test environments**
   - Runtime: 15-30 minutes
   - Detects: Injection flaws, authentication bypass, business logic errors

**When it Runs**:
- On every push to `main` branch
- On pull requests to `main` branch
- After successful application build
- Tests against `http://localhost:5000`

**Where to Find Results**:
- **GitHub Actions** → Artifacts
  - `zap-baseline-reports` - Passive scan results
  - `zap-fullscan-reports` - Active scan results
- Report formats:
  - `report_html.html` - Detailed findings with remediation steps
  - `report_json.json` - Machine-readable format
  - `report_md.md` - Markdown summary

**Workflow Files**:
- [`.github/workflows/3-dast-only.yml`](.github/workflows/3-dast-only.yml)
- [`.github/workflows/4-complete-security.yml`](.github/workflows/4-complete-security.yml)

**Expected Runtime**:
- Baseline: 5-10 minutes
- Full scan: 15-30 minutes

---

## Complete Security Pipeline

### Workflow Execution Order

```
┌─────────────────────────────────────────────────────┐
│  1. SAST (CodeQL)                                   │
│     ↓ Analyzes source code                         │
│     ↓ 2-5 minutes                                   │
├─────────────────────────────────────────────────────┤
│  2. SCA (Dependency-Check)                          │
│     ↓ Scans dependencies                            │
│     ↓ 3-5 minutes                                   │
├─────────────────────────────────────────────────────┤
│  3. Build                                           │
│     ↓ Verifies application builds successfully     │
│     ↓ 1-2 minutes                                   │
├─────────────────────────────────────────────────────┤
│  4. DAST (OWASP ZAP)                                │
│     ↓ Tests running application                     │
│     ↓ 15-30 minutes                                 │
├─────────────────────────────────────────────────────┤
│  5. Summary Report                                  │
│     → Generates consolidated findings              │
└─────────────────────────────────────────────────────┘
```

**Total Pipeline Runtime**: 25-45 minutes

**Workflow File**: [`.github/workflows/4-complete-security.yml`](.github/workflows/4-complete-security.yml)

---

## Understanding Security Scan Results

### Severity Levels

Our scans use CVSS (Common Vulnerability Scoring System) to classify findings:

| Severity | CVSS Score | Action Required | Example |
|:---------|:-----------|:----------------|:--------|
| 🔴 **Critical** | 9.0-10.0 | Fix immediately (within 24 hours) | Remote code execution, SQL injection with data access |
| 🟠 **High** | 7.0-8.9 | Fix within days | Authentication bypass, sensitive data exposure |
| 🟡 **Medium** | 4.0-6.9 | Fix within weeks | Missing security headers, information disclosure |
| 🟢 **Low** | 0.1-3.9 | Monitor, fix when possible | Minor configuration issues, low-impact leaks |
| ℹ️ **Informational** | 0.0 | No action required | Best practice recommendations |

### Reading DAST Results

**ZAP Result Codes**:
- **PASS**: Security check passed ✅
- **WARN-NEW**: New warning found, review required ⚠️
- **WARN-INPROG**: Existing warning, already tracked 📋
- **FAIL-NEW**: Critical issue found, fix immediately 🚨
- **FAIL-INPROG**: Existing critical issue, still needs fixing 🔴
- **INFO**: Informational finding, low priority ℹ️

**Common DAST Alert IDs**:

| Alert ID | Finding | Severity | Impact |
|:---------|:--------|:---------|:-------|
| 10020 | Missing X-Frame-Options | Medium | Clickjacking possible |
| 10021 | X-Content-Type-Options missing | Low | MIME-sniffing attacks |
| 10035 | Missing HSTS header | Medium | HTTPS downgrade attacks |
| 10038 | Content Security Policy missing | Medium | XSS attacks possible |
| 10036 | Server version disclosure | Low | Information leakage |
| 10063 | Permissions Policy missing | Low | Unauthorized feature access |
| 10106 | HTTP-only site | Medium | Man-in-the-middle attacks |
| 90004 | Spectre vulnerability | Low | Side-channel attacks |

**Detailed Explanations**: See [ZAP_FINDINGS_INTERPRETATION.md](../ZAP_FINDINGS_INTERPRETATION.md)

---

## Accessing Scan Results

### 1. GitHub Security Tab

**Location**: Repository → Security → Code scanning alerts

**What You'll Find**:
- Centralized vulnerability dashboard
- All SAST and SCA findings (if SARIF uploaded)
- Filter by severity, tool, status
- Direct links to affected code
- Remediation suggestions

**How to Use**:
1. Click on any alert for detailed information
2. Review affected code and data flow
3. Click "Show paths" to see vulnerability chains
4. Assign to team member or create issue
5. Mark as "Dismissed" with reason if false positive

### 2. GitHub Actions Artifacts

**Location**: Repository → Actions → [Workflow Run] → Artifacts section (bottom)

**Available Downloads**:
- `sca-reports` - OWASP Dependency-Check results
- `zap-baseline-reports` - ZAP passive scan
- `zap-fullscan-reports` - ZAP active scan

**Retention**: Artifacts retained for 90 days (configurable)

### 3. Workflow Run Logs

**Location**: Repository → Actions → [Workflow Run] → Click job name

**What You'll Find**:
- Real-time scan progress
- Detailed step-by-step logs
- Error messages and warnings
- Scan statistics and summaries

---

## Response Procedures

### When a Vulnerability is Found

#### Critical/High Severity (CVSS ≥ 7.0)

1. **Immediate Response** (Within 24 hours)
   - Notify security team and development lead
   - Assess exploitability and impact
   - Create hotfix branch if production affected

2. **Remediation**
   - Implement fix according to scanner guidance
   - Update dependencies if SCA finding
   - Add security headers if DAST finding
   - Refactor code if SAST finding

3. **Verification**
   - Re-run affected scanner
   - Verify fix resolves issue
   - Check for regression in other areas

4. **Documentation**
   - Update changelog
   - Document fix in commit message
   - Add test case to prevent recurrence

#### Medium Severity (CVSS 4.0-6.9)

1. **Response Timeline**: Within 1-2 weeks
2. **Prioritization**: Include in next sprint
3. **Review**: Assess impact on current deployment
4. **Fix**: Implement during normal development cycle

#### Low/Informational (CVSS < 4.0)

1. **Response Timeline**: Monitor, fix opportunistically
2. **Backlog**: Add to technical debt backlog
3. **Review**: Quarterly security review

---

## False Positive Handling

### Dismissing Alerts

**When to Dismiss**:
- Code pattern is actually safe in this context
- Finding is not applicable to deployment environment
- Risk is mitigated by other controls

**How to Dismiss**:
1. Go to Security → Code scanning alerts
2. Click on the alert
3. Click "Dismiss alert"
4. Select reason:
   - False positive
   - Won't fix
   - Used in tests
5. Add justification comment (required)

**Documentation**: All dismissals should be documented in monthly security review

---

## Reporting Security Vulnerabilities

### For External Researchers

If you discover a security vulnerability in this project:

**DO**:
- Email: [security@example.com](mailto:security@example.com)
- Include detailed steps to reproduce
- Provide proof of concept (non-destructive)
- Allow 90 days for fix before public disclosure

**DO NOT**:
- Open public GitHub issues for security bugs
- Exploit vulnerabilities beyond proof of concept
- Access or modify user data
- Perform destructive testing (DoS, data deletion)

**Response Timeline**:
- Acknowledgment: Within 48 hours
- Initial assessment: Within 5 business days
- Fix timeline: Provided after assessment
- Public disclosure: After fix deployed + 90 days

### For Internal Team

**Reporting Channel**:
1. Create private security advisory via GitHub
2. Notify `@security-team` in Slack
3. For critical issues, escalate to security lead immediately

**Template**:
```markdown
## Vulnerability Report

**Severity**: [Critical/High/Medium/Low]
**Component**: [Affected file/package]
**Scanner**: [CodeQL/Dependency-Check/ZAP/Manual]

**Description**:
[Clear description of the vulnerability]

**Steps to Reproduce**:
1. [Step 1]
2. [Step 2]
3. [Step 3]

**Impact**:
[What attacker could achieve]

**Proposed Fix**:
[Suggested remediation]

**References**:
- CVE ID (if applicable)
- Related issues
- Documentation links
```

---

## Security Best Practices

### For Developers

**Code Contributions**:
- ✅ Run local SAST checks before committing
- ✅ Keep dependencies up to date
- ✅ Review security scan results in PR checks
- ✅ Never commit secrets or credentials
- ✅ Use environment variables for configuration
- ✅ Implement input validation and output encoding
- ✅ Follow secure coding guidelines

**Pull Request Requirements**:
- ✅ All security scans must pass (GREEN status)
- ✅ No new HIGH or CRITICAL findings introduced
- ✅ Security implications documented if applicable
- ❌ Cannot merge with failing security checks

### For Maintainers

**Regular Tasks**:
- 📅 Weekly: Review new security alerts
- 📅 Monthly: Dependency update review
- 📅 Quarterly: Full security audit
- 📅 Annually: Penetration testing (external)

**Maintenance**:
- Keep GitHub Actions up to date
- Update scanner versions quarterly
- Review and tune false positive rates
- Maintain security documentation

---

## Known Limitations

### Current Security Posture

**Intentional Vulnerabilities** (Educational Project):
- ⚠️ Using outdated Flask 2.0.1 (has known CVEs)
- ⚠️ Using outdated Werkzeug 2.0.1 (has known CVEs)
- ⚠️ Debug mode enabled in code (information disclosure)
- ⚠️ Missing security headers (clickjacking, XSS)
- ⚠️ HTTP-only (no HTTPS)

**Production Deployment Checklist**:
```bash
# Before deploying to production:
□ Update Flask to latest (3.0.3+)
□ Update Werkzeug to latest (3.0.3+)
□ Set debug=False
□ Implement HTTPS with valid certificate
□ Add security headers (see ZAP_FINDINGS_INTERPRETATION.md)
□ Configure CORS appropriately
□ Implement rate limiting
□ Add authentication if needed
□ Set up monitoring and logging
□ Review and apply all security scan findings
```

### Scanner Limitations

**OWASP Dependency-Check**:
- Current configuration may not detect Python dependencies
- See [SCAN_ANALYSIS.md](../SCAN_ANALYSIS.md) for details
- Consider supplementing with `pip-audit` or `safety`

**OWASP ZAP**:
- May produce false positives on custom implementations
- Cannot test business logic thoroughly
- Consider manual penetration testing for critical applications

**CodeQL**:
- May miss complex business logic vulnerabilities
- Focuses on common vulnerability patterns
- Supplement with code review for critical code

---

## Additional Resources

### Documentation
- [Complete Tutorial](../readme.md) - Step-by-step setup guide
- [Scan Analysis](../SCAN_ANALYSIS.md) - Detailed scan results
- [ZAP Findings](../ZAP_FINDINGS_INTERPRETATION.md) - DAST alert explanations
- [Scanner Comparison](../SCANNER_COMPARISON.md) - Tool comparison analysis
- [Troubleshooting Guide](../readme.md#part-11-troubleshooting) - Common issues and solutions

### External Resources

**Tools**:
- [GitHub CodeQL Documentation](https://codeql.github.com/docs/)
- [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)
- [OWASP ZAP User Guide](https://www.zaproxy.org/docs/)
- [GitHub Security Features](https://docs.github.com/en/code-security)

**Learning**:
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [GitHub Security Lab](https://securitylab.github.com/)
- [CVSS Calculator](https://www.first.org/cvss/calculator/3.1)

**CVE Databases**:
- [National Vulnerability Database](https://nvd.nist.gov/)
- [CVE Details](https://www.cvedetails.com/)
- [GitHub Advisory Database](https://github.com/advisories)

---

## Contact

**Security Team**: security@example.com
**Project Maintainer**: [Your Name]
**Security Lead**: [Security Lead Name]

**Response Times**:
- Critical vulnerabilities: 24 hours
- High vulnerabilities: 5 business days
- Medium vulnerabilities: 2 weeks
- Low/Info: Best effort

---

## Changelog

### Version History

**2025-12-05** - Initial security policy
- Implemented SAST with CodeQL
- Implemented SCA with OWASP Dependency-Check
- Implemented DAST with OWASP ZAP
- Created complete security scanning pipeline
- Documented all procedures and findings

---

**Last Updated**: December 5, 2025
**Policy Version**: 1.0
**Next Review**: March 5, 2026
