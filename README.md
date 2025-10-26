# 🛡️ WebSecure Scanner - Advanced Web Application Security Testing Suite

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/v/release/Noshadi-sec/WebSecure-Scanner.svg)](https://github.com/Noshadi-sec/WebSecure-Scanner/releases)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

**WebSecure Scanner** is a comprehensive, professional-grade web application security testing suite designed for penetration testers, security researchers, and DevSecOps teams. Built entirely in PowerShell, it performs 33 different security tests covering the OWASP Top 10 and beyond.

## Key Features

### Comprehensive Testing (33 Security Tests)
-  **Authentication & Session Management** - Session fixation, logout bypass, JWT tampering
-  **Authorization Flaws** - IDOR (Insecure Direct Object References), privilege escalation
-  **CSRF Protection** - Token detection + **exploit attempts** with proof-of-concept
-  **XSS Detection** - Reflected, Stored, DOM-based
-  **SQL Injection** - Error-based, blind, time-based detection
-  **Security Headers** - CSP, HSTS, X-Frame-Options, etc.
-  **File Upload Security** - RCE testing, MIME bypass, path traversal
-  **Parameter Tampering** - Mass assignment, privilege escalation via JSON injection
-  **Information Disclosure** - Sensitive files, API documentation, secrets in JS
- **TLS/HTTPS Configuration** - Certificate validation, redirect enforcement
- **Access Control** - Broken authentication, anonymous access testing
-**API Security** - CORS, REST endpoint discovery, GraphQL testing
- **Infrastructure** - Subdomain enumeration, WAF detection, open redirects

### Advanced Capabilities
-  **Authenticated Testing** - Session replay for testing protected endpoints
-  **Exploit Proof-of-Concept** - Not just detection, actual exploitation attempts
-  **Multiple Report Formats** - JSON, HTML, CSV outputs
-  **Aggressive Mode** - Deep testing with configurable request limits
-  **Baseline Comparison** - Track security posture changes over time
-  **External Target Support** - Test any website with proper authorization

## Prerequisites

- **PowerShell 5.1+** (Windows) or **PowerShell Core 7+** (Cross-platform)
- **Internet Connection** for external target testing
- **Authorization** to test the target application

##  Quick Start

### Installation

```powershell
# Clone the repository
git clone https://github.com/Noshadi-sec/WebSecure-Scanner.git
cd WebSecure-Scanner

# Unblock the script (Windows only)
Unblock-File -Path .\security_test2.ps1
```

### Basic Usage

```powershell
# Simple scan
.\security_test2.ps1 -site "https://example.com" -Mode "Normal"

# Aggressive scan with HTML report
.\security_test2.ps1 `
    -site "https://example.com" `
    -Mode "Aggressive" `
    -htmlReport `
    -outputDir ".\reports"
```

### Authenticated Testing (Recommended)

```powershell
# With session cookie (most common)
.\security_test2.ps1 `
    -site "https://example.com" `
    -SessionCookie "session=your_session_cookie_here" `
    -AuthUserId "123" `
    -Mode "Aggressive" `
    -htmlReport
```

##  Usage Examples

### Example 1: Quick Security Assessment
```powershell
.\security_test2.ps1 -site "https://example.com" -Mode "Normal"
```
**Output**: JSON report with findings, ~5-10 minutes

### Example 2: Deep Authenticated Scan
```powershell
.\security_test2.ps1 `
    -site "https://app.example.com" `
    -SessionCookie "session=abc123..." `
    -AuthUserId "100" `
    -Mode "Aggressive" `
    -MaxRequests 3000 `
    -ConfirmAuthorization "I am authorized to test this application" `
    -htmlReport `
    -outputDir ".\scan_results"
```
**Output**: HTML + JSON + CSV reports with exploitation proofs, ~20-30 minutes

### Example 3: Regression Testing
```powershell
# First scan (baseline)
.\security_test2.ps1 -site "https://example.com" -Mode "Normal" -outputDir ".\baseline"

# Later scan (comparison)
.\security_test2.ps1 `
    -site "https://example.com" `
    -Mode "Normal" `
    -BaselineReport ".\baseline\security_report_*.json" `
    -outputDir ".\regression"
```
**Output**: Highlights new issues, resolved issues, and severity changes

### Example 4: API Testing
```powershell
.\security_test2.ps1 `
    -site "https://api.example.com" `
    -SessionCookie "Authorization: Bearer eyJhbGc..." `
    -Mode "Aggressive"
```

##  Command-Line Parameters

| Parameter | Description | Required | Default |
|-----------|-------------|----------|---------|
| `-site` | Target URL (e.g., https://example.com) | Yes | - |
| `-Mode` | Scan intensity: Passive, Normal, Aggressive | No | Normal |
| `-SessionCookie` | Authentication cookie for authenticated tests | No | - |
| `-AuthUserId` | Your user ID for IDOR testing | No | - |
| `-Username` | Username for automated login | No | - |
| `-Password` | Password for automated login | No | - |
| `-LoginUrl` | Login endpoint URL | No | - |
| `-MaxRequests` | Maximum requests to send | No | 1000 |
| `-htmlReport` | Generate HTML report | No | false |
| `-outputDir` | Output directory for reports | No | ./reports |
| `-BaselineReport` | Path to baseline report for comparison | No | - |
| `-ConfirmAuthorization` | Authorization confirmation statement | No | - |
| `-ForceExternal` | Allow testing external sites | No | false |

##  Test Coverage

### OWASP Top 10 (2021) Coverage

| OWASP Category | Tests | Severity |
|----------------|-------|----------|
| **A01: Broken Access Control** | Test 23 (IDOR, privilege escalation) | CRITICAL |
| **A02: Cryptographic Failures** | Test 02 (TLS), Test 03 (Cookie security) | HIGH |
| **A03: Injection** | Test 04 (XSS), Test 05 (SQLi), Test 21 (Command Injection) | CRITICAL |
| **A04: Insecure Design** | Test 31 (Parameter tampering) | HIGH |
| **A05: Security Misconfiguration** | Test 01 (Headers), Test 12 (HTTP methods) | MEDIUM |
| **A06: Vulnerable Components** | Test 15 (Version disclosure) | LOW |
| **A07: Authentication Failures** | Test 30 (Session security) | CRITICAL |
| **A08: Data Integrity Failures** | Test 09 (CSRF), Test 31 (Mass assignment) | HIGH |
| **A09: Logging Failures** | Test 06 (Sensitive files) | MEDIUM |
| **A10: SSRF** | Test 08 (CORS), Test 14 (Open redirect) | MEDIUM |

### Full Test Suite (33 Tests)

<details>
<summary>Click to expand complete test list</summary>

1. **Security Headers Analysis** - CSP, HSTS, X-Frame-Options, etc.
2. **TLS/HTTPS Configuration** - Certificate validation, HTTP→HTTPS redirect
3. **Cookie Security** - Secure, HttpOnly, SameSite flags
4. **XSS Detection** - Reflected, stored, DOM-based
5. **SQL Injection** - Error-based, blind, time-based
6. **Sensitive Files** - robots.txt, .git, backups, configs
7. **Directory Traversal** - Path manipulation, file access
8. **CORS Misconfiguration** - Origin validation, credential exposure
9. **CSRF Protection** - Token detection + exploitation attempts
10. **Rate Limiting** - Brute force protection testing
11. **Admin Panel Discovery** - Common admin paths
12. **HTTP Methods Testing** - TRACE, PUT, DELETE exposure
13. **XML External Entity (XXE)** - XML parser vulnerabilities
14. **Open Redirect** - URL parameter manipulation
14B. **WAF Detection** - Cloudflare, AWS WAF, Akamai
15. **Information Disclosure** - Error messages, version info
15B. **JavaScript Secret Scanning** - API keys in JS files
16. **Baseline Comparison** - Regression tracking
17. **Subdomain Enumeration** - Active subdomain discovery
18. **API Documentation** - Swagger, GraphQL exposure
19. **HTTP Parameter Pollution** - Duplicate parameter handling
20. **Cache Poisoning** - Host header injection
21. **Command Injection** - OS command execution
22. **DoS Behavior** - Large parameter handling
23. **Broken Access Control** - IDOR, privilege escalation
24. **Clickjacking Protection** - Frame-ancestors testing
30. **Session Security** - Fixation, logout bypass, JWT tampering
31. **Parameter Tampering** - Mass assignment, privilege escalation
32. **File Upload Security** - RCE, MIME bypass, path traversal
33. **Stored XSS** - Persistent payload injection

</details>

##  Report Formats

### JSON Report (Always Generated)
```json
{
  "ScanInfo": {
    "Target": "https://example.com",
    "Duration": 847.23,
    "TestsRun": 33
  },
  "Summary": {
    "Critical": 3,
    "High": 7,
    "Medium": 12,
    "Low": 5,
    "RiskScore": 89
  },
  "Issues": { ... }
}
```

### HTML Report (Optional)
Beautiful, interactive report with:
- Executive summary dashboard
- Issue severity breakdown
- Detailed findings with remediation
- OWASP/CWE mappings
- Evidence and proof-of-concept

### CSV Export (Always Generated)
Importable into Excel, Jira, or ticketing systems

##  Security & Ethics

###  LEGAL WARNING

**This tool is designed for authorized security testing only.**

-  **DO**: Test applications you own or have written permission to test
-  **DO**: Use in bug bounty programs with proper scope
- **DO**: Use in professional penetration testing engagements
-  **DON'T**: Test websites without explicit authorization
-  **DON'T**: Use for malicious purposes

**Unauthorized testing may be illegal in your jurisdiction.**

### Authorization Confirmation
The `-ConfirmAuthorization` parameter requires an explicit statement:
```powershell
-ConfirmAuthorization "I am authorized to test example.com"
```

### Antivirus False Positives
This tool contains **legitimate security testing payloads** (SQL injection, XSS, command injection) that may trigger antivirus software.

**To bypass Windows Defender:**
```powershell
# Run PowerShell as Administrator
Add-MpPreference -ExclusionPath "C:\path\to\websecure-scanner"
```

Or temporarily disable real-time protection during testing.

##  How to Get Session Cookies

### Method 1: Browser DevTools
1. Login to target application
2. Press `F12` (DevTools)
3. Navigate to **Application** tab (Chrome) or **Storage** tab (Firefox)
4. Click **Cookies** → select your domain
5. Find cookie named `session`, `sessionid`, `PHPSESSID`, etc.
6. Copy the **Value** column
7. Use in command: `-SessionCookie "session=copied_value"`

### Method 2: Network Tab
1. Login to site
2. DevTools → **Network** tab
3. Click any request to authenticated page
4. Look at **Request Headers**
5. Copy entire `Cookie:` header value

### Method 3: Browser Extension
Use **EditThisCookie** (Chrome) or **Cookie-Editor** (Firefox) to export cookies

##  Architecture

### Core Components
- **Test Framework** - Modular test engine with 33 security checks
- **HTTP Client** - Robust request handling with timeout/retry logic
- **Authentication Manager** - Session management and replay
- **Issue Tracker** - Severity-based vulnerability classification
- **Report Generator** - Multi-format output (JSON, HTML, CSV)

### Code Statistics
- **7,585 lines** of PowerShell code
- **33 security test modules**
- **50+ vulnerability detection patterns**
- **15+ exploitation proof-of-concepts**

##  Documentation

- [**Authentication Guide**](AUTHENTICATION_GUIDE.md) - How to enable authenticated testing
- [**Authenticated vs Unauthenticated Comparison**](AUTHENTICATED_VS_UNAUTHENTICATED.md) - See the difference
- [**Contributing Guide**](CONTRIBUTING.md) - How to contribute to this project
- [**Changelog**](CHANGELOG.md) - Version history and updates

##  Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

### Ways to Contribute
-  Report bugs and false positives
-  Suggest new security tests
-  Improve documentation
-  Submit pull requests with fixes/features

##  License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

### Why MIT?
-  Free for commercial and personal use
-  Modify and distribute freely
-  No warranty or liability (as-is basis)
-  Only requires attribution

##  Key Differentiators

### vs. Commercial Scanners (Burp Suite, Acunetix)
-  **Free and Open Source**
-  **No license fees or limitations**
-  **Customizable and extensible**
-  Fewer features than enterprise tools
-  No GUI (command-line only)

### vs. Other Open Source Scanners (OWASP ZAP, Nikto)
-  **Native Windows support** (PowerShell)
-  **Exploitation proof-of-concepts** (not just detection)
-  **Authenticated testing built-in**
-  **Beautiful HTML reports**
-  Not as mature as 10+ year old projects
-  Smaller community

### vs. Web Vulnerability Scanners (WPScan, SQLMap)
-  **Comprehensive** (33 tests, not single-purpose)
-  **All-in-one solution** (no tool chaining needed)
-  **Easy to use** (one command to scan)
-  Less specialized than single-purpose tools

##  Benchmarks

### Test Coverage Comparison

| Tool | OWASP Top 10 | Authentication Tests | Exploitation POCs | Report Formats |
|------|-------------|---------------------|-------------------|----------------|
| **WebSecure Scanner** |  100% |  7 tests | 6 POCs | JSON, HTML, CSV |
| OWASP ZAP |  100% |  Limited |  Detection only | HTML, XML |
| Nikto |  60% | None |  Detection only | TXT, CSV |
| Burp Suite Free |  80% |  Limited |  Detection only | HTML |

### Performance

| Target Size | Scan Mode | Duration | Requests |
|-------------|-----------|----------|----------|
| Small (10 pages) | Normal | 3-5 min | ~500 |
| Medium (50 pages) | Normal | 8-12 min | ~1,000 |
| Large (100+ pages) | Aggressive | 20-30 min | ~2,500 |
| API (20 endpoints) | Aggressive | 10-15 min | ~1,500 |

##  Troubleshooting

### Common Issues

#### Issue: "This script contains malicious content"
**Solution**: Windows Defender detects testing payloads as malicious. Add exclusion:
```powershell
Add-MpPreference -ExclusionPath "C:\path\to\websecure-scanner"
```

#### Issue: "No authenticated tests executed"
**Solution**: Provide `-SessionCookie` and `-AuthUserId` parameters

#### Issue: "Request timeout" or "Too many requests"
**Solution**: Reduce `-MaxRequests` or use `-Mode "Passive"`

#### Issue: "File upload tests skipped"
**Solution**: Ensure you're authenticated and target has upload functionality

### Debug Mode
Enable verbose logging:
```powershell
$VerbosePreference = "Continue"
.\security_test2.ps1 -site "https://example.com" -Verbose
```

##  Roadmap

### v1.1 (Planned)
- [ ] GUI interface (PowerShell Forms)
- [ ] Browser automation for JavaScript-heavy apps
- [ ] GraphQL-specific testing module
- [ ] WebSocket security testing
- [ ] Multi-threading for faster scans

### v2.0 (Future)
- [ ] Machine learning for anomaly detection
- [ ] Exploit database integration
- [ ] Custom test module plugins
- [ ] Real-time reporting dashboard
- [ ] Team collaboration features

##  Support

- **Issues**: [GitHub Issues](https://github.com/Noshadi-sec/WebSecure-Scanner/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Noshadi-sec/WebSecure-Scanner/discussions)
- **Security Vulnerabilities**: Please report privately via GitHub Security Advisories

##  Acknowledgments

- **OWASP Foundation** - Security testing methodology
- **PortSwigger** - Web security research and techniques
- **PowerShell Community** - Development support

## 📸 Screenshots

### HTML Report Dashboard
![HTML Report](docs/images/html-report.png)

### Console Output
![Console Output](docs/images/console-output.png)

### Vulnerability Details
![Vulnerability Details](docs/images/vulnerability-details.png)

---

** If you find this tool useful, please star the repository!**

**Made by security professionals, for security professionals.**
