# WebSecure Scanner - Advanced Web Application Security Testing Suite

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/v/release/Noshadi-sec/WebSecure-Scanner.svg)](https://github.com/Noshadi-sec/WebSecure-Scanner/releases)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

**WebSecure Scanner** is a professional-grade web application security testing suite designed for penetration testers, security researchers, and DevSecOps teams. Built entirely in PowerShell, it performs 33 different security tests covering the OWASP Top 10 and beyond.

---

## LEGAL DISCLAIMER

**READ THIS CAREFULLY BEFORE USING THIS TOOL**

# EDUCATIONAL AND AUTHORIZED SECURITY TESTING PURPOSES ONLY 
# NEVER EVER USE IT FOR HACKING OR EXPLOITING WEBSITES YOU DON'T OWN 

This tool is provided for **EDUCATIONAL AND AUTHORIZED SECURITY TESTING PURPOSES ONLY. Never EVER USE IT FOR HACKING OR EXPLOITING WEBSITE YOU DONT OWN**.

### YOU MUST:
- **✓** Only test applications **YOU OWN** or have **EXPLICIT WRITTEN PERMISSION** to test
- **✓** Obtain proper authorization before testing any system
- **✓** Comply with all applicable laws and regulations in your jurisdiction
- **✓** Use this tool responsibly and ethically

### YOU MUST NOT:
- **✗** Test websites or applications without explicit authorization
- **✗** Use this tool for illegal activities or unauthorized access
- **✗** Cause harm, disruption, or damage to any system
- **✗** Violate any applicable laws, terms of service, or computer misuse regulations

### RESPONSIBILITY:
**THE AUTHOR AND CONTRIBUTORS ARE NOT RESPONSIBLE FOR ANY MISUSE, DAMAGE, OR ILLEGAL ACTIVITIES CONDUCTED WITH THIS TOOL.**

By using this software, you agree that:
1. You are solely responsible for your actions
2. You will only use this tool on systems you are authorized to test
3. You understand that unauthorized access to computer systems is illegal
4. The author disclaims all liability for any direct, indirect, incidental, or consequential damages

**Unauthorized access to computer systems is illegal under laws such as the Computer Fraud and Abuse Act (CFAA) in the United States and similar legislation worldwide. Violations can result in criminal prosecution and civil liability.**

**USE AT YOUR OWN RISK. YOU HAVE BEEN WARNED.**

---

## Key Features

### Comprehensive Testing (33 Security Tests)
- **Authentication & Session Management** - Session fixation, logout bypass, JWT tampering
- **Authorization Flaws** - IDOR (Insecure Direct Object References), privilege escalation
- **CSRF Protection** - Token detection + **exploit attempts** with proof-of-concept
- **XSS Detection** - Reflected, Stored, DOM-based
- **SQL Injection** - Error-based, blind, time-based detection
- **Security Headers** - CSP, HSTS, X-Frame-Options, etc.
- **File Upload Security** - RCE testing, MIME bypass, path traversal
- **Parameter Tampering** - Mass assignment, privilege escalation via JSON injection
- **Information Disclosure** - Sensitive files, API documentation, secrets in JS
- **TLS/HTTPS Configuration** - Certificate validation, redirect enforcement
- **Access Control** - Broken authentication, anonymous access testing
- **API Security** - CORS, REST endpoint discovery, GraphQL testing
- **Infrastructure** - Subdomain enumeration, WAF detection, open redirects

### Advanced Capabilities
- **Authenticated Testing** - Session replay for testing protected endpoints
- **Exploit Proof-of-Concept** - Not just detection, actual exploitation attempts
- **Multiple Report Formats** - JSON, HTML, CSV outputs
- **Aggressive Mode** - Deep testing with configurable request limits
- **Baseline Comparison** - Track security posture changes over time
- **External Target Support** - Test any website with proper authorization

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

### Example 3: Full Comprehensive Scan (Recommended)
```powershell
.\security_test2.ps1 `
    -site "https://your-authorized-site.com" `
    -Mode "Aggressive" `
    -MaxRequests 2000 `
    -ConfirmAuthorization "I am authorized to test your-authorized-site.com" `
    -ForceExternal `
    -htmlReport `
    -outputDir ".\scan_results"
```
**Output**: Complete security assessment with HTML report, all 33 tests, exploitation attempts

### Example 4: Regression Testing
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

### Example 5: API Testing
```powershell
.\security_test2.ps1 `
    -site "https://api.example.com" `
    -SessionCookie "Authorization: Bearer eyJhbGc..." `
    -Mode "Aggressive"
```

## Scan Modes Explained

### Passive Mode
- **Purpose**: Reconnaissance only, no active exploitation
- **Tests**: Header analysis, information disclosure, configuration review
- **Impact**: Read-only, minimal traffic
- **Use When**: Initial assessment, production systems, limited authorization
- **Requirements**: Only `-site` parameter needed

**Basic Command:**
```powershell
.\security_test2.ps1 -site "https://example.com" -Mode "Passive"
```

**Complete Command (with reporting):**
```powershell
.\security_test2.ps1 `
    -site "https://your-site.com" `
    -Mode "Passive" `
    -htmlReport `
    -outputDir ".\scan_results"
```

### Normal Mode (Default)
- **Purpose**: Balanced testing with safe exploitation attempts
- **Tests**: All 33 tests with conservative payloads
- **Impact**: Moderate traffic, safe for most environments
- **Use When**: Standard security assessments, staging environments
- **Requirements**: Use `-ConfirmAuthorization` for external sites

**Basic Command:**
```powershell
.\security_test2.ps1 -site "https://example.com" -Mode "Normal"
```

**Complete Command (with all features):**
```powershell
.\security_test2.ps1 `
    -site "https://your-authorized-site.com" `
    -Mode "Normal" `
    -MaxRequests 1000 `
    -ConfirmAuthorization "I am authorized to test your-authorized-site.com" `
    -ForceExternal `
    -htmlReport `
    -outputDir ".\scan_results"
```

### Aggressive Mode (Recommended for Full Testing)
- **Purpose**: Comprehensive deep testing with extensive payloads
- **Tests**: All 33 tests with maximum coverage and exploitation POCs
- **Impact**: High traffic (up to MaxRequests), thorough but intensive
- **Use When**: Penetration testing, dedicated test environments, authorized assessments
- **Requirements**: MUST use `-ConfirmAuthorization` and `-ForceExternal` for external sites

**Complete Command (Recommended):**
```powershell
.\security_test2.ps1 `
    -site "https://your-authorized-site.com" `
    -Mode "Aggressive" `
    -MaxRequests 2000 `
    -ConfirmAuthorization "I am authorized to test your-authorized-site.com" `
    -ForceExternal `
    -htmlReport `
    -outputDir ".\scan_results"
```

**Note**: Aggressive mode may trigger WAF alerts and generate significant logs. Ensure you have proper authorization and notify the system owner.

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

### Legal Warning

**This tool is designed for authorized security testing only.**

- **DO**: Test applications you own or have written permission to test
- **DO**: Use in bug bounty programs with proper scope
- **DO**: Use in professional penetration testing engagements
- **DON'T**: Test websites without explicit authorization
- **DON'T**: Use for malicious purposes

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

##  Documentation

- [**Authentication Guide**](AUTHENTICATION_GUIDE.md) - How to enable authenticated testing
- [**Authenticated vs Unauthenticated Comparison**](AUTHENTICATED_VS_UNAUTHENTICATED.md) - See the difference
- [**Contributing Guide**](CONTRIBUTING.md) - How to contribute to this project
- [**Changelog**](CHANGELOG.md) - Version history and updates

##  Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

### Ways to Contribute
- Report bugs and false positives
- Suggest new security tests
- Improve documentation
- Submit pull requests with fixes/features

## License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

## Benchmarks

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

## Support

- **Issues**: [GitHub Issues](https://github.com/Noshadi-sec/WebSecure-Scanner/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Noshadi-sec/WebSecure-Scanner/discussions)
- **Security Vulnerabilities**: Please report privately via GitHub Security Advisories

## Acknowledgments

- **OWASP Foundation** - Security testing methodology
- **PortSwigger** - Web security research and techniques
- **PowerShell Community** - Development support

---

**If you find this tool useful, please star the repository!**
