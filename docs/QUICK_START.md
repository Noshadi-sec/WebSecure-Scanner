# Quick Start Guide

## 3Minute Setup

### Step 1: Install Prerequisites
```powershell
# Check PowerShell version (must be 5.1+)
$PSVersionTable.PSVersion

# If less than 5.1, install PowerShell Core
# Download from: https://github.com/PowerShell/PowerShell/releases
```

### Step 2: Download Scanner
```powershell
# Clone repository
git clone https://github.com/Noshadi-sec/WebSecure-Scanner.git
cd WebSecure-Scanner

# Unblock script (Windows only)
Unblock-File -Path .\security_test2.ps1
```

### Step 3: Basic Scan
```powershell
# Run your first scan
.\security_test2.ps1 -site "https://example.com" -Mode "Normal"

# Results saved to: reports/security_report_<timestamp>.json
```

## Common Use Cases

### Use Case 1: Quick Security Check
**Goal**: Fast security assessment of public website

```powershell
.\security_test2.ps1 `
    -site "https://example.com" `
    -Mode "Passive" `
    -htmlReport
```

**Duration**: 2-3 minutes  
**Output**: HTML report with critical issues only

---

### Use Case 2: Deep Application Scan
**Goal**: Comprehensive testing with authentication

```powershell
# Step 1: Get session cookie (see guide below)
# Step 2: Run scan
.\security_test2.ps1 `
    -site "https://app.example.com" `
    -SessionCookie "session=abc123..." `
    -AuthUserId "100" `
    -Mode "Aggressive" `
    -MaxRequests 2000 `
    -htmlReport `
    -outputDir ".\reports\app_scan"
```

**Duration**: 15-30 minutes  
**Output**: HTML + JSON + CSV with exploitation proofs

---

### Use Case 3: Bug Bounty Hunting
**Goal**: Find vulnerabilities for bug bounty submission

```powershell
.\security_test2.ps1 `
    -site "https://bugbounty-target.com" `
    -SessionCookie "session=..." `
    -Mode "Aggressive" `
    -ConfirmAuthorization "I have permission via HackerOne program" `
    -ForceExternal `
    -htmlReport
```

**Focus**: Critical/High severity issues with exploitation POCs

---

### Use Case 4: CI/CD Integration
**Goal**: Automated security testing in pipeline

```powershell
# In your CI/CD script
.\security_test2.ps1 `
    -site "https://staging.example.com" `
    -Mode "Normal" `
    -BaselineReport ".\baseline\security_report.json" `
    -outputDir ".\regression"

# Check exit code
if ($LASTEXITCODE -ne 0) {
    Write-Error "New security issues detected!"
    exit 1
}
```

---

## Getting Session Cookies

### Method 1: Chrome DevTools
1. Open Chrome and login to target site
2. Press `F12` to open DevTools
3. Click **Application** tab
4. In left sidebar, expand **Cookies**
5. Click on your domain (e.g., `https://example.com`)
6. Find row with Name = `session` (or `sessionid`, `PHPSESSID`)
7. Double-click the **Value** column to select
8. Right-click → Copy
9. Use in command: `-SessionCookie "session=<paste_here>"`

### Method 2: Firefox DevTools
1. Open Firefox and login to target site
2. Press `F12` to open DevTools
3. Click **Storage** tab
4. In left sidebar, expand **Cookies**
5. Click on your domain
6. Find session cookie and copy **Value**

### Method 3: Network Tab (Any Browser)
1. Login to site
2. Open DevTools (F12) → **Network** tab
3. Click any request to authenticated page (e.g., `/dashboard`)
4. Look at **Request Headers** section
5. Find `Cookie:` header
6. Copy entire value (e.g., `session=abc; csrf=xyz`)
7. Use in command: `-SessionCookie "session=abc; csrf=xyz"`

### Method 4: Copy as cURL (Advanced)
1. Login to site
2. DevTools → Network tab
3. Right-click on authenticated request
4. Select **Copy** → **Copy as cURL**
5. Extract cookie from `-H 'Cookie: ...'` section

---

## Understanding Results

### Severity Levels

| Severity | Risk | Action Required | Example |
|----------|------|-----------------|---------|
| **CRITICAL** | Immediate exploitation possible | Fix within 24 hours | RCE, SQL Injection, IDOR |
| **HIGH** | Significant security risk | Fix within 1 week | Missing CSRF tokens, XSS |
| **MEDIUM** | Moderate risk | Fix within 1 month | Missing security headers |
| **LOW** | Minor issue | Fix when convenient | Version disclosure |
| **INFO** | Informational | No action needed | Security features detected |

### Risk Score Calculation
```
Risk Score = (Critical × 10) + (High × 7) + (Medium × 4) + (Low × 1)

Example:
- 2 Critical = 20 points
- 5 High = 35 points
- 10 Medium = 40 points
- 3 Low = 3 points
Total Risk Score = 98 (HIGH RISK)
```

### Reading JSON Reports
```powershell
# Load report
$report = Get-Content ".\reports\security_report_*.json" | ConvertFrom-Json

# Get all Critical issues
$report.Issues.Critical | ForEach-Object { $_.Title }

# Get total issue count
$report.Summary.TotalIssues

# Get risk score
$report.Summary.RiskScore
```

---

## Troubleshooting

### Problem: "Script is blocked by antivirus"
**Solution**:
```powershell
# Option 1: Add exclusion (requires Admin)
Add-MpPreference -ExclusionPath "C:\path\to\websecure-scanner"

# Option 2: Temporarily disable Windows Defender
# Windows Security → Virus & threat protection → Manage settings → Turn off Real-time protection
```

### Problem: "No authenticated tests executed"
**Solution**: You need to provide `-SessionCookie` parameter
```powershell
# Add this parameter:
-SessionCookie "session=your_cookie_here"
```

### Problem: "Too many requests / Rate limited"
**Solution**: Reduce scan intensity
```powershell
# Use Passive mode
-Mode "Passive"

# Or reduce max requests
-MaxRequests 500
```

### Problem: "Connection timeout"
**Solution**:
```powershell
# Increase timeout (default is 10 seconds)
# Modify script or use Passive mode for slower sites
-Mode "Passive"
```

---

## Next Steps

### Learn More
- Read [README.md](../README.md) for full documentation
- Check [AUTHENTICATION_GUIDE.md](../AUTHENTICATION_GUIDE.md) for advanced auth
- See [AUTHENTICATED_VS_UNAUTHENTICATED.md](../AUTHENTICATED_VS_UNAUTHENTICATED.md) for comparison

### Get Help
- Open [GitHub Issues](https://github.com/Noshadi-sec/WebSecure-Scanner/issues)
- Join [Discussions](https://github.com/Noshadi-sec/WebSecure-Scanner/discussions)

### Contribute
- Report bugs
- Suggest features
- Submit pull requests
- Improve documentation

---

**Happy Hunting! **
