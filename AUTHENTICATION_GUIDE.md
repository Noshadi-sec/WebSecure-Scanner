# Authentication & Advanced Testing Guide

## How to Enable Authenticated Testing (Close the Gaps)

The scanner has 33 tests, but **7 critical tests require authentication** to execute:

### Tests That Need Auth:
- **Test 09 Phase 4-5**: Authenticated CSRF + exploitation attempts
- **Test 23**: IDOR testing (horizontal/vertical privilege escalation)
- **Test 30**: Session security (fixation, logout bypass, JWT tampering)
- **Test 31**: Parameter tampering & mass assignment
- **Test 32**: File upload security (needs auth to access upload forms)
- **Test 33**: Stored XSS (requires posting to authenticated endpoints)

---

## Method 1: Session Cookie (Fastest)

### Step 1: Get Your Session Cookie
1. Log into target site in browser
2. Open DevTools (F12) → Application/Storage → Cookies
3. Find session cookie (usually named: `session`, `PHPSESSID`, `connect.sid`, `sessionid`)
4. Copy the full cookie value

### Step 2: Run Scanner with Session
```powershell
.\security_test2.ps1 `
    -site "https://canifly.it" `
    -SessionCookie "session=eyJhbGciOiJIUzI1NiIsInR5cCI..." `
    -AuthUserId "123" `
    -Mode "Aggressive" `
    -ConfirmAuthorization "I am authorized" `
    -ForceExternal `
    -htmlReport
```

### What This Unlocks:
**Test 09 Phase 4**: Checks authenticated forms for CSRF tokens  
 **Test 09 Phase 5**: Attempts CSRF exploitation (submits forms without tokens)  
 **Test 23**: IDOR testing (tries to access user 124's data with user 123's session)  
 **Test 30**: Session security (logout bypass, JWT tampering)  
 **Test 31**: Mass assignment (injects `role=admin` into PUT /api/user)  
 **Test 32**: File upload fuzzing (tests discovered upload endpoints)  
 **Test 33**: Stored XSS (posts payloads to feedback/comment forms)

---

## Method 2: Username + Password (Most Automated)

### Requirements:
1. Site must have discoverable login endpoint
2. Must use standard form-based auth (not OAuth/SAML)

### Run Command:
```powershell
.\security_test2.ps1 `
    -site "https://canifly.it" `
    -Username "testuser@example.com" `
    -Password "MyPassword123!" `
    -LoginUrl "https://canifly.it/login" `
    -AuthUserId "123" `
    -Mode "Aggressive" `
    -ConfirmAuthorization "I am authorized" `
    -ForceExternal `
    -htmlReport
```

### What Happens:
1. Scanner POSTs credentials to `/login`
2. Extracts session cookie from response
3. Uses session for all authenticated tests
4. Tests logout/session invalidation

---

## Method 3: API Token/Bearer Auth

For API testing with JWT/Bearer tokens:

```powershell
.\security_test2.ps1 `
    -site "https://api.canifly.it" `
    -SessionCookie "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." `
    -Mode "Aggressive" `
    -ConfirmAuthorization "I am authorized" `
    -ForceExternal `
    -htmlReport
```

---

## Advanced: Multi-User IDOR Testing

To test horizontal privilege escalation (User A accessing User B's data):

### Step 1: Get Two User Sessions
```powershell
# Login as User 1
$session1 = "session=abc123..."
$userId1 = "100"

# Login as User 2  
$session2 = "session=xyz789..."
$userId2 = "200"
```

### Step 2: Run Scanner as User 1
```powershell
.\security_test2.ps1 `
    -site "https://canifly.it" `
    -SessionCookie $session1 `
    -AuthUserId $userId1 `
    -Mode "Aggressive"
```

### What Test 23 Will Do:
1. Calculate `$otherUserId = [int]$AuthUserId + 1`  (101)
2. Try to GET `/api/user?id=101` with User 1's session
3. If successful → **CONFIRMED IDOR VULNERABILITY**
4. Reports as **CRITICAL** issue

---

## File Upload Testing (Test 32)

### Why It Skipped:
```
"No obvious upload endpoints found via direct testing"
```

### How to Unlock:
1. **Provide known upload endpoint**:
```powershell
.\security_test2.ps1 `
    -site "https://canifly.it" `
    -SessionCookie "session=..." `
    -Mode "Aggressive"
```

2. **Script will auto-test these paths**:
   - `/upload`
   - `/api/upload`
   - `/api/avatar/upload`
   - `/api/file/upload`
   - `/user/avatar`
   - `/profile/picture`

3. **If found, script tests**:
   -  `.php` file upload (RCE attempt)
   -  MIME type bypass (`.php` with `Content-Type: image/jpeg`)
   -  Path traversal (`../../evil.php`)
   -  SVG with embedded JavaScript (XSS)

### Manual Enhancement:
If you know exact upload endpoint, modify script line ~7080:
```powershell
$uploadEndpoints = @(
    "/upload",
    "/api/upload",
    "/your/custom/endpoint"  # <-- Add here
)
```

---

## Stored XSS Testing (Test 33)

### Why It Skipped:
- Requires authentication
- Tests these endpoints with XSS payloads:
  - `/api/feedback`
  - `/api/comments`
  - `/api/reviews`
  - `/api/posts`

### How to Unlock:
```powershell
.\security_test2.ps1 `
    -site "https://canifly.it" `
    -SessionCookie "session=..." `
    -Mode "Aggressive"
```

### What Happens:
1. **POST** XSS payload to `/api/feedback?message=<script>alert(1)</script>`
2. **GET** same endpoint to see if payload persists
3. If payload appears in response → **CONFIRMED STORED XSS**

---

## Session Security Testing (Test 30)

### Tests Performed (when authenticated):

#### Test 1: Session Fixation
- Re-login and check if session ID changes
- If unchanged → **HIGH severity** (session fixation vuln)

#### Test 2: Logout Bypass
- Call `/logout`
- Try to access `/dashboard` with old session
- If still works → **CRITICAL** (session not invalidated)

#### Test 3: JWT Tampering
- Detect JWT in cookies
- Change `alg` to `none`
- Remove signature
- Test if accepted → **CRITICAL** (JWT bypass)

---

## Parameter Tampering & Mass Assignment (Test 31)

### Automated Tests:

#### Test 1: Boundary Fuzzing
Tests these values on `/api/user?id=`:
- `0` (may return all users)
- `-1` (may access system records)
- `999999` (may cause errors)
- `null`, `undefined`, `[]`, `{}`

#### Test 2: Mass Assignment
POSTs to `/api/user` with:
```json
{
  "name": "Test User",
  "email": "test@example.com",
  "role": "admin",           // ← Injected
  "isAdmin": true,            // ← Injected
  "isPremium": true,          // ← Injected
  "credits": 999999           // ← Injected
}
```

Then GETs `/api/user` to see if fields were accepted.

**If successful** → **CRITICAL: Mass Assignment / Privilege Escalation**

---

## What's Still Manual (Expected Limitations)

### Business Logic Abuse
Cannot automate:
- "Skip payment step but still get premium account"
- "Book flight for $0 by manipulating price"
- "Redeem promo code multiple times"

**Why**: Requires understanding application flow, multi-step processes

**Workaround**: Use scanner to find API endpoints, then manually test logic flaws

### Complex Authentication
 Cannot handle:
- OAuth flows
- 2FA/MFA
- SAML
- Biometric auth

**Workaround**: Provide final session cookie after manual login

---

## Example: Complete Authenticated Scan

```powershell
# 1. Login to site manually and get session cookie
# 2. Find your user ID (check browser network tab or /api/user response)
# 3. Run full scan:

.\security_test2.ps1 `
    -site "https://canifly.it" `
    -SessionCookie "session=your_session_cookie_here" `
    -AuthUserId "123" `
    -Mode "Aggressive" `
    -MaxRequests 3000 `
    -ConfirmAuthorization "I am authorized to test canifly.it" `
    -ForceExternal `
    -htmlReport `
    -outputDir ".\authenticated_scan_results"
```

### Expected Output:
```
[09] CSRF Protection Analysis
  Phase 4: Authenticated CSRF testing (session replay enabled)...
  ✓ Found 3 authenticated forms
  ✗ CRITICAL: 1 authenticated form MISSING CSRF token

[23] Broken Access Control / IDOR Detection
  Your User ID: 123 | Testing access to User ID: 124
  ✗ IDOR DETECTED: User 123 can access User 124 data!

[30] Session Security & Token Validation
  Test 2: Testing session invalidation on logout...
  ✗ CRITICAL: Session token still valid after logout

[31] Parameter Tampering & Mass Assignment
  Test 2: Mass assignment vulnerability testing...
  ✗ CRITICAL: Mass assignment confirmed! Injected: role, isAdmin

[32] File Upload Security Testing
  Found potential upload endpoint: /api/avatar/upload
  ✗ CRITICAL: PHP file upload accepted! Potential RCE

[33] Stored XSS Testing
  Testing persistent payload injection...
  ✗ CRITICAL: Stored XSS confirmed at /api/feedback
```

---

## Next Evolution (Future Enhancements)

### 1. HTML Form Discovery
Crawl HTML and parse:
```html
<form action="/upload" enctype="multipart/form-data">
  <input type="file" name="avatar">
</form>
```
Then auto-test discovered upload endpoints.

### 2. JavaScript Endpoint Extraction
Parse JS files for:
```javascript
fetch('/api/internal/admin', {...})
axios.post('/secret/endpoint', data)
```

### 3. Multi-Step Attack Chains
- Create account → Verify email bypass → Privilege escalation

---

## Bypassing Antivirus Block

Your script is **legitimate pentesting** but Windows Defender blocks it.

### Solution 1: Admin PowerShell Exclusion
```powershell
# Run as Administrator
Add-MpPreference -ExclusionPath "C:\Users\amirn\OneDrive\Desktop\site_tester"
```

### Solution 2: Temporarily Disable Protection
1. Windows Security → Virus & threat protection
2. Manage settings → Turn off Real-time protection
3. Run scan
4. Re-enable protection

### Solution 3: WSL2 / Linux VM
Windows Defender won't interfere with Linux environments.

---

## Summary

**Current Gap**: You have the weapon, but no ammunition (auth credentials).

**To Close Gap**: Provide `-SessionCookie` + `-AuthUserId` and re-run.

**Result**: 7 additional critical tests will execute, potentially finding:
- CSRF exploitation
- IDOR vulnerabilities  
- Session fixation/logout bypass
- JWT tampering
- Mass assignment → privilege escalation
- Unrestricted file upload → RCE
- Stored XSS

The scanner is **production-ready**. It just needs credentials to prove its worth.
ahan