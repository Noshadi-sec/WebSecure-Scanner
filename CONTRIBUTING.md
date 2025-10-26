# Contributing to WebSecure Scanner

First off, thank you for considering contributing to WebSecure Scanner! It's people like you that make this tool better for the security community.

## Ways to Contribute

### Reporting Bugs
- Use GitHub Issues to report bugs
- Include steps to reproduce
- Provide PowerShell version (`$PSVersionTable`)
- Include error messages and logs

### Suggesting Features
- Check existing issues first
- Explain the use case
- Describe expected behavior
- Consider backward compatibility

### Improving Documentation
- Fix typos and grammar
- Add examples
- Clarify confusing sections
- Translate to other languages

### Code Contributions
- Fork the repository
- Create a feature branch
- Write clean, commented code
- Test your changes thoroughly
- Submit a pull request

## Getting Started

### Prerequisites
- PowerShell 5.1+ or PowerShell Core 7+
- Git
- Text editor (VS Code recommended)

### Development Setup
```powershell
# Clone your fork
git clone https://github.com/<your-username>/WebSecure-Scanner.git
cd WebSecure-Scanner

# Create a feature branch
git checkout -b feature/your-feature-name
```

## Pull Request Process

### Before Submitting
1. **Test your changes** - Run against multiple test targets
2. **Follow code style** - Match existing PowerShell conventions
3. **Update documentation** - README, comments, and help text
4. **No breaking changes** - Unless absolutely necessary

### PR Template
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement

## Testing
- Tested against: [list targets]
- PowerShell version: [version]
- OS: [Windows/Linux/macOS]

## Checklist
- [ ] Code follows project style
- [ ] Self-reviewed the code
- [ ] Commented complex sections
- [ ] Updated documentation
- [ ] No breaking changes
```

## Code Style Guidelines

### PowerShell Conventions
```powershell
# Use approved verbs (Get, Set, Test, Invoke, etc.)
function Test-SecurityFeature { }

# PascalCase for functions and parameters
param(
    [string]$TargetUrl,
    [int]$MaxRequests
)

# camelCase for variables
$testResults = @()
$isVulnerable = $false

# Comments for complex logic
# Check if response contains SQL error patterns
if ($response.Content -match "sql|mysql|postgres") {
    # Additional validation
}

# Use proper error handling
try {
    $result = Invoke-WebRequest -Uri $url
}
catch {
    Write-Error "Request failed: $_"
}
```

### Adding New Security Tests

```powershell
# ============================================================================
# TEST XX: YOUR TEST NAME
# ============================================================================
function Test-YourSecurityCheck {
    Start-SecurityTest "Your Test Description" "XX"
    
    try {
        Write-Info "Phase 1: Description..."
        
        # Your test logic here
        $vulnerable = $false
        
        if ($vulnerable) {
            Add-Issue -severity "High" `
                -title "Issue Title" `
                -description "Detailed description" `
                -remediation "How to fix" `
                -whyItMatters "Impact explanation" `
                -suggestedFix "Specific code fix" `
                -url $testedUrl `
                -cweId "CWE-XXX" `
                -confidence "High"
        }
        
        Complete-SecurityTest
    }
    catch {
        Write-Danger "Test failed: $_"
        Complete-SecurityTest "Failed"
    }
}
```

## Testing Guidelines

### Manual Testing
```powershell
# Test against known vulnerable apps
.\security_test2.ps1 -site "http://testphp.vulnweb.com"

# Test authenticated features
.\security_test2.ps1 -site "https://example.com" -SessionCookie "test"

# Test error handling
.\security_test2.ps1 -site "https://invalid-url-test"
```

### Regression Testing
- Ensure existing tests still pass
- Don't break backward compatibility
- Test on Windows PowerShell 5.1 AND PowerShell Core 7+

## Issue Labels

- `bug` - Something isn't working
- `enhancement` - New feature request
- `documentation` - Documentation improvements
- `good first issue` - Good for newcomers
- `help wanted` - Extra attention needed
- `security` - Security vulnerability in scanner itself
- `false-positive` - Scanner incorrectly flags issue

## Security Vulnerabilities

**Do NOT create public issues for security vulnerabilities in the scanner itself.**

Instead:
1. Use GitHub Security Advisories (private disclosure)
2. Go to: https://github.com/Noshadi-sec/WebSecure-Scanner/security/advisories
3. Allow 90 days for patch before public disclosure

## Code of Conduct

### Our Pledge
We pledge to make participation in this project a harassment-free experience for everyone.

### Our Standards
- Be respectful and inclusive
- Accept constructive criticism
- Focus on what's best for the community
- Show empathy toward others

### Unacceptable Behavior
- Harassment or discrimination
- Trolling or insulting comments
- Doxxing or privacy violations
- Promoting illegal activities

## Resources

### Learning PowerShell
- [PowerShell Documentation](https://docs.microsoft.com/powershell/)
- [PowerShell Best Practices](https://github.com/PoshCode/PowerShellPracticeAndStyle)

### Web Security
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)

### Similar Projects
- [OWASP ZAP](https://github.com/zaproxy/zaproxy)
- [Nikto](https://github.com/sullo/nikto)

## Questions?

- Open a [GitHub Discussion](https://github.com/Noshadi-sec/WebSecure-Scanner/discussions)
- Comment on relevant issues
- Join community chat (if available)

## Attribution

Contributors will be added to:
- README.md Contributors section
- CHANGELOG.md for their contributions
- GitHub contributors page

---

**Thank you for contributing to WebSecure Scanner! Your efforts help make the web more secure.**
