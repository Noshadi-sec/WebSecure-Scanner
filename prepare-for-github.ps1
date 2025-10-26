# GitHub Preparation Script
# This script cleans up the project folder and prepares it for GitHub

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  WebSecure Scanner - GitHub Prep" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$projectRoot = $PSScriptRoot

Write-Host "[1/6] Checking current directory..." -ForegroundColor Yellow
Write-Host "      Project root: $projectRoot" -ForegroundColor Gray

# Files to remove
$filesToRemove = @(
    "security_test.ps1",
    "test.py",
    "test_enhancements.ps1",
    "DEVELOPMENT_PROGRESS.md",
    "IMPLEMENTATION_SUMMARY.md",
    "QUICK_GUIDE.md",
    "ROADMAP_TO_100_PERCENT.md",
    "AUTHENTICATED_SCANNING_GUIDE.md"
)

# Folders to remove
$foldersToRemove = @(
    "scan_results"
)

Write-Host ""
Write-Host "[2/6] Removing unnecessary files..." -ForegroundColor Yellow
foreach ($file in $filesToRemove) {
    $filePath = Join-Path $projectRoot $file
    if (Test-Path $filePath) {
        Remove-Item $filePath -Force
        Write-Host "      [OK] Removed: $file" -ForegroundColor Green
    }
    else {
        Write-Host "      [SKIP] Not found: $file" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "[3/6] Removing test output folders..." -ForegroundColor Yellow
foreach ($folder in $foldersToRemove) {
    $folderPath = Join-Path $projectRoot $folder
    if (Test-Path $folderPath) {
        Remove-Item $folderPath -Recurse -Force
        Write-Host "      [OK] Removed: $folder" -ForegroundColor Green
    }
    else {
        Write-Host "      [SKIP] Not found: $folder" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "[4/6] Verifying essential files..." -ForegroundColor Yellow
$essentialFiles = @(
    "security_test2.ps1",
    "README.md",
    "LICENSE",
    "CONTRIBUTING.md",
    "CHANGELOG.md",
    ".gitignore",
    "AUTHENTICATION_GUIDE.md",
    "AUTHENTICATED_VS_UNAUTHENTICATED.md"
)

$allPresent = $true
foreach ($file in $essentialFiles) {
    $filePath = Join-Path $projectRoot $file
    if (Test-Path $filePath) {
        Write-Host "      [OK] Found: $file" -ForegroundColor Green
    }
    else {
        Write-Host "      [MISSING] $file" -ForegroundColor Red
        $allPresent = $false
    }
}

Write-Host ""
Write-Host "[5/6] Checking Git installation..." -ForegroundColor Yellow
try {
    $gitVersion = git --version
    Write-Host "      [OK] Git installed: $gitVersion" -ForegroundColor Green
}
catch {
    Write-Host "      [ERROR] Git not found! Install from: https://git-scm.com" -ForegroundColor Red
    Write-Host ""
    Write-Host "Cleanup complete, but Git is required for GitHub publishing." -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "[6/6] Final check..." -ForegroundColor Yellow

if ($allPresent) {
    Write-Host "      [OK] All essential files present" -ForegroundColor Green
}
else {
    Write-Host "      [ERROR] Some essential files are missing!" -ForegroundColor Red
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Cleanup Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Project Structure:" -ForegroundColor Cyan
Get-ChildItem $projectRoot | Where-Object { $_.Name -notmatch "^\.git" } | ForEach-Object {
    if ($_.PSIsContainer) {
        Write-Host "   [DIR]  $($_.Name)" -ForegroundColor Yellow
    }
    else {
        Write-Host "   [FILE] $($_.Name)" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Next Steps" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Step 1: Review GITHUB_PUBLISHING_GUIDE.md for detailed instructions" -ForegroundColor White
Write-Host ""
Write-Host "Step 2: Initialize Git repository:" -ForegroundColor White
Write-Host "        git init" -ForegroundColor Gray
Write-Host "        git add ." -ForegroundColor Gray
Write-Host "        git commit -m `"Initial release v1.0.0`"" -ForegroundColor Gray
Write-Host ""
Write-Host "Step 3: Create GitHub repository at: https://github.com/new" -ForegroundColor White
Write-Host "        Name: websecure-scanner" -ForegroundColor Gray
Write-Host "        Type: Public" -ForegroundColor Gray
Write-Host ""
Write-Host "Step 4: Connect and push:" -ForegroundColor White
Write-Host "        git remote add origin https://github.com/YOUR_USERNAME/websecure-scanner.git" -ForegroundColor Gray
Write-Host "        git branch -M main" -ForegroundColor Gray
Write-Host "        git push -u origin main" -ForegroundColor Gray
Write-Host ""
Write-Host "See GITHUB_PUBLISHING_GUIDE.md for complete instructions!" -ForegroundColor Cyan
Write-Host ""
Write-Host "Good luck with your open source project!" -ForegroundColor Green
