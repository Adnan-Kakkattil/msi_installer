# Test script to run installer with specific branch ID
# Usage: .\test_install_with_branch.ps1

$ErrorActionPreference = "Continue"

Write-Host "=== Testing Ebantis Installer with Branch ID ===" -ForegroundColor Cyan
Write-Host "Branch ID: ae72b051-1a4c-4820-8a26-30773e552ee1" -ForegroundColor Yellow
Write-Host ""

# Set environment variable for branch ID
$env:EBANTIS_BRANCH_ID = "ae72b051-1a4c-4820-8a26-30773e552ee1"

Write-Host "Branch ID environment variable set: $env:EBANTIS_BRANCH_ID" -ForegroundColor Green
Write-Host ""
Write-Host "Starting installer..." -ForegroundColor Cyan
Write-Host "Note: This will require administrator privileges" -ForegroundColor Yellow
Write-Host ""

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "Requesting administrator privileges..." -ForegroundColor Yellow
    # Re-run script as admin
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

# Run the installer
if (Test-Path "installer.ps1") {
    Write-Host "Executing installer.ps1..." -ForegroundColor Green
    & ".\installer.ps1"
} else {
    Write-Host "ERROR: installer.ps1 not found in current directory!" -ForegroundColor Red
    Write-Host "Current directory: $(Get-Location)" -ForegroundColor Yellow
    Exit 1
}

Write-Host ""
Write-Host "=== Test Complete ===" -ForegroundColor Cyan
