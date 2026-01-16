<#
.SYNOPSIS
    Cleanup and Reinstall Script for Ebantis MSI Installer
    Removes all traces of previous installation before reinstalling

.DESCRIPTION
    This script completely removes the Ebantis installation from:
    - Registry (ProductCode, UpgradeCode)
    - Program Files
    - ProgramData
    - MSI cache
    - Then reinstalls the MSI

.PARAMETER MsiPath
    Path to the MSI file to install after cleanup

.PARAMETER ProductCode
    Optional: Product Code GUID to uninstall. If not provided, will search for it.

.EXAMPLE
    .\cleanup_and_install.ps1 -MsiPath "installer_abc123.msi"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$MsiPath,
    
    [Parameter(Mandatory=$false)]
    [string]$ProductCode = ""
)

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = "Cyan"
    if ($Level -eq "ERROR") { $color = "Red" }
    elseif ($Level -eq "WARNING") { $color = "Yellow" }
    Write-Host "$timestamp | $Level | $Message" -ForegroundColor $color
}

function Test-IsAdmin {
    $Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = [System.Security.Principal.WindowsPrincipal]$Identity
    return $Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Log "Requesting administrative privileges..." "WARNING"
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -MsiPath `"$MsiPath`"" -Verb RunAs
    Exit
}

Write-Log "=== Ebantis Complete Cleanup and Reinstall Script ===" "INFO"

# Step 1: Find Product Code if not provided
if ([string]::IsNullOrEmpty($ProductCode)) {
    Write-Log "Searching for Ebantis Product Code in registry..." "INFO"
    
    # Search by UpgradeCode
    $UpgradeCode = "{B8B8B8B8-B8B8-B8B8-B8B8-B8B8B8B8B8B8}"
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes\$($UpgradeCode -replace '[{}]','').Replace('-','')"
    
    if (Test-Path $regPath) {
        $products = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
        if ($products) {
            $productProps = $products.PSObject.Properties | Where-Object { $_.Name -ne "PSPath" -and $_.Name -ne "PSParentPath" -and $_.Name -ne "PSChildName" }
            if ($productProps) {
                $ProductCode = $productProps[0].Name
                $ProductCode = "{" + $ProductCode.Substring(0,8) + "-" + $ProductCode.Substring(8,4) + "-" + $ProductCode.Substring(12,4) + "-" + $ProductCode.Substring(16,4) + "-" + $ProductCode.Substring(20) + "}"
                Write-Log "Found Product Code: $ProductCode" "INFO"
            }
        }
    }
    
    # Alternative: Search by product name
    if ([string]::IsNullOrEmpty($ProductCode)) {
        Write-Log "Searching by product name..." "INFO"
        $uninstallKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        $products = Get-ChildItem -Path $uninstallKey -ErrorAction SilentlyContinue | Get-ItemProperty | Where-Object { $_.DisplayName -like "*Ebantis*" }
        if ($products) {
            $ProductCode = $products[0].PSChildName
            Write-Log "Found Product Code from Uninstall key: $ProductCode" "INFO"
        }
    }
}

# Step 2: Uninstall using MSI if Product Code found
if (-not [string]::IsNullOrEmpty($ProductCode)) {
    Write-Log "Uninstalling Product Code: $ProductCode" "INFO"
    try {
        $uninstallResult = Start-Process -FilePath "msiexec.exe" -ArgumentList "/x $ProductCode /qn /norestart /L*v `"$env:TEMP\ebantis_uninstall.log`"" -Wait -PassThru -NoNewWindow
        if ($uninstallResult.ExitCode -eq 0 -or $uninstallResult.ExitCode -eq 3010) {
            Write-Log "Uninstallation completed successfully (Exit Code: $($uninstallResult.ExitCode))" "INFO"
            Start-Sleep -Seconds 3
        } else {
            Write-Log "Uninstallation completed with exit code: $($uninstallResult.ExitCode)" "WARNING"
        }
    } catch {
        Write-Log "Error during MSI uninstall: $_" "WARNING"
    }
} else {
    Write-Log "Product Code not found. Proceeding with manual cleanup..." "WARNING"
}

# Step 3: Remove Program Files directory
$ProgramFilesPath = Join-Path $env:ProgramFiles "EbantisV4"
if (Test-Path $ProgramFilesPath) {
    Write-Log "Removing Program Files directory: $ProgramFilesPath" "INFO"
    try {
        Remove-Item -Path $ProgramFilesPath -Recurse -Force -ErrorAction Stop
        Write-Log "Program Files directory removed successfully" "INFO"
    } catch {
        Write-Log "Error removing Program Files directory: $_" "WARNING"
    }
}

# Step 4: Remove ProgramData directory
$ProgramDataPath = Join-Path $env:ProgramData "EbantisV4"
if (Test-Path $ProgramDataPath) {
    Write-Log "Removing ProgramData directory: $ProgramDataPath" "INFO"
    try {
        Remove-Item -Path $ProgramDataPath -Recurse -Force -ErrorAction Stop
        Write-Log "ProgramData directory removed successfully" "INFO"
    } catch {
        Write-Log "Error removing ProgramData directory: $_" "WARNING"
    }
}

# Step 5: Clean MSI cache
Write-Log "Cleaning MSI cache..." "INFO"
$msiCachePath = "$env:WINDOWS\Installer"
if (-not [string]::IsNullOrEmpty($ProductCode)) {
    $productCodeNoBraces = $ProductCode -replace '[{}]',''
    $cachePattern = "*$productCodeNoBraces*"
    $cacheFiles = Get-ChildItem -Path $msiCachePath -Filter $cachePattern -ErrorAction SilentlyContinue
    foreach ($file in $cacheFiles) {
        try {
            Remove-Item -Path $file.FullName -Force -ErrorAction Stop
            Write-Log "Removed cache file: $($file.Name)" "INFO"
        } catch {
            Write-Log "Could not remove cache file $($file.Name): $_" "WARNING"
        }
    }
}

# Step 6: Clean registry entries
Write-Log "Cleaning registry entries..." "INFO"
if (-not [string]::IsNullOrEmpty($ProductCode)) {
    # Remove from Uninstall registry
    $uninstallPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$ProductCode"
    if (Test-Path $uninstallPath) {
        try {
            Remove-Item -Path $uninstallPath -Recurse -Force -ErrorAction Stop
            Write-Log "Removed Uninstall registry entry" "INFO"
        } catch {
            Write-Log "Could not remove Uninstall registry entry: $_" "WARNING"
        }
    }
    
    # Remove from Installer registry
    $installerPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products"
    if (Test-Path $installerPath) {
        $productFolders = Get-ChildItem -Path $installerPath -ErrorAction SilentlyContinue | Where-Object {
            (Get-ItemProperty -Path $_.PSPath -Name "PackageCode" -ErrorAction SilentlyContinue) -or
            $_.Name -like "*$($ProductCode -replace '[{}]','').Replace('-','')*"
        }
        foreach ($folder in $productFolders) {
            try {
                Remove-Item -Path $folder.PSPath -Recurse -Force -ErrorAction Stop
                Write-Log "Removed Installer registry folder: $($folder.Name)" "INFO"
            } catch {
                Write-Log "Could not remove Installer registry folder: $_" "WARNING"
            }
        }
    }
}

Write-Log "Cleanup completed. Waiting 2 seconds before reinstallation..." "INFO"
Start-Sleep -Seconds 2

# Step 7: Reinstall MSI
if (Test-Path $MsiPath) {
    Write-Log "Installing MSI: $MsiPath" "INFO"
    try {
        $installResult = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$MsiPath`" /qn /norestart /L*v `"$env:TEMP\ebantis_install.log`"" -Wait -PassThru -NoNewWindow
        if ($installResult.ExitCode -eq 0 -or $installResult.ExitCode -eq 3010) {
            Write-Log "Installation completed successfully (Exit Code: $($installResult.ExitCode))" "INFO"
        } else {
            Write-Log "Installation completed with exit code: $($installResult.ExitCode)" "ERROR"
            Write-Log "Check log file: $env:TEMP\ebantis_install.log" "ERROR"
            Exit $installResult.ExitCode
        }
    } catch {
        Write-Log "Error during MSI install: $_" "ERROR"
        Exit 1
    }
} else {
    Write-Log "MSI file not found: $MsiPath" "ERROR"
    Exit 1
}

Write-Log "=== Cleanup and Reinstall Completed ===" "INFO"
