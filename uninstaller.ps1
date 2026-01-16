<#
.SYNOPSIS
    Ebantis V4 Uninstaller - PowerShell Version
    Complete uninstallation flow for Ebantis Agent

.DESCRIPTION
    Handles the complete uninstallation of the Ebantis Agent, including:
    - Process Termination (EbantisV4, AutoUpdationService, and related processes)
    - Startup Shortcut Removal
    - File and Folder Cleanup (Program Files and ProgramData)
    - API Status Update (uninstalled)
    - Tenant Information Cleanup

.NOTES
    Version: 4.0
    Based on: uninstallation.pyx flow
#>

# -------------------------------------------------------------------------
# STEP 1: ADMIN PRIVILEGE CHECK & INITIALIZATION
# -------------------------------------------------------------------------

function Test-IsAdmin {
    $Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = [System.Security.Principal.WindowsPrincipal]$Identity
    return $Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Host "Requesting administrative privileges for uninstallation..." -ForegroundColor Yellow
    $envArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    Start-Process powershell -ArgumentList $envArgs -Verb RunAs
    Exit
}

# Configuration Constants
$AppName = "EbantisV4"
$ProgramFilesPath = [System.IO.Path]::Combine($env:ProgramFiles, $AppName)
$ProgramDataPath = [System.IO.Path]::Combine($env:ProgramData, $AppName)
$LogFolder = [System.IO.Path]::Combine($ProgramDataPath, "Logs")

# Create Log Folder if it doesn't exist (for uninstallation log)
if (-not (Test-Path $LogFolder)) {
    New-Item -ItemType Directory -Path $LogFolder -Force | Out-Null
}

$LogFile = [System.IO.Path]::Combine($LogFolder, "Ebantis_uninstall_$(Get-Date -Format 'yyyy-MM-dd').log")

# Logging Function
function Write-Log {
    param(
        [Parameter(Mandatory=$true)] [string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR")] [string]$Level = "INFO"
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "$Timestamp | $Level | $Message"
    $Color = "Cyan"
    if ($Level -eq "ERROR") { $Color = "Red" }
    elseif ($Level -eq "WARNING") { $Color = "Yellow" }
   
    Write-Host $LogEntry -ForegroundColor $Color
    Add-Content -Path $LogFile -Value $LogEntry -Encoding UTF8 -ErrorAction SilentlyContinue
}

Write-Log "=== Starting Ebantis V4 Uninstallation ===" "INFO"
Write-Log "Running with administrative privileges." "INFO"

# -------------------------------------------------------------------------
# STEP 2: SYSTEM INFORMATION GATHERING
# -------------------------------------------------------------------------

function Get-MachineID {
    try {
        $UUID = (Get-WmiObject -Class Win32_ComputerSystemProduct).UUID
        if ($UUID -and $UUID -ne "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF") {
            Write-Log "Machine ID retrieved from WMI: $UUID" "INFO"
            return $UUID
        }
    } catch {
        Write-Log "Failed to get UUID via WMI: $_" "WARNING"
    }
   
    try {
        $reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name "MachineGuid" -ErrorAction Stop
        Write-Log "Machine ID retrieved from registry: $($reg.MachineGuid)" "INFO"
        return $reg.MachineGuid
    } catch {
        Write-Log "Failed to get Machine GUID from registry: $_" "WARNING"
        $fallbackId = [guid]::NewGuid().ToString()
        Write-Log "Using fallback Machine ID: $fallbackId" "WARNING"
        return $fallbackId
    }
}

function Get-TenantInfoFromJson {
    try {
        $tenantInfoPath = [System.IO.Path]::Combine($ProgramDataPath, "tenant_info", "tenant_details.json")
        if (Test-Path $tenantInfoPath) {
            $tenantData = Get-Content -Path $tenantInfoPath -Raw -ErrorAction Stop | ConvertFrom-Json
            return @{
                tenantId = $tenantData.tenant_id
                companyId = $tenantData.company_id
                branchId = $tenantData.branch_id
            }
        }
    } catch {
        Write-Log "Failed to read tenant info from JSON: $_" "WARNING"
    }
    return $null
}

$MachineID = Get-MachineID
$Hostname = $env:COMPUTERNAME

Write-Log "System Information:" "INFO"
Write-Log "  Machine ID: $MachineID" "INFO"
Write-Log "  Hostname: $Hostname" "INFO"

# -------------------------------------------------------------------------
# STEP 3: AUTHENTICATION & API FUNCTIONS
# -------------------------------------------------------------------------

function Get-AuthToken {
    try {
        $authApiUrl = "https://ebantisv4service.thekosmoz.com/api/v1/users/auth/login"
        $payload = @{
            userName = "internalmanager@mail.com"
            password = "#@Admin&eu1"
        } | ConvertTo-Json
        
        Write-Log "Authenticating to get access token..." "INFO"
        
        $response = Invoke-RestMethod -Uri $authApiUrl -Method Post -Body $payload -ContentType "application/json" -TimeoutSec 30
        
        if ($response.accessToken) {
            Write-Log "Access token obtained successfully." "INFO"
            return $response.accessToken
        } else {
            Write-Log "No access token found in authentication response." "WARNING"
            return $null
        }
    } catch {
        Write-Log "Authentication API request failed: $_" "WARNING"
        return $null
    }
}

function Update-UninstallationStatus {
    param(
        [string]$TenantId,
        [string]$BranchId
    )
    
    try {
        $authToken = Get-AuthToken
        if (-not $authToken) {
            Write-Log "Failed to obtain authentication token for uninstallation status update." "WARNING"
            return $false
        }
        
        $apiUrl = "https://ebantisv4service.thekosmoz.com/api/v1/app-installations"
        $headers = @{
            "Authorization" = "Bearer $authToken"
        }
        
        # Match Python uninstall_record: updates status to "Uninstalled"
        $payload = @{
            branchUniqueId = $BranchId
            tenantUniqueId = $TenantId
            hostName = $Hostname
            installedOn = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            isDownloaded = $false
            isInstalled = $false
            versionId = ""
            status = "Uninstalled"
            userName = $env:USERNAME
            userExternalId = 0
            email = ""
        } | ConvertTo-Json -Depth 10
        
        Write-Log "Updating uninstallation status to API for host: $Hostname" "INFO"
        
        try {
            $response = Invoke-RestMethod -Uri $apiUrl -Method Post -Body $payload -ContentType "application/json" -Headers $headers -TimeoutSec 30
            Write-Log "Uninstallation status updated successfully for host: $Hostname" "INFO"
            return $true
        } catch {
            # Try PUT method as fallback (in case API expects update of existing record)
            try {
                Write-Log "Trying PUT method as fallback..." "INFO"
                $response = Invoke-RestMethod -Uri "$apiUrl/$BranchId" -Method Put -Body $payload -ContentType "application/json" -Headers $headers -TimeoutSec 30
                Write-Log "Uninstallation status updated successfully (PUT method) for host: $Hostname" "INFO"
                return $true
            } catch {
                Write-Log "Failed to update uninstallation status via API: $_" "WARNING"
                return $false
            }
        }
    } catch {
        Write-Log "Error updating uninstallation status: $_" "WARNING"
        return $false
    }
}

# -------------------------------------------------------------------------
# STEP 4: PROCESS TERMINATION
# -------------------------------------------------------------------------

function Stop-EbantisProcesses {
    Write-Log "=== Stopping Ebantis Processes ===" "INFO"
    
    try {
        # Known process names to kill
        $knownProcesses = @("EbantisV4", "AutoUpdationService")
        $processesToKill = @()
        
        # Add known processes
        foreach ($ProcName in $knownProcesses) {
            $processesToKill += $ProcName
        }
        
        # Find processes from installation folders
        $MainFolder = [System.IO.Path]::Combine($ProgramFilesPath, "data", $AppName)
        $UtilsFolder = [System.IO.Path]::Combine($MainFolder, "utils")
        $UpdateFolder = [System.IO.Path]::Combine($MainFolder, "update")
        
        $foldersToCheck = @($MainFolder, $UtilsFolder, $UpdateFolder)
        
        foreach ($folder in $foldersToCheck) {
            if (Test-Path $folder) {
                $Exes = Get-ChildItem -Path $folder -Filter "*.exe" -ErrorAction SilentlyContinue
                foreach ($Exe in $Exes) {
                    $processName = $Exe.BaseName
                    if ($processName -notin $processesToKill) {
                        $processesToKill += $processName
                    }
                }
            }
        }
        
        # Kill all processes
        $processesToKill = $processesToKill | Select-Object -Unique
        $killedCount = 0
        
        foreach ($ProcName in $processesToKill) {
            $Procs = Get-Process -Name $ProcName -ErrorAction SilentlyContinue
            if ($Procs) {
                foreach ($Proc in $Procs) {
                    try {
                        Write-Log "Stopping process: $ProcName (PID: $($Proc.Id))" "INFO"
                        Stop-Process -Id $Proc.Id -Force -ErrorAction Stop
                        $killedCount++
                    } catch {
                        Write-Log "Failed to stop process $ProcName (PID: $($Proc.Id)): $_" "WARNING"
                    }
                }
            }
        }
        
        if ($killedCount -gt 0) {
            Write-Log "Waiting for processes to fully terminate..." "INFO"
            Start-Sleep -Seconds 5  # Wait longer for cleanup
        }
        
        Write-Log "Process termination completed. Killed $killedCount process(es)." "INFO"
        return $true
    } catch {
        Write-Log "Error stopping processes: $_" "ERROR"
        return $false
    }
}

# -------------------------------------------------------------------------
# STEP 5: REMOVE STARTUP SHORTCUTS
# -------------------------------------------------------------------------

function Remove-StartupShortcuts {
    Write-Log "=== Removing Startup Shortcuts ===" "INFO"
    
    try {
        $StartupFolder = [System.IO.Path]::Combine($env:ProgramData, "Microsoft\Windows\Start Menu\Programs\StartUp")
        $shortcutsToRemove = @("EbantisV4.lnk", "AutoUpdationService.lnk")
        $removedCount = 0
        
        foreach ($shortcutName in $shortcutsToRemove) {
            $shortcutPath = [System.IO.Path]::Combine($StartupFolder, $shortcutName)
            if (Test-Path $shortcutPath) {
                try {
                    Remove-Item -Path $shortcutPath -Force -ErrorAction Stop
                    Write-Log "Removed startup shortcut: $shortcutName" "INFO"
                    $removedCount++
                } catch {
                    Write-Log "Failed to remove shortcut $shortcutName : $_" "WARNING"
                }
            }
        }
        
        # Also remove any .bat files (old startup files)
        $batchFiles = @("ebantis.bat")
        foreach ($batchName in $batchFiles) {
            $batchPath = [System.IO.Path]::Combine($StartupFolder, $batchName)
            if (Test-Path $batchPath) {
                try {
                    Remove-Item -Path $batchPath -Force -ErrorAction Stop
                    Write-Log "Removed startup batch file: $batchName" "INFO"
                    $removedCount++
                } catch {
                    Write-Log "Failed to remove batch file $batchName : $_" "WARNING"
                }
            }
        }
        
        Write-Log "Startup shortcut removal completed. Removed $removedCount item(s)." "INFO"
        return $true
    } catch {
        Write-Log "Error removing startup shortcuts: $_" "ERROR"
        return $false
    }
}

# -------------------------------------------------------------------------
# STEP 6: REMOVE FILES AND FOLDERS
# -------------------------------------------------------------------------

function Remove-EbantisFiles {
    Write-Log "=== Removing Files and Folders ===" "INFO"
    
    $removedItems = 0
    
    try {
        # Remove Program Files directory
        if (Test-Path $ProgramFilesPath) {
            try {
                Write-Log "Removing Program Files directory: $ProgramFilesPath" "INFO"
                Remove-Item -Path $ProgramFilesPath -Recurse -Force -ErrorAction Stop
                Write-Log "Successfully removed Program Files directory." "INFO"
                $removedItems++
            } catch {
                Write-Log "Error removing Program Files directory: $_" "ERROR"
                Write-Log "Attempting to remove individual folders..." "WARNING"
                
                # Try removing subdirectories individually
                $subDirs = Get-ChildItem -Path $ProgramFilesPath -Directory -ErrorAction SilentlyContinue
                foreach ($subDir in $subDirs) {
                    try {
                        Remove-Item -Path $subDir.FullName -Recurse -Force -ErrorAction Stop
                        Write-Log "Removed subdirectory: $($subDir.Name)" "INFO"
                    } catch {
                        Write-Log "Failed to remove subdirectory $($subDir.Name): $_" "WARNING"
                    }
                }
            }
        } else {
            Write-Log "Program Files directory does not exist: $ProgramFilesPath" "INFO"
        }
        
        # Remove ProgramData directory (logs, tenant info, user collection, etc.)
        if (Test-Path $ProgramDataPath) {
            try {
                Write-Log "Removing ProgramData directory: $ProgramDataPath" "INFO"
                Remove-Item -Path $ProgramDataPath -Recurse -Force -ErrorAction Stop
                Write-Log "Successfully removed ProgramData directory." "INFO"
                $removedItems++
            } catch {
                Write-Log "Error removing ProgramData directory: $_" "ERROR"
                Write-Log "Attempting to remove individual folders..." "WARNING"
                
                # Try removing subdirectories individually
                $subDirs = Get-ChildItem -Path $ProgramDataPath -Directory -ErrorAction SilentlyContinue
                foreach ($subDir in $subDirs) {
                    try {
                        Remove-Item -Path $subDir.FullName -Recurse -Force -ErrorAction Stop
                        Write-Log "Removed subdirectory: $($subDir.Name)" "INFO"
                    } catch {
                        Write-Log "Failed to remove subdirectory $($subDir.Name): $_" "WARNING"
                    }
                }
                
                # Try to remove the parent directory after subdirectories are removed
                try {
                    Remove-Item -Path $ProgramDataPath -Force -ErrorAction Stop
                    Write-Log "Removed ProgramData parent directory after subdirectory cleanup." "INFO"
                } catch {
                    Write-Log "Could not remove ProgramData parent directory: $_" "WARNING"
                }
            }
        } else {
            Write-Log "ProgramData directory does not exist: $ProgramDataPath" "INFO"
        }
        
        Write-Log "File and folder removal completed. Removed $removedItems top-level directory/directories." "INFO"
        return $true
    } catch {
        Write-Log "Error in file/folder removal process: $_" "ERROR"
        return $false
    }
}

# -------------------------------------------------------------------------
# STEP 7: MAIN UNINSTALLATION FLOW
# -------------------------------------------------------------------------

try {
    Write-Log "=== Ebantis V4 Uninstallation Process Started ===" "INFO"
    
    # Step 1: Get tenant info (if available)
    $tenantInfo = Get-TenantInfoFromJson
    $TenantId = $null
    $BranchId = $null
    
    if ($tenantInfo) {
        $TenantId = $tenantInfo.tenantId
        $BranchId = $tenantInfo.branchId
        Write-Log "Retrieved tenant info - TenantId: $TenantId, BranchId: $BranchId" "INFO"
    } else {
        Write-Log "Tenant info not found. Uninstallation will continue without API status update." "WARNING"
    }
    
    # Step 2: Stop all processes
    Write-Log "Step 1: Stopping all Ebantis processes..." "INFO"
    $processResult = Stop-EbantisProcesses
    if (-not $processResult) {
        Write-Log "Warning: Some processes may not have been stopped." "WARNING"
    }
    
    # Step 3: Remove startup shortcuts
    Write-Log "Step 2: Removing startup shortcuts..." "INFO"
    $shortcutResult = Remove-StartupShortcuts
    if (-not $shortcutResult) {
        Write-Log "Warning: Some startup shortcuts may not have been removed." "WARNING"
    }
    
    # Step 4: Remove files and folders
    Write-Log "Step 3: Removing files and folders..." "INFO"
    $fileResult = Remove-EbantisFiles
    if (-not $fileResult) {
        Write-Log "Warning: Some files/folders may not have been removed." "WARNING"
    }
    
    # Step 5: Update API status (if tenant info is available)
    if ($TenantId -and $BranchId) {
        Write-Log "Step 4: Updating uninstallation status via API..." "INFO"
        $apiResult = Update-UninstallationStatus -TenantId $TenantId -BranchId $BranchId
        if (-not $apiResult) {
            Write-Log "Warning: Failed to update API status. Uninstallation will continue." "WARNING"
        }
    } else {
        Write-Log "Step 4: Skipping API status update (tenant info not available)" "INFO"
    }
    
    Write-Log "=== Ebantis V4 Uninstallation Process Completed ===" "INFO"
    Write-Log "Uninstallation completed successfully!" "INFO"
    Write-Log "Log file location: $LogFile" "INFO"
    
    # Success exit code
    Exit 0
    
} catch {
    Write-Log "=== FATAL ERROR IN UNINSTALLATION ===" "ERROR"
    Write-Log "Fatal error in uninstallation process: $_" "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"
    Write-Log "Uninstallation may have been incomplete. Check the log file for details: $LogFile" "ERROR"
    Exit 1
}
