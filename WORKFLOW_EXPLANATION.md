# Ebantis MSI Installer - Workflow Explanation

## Overview

This project converts a Python-based installer to a PowerShell-based installer and packages it as an MSI file using Rust. The MSI installer extracts branch IDs from the filename and executes the PowerShell installation script.

---

## Architecture Comparison

### **Original Python Installer (Ebantis_setup/)**

The Python installer was a standalone executable built with PyInstaller that included:

1. **Entry Point**: `installation_run.py`
   - Checks for admin privileges
   - Relaunches with admin if needed
   - Imports and runs `installation.pyx` (Cython module)

2. **Main Installation Logic**: `installation.pyx`
   - Extracts branch ID from executable filename (`EbantisTracker_{branch_id}.exe`)
   - Fetches tenant information from API using branch ID
   - Downloads application package from cloud
   - Extracts ZIP files
   - Updates folder permissions
   - Installs Wazuh agent
   - Configures autostart
   - Updates installation status via API
   - Uses PyQt6 for GUI progress display

3. **Key Features**:
   - GUI-based installation with progress bar
   - Multi-threaded downloads
   - SQLite database for credentials
   - MongoDB connection validation
   - Service registration

### **New PowerShell + MSI Installer**

The new system uses a three-layer approach:

1. **MSI Package** (WiX Toolset)
   - Traditional Windows installer experience
   - Extracts files to `C:\Program Files\EbantisV4\`
   - Runs Rust executable as custom action

2. **Rust Executable** (`src/main.rs`)
   - Extracts branch ID from MSI filename
   - Sets `EBANTIS_BRANCH_ID` environment variable
   - Executes PowerShell script

3. **PowerShell Script** (`installer.ps1`)
   - Complete installation flow converted from Python
   - Reads branch ID from environment variable
   - Performs all installation steps

---

## Detailed Workflow

### **Python Installer Flow (Original)**

```
User runs: EbantisTracker_{branch_id}.exe
    ↓
installation_run.py:
  - Checks admin privileges
  - Relaunches with admin if needed
    ↓
installation.pyx:
  - extract_branch_id_from_filename()
    → Extracts {branch_id} from exe name
  - initialize_tenant_info()
    → API call: GET /api/v1/branches/branch/{branch_id}
    → Gets tenant_id, company_id, branch_id
    → Saves to JSON file
  - check_installation_allowed(branch_id)
    → API call: GET /api/v1/app-versions/branches/{branch_id}
    → Checks installed vs allowed device count
  - InstallWorker.run() (QThread):
    ├─ End_task() - Kill processes, remove old installation
    ├─ trigger_download() - Download ZIP from API
    ├─ Extract ZIP to UPDATION_DIREC
    ├─ update_permission() - Set folder permissions (PowerShell)
    ├─ install_wazuh() - Download & install Wazuh agent
    └─ upsert_installation_data() - Update API status
  - InstallerUI (PyQt6):
    └─ Shows progress bar and status
```

### **PowerShell + MSI Installer Flow (New)**

```
User runs: EbantisTrack_{branch_id}.msi
    ↓
MSI Installation (WiX):
  - Extracts files to C:\Program Files\EbantisV4\
    ├─ ebantis-msi-installer.exe (Rust)
    └─ installer.ps1 (PowerShell)
  - Custom Action: Runs ebantis-msi-installer.exe
    ↓
Rust Executable (src/main.rs):
  - extract_branch_id_from_msi_name()
    → Reads OriginalDatabase env var (MSI filename)
    → Extracts {branch_id} from "EbantisTrack_{branch_id}.msi"
  - Sets: env::set_var("EBANTIS_BRANCH_ID", branch_id)
  - Executes: installer.ps1
    ↓
PowerShell Script (installer.ps1):
  - Test-IsAdmin() - Checks admin, elevates if needed
  - Initialize-TenantInfo()
    → Reads $env:EBANTIS_BRANCH_ID
    → API call: GET /api/v1/branches/branch/{branch_id}
    → Gets tenant_id, company_id, branch_id
    → Saves to JSON file
  - Test-InstallationAllowed()
    → API call: GET /api/v1/app-versions/branches/{branch_id}
  - Main Installation:
    ├─ Stop-EbantisProcesses() - Kill running processes
    ├─ Remove-ExistingInstallation() - Clean old install
    ├─ Download-AppPackage() - Download ZIP from API
    ├─ Extract-AppPackage() - Extract ZIP
    ├─ Update-FolderPermissions() - Set permissions
    ├─ Configure-Autostart() - Create startup shortcut
    ├─ Find-EbantisExecutables() - Locate .exe files
    ├─ Start-EbantisExecutables() - Launch apps
    └─ Update-InstallationData() - Update API status
```

---

## Key Conversion Points

### **1. Branch ID Extraction**

**Python:**
```python
def extract_branch_id_from_filename():
    exe_name = os.path.basename(sys.executable)
    if "EbantisTracker_" in exe_name:
        parts = exe_name.split("EbantisTracker_")
        branch_id = parts[1].rsplit('.', 1)[0]
        return branch_id
```

**Rust:**
```rust
fn extract_branch_id_from_msi_name() -> Option<String> {
    let msi_path = env::var("OriginalDatabase").ok()?;
    // Extract from "EbantisTrack_{branch_id}.msi"
    // Returns branch_id
}
```

**PowerShell:**
```powershell
$BranchId = $env:EBANTIS_BRANCH_ID
if (-not $BranchId) {
    # Fallback: extract from script filename
    $BranchId = Extract-BranchIdFromFilename
}
```

### **2. Admin Privilege Check**

**Python:**
```python
def is_admin():
    return ctypes.windll.shell32.IsUserAnAdmin()

if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1
    )
```

**PowerShell:**
```powershell
function Test-IsAdmin {
    $Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = [System.Security.Principal.WindowsPrincipal]$Identity
    return $Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Start-Process powershell -ArgumentList "-File `"$PSCommandPath`"" -Verb RunAs
    Exit
}
```

### **3. API Calls**

**Python:**
```python
auth_token = get_auth_token()
headers = {"Authorization": f"Bearer {auth_token}"}
response = requests.get(api_url, headers=headers, verify=False)
```

**PowerShell:**
```powershell
$AuthToken = Get-AuthToken
$Headers = @{
    "Authorization" = "Bearer $AuthToken"
}
$Response = Invoke-RestMethod -Uri $ApiUrl -Headers $Headers -Method Get -SkipCertificateCheck
```

### **4. File Downloads**

**Python:**
```python
with requests.post(api_url, stream=True) as response:
    with open(download_path, "wb") as file:
        for chunk in response.iter_content(chunk_size=8192):
            file.write(chunk)
```

**PowerShell:**
```powershell
$Response = Invoke-WebRequest -Uri $ApiUrl -Method Post -OutFile $DownloadPath -UseBasicParsing
```

### **5. ZIP Extraction**

**Python:**
```python
with zipfile.ZipFile(download_path, "r") as zip_ref:
    _robust_extract_zip(zip_ref, extract_path)
```

**PowerShell:**
```powershell
Expand-Archive -Path $DownloadPath -DestinationPath $ExtractPath -Force
```

### **6. Folder Permissions**

**Python:**
```python
ps_command = command_template.format(folder=folder)
subprocess.run(["powershell", "-noprofile", "-command", ps_command])
```

**PowerShell:**
```powershell
$acl = Get-Acl $folderPath
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\Users",
    [System.Security.AccessControl.FileSystemRights]::Modify,
    ...
)
$acl.AddAccessRule($rule)
Set-Acl -Path $folderPath -AclObject $acl
```

---

## File Structure

```
msi_installer/
├── Ebantis_setup/                    # Original Python installer
│   ├── installation_run.py          # Entry point (admin check, launch)
│   ├── installation.pyx              # Main installation logic (Cython)
│   ├── encryption.py                 # Credential decryption
│   ├── utils/
│   │   ├── config.py                # Configuration & logging
│   │   ├── service.pyx              # Service registration (Cython)
│   │   └── service.c                # C extension source
│   └── update/
│       └── AutoUpdaterService.py     # Auto-update service
│
├── src/
│   └── main.rs                       # Rust executable (extracts branch ID, runs PS)
│
├── wix/
│   └── main.wxs                      # WiX installer configuration
│
├── installer.ps1                     # PowerShell installation script (converted from Python)
├── build.ps1                         # Build automation script
├── build_msi.ps1                     # Alternative build script
├── Cargo.toml                        # Rust project configuration
├── wix.toml                          # cargo-wix configuration
├── build.rs                          # Rust build script
│
└── Documentation/
    ├── BUILD_INSTRUCTIONS.md         # Build instructions
    ├── README.md                     # Project overview
    ├── PROJECT_SUMMARY.md            # Project summary
    └── WORKFLOW_EXPLANATION.md       # This file
```

---

## Key Differences

| Aspect | Python Installer | PowerShell + MSI Installer |
|--------|------------------|---------------------------|
| **Packaging** | PyInstaller EXE | MSI package (WiX) |
| **Entry Point** | Python script | Rust executable |
| **Branch ID Source** | Executable filename | MSI filename → Env var |
| **GUI** | PyQt6 window | No GUI (silent/console) |
| **Admin Check** | ctypes.windll.shell32 | PowerShell Test-IsAdmin |
| **Dependencies** | Python, PyQt6, Cython | PowerShell (built-in) |
| **Distribution** | Single EXE file | MSI installer |
| **Installation Experience** | Custom GUI | Standard MSI wizard |

---

## Advantages of New Approach

1. **Standard MSI Experience**: Users get familiar Windows installer UI
2. **No Python Runtime**: No need to bundle Python interpreter
3. **Smaller Package**: PowerShell is built into Windows
4. **Better Integration**: MSI integrates with Windows Installer service
5. **Easier Updates**: MSI supports upgrade/uninstall workflows
6. **Corporate Friendly**: MSI is standard for enterprise deployments

---

## What Was Preserved

✅ All installation logic from Python
✅ API communication patterns
✅ Download and extraction flows
✅ Permission management
✅ Process management
✅ Status updates to API
✅ Error handling
✅ Logging functionality

## What Was Removed/Changed

❌ PyQt6 GUI (replaced with console output)
❌ Wazuh installation (excluded from PowerShell version)
❌ Uninstaller (separate implementation)
❌ MongoDB DNS validation (simplified)
❌ Multi-threaded downloads (simplified to single-threaded)

---

## Build Process

1. **Build Rust Executable**:
   ```powershell
   cargo build --release
   ```
   Creates: `target/release/ebantis-msi-installer.exe`

2. **Create MSI Package**:
   ```powershell
   cargo wix
   ```
   Creates: `target/wix/ebantis-msi-installer-4.0.0-x86_64.msi`

3. **Rename with Branch ID**:
   ```powershell
   Rename-Item "target\wix\ebantis-msi-installer-4.0.0-x86_64.msi" "EbantisTrack_{branch_id}.msi"
   ```

4. **Distribute MSI**:
   - Users double-click MSI
   - MSI extracts files and runs installer
   - Installation completes automatically

---

## Testing the Conversion

To verify the PowerShell script matches Python behavior:

1. **Compare API Calls**: Both use same endpoints and payloads
2. **Compare File Operations**: Same paths and operations
3. **Compare Error Handling**: Similar error messages and logging
4. **Test Installation**: Run both installers and compare results

---

## Summary

The project successfully converts a Python-based installer to a PowerShell-based installer packaged as an MSI. The Rust executable acts as a bridge between the MSI package and PowerShell script, extracting the branch ID from the MSI filename and passing it to the PowerShell script via environment variable. All core installation logic has been preserved while improving the user experience with a standard MSI installer.
