# Python Installer - Complete Step-by-Step Installation Process

## Overview

This document provides a detailed, step-by-step breakdown of the Python-based Ebantis installer (`Ebantis_setup/`) installation process. Each step is documented with its purpose, code location, and execution order.

---

## Installation Flow Diagram

```
User runs: EbantisTracker_{branch_id}.exe
    ↓
[STEP 0] installation_run.py - Admin Check & Launch
    ↓
[STEP 1] InstallerUI - Initialize GUI
    ↓
[STEP 2] Initialize Tenant Information
    ↓
[STEP 3] Check Installation Allowed
    ↓
[STEP 4] InstallWorker.run() - Main Installation Thread
    ├─ [STEP 4.1] Clear Previous Version
    ├─ [STEP 4.2] Download Main Package
    ├─ [STEP 4.3] Extract Package
    ├─ [STEP 4.4] Update Folder Permissions (Parallel)
    ├─ [STEP 4.5] Install Wazuh Agent (Parallel)
    ├─ [STEP 4.6] Update Installation Status
    └─ [STEP 4.7] Launch Executables
```

---

## Detailed Step-by-Step Process

### **STEP 0: Entry Point & Admin Privilege Check**

**File**: `Ebantis_setup/installation_run.py`

**Purpose**: Ensure the installer runs with administrator privileges

**Process**:
1. Check if running as admin using `ctypes.windll.shell32.IsUserAnAdmin()`
2. If NOT admin:
   - Use `ShellExecuteW` with `"runas"` to relaunch with admin privileges
   - Exit current process
3. If admin:
   - Import logger from `utils.config`
   - Import and execute `installation.main()`

**Code Location**: Lines 1-34

---

### **STEP 1: Application Initialization & GUI Setup**

**File**: `Ebantis_setup/installation.pyx`

**Function**: `main()` → `InstallerUI.__init__()`

**Purpose**: Initialize PyQt6 application and create installation GUI

**Process**:
1. Create `QApplication` instance
2. Create `InstallerUI` widget:
   - Window title: "Ebantis Installation"
   - Fixed size: 650x350 pixels
   - Progress label: "Installation starting automatically..."
   - Progress bar (0-100%)
   - Exit button (disabled until completion)
3. Auto-start installation after 500ms delay using `QTimer.singleShot(500, self.start_installation_process)`

**Code Location**: Lines 1455-1460, 1303-1340

---

### **STEP 2: Tenant Information Initialization**

**File**: `Ebantis_setup/installation.pyx`

**Function**: `InstallerUI.start_installation_process()` → `initialize_tenant_info()`

**Purpose**: Extract branch ID from executable filename and fetch tenant details from API

**Sub-steps**:

#### **2.1 Extract Branch ID from Filename**
- **Function**: `extract_branch_id_from_filename()` (Lines 44-72)
- **Process**:
  1. Get executable filename: `os.path.basename(sys.executable)`
  2. Check if filename contains `"EbantisTracker_"`
  3. Split by `"EbantisTracker_"` and extract part after prefix
  4. Remove file extension (`.exe` or `.msi`)
  5. Return branch ID (e.g., `"8b56528f-eedd-4d34-8250-a2b4a07763d4"`)

#### **2.2 Fetch Tenant Information from API**
- **Function**: `get_tenant_info_by_branch_id(branch_id)` (Lines 74-124)
- **Process**:
  1. Get authentication token: `get_auth_token()`
  2. API Call: `GET https://qaebantisv4service.thekosmoz.com/api/v1/branches/branch/{branch_id}`
  3. Headers: `{"Authorization": "Bearer {auth_token}"}`
  4. Extract from response:
     - `tenantUniqueId` → `GLOBAL_TENANT_ID`
     - `companyUniqueId` → `GLOBAL_COMPANY_ID`
     - `branchId` → `GLOBAL_BRANCH_ID`
  5. Save to JSON file: `save_tenant_name_to_json()`

#### **2.3 Save Tenant Info to JSON**
- **Function**: `save_tenant_name_to_json()` (Lines 755-784)
- **File**: `C:\ProgramData\EbantisV4\tenant_info\tenant_details.json`
- **Content**:
  ```json
  {
    "tenant_id": "...",
    "company_id": "...",
    "branch_id": "..."
  }
  ```

**Code Location**: Lines 126-165, 1344-1350

---

### **STEP 3: Installation Validation Check**

**File**: `Ebantis_setup/installation.pyx`

**Function**: `check_installation_allowed(branch_id)` (Lines 484-540)

**Purpose**: Verify if installation is allowed based on device count limits

**Process**:
1. Get authentication token: `get_auth_token()`
2. API Call: `GET https://qaebantisv4service.thekosmoz.com/api/v1/app-versions/branches/{branch_id}`
3. Extract from response:
   - `allowedInstallationCount` - Maximum allowed installations
   - `installedDeviceCount` - Current installed count
4. Validation:
   - If `installedDeviceCount < allowedInstallationCount` → **Allowed**
   - If `installedDeviceCount >= allowedInstallationCount` → **Blocked**
5. If blocked: Show error message and exit
6. If allowed: Proceed to installation

**Code Location**: Lines 1361-1365

---

### **STEP 4: Main Installation Process**

**File**: `Ebantis_setup/installation.pyx`

**Class**: `InstallWorker` (QThread)

**Function**: `InstallWorker.run()` (Lines 1024-1300)

**Purpose**: Execute all installation steps in a background thread

**Progress Updates**: 
- 30% - Clearing previous version
- 40% - Downloading packages
- 50% - Permission updates & Wazuh install
- 100% - Installation completed

---

#### **STEP 4.1: Clear Previous Version**

**Progress**: 30%

**Functions**: `End_task()`, `remove_startup_file()`, `remove()`

**Purpose**: Remove any existing installation before proceeding

**Sub-steps**:

##### **4.1.1 Identify Running Processes**
- **Function**: `End_task()` (Lines 196-269)
- **Process**:
  1. Scan directories for `.exe` files:
     - `UTILS_PATH` = `C:\Program Files\EbantisV4\data\EbantisV4\utils`
     - `UPDATE_FOLDER_PATH` = `C:\Program Files\EbantisV4\data\EbantisV4\update`
     - `EXE_DIREC` = `C:\Program Files\EbantisV4\data\EbantisV4`
  2. Collect all `.exe` filenames into a list

##### **4.1.2 Kill Running Processes**
- **Process**:
  1. Iterate through all running processes using `psutil.process_iter()`
  2. Match process names against collected `.exe` filenames
  3. Kill matching processes: `proc.kill()`
  4. Wait up to 10 seconds for processes to terminate
  5. Verify all processes are killed

##### **4.1.3 Remove Directories**
- **Process**:
  1. Wait 2 seconds for Windows to release file handles
  2. Remove directories in parallel threads:
     - `UTILS_PATH`
     - `UPDATE_FOLDER_PATH`
     - `EXE_DIREC`
  3. Retry up to 5 times with 1-second delays if removal fails

##### **4.1.4 Remove Update Directory**
- **Function**: `remove(UPDATION_DIREC)` (Line 1033)
- **Directory**: `C:\Program Files\EbantisV4\data`

##### **4.1.5 Remove Startup Files**
- **Function**: `remove_startup_file()` (Lines 734-753)
- **Process**:
  1. Check startup folder: `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`
  2. Remove batch files matching: `ebantis*.bat`

**Code Location**: Lines 1027-1040

---

#### **STEP 4.2: Download Main Package**

**Progress**: 40%

**Function**: `download_main_package_with_extraction()` → `trigger_download()` → `cloud_dwnld()`

**Purpose**: Download application ZIP package from API

**Sub-steps**:

##### **4.2.1 Prepare Download**
- **Function**: `cloud_dwnld()` (Lines 856-998)
- **API URL**: `{CLOUD_DOWNLOAD_API}?branch_id={branch_id}`
- **Download Path**: `C:\ProgramData\EbantisV4\Ebantisv4.zip`
- **Extract Path**: `C:\Program Files\EbantisV4\data`

##### **4.2.2 Update Installation Status (Initial)**
- **Function**: `upsert_installation_data()` (Lines 325-399)
- **Status**: `isDownloaded: false`, `isInstalled: false`, `status: "inprogress"`
- **API Call**: `POST https://qaebantisv4service.thekosmoz.com/api/v1/app-installations`
- **Payload**:
  ```json
  {
    "branchUniqueId": "{branch_id}",
    "tenantUniqueId": "{tenant_id}",
    "hostName": "{hostname}",
    "installedOn": "{datetime}",
    "isDownloaded": false,
    "isInstalled": false,
    "versionId": "{version_id}",
    "status": "inprogress",
    "userName": "{display_name}",
    "userExternalId": {user_external_id},
    "email": "{email}"
  }
  ```

##### **4.2.3 Download ZIP File**
- **Process**:
  1. Check file size from server (HEAD request)
  2. If file > 5MB: Multi-threaded download (4 threads)
     - Each thread downloads a portion of the file
     - Uses `Range` headers for partial downloads
  3. If file ≤ 5MB: Single-threaded download
  4. Download using `requests.post()` with streaming
  5. Write chunks to file: `DATA_FILE_PATH`

##### **4.2.4 Validate Downloaded File**
- **Process**:
  1. Check if file exists
  2. Check if file size > 0
  3. Validate ZIP format: `zipfile.is_zipfile(download_path)`
  4. If invalid: Show error alert and abort

##### **4.2.5 Extract ZIP File**
- **Function**: `_robust_extract_zip()` (Lines 828-850)
- **Process**:
  1. Open ZIP file: `zipfile.ZipFile(download_path, "r")`
  2. Detect root directory in ZIP
  3. Extract all files to: `UPDATION_DIREC` = `C:\Program Files\EbantisV4\data`
  4. Strip root directory if present (robust extraction)

##### **4.2.6 Cleanup Downloaded ZIP**
- **Function**: `trigger_download()` (Lines 1000-1017)
- **Process**: Remove `DATA_FILE_PATH` after successful extraction

##### **4.2.7 Update Installation Status (Download Complete)**
- **Status**: `isDownloaded: true`, `isInstalled: false`, `status: "inprogress"`

**Code Location**: Lines 1042-1084

---

#### **STEP 4.3: Extract Package** (Already done in 4.2.5)

The extraction happens during download process, so this step is combined with download.

---

#### **STEP 4.4: Update Folder Permissions (Parallel)**

**Progress**: 50%

**Function**: `update_permission(folder)` (Lines 1136-1153)

**Purpose**: Set folder permissions to allow BUILTIN\Users Modify access

**Process**:
1. Execute in parallel for multiple folders using `ThreadPoolExecutor`
2. Folders to modify:
   - `USERS_FOLDER` = `C:\ProgramData\EbantisV4\user_collection`
   - `DOWNLOAD_ZIP_PATH` = `C:\Program Files\EbantisV4\data\downloaded_version`
   - `EXE_DIREC` = `C:\Program Files\EbantisV4\data\EbantisV4`

3. For each folder:
   - Create folder if it doesn't exist
   - Execute PowerShell command:
     ```powershell
     $acl = Get-Acl $folderPath
     $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
         "BUILTIN\Users",
         [System.Security.AccessControl.FileSystemRights]::Modify,
         [InheritanceFlags]::ContainerInherit -bor [InheritanceFlags]::ObjectInherit,
         [PropagationFlags]::None,
         [AccessControlType]::Allow
     )
     $acl.AddAccessRule($rule)
     Set-Acl -Path $folderPath -AclObject $acl
     ```

**Code Location**: Lines 1103-1153, 1248-1257

---

#### **STEP 4.5: Install Wazuh Agent (Parallel)**

**Progress**: 50%

**Function**: `install_wazuh()` (Lines 1155-1246)

**Purpose**: Download, install, and configure Wazuh security agent

**Sub-steps**:

##### **4.5.1 Configure Autostart**
- **Function**: `install_module.Autostart(startup_flag)` (Line 1158)
- **Purpose**: Create startup shortcut for Ebantis executables

##### **4.5.2 Download Wazuh MSI**
- **URL**: `https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.0-1.msi`
- **Destination**: `%TEMP%\wazuh-agent.msi`
- **Method**: PowerShell `Invoke-WebRequest`

##### **4.5.3 Install Wazuh MSI Silently**
- **Command**: `msiexec.exe /i wazuh-agent.msi /qn`
- **Parameters**:
  - `WAZUH_MANAGER=135.235.18.31`
  - `WAZUH_AGENT_GROUP=default,Windows`
  - `WAZUH_AGENT_NAME={hostname}`
- **Expected Return Codes**: 0, 3010 (reboot required), 1641 (success)

##### **4.5.4 Start Wazuh Service**
- **Command**: `NET START WazuhSvc`
- **Wait**: 5 seconds
- **Verify**: Check if service is running using `is_service_running("WazuhSvc")`

##### **4.5.5 Verify Agent Connection**
- **State File**: `C:\Program Files\ossec-agent\wazuh-agent.state` (or `C:\Program Files (x86)\ossec-agent\wazuh-agent.state`)
- **Process**:
  1. Check if state file exists
  2. Read file content
  3. Wait up to 120 seconds for "connected" status
  4. Check every 5 seconds
  5. If "pending" after 120 seconds: Show warning but continue

**Code Location**: Lines 1155-1246, 1254-1258

---

#### **STEP 4.6: Update Installation Status**

**Function**: `upsert_installation_data()` (Lines 325-399)

**Purpose**: Update API with final installation status

**Sub-steps**:

##### **4.6.1 Get Version ID**
- **Function**: `update_version_details(branch_id)` (Lines 590-633)
- **API Call**: `GET https://qaebantisv4service.thekosmoz.com/api/v1/app-versions/branches/{branch_id}`
- **Extract**: `versionId` from response

##### **4.6.2 Prepare Installation Data**
- **Gather Information**:
  - `hostname`: `socket.gethostname()`
  - `installed_date`: `datetime.now().isoformat()`
  - `user_name`: `display_name` (fallback to `user_name`)
  - `email`: From credentials or constructed
  - `user_external_id`: From decoded credentials (default: 0)

##### **4.6.3 Update Installation Status**
- **API Call**: `POST https://qaebantisv4service.thekosmoz.com/api/v1/app-installations`
- **Status**: 
  - `isDownloaded: true`
  - `isInstalled: true` (if Wazuh installation succeeded)
  - `status: "installed"` or `"failed"`

##### **4.6.4 Update Installed Device Count**
- **Function**: `update_installed_device_count(branch_id)` (Lines 541-588)
- **API Call**: `PUT https://qaebantisv4service.thekosmoz.com/api/v1/app-versions/branches/{branch_id}/installed-count`
- **Payload**: `{"installedDeviceCount": 1}`

**Code Location**: Lines 1272-1274

---

#### **STEP 4.7: Launch Executables**

**Function**: `InstallerUI.exe_run()` (Lines 1402-1420)

**Purpose**: Start Ebantis executables after successful installation

**Process**:
1. Wait for installation completion
2. Show success message box
3. When user clicks OK, execute `exe_run()`:
   - Scan directories for `.exe` files:
     - `UTILS_PATH` = `C:\Program Files\EbantisV4\data\EbantisV4\utils`
     - `UPDATE_FOLDER_PATH` = `C:\Program Files\EbantisV4\data\EbantisV4\update`
   - Launch each `.exe` file using `os.startfile(exe)`

**Code Location**: Lines 1385-1420

---

## Supporting Functions

### **Authentication**

**Function**: `get_auth_token()` (Lines 401-435)

**Purpose**: Authenticate with API to get access token

**Process**:
1. API Call: `POST https://qaebantisv4service.thekosmoz.com/api/v1/users/auth/login`
2. Payload:
   ```json
   {
     "userName": "internalmanager@mail.com",
     "password": "#@Admin&eu1"
   }
   ```
3. Extract: `accessToken` from response
4. Return token for use in subsequent API calls

---

### **Internet Connection Check**

**Function**: `is_connected()` (Lines 178-185)

**Purpose**: Verify internet connectivity before installation

**Process**:
1. Attempt TCP connection to `1.1.1.1:53` (Cloudflare DNS)
2. Timeout: 5 seconds
3. Return `True` if connection succeeds, `False` otherwise

**Note**: This check happens in the UI initialization, not shown in InstallWorker

---

### **Service Status Check**

**Function**: `is_service_running(service_name)` (Lines 306-323)

**Purpose**: Verify if a Windows service is running

**Process**:
1. Use `psutil.win_service_get(service_name)`
2. Check if `status == "running"`
3. Return boolean result

---

## Error Handling

### **Installation Failures**

1. **Tenant Info Initialization Failure**:
   - Show error: "Failed to initialize tenant information"
   - Exit installation

2. **Installation Not Allowed**:
   - Show error: "Maximum installations reached"
   - Exit installation

3. **Download Failure**:
   - Show error: "Download failed or file missing"
   - Update status: `status: "failed"`
   - Exit installation

4. **Permission Update Failure**:
   - Log warning
   - Continue installation (non-critical)

5. **Wazuh Installation Failure**:
   - Log error
   - Update status: `status: "failed"`
   - Exit installation

---

## File Paths Summary

| Purpose | Path |
|---------|------|
| **Program Files** | `C:\Program Files\EbantisV4` |
| **Program Data** | `C:\ProgramData\EbantisV4` |
| **Logs** | `C:\ProgramData\EbantisV4\Logs\Ebantis_setup_YYYY-MM-DD.log` |
| **Application Data** | `C:\Program Files\EbantisV4\data\EbantisV4` |
| **Utils** | `C:\Program Files\EbantisV4\data\EbantisV4\utils` |
| **Update** | `C:\Program Files\EbantisV4\data\EbantisV4\update` |
| **Downloaded ZIP** | `C:\ProgramData\EbantisV4\Ebantisv4.zip` |
| **Extract Location** | `C:\Program Files\EbantisV4\data` |
| **User Data** | `C:\ProgramData\EbantisV4\user_collection\{username}` |
| **Database** | `C:\ProgramData\EbantisV4\user_collection\{username}\tracking_system.db` |
| **Tenant Info JSON** | `C:\ProgramData\EbantisV4\tenant_info\tenant_details.json` |
| **Startup Folder** | `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp` |

---

## API Endpoints Used

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/users/auth/login` | POST | Get authentication token |
| `/api/v1/branches/branch/{branch_id}` | GET | Get tenant/company/branch info |
| `/api/v1/app-versions/branches/{branch_id}` | GET | Check installation allowed & get version |
| `/api/v1/app-installations` | POST | Update installation status |
| `/api/v1/app-versions/branches/{branch_id}/installed-count` | PUT | Update installed device count |
| `/DownloadLatestversion?branch_id={branch_id}` | POST | Download application ZIP |

---

## Summary

The Python installer follows this exact sequence:

1. **Entry**: Admin check and relaunch
2. **Initialize**: GUI setup and tenant info extraction
3. **Validate**: Check installation allowed
4. **Clean**: Remove previous installation
5. **Download**: Get application package from API
6. **Extract**: Unzip package to installation directory
7. **Configure**: Update folder permissions (parallel)
8. **Install**: Wazuh agent installation (parallel)
9. **Update**: Report installation status to API
10. **Launch**: Start Ebantis executables

All steps include comprehensive error handling, logging, and progress updates to the GUI.
