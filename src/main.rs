// Windows subsystem - no console window
#![windows_subsystem = "windows"]

use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use wait_timeout::ChildExt;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
use winapi::um::shellapi::ShellExecuteW;
#[cfg(windows)]
use winapi::um::winuser::SW_SHOW;
#[cfg(windows)]
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
#[cfg(windows)]
use winapi::um::securitybaseapi::GetTokenInformation;
#[cfg(windows)]
use winapi::um::winnt::{TOKEN_QUERY, TokenElevation, TOKEN_ELEVATION, HANDLE};
#[cfg(windows)]
use winapi::um::handleapi::CloseHandle;
#[cfg(windows)]
use winapi::shared::minwindef::LPVOID;
#[cfg(windows)]
use winapi::um::winbase::CREATE_NO_WINDOW;

use winapi::um::winuser::{MessageBoxW, MB_OK, MB_ICONERROR};

// Elevation Helpers
#[cfg(windows)]
fn is_elevated() -> bool {
    unsafe {
        let mut handle: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) == 0 {
            return false;
        }

        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
        let success = GetTokenInformation(
            handle,
            TokenElevation,
            &mut elevation as *mut _ as LPVOID,
            size,
            &mut size,
        );
        
        CloseHandle(handle);
        
        success != 0 && elevation.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
fn is_elevated() -> bool { false }

#[cfg(windows)]
fn run_elevated() -> bool {
    let exe_path = env::current_exe().unwrap_or_else(|_| PathBuf::from("ebantis-msi-installer.exe"));
    let exe_wstr: Vec<u16> = exe_path.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();
    let verb: Vec<u16> = "runas\0".encode_utf16().collect();
    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let cwd_wstr: Vec<u16> = cwd.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();

    // Pass original arguments forwarded
    let args: Vec<String> = env::args().skip(1).collect();
    let args_str = args.join(" ");
    let args_wstr: Vec<u16> = args_str.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        let result = ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            exe_wstr.as_ptr(),
            if args.is_empty() { std::ptr::null() } else { args_wstr.as_ptr() },
            cwd_wstr.as_ptr(),
            SW_SHOW,
        );
        // If result > 32, it succeeded
        result as usize > 32
    }
}

#[cfg(not(windows))]
fn run_elevated() -> bool { false }

fn log(msg: &str) {
    let program_data = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
    let log_dir = PathBuf::from(program_data).join("EbantisV4").join("Logs");
    
    // Ensure log directory exists
    let _ = std::fs::create_dir_all(&log_dir);
    
    let path = log_dir.join("Ebantis_Setup_Log.txt");
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        // Align with installer.ps1 format: Timestamp | Level | Message
        let level = if msg.starts_with("ERROR:") { "ERROR" } else if msg.starts_with("WARNING:") { "WARNING" } else { "INFO" };
        let content = if msg.contains(':') && (msg.starts_with("ERROR:") || msg.starts_with("WARNING:")) {
            msg.split_once(':').unwrap().1.trim()
        } else {
            msg
        };
        let _ = writeln!(file, "{} | {} | [EBANTIS] {}", timestamp, level, content);
    }
}

fn show_error(message: &str) {
    log(&format!("ERROR: {}", message));
    let wide: Vec<u16> = message.encode_utf16().chain(std::iter::once(0)).collect();
    let title: Vec<u16> = "Ebantis Installer Error\0".encode_utf16().chain(std::iter::once(0)).collect();
    
    // Add MB_SERVICE_NOTIFICATION (0x00200000L) to ensure it shows up if run as SYSTEM
    const MB_SERVICE_NOTIFICATION: u32 = 0x00200000;
    
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            wide.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONERROR | MB_SERVICE_NOTIFICATION
        );
    }
}

fn get_last_error_from_log() -> Option<String> {
    let program_data = env::var("ProgramData").ok()?;
    let log_dir = PathBuf::from(program_data).join("EbantisV4").join("Logs");
    
    if !log_dir.exists() {
        return None;
    }

    // Find the most recent log file
    let entries = std::fs::read_dir(log_dir).ok()?;
    let mut log_files: Vec<_> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .filter(|e| {
            let path = e.path();
            let ext = path.extension().and_then(|s| s.to_str());
            ext == Some("log") || ext == Some("txt")
        })
        .collect();

    if log_files.is_empty() {
        return None;
    }

    log_files.sort_by_key(|e| e.metadata().and_then(|m| m.modified()).ok());
    
    let last_log = log_files.last()?;
    let content = std::fs::read_to_string(last_log.path()).ok()?;
    
    // Find the last line containing "| ERROR |"
    content.lines()
        .rev()
        .find(|line| line.contains("| ERROR |"))
        .map(|line| {
            // Strip the timestamp and level if possible
            if let Some(pos) = line.find("| ERROR |") {
                line[pos + "| ERROR |".len()..].trim().to_string()
            } else {
                line.to_string()
            }
        })
}

fn extract_branch_id_from_msi_name() -> Option<String> {
    log("Attempting to extract Branch ID...");

    // Try environment variable first (if passed by MSI property)
    if let Ok(id) = env::var("EBANTIS_BRANCH_ID") {
        if !id.is_empty() && id != "[EBANTIS_BRANCH_ID]" {
            log(&format!("Found Branch ID in environment variable: {}", id));
            return Some(id);
        }
    }

    // Try 2nd command line argument (passed from WiX custom action)
    if let Some(id) = env::args().nth(2) {
        if !id.is_empty() && id != "[EBANTIS_BRANCH_ID]" {
            log(&format!("Found Branch ID in command line argument 2: {}", id));
            return Some(id);
        }
    }

    let msi_path = env::args()
        .nth(1)  // First argument after executable name
        .or_else(|| env::var("OriginalDatabase").ok())
        .or_else(|| env::var("INSTALLER_PATH").ok())
        .or_else(|| env::args().nth(0));
    
    log(&format!("MSI Path detected: {:?}", msi_path));

    if let Some(path) = msi_path {
        let path_buf = PathBuf::from(&path);
        if let Some(file_name) = path_buf.file_name() {
            if let Some(name_str) = file_name.to_str() {
                log(&format!("Analyzing filename: {}", name_str));
                
                // Find where the extension starts
                let end_pos = name_str.rfind('.').unwrap_or(name_str.len());
                let base_name = &name_str[..end_pos];

                let mut extracted_id = None;

                // 1. Try common prefixes first (exactly as in installer.ps1)
                if let Some(start) = base_name.find("installer_") {
                    extracted_id = Some(base_name[start + "installer_".len()..].to_string());
                } else if let Some(start) = base_name.find("EbantisTrack_") {
                    extracted_id = Some(base_name[start + "EbantisTrack_".len()..].to_string());
                } else if let Some(start) = base_name.find("EbantisV4_") {
                    extracted_id = Some(base_name[start + "EbantisV4_".len()..].to_string());
                } 
                // 2. Fallback: if there is an underscore, take everything after the LAST underscore
                else if let Some(pos) = base_name.rfind('_') {
                    extracted_id = Some(base_name[pos + 1..].to_string());
                }
                // 3. Last resort: use the whole name if it doesn't look like a generic setup name
                else if !base_name.to_lowercase().contains("setup") && !base_name.to_lowercase().contains("install") {
                    extracted_id = Some(base_name.to_string());
                }

                if let Some(mut id) = extracted_id {
                    log(&format!("Initial extraction: {}", id));
                    // Handle Windows copy suffixes like " (1)", " (2)", etc.
                    if let Some(pos) = id.rfind(" (") {
                        let suffix = &id[pos..];
                        if suffix.starts_with(" (") && suffix.ends_with(')') {
                            let inner = &suffix[2..suffix.len()-1];
                            if !inner.is_empty() && inner.chars().all(|c| c.is_ascii_digit()) {
                                id = id[..pos].to_string();
                            }
                        }
                    }
                    
                    if let Some(pos) = id.rfind('_') {
                        let suffix = &id[pos+1..];
                        if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
                            if pos > 0 {
                                id = id[..pos].to_string();
                            }
                        }
                    }

                    if !id.is_empty() {
                        log(&format!("Final extracted Branch ID: {}", id));
                        return Some(id);
                    }
                }
            }
        }
    }
    
    log("Failed to extract Branch ID from any source.");
    None
}

fn get_installer_script_path() -> PathBuf {
    // Get the directory where the executable is located
    let exe_dir = env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    
    // Look for installer.ps1 in the same directory
    let script_path = exe_dir.join("installer.ps1");
    
    if script_path.exists() {
        return script_path;
    }
    
    // Fallback: try current directory
    PathBuf::from("installer.ps1")
}

fn cleanup_old_installations() {
    log("Checking for existing product registrations to scrub...");
    
    let current_pid = std::process::id();
    log(&format!("Current Bootstrapper PID: {}", current_pid));

    // Multi-stage scrubbing logic
    // We use format! to inject the current PID so we don't kill ourselves
    // We also define a mini-logger here to ensure these pre-install actions are recorded in the main log file
    let script_template = r#"
        $LogFile = "C:\ProgramData\EbantisV4\Logs\Ebantis_Setup_Log.txt"
        $LogDir = [System.IO.Path]::GetDirectoryName($LogFile)
        if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
        
        function Write-CleanupLog {
            param([string]$Message)
            $Entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | INFO | [CLEANUP] $Message"
            Add-Content -Path $LogFile -Value $Entry -Encoding UTF8 -ErrorAction SilentlyContinue
            Write-Host $Message
        }

        $MyPid = {CURRENT_PID}
        Write-CleanupLog "Starting Pre-Install Cleanup. Current Bootstrapper PID: $MyPid"
        
        # Check Admin Status
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        Write-CleanupLog "Running as Admin: $isAdmin"

        # ----------------------------------------------------------------
        # 0. Kill stuck Installer/Setup tasks
        # ----------------------------------------------------------------
        
        # Check for msiexec
        $msiProcs = Get-Process -Name "msiexec" -ErrorAction SilentlyContinue
        if ($msiProcs) {
            $pids = $msiProcs.Id -join ', '
            Write-CleanupLog "Found $($msiProcs.Count) running msiexec processes. PIDs: $pids"
            Write-CleanupLog "Attempting to force kill msiexec.exe via taskkill..."
            
            taskkill /F /IM msiexec.exe /T 2>&1 | Out-Null
            
            Start-Sleep -Milliseconds 500
            $leftover = Get-Process -Name "msiexec" -ErrorAction SilentlyContinue
            if ($leftover) {
                Write-CleanupLog "taskkill finished, but $($leftover.Count) msiexec processes remain. Trying Stop-Process..."
                $leftover | Stop-Process -Force -ErrorAction SilentlyContinue
            } else {
                Write-CleanupLog "All msiexec processes terminated."
            }
        } else {
            Write-CleanupLog "No running msiexec processes found."
        }

        # Check for other ebantis-msi-installer instances
        $setupProcs = Get-Process -Name "ebantis-msi-installer" -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne $MyPid }
        if ($setupProcs) {
            $pids = $setupProcs.Id -join ', '
            Write-CleanupLog "Found $($setupProcs.Count) other installer instances. PIDs: $pids"
            
            taskkill /F /IM ebantis-msi-installer.exe /T 2>&1 | Out-Null
            
            Start-Sleep -Milliseconds 500
            $setupProcs | Stop-Process -Force -ErrorAction SilentlyContinue
        } else {
            Write-CleanupLog "No other installer instances found."
        }

        # ----------------------------------------------------------------
        # 1. Kill any running Ebantis Application processes
        # ----------------------------------------------------------------
        $appProcs = Get-Process | Where-Object { $_.Name -like '*Ebantis*' -or $_.Name -like '*AutoUpdation*' } | Where-Object { $_.Id -ne $MyPid }
        if ($appProcs) {
            Write-CleanupLog "Stopping $($appProcs.Count) application processes..."
            $appProcs | Stop-Process -Force -ErrorAction SilentlyContinue
        }

        # ----------------------------------------------------------------
        # 2. Registries and Folders
        # ----------------------------------------------------------------
        Write-CleanupLog "Checking for legacy packages to uninstall..."
        Get-Package -Name '*Ebantis*' -ErrorAction SilentlyContinue | Uninstall-Package -Force -ErrorAction SilentlyContinue

        # 3. Search Registry for ANY ProductCode related to Ebantis
        $paths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKLM:\SOFTWARE\Classes\Installer\Products"
        )
        
        foreach ($path in $paths) {
            if (Test-Path $path) {
                Get-ChildItem -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
                    $name = $_.GetValue("ProductName")
                    if (-not $name) { $name = $_.GetValue("DisplayName") }
                    
                    if ($name -and $name -like "*Ebantis*") {
                        $code = $_.PSChildName
                        Write-CleanupLog "Force scrubbing Product ID: $code ($name)"
                        
                        # If it's a GUID format (from Uninstall), use msiexec to clean internal DB
                        if ($code -match '^\{.*\}$') {
                            # If we are here, we should have killed msiexec already, so this might work, 
                            # but safer to just nuke registry to avoid re-triggering the mutex we just freed.
                            # Start-Process msiexec.exe -ArgumentList "/x $code /qn /norestart" -Wait -ErrorAction SilentlyContinue
                            Write-CleanupLog "Skipping msiexec /x for cleanup to prevent mutex race. Nuking registry key instead."
                        }
                        
                        # Nuke the registry key directly to clear the 'already installed' block
                        Remove-Item -Path $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        }

        # 4. Cleanup the installation folders
        $progFiles = "${env:ProgramFiles}\EbantisV4"
        if (Test-Path $progFiles) {
            Write-CleanupLog "Removing installation folder: $progFiles"
            Remove-Item -Path $progFiles -Recurse -Force -ErrorAction SilentlyContinue
        }
    "#;

    let registry_nuke = script_template.replace("{CURRENT_PID}", &current_pid.to_string());

    let mut cmd = Command::new("powershell.exe");
    cmd.args(&["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &registry_nuke]);
    #[cfg(windows)]
    {
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    
    match cmd.spawn() {
        Ok(mut child) => {
            // Wait up to 60 seconds for cleanup to finish (increased time since we are killing things)
            let timeout = std::time::Duration::from_secs(60);
            match child.wait_timeout(timeout) {
                Ok(Some(status)) => log(&format!("Force cleanup routine finished with status: {:?}", status)),
                Ok(None) => {
                    log("Cleanup routine timed out after 60s. Killing process and continuing...");
                    let _ = child.kill();
                }
                Err(e) => log(&format!("Error waiting for cleanup: {}", e)),
            }
        }
        Err(e) => log(&format!("Failed to spawn cleanup process: {}", e)),
    }
}

fn launch_msi_with_logging() {
    let msi_name = "EbantisV4_Setup.msi";
    let log_path = "C:\\Ebantis_Setup_Log.txt";
    
    log(&format!("Bootstrapper: Starting MSI with forced logging into {}", log_path));
    
    // Command: msiexec /i "EbantisV4_Setup.msi" /L*v "C:\Ebantis_Setup_Log.txt" /qn
    let mut cmd = Command::new("msiexec.exe");
    cmd.args(&[
        "/i", msi_name,
        "/L*v", log_path,
        "/qn" // Added /qn for quiet install, remove if you want the UI
    ]);
    
    match cmd.spawn() {
        Ok(_) => log("Bootstrapper: MSI process launched successfully."),
        Err(e) => log(&format!("Bootstrapper: Failed to launch MSI: {}", e)),
    }
}

fn main() {
    log("Starting Ebantis Wrapper execution");

    // Get command line args to see if we are running as a Bootstrapper or inside MSI
    let args: Vec<String> = env::args().collect();
    
    // If run without special MSI flags (like /i or /x), act as the Setup Bootstrapper
    // This is a heuristic; a more robust check might involve looking for specific WiX custom action properties.
    // For now, if the first argument is not an MSI command, assume standalone.
    if args.len() <= 1 || (args.len() > 1 && !args[1].starts_with('/') && !args[1].ends_with(".msi")) {
        
        // --- ELEVATION CHECK (Only for Bootstrapper) ---
        if !is_elevated() {
            log("Process is NOT running as Administrator. Attempting to restart with elevation...");
            
            if run_elevated() {
                 log("Restarted with RunAs. Exiting current process.");
                 std::process::exit(0);
            } else {
                 log("Failed to elevate process. User returned 'No' or UAC error.");
                 show_error("This installer requires Administrator privileges to clean up previous versions.\n\nPlease permit the UAC prompt or run as Administrator.");
                 std::process::exit(1);
            }
        }
        log("Running with Administrator privileges.");
        // -----------------------------------------------
        
        log("Detected Standalone execution. Acting as Setup Bootstrapper...");
        cleanup_old_installations();
        launch_msi_with_logging();
        // The MSI process will run independently, so we can exit.
        std::process::exit(0); 
    }

    // --- ORIGINAL MSI CUSTOM ACTION LOGIC (when run as a custom action from MSI) ---
    // When running inside MSI, we should NOT call cleanup_old_installations() 
    // if it tries to use msiexec /x because it will deadlock/fail.
    // The installer.ps1 also has its own cleanup which we should be careful with.
    log("Running in MSI Custom Action mode. Skipping main scrubbing to avoid msiexec conflicts.");
    // cleanup_old_installations(); // SKIP THIS in MSI mode
    
    // Extract branch ID from MSI filename
    let branch_id = match extract_branch_id_from_msi_name() {
        Some(id) => {
            log(&format!("Extracted Branch ID: {}", id));
            id
        },
        None => {
            // If running as a custom action and branch ID can't be extracted, it's an error.
            show_error("Failed to extract branch ID from MSI filename.\n\nExpected format: installer_{branch_id}.msi or EbantisTrack_{branch_id}.msi\n\nPlease ensure the MSI file follows this naming convention.");
            std::process::exit(1);
        }
    };
    
    // Get PowerShell script path
    let script_path = get_installer_script_path();
    
    if !script_path.exists() {
        show_error(&format!(
            "PowerShell installer script not found at:\n{}\n\nPlease ensure installer.ps1 is in the same directory as the MSI.",
            script_path.display()
        ));
        std::process::exit(1);
    }
    
    // Set environment variable for branch ID
    env::set_var("EBANTIS_BRANCH_ID", &branch_id);
    
    // Execute PowerShell script with admin privileges
    // The script will check for admin and elevate if needed
    // Use CREATE_NO_WINDOW to hide the PowerShell console window
    let mut cmd = Command::new("powershell.exe");
    cmd.args(&[
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-WindowStyle",
        "Hidden",
        "-File",
        script_path.to_str().unwrap(),
    ]);
    cmd.env("EBANTIS_BRANCH_ID", &branch_id);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::null());  // Suppress output
    cmd.stderr(Stdio::null());  // Suppress errors
    // Hide PowerShell window using CREATE_NO_WINDOW flag
    #[cfg(windows)]
    {
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    
    log("Executing PowerShell installer script...");
    match cmd.status() {
        Ok(status) => {
            if status.success() {
                log("PowerShell installer script completed successfully.");
                // Silent success - no popup
                std::process::exit(0);
            } else {
                log(&format!("PowerShell script failed with exit code: {}", status.code().unwrap_or(-1)));
                // Try to get a more specific error from the log file
                let mut error_msg = format!("Installation failed with exit code: {}", status.code().unwrap_or(-1));
                
                if let Some(specific_error) = get_last_error_from_log() {
                    error_msg = format!("{}\n\nReason: {}", error_msg, specific_error);
                }
                
                error_msg = format!("{}\n\nPlease check the log files in C:\\ProgramData\\EbantisV4\\Logs for more details.", error_msg);
                
                show_error(&error_msg);
                std::process::exit(1);
            }
        }
        Err(e) => {
            show_error(&format!("Failed to execute installer: {}\n\nPlease ensure PowerShell is available and you have administrative privileges.", e));
            std::process::exit(1);
        }
    }
}
