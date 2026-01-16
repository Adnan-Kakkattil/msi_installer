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
use winapi::um::winbase::CREATE_NO_WINDOW;

use winapi::um::winuser::{MessageBoxW, MB_OK, MB_ICONERROR};

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
        let _ = writeln!(file, "{} | [EBANTIS] {}", timestamp, msg);
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
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("log"))
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

                // Try installer_ prefix first
                if let Some(start) = base_name.find("installer_") {
                    extracted_id = Some(base_name[start + "installer_".len()..].to_string());
                }
                // Fallback to EbantisTrack_ prefix
                else if let Some(start) = base_name.find("EbantisTrack_") {
                    extracted_id = Some(base_name[start + "EbantisTrack_".len()..].to_string());
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
    
    // Multi-stage scrubbing logic
    let registry_nuke = r#"
        # 1. Kill any running Ebantis processes first
        $procs = Get-Process | Where-Object { $_.Name -like '*Ebantis*' -or $_.Name -like '*AutoUpdation*' }
        if ($procs) {
            Write-Host "Stopping $($procs.Count) processes..."
            $procs | Stop-Process -Force -ErrorAction SilentlyContinue
        }

        # 2. Try standard uninstallation by name
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
                        Write-Output "Force scrubbing Product ID: $code ($name)"
                        
                        # If it's a GUID format (from Uninstall), use msiexec to clean internal DB
                        if ($code -match '^\{.*\}$') {
                            Start-Process msiexec.exe -ArgumentList "/x $code /qn /norestart" -Wait -ErrorAction SilentlyContinue
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
            # Try to rename first if locked, then schedule for delete
            Remove-Item -Path $progFiles -Recurse -Force -ErrorAction SilentlyContinue
        }
    "#;

    let mut cmd = Command::new("powershell.exe");
    cmd.args(&["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", registry_nuke]);
    #[cfg(windows)]
    {
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    
    match cmd.spawn() {
        Ok(mut child) => {
            // Wait up to 30 seconds for cleanup to finish
            let timeout = std::time::Duration::from_secs(30);
            match child.wait_timeout(timeout) {
                Ok(Some(status)) => log(&format!("Force cleanup routine finished with status: {:?}", status)),
                Ok(None) => {
                    log("Cleanup routine timed out after 30s. Killing process and continuing...");
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
        log("Detected Standalone execution. Acting as Setup Bootstrapper...");
        cleanup_old_installations();
        launch_msi_with_logging();
        // The MSI process will run independently, so we can exit.
        // If we wanted to wait for it, we'd use cmd.status() instead of cmd.spawn().
        std::process::exit(0); 
    }

    // --- ORIGINAL MSI CUSTOM ACTION LOGIC (when run as a custom action from MSI) ---
    // Forcefully remove any existing traces before starting (this was moved here from the top of main)
    cleanup_old_installations();
    
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
