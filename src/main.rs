// Windows subsystem - no console window
#![windows_subsystem = "windows"]

use std::env;
use std::path::PathBuf;
use std::process::{Command, Stdio};
<<<<<<< HEAD
=======
use wait_timeout::ChildExt;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
>>>>>>> 7b633b5c1ab0b08f21cc91b98148f2bcc4e1393d
use winapi::um::winbase::CREATE_NO_WINDOW;
use winapi::um::winuser::{MessageBoxW, MB_OK, MB_ICONERROR};

fn show_error(message: &str) {
    let wide: Vec<u16> = message.encode_utf16().chain(std::iter::once(0)).collect();
    let title: Vec<u16> = "Ebantis Installer Error\0".encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            wide.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONERROR
        );
    }
}

// Removed show_info function - no popup on success

fn extract_branch_id_from_msi_name() -> Option<String> {
    // Try multiple methods to get the MSI file path:
    // 1. Command-line argument (passed from WiX custom action)
    // 2. OriginalDatabase environment variable
    // 3. Executable path (env::args().nth(0))
    // 4. INSTALLER_PATH environment variable
    
    let msi_path = env::args()
        .nth(1)  // First argument after executable name
        .or_else(|| env::var("OriginalDatabase").ok())
        .or_else(|| env::args().nth(0))
        .or_else(|| env::var("INSTALLER_PATH").ok());
    
    if let Some(path) = msi_path {
        let path_buf = PathBuf::from(&path);
        if let Some(file_name) = path_buf.file_name() {
            if let Some(name_str) = file_name.to_str() {
                // Extract branch_id from format: installer_{branch_id}.msi or EbantisTrack_{branch_id}.msi
                // Branch ID can be any format (including UUIDs with hyphens)
                if name_str.ends_with(".msi") {
                    // Try installer_ prefix first
                    if let Some(start) = name_str.find("installer_") {
                        let after_prefix = &name_str[start + "installer_".len()..];
                        if let Some(end) = after_prefix.find(".msi") {
                            let branch_id = &after_prefix[..end];
                            if !branch_id.is_empty() {
                                return Some(branch_id.to_string());
                            }
                        }
                    }
                    // Fallback to EbantisTrack_ prefix for backward compatibility
                    else if let Some(start) = name_str.find("EbantisTrack_") {
                        let after_prefix = &name_str[start + "EbantisTrack_".len()..];
                        if let Some(end) = after_prefix.find(".msi") {
                            let branch_id = &after_prefix[..end];
                            if !branch_id.is_empty() {
                                return Some(branch_id.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    
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

<<<<<<< HEAD
=======
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

>>>>>>> 7b633b5c1ab0b08f21cc91b98148f2bcc4e1393d
fn main() {
    // Extract branch ID from MSI filename
    let branch_id = match extract_branch_id_from_msi_name() {
        Some(id) => id,
        None => {
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
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    
    match cmd.status() {
        Ok(status) => {
            if status.success() {
                // Silent success - no popup
                std::process::exit(0);
            } else {
                // Only show error popup on failure
                show_error(&format!(
                    "Installation failed with exit code: {}",
                    status.code().unwrap_or(-1)
                ));
                std::process::exit(1);
            }
        }
        Err(e) => {
            show_error(&format!("Failed to execute installer: {}", e));
            std::process::exit(1);
        }
    }
}
