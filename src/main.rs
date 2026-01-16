// Windows subsystem - no console window
#![windows_subsystem = "windows"]

use std::env;
use std::path::PathBuf;
use std::process::{Command, Stdio};
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
                
                // Find where the extension starts (handle cases like .msi or .exe)
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
                    // Handle Windows copy suffixes like " (1)", " (2)", etc.
                    if let Some(pos) = id.rfind(" (") {
                        let suffix = &id[pos..];
                        // Check if suffix matches " (\d+)"
                        if suffix.starts_with(" (") && suffix.ends_with(')') {
                            let inner = &suffix[2..suffix.len()-1];
                            if !inner.is_empty() && inner.chars().all(|c| c.is_ascii_digit()) {
                                id = id[..pos].to_string();
                            }
                        }
                    }
                    
                    // Also handle "_" suffixes if they exist (sometimes browsers do this)
                    if let Some(pos) = id.rfind('_') {
                        let suffix = &id[pos+1..];
                        if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
                            // Only strip if it's likely a copy suffix (e.g. EbantisTrack_abc_1)
                            // This is a bit riskier as branch IDs might have underscores, 
                            // but usually they are UUIDs or alphanumeric.
                            // We only strip if the part before is not empty.
                            if pos > 0 {
                                id = id[..pos].to_string();
                            }
                        }
                    }

                    if !id.is_empty() {
                        return Some(id);
                    }
                }
            }
        }
    }
    
    None
}

fn get_script_path(is_uninstall: bool) -> PathBuf {
    // Get the directory where the executable is located
    let exe_dir = env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    
    // Look for installer.ps1 or uninstaller.ps1 in the same directory
    let script_name = if is_uninstall { "uninstaller.ps1" } else { "installer.ps1" };
    let script_path = exe_dir.join(script_name);
    
    if script_path.exists() {
        return script_path;
    }
    
    // Fallback: try current directory
    PathBuf::from(script_name)
}

fn execute_uninstaller() -> i32 {
    // For uninstallation, we don't need branch ID
    let script_path = get_script_path(true);
    
    if !script_path.exists() {
        show_error(&format!(
            "PowerShell uninstaller script not found at:\n{}\n\nPlease ensure uninstaller.ps1 is in the same directory as the MSI.",
            script_path.display()
        ));
        return 1;
    }
    
    // Execute PowerShell uninstaller script with admin privileges
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
                return 0;
            } else {
                // Try to get a more specific error from the log file
                let mut error_msg = format!("Uninstallation failed with exit code: {}", status.code().unwrap_or(-1));
                
                if let Some(specific_error) = get_last_error_from_log() {
                    error_msg = format!("{}\n\nReason: {}", error_msg, specific_error);
                }
                
                error_msg = format!("{}\n\nPlease check the log files in C:\\ProgramData\\EbantisV4\\Logs for more details.", error_msg);
                
                show_error(&error_msg);
                return 1;
            }
        }
        Err(e) => {
            show_error(&format!("Failed to execute uninstaller: {}\n\nPlease ensure PowerShell is available and you have administrative privileges.", e));
            return 1;
        }
    }
}

fn execute_installer() -> i32 {
    // Extract branch ID from MSI filename
    let branch_id = match extract_branch_id_from_msi_name() {
        Some(id) => id,
        None => {
            show_error("Failed to extract branch ID from MSI filename.\n\nExpected format: installer_{branch_id}.msi or EbantisTrack_{branch_id}.msi\n\nPlease ensure the MSI file follows this naming convention.");
            return 1;
        }
    };
    
    // Get PowerShell installer script path
    let script_path = get_script_path(false);
    
    if !script_path.exists() {
        show_error(&format!(
            "PowerShell installer script not found at:\n{}\n\nPlease ensure installer.ps1 is in the same directory as the MSI.",
            script_path.display()
        ));
        return 1;
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
                return 0;
            } else {
                // Try to get a more specific error from the log file
                let mut error_msg = format!("Installation failed with exit code: {}", status.code().unwrap_or(-1));
                
                if let Some(specific_error) = get_last_error_from_log() {
                    error_msg = format!("{}\n\nReason: {}", error_msg, specific_error);
                }
                
                error_msg = format!("{}\n\nPlease check the log files in C:\\ProgramData\\EbantisV4\\Logs for more details.", error_msg);
                
                show_error(&error_msg);
                return 1;
            }
        }
        Err(e) => {
            show_error(&format!("Failed to execute installer: {}\n\nPlease ensure PowerShell is available and you have administrative privileges.", e));
            return 1;
        }
    }
}

fn main() {
    // Check command-line arguments for uninstall flag
    let args: Vec<String> = env::args().collect();
    let is_uninstall = args.iter().any(|arg| {
        arg.eq_ignore_ascii_case("-uninstall") || 
        arg.eq_ignore_ascii_case("--uninstall") ||
        arg.eq_ignore_ascii_case("/uninstall") ||
        arg.eq_ignore_ascii_case("uninstall")
    });
    
    // Check environment variable (set by WiX during uninstall)
    let is_uninstall_env = env::var("REMOVE").as_ref()
        .map(|v| v == "ALL")
        .unwrap_or(false) || 
        env::var("ACTION").as_ref()
        .map(|v| v == "REMOVE" || v == "UNINSTALL")
        .unwrap_or(false);
    
    let exit_code = if is_uninstall || is_uninstall_env {
        execute_uninstaller()
    } else {
        execute_installer()
    };
    
    std::process::exit(exit_code);
}
