# Installation Fix Summary

## Problem
The MSI installer was entering "maintenance mode" when the product was already registered, causing custom actions (`SetMsiFilename` and `RunInstaller`) to be skipped with the error:
```
Skipping action: SetMsiFilename (condition is false)
Skipping action: RunInstaller (condition is false)
```

## Root Cause
The WiX condition `NOT REMOVE` was evaluating to `false` in maintenance mode because when REMOVE property is not set at all (empty string), the condition `NOT REMOVE` doesn't work as expected.

## Fixes Applied

### 1. Fixed WiX Custom Action Conditions (`wix/main.wxs`)
**Changed from:**
```xml
<Custom Action="SetMsiFilename" After="InstallInitialize">NOT REMOVE</Custom>
<Custom Action="RunInstaller" After="InstallFiles">NOT REMOVE</Custom>
```

**Changed to:**
```xml
<Custom Action="SetMsiFilename" After="InstallInitialize">(REMOVE="" OR REMOVE&lt;&gt;"ALL")</Custom>
<Custom Action="RunInstaller" After="InstallFiles">(REMOVE="" OR REMOVE&lt;&gt;"ALL")</Custom>
```

This condition explicitly checks:
- If REMOVE is empty (not set) - run the action
- If REMOVE is not equal to "ALL" (not uninstalling) - run the action
- Only skip if REMOVE="ALL" (uninstall scenario)

### 2. Added Comprehensive Logging (`src/main.rs`)
- Added `log_msi_environment()` function to log all MSI environment variables
- Added `write_msi_debug_log()` function to write debug logs to `C:\ProgramData\EbantisV4\Logs\msi_debug.log`
- Logs include: ACTION, REMOVE, REINSTALL, REINSTALLMODE, OriginalDatabase, ProductCode, etc.
- Logs command-line arguments and execution path

### 3. Enhanced PowerShell Installer Logging (`installer.ps1`)
- Added MSI environment variable logging at the start of the installer
- Logs all relevant MSI properties (ACTION, REMOVE, OriginalDatabase, etc.)
- Helps diagnose why conditions might be failing

### 4. Created Cleanup and Reinstall Script (`cleanup_and_install.ps1`)
A comprehensive cleanup script that:
- Finds Product Code automatically (by UpgradeCode or product name)
- Uninstalls using MSIEXEC
- Removes Program Files directory
- Removes ProgramData directory
- Cleans MSI cache files
- Removes registry entries
- Reinstalls the MSI fresh

## Usage

### For Fresh Installation (No Previous Installation)
Just run the MSI normally:
```powershell
msiexec /i "installer_36851736-5317-4697-b7ab-835c2037696f.msi" /qn /L*v "install.log"
```

### For Reinstallation (Previous Installation Exists)
Use the cleanup script:
```powershell
.\cleanup_and_install.ps1 -MsiPath "installer_36851736-5317-4697-b7ab-835c2037696f.msi"
```

Or manually uninstall first:
```powershell
# Find Product Code
$productCode = "{1999A007-C3FC-4C62-AE59-D53C7292536A}"  # From MSI log

# Uninstall
msiexec /x $productCode /qn

# Then install
msiexec /i "installer_36851736-5317-4697-b7ab-835c2037696f.msi" /qn /L*v "install.log"
```

### For Repair/Upgrade (Previous Installation Exists)
The fixed conditions should now allow the installer to run even in maintenance mode:
```powershell
msiexec /i "installer_36851736-5317-4697-b7ab-835c2037696f.msi" /qn /L*v "install.log"
```

## Log Files Location

1. **MSI Installer Log**: Location specified in `/L*v` parameter (default: current directory)
2. **Rust Debug Log**: `C:\ProgramData\EbantisV4\Logs\msi_debug.log`
3. **PowerShell Installer Log**: `C:\ProgramData\EbantisV4\Logs\Ebantis_setup_YYYY-MM-DD.log`

## Verification

After installation, check:
1. **MSI Log**: Look for `Custom Action: SetMsiFilename` and `Custom Action: RunInstaller` - they should NOT be skipped
2. **Debug Log**: Check `C:\ProgramData\EbantisV4\Logs\msi_debug.log` for environment variables
3. **Installer Log**: Check `C:\ProgramData\EbantisV4\Logs\Ebantis_setup_*.log` for installation progress

## Expected Behavior

### Before Fix:
```
MSI (s) (84:80) [11:20:52:602]: Skipping action: SetMsiFilename (condition is false)
MSI (s) (84:80) [11:20:52:614]: Skipping action: RunInstaller (condition is false)
```

### After Fix:
```
MSI (s) (84:80) [11:20:52:602]: Doing action: SetMsiFilename
Action start 11:20:52: SetMsiFilename.
...
MSI (s) (84:80) [11:20:52:614]: Doing action: RunInstaller
Action start 11:20:52: RunInstaller.
```

## Building

After making changes, rebuild:
```powershell
# Build Rust executable
cargo build --release

# Generate MSI
cargo wix

# Output will be in: target\wix\ebantis-msi-installer-4.0.0-x86_64.msi
```

## Notes

- The condition `(REMOVE="" OR REMOVE<>"ALL")` ensures the custom actions run in:
  - Fresh installations (REMOVE not set)
  - Upgrades (REMOVE not set)
  - Repairs (REMOVE not set)
  - Maintenance mode reinstalls (REMOVE not set)
  - But NOT during uninstall (REMOVE="ALL")

- The logging additions help diagnose issues if they occur in the future

- The cleanup script can be used to completely remove all traces before a fresh install
