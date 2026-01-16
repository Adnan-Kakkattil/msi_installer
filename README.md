# Ebantis V4 MSI Installer

This Rust-based MSI installer extracts the branch ID from the MSI filename and executes the PowerShell installation script.

## Requirements

1. **Rust** (latest stable version)
2. **cargo-wix** - Install with: `cargo install cargo-wix`
3. **WiX Toolset** - Download from https://wixtoolset.org/
4. **Visual Studio Build Tools** (for Windows MSVC toolchain)

## Building the MSI

1. **Install dependencies:**
   ```powershell
   cargo install cargo-wix
   ```

2. **Build the Rust executable:**
   ```powershell
   cargo build --release
   ```

3. **Create the MSI:**
   ```powershell
   cargo wix
   ```

4. **Rename the MSI with branch ID:**
   The MSI should be named: `EbantisTrack_{branch_id}.msi`
   
   Example: `EbantisTrack_abc123def456.msi`

## How It Works

1. The MSI installer extracts the branch ID from its filename (format: `EbantisTrack_{branch_id}.msi`)
2. Sets the `EBANTIS_BRANCH_ID` environment variable
3. Executes the embedded `installer.ps1` script
4. The PowerShell script reads the branch ID from the environment variable and proceeds with installation

## File Structure

```
msi_installer/
├── Cargo.toml          # Rust project configuration
├── src/
│   └── main.rs        # Main installer executable
├── wix/
│   └── main.wxs       # WiX installer configuration
├── installer.ps1      # PowerShell installation script (copied here)
└── README.md          # This file
```

## Installation Flow

1. User double-clicks `EbantisTrack_{branch_id}.msi`
2. MSI extracts files to `C:\Program Files\EbantisV4\`
3. MSI runs `ebantis-msi-installer.exe` which:
   - Extracts branch ID from MSI filename
   - Sets `EBANTIS_BRANCH_ID` environment variable
   - Executes `installer.ps1` with admin privileges
4. PowerShell script performs full installation

## Notes

- The MSI requires administrator privileges
- The PowerShell script will request elevation if not running as admin
- The branch ID must be in the MSI filename for the installer to work

## Troubleshooting

### Issue: Installation enters "Maintenance Mode" and skips installation

**Symptoms:**
- MSI log shows: `Product registered: entering maintenance mode`
- Custom actions are skipped: `Skipping action: RunInstaller (condition is false)`
- Installation completes but no files are installed

**Cause:**
Windows Installer detects that the Product Code is already registered on the system, so it enters maintenance mode instead of performing a fresh installation.

**Solutions:**

1. **Uninstall the previous version first:**
   ```powershell
   # Find the Product Code from the MSI or registry
   # Then uninstall:
   msiexec /x "{ProductCode}" /qn
   ```

2. **Use Repair/Reinstall with REINSTALLMODE:**
   ```powershell
   # Force reinstall all files
   msiexec /i "installer_{branch_id}.msi" /qn REINSTALLMODE=vamus REINSTALL=ALL
   ```

3. **For testing, use a different Product Code:**
   - Change the Product Code in `wix/main.wxs` (set `Product Id` to `*` for auto-generation)
   - Or increment the version number to trigger an upgrade

4. **The installer now runs on upgrades:**
   - The WiX configuration has been updated to run the installer script during upgrades, repairs, and fresh installs
   - The condition `(REMOVE="" OR REMOVE<>"ALL")` ensures it runs on any installation scenario except uninstall
   - This fix resolves the "condition is false" error in maintenance mode

5. **Use the cleanup script for complete reinstallation:**
   ```powershell
   .\cleanup_and_install.ps1 -MsiPath "installer_{branch_id}.msi"
   ```
   This script completely removes the product (files, registry, cache) and reinstalls fresh.

### Issue: Custom actions not running

**Check the MSI log for:**
- `Skipping action: RunInstaller (condition is false)` - This means the condition evaluated to false
- Verify that files are being copied (look for `Installing:` messages)

**Solutions:**
- Ensure you're not in uninstall mode (`REMOVE="ALL"` means uninstall)
- Check that files are actually being installed (`InstallFiles` action should run before `RunInstaller`)
- Check debug logs: `C:\ProgramData\EbantisV4\Logs\msi_debug.log` for environment variable values
- Use the cleanup script: `.\cleanup_and_install.ps1 -MsiPath "installer_{branch_id}.msi"` for a fresh install

### Testing Installation

**For fresh installation test:**
```powershell
# Uninstall first (if installed)
msiexec /x "{ProductCode}" /qn

# Then install
msiexec /i "installer_{branch_id}.msi" /qn /L*v "install.log"
```

**For upgrade test:**
```powershell
# Just install with the new MSI - it will upgrade automatically
msiexec /i "installer_{branch_id}.msi" /qn /L*v "upgrade.log"
```

**To view verbose logs:**
```powershell
msiexec /i "installer_{branch_id}.msi" /qn /L*v "C:\Users\YourName\install.log"
```

## Uninstallation

The MSI installer includes a complete uninstallation flow:

1. When user clicks "Remove" in Programs and Features
2. MSI custom action runs `uninstaller.ps1` before files are removed
3. Uninstaller script:
   - Kills all Ebantis processes
   - Removes startup shortcuts
   - Removes all files and folders
   - Updates API status to "Uninstalled"
4. MSI continues with standard cleanup

To manually uninstall:
```powershell
msiexec /x "{ProductCode}" /qn
```
