# Python vs PowerShell Installer - Path Comparison

## Extraction Path Comparison

### Python Installer (`Ebantis_setup/installation.pyx`)

**Configuration** (`utils/config.py`):
```python
PROGRAM_FILES_PATH = r"C:/Program Files/EbantisV4"
PROGRAM_DATA_PATH = r"C:/ProgramData/EbantisV4"
UPDATION_DIREC = os.path.join(PROGRAM_FILES_PATH, "data")  # C:\Program Files\EbantisV4\data
DATA_FILE_PATH = os.path.join(PROGRAM_DATA_PATH, "Ebantisv4.zip")  # C:\ProgramData\EbantisV4\Ebantisv4.zip
```

**Extraction Code** (`installation.pyx` line 869):
```python
extract_path = UPDATION_DIREC  # C:\Program Files\EbantisV4\data
os.makedirs(extract_path, exist_ok=True)
# ... download code ...
# Extract to extract_path
_robust_extract_zip(zip_ref, extract_path)
```

**Result**: ZIP extracts to `C:\Program Files\EbantisV4\data\`

---

### PowerShell Installer (`installer.ps1`)

**Configuration** (lines 40-45):
```powershell
$AppName = "EbantisV4"
$ProgramFilesPath = [System.IO.Path]::Combine($env:ProgramFiles, $AppName)  # C:\Program Files\EbantisV4
$ProgramDataPath = [System.IO.Path]::Combine($env:ProgramData, $AppName)   # C:\ProgramData\EbantisV4
```

**Extraction Code** (lines 856-857):
```powershell
$DownloadPath = [System.IO.Path]::Combine($ProgramDataPath, "Ebantisv4.zip")  # C:\ProgramData\EbantisV4\Ebantisv4.zip
$ExtractPath = [System.IO.Path]::Combine($ProgramFilesPath, "data")           # C:\Program Files\EbantisV4\data
```

**Result**: ZIP extracts to `C:\Program Files\EbantisV4\data\`

---

## ✅ Verification

| Component | Python | PowerShell | Match |
|-----------|--------|------------|-------|
| **Download Path** | `C:\ProgramData\EbantisV4\Ebantisv4.zip` | `C:\ProgramData\EbantisV4\Ebantisv4.zip` | ✅ |
| **Extract Path** | `C:\Program Files\EbantisV4\data` | `C:\Program Files\EbantisV4\data` | ✅ |
| **Program Files Base** | `C:\Program Files\EbantisV4` | `C:\Program Files\EbantisV4` | ✅ |
| **Program Data Base** | `C:\ProgramData\EbantisV4` | `C:\ProgramData\EbantisV4` | ✅ |

---

## Expected Folder Structure After Extraction

```
C:\Program Files\EbantisV4\
└── data\
    ├── EbantisV4\          # Main application folder
    │   ├── EbantisV4.exe
    │   ├── AutoUpdationService.exe
    │   ├── lib\            # Should be here (moved from root)
    │   ├── utils\
    │   └── update\
    ├── lib\                # May extract here initially (needs to be moved)
    └── downloaded_version\
```

---

## Conclusion

**The extraction paths are CORRECT and match the Python installer.**

The ZIP is correctly extracted to `C:\Program Files\EbantisV4\data\` in both installers.

The only difference is the post-extraction handling:
- Python: Relies on ZIP structure to extract correctly
- PowerShell: Has additional logic to move `lib` folder and handle `EbantisV4prod` folder name

Both achieve the same final result: files in `C:\Program Files\EbantisV4\data\EbantisV4\`
