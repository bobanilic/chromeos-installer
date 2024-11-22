# ChromeOS-Brunch Portable Installer
# Version: 1.2
# Description: Automated installer for ChromeOS-Brunch

# Define the required folder structure
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$MINGW_DIR = Join-Path $SCRIPT_DIR "mingw"
$MINGW_BIN = Join-Path $MINGW_DIR "bin"
$MINGW_LIB = Join-Path $MINGW_DIR "lib"
$MINGW_SHARE = Join-Path $MINGW_DIR "share"
$TEMP_DIR = Join-Path $SCRIPT_DIR "temp"
$LOG_FILE = Join-Path $SCRIPT_DIR "install_log.txt"

# Required MinGW components
$REQUIRED_STRUCTURE = @{
    "Folders" = @{
        "mingw" = @{
            "Path" = $MINGW_DIR
            "Description" = "Main MinGW directory"
        }
        "mingw/bin" = @{
            "Path" = $MINGW_BIN
            "Description" = "MinGW binaries directory"
        }
        "mingw/lib" = @{
            "Path" = $MINGW_LIB
            "Description" = "MinGW libraries directory"
        }
        "mingw/share" = @{
            "Path" = $MINGW_SHARE
            "Description" = "MinGW shared resources directory"
        }
    }
    "Files" = @{
        "bash.exe" = @{
            "Path" = Join-Path $MINGW_BIN "bash.exe"
            "Description" = "Bash shell interpreter"
            "Required" = $true
        }
        "tar.exe" = @{
            "Path" = Join-Path $MINGW_BIN "tar.exe"
            "Description" = "Archive manipulation tool"
            "Required" = $true
        }
        "parted.exe" = @{
            "Path" = Join-Path $MINGW_BIN "parted.exe"
            "Description" = "Partition manipulation tool"
            "Required" = $true
        }
        "grub-install.exe" = @{
            "Path" = Join-Path $MINGW_BIN "grub-install.exe"
            "Description" = "GRUB bootloader installer"
            "Required" = $true
        }
        "mkfs.ext4.exe" = @{
            "Path" = Join-Path $MINGW_BIN "mkfs.ext4.exe"
            "Description" = "EXT4 filesystem creator"
            "Required" = $true
        }
        "mount.exe" = @{
            "Path" = Join-Path $MINGW_BIN "mount.exe"
            "Description" = "Filesystem mount tool"
            "Required" = $true
        }
    }
    "Libraries" = @{
        "libwin32.dll" = @{
            "Path" = Join-Path $MINGW_LIB "libwin32.dll"
            "Description" = "Win32 compatibility layer"
            "Required" = $true
        }
        "libgcc_s_dw2-1.dll" = @{
            "Path" = Join-Path $MINGW_LIB "libgcc_s_dw2-1.dll"
            "Description" = "GCC support library"
            "Required" = $true
        }
    }
}

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp [$Level] - $Message" | Tee-Object -FilePath $LOG_FILE -Append
}

function Test-InstallerStructure {
    $missingComponents = @{
        Folders = @()
        Files = @()
        Libraries = @()
    }
    
    Write-Host "`nValidating installer structure..." -ForegroundColor Cyan
    Write-Log "Starting installer structure validation"
    
    # Check folders
    foreach ($folder in $REQUIRED_STRUCTURE.Folders.Keys) {
        $folderInfo = $REQUIRED_STRUCTURE.Folders[$folder]
        if (-not (Test-Path $folderInfo.Path)) {
            $missingComponents.Folders += @{
                Name = $folder
                Description = $folderInfo.Description
            }
        }
    }
    
    # Check files
    foreach ($file in $REQUIRED_STRUCTURE.Files.Keys) {
        $fileInfo = $REQUIRED_STRUCTURE.Files[$file]
        if (-not (Test-Path $fileInfo.Path)) {
            $missingComponents.Files += @{
                Name = $file
                Description = $fileInfo.Description
                Required = $fileInfo.Required
            }
        }
    }
    
    # Check libraries
    foreach ($lib in $REQUIRED_STRUCTURE.Libraries.Keys) {
        $libInfo = $REQUIRED_STRUCTURE.Libraries[$lib]
        if (-not (Test-Path $libInfo.Path)) {
            $missingComponents.Libraries += @{
                Name = $lib
                Description = $libInfo.Description
                Required = $libInfo.Required
            }
        }
    }
    
    # Report results
    $hasErrors = $false
    
    if ($missingComponents.Folders.Count -gt 0) {
        Write-Host "`nMissing Folders:" -ForegroundColor Red
        foreach ($folder in $missingComponents.Folders) {
            Write-Host "  × $($folder.Name) - $($folder.Description)" -ForegroundColor Red
            Write-Log "Missing folder: $($folder.Name)" "ERROR"
        }
        $hasErrors = $true
    }
    
    if ($missingComponents.Files.Count -gt 0) {
        Write-Host "`nMissing Files:" -ForegroundColor Red
        foreach ($file in $missingComponents.Files) {
            $marker = if ($file.Required) { "×" } else { "!" }
            $color = if ($file.Required) { "Red" } else { "Yellow" }
            Write-Host "  $marker $($file.Name) - $($file.Description)" -ForegroundColor $color
            Write-Log "Missing file: $($file.Name)" $(if ($file.Required) { "ERROR" } else { "WARN" })
        }
        if ($missingComponents.Files.Where({$_.Required}).Count -gt 0) {
            $hasErrors = $true
        }
    }
    
    if ($missingComponents.Libraries.Count -gt 0) {
        Write-Host "`nMissing Libraries:" -ForegroundColor Red
        foreach ($lib in $missingComponents.Libraries) {
            $marker = if ($lib.Required) { "×" } else { "!" }
            $color = if ($lib.Required) { "Red" } else { "Yellow" }
            Write-Host "  $marker $($lib.Name) - $($lib.Description)" -ForegroundColor $color
            Write-Log "Missing library: $($lib.Name)" $(if ($lib.Required) { "ERROR" } else { "WARN" })
        }
        if ($missingComponents.Libraries.Where({$_.Required}).Count -gt 0) {
            $hasErrors = $true
        }
    }
    
    if (-not $hasErrors) {
        Write-Host "`n✓ All required components are present" -ForegroundColor Green
        Write-Log "Structure validation successful"
        return $true
    }
    else {
        Write-Host "`nStructure validation failed. Please ensure you have:" -ForegroundColor Red
        Write-Host "1. Downloaded the complete installer package" -ForegroundColor Yellow
        Write-Host "2. Extracted all contents preserving folder structure" -ForegroundColor Yellow
        Write-Host "3. Not moved or deleted any components" -ForegroundColor Yellow
        Write-Host "`nDownload the installer package again if problems persist." -ForegroundColor Yellow
        Write-Log "Structure validation failed"
        return $false
    }
}

function Initialize-InstallerEnvironment {
    Write-Host "Initializing installer environment..." -ForegroundColor Cyan
    
    # Create temp directory if it doesn't exist
    if (-not (Test-Path $TEMP_DIR)) {
        New-Item -ItemType Directory -Force -Path $TEMP_DIR | Out-Null
        Write-Log "Created temporary directory: $TEMP_DIR"
    }
    
    # Verify MinGW environment variables
    $env:MINGW_HOME = $MINGW_DIR
    $env:PATH = "$MINGW_BIN;$env:PATH"
    Write-Log "Set MinGW environment variables"
    
    # Test MinGW basic functionality
    try {
        $bashVersion = & "$MINGW_BIN\bash.exe" --version | Select-Object -First 1
        Write-Log "Verified bash functionality: $bashVersion"
    }
    catch {
        Write-Log "Failed to execute bash: $_" "ERROR"
        throw "Failed to initialize MinGW environment"
    }
}

# Modified main script to use new structure validation
try {
    Write-Host "ChromeOS-Brunch Installer" -ForegroundColor Cyan
    Write-Host "=========================" -ForegroundColor Cyan
    
    # Validate installer structure
    if (-not (Test-InstallerStructure)) {
        throw "Invalid installer structure. Please check the requirements above."
    }
    
    # Initialize environment
    Initialize-InstallerEnvironment
    
    Write-Host "`n✓ Installer validation complete - ready to proceed" -ForegroundColor Green
    
    # ... rest of the main script continues here ...
    
}
catch {
    Write-Log "Fatal error: $_" "ERROR"
    Write-Host "`nInstallation cannot proceed due to errors. See install_log.txt for details." -ForegroundColor Red
    exit 1
}
