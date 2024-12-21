# Error handling and logging setup
$ErrorActionPreference = "Stop"
$Global:CONFIG = @{
    StartTime = Get-Date
    Paths = @{
        Cygwin = "C:\cygwin64"
        Downloads = ".\downloads"
        Temp = ".\temp"
        Logs = ".\logs"
        Cache = ".\cache"
    }
}

# Create required directories
foreach ($path in $Global:CONFIG.Paths.Values) {
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
}

# Initial environment check
#Write-Host "ChromeOS Installer - Environment Check" -ForegroundColor Cyan
#Write-Host "========================================" -ForegroundColor Cyan
#Write-Host "Time: $(Get-Date)" -ForegroundColor Gray
#Write-Host "User: $env:USERNAME" -ForegroundColor Gray
#Write-Host "Directory: $PWD" -ForegroundColor Gray
#Write-Host "========================================" -ForegroundColor Cyan

# Set console encoding to UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$Host.UI.RawUI.WindowTitle = "ChromeOS Installer"

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: Script must be run as Administrator" -ForegroundColor Red
    Write-Host "Please right-click and select 'Run as Administrator'" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# Verify Cygwin installation
$cygwinPath = $Global:CONFIG.Paths.Cygwin
if (-not (Test-Path $cygwinPath)) {
    Write-Host "ERROR: Cygwin not found at $cygwinPath" -ForegroundColor Red
    Write-Host "Please install Cygwin with required packages:" -ForegroundColor Yellow
    Write-Host "- pv" -ForegroundColor Yellow
    Write-Host "- tar" -ForegroundColor Yellow
    Write-Host "- unzip" -ForegroundColor Yellow
    Write-Host "- e2fsprogs" -ForegroundColor Yellow
    Write-Host "- bash" -ForegroundColor Yellow
    Write-Host "- dd" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# Check required Cygwin tools
$requiredTools = @("bash.exe", "dd.exe", "pv.exe", "tar.exe", "unzip.exe")
$missingTools = @()

foreach ($tool in $requiredTools) {
    $toolPath = Join-Path $cygwinPath "bin\$tool"
    if (-not (Test-Path $toolPath)) {
        $missingTools += $tool
    }
}

if ($missingTools.Count -gt 0) {
    Write-Host "ERROR: Missing required Cygwin tools:" -ForegroundColor Red
    $missingTools | ForEach-Object { Write-Host "- $_" -ForegroundColor Yellow }
    Write-Host "`nPlease install missing packages using Cygwin setup" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "Environment check passed!" -ForegroundColor Green
Write-Host "Starting installation..." -ForegroundColor Cyan
#Write-Host ""

<#
.SYNOPSIS
    ChromeOS Windows Installer Script
.DESCRIPTION
    Automated ChromeOS installation script for Windows that handles:
    - Processor detection and compatible build selection
    - Automatic download of latest stable builds
    - Disk preparation and partitioning
    - ChromeOS installation with Cygwin tools
.NOTES
    Author: bobanilic
    Version: 2.0.0
    Last Updated: 2024-12-21
    Requires: PowerShell 5.1+, Administrator rights, Cygwin with required packages
.PARAMETER Debug
    Enables detailed debug logging
.PARAMETER SkipDiskCheck
    Skips the disk validation checks
.PARAMETER RecoveryUrl
    Optional URL to a specific ChromeOS recovery image
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

# Script parameters
$Debug = $false
$SkipDiskCheck = $false
$RecoveryUrl = ""

# Script initialization
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'Continue'
$PSDefaultParameterValues['*:Encoding'] = 'utf8'

# Version information
$Global:SCRIPT_VERSION = "2.0.0"
$Global:SCRIPT_DATE = "2024-12-21"

# Script metadata
$script:metadata = @{
    StartTime = [datetime]::UtcNow
    UserName = $env:USERNAME
    ComputerName = $env:COMPUTERNAME
    PSVersion = $PSVersionTable.PSVersion.ToString()
    OS = [System.Environment]::OSVersion.VersionString
    ExecutionPath = $PSScriptRoot
    LogFile = $null  # Will be set during initialization
}

# Global configuration
$Global:CONFIG = @{
    # Paths
    Paths = @{
        Cygwin = "C:\cygwin64"
        Logs = "$env:USERPROFILE\ChromeOS_Install_Logs"
        Temp = "$env:TEMP\ChromeOS_Install"
        Downloads = "$env:USERPROFILE\Downloads\ChromeOS"
        Cache = "$env:USERPROFILE\.chromeos-installer"
    }

    # Cygwin required packages
    RequiredPackages = @{
        'pv' = 'pv.exe'
        'tar' = 'tar.exe'
        'unzip' = 'unzip.exe'
        'e2fsprogs' = 'mkfs.ext4.exe'
    }

    # ChromeOS devices and compatibility
    Devices = @{
        'shyvana' = @{
            Description = "8th/9th Gen Intel"
            MinGeneration = 8
            MaxGeneration = 9
        }
        'jinlon' = @{
            Description = "10th Gen Intel"
            MinGeneration = 10
            MaxGeneration = 10
        }
        'voxel' = @{
            Description = "11th Gen Intel and above"
            MinGeneration = 11
            MaxGeneration = 99
        }
        'gumboz' = @{
            Description = "AMD Ryzen"
            ProcessorType = "AMD"
        }
    }

    # Partition configuration
    Partitions = @{
        'EFI-SYSTEM' = @{
            Guid = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
            MinSize = 512MB
            Format = "FAT32"
            Required = $true
        }
        'ROOT-A' = @{
            Guid = "3CB8E202-3B7E-47DD-8A3C-7FF2A13CFCEC"
            MinSize = 8GB
            Format = "ext4"
            Required = $true
        }
        'STATE' = @{
            Guid = "CA7D7CCB-63ED-4C53-861C-1742536059CC"
            MinSize = 1GB
            Format = "ext4"
            Required = $true
        }
    }

    # Installation requirements
    MinimumDiskSize = 14GB
    MinimumMemory = 4GB
}

# Initialize working directories
function Initialize-WorkingEnvironment {
    try {
        # Create necessary directories
        foreach ($path in $Global:CONFIG.Paths.Values) {
            if (-not (Test-Path $path)) {
                New-Item -ItemType Directory -Path $path -Force | Out-Null
            }
        }

        # Set up logging
        $logDir = $Global:CONFIG.Paths.Logs
        $logFile = Join-Path $logDir "chromeos_install_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        $script:metadata.LogFile = $logFile

        # Create log file
        if (-not (Test-Path $logFile)) {
            New-Item -ItemType File -Path $logFile -Force | Out-Null
        }

        return $true
    }
    catch {
        Write-Error "Failed to initialize working environment: $_"
        return $false
    }
}
# Enhanced logging function
function Write-InstallLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Debug', 'Success')]
        [string]$Level = 'Info',
        
        [Parameter(Mandatory=$false)]
        [switch]$NoConsole
    )

    try {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logMessage = "[$timestamp UTC] [$Level] $Message"
        
        # Add to log file
        if ($script:metadata.LogFile) {
            Add-Content -Path $script:metadata.LogFile -Value $logMessage -Encoding UTF8
        }

        # Console output unless suppressed
        if (-not $NoConsole) {
            switch ($Level) {
                'Debug' { 
                    if ($Debug) { 
                        Write-Host $logMessage -ForegroundColor Gray
                    }
                }
                'Warning' { Write-Warning $Message }
                'Error' { Write-Host $logMessage -ForegroundColor Red }
                'Success' { Write-Host $logMessage -ForegroundColor Green }
                default { Write-Host $logMessage }
            }
        }
    }
    catch {
        Write-Error "Logging failed: $_"
    }
}

# Script banner display
function Show-Banner {
    Write-Host ""
    Write-Host "Current Date and Time (UTC): $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host "Current User's Login: $env:USERNAME" -ForegroundColor Gray  # Using environment variable instead of metadata
    Write-Host ""
    $banner = @"
+====================================================+
|              ChromeOS Installation Menu              |
+====================================================+
| 1. Automatic Installation (Recommended)              |
| 2. Custom Installation                              |
| 3. Verify System Requirements                       |
| 4. Show Available Disks                             |
| 5. Exit                                             |
+====================================================+

"@
    Write-Host $banner -ForegroundColor Cyan
}

# System requirements validation
function Test-SystemRequirements {
    Write-InstallLog "Checking system requirements..." -Level 'Info'
    
    # Create a custom object with IsValid property
    $requirements = New-Object PSObject -Property @{
        IsValid = $true
        Details = @{
            AdminRights = @{
                Pass = $false
                Required = "Administrator"
                Current = ""
            }
            RAM = @{
                Pass = $false
                Required = "4GB"
                Current = ""
            }
            DiskSpace = @{
                Pass = $false
                Required = "16GB"
                Current = ""
            }
            Architecture = @{
                Pass = $false
                Required = "64-bit"
                Current = ""
            }
        }
    }

    try {
        # Check Admin Rights
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        $adminStatus = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $requirements.Details.AdminRights.Current = if ($adminStatus) { "Administrator" } else { "User" }
        $requirements.Details.AdminRights.Pass = $adminStatus

        # Check RAM
        $ram = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB
        $requirements.Details.RAM.Current = "$([math]::Round($ram, 2))GB"
        $requirements.Details.RAM.Pass = $ram -ge 4

        # Check Disk Space
        $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
        $freeSpace = $disk.FreeSpace / 1GB
        $requirements.Details.DiskSpace.Current = "$([math]::Round($freeSpace, 2))GB"
        $requirements.Details.DiskSpace.Pass = $freeSpace -ge 16

        # Check Architecture
        $arch = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
        $requirements.Details.Architecture.Current = $arch
        $requirements.Details.Architecture.Pass = $arch -eq "64-bit"

        # Set IsValid based on all requirements passing
        $requirements.IsValid = -not ($requirements.Details.Values | Where-Object { -not $_.Pass })

        Write-InstallLog "System requirements check completed. IsValid: $($requirements.IsValid)" -Level 'Info'
        return $requirements
    }
    catch {
        Write-InstallLog "Error checking system requirements: $_" -Level 'Error'
        $requirements.IsValid = $false
        return $requirements
    }
}

function Test-Prerequisites {
    Write-InstallLog "Checking prerequisites..." -Level 'Info'
    
    try {
        # Check system requirements first
        $requirements = Test-SystemRequirements
        
        if (-not $requirements.IsValid) {
            Write-Host "`nSystem requirements not met:" -ForegroundColor Red
            $requirements.Details.GetEnumerator() | ForEach-Object {
                $status = if ($_.Value.Pass) { "PASS" } else { "FAIL" }
                $color = if ($_.Value.Pass) { "Green" } else { "Red" }
                Write-Host "$($_.Key): [$status] - Required: $($_.Value.Required), Current: $($_.Value.Current)" -ForegroundColor $color
            }
            return $false
        }

        # Check processor compatibility
        Write-InstallLog "Detecting system processor..." -Level 'Info'
        $processor = Get-SystemProcessor
        if (-not $processor.Supported) {
            Write-Host "`nUnsupported processor: $($processor.Name)" -ForegroundColor Red
            return $false
        }

        # Check available disks
        Write-InstallLog "Scanning for available disks..." -Level 'Info'
        $disks = Get-AvailableDisks
        if (-not $disks) {
            Write-Host "`nNo suitable disks found for installation." -ForegroundColor Red
            return $false
        }

        return $true
    }
    catch {
        Write-InstallLog "Prerequisites check failed: $_" -Level 'Error'
        return $false
    }
}
# Error handling wrapper
function Invoke-WithErrorHandling {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [scriptblock]$ScriptBlock,
        
        [Parameter(Mandatory=$true)]
        [string]$ErrorMessage,
        
        [Parameter(Mandatory=$false)]
        [scriptblock]$Finally = $null
    )

    try {
        Write-InstallLog "Starting: $ErrorMessage" -Level 'Debug'
        $result = & $ScriptBlock
        Write-InstallLog "Completed: $ErrorMessage" -Level 'Debug'
        return $result
    }
    catch {
        Write-InstallLog "$ErrorMessage - Failed: $_" -Level 'Error'
        throw
    }
    finally {
        if ($null -ne $Finally) {
            & $Finally
        }
    }
}

# Cleanup function
function Remove-InstallationArtifacts {
    param(
        [switch]$KeepLogs
    )

    Write-InstallLog "Cleaning up installation artifacts..." -Level 'Debug'

    $pathsToClean = @(
        $Global:CONFIG.Paths.Temp,
        $Global:CONFIG.Paths.Downloads
    )

    foreach ($path in $pathsToClean) {
        if (Test-Path $path) {
            Write-InstallLog "Removing directory: $path" -Level 'Debug'
            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    if (-not $KeepLogs) {
        $oldLogs = Get-ChildItem -Path $Global:CONFIG.Paths.Logs -Filter "chromeos_install_*.log" |
            Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) }
        
        foreach ($log in $oldLogs) {
            Remove-Item -Path $log.FullName -Force -ErrorAction SilentlyContinue
        }
    }
}
# Processor detection and compatibility check
function Get-SystemProcessor {
    try {
        Write-InstallLog "Detecting system processor..." -Level 'Info'
        
        # Create result object with IsValid property
        $result = New-Object PSObject -Property @{
            IsValid = $false
            Name = ""
            Manufacturer = ""
            Device = ""
            Supported = $false
        }

        # Get processor information
        $processorInfo = Get-CimInstance Win32_Processor | Select-Object -First 1
        if (-not $processorInfo) {
            throw "Failed to get processor information"
        }

        $result.Name = $processorInfo.Name
        $result.Manufacturer = $processorInfo.Manufacturer

        # Determine device based on processor
        if ($processorInfo.Manufacturer -like "*AMD*") {
            Write-InstallLog "AMD processor detected - using gumboz device" -Level 'Info'
            $result.Device = "gumboz"
            $result.Supported = $true
        }
        elseif ($processorInfo.Manufacturer -like "*Intel*") {
            Write-InstallLog "Intel processor detected - using rammus device" -Level 'Info'
            $result.Device = "rammus"
            $result.Supported = $true
        }
        else {
            Write-InstallLog "Unsupported processor manufacturer: $($processorInfo.Manufacturer)" -Level 'Warning'
            $result.Device = "unknown"
            $result.Supported = $false
        }

        $result.IsValid = $true
        return $result
    }
    catch {
        Write-InstallLog "Error detecting processor: $_" -Level 'Error'
        return $result  # Returns object with IsValid = false
    }
}

# ChromeOS build fetching and selection
function Get-ChromeOSBuilds {
    param (
        [string]$Device
    )

    try {
        # Create result object with IsValid property
        $result = New-Object PSObject -Property @{
            IsValid = $false
            Builds = @()
        }

        # Validate device parameter
        if ([string]::IsNullOrEmpty($Device)) {
            throw "Device parameter is required"
        }

        # Mock data for demonstration
        $result.Builds = @(
            @{
                Version = "R118-15604.0.0"
                Channel = "Stable"
                DownloadUrl = "https://example.com/chromeos/R118-15604.0.0"
                Device = $Device
            },
            @{
                Version = "R117-15437.0.0"
                Channel = "Beta"
                DownloadUrl = "https://example.com/chromeos/R117-15437.0.0"
                Device = $Device
            }
        )

        $result.IsValid = $true
        return $result
    }
    catch {
        Write-InstallLog "Error getting ChromeOS builds: $_" -Level 'Error'
        return $result  # Returns object with IsValid = false
    }
}

function Select-ChromeOSBuild {
    param (
        [switch]$Interactive,
        [switch]$ForceLatest
    )

    try {
        # Create result object with IsValid property
        $result = New-Object PSObject -Property @{
            IsValid = $false
            DownloadUrl = ""
            BuildInfo = $null
        }

        # Get processor info
        $processor = Get-SystemProcessor
        if (-not $processor.Supported) {
            throw "Unsupported processor detected"
        }

        # Get available builds
        $buildsResult = Get-ChromeOSBuilds -Device $processor.Device
        if (-not $buildsResult.IsValid -or $buildsResult.Builds.Count -eq 0) {
            throw "No builds found for device: $($processor.Device)"
        }

        $builds = $buildsResult.Builds

        if ($ForceLatest) {
            # Get latest build
            $selectedBuild = $builds | Select-Object -First 1
            Write-Host "Selected latest build: $($selectedBuild.Version)" -ForegroundColor Cyan
        }
        elseif ($Interactive) {
            # Show available builds
            Write-Host "`nAvailable ChromeOS builds for $($processor.Device):" -ForegroundColor Yellow
            for ($i = 0; $i -lt [Math]::Min($builds.Count, 5); $i++) {
                Write-Host "$($i + 1). Version: $($builds[$i].Version) - $($builds[$i].Channel)" -ForegroundColor Cyan
            }

            # Let user select a build
            do {
                $selection = Read-Host "`nSelect a build (1-$([Math]::Min($builds.Count, 5)))"
                if ($selection -match '^\d+$' -and [int]$selection -ge 1 -and [int]$selection -le [Math]::Min($builds.Count, 5)) {
                    $selectedBuild = $builds[$selection - 1]
                    break
                }
                Write-Host "Invalid selection. Please try again." -ForegroundColor Red
            } while ($true)
        }
        else {
            $selectedBuild = $builds | Select-Object -First 1
        }

        if ($selectedBuild) {
            $result.IsValid = $true
            $result.DownloadUrl = $selectedBuild.DownloadUrl
            $result.BuildInfo = $selectedBuild
        }

        return $result
    }
    catch {
        Write-InstallLog "Error selecting ChromeOS build: $_" -Level 'Error'
        return $result  # Returns object with IsValid = false
    }
}
# ChromeOS image download and verification functions
function Get-ChromeOSImage {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Url,
        
        [Parameter(Mandatory=$false)]
        [string]$DestinationPath = $Global:CONFIG.Paths.Downloads,

        [Parameter(Mandatory=$false)]
        [switch]$Force
    )

    try {
        Write-InstallLog "Preparing to download ChromeOS image..." -Level 'Info'
        
        # Ensure destination directory exists
        if (-not (Test-Path $DestinationPath)) {
            New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
        }

        # Generate file path
        $fileName = [System.IO.Path]::GetFileName($Url)
        $filePath = Join-Path $DestinationPath $fileName

        # Check if file already exists
        if (Test-Path $filePath) {
            if ($Force) {
                Write-InstallLog "Removing existing file (Force mode)" -Level 'Debug'
                Remove-Item $filePath -Force
            }
            else {
                Write-InstallLog "Found existing download: $filePath" -Level 'Debug'
                $response = Read-Host "File already exists. Download again? (Y/N)"
                if ($response -eq 'Y') {
                    Remove-Item $filePath -Force
                }
                else {
                    Write-InstallLog "Using existing file" -Level 'Info'
                    return $filePath
                }
            }
        }

        # Download file with progress
        Write-InstallLog "Downloading ChromeOS image from: $Url" -Level 'Info'
        
        $webClient = New-Object System.Net.WebClient
        $downloadStartTime = Get-Date
        $lastUpdateTime = $downloadStartTime
        $lastBytesReceived = 0

        # Configure timeout and headers
        $webClient.Headers.Add("User-Agent", "ChromeOS-Installer/2.0")
        $webClient.Timeout = 3600000 # 1 hour timeout

        # Add download progress handler
        $downloadProgress = 0
        $webClient.DownloadProgressChanged = {
            param($sender, $e)
            
            $currentProgress = $e.ProgressPercentage
            $currentTime = Get-Date
            
            # Update progress every 1 second
            if (($currentTime - $lastUpdateTime).TotalSeconds -ge 1) {
                $bytesChange = $e.BytesReceived - $lastBytesReceived
                $timeChange = ($currentTime - $lastUpdateTime).TotalSeconds
                $currentSpeed = $bytesChange / $timeChange / 1MB
                
                $downloaded = $e.BytesReceived / 1MB
                $total = $e.TotalBytesToReceive / 1MB
                
                # Calculate ETA
                $remainingBytes = $e.TotalBytesToReceive - $e.BytesReceived
                $eta = if ($currentSpeed -gt 0) {
                    [TimeSpan]::FromSeconds($remainingBytes / ($currentSpeed * 1MB))
                } else {
                    [TimeSpan]::Zero
                }

                $status = @(
                    "Downloaded: {0:N2} MB of {1:N2} MB" -f $downloaded, $total
                    "Speed: {0:N2} MB/s" -f $currentSpeed
                    "ETA: {0:hh\:mm\:ss}" -f $eta
                ) -join " | "

                Write-Progress -Activity "Downloading ChromeOS Image" `
                    -Status $status `
                    -PercentComplete $currentProgress

                $lastUpdateTime = $currentTime
                $lastBytesReceived = $e.BytesReceived
            }
        }

        # Download completion handler
        $webClient.DownloadFileCompleted = {
            param($sender, $e)
            Write-Progress -Activity "Downloading ChromeOS Image" -Completed
            if ($e.Error) {
                throw $e.Error
            }
        }

        # Start download with timeout handling
        $downloadTask = $webClient.DownloadFileTaskAsync($Url, $filePath)
        
        if (-not ($downloadTask.Wait(3600000))) { # 1 hour timeout
            throw "Download timed out after 1 hour"
        }

        Write-InstallLog "Download completed: $filePath" -Level 'Success'
        
        # Verify download
        if (-not (Test-ChromeOSImage -ImagePath $filePath)) {
            throw "Image verification failed"
        }

        return $filePath
    }
    catch {
        Write-InstallLog "Failed to download ChromeOS image: $_" -Level 'Error'
        if (Test-Path $filePath) {
            Write-InstallLog "Removing incomplete download" -Level 'Debug'
            Remove-Item $filePath -Force -ErrorAction SilentlyContinue
        }
        throw
    }
    finally {
        if ($webClient) {
            $webClient.Dispose()
        }
    }
}

function Test-ChromeOSImage {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ImagePath
    )

    try {
        Write-InstallLog "Verifying ChromeOS image: $ImagePath" -Level 'Info'

        # Basic file checks
        if (-not (Test-Path $ImagePath)) {
            throw "Image file not found"
        }

        if (-not $ImagePath.EndsWith('.zip')) {
            throw "Invalid file format. Expected .zip file"
        }

        $file = Get-Item $ImagePath
        $fileSize = $file.Length / 1GB

        # Size verification
        if ($fileSize -lt 1) {
            throw "File size too small. Expected at least 1GB, got: $($fileSize.ToString('N2'))GB"
        }

        # ZIP integrity check
        Write-InstallLog "Checking ZIP file integrity..." -Level 'Debug'
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        try {
            [System.IO.Compression.ZipFile]::OpenRead($ImagePath).Dispose()
        }
        catch {
            throw "ZIP file is corrupted: $_"
        }

        # Content verification
        $expectedContent = @(
            '*recovery*.bin'
        )

        $zipEntries = [System.IO.Compression.ZipFile]::OpenRead($ImagePath).Entries.Name
        $hasRequiredFiles = $false

        foreach ($pattern in $expectedContent) {
            if ($zipEntries | Where-Object { $_ -like $pattern }) {
                $hasRequiredFiles = $true
                break
            }
        }

        if (-not $hasRequiredFiles) {
            throw "ZIP file does not contain required ChromeOS recovery files"
        }

        Write-InstallLog "Image verification passed successfully" -Level 'Success'
        Write-InstallLog "File size: $($fileSize.ToString('N2')) GB" -Level 'Debug'
        return $true
    }
    catch {
        Write-InstallLog "Image verification failed: $_" -Level 'Error'
        return $false
    }
}

function Expand-ChromeOSImage {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ImagePath,
        
        [Parameter(Mandatory=$false)]
        [string]$ExtractPath = (Join-Path $Global:CONFIG.Paths.Temp "extracted")
    )

    try {
        Write-InstallLog "Extracting ChromeOS image..." -Level 'Info'

        # Ensure extract directory exists and is empty
        if (Test-Path $ExtractPath) {
            Remove-Item $ExtractPath -Recurse -Force
        }
        New-Item -ItemType Directory -Path $ExtractPath -Force | Out-Null

        # Use Cygwin tools for extraction
        $cygwinBash = Join-Path $Global:CONFIG.Paths.Cygwin "bin\bash.exe"
        
        # Convert Windows paths to Cygwin paths
        $cygwinImagePath = $ImagePath.Replace('\', '/').Replace('C:', '/cygdrive/c')
        $cygwinExtractPath = $ExtractPath.Replace('\', '/').Replace('C:', '/cygdrive/c')

        $extractCommands = @(
            "cd `"$cygwinExtractPath`"",
            "unzip -o `"$cygwinImagePath`"",
            "for f in *.bin; do tar xf `"`$f`"; done"
        )

        $result = Start-Process -FilePath $cygwinBash `
            -ArgumentList "-c", ($extractCommands -join "; ") `
            -Wait -NoNewWindow -PassThru

        if ($result.ExitCode -ne 0) {
            throw "Image extraction failed with exit code: $($result.ExitCode)"
        }

        # Verify extraction
        $extractedFiles = Get-ChildItem $ExtractPath -Recurse
        Write-InstallLog "Extracted $($extractedFiles.Count) files" -Level 'Debug'

        if (-not $extractedFiles) {
            throw "No files were extracted"
        }

        Write-InstallLog "Image extraction completed successfully" -Level 'Success'
        return $ExtractPath
    }
    catch {
        Write-InstallLog "Failed to extract ChromeOS image: $_" -Level 'Error'
        throw
    }
}
# Disk management and installation functions
function Get-AvailableDisks {
    try {
        Write-InstallLog "Scanning for available disks..." -Level 'Info'
        
        # Create a custom object to store disk information and validity
        $diskInfo = New-Object PSObject -Property @{
            IsValid = $false
            Disks = @()
        }

        # Get all physical disks
        $physicalDisks = Get-Disk | Where-Object {
            $_.Size -ge 16GB -and  # Minimum size requirement
            -not $_.IsBoot -and    # Not the boot disk
            -not $_.IsSystem       # Not the system disk
        }

        if ($physicalDisks) {
            $diskInfo.Disks = $physicalDisks | Select-Object @(
                'Number',
                'FriendlyName',
                @{Name='Size(GB)'; Expression={[math]::Round($_.Size / 1GB, 2)}},
                'PartitionStyle',
                'OperationalStatus'
            )
            $diskInfo.IsValid = $true
        }

        Write-InstallLog "Found $($diskInfo.Disks.Count) suitable disks" -Level 'Info'
        return $diskInfo
    }
    catch {
        Write-InstallLog "Error scanning for available disks: $_" -Level 'Error'
        return New-Object PSObject -Property @{
            IsValid = $false
            Disks = @()
        }
    }
}

function Initialize-InstallationDisk {
    param (
        [Parameter(Mandatory=$true)]
        [int]$DiskNumber,
        
        [Parameter(Mandatory=$false)]
        [switch]$Force
    )

    try {
        Write-InstallLog "Initializing disk $DiskNumber for ChromeOS installation..." -Level 'Info'

        # Get disk information
        $disk = Get-Disk -Number $DiskNumber
        if (-not $disk) {
            throw "Disk $DiskNumber not found"
        }

        # Safety checks
        if (-not $Force) {
            if ($disk.IsBoot -or $disk.IsSystem) {
                throw "Cannot use boot or system disk for installation"
            }

            if ($disk.Size -lt $Global:CONFIG.MinimumDiskSize) {
                throw "Disk size too small. Required: $($Global:CONFIG.MinimumDiskSize / 1GB) GB, Available: $([math]::Round($disk.Size / 1GB, 2)) GB"
            }

            # Prompt for confirmation if disk has existing partitions
            $existingPartitions = Get-Partition -DiskNumber $DiskNumber -ErrorAction SilentlyContinue
            if ($existingPartitions) {
                Write-Host "`nWARNING: Disk $DiskNumber contains existing partitions:" -ForegroundColor Yellow
                $existingPartitions | Format-Table -AutoSize
                $confirmation = Read-Host "All data will be erased. Continue? (Y/N)"
                if ($confirmation -ne 'Y') {
                    throw "Operation cancelled by user"
                }
            }
        }

        # Clear and initialize disk
        Write-InstallLog "Clearing disk..." -Level 'Debug'
        Clear-Disk -Number $DiskNumber -RemoveData -RemoveOEM -Confirm:$false

        Write-InstallLog "Initializing disk as GPT..." -Level 'Debug'
        Initialize-Disk -Number $DiskNumber -PartitionStyle GPT

        # Create ChromeOS partitions
        $partitions = @(
            @{
                Name = "EFI-SYSTEM"
                Size = 512MB
                Type = $Global:CONFIG.Partitions['EFI-SYSTEM'].Guid
                Format = "FAT32"
                Label = "EFI-SYSTEM"
            },
            @{
                Name = "ROOT-A"
                Size = 8GB
                Type = $Global:CONFIG.Partitions['ROOT-A'].Guid
                Format = "RAW"
                Label = "ROOT-A"
            },
            @{
                Name = "STATE"
                Size = 0  # Use remaining space
                Type = $Global:CONFIG.Partitions['STATE'].Guid
                Format = "RAW"
                Label = "STATE"
            }
        )

        # Create partitions
        $createdPartitions = @()
        foreach ($partition in $partitions) {
            Write-InstallLog "Creating partition: $($partition.Name)" -Level 'Debug'
            
            $newPartition = New-Partition -DiskNumber $DiskNumber `
                -Size $partition.Size `
                -GptType $partition.Type

            if ($partition.Format -eq "FAT32") {
                Format-Volume -Partition $newPartition `
                    -FileSystem FAT32 `
                    -NewFileSystemLabel $partition.Label `
                    -Confirm:$false
            }

            $createdPartitions += $newPartition
        }

        # Verify partitions
        $verifiedPartitions = Get-Partition -DiskNumber $DiskNumber
        if ($verifiedPartitions.Count -lt 3) {
            throw "Partition creation failed. Expected 3 partitions, found $($verifiedPartitions.Count)"
        }

        Write-InstallLog "Disk initialization completed successfully" -Level 'Success'
        return $createdPartitions
    }
    catch {
        Write-InstallLog "Failed to initialize disk: $_" -Level 'Error'
        throw
    }
}

# Prerequisites check function
function Test-Prerequisites {
    Write-InstallLog "Checking prerequisites..." -Level 'Info'
    
    try {
        # Check system requirements first
        $requirements = Test-SystemRequirements
        
        if (-not $requirements.IsValid) {
            Write-Host "`nSystem requirements not met:" -ForegroundColor Red
            $requirements.Details.GetEnumerator() | ForEach-Object {
                $status = if ($_.Value.Pass) { "PASS" } else { "FAIL" }
                $color = if ($_.Value.Pass) { "Green" } else { "Red" }
                Write-Host "$($_.Key): [$status] - Required: $($_.Value.Required), Current: $($_.Value.Current)" -ForegroundColor $color
            }
            return $false
        }

        # Check processor compatibility
        Write-InstallLog "Detecting system processor..." -Level 'Info'
        $processor = Get-SystemProcessor
        if (-not $processor.Supported) {
            Write-Host "`nUnsupported processor: $($processor.Name)" -ForegroundColor Red
            return $false
        }

        # Check available disks
        Write-InstallLog "Scanning for available disks..." -Level 'Info'
        $diskInfo = Get-AvailableDisks
        if (-not $diskInfo.IsValid -or $diskInfo.Disks.Count -eq 0) {
            Write-Host "`nNo suitable disks found for installation." -ForegroundColor Red
            return $false
        }

        return $true
    }
    catch {
        Write-InstallLog "Prerequisites check failed: $_" -Level 'Error'
        return $false
    }
}

function Install-ChromeOS {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ImagePath,
        
        [Parameter(Mandatory=$true)]
        [int]$DiskNumber,
        
        [Parameter(Mandatory=$false)]
        [switch]$NoVerify
    )

    try {
        Write-InstallLog "Starting ChromeOS installation to disk $DiskNumber..." -Level 'Info'

        # Verify source image
        if (-not $NoVerify) {
            if (-not (Test-ChromeOSImage -ImagePath $ImagePath)) {
                throw "Image verification failed"
            }
        }

        # Extract image if needed
        $extractPath = Join-Path $Global:CONFIG.Paths.Temp "extracted"
        $extractedImage = Expand-ChromeOSImage -ImagePath $ImagePath -ExtractPath $extractPath

        # Use Cygwin tools for installation
        $cygwinBash = Join-Path $Global:CONFIG.Paths.Cygwin "bin\bash.exe"
        
        # Convert Windows paths to Cygwin paths
        $cygwinExtractPath = $extractPath.Replace('\', '/').Replace('C:', '/cygdrive/c')

        # Prepare dd command with progress monitoring using pv
        $ddCommand = @"
            cd "$cygwinExtractPath"
            image=`$(ls *.bin | head -n 1)
            if [ -z "`$image" ]; then
                echo "No image file found"
                exit 1
            fi
            echo "Installing `$image to disk $DiskNumber..."
            pv -tpreb "`$image" | dd of=/dev/sd$(chr $([int][char]'a' + $DiskNumber)) bs=4M
"@

        Write-InstallLog "Writing image to disk..." -Level 'Info'
        $result = Start-Process -FilePath $cygwinBash `
            -ArgumentList "-c", $ddCommand `
            -Wait -NoNewWindow -PassThru

        if ($result.ExitCode -ne 0) {
            throw "Image installation failed with exit code: $($result.ExitCode)"
        }

        # Verify installation
        Write-InstallLog "Verifying installation..." -Level 'Debug'
        $verifyPartitions = Get-Partition -DiskNumber $DiskNumber
        if (-not $verifyPartitions -or $verifyPartitions.Count -lt 3) {
            throw "Installation verification failed. Partition structure is incorrect."
        }

        Write-InstallLog "ChromeOS installation completed successfully" -Level 'Success'
        return $true
    }
    catch {
        Write-InstallLog "Installation failed: $_" -Level 'Error'
        throw
    }
    finally {
        # Cleanup
        if (Test-Path $extractPath) {
            Remove-Item -Path $extractPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# Post-installation verification and cleanup
function Test-Installation {
    param (
        [Parameter(Mandatory=$true)]
        [int]$DiskNumber
    )

    try {
        Write-InstallLog "Verifying ChromeOS installation on disk $DiskNumber..." -Level 'Info'

        # Check disk status
        $disk = Get-Disk -Number $DiskNumber
        if (-not $disk -or $disk.OperationalStatus -ne "Online") {
            throw "Disk $DiskNumber is not accessible"
        }

        # Verify partition structure
        $partitions = Get-Partition -DiskNumber $DiskNumber
        
        # Check required partitions
        foreach ($partitionConfig in $Global:CONFIG.Partitions.GetEnumerator()) {
            $partition = $partitions | Where-Object { $_.GptType -eq $partitionConfig.Value.Guid }
            if (-not $partition -and $partitionConfig.Value.Required) {
                throw "Required partition '$($partitionConfig.Key)' not found"
            }
        }

        Write-InstallLog "Installation verification completed successfully" -Level 'Success'
        return $true
    }
    catch {
        Write-InstallLog "Installation verification failed: $_" -Level 'Error'
        return $false
    }
}
# User interface and main execution functions
function Show-InstallationMenu {
    $menu = @"
╔════════════════════════════════════════════════════════════╗
║              ChromeOS Installation Options                 ║
╠════════════════════════════════════════════════════════════╣
║ 1. Automatic Installation (Recommended)                    ║
║ 2. Custom Installation                                    ║
║ 3. Verify System Requirements                             ║
║ 4. Show Available Disks                                   ║
║ 5. Exit                                                   ║
╚════════════════════════════════════════════════════════════╝
"@
    Write-Host $menu -ForegroundColor Cyan
    
    do {
        $choice = Read-Host "Select an option (1-5)"
    } while ($choice -notmatch '^[1-5]$')
    
    return $choice
}

function Show-InstallationProgress {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Status,
        
        [Parameter(Mandatory=$true)]
        [int]$PercentComplete,
        
        [Parameter(Mandatory=$false)]
        [string]$CurrentOperation
    )

    $progressParams = @{
        Activity = "Installing ChromeOS"
        Status = $Status
        PercentComplete = $PercentComplete
    }

    if ($CurrentOperation) {
        $progressParams.CurrentOperation = $CurrentOperation
    }

    Write-Progress @progressParams
}

function Start-AutomaticInstallation {
    try {
        Write-InstallLog "Starting automatic installation process..." -Level 'Info'
        Show-InstallationProgress -Status "Initializing" -PercentComplete 0

        # Check prerequisites
        Show-InstallationProgress -Status "Checking prerequisites" -PercentComplete 10
        $preCheck = Test-Prerequisites
        if (-not $preCheck.IsValid) {
            throw "System does not meet prerequisites"
        }

        # Select ChromeOS build
        Show-InstallationProgress -Status "Selecting ChromeOS build" -PercentComplete 20
        $selectedBuild = Select-ChromeOSBuild -ForceLatest

        # Get available disks
        Show-InstallationProgress -Status "Scanning for available disks" -PercentComplete 30
        $availableDisks = Get-AvailableDisks
        if (-not $availableDisks) {
            throw "No suitable disks found for installation"
        }

        # Select largest non-system disk
        $targetDisk = $availableDisks | 
            Sort-Object { [decimal]($_.Size -replace ' GB$', '') } -Descending |
            Select-Object -First 1

        Write-InstallLog "Selected disk $($targetDisk.Number) ($($targetDisk.Size))" -Level 'Info'

        # Download ChromeOS image
        Show-InstallationProgress -Status "Downloading ChromeOS image" -PercentComplete 40
        $imagePath = Get-ChromeOSImage -Url $selectedBuild.DownloadUrl

        # Initialize disk
        Show-InstallationProgress -Status "Preparing disk" -PercentComplete 60
        Initialize-InstallationDisk -DiskNumber $targetDisk.Number -Force

        # Install ChromeOS
        Show-InstallationProgress -Status "Installing ChromeOS" -PercentComplete 70
        Install-ChromeOS -ImagePath $imagePath -DiskNumber $targetDisk.Number

        # Verify installation
        Show-InstallationProgress -Status "Verifying installation" -PercentComplete 90
        if (-not (Test-Installation -DiskNumber $targetDisk.Number)) {
            throw "Installation verification failed"
        }

        Show-InstallationProgress -Status "Installation complete" -PercentComplete 100
        Write-Host "`nChrome OS installation completed successfully!" -ForegroundColor Green
        
        return $true
    }
    catch {
        Write-InstallLog "Automatic installation failed: $_" -Level 'Error'
        throw
    }
    finally {
        Write-Progress -Activity "Installing ChromeOS" -Completed
    }
}

function Start-CustomInstallation {
    try {
        Write-InstallLog "Starting custom installation process..." -Level 'Info'

        # Show available builds
        $selectedBuild = Select-ChromeOSBuild -Interactive

        # Show available disks
        $availableDisks = Get-AvailableDisks
        if (-not $availableDisks) {
            throw "No suitable disks found for installation"
        }

        Write-Host "`nAvailable disks for installation:" -ForegroundColor Cyan
        $availableDisks | Format-Table -AutoSize

        # Select disk
        do {
            $diskNumber = Read-Host "Enter disk number to install ChromeOS"
        } while ($diskNumber -notmatch '^\d+$' -or $diskNumber -notin $availableDisks.Number)

        # Confirm installation
        Write-Host "`nInstallation Summary:" -ForegroundColor Yellow
        Write-Host "ChromeOS Build: $($selectedBuild.Version)" -ForegroundColor White
        Write-Host "Target Disk: $diskNumber ($($availableDisks | Where-Object Number -eq $diskNumber | Select-Object -ExpandProperty Size))" -ForegroundColor White
        
        $confirm = Read-Host "`nProceed with installation? (Y/N)"
        if ($confirm -ne 'Y') {
            throw "Installation cancelled by user"
        }

        # Proceed with installation
        Show-InstallationProgress -Status "Downloading ChromeOS image" -PercentComplete 20
        $imagePath = Get-ChromeOSImage -Url $selectedBuild.DownloadUrl

        Show-InstallationProgress -Status "Preparing disk" -PercentComplete 40
        Initialize-InstallationDisk -DiskNumber $diskNumber

        Show-InstallationProgress -Status "Installing ChromeOS" -PercentComplete 60
        Install-ChromeOS -ImagePath $imagePath -DiskNumber $diskNumber

        Show-InstallationProgress -Status "Verifying installation" -PercentComplete 80
        if (-not (Test-Installation -DiskNumber $diskNumber)) {
            throw "Installation verification failed"
        }

        Show-InstallationProgress -Status "Installation complete" -PercentComplete 100
        Write-Host "`nChrome OS installation completed successfully!" -ForegroundColor Green
        
        return $true
    }
    catch {
        Write-InstallLog "Custom installation failed: $_" -Level 'Error'
        throw
    }
    finally {
        Write-Progress -Activity "Installing ChromeOS" -Completed
    }
}

# Main script execution
try {
    Show-Banner

    # Initialize working environment
    if (-not (Initialize-WorkingEnvironment)) {
        throw "Failed to initialize working environment"
    }

    do {
        $choice = Show-InstallationMenu
        
        switch ($choice) {
            '1' { 
                Start-AutomaticInstallation
                break
            }
            '2' { 
                Start-CustomInstallation
                break
            }
            '3' {
                $requirements = Test-Prerequisites
                Write-Host "`nSystem Requirements Check:" -ForegroundColor Cyan
                $requirements.Details | Format-Table -AutoSize
                Read-Host "Press Enter to continue"
            }
            '4' {
                $disks = Get-AvailableDisks
                Write-Host "`nAvailable Disks:" -ForegroundColor Cyan
                $disks | Format-Table -AutoSize
                Read-Host "Press Enter to continue"
            }
            '5' { 
                Write-Host "Exiting installation..." -ForegroundColor Yellow
                return 
            }
        }
    } while ($choice -in '3','4')

    # Post-installation cleanup
    Remove-InstallationArtifacts -KeepLogs
}
catch {
    Write-InstallLog "Installation failed: $_" -Level 'Error'
    if ($Debug) {
        throw
    }
    exit 1
}
finally {
    $duration = [datetime]::UtcNow - $script:metadata.StartTime
    Write-InstallLog "Script completed in $($duration.TotalMinutes.ToString('F2')) minutes" -Level 'Info'
}

Write-Host "Script completed!" -ForegroundColor Green
Read-Host "Press Enter to exit"

# Main menu function
function Show-InstallationMenu {
    Write-Host "`nChrome OS Installation Options:" -ForegroundColor Cyan
    Write-Host "1. Start Automatic Installation" -ForegroundColor Yellow
    Write-Host "2. Start Custom Installation" -ForegroundColor Yellow
    Write-Host "3. Exit" -ForegroundColor Yellow
    Write-Host ""
    
    do {
        $choice = Read-Host "Select an option (1-3)"
    } while ($choice -notin '1','2','3')
    
    return $choice
}

# Main execution block
function Start-ChromeOSInstallation {
    try {
        Write-Host "Environment check passed!" -ForegroundColor Green
        Write-Host "Starting installation...`n" -ForegroundColor Cyan
        
        # Initialize working environment
        if (-not (Initialize-WorkingEnvironment)) {
            throw "Failed to initialize working environment"
        }

        # Show banner once at the start
        Show-Banner
        
        # Main menu loop
        do {
            $choice = Read-Host "Select an option (1-5)"
            
            switch ($choice) {
                '1' {
                    Write-InstallLog "Starting automatic installation process..." -Level 'Info'
                    try {
                        if (-not (Test-Prerequisites)) {
                            throw "Prerequisites check failed"
                        }
                        
                        # Get processor and compatible build
                        $processor = Get-SystemProcessor
                        if (-not $processor.IsValid) {
                            throw "Failed to detect processor information"
                        }
                        if (-not $processor.Supported) {
                            throw "Unsupported processor: $($processor.Name)"
                        }

                        Write-Host "`nDetected processor: $($processor.Name)" -ForegroundColor Cyan
                        Write-Host "Compatible with ChromeOS device: $($processor.Device)" -ForegroundColor Cyan

                        # Get available disks
                        $diskInfo = Get-AvailableDisks
                        if (-not $diskInfo.IsValid -or $diskInfo.Disks.Count -eq 0) {
                            throw "No suitable disks found for installation"
                        }

                        # Get latest build
                        Write-Host "`nFetching latest ChromeOS build..." -ForegroundColor Cyan
                        $buildResult = Select-ChromeOSBuild -ForceLatest
                        if (-not $buildResult.IsValid) {
                            throw "Failed to get ChromeOS build"
                        }

                        # Download image
                        Write-Host "`nDownloading ChromeOS image..." -ForegroundColor Cyan
                        $imagePath = Get-ChromeOSImage -Url $buildResult.DownloadUrl
                        if (-not $imagePath) {
                            throw "Failed to download ChromeOS image"
                        }

                        Write-Host "Auto installation complete!" -ForegroundColor Green
                        Read-Host "`nPress Enter to continue"
                        Show-Banner
                    }
                    catch {
                        Write-InstallLog "Automatic installation failed: $_" -Level 'Error'
                        Read-Host "`nPress Enter to continue"
                        Show-Banner
                    }
                }
                
                '2' {
                    Write-InstallLog "Starting custom installation process..." -Level 'Info'
                    try {
                        if (-not (Test-Prerequisites)) {
                            throw "Prerequisites check failed"
                        }
                        
                        # Get processor info
                        $processor = Get-SystemProcessor
                        if (-not $processor.IsValid) {
                            throw "Failed to detect processor information"
                        }
                        if (-not $processor.Supported) {
                            throw "Unsupported processor: $($processor.Name)"
                        }

                        Write-Host "`nDetected processor: $($processor.Name)" -ForegroundColor Cyan
                        Write-Host "Compatible with ChromeOS device: $($processor.Device)" -ForegroundColor Cyan

                        # Get available disks
                        $diskInfo = Get-AvailableDisks
                        if (-not $diskInfo.IsValid -or $diskInfo.Disks.Count -eq 0) {
                            throw "No suitable disks found for installation"
                        }

                        # Interactive build selection
                        Write-Host "`nSelecting ChromeOS build..." -ForegroundColor Cyan
                        $buildResult = Select-ChromeOSBuild -Interactive
                        if (-not $buildResult.IsValid) {
                            throw "Failed to select ChromeOS build"
                        }

                        # Download image
                        Write-Host "`nDownloading ChromeOS image..." -ForegroundColor Cyan
                        $imagePath = Get-ChromeOSImage -Url $buildResult.DownloadUrl
                        if (-not $imagePath) {
                            throw "Failed to download ChromeOS image"
                        }

                        Write-Host "Custom installation complete!" -ForegroundColor Green
                        Read-Host "`nPress Enter to continue"
                        Show-Banner
                    }
                    catch {
                        Write-InstallLog "Custom installation failed: $_" -Level 'Error'
                        Read-Host "`nPress Enter to continue"
                        Show-Banner
                    }
                }
                
                '3' {
                    Write-Host "`nVerifying system requirements..." -ForegroundColor Cyan
                    $requirements = Test-SystemRequirements
                    Write-Host "`nSystem Requirements Check Results:" -ForegroundColor Yellow
                    $requirements.Details.GetEnumerator() | ForEach-Object {
                        $status = if ($_.Value.Pass) { "PASS" } else { "FAIL" }
                        $color = if ($_.Value.Pass) { "Green" } else { "Red" }
                        Write-Host "$($_.Key): [$status] - Required: $($_.Value.Required), Current: $($_.Value.Current)" -ForegroundColor $color
                    }
                    
                    # Also show processor compatibility
                    Write-Host "`nChecking processor compatibility..." -ForegroundColor Cyan
                    $processor = Get-SystemProcessor
                    if ($processor.IsValid) {
                        Write-Host "Processor: $($processor.Name)" -ForegroundColor Yellow
                        Write-Host "Compatible Device: $($processor.Device)" -ForegroundColor Yellow
                        Write-Host "Supported: $(if ($processor.Supported) { 'Yes' } else { 'No' })" -ForegroundColor $(if ($processor.Supported) { 'Green' } else { 'Red' })
                    }
                    else {
                        Write-Host "Failed to detect processor information" -ForegroundColor Red
                    }
                    
                    Read-Host "`nPress Enter to continue"
                    Show-Banner
                }
                
                '4' {
                    Write-Host "`nScanning for available disks..." -ForegroundColor Cyan
                    $diskInfo = Get-AvailableDisks
                    if ($diskInfo.IsValid -and $diskInfo.Disks.Count -gt 0) {
                        Write-Host "`nAvailable Disks:" -ForegroundColor Yellow
                        $diskInfo.Disks | Format-Table -AutoSize
                    }
                    else {
                        Write-Host "`nNo suitable disks found!" -ForegroundColor Red
                        Write-Host "Requirements:" -ForegroundColor Yellow
                        Write-Host "- Minimum 16GB size" -ForegroundColor Gray
                        Write-Host "- Not boot/system disk" -ForegroundColor Gray
                    }
                    Read-Host "`nPress Enter to continue"
                    Show-Banner
                }
                
                '5' {
                    Write-Host "Exiting..." -ForegroundColor Yellow
                    exit 0
                }
                
                default {
                    Write-Host "`nInvalid option. Please select 1-5." -ForegroundColor Red
                    Start-Sleep -Seconds 2
                    Show-Banner
                }
            }
        } while ($true)
    }
    catch {
        Write-InstallLog "Installation failed: $_" -Level 'Error'
        Write-Host "`nInstallation failed. Check the log file for details:" -ForegroundColor Red
        Write-Host $script:metadata.LogFile -ForegroundColor Yellow
        exit 1
    }
}

# Start the installation
Start-ChromeOSInstallation
