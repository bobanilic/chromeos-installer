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

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$Debug,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipDiskCheck,
    
    [Parameter(Mandatory=$false)]
    [string]$RecoveryUrl
)

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
    $banner = @"
╔════════════════════════════════════════════════════════════╗
║                 ChromeOS Installer v$($Global:SCRIPT_VERSION)                  ║
║                                                            ║
║  Current Time (UTC) : $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")        ║
║  User               : $($script:metadata.UserName)         ║
║  Computer          : $($script:metadata.ComputerName)     ║
║                                                            ║
║  Author: bobanilic                                        ║
║  Last Updated: $($Global:SCRIPT_DATE)                     ║
╚════════════════════════════════════════════════════════════╝
"@
    Write-Host $banner -ForegroundColor Cyan
    Write-InstallLog "Script started - $($script:metadata | ConvertTo-Json)" -Level 'Debug'
}

# System requirements validation
function Test-SystemRequirements {
    Write-InstallLog "Checking system requirements..." -Level 'Info'
    
    $requirements = @{
        IsValid = $true
        Details = @{}
    }

    # Check PowerShell version
    $requirements.Details.PowerShell = @{
        Required = "5.1"
        Current = $PSVersionTable.PSVersion.ToString()
        Pass = $PSVersionTable.PSVersion.Major -ge 5
    }

    # Check Administrator privileges
    $requirements.Details.AdminRights = @{
        Required = $true
        Current = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        Pass = $requirements.Details.AdminRights.Current
    }

    # Check available memory
    $memory = Get-WmiObject -Class Win32_ComputerSystem
    $memoryGB = [math]::Round($memory.TotalPhysicalMemory / 1GB, 2)
    $requirements.Details.Memory = @{
        Required = "$($Global:CONFIG.MinimumMemory / 1GB) GB"
        Current = "$memoryGB GB"
        Pass = $memoryGB -ge ($Global:CONFIG.MinimumMemory / 1GB)
    }

    # Check Cygwin installation
    $requirements.Details.Cygwin = @{
        Required = $true
        Current = Test-Path $Global:CONFIG.Paths.Cygwin
        Pass = $requirements.Details.Cygwin.Current
    }

    # Check required Cygwin packages
    $requirements.Details.CygwinPackages = @{
        Required = $Global:CONFIG.RequiredPackages.Keys -join ", "
        Missing = @()
        Pass = $true
    }

    foreach ($package in $Global:CONFIG.RequiredPackages.GetEnumerator()) {
        $execPath = Join-Path $Global:CONFIG.Paths.Cygwin "bin\$($package.Value)"
        if (-not (Test-Path $execPath)) {
            $requirements.Details.CygwinPackages.Missing += $package.Key
            $requirements.Details.CygwinPackages.Pass = $false
        }
    }

    # Update overall validity
    $requirements.IsValid = $requirements.Details.Values.Pass -notcontains $false

    # Log results
    foreach ($check in $requirements.Details.GetEnumerator()) {
        $status = if ($check.Value.Pass) { "PASS" } else { "FAIL" }
        $message = "$($check.Key): [$status] - Required: $($check.Value.Required), Current: $($check.Value.Current)"
        $level = if ($check.Value.Pass) { "Debug" } else { "Error" }
        Write-InstallLog $message -Level $level
    }

    return $requirements
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
    Write-InstallLog "Detecting system processor..." -Level 'Info'
    
    try {
        $cpu = Get-WmiObject Win32_Processor | Select-Object -First 1
        $processorName = $cpu.Name
        
        $processorInfo = @{
            Name = $processorName
            Manufacturer = $cpu.Manufacturer
            MaxClockSpeed = $cpu.MaxClockSpeed
            NumberOfCores = $cpu.NumberOfCores
            Architecture = $cpu.AddressWidth
            Virtualization = $cpu.VirtualizationFirmwareEnabled
        }
        
        Write-InstallLog "Processor details: $($processorInfo | ConvertTo-Json)" -Level 'Debug'
        
        $isAMD = $processorName -match "AMD"
        
        if ($isAMD) {
            Write-InstallLog "AMD processor detected - using gumboz device" -Level 'Info'
            return @{
                Type = "AMD"
                Device = "gumboz"
                Name = $processorName
                Description = $Global:CONFIG.Devices['gumboz'].Description
                Details = $processorInfo
                Supported = $true
            }
        }

        # Extract Intel generation
        if ($processorName -match "Intel.*i[3579]-(\d{4,5})|Intel.*i[3579]\s+(\d{4,5})") {
            $model = $matches[1] ?? $matches[2]
            $generation = [int]($model.ToString()[0])
            
            $device = switch ($generation) {
                { $_ -le 9 } { "shyvana" }
                10 { "jinlon" }
                default { "voxel" }
            }

            Write-InstallLog "Intel $generation`th Gen processor detected - using $device device" -Level 'Info'
            
            return @{
                Type = "Intel"
                Generation = $generation
                Device = $device
                Name = $processorName
                Description = $Global:CONFIG.Devices[$device].Description
                Details = $processorInfo
                Supported = $true
            }
        }

        Write-InstallLog "Unsupported processor detected: $processorName" -Level 'Warning'
        return @{
            Type = "Unknown"
            Name = $processorName
            Details = $processorInfo
            Supported = $false
        }
    }
    catch {
        Write-InstallLog "Failed to detect processor: $_" -Level 'Error'
        throw
    }
}

# ChromeOS build fetching and selection
function Get-ChromeOSBuilds {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet('shyvana', 'jinlon', 'voxel', 'gumboz')]
        [string]$Device,
        
        [Parameter(Mandatory=$false)]
        [switch]$UseCache,
        
        [Parameter(Mandatory=$false)]
        [switch]$ForceRefresh
    )

    try {
        Write-InstallLog "Fetching ChromeOS builds for device: $Device" -Level 'Info'
        
        # Cache management
        $cacheFile = Join-Path $Global:CONFIG.Paths.Cache "builds_$Device.json"
        if ($UseCache -and -not $ForceRefresh -and (Test-Path $cacheFile)) {
            $cacheAge = (Get-Date) - (Get-Item $cacheFile).LastWriteTime
            if ($cacheAge.TotalHours -lt 24) {
                Write-InstallLog "Using cached build information (Age: $($cacheAge.TotalHours.ToString('N2')) hours)" -Level 'Debug'
                $builds = Get-Content $cacheFile | ConvertFrom-Json
                return $builds
            }
        }

        # API request with retry logic
        $maxRetries = 3
        $retryCount = 0
        $success = $false

        while (-not $success -and $retryCount -lt $maxRetries) {
            try {
                $apiUrl = "https://cros.tech/api/v1/device/$Device"
                Write-InstallLog "Querying API: $apiUrl (Attempt $($retryCount + 1))" -Level 'Debug'
                
                $response = Invoke-RestMethod -Uri $apiUrl -Method Get -ErrorAction Stop
                $success = $true
            }
            catch {
                $retryCount++
                if ($retryCount -lt $maxRetries) {
                    Write-InstallLog "API request failed, retrying in 5 seconds..." -Level 'Warning'
                    Start-Sleep -Seconds 5
                }
                else {
                    throw
                }
            }
        }

        # Process and sort builds
        $builds = $response.builds | Where-Object {
            $_.channel -eq "stable" -and
            $_.success -eq $true -and
            $_.downloadUrl
        } | Sort-Object -Property {[version]$_.version} -Descending |
        Select-Object -First 5 @{
            Name = 'Version'
            Expression = {$_.version}
        }, @{
            Name = 'ReleaseDate'
            Expression = {[datetime]$_.date}
        }, @{
            Name = 'DownloadUrl'
            Expression = {$_.downloadUrl}
        }, @{
            Name = 'Size'
            Expression = {[math]::Round($_.filesize / 1GB, 2).ToString() + " GB"}
        }, @{
            Name = 'Channel'
            Expression = {$_.channel}
        }

        if (-not $builds) {
            throw "No valid builds found for $Device"
        }

        # Cache results
        if (-not (Test-Path $Global:CONFIG.Paths.Cache)) {
            New-Item -ItemType Directory -Path $Global:CONFIG.Paths.Cache -Force | Out-Null
        }
        $builds | ConvertTo-Json | Set-Content $cacheFile

        Write-InstallLog "Successfully retrieved $($builds.Count) builds for $Device" -Level 'Success'
        return $builds
    }
    catch {
        Write-InstallLog "Failed to fetch builds for $Device: $_" -Level 'Error'
        throw
    }
}

function Select-ChromeOSBuild {
    param(
        [Parameter(Mandatory=$false)]
        [string]$RecoveryUrl,
        
        [Parameter(Mandatory=$false)]
        [switch]$Interactive,
        
        [Parameter(Mandatory=$false)]
        [switch]$ForceLatest
    )
    
    try {
        if ($RecoveryUrl) {
            Write-InstallLog "Using provided recovery URL: $RecoveryUrl" -Level 'Info'
            return @{
                Version = "Custom"
                DownloadUrl = $RecoveryUrl
                ReleaseDate = Get-Date
                IsCustom = $true
            }
        }

        # Detect processor and compatible device
        $processor = Get-SystemProcessor
        if (-not $processor.Supported) {
            throw "Unsupported processor: $($processor.Name)"
        }

        Write-InstallLog "System compatible with ChromeOS device: $($processor.Device) ($($processor.Description))" -Level 'Info'

        # Fetch latest builds
        $builds = Get-ChromeOSBuilds -Device $processor.Device -UseCache:(-not $ForceLatest)
        
        # Display available builds
        Write-Host "`nAvailable ChromeOS builds for $($processor.Device):" -ForegroundColor Cyan
        $builds | Format-Table Version, ReleaseDate, Size, Channel -AutoSize

        $selectedBuild = if ($ForceLatest) {
            $builds[0]
        }
        elseif ($Interactive) {
            do {
                Write-Host "`nSelect a build number (1-$($builds.Count)) or press Enter for latest: " -NoNewline -ForegroundColor Yellow
                $selection = Read-Host
                
                if ([string]::IsNullOrWhiteSpace($selection)) {
                    $builds[0]
                    break
                }
                elseif ($selection -match '^\d+$' -and [int]$selection -ge 1 -and [int]$selection -le $builds.Count) {
                    $builds[[int]$selection - 1]
                    break
                }
                else {
                    Write-Host "Invalid selection. Please try again." -ForegroundColor Red
                }
            } while ($true)
        }
        else {
            $builds[0]
        }

        Write-InstallLog "Selected build: $($selectedBuild.Version) (Released: $($selectedBuild.ReleaseDate))" -Level 'Success'
        
        return @{
            Version = $selectedBuild.Version
            DownloadUrl = $selectedBuild.DownloadUrl
            ReleaseDate = $selectedBuild.ReleaseDate
            Size = $selectedBuild.Size
            Channel = $selectedBuild.Channel
            IsCustom = $false
            Device = $processor.Device
            ProcessorType = $processor.Type
        }
    }
    catch {
        Write-InstallLog "Failed to select ChromeOS build: $_" -Level 'Error'
        throw
    }
}
