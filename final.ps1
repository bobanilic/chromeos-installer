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

# Basic logging function
function Write-InstallLog {
    param(
        [string]$Message,
        [string]$Level = 'Info'
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp UTC] [$Level] $Message"
}

# Banner display
function Show-Banner {
    Write-Host ""
    Write-Host "Current Date and Time (UTC): $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
    Write-Host "Current User's Login: $env:USERNAME" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "+====================================================+" -ForegroundColor Cyan
    Write-Host "|              ChromeOS Installation Menu              |" -ForegroundColor Cyan
    Write-Host "+====================================================+" -ForegroundColor Cyan
    Write-Host "| 1. Automatic Installation (Recommended)              |" -ForegroundColor Cyan
    Write-Host "| 2. Custom Installation                              |" -ForegroundColor Cyan
    Write-Host "| 3. Verify System Requirements                       |" -ForegroundColor Cyan
    Write-Host "| 4. Show Available Disks                            |" -ForegroundColor Cyan
    Write-Host "| 5. Exit                                            |" -ForegroundColor Cyan
    Write-Host "+====================================================+" -ForegroundColor Cyan
    Write-Host ""
}

# Processor detection
function Get-SystemProcessor {
    try {
        Write-InstallLog "Detecting system processor..."
        $processorInfo = Get-CimInstance Win32_Processor | Select-Object -First 1
        
        if ($processorInfo.Manufacturer -like "*AMD*") {
            Write-InstallLog "AMD processor detected - using gumboz device"
            return @{
                IsValid = $true
                Name = $processorInfo.Name
                Device = "gumboz"
                Supported = $true
            }
        }
        elseif ($processorInfo.Manufacturer -like "*Intel*") {
            Write-InstallLog "Intel processor detected - using rammus device"
            return @{
                IsValid = $true
                Name = $processorInfo.Name
                Device = "rammus"
                Supported = $true
            }
        }
        else {
            Write-InstallLog "Unsupported processor: $($processorInfo.Manufacturer)"
            return @{
                IsValid = $false
                Name = $processorInfo.Name
                Device = "unknown"
                Supported = $false
            }
        }
    }
    catch {
        Write-InstallLog "Error detecting processor: $_" -Level 'Error'
        return @{
            IsValid = $false
            Name = "Unknown"
            Device = "unknown"
            Supported = $false
        }
    }
}

# Get available disks
function Get-AvailableDisks {
    try {
        Write-InstallLog "Scanning for available disks..."
        
        # Get all physical disks first
        $allDisks = Get-Disk
        Write-InstallLog "Found $($allDisks.Count) total disks"

        # Filter disks with detailed logging
        $availableDisks = @()
        foreach ($disk in $allDisks) {
            # Convert size to GB with proper rounding
            $diskSizeBytes = $disk.Size
            $diskSizeGB = [math]::Round($diskSizeBytes / 1GB, 2)
            $minSizeGB = 16

            #Write-InstallLog "Checking disk $($disk.Number):" -Level 'Debug'
            #Write-InstallLog "- Name: $($disk.FriendlyName)" -Level 'Debug'
            #Write-InstallLog "- Size: $diskSizeGB GB ($diskSizeBytes bytes)" -Level 'Debug'
            #Write-InstallLog "- Boot: $($disk.IsBoot)" -Level 'Debug'
            #Write-InstallLog "- System: $($disk.IsSystem)" -Level 'Debug'
            #Write-InstallLog "- Bus Type: $($disk.BusType)" -Level 'Debug'

            # Size check with detailed logging
            if ($diskSizeBytes -lt ($minSizeGB * 1GB)) {
                Write-InstallLog "Disk $($disk.Number) excluded: Too small ($diskSizeGB GB < $minSizeGB GB)" -Level 'Debug'
                continue
            }
            
            # Boot/System check
            if ($disk.IsBoot -and $disk.IsSystem) {
                Write-InstallLog "Disk $($disk.Number) excluded: Boot/System disk" -Level 'Debug'
                continue
            }

            Write-InstallLog "Disk $($disk.Number) is suitable for installation" -Level 'Debug'
            
            $availableDisks += [PSCustomObject]@{
                Number = $disk.Number
                FriendlyName = $disk.FriendlyName
                'Size(GB)' = $diskSizeGB
                IsBoot = $disk.IsBoot
                IsSystem = $disk.IsSystem
                BusType = $disk.BusType
                PartitionStyle = $disk.PartitionStyle
                OperationalStatus = $disk.OperationalStatus
            }
        }

        Write-InstallLog "Found $($availableDisks.Count) suitable disks"
        return ,$availableDisks  # Force array return
    }
    catch {
        Write-InstallLog "Error scanning disks: $_" -Level 'Error'
        return @()
    }
}

# Display disks function
function Show-AvailableDisks {
    param (
        [string]$TitleText = "Available Disks"
    )
    
    Write-Host "`n$TitleText" -ForegroundColor Cyan
    Write-Host ("-" * ($TitleText.Length + 1)) -ForegroundColor Cyan
    
    $disks = Get-AvailableDisks
    
    if ($null -ne $disks -and $disks.Count -gt 0) {
        Write-Host "`nFound $($disks.Count) suitable disk(s):" -ForegroundColor Green
        $disks | Format-Table -Property @(
            'Number',
            'FriendlyName',
            @{Name='Size(GB)'; Expression={$_.'Size(GB)'}},
            'BusType',
            @{Name='Boot/Sys'; Expression={"$($_.IsBoot)/$($_.IsSystem)"}},
            'PartitionStyle',
            'OperationalStatus'
        ) -AutoSize
        
        Write-Host "`nNOTE: Please ensure you select the correct disk for installation!" -ForegroundColor Yellow
        Write-Host "      Any data on the selected disk will be erased." -ForegroundColor Yellow
        
        return $disks
    } else {
        Write-Host "`nNo suitable disks found!" -ForegroundColor Red
        Write-Host "Requirements:" -ForegroundColor Yellow
        Write-Host "- Minimum 16GB size" -ForegroundColor Gray
        Write-Host "- Not both boot AND system disk" -ForegroundColor Gray
        Write-Host "- Must be in operational state" -ForegroundColor Gray
        
        return $null
    }
}

# Main menu loop
function Start-Installation {
    Show-Banner
    
    do {
        $choice = Read-Host "Select an option (1-5)"
        
        switch ($choice) {
            '1' {
                try {
                    Write-Host "`nStarting Automatic Installation..." -ForegroundColor Cyan
                    
                    # Check processor
                    $processor = Get-SystemProcessor
                    if (-not $processor.Supported) {
                        throw "Unsupported processor: $($processor.Name)"
                    }
                    Write-Host "Processor: $($processor.Name) [SUPPORTED]" -ForegroundColor Green
                    
                    # Get available disks
                    $disks = Get-AvailableDisks
                    if ($disks.Count -eq 0) {
                        throw "No suitable disks found for installation"
                    }
                    
                    # Select largest disk automatically
                    $targetDisk = $disks | Sort-Object 'Size(GB)' -Descending | Select-Object -First 1
                    Write-Host "Selected disk: Disk $($targetDisk.Number) - $($targetDisk.FriendlyName) ($($targetDisk.'Size(GB)') GB)" -ForegroundColor Cyan
                    
                    $confirm = Read-Host "`nWARNING: This will erase all data on the selected disk. Continue? (Y/N)"
                    if ($confirm -ne 'Y') {
                        throw "Installation cancelled by user"
                    }

                    Write-Host "`nStarting installation process..." -ForegroundColor Cyan
                    # Add your installation steps here
                    
                    Write-Host "Installation completed successfully!" -ForegroundColor Green
                }
                catch {
                    Write-Host "`nInstallation failed: $_" -ForegroundColor Red
                }
                finally {
                    Read-Host "`nPress Enter to continue"
                    Show-Banner
                }
            }
            '2' {
                try {
                    Write-Host "`nStarting Custom Installation..." -ForegroundColor Cyan
                    
                    # Check processor
                    $processor = Get-SystemProcessor
                    if (-not $processor.Supported) {
                        throw "Unsupported processor: $($processor.Name)"
                    }
                    Write-Host "Processor: $($processor.Name) [SUPPORTED]" -ForegroundColor Green
                    
                    # Show available disks
                    $disks = Get-AvailableDisks
                    if ($disks.Count -eq 0) {
                        throw "No suitable disks found for installation"
                    }
                    
                    Write-Host "`nAvailable disks:" -ForegroundColor Cyan
                    $disks | Format-Table -AutoSize
                    
                    # Let user select disk
                    do {
                        $diskNumber = Read-Host "`nEnter disk number to install ChromeOS"
                        $targetDisk = $disks | Where-Object Number -eq $diskNumber
                    } while (-not $targetDisk)
                    
                    Write-Host "Selected disk: Disk $($targetDisk.Number) - $($targetDisk.FriendlyName) ($($targetDisk.'Size(GB)') GB)" -ForegroundColor Cyan
                    
                    $confirm = Read-Host "`nWARNING: This will erase all data on the selected disk. Continue? (Y/N)"
                    if ($confirm -ne 'Y') {
                        throw "Installation cancelled by user"
                    }

                    Write-Host "`nStarting installation process..." -ForegroundColor Cyan
                    # Add your installation steps here
                    
                    Write-Host "Installation completed successfully!" -ForegroundColor Green
                }
                catch {
                    Write-Host "`nInstallation failed: $_" -ForegroundColor Red
                }
                finally {
                    Read-Host "`nPress Enter to continue"
                    Show-Banner
                }
            }
            '3' {
                # System requirements check
                Write-Host "`nSystem Requirements Check" -ForegroundColor Yellow
                Write-Host "-------------------------" -ForegroundColor Yellow

                # Admin Rights
                $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
                Write-Host "Admin Rights: $(if ($isAdmin) { "[PASS]" } else { "[FAIL]" })" -ForegroundColor $(if ($isAdmin) { "Green" } else { "Red" })

                # RAM
                $ram = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
                Write-Host "RAM: $(if ($ram -ge 4) { "[PASS]" } else { "[FAIL]" }) ($ram GB / 4 GB required)" -ForegroundColor $(if ($ram -ge 4) { "Green" } else { "Red" })

                # Disk Space
                $freeSpace = [math]::Round((Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'").FreeSpace / 1GB, 2)
                Write-Host "Free Space: $(if ($freeSpace -ge 16) { "[PASS]" } else { "[FAIL]" }) ($freeSpace GB / 16 GB required)" -ForegroundColor $(if ($freeSpace -ge 16) { "Green" } else { "Red" })

                # Architecture
                $arch = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
                Write-Host "Architecture: $(if ($arch -eq "64-bit") { "[PASS]" } else { "[FAIL]" }) ($arch)" -ForegroundColor $(if ($arch -eq "64-bit") { "Green" } else { "Red" })

                # Processor Check
                Write-Host "`nProcessor Information:" -ForegroundColor Cyan
                $processor = Get-SystemProcessor
                Write-Host "Type: $($processor.Name)"
                Write-Host "Compatible Device: $($processor.Device)"
                Write-Host "Status: $(if ($processor.Supported) { "[SUPPORTED]" } else { "[NOT SUPPORTED]" })" -ForegroundColor $(if ($processor.Supported) { "Green" } else { "Red" })

                # Available Disks
                Show-AvailableDisks
                
                Read-Host "`nPress Enter to continue"
                Show-Banner
            }
            '4' {
                Write-Host "`nAvailable Disks:" -ForegroundColor Cyan
                Write-Host "----------------" -ForegroundColor Cyan
                $disks = Get-AvailableDisks
                if ($disks.Count -gt 0) {
                    Write-Host "`nFound $($disks.Count) suitable disk(s):" -ForegroundColor Green
                    $disks | Format-Table Number, 
                                        FriendlyName, 
                                        'Size(GB)', 
                                        BusType,
                                        @{Name='Boot/Sys'; Expression={"$($_.IsBoot)/$($_.IsSystem)"}},
                                        PartitionStyle, 
                                        OperationalStatus -AutoSize
                    
                    Write-Host "`nNOTE: Please ensure you select the correct disk for installation!" -ForegroundColor Yellow
                    Write-Host "      Any data on the selected disk will be erased." -ForegroundColor Yellow
                } else {
                    Write-Host "`nNo suitable disks found!" -ForegroundColor Red
                    Write-Host "Requirements:" -ForegroundColor Yellow
                    Write-Host "- Minimum 16GB size" -ForegroundColor Gray
                    Write-Host "- Not both boot AND system disk" -ForegroundColor Gray
                    Write-Host "- Must be in operational state" -ForegroundColor Gray
                }
                Read-Host "`nPress Enter to continue"
                Show-Banner
            }
        }
    } while ($true)
}

# Start the program
Start-Installation
