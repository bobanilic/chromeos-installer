<#
.SYNOPSIS
    ChromeOS Windows Installer Script
.DESCRIPTION
    Automated ChromeOS installation script for Windows systems.
    Handles partitioning, formatting, and installation using PowerShell and Cygwin.
.NOTES
    Author: Created for bobanilic
    Created: 2024-12-21
    Version: 1.0
    Requires: PowerShell 5.1+, Admin rights, Cygwin with e2fsprogs
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

# Add this at the beginning of the script after global constants
$Global:REQUIRED_CYGWIN_PACKAGES = @{
    'pv'        = 'pv.exe'
    'tar'       = 'tar.exe'
    'unzip'     = 'unzip.exe'
    'e2fsprogs' = 'mkfs.ext4.exe'
}

function Test-CygwinPrerequisites {
    param (
        [Parameter(Mandatory=$false)]
        [switch]$Detailed
    )

    $results = @{
        IsValid = $true
        Missing = @()
        CygwinPath = $Global:CHROMEOS_CONSTANTS.CYGWIN_PATH
        Details = @{}
    }

    # Check if Cygwin is installed
    if (-not (Test-Path $Global:CHROMEOS_CONSTANTS.CYGWIN_PATH)) {
        Write-InstallLog "Cygwin not found at $($Global:CHROMEOS_CONSTANTS.CYGWIN_PATH)" -Level 'Error'
        $results.IsValid = $false
        $results.Missing += "Cygwin installation"
        return $results
    }

    # Check each required package
    foreach ($package in $Global:REQUIRED_CYGWIN_PACKAGES.GetEnumerator()) {
        $executablePath = Join-Path $Global:CHROMEOS_CONSTANTS.CYGWIN_PATH "bin\$($package.Value)"
        $isInstalled = Test-Path $executablePath

        $results.Details[$package.Key] = @{
            Installed = $isInstalled
            Path = $executablePath
        }

        if (-not $isInstalled) {
            $results.IsValid = $false
            $results.Missing += $package.Key
        }
    }

    # Log results
    if ($results.IsValid) {
        Write-InstallLog "All required Cygwin packages are installed" -Level 'Info'
    } else {
        Write-InstallLog "Missing required Cygwin packages: $($results.Missing -join ', ')" -Level 'Error'
        Write-InstallLog "Please install missing packages using Cygwin's setup.exe" -Level 'Info'
        Write-InstallLog "Run: setup-x86_64.exe -q -P $($results.Missing -join ',')" -Level 'Info'
    }

    if ($Detailed) {
        return $results
    }
    return $results.IsValid
}

# Add this check at the beginning of the main installation function
function Install-ChromeOS {
    param (
        [Parameter(Mandatory=$false)]
        [int]$DiskNumber = -1,
        [Parameter(Mandatory=$false)]
        [switch]$DualBoot,
        [Parameter(Mandatory=$false)]
        [switch]$Force
    )

    try {
        Write-InstallLog "Starting ChromeOS installation process" -Level 'Info'
        
        # Check prerequisites
        Write-InstallLog "Checking Cygwin prerequisites..." -Level 'Info'
        $prereqCheck = Test-CygwinPrerequisites -Detailed
        if (-not $prereqCheck.IsValid) {
            throw "Missing prerequisites: $($prereqCheck.Missing -join ', ')"
        }

        # Continue with rest of installation
        # ... [Rest of the installation code]
    }
    catch {
        Write-InstallLog "Installation failed: $_" -Level 'Error'
        throw
    }
}

# Helper function to install Cygwin packages
function Install-CygwinPackages {
    param (
        [Parameter(Mandatory=$false)]
        [string]$CygwinMirror = "https://mirrors.kernel.org/sourceware/cygwin/",
        [Parameter(Mandatory=$false)]
        [string]$InstallPath = $Global:CHROMEOS_CONSTANTS.CYGWIN_PATH
    )

    try {
        # Download Cygwin setup
        $setupExe = "$env:TEMP\setup-x86_64.exe"
        if (-not (Test-Path $setupExe)) {
            Write-InstallLog "Downloading Cygwin setup..." -Level 'Info'
            $webClient = New-Object System.Net.WebClient
            $webClient.DownloadFile("https://www.cygwin.com/setup-x86_64.exe", $setupExe)
        }

        # Install/update required packages
        $packages = $Global:REQUIRED_CYGWIN_PACKAGES.Keys -join ','
        $arguments = @(
            "--quiet-mode",
            "--no-desktop",
            "--no-startmenu",
            "--no-shortcuts",
            "--site $CygwinMirror",
            "--root `"$InstallPath`"",
            "--packages $packages"
        )

        Write-InstallLog "Installing Cygwin packages: $packages" -Level 'Info'
        Start-Process -FilePath $setupExe -ArgumentList $arguments -Wait -NoNewWindow

        # Verify installation
        $verifyResult = Test-CygwinPrerequisites
        if (-not $verifyResult) {
            throw "Failed to install all required packages"
        }

        Write-InstallLog "Cygwin packages installed successfully" -Level 'Info'
        return $true
    }
    catch {
        Write-InstallLog "Failed to install Cygwin packages: $_" -Level 'Error'
        return $false
    }
}

# Example usage:
# 1. Check if prerequisites are met
if (-not (Test-CygwinPrerequisites)) {
    Write-Host "Would you like to install missing Cygwin packages? (Y/N)"
    $response = Read-Host
    if ($response -eq 'Y') {
        Install-CygwinPackages
    } else {
        Write-InstallLog "Installation cancelled - missing prerequisites" -Level 'Error'
        exit 1
    }
}

# 2. Proceed with installation
Install-ChromeOS -DualBoot:$false

# Initialize strict mode and error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'Continue'

#region Global Constants
$Global:CHROMEOS_CONSTANTS = @{
    SECTOR_SIZE = 512
    ALIGNMENT = 1MB
    RESERVED_SPACE = 32MB
    CYGWIN_PATH = "C:\cygwin64"
    LOG_PATH = "$env:USERPROFILE\ChromeOS_Install_Logs"
    TEMP_PATH = "$env:TEMP\ChromeOS_Install"
    DOWNLOAD_PATH = "$env:USERPROFILE\Downloads\ChromeOS"
}

$Global:CHROMEOS_PARTITION_TYPES = @{
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
    'ROOT-B' = @{
        Guid = "3CB8E202-3B7E-47DD-8A3C-7FF2A13CFCEC"
        MinSize = 8GB
        Format = "ext4"
        Required = $false
    }
    'STATE' = @{
        Guid = "CA7D7CCB-63ED-4C53-861C-1742536059CC"
        MinSize = 1GB
        Format = "ext4"
        Required = $true
    }
    'KERN-A' = @{
        Guid = "FE3A2A5D-4F32-41A7-B725-ACCC3285A309"
        MinSize = 64MB
        Format = "raw"
        Required = $true
    }
    'KERN-B' = @{
        Guid = "FE3A2A5D-4F32-41A7-B725-ACCC3285A309"
        MinSize = 64MB
        Format = "raw"
        Required = $false
    }
}
#endregion

#region C# Classes
# Add required .NET types
$DiskAccessCode = @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public class DiskAccess
{
    // Win32 API constants
    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint FILE_SHARE_READ = 0x1;
    private const uint FILE_SHARE_WRITE = 0x2;
    private const uint OPEN_EXISTING = 3;
    private const uint IOCTL_DISK_GET_DRIVE_LAYOUT_EX = 0x00070050;
    private const uint IOCTL_DISK_SET_DRIVE_LAYOUT_EX = 0x0007C050;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    [StructLayout(LayoutKind.Sequential)]
    public struct PARTITION_INFORMATION_GPT
    {
        public Guid PartitionType;
        public Guid PartitionId;
        public ulong Attributes;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 36)]
        public char[] Name;
    }

    public static SafeFileHandle OpenDisk(int diskNumber, bool readOnly = false)
    {
        string path = $"\\\\.\\PhysicalDrive{diskNumber}";
        uint access = readOnly ? GENERIC_READ : (GENERIC_READ | GENERIC_WRITE);
        uint share = readOnly ? FILE_SHARE_READ : (FILE_SHARE_READ | FILE_SHARE_WRITE);

        return CreateFile(path, access, share, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
    }
}
"@

Add-Type -TypeDefinition $DiskAccessCode
#endregion

#region Resource Management
class ChromeOSResourceManager : IDisposable {
    hidden [System.Collections.Generic.List[System.IDisposable]] $resources
    hidden [bool] $disposed

    ChromeOSResourceManager() {
        $this.resources = [System.Collections.Generic.List[System.IDisposable]]::new()
        $this.disposed = $false
    }

    [void] AddResource([System.IDisposable]$resource) {
        if ($null -ne $resource) {
            $this.resources.Add($resource)
        }
    }

    [void] Dispose() {
        $this.Dispose($true)
        [System.GC]::SuppressFinalize($this)
    }

    hidden [void] Dispose([bool]$disposing) {
        if (-not $this.disposed) {
            if ($disposing) {
                for ($i = $this.resources.Count - 1; $i -ge 0; $i--) {
                    try {
                        $this.resources[$i].Dispose()
                    }
                    catch {
                        Write-Warning "Error disposing resource: $_"
                    }
                }
                $this.resources.Clear()
            }
            $this.disposed = $true
        }
    }
}
#endregion

#region Logging Functions
function Write-InstallLog {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [Parameter(Mandatory=$false)]
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    if (-not (Test-Path $Global:CHROMEOS_CONSTANTS.LOG_PATH)) {
        New-Item -ItemType Directory -Path $Global:CHROMEOS_CONSTANTS.LOG_PATH -Force | Out-Null
    }

    $logFile = Join-Path $Global:CHROMEOS_CONSTANTS.LOG_PATH "chromeos_install_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logMessage

    switch ($Level) {
        'Info' { Write-Host $logMessage }
        'Warning' { Write-Warning $logMessage }
        'Error' { Write-Error $logMessage }
    }
}
#endregion

#region Disk Management Functions
# [Previous functions: Format-ChromeOSPartition, Get-DiskFreeSpace, etc.]
# ... [Include all the previously defined disk management functions here]
#endregion

#region GUI Functions
function Show-ChromeOSInstaller {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "ChromeOS Installer"
    $form.Size = New-Object System.Drawing.Size(600,400)
    $form.StartPosition = "CenterScreen"

    # Add CPU information
    $cpuInfo = Get-CpuGeneration
    $cpuLabel = New-Object System.Windows.Forms.Label
    $cpuLabel.Location = New-Object System.Drawing.Point(10,20)
    $cpuLabel.Size = New-Object System.Drawing.Size(280,20)
    $cpuLabel.Text = "CPU: $($cpuInfo.Name) (Gen: $($cpuInfo.Generation))"
    $form.Controls.Add($cpuLabel)

    # Add disk selection
    $diskLabel = New-Object System.Windows.Forms.Label
    $diskLabel.Location = New-Object System.Drawing.Point(10,50)
    $diskLabel.Size = New-Object System.Drawing.Size(280,20)
    $diskLabel.Text = "Select Installation Disk:"
    $form.Controls.Add($diskLabel)

    $diskCombo = New-Object System.Windows.Forms.ComboBox
    $diskCombo.Location = New-Object System.Drawing.Point(10,70)
    $diskCombo.Size = New-Object System.Drawing.Size(280,20)
    Get-Disk | ForEach-Object {
        $diskCombo.Items.Add("Disk $($_.Number): $($_.FriendlyName) ($([Math]::Round($_.Size/1GB))GB)")
    }
    $form.Controls.Add($diskCombo)

    # Add install button
    $installButton = New-Object System.Windows.Forms.Button
    $installButton.Location = New-Object System.Drawing.Point(10,300)
    $installButton.Size = New-Object System.Drawing.Size(120,30)
    $installButton.Text = "Install ChromeOS"
    $installButton.Add_Click({
        $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.Close()
    })
    $form.Controls.Add($installButton)

    $form.ShowDialog()
}
#endregion

#region Main Installation Function
function Install-ChromeOS {
    param (
        [Parameter(Mandatory=$false)]
        [int]$DiskNumber = -1,
        [Parameter(Mandatory=$false)]
        [switch]$DualBoot,
        [Parameter(Mandatory=$false)]
        [switch]$NoGUI,
        [Parameter(Mandatory=$false)]
        [string]$ChromeOSVersion
    )

    try {
        Write-InstallLog "Starting ChromeOS installation"

        # Show GUI if not suppressed
        if (-not $NoGUI) {
            $result = Show-ChromeOSInstaller
            if ($result -ne [System.Windows.Forms.DialogResult]::OK) {
                Write-InstallLog "Installation cancelled by user" -Level Warning
                return
            }
        }

        # Validate requirements
        if (-not (Test-Prerequisites)) {
            throw "Prerequisites check failed"
        }

        # Initialize disk
        Write-InstallLog "Initializing disk $DiskNumber"
        Initialize-ChromeOSLayout -DiskNumber $DiskNumber -DualBoot:$DualBoot

        # Download ChromeOS image
        Write-InstallLog "Downloading ChromeOS image"
        $imagePath = Get-ChromeOSImage -Version $ChromeOSVersion

        # Install ChromeOS
        Write-InstallLog "Installing ChromeOS"
        Install-ChromeOSImage -ImagePath $imagePath -DiskNumber $DiskNumber

        Write-InstallLog "ChromeOS installation completed successfully"
    }
    catch {
        Write-InstallLog "Installation failed: $_" -Level Error
        throw
    }
}
#endregion

# Script entry point
if ($MyInvocation.InvocationName -ne ".") {
    # Script is being run directly (not sourced)
    try {
        Install-ChromeOS
    }
    catch {
        Write-InstallLog "Fatal error: $_" -Level Error
        exit 1
    }
}
