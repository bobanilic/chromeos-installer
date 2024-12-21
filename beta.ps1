<#
.SYNOPSIS
    ChromeOS Windows Installer Script
.DESCRIPTION
    Installs ChromeOS on Windows systems using PowerShell and Cygwin tools.
.NOTES
    Author: bobanilic
    Modified: 2024-12-21
    Version: 2.0
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

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

# Version info
$SCRIPT_VERSION = "2.0.0"
$SCRIPT_DATE = "2024-12-21"

# Script metadata
$script:metadata = @{
    StartTime = [datetime]::UtcNow
    UserName = $env:USERNAME
    ComputerName = $env:COMPUTERNAME
    PSVersion = $PSVersionTable.PSVersion.ToString()
    OS = [System.Environment]::OSVersion.VersionString
}

# Global paths
$Global:CHROMEOS_PATHS = @{
    CYGWIN = "C:\cygwin64"
    LOGS = "$env:USERPROFILE\ChromeOS_Install_Logs"
    TEMP = "$env:TEMP\ChromeOS_Install"
    DOWNLOADS = "$env:USERPROFILE\Downloads\ChromeOS"
}

# Create necessary directories
$Global:CHROMEOS_PATHS.Values | ForEach-Object {
    if (-not (Test-Path $_)) {
        New-Item -ItemType Directory -Path $_ -Force | Out-Null
    }
}

# Enhanced logging function with timestamps and log rotation
function Write-InstallLog {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [Parameter(Mandatory=$false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Debug')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp UTC] [$Level] $Message"
    
    $logFile = Join-Path $Global:CHROMEOS_PATHS.LOGS "chromeos_install_$(Get-Date -Format 'yyyyMMdd').log"
    
    # Rotate logs if they get too large (>10MB)
    if ((Test-Path $logFile) -and ((Get-Item $logFile).Length -gt 10MB)) {
        Move-Item -Path $logFile -Destination "$logFile.old" -Force
    }

    Add-Content -Path $logFile -Value $logMessage

    switch ($Level) {
        'Debug' { 
            if ($Debug) { Write-Host $logMessage -ForegroundColor Gray } 
        }
        'Info' { Write-Host $logMessage }
        'Warning' { Write-Warning $logMessage }
        'Error' { Write-Error $logMessage }
    }
}

# Script banner
function Show-Banner {
    $banner = @"
ChromeOS Installer v$SCRIPT_VERSION
Created by: bobanilic
Date: $SCRIPT_DATE
Running as: $($script:metadata.UserName)
Computer: $($script:metadata.ComputerName)
"@
    Write-Host $banner -ForegroundColor Cyan
    Write-InstallLog "Script started - $($script:metadata | ConvertTo-Json)" -Level 'Info'
}

# Prerequisite checker with more detailed reporting
function Test-Prerequisites {
    Write-InstallLog "Checking system prerequisites..." -Level 'Info'
    
    $results = @{
        IsValid = $true
        Checks = @{}
    }

    # System checks
    $checks = @(
        @{
            Name = "PowerShell Version"
            Test = { $PSVersionTable.PSVersion.Major -ge 5 }
            Message = "PowerShell 5.0 or higher is required"
        }
        @{
            Name = "Admin Rights"
            Test = { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
            Message = "Administrator privileges required"
        }
        @{
            Name = "Cygwin Installation"
            Test = { Test-Path $Global:CHROMEOS_PATHS.CYGWIN }
            Message = "Cygwin not found at $($Global:CHROMEOS_PATHS.CYGWIN)"
        }
    )

    foreach ($check in $checks) {
        $results.Checks[$check.Name] = @{
            Success = & $check.Test
            Message = $check.Message
        }

        if (-not $results.Checks[$check.Name].Success) {
            $results.IsValid = $false
            Write-InstallLog "$($check.Name) check failed: $($check.Message)" -Level 'Error'
        }
        else {
            Write-InstallLog "$($check.Name) check passed" -Level 'Debug'
        }
    }

    # Required Cygwin packages
    $requiredPackages = @{
        'pv'        = 'pv.exe'
        'tar'       = 'tar.exe'
        'unzip'     = 'unzip.exe'
        'e2fsprogs' = 'mkfs.ext4.exe'
    }

    $results.Checks["Cygwin Packages"] = @{
        Success = $true
        Missing = @()
    }

    foreach ($package in $requiredPackages.GetEnumerator()) {
        $execPath = Join-Path $Global:CHROMEOS_PATHS.CYGWIN "bin\$($package.Value)"
        if (-not (Test-Path $execPath)) {
            $results.Checks["Cygwin Packages"].Success = $false
            $results.Checks["Cygwin Packages"].Missing += $package.Key
            $results.IsValid = $false
        }
    }

    if (-not $results.Checks["Cygwin Packages"].Success) {
        Write-InstallLog "Missing Cygwin packages: $($results.Checks["Cygwin Packages"].Missing -join ', ')" -Level 'Error'
    }

    return $results
}

# Main installation logic would follow here
# ... [Rest of the installation code from our previous discussion] ...

# Script execution
try {
    Show-Banner

    # Check prerequisites
    $preCheck = Test-Prerequisites
    if (-not $preCheck.IsValid) {
        throw "Prerequisites not met. Please check the log for details."
    }

    Write-InstallLog "All prerequisites met, proceeding with installation..." -Level 'Info'

    # Main installation steps would go here
    # ... [Installation steps from previous discussion] ...

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
