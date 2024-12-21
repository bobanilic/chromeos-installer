# verify-setup.ps1
$requirements = @{
    CygwinPath = "C:\cygwin64"
    RequiredTools = @(
        "bin\bash.exe",
        "bin\dd.exe",
        "bin\pv.exe",
        "bin\tar.exe",
        "bin\unzip.exe"
    )
}

Write-Host "Checking installation requirements..." -ForegroundColor Cyan

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "Running as Administrator: $($isAdmin ? 'Yes ✓' : 'No ✗')" -ForegroundColor ($isAdmin ? 'Green' : 'Red')

# Check Cygwin installation
$cygwinExists = Test-Path $requirements.CygwinPath
Write-Host "Cygwin installation found: $($cygwinExists ? 'Yes ✓' : 'No ✗')" -ForegroundColor ($cygwinExists ? 'Green' : 'Red')

# Check required tools
$missingTools = @()
foreach ($tool in $requirements.RequiredTools) {
    $toolPath = Join-Path $requirements.CygwinPath $tool
    if (-not (Test-Path $toolPath)) {
        $missingTools += $tool
    }
}

Write-Host "Required tools check:" -ForegroundColor Cyan
if ($missingTools.Count -eq 0) {
    Write-Host "All required tools found ✓" -ForegroundColor Green
} else {
    Write-Host "Missing tools:" -ForegroundColor Red
    $missingTools | ForEach-Object { Write-Host "- $_" -ForegroundColor Red }
}

# Check available space
$systemDrive = Get-PSDrive -Name C
$freeSpaceGB = [math]::Round($systemDrive.Free / 1GB, 2)
Write-Host "Free space on system drive: $freeSpaceGB GB $($freeSpaceGB -ge 20 ? '✓' : '✗')" -ForegroundColor ($freeSpaceGB -ge 20 ? 'Green' : 'Red')

# Final verdict
$readyToInstall = $isAdmin -and $cygwinExists -and ($missingTools.Count -eq 0) -and ($freeSpaceGB -ge 20)
Write-Host "`nSystem $(if ($readyToInstall) {'is'} else {'is not'}) ready for ChromeOS installation" -ForegroundColor ($readyToInstall ? 'Green' : 'Red')
