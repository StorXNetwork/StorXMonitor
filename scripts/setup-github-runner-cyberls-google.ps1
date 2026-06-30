# GitHub Actions Runner - storx-google (CyberLs-web)
# Copy to D:\Runners\setup-github-runner-cyberls-google.ps1
#
# Run as Administrator:
#   powershell -ExecutionPolicy Bypass -File D:\Runners\setup-github-runner-cyberls-google.ps1

#Requires -Version 5.1
#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'

# --- from GitHub runner setup page ---
$RepoUrl             = 'https://github.com/StorXNetwork/storx-google'
$RegistrationToken   = 'AD74DNQ343D2YEB24XG3LH3KINVSK'
$RunnerName          = 'cyberls-web-prod'
$Labels              = 'windows,x64,production'
$RunnerVersion       = '2.335.1'
$RunnerPackageSHA256 = 'eb65c95277af42bcf3778a799c41359d224ba2a67b4de26b7cea1729b09c803d'

# Runner files (separate from this script)
$InstallPath = 'D:\Runners\CyberLs-web'
# ---

Write-Host ''
Write-Host ('Runner setup - {0}' -f $RunnerName) -ForegroundColor Green
Write-Host ('Folder: {0}' -f $InstallPath)
Write-Host ''

# Create folder
if (-not (Test-Path -LiteralPath $InstallPath)) {
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
}

Set-Location $InstallPath

$zipName = "actions-runner-win-x64-$RunnerVersion.zip"
$zipPath = Join-Path $InstallPath $zipName

# Download latest runner package
if (-not (Test-Path -LiteralPath '.\config.cmd')) {
    Write-Host 'Downloading runner package...' -ForegroundColor Cyan
    Invoke-WebRequest -Uri "https://github.com/actions/runner/releases/download/v$RunnerVersion/$zipName" -OutFile $zipPath -UseBasicParsing

    # Validate hash
    $hash = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToUpper()
    if ($hash -ne $RunnerPackageSHA256.ToUpper()) {
        throw 'Computed checksum did not match'
    }

    # Extract
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $InstallPath)
    Remove-Item -LiteralPath $zipPath -Force
}

# Configure (svc.cmd is created during config -- do not check for it before this)
Write-Host 'Configuring runner...' -ForegroundColor Cyan
& .\config.cmd --url $RepoUrl --token $RegistrationToken --name $RunnerName --labels $Labels --unattended --replace --runasservice

if ($LASTEXITCODE -ne 0) {
    throw 'config.cmd failed - get a fresh token from GitHub and update RegistrationToken in this script'
}

# Verify service (replaces interactive .\run.cmd for production)
$svc = Get-Service -Name 'actions.runner.*' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($svc) {
    if ($svc.Status -ne 'Running') {
        Start-Service -Name $svc.Name
    }
    Write-Host ('Service running: {0}' -f $svc.Name) -ForegroundColor Green
}
else {
    Write-Host 'Starting interactively (.\run.cmd)...' -ForegroundColor Yellow
    Write-Host 'Press Ctrl+C to stop' -ForegroundColor Yellow
    & .\run.cmd
}

Write-Host ''
Write-Host 'Done. Check GitHub -> storx-google -> Settings -> Actions -> Runners' -ForegroundColor Green
Write-Host 'Workflow: runs-on: [self-hosted, windows, x64, production]' -ForegroundColor Green
Write-Host ''
