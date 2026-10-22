# GitHub Actions Self-Hosted Runner Setup Script for Windows - StorXMonitor
# Fully automated setup for cyberls-production (StorXMonitor / Satellite)
# Path: D:\deployment\storx-monitor\actions-runner
#
# One runner deploys both satellites on the CyberLS server (Google and Microsoft);
# the workflows pick the target with their `target` input.
#
# Reference layout on same CyberLS production server:
#   D:\deployment\storx-monitor\actions-runner
#   actions.runner.StorXNetwork-StorXMonitor.cyberls-production
#
#   D:\deployment\storx-admin-console\actions-runner
#   actions.runner.StorXNetwork-storx-admin-web.cyberls-production
#
#   D:\deployment\storx-developer-console\actions-runner
#   actions.runner.StorXNetwork-storx-developer-web.cyberls-production
#
# If you get an execution policy error, run one of these commands first:
#   Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
#   OR
#   powershell -ExecutionPolicy Bypass -File D:\deployment\setup-github-runner-cyberls-storxmonitor.ps1
#   OR
#   Unblock-File -Path D:\deployment\setup-github-runner-cyberls-storxmonitor.ps1
#
# Example (fresh registration token from GitHub -> Settings -> Actions -> Runners -> New):
#   powershell -ExecutionPolicy Bypass -File .\setup-github-runner-cyberls-storxmonitor.ps1 -Token "YOUR_TOKEN" -InstallService
#
# Or use a GitHub PAT (ghp_...) with repo scope; the script will exchange it for a registration token.
# Never put a token into this file; always pass it with -Token.
#
# Give an existing runner access to the Microsoft deployment (after setup-cyberls-microsoft-service.ps1 created it):
#   powershell -ExecutionPolicy Bypass -File .\setup-github-runner-cyberls-storxmonitor.ps1 -GrantMicrosoftAccess
#
# Workflows that use this runner (labels must match; GitHub compares labels case-insensitively):
#   .github/workflows/satellite-cyberls.yml
#     runs-on: [self-hosted, windows, production, cyberls]
#   .github/workflows/storj-sim-cyberls.yml
#     runs-on: [self-hosted, windows, CyberLS]
#
# Deploy targets used by both workflows:
#   google:    service Cyberls-Satellite,           BIN_PATH D:\bin,                     TEMP_PATH D:\deployment
#   microsoft: service Cyberls-Microsoft-Satellite, BIN_PATH D:\cyberls-microsoft\bin,  TEMP_PATH D:\cyberls-microsoft\deployment

param(
    [Parameter(Mandatory = $false)]
    [string]$RunnerPath = "D:\deployment\storx-monitor\actions-runner",

    [Parameter(Mandatory = $false)]
    [string]$GitHubUrl = "https://github.com/StorXNetwork/StorXMonitor",

    # GitHub PAT (ghp_...) OR short-lived runner registration token from GitHub UI.
    # From: StorXNetwork/StorXMonitor -> Settings -> Actions -> Runners -> New self-hosted runner
    # NOTE: registration tokens expire ~1 hour. Generate a fresh one if configure fails.
    [Parameter(Mandatory = $false)]
    [string]$Token = "",

    [Parameter(Mandatory = $false)]
    [string]$RunnerName = "cyberls-production",

    # Keep labels compatible with satellite-cyberls.yml and storj-sim-cyberls.yml
    [Parameter(Mandatory = $false)]
    [string]$Labels = "self-hosted,windows,x64,production,cyberls",

    [Parameter(Mandatory = $false)]
    [string]$ServiceName = "actions.runner.StorXNetwork-StorXMonitor.cyberls-production",

    [Parameter(Mandatory = $false)]
    [string]$RunnerVersion = "2.337.0",

    # SHA256 for actions-runner-win-x64-2.337.0.zip
    [Parameter(Mandatory = $false)]
    [string]$ExpectedHash = "1150692afa94e71f872017e254ea55b6eece1eece3fe7e3a6d4c93d0a1b85cfc",

    [Parameter(Mandatory = $false)]
    [switch]$InstallService,

    [Parameter(Mandatory = $false)]
    [switch]$SkipDownload,

    # Only grant the runner access to the Microsoft deployment; skips download/configure/service install.
    [Parameter(Mandatory = $false)]
    [switch]$GrantMicrosoftAccess,

    [Parameter(Mandatory = $false)]
    [string]$GoogleServiceName = "Cyberls-Satellite",

    [Parameter(Mandatory = $false)]
    [string]$MicrosoftServiceName = "Cyberls-Microsoft-Satellite",

    [Parameter(Mandatory = $false)]
    [string]$MicrosoftRoot = "D:\cyberls-microsoft"
)

$ErrorActionPreference = "Stop"

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-Fail {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Test-IsAdmin {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

Write-Host ""
Write-Host "===============================================================" -ForegroundColor Green
Write-Host "  GitHub Actions Self-Hosted Runner Setup - StorXMonitor" -ForegroundColor Green
Write-Host "  cyberls-production (Google + Microsoft satellites) - Automated" -ForegroundColor Green
Write-Host "===============================================================" -ForegroundColor Green
Write-Host ""

Write-Info "Configuration:"
Write-Info "  Runner Path: $RunnerPath"
Write-Info "  GitHub URL: $GitHubUrl"
Write-Info "  Runner Name: $RunnerName"
Write-Info "  Labels: $Labels"
Write-Info "  Service Name: $ServiceName"
Write-Info "  Runner Version: $RunnerVersion"
Write-Info "  Install Service: $InstallService"
Write-Info "  Grant Microsoft Access: $GrantMicrosoftAccess"
Write-Host ""

function Test-IsGitHubPAT {
    param([string]$Value)

    return $Value -match '^(ghp_|github_pat_|gho_|ghu_|ghs_|ghr_)'
}

function Get-RegistrationTokenFromPAT {
    param(
        [string]$Pat,
        [string]$GitHubUrl
    )

    $repoSlug = ($GitHubUrl -replace '^https://github\.com/', '').TrimEnd('/')
    $uri = "https://api.github.com/repos/$repoSlug/actions/runners/registration-token"

    Write-Info "Token looks like a GitHub PAT; requesting runner registration token from API..."

    $headers = @{
        Authorization          = "Bearer $Pat"
        Accept                 = 'application/vnd.github+json'
        'X-GitHub-Api-Version' = '2022-11-28'
    }

    try {
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers
    }
    catch {
        Write-Fail "Failed to get registration token using PAT."
        Write-Fail "Ensure the PAT has 'repo' scope and access to $GitHubUrl"
        throw
    }

    if ([string]::IsNullOrWhiteSpace($response.token)) {
        throw "GitHub API returned an empty registration token."
    }

    Write-Success "Registration token obtained (expires at $($response.expires_at))"
    return $response.token
}

function Resolve-RunnerRegistrationToken {
    param(
        [string]$Token,
        [string]$GitHubUrl
    )

    if ([string]::IsNullOrWhiteSpace($Token)) {
        throw "Token is required. Pass a GitHub PAT (ghp_...) or a runner registration token with -Token"
    }

    if (Test-IsGitHubPAT -Value $Token) {
        return Get-RegistrationTokenFromPAT -Pat $Token -GitHubUrl $GitHubUrl
    }

    Write-Info "Using provided runner registration token"
    return $Token
}

function Get-RunnerDownloadUrl {
    param(
        [string]$Version,
        [string]$Architecture = "x64"
    )

    $fileName = "actions-runner-win-$Architecture-$Version.zip"
    $downloadUrl = "https://github.com/actions/runner/releases/download/v$Version/$fileName"

    return @{
        Url      = $downloadUrl
        FileName = $fileName
    }
}

function Download-Runner {
    param(
        [string]$DownloadUrl,
        [string]$DestinationPath,
        [string]$FileName,
        [string]$ExpectedHash
    )

    $zipPath = Join-Path $DestinationPath $FileName

    Write-Info "Downloading runner from: $DownloadUrl"
    Write-Info "Saving to: $zipPath"

    try {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $zipPath -UseBasicParsing -ErrorAction Stop

        Write-Success "Download completed: $zipPath"

        $fileSize = (Get-Item $zipPath).Length / 1MB
        Write-Info "File size: $([math]::Round($fileSize, 2)) MB"

        if (-not [string]::IsNullOrWhiteSpace($ExpectedHash)) {
            Write-Info "Validating file hash (SHA256)..."
            $actualHash = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToUpper()
            $expectedHashUpper = $ExpectedHash.ToUpper()

            if ($actualHash -ne $expectedHashUpper) {
                Write-Fail "Hash validation failed!"
                Write-Fail "  Expected: $expectedHashUpper"
                Write-Fail "  Actual:   $actualHash"
                throw "Computed checksum did not match"
            }

            Write-Success "Hash validation passed"
        }

        return $zipPath
    }
    catch {
        Write-Fail "Failed to download runner: $_"
        throw
    }
}

function Expand-Runner {
    param(
        [string]$ZipPath,
        [string]$DestinationPath
    )

    Write-Info "Extracting runner to: $DestinationPath"

    try {
        if (-not (Test-Path $DestinationPath)) {
            New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
        }

        Write-Info "Extracting files..."
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($ZipPath, $DestinationPath)

        Write-Success "Runner extracted successfully"

        Write-Info "Removing zip file..."
        Remove-Item -Path $ZipPath -Force -ErrorAction SilentlyContinue

        Write-Success "Extraction complete"
    }
    catch {
        Write-Fail "Failed to extract runner: $_"
        throw
    }
}

function Configure-Runner {
    param(
        [string]$RunnerPath,
        [string]$GitHubUrl,
        [string]$Token,
        [string]$RunnerName,
        [string]$Labels,
        [bool]$RunAsService = $false
    )

    Write-Info "Configuring runner..."

    Push-Location $RunnerPath

    try {
        $configArgs = @(
            "--url", $GitHubUrl,
            "--token", $Token,
            "--name", $RunnerName,
            "--work", "_work",
            "--labels", $Labels,
            "--unattended",
            "--replace"
        )

        if ($RunAsService) {
            $configArgs += "--runasservice"
        }

        $configFlags = ($configArgs | Where-Object { $_ -ne $Token }) -join ' '
        Write-Info "Running configuration command..."
        Write-Info "  .\config.cmd $configFlags"

        $configCmd = Join-Path $RunnerPath "config.cmd"
        if (-not (Test-Path -LiteralPath $configCmd)) {
            throw "config.cmd not found in $RunnerPath"
        }

        # Use cmd.exe so .cmd batch files run reliably (Start-Process on .cmd often fails).
        $quotedArgs = ($configArgs | ForEach-Object {
            if ($_ -match '\s') { "`"$_`"" } else { $_ }
        }) -join ' '
        $process = Start-Process -FilePath "cmd.exe" `
            -ArgumentList "/c", "`"$configCmd`" $quotedArgs" `
            -WorkingDirectory $RunnerPath `
            -Wait -NoNewWindow -PassThru

        if ($process.ExitCode -ne 0) {
            throw "Configuration failed with exit code: $($process.ExitCode)"
        }

        Write-Success "Runner configured successfully"
        Write-Info "  Repository: $GitHubUrl"
        Write-Info "  Runner Name: $RunnerName"
        Write-Info "  Labels: $Labels"
        if ($RunAsService) {
            Write-Info "  Mode: Windows service (--runasservice)"
        }
    }
    catch {
        Write-Fail "Failed to configure runner: $_"
        throw
    }
    finally {
        Pop-Location
    }
}

function Get-GitHubRunnerService {
    param(
        [string]$RunnerName
    )

    $services = Get-Service -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -like 'actions.runner.*' -or $_.DisplayName -like 'GitHub Actions Runner (*)'
    }

    if ($RunnerName) {
        $matched = @($services | Where-Object {
            $_.Name -like "*$RunnerName*" -or $_.DisplayName -like "*$RunnerName*"
        })
        # Prefer StorXMonitor when multiple runners share the same RunnerName on this machine
        $storxMonitor = @($matched | Where-Object {
            $_.Name -like '*StorXMonitor*' -or $_.DisplayName -like '*StorXMonitor*' -or
            $_.Name -like '*storx-monitor*' -or $_.DisplayName -like '*storx-monitor*'
        })
        if ($storxMonitor.Count -gt 0) {
            return $storxMonitor[0]
        }
        if ($matched.Count -gt 0) {
            return $matched[0]
        }
    }

    # Prefer StorXMonitor service if multiple runners exist on this machine
    $storxMonitor = @($services | Where-Object {
        $_.Name -like '*StorXMonitor*' -or $_.DisplayName -like '*StorXMonitor*' -or
        $_.Name -like '*storx-monitor*' -or $_.DisplayName -like '*storx-monitor*'
    })
    if ($storxMonitor.Count -gt 0) {
        return $storxMonitor[0]
    }

    if ($services) {
        return @($services)[0]
    }

    return $null
}

function Invoke-RunnerBatch {
    param(
        [string]$BatchPath,
        [string]$Arguments,
        [string]$WorkingDirectory
    )

    if (-not (Test-Path -LiteralPath $BatchPath)) {
        throw "Batch file not found: $BatchPath"
    }

    $process = Start-Process -FilePath "cmd.exe" `
        -ArgumentList "/c", "`"$BatchPath`" $Arguments" `
        -WorkingDirectory $WorkingDirectory `
        -Wait -NoNewWindow -PassThru

    return $process.ExitCode
}

function Install-RunnerService {
    param(
        [string]$RunnerPath,
        [string]$RunnerName,
        [string]$ServiceName
    )

    Write-Info "Installing runner as Windows service: $ServiceName"

    if (-not (Test-IsAdmin)) {
        Write-Warn "Administrator privileges required for service installation"
        Write-Info "Please run PowerShell as Administrator and try again"
        Write-Info "Or run manually: cd $RunnerPath; .\svc.cmd install; .\svc.cmd start"
        return $false
    }

    Push-Location $RunnerPath

    try {
        $existingService = Get-GitHubRunnerService -RunnerName $RunnerName
        if ($existingService) {
            Write-Success "Runner service already registered: $($existingService.Name)"
            if ($existingService.Status -ne 'Running') {
                Write-Info "Starting service $($existingService.Name)..."
                Start-Service -Name $existingService.Name
            }
            Write-Success "Service is running: $($existingService.Name)"
            return $true
        }

        $svcCmd = Join-Path $RunnerPath "svc.cmd"
        if (-not (Test-Path -LiteralPath $svcCmd)) {
            Write-Fail "svc.cmd not found in $RunnerPath"
            Write-Info "Re-run with -InstallService so config.cmd uses --runasservice"
            Write-Info "Or manually:"
            Write-Info "  cd $RunnerPath"
            Write-Info "  .\config.cmd --url $GitHubUrl --token <NEW_TOKEN> --name $RunnerName --work _work --labels `"$Labels`" --unattended --replace --runasservice"
            return $false
        }

        Write-Info "Installing service via svc.cmd..."
        $installExit = Invoke-RunnerBatch -BatchPath $svcCmd -Arguments "install" -WorkingDirectory $RunnerPath
        if ($installExit -ne 0) {
            Write-Fail "Service installation failed with exit code: $installExit"
            return $false
        }

        Write-Success "Service installed successfully"

        Write-Info "Starting service..."
        $startExit = Invoke-RunnerBatch -BatchPath $svcCmd -Arguments "start" -WorkingDirectory $RunnerPath
        if ($startExit -ne 0) {
            $existingService = Get-GitHubRunnerService -RunnerName $RunnerName
            if ($existingService -and $existingService.Status -eq 'Running') {
                Write-Success "Service is running: $($existingService.Name)"
                return $true
            }
            Write-Fail "Service start failed with exit code: $startExit"
            return $false
        }

        $existingService = Get-GitHubRunnerService -RunnerName $RunnerName
        if ($existingService) {
            Write-Success "Service started: $($existingService.Name)"
        }
        else {
            Write-Success "Service started successfully"
        }

        Write-Host ""
        Write-Info "Service management commands:"
        Write-Info "  Start service:   cd $RunnerPath; .\svc.cmd start"
        Write-Info "  Stop service:    cd $RunnerPath; .\svc.cmd stop"
        Write-Info "  Remove service:  cd $RunnerPath; .\svc.cmd uninstall"
        return $true
    }
    catch {
        Write-Fail "Failed to install service: $_"
        return $false
    }
    finally {
        Pop-Location
    }
}

# The runner service account must be able to replace files in the Microsoft folders and stop/start the
# Microsoft nssm service, exactly like it already can for Google (D:\bin, Cyberls-Satellite).
function Grant-MicrosoftDeployAccess {
    param(
        [string]$RunnerName,
        [string]$GoogleServiceName,
        [string]$MicrosoftServiceName,
        [string]$MicrosoftRoot
    )

    if (-not (Test-IsAdmin)) {
        throw "Administrator privileges are required to grant access"
    }

    $runnerService = Get-GitHubRunnerService -RunnerName $RunnerName
    if (-not $runnerService) {
        throw "No GitHub runner service found for $RunnerName"
    }

    $account = (Get-CimInstance Win32_Service -Filter "Name='$($runnerService.Name)'").StartName
    Write-Info "Runner service $($runnerService.Name) runs as: $account"

    if ($account -in @("LocalSystem", "NT AUTHORITY\SYSTEM")) {
        Write-Success "Runner runs as LocalSystem; it already has access to the Microsoft deployment"
        return
    }

    if (-not (Test-Path $MicrosoftRoot)) {
        throw "$MicrosoftRoot does not exist; run setup-cyberls-microsoft-service.ps1 first"
    }
    Write-Info "Granting $account modify access on $MicrosoftRoot"
    & icacls $MicrosoftRoot /grant "${account}:(OI)(CI)M" /T /C /Q
    if ($LASTEXITCODE -ne 0) {
        throw "icacls failed with exit code $LASTEXITCODE"
    }
    Write-Success "Folder access granted"

    if (-not (Get-Service -Name $MicrosoftServiceName -ErrorAction SilentlyContinue)) {
        throw "Service $MicrosoftServiceName does not exist; run setup-cyberls-microsoft-service.ps1 first"
    }
    if (-not (Get-Service -Name $GoogleServiceName -ErrorAction SilentlyContinue)) {
        throw "Service $GoogleServiceName not found; cannot copy its permissions"
    }

    $sddl = (& sc.exe sdshow $GoogleServiceName | Where-Object { $_.Trim() }) -join ''
    if ($LASTEXITCODE -ne 0 -or $sddl -notmatch '^D:') {
        throw "Could not read the permissions of $GoogleServiceName"
    }
    Write-Info "Copying service permissions from $GoogleServiceName to $MicrosoftServiceName"
    & sc.exe sdset $MicrosoftServiceName $sddl.Trim() | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe sdset failed with exit code $LASTEXITCODE"
    }
    Write-Success "Service permissions copied; the runner can now stop and start $MicrosoftServiceName"
}

try {
    if ($GrantMicrosoftAccess) {
        Write-Host "===============================================================" -ForegroundColor Cyan
        Write-Info "Granting runner access to the Microsoft deployment..."
        Write-Host "===============================================================" -ForegroundColor Cyan

        Grant-MicrosoftDeployAccess `
            -RunnerName $RunnerName `
            -GoogleServiceName $GoogleServiceName `
            -MicrosoftServiceName $MicrosoftServiceName `
            -MicrosoftRoot $MicrosoftRoot

        Write-Host ""
        Write-Success "Microsoft deployment access is ready. Run the CyberLS workflows with target=microsoft."
        exit 0
    }

    Write-Host "===============================================================" -ForegroundColor Cyan
    Write-Info "Step 1: Creating runner directory..."
    Write-Host "===============================================================" -ForegroundColor Cyan

    if (-not (Test-Path $RunnerPath)) {
        New-Item -ItemType Directory -Path $RunnerPath -Force | Out-Null
        Write-Success "Runner directory created: $RunnerPath"
    }
    else {
        Write-Warn "Runner directory already exists: $RunnerPath"
    }

    $zipPath = $null
    $configPath = Join-Path $RunnerPath "config.cmd"

    if (-not $SkipDownload -and -not (Test-Path $configPath)) {
        Write-Host "===============================================================" -ForegroundColor Cyan
        Write-Info "Step 2: Downloading runner..."
        Write-Host "===============================================================" -ForegroundColor Cyan

        $downloadInfo = Get-RunnerDownloadUrl -Version $RunnerVersion -Architecture "x64"

        $zipPath = Download-Runner `
            -DownloadUrl $downloadInfo.Url `
            -DestinationPath $RunnerPath `
            -FileName $downloadInfo.FileName `
            -ExpectedHash $ExpectedHash
    }
    else {
        if ($SkipDownload) {
            Write-Info "Step 2: Skipping download (using existing files)"
        }
        else {
            Write-Info "Step 2: Runner files already exist, skipping download"
        }
    }

    if (-not (Test-Path $configPath)) {
        Write-Host "===============================================================" -ForegroundColor Cyan
        Write-Info "Step 3: Extracting runner..."
        Write-Host "===============================================================" -ForegroundColor Cyan

        if ($null -eq $zipPath) {
            $zipFiles = Get-ChildItem -Path $RunnerPath -Filter "actions-runner-win-x64-*.zip" -ErrorAction SilentlyContinue
            if ($zipFiles.Count -gt 0) {
                $zipPath = $zipFiles[0].FullName
                Write-Info "Using existing zip file: $zipPath"
            }
            else {
                throw "No zip file found and download was skipped"
            }
        }

        Expand-Runner -ZipPath $zipPath -DestinationPath $RunnerPath
    }
    else {
        Write-Info "Step 3: Runner files already extracted, skipping"
    }

    Write-Host "===============================================================" -ForegroundColor Cyan
    Write-Info "Step 4: Configuring runner..."
    Write-Host "===============================================================" -ForegroundColor Cyan

    $registrationToken = Resolve-RunnerRegistrationToken -Token $Token -GitHubUrl $GitHubUrl

    Configure-Runner `
        -RunnerPath $RunnerPath `
        -GitHubUrl $GitHubUrl `
        -Token $registrationToken `
        -RunnerName $RunnerName `
        -Labels $Labels `
        -RunAsService:$InstallService

    if ($InstallService) {
        Write-Host "===============================================================" -ForegroundColor Cyan
        Write-Info "Step 5: Installing Windows service..."
        Write-Host "===============================================================" -ForegroundColor Cyan

        $serviceInstalled = Install-RunnerService -RunnerPath $RunnerPath -RunnerName $RunnerName -ServiceName $ServiceName
        if (-not $serviceInstalled) {
            Write-Warn "Service installation skipped or failed. You can install it manually later."
        }
    }
    else {
        Write-Info "Step 5: Service installation skipped"
        Write-Host "===============================================================" -ForegroundColor Cyan
        Write-Info "Step 6: Starting runner..."
        Write-Host "===============================================================" -ForegroundColor Cyan

        Push-Location $RunnerPath
        try {
            Write-Info "Running .\run.cmd (Ctrl+C to stop)"
            & (Join-Path $RunnerPath "run.cmd")
        }
        finally {
            Pop-Location
        }
    }

    Write-Host ""
    Write-Host "===============================================================" -ForegroundColor Green
    Write-Host "[SUCCESS] GitHub Actions Runner Setup Completed!" -ForegroundColor Green
    Write-Host "===============================================================" -ForegroundColor Green
    Write-Host ""
    Write-Info "Runner Details:"
    Write-Info "  Path: $RunnerPath"
    Write-Info "  Name: $RunnerName"
    Write-Info "  Repository: $GitHubUrl"
    Write-Info "  Labels: $Labels"
    Write-Host ""
    Write-Info "Verify runner: $GitHubUrl/settings/actions/runners"
    Write-Info "Workflow files (choose target google or microsoft when running):"
    Write-Info "  .github/workflows/satellite-cyberls.yml   runs-on: [self-hosted, windows, production, cyberls]"
    Write-Info "  .github/workflows/storj-sim-cyberls.yml   runs-on: [self-hosted, windows, CyberLS]"
    Write-Host ""
    Write-Info "Expected Windows service:"
    Write-Info "  Service:  $ServiceName"
    Write-Info "  Exe:      $RunnerPath\bin\RunnerService.exe"
    Write-Host ""
    Write-Info "Deploy targets:"
    Write-Info "  google:    $GoogleServiceName, D:\bin, D:\deployment"
    Write-Info "  microsoft: $MicrosoftServiceName, $MicrosoftRoot\bin, $MicrosoftRoot\deployment"
    Write-Info "For Microsoft, once its service exists, run this script again with -GrantMicrosoftAccess."
    Write-Host ""
    Write-Success "Setup complete! cyberls-production (StorXMonitor) runner is ready."
    Write-Host ""
}
catch {
    Write-Host ""
    Write-Fail "==============================================================="
    Write-Fail "Setup failed: $_"
    Write-Fail "==============================================================="
    Write-Host ""
    Write-Fail $_.Exception.Message
    if ($_.ScriptStackTrace) {
        Write-Fail $_.ScriptStackTrace
    }
    Write-Host ""
    exit 1
}
