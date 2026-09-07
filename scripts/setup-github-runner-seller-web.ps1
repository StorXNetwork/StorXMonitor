# GitHub Actions Self-Hosted Runner Setup Script for Windows - seller-web
# Fully automated setup for cyberls-seller-web
# Path: D:\deployment\cyberls-seller-web
#
# If you get an execution policy error, run one of these commands first:
#   Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
#   OR
#   powershell -ExecutionPolicy Bypass -File D:\deployment\setup-github-runner-seller-web.ps1
#   OR
#   Unblock-File -Path D:\deployment\setup-github-runner-seller-web.ps1
#
# Example (fresh registration token from GitHub -> Settings -> Actions -> Runners -> New):
#   powershell -ExecutionPolicy Bypass -File .\setup-github-runner-seller-web.ps1 -Token "YOUR_TOKEN" -InstallService
#
# Or use a GitHub PAT (ghp_...) with repo scope; the script will exchange it for a registration token.

param(
    [Parameter(Mandatory = $false)]
    [string]$RunnerPath = "D:\deployment\cyberls-seller-web",

    [Parameter(Mandatory = $false)]
    [string]$GitHubUrl = "https://github.com/DerDhaval/seller-web",

    # GitHub PAT with repo scope; exchanged for a runner registration token at runtime.
    [Parameter(Mandatory = $false)]
    [string]$Token = "",

    [Parameter(Mandatory = $false)]
    [string]$RunnerName = "cyberls-seller-web",

    [Parameter(Mandatory = $false)]
    [string]$Labels = "self-hosted,windows,x64,seller-web,cyberls-staging",

    [Parameter(Mandatory = $false)]
    [string]$ServiceName = "cyberls-seller-web",

    [Parameter(Mandatory = $false)]
    [string]$RunnerVersion = "2.335.1",

    [Parameter(Mandatory = $false)]
    [string]$ExpectedHash = "eb65c95277af42bcf3778a799c41359d224ba2a67b4de26b7cea1729b09c803d",

    [Parameter(Mandatory = $false)]
    [switch]$InstallService,

    [Parameter(Mandatory = $false)]
    [switch]$SkipDownload
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

Write-Host ""
Write-Host "===============================================================" -ForegroundColor Green
Write-Host "  GitHub Actions Self-Hosted Runner Setup - seller-web" -ForegroundColor Green
Write-Host "  cyberls-seller-web - Automated Installation" -ForegroundColor Green
Write-Host "===============================================================" -ForegroundColor Green
Write-Host ""

Write-Info "Configuration:"
Write-Info "  Runner Path: $RunnerPath"
Write-Info "  GitHub URL: $GitHubUrl"
Write-Info "  Runner Name: $RunnerName"
Write-Info "  Labels: $Labels"
Write-Info "  Runner Version: $RunnerVersion"
Write-Info "  Install Service: $InstallService"
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
        $_.Name -like 'actions.runner.*' -or $_.Name -like 'GitHub Actions Runner (*)'
    }

    if ($RunnerName) {
        $matched = @($services | Where-Object {
            $_.Name -like "*$RunnerName*" -or $_.DisplayName -like "*$RunnerName*"
        })
        if ($matched.Count -gt 0) {
            return $matched[0]
        }
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

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
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

try {
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
    Write-Info "Workflow YAML:  runs-on: [self-hosted, windows, cyberls-staging]"
    Write-Host ""
    Write-Info "NSSM service (optional, run as Admin from D:\bin if you use nssm):"
    Write-Info "  .\nssm.exe install cyberls-seller-web `"C:\Windows\System32\cmd.exe`""
    Write-Info "  .\nssm.exe set cyberls-seller-web AppParameters `"/c D:\deployment\cyberls-seller-web\run.cmd`""
    Write-Info "  .\nssm.exe set cyberls-seller-web AppDirectory `"D:\deployment\cyberls-seller-web`""
    Write-Info "  .\nssm.exe set cyberls-seller-web Start SERVICE_AUTO_START"
    Write-Info "  .\nssm.exe start cyberls-seller-web"
    Write-Host ""
    Write-Success "Setup complete! cyberls-seller-web runner is ready."
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
