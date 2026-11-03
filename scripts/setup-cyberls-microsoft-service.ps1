# Creates the Microsoft satellite network service on the CyberLS server, next to the existing Google one.
#
# Run in PowerShell as Administrator:
#   powershell -ExecutionPolicy Bypass -File .\setup-cyberls-microsoft-service.ps1 -PreflightOnly
#   powershell -ExecutionPolicy Bypass -File .\setup-cyberls-microsoft-service.ps1 -RunSetup
#
# Postgres URL: set $env:CYBERLS_MS_POSTGRES (never commit it). It is stored in the service as
# STORJ_SIM_POSTGRES, not in nssm AppParameters, so special characters in the password are safe.
#
# satellite.exe and storxnetwork-sim.exe are NOT copied from Google by default. Deploy them with the
# CyberLS workflows (target=microsoft) so satellite is built with WEB3_AUTH_PRIVATE_KEY from cyberls-microsoft.
# Use -BootstrapFromGoogleBin only for a throwaway local test; replace those binaries before production.
#
# Config:  D:\cyberls-microsoft\ms-cyberls-configs
# Build temp (workflows): D:\cyberls-microsoft\deployment

param(
    [string]$Root = "D:\cyberls-microsoft",
    [string]$ConfigDir = "D:\cyberls-microsoft\ms-cyberls-configs",
    [string]$ServiceName = "Cyberls-Microsoft-Satellite",
    [string]$GoogleServiceName = "Cyberls-Satellite",
    [string]$SourceBin = "D:\bin",
    [int]$PortOffset = 8000,
    [string]$GatewayCredentialsUrl = "https://auth-outh365.cyberls.com",
    [string]$LinkSharingUrl = "https://ls-outh365.cyberls.com",
    [string]$ExtraArgs = "",
    [switch]$RunSetup,
    [switch]$Start,
    [switch]$PreflightOnly,
    [switch]$BootstrapFromGoogleBin,
    [switch]$SkipDbConnectivityCheck
)

$ErrorActionPreference = "Stop"

function Fail([string]$message) {
    Write-Host "ERROR: $message" -ForegroundColor Red
    exit 1
}

function Read-PostgresUrlSecure {
    $secure = Read-Host "Microsoft Postgres URL (postgres://user:password@host:5432/dbname?sslmode=disable)" -AsSecureString
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    }
    finally {
        if ($ptr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
        }
    }
}

function Get-PostgresEndpoint {
    param([string]$Url)
    if ($Url -notmatch '^postgres(ql)?://') { return $null }
    $parsed = $null
    try {
        $parsed = [Uri]$Url
    }
    catch {
        return $null
    }
    $dbName = ($parsed.AbsolutePath -replace '^/', '').Split('?')[0]
    if (-not $dbName) { return $null }
    $port = if ($parsed.Port -gt 0) { $parsed.Port } else { 5432 }
    return @{
        Host     = $parsed.Host
        Port     = $port
        Database = $dbName
        Key      = "$($parsed.Host):$port/$dbName"
    }
}

function Get-GooglePostgresFromNssm {
    param(
        [string]$NssmExe,
        [string]$GoogleService
    )
    if (-not (Test-Path $NssmExe)) { return $null }
    if (-not (Get-Service -Name $GoogleService -ErrorAction SilentlyContinue)) { return $null }
    $raw = ((& $NssmExe get $GoogleService AppParameters | Out-String) -replace "`0", "").Trim()
    if ($raw -match '--postgres\s+(\S+)') {
        return $Matches[1]
    }
    $envBlock = ((& $NssmExe get $GoogleService AppEnvironmentExtra | Out-String) -replace "`0", "")
    foreach ($line in ($envBlock -split "`n")) {
        if ($line -match '^STORJ_SIM_POSTGRES=(.+)$') { return $Matches[1].Trim() }
    }
    return $null
}

function Assert-NotGoogleDatabase {
    param(
        [string]$MicrosoftUrl,
        [string]$GoogleUrl
    )
    if (-not $GoogleUrl) { return }
    $ms = Get-PostgresEndpoint $MicrosoftUrl
    $goog = Get-PostgresEndpoint $GoogleUrl
    if (-not $ms -or -not $goog) { return }
    if ($ms.Key -eq $goog.Key) {
        Fail "Microsoft Postgres endpoint matches Google ($($ms.Key)). Create a separate database on a separate DB name (and host if needed)."
    }
}

function Test-PostgresReachable {
    param([string]$Url)
    $ep = Get-PostgresEndpoint $Url
    if (-not $ep) { Fail "could not parse Postgres URL" }
    $psql = Get-Command psql -ErrorAction SilentlyContinue
    if (-not $psql) {
        Write-Host "WARN: psql not in PATH; skipping database connectivity check" -ForegroundColor Yellow
        return
    }
    $env:PGPASSWORD = $null
    & $psql.Source $Url -c "SELECT 1" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Fail "cannot connect to Microsoft database $($ep.Key). Create the database first, then re-run."
    }
    Write-Host "database connectivity OK ($($ep.Key))"
}

function Get-RequiredListenPorts {
    param([int]$Offset)
    # storxnetwork-sim port formula: 10000 + offset + peer*1000 + index*10 + endpoint (satellite 0, key endpoints).
    $base = [int](10000 + $Offset)
    # Parentheses on each port: commas inside @() are the array separator, not arithmetic.
    $ports = @(
        ($base)
        ($base + 1)
        ($base + 2)
        ($base + 3)
        ($base + 4)
        ($base + 8)
        ($base + 2000)
        ($base + 3000)
    )
    return $ports | Sort-Object -Unique
}

function Test-PortsAvailable {
    param([int[]]$Ports)
    $busy = @()
    foreach ($p in $Ports) {
        $hit = Get-NetTCPConnection -State Listen -LocalPort $p -ErrorAction SilentlyContinue
        if ($hit) { $busy += $p }
    }
    if ($busy.Count -gt 0) {
        Write-Host "ports already listening: $($busy -join ', ')" -ForegroundColor Red
        Fail "required Microsoft ports are in use"
    }
}

function Invoke-NssmExe {
    param(
        [string]$NssmPath,
        [string[]]$NssmArgs
    )
    & $NssmPath @NssmArgs
    if ($LASTEXITCODE -ne 0) {
        Fail "nssm $($NssmArgs -join ' ') failed with exit code $LASTEXITCODE"
    }
}

function Remove-ServiceIfCreated {
    param(
        [string]$NssmPath,
        [string]$Name,
        [bool]$Created
    )
    if (-not $Created) { return }
    $ErrorActionPreference = "Continue"
    & $NssmPath stop $Name 2>&1 | Out-Null
    & $NssmPath remove $Name confirm 2>&1 | Out-Null
    $ErrorActionPreference = "Stop"
    Write-Host "rolled back nssm service $Name" -ForegroundColor Yellow
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Fail "run this script as Administrator" }
if ($PortOffset -le 0) { Fail "port offset must be above 0" }

$bin = Join-Path $Root "bin"
$logs = Join-Path $Root "logs"
$sourceNssm = Join-Path $SourceBin "nssm.exe"

if (-not (Test-Path $sourceNssm)) { Fail "Google nssm not found at $sourceNssm; cannot bootstrap Microsoft service" }

$db = $env:CYBERLS_MS_POSTGRES
if (-not $db) {
    if ($PreflightOnly) { Fail "set CYBERLS_MS_POSTGRES for preflight, or run without -PreflightOnly" }
    $db = Read-PostgresUrlSecure
}
if ($db -match '\s') { Fail "Postgres URL must not contain spaces; use URL-encoding in the password if needed" }
$msEp = Get-PostgresEndpoint $db
if (-not $msEp) { Fail "Postgres URL must look like postgres://user:pass@host:5432/dbname?sslmode=disable" }

$googleDb = Get-GooglePostgresFromNssm -NssmExe $sourceNssm -GoogleService $GoogleServiceName
Assert-NotGoogleDatabase -MicrosoftUrl $db -GoogleUrl $googleDb

$requiredPorts = Get-RequiredListenPorts -Offset $PortOffset
Test-PortsAvailable -Ports $requiredPorts

if (-not $SkipDbConnectivityCheck) {
    Test-PostgresReachable -Url $db
}

Write-Host "preflight: service=$ServiceName config=$ConfigDir ports=$($requiredPorts -join ', ')" -ForegroundColor Cyan
if ($PreflightOnly) {
    Write-Host "preflight passed" -ForegroundColor Green
    exit 0
}

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Fail "service $ServiceName already exists; nssm remove $ServiceName confirm first to recreate"
}
if ($RunSetup -and (Test-Path (Join-Path $ConfigDir "satellite"))) {
    Fail "$ConfigDir already has a network config; remove it manually or use a different -ConfigDir"
}

if ($Start -and -not $RunSetup -and -not (Test-Path (Join-Path $ConfigDir "satellite\0\config.yaml"))) {
    Fail "-Start requires an existing config at $ConfigDir\satellite\0\config.yaml (run with -RunSetup first)"
}

foreach ($dir in $bin, (Join-Path $Root "deployment"), (Join-Path $Root "Mails"), $ConfigDir, $logs) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}

# nssm first so later steps can call it.
$nssm = Join-Path $bin "nssm.exe"
if (-not (Test-Path $nssm)) {
    Copy-Item $sourceNssm $nssm
    Write-Host "copied $sourceNssm -> $nssm"
}
if (-not (Test-Path $nssm)) { Fail "nssm.exe missing at $nssm" }

$alwaysCopy = "storagenode.exe", "versioncontrol.exe", "multinode.exe", "identity.exe", "redis-server.exe"
$workflowBinaries = "satellite.exe", "storxnetwork-sim.exe"

foreach ($program in $alwaysCopy) {
    $target = Join-Path $bin $program
    if (Test-Path $target) { Write-Host "keep   $target"; continue }
    $source = Join-Path $SourceBin $program
    if (-not (Test-Path $source)) {
        $found = Get-Command $program -ErrorAction SilentlyContinue
        if (-not $found) { Fail "$program not found in $SourceBin or PATH" }
        $source = $found.Source
    }
    Copy-Item $source $target
    Write-Host "copied $source -> $target"
}

foreach ($program in $workflowBinaries) {
    $target = Join-Path $bin $program
    if (Test-Path $target) {
        Write-Host "keep   $target"
        continue
    }
    if (-not $BootstrapFromGoogleBin) {
        Fail "$target is missing. Run satellite-cyberls.yml and storj-sim-cyberls.yml with target=microsoft first, or pass -BootstrapFromGoogleBin for temporary testing only (satellite will use Google's Web3 build key)."
    }
    $source = Join-Path $SourceBin $program
    if (-not (Test-Path $source)) { Fail "$program not found in $SourceBin" }
    Copy-Item $source $target
    Write-Host "WARN: copied $source -> $target (replace via GitHub workflow before production)" -ForegroundColor Yellow
}

$path = "$bin;C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem"
$runArgs = "--port-offset $PortOffset --no-gateways --config-dir `"$ConfigDir`" $ExtraArgs".Trim()
$extra = @(-split $ExtraArgs | Where-Object { $_ })

if ($RunSetup) {
    Write-Host "running network setup in $ConfigDir"
    $previousPath = $env:PATH
    $previousPg = $env:STORJ_SIM_POSTGRES
    $env:PATH = $path
    $env:STORJ_SIM_POSTGRES = $db
    try {
        $setupArgs = @(
            "network", "setup",
            "--port-offset", $PortOffset,
            "--no-gateways",
            "--config-dir", $ConfigDir,
            "--postgres", $db,
            "-g", $GatewayCredentialsUrl,
            "-s", $LinkSharingUrl
        ) + $extra
        & (Join-Path $bin "storxnetwork-sim.exe") @setupArgs
        if ($LASTEXITCODE -ne 0) { Fail "network setup failed with exit code $LASTEXITCODE" }
    }
    finally {
        $env:PATH = $previousPath
        if ($null -eq $previousPg) { Remove-Item Env:\STORJ_SIM_POSTGRES -ErrorAction SilentlyContinue }
        else { $env:STORJ_SIM_POSTGRES = $previousPg }
    }
}

$serviceCreated = $false
$simExe = Join-Path $bin "storxnetwork-sim.exe"
try {
    Write-Host "creating service $ServiceName"
    Invoke-NssmExe $nssm @("install", $ServiceName, $simExe)
    $serviceCreated = $true

    Invoke-NssmExe $nssm @("set", $ServiceName, "AppParameters", "network run $runArgs")
    Invoke-NssmExe $nssm @("set", $ServiceName, "AppDirectory", $bin)
    # Postgres in the environment, not in AppParameters (password-safe; storxnetwork-sim reads STORJ_SIM_POSTGRES).
    Invoke-NssmExe $nssm @("set", $ServiceName, "AppEnvironmentExtra", "PATH=$path`nSTORJ_SIM_POSTGRES=$db")
    Invoke-NssmExe $nssm @("set", $ServiceName, "DisplayName", "Cyberls Microsoft Satellite")
    Invoke-NssmExe $nssm @("set", $ServiceName, "AppStdout", (Join-Path $logs "satellite.log"))
    Invoke-NssmExe $nssm @("set", $ServiceName, "AppStderr", (Join-Path $logs "satellite.log"))
    Invoke-NssmExe $nssm @("set", $ServiceName, "AppRotateFiles", "1")
    Invoke-NssmExe $nssm @("set", $ServiceName, "AppRotateOnline", "1")
    Invoke-NssmExe $nssm @("set", $ServiceName, "AppRotateBytes", "104857600")
    Invoke-NssmExe $nssm @("set", $ServiceName, "Start", "SERVICE_DEMAND_START")
}
catch {
    Remove-ServiceIfCreated -NssmPath $nssm -Name $ServiceName -Created $serviceCreated
    throw
}

Write-Host ""
Write-Host "Service $ServiceName created (manual start)." -ForegroundColor Green
Write-Host "  bin:       $bin"
Write-Host "  config:    $ConfigDir"
Write-Host "  logs:      $logs\satellite.log"
$rpcPortHint = 10000 + $PortOffset
Write-Host "  key ports: RPC $rpcPortHint, console $($rpcPortHint + 2), developer $($rpcPortHint + 8)"
Write-Host "  database:  $($msEp.Key) (via STORJ_SIM_POSTGRES on the service, not shown)"

if (-not $Start) {
    Write-Host ""
    Write-Host "Next:"
    Write-Host "  1. Deploy satellite.exe + storxnetwork-sim.exe from GitHub (target=microsoft) if you have not already."
    Write-Host "  2. Edit $ConfigDir\satellite\0\config.yaml (domains, mail.template-path, auth secret, SSO, seller)."
    Write-Host "  3. setup-github-runner-cyberls-storxmonitor.ps1 -GrantMicrosoftAccess"
    Write-Host "  4. $nssm start $ServiceName"
    exit 0
}

$ErrorActionPreference = "Continue"
& $nssm start $ServiceName 2>&1 | Out-Host
$ErrorActionPreference = "Stop"

$deadline = (Get-Date).AddSeconds(45)
do {
    Start-Sleep -Seconds 2
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
} while ($svc -and $svc.Status -ne "Running" -and (Get-Date) -lt $deadline)

if ($svc.Status -ne "Running") { Fail "$ServiceName status is $($svc.Status); see $logs\satellite.log" }

$rpcPort = 10000 + $PortOffset
$listening = Get-NetTCPConnection -State Listen -LocalPort $rpcPort -ErrorAction SilentlyContinue
if (-not $listening) {
    Fail "service is Running but port $rpcPort is not listening; check $logs\satellite.log (seller config, postgres, etc.)"
}

$nssmPid = (Get-CimInstance Win32_Service -Filter "Name='$ServiceName'").ProcessId
$simChild = Get-CimInstance Win32_Process -Filter "ParentProcessId=$nssmPid AND Name='storxnetwork-sim.exe'" -ErrorAction SilentlyContinue
Write-Host "$ServiceName is running (sim PID $($simChild.ProcessId), RPC port $rpcPort listening)" -ForegroundColor Green
exit 0
