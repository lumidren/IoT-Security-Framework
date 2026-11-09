<#
.SYNOPSIS
  IronMesh 5-minute quickstart for Windows PowerShell 5.1+ / PowerShell 7.

.DESCRIPTION
  Generates deploy/docker/.env with random secrets (first run), starts the compose stack, waits
  for the 500-device virtual fleet to enroll, uploads a signed demo firmware, starts a staged
  campaign (1% -> 10% -> 100%) and waits until the anomaly engine auto-quarantines the
  misbehaving device. Prints the console URL and the demo credentials.

  Requires Docker Desktop (or Docker Engine) with the Compose v2 plugin.

.PARAMETER NoBuild
  Use already built or pulled images instead of building them.
#>
[CmdletBinding()]
param(
    [switch]$NoBuild,
    [int]$TimeoutSeconds = 900
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$DockerDir = Join-Path $Root 'deploy\docker'
$EnvFile = Join-Path $DockerDir '.env'
$ComposeFile = Join-Path $DockerDir 'docker-compose.yml'
$ComposeArgs = @('compose', '--project-directory', $DockerDir, '-f', $ComposeFile, '--env-file', $EnvFile)

function Write-Step([string]$Message) { Write-Host "==> $Message" -ForegroundColor Cyan }
function Stop-WithError([string]$Message) { Write-Host "error: $Message" -ForegroundColor Red; exit 1 }

# Plain functions (no param block): every token, including --flags, lands in $args verbatim.
function Invoke-Compose {
    $rest = @($args)
    & docker @ComposeArgs @rest
    if ($LASTEXITCODE -ne 0) { throw "docker compose $($rest -join ' ') failed with exit code $LASTEXITCODE" }
}

function New-RandomHex {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return -join ($bytes | ForEach-Object { $_.ToString('x2') })
}

function Get-EnvValue([string]$Name) {
    $line = Get-Content -LiteralPath $EnvFile | Where-Object { $_ -match "^$([regex]::Escape($Name))=" } | Select-Object -Last 1
    if ($null -eq $line) { return '' }
    return $line.Substring($Name.Length + 1)
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { Stop-WithError 'docker is not installed' }
& docker compose version *> $null
if ($LASTEXITCODE -ne 0) { Stop-WithError 'the Docker Compose v2 plugin is required (docker compose)' }

# 1. Secrets -----------------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $EnvFile)) {
    Write-Step "generating $EnvFile with random secrets"
    $lines = foreach ($line in Get-Content -LiteralPath (Join-Path $DockerDir '.env.example')) {
        if ($line -match '^([A-Z0-9_]+)=__GENERATE__$') { "$($Matches[1])=$(New-RandomHex)" } else { $line }
    }
    # LF line endings, UTF-8 without BOM: the format docker compose expects.
    [System.IO.File]::WriteAllText($EnvFile, (($lines -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))
} else {
    Write-Step "using existing $EnvFile"
    if (Select-String -LiteralPath $EnvFile -Pattern '=__GENERATE__' -Quiet) {
        Stop-WithError "$EnvFile still contains __GENERATE__ placeholders"
    }
}
$FleetCount = Get-EnvValue 'IRONMESH_FLEET_COUNT'
if ([string]::IsNullOrEmpty($FleetCount)) { $FleetCount = '500' }

# 2. Stack -------------------------------------------------------------------------------------
Write-Step 'starting the stack (first run builds every image; this takes a few minutes)'
$upArgs = @('up', '-d')
if (-not $NoBuild) { $upArgs += '--build' }
& docker @ComposeArgs @upArgs
if ($LASTEXITCODE -ne 0) {
    & docker @ComposeArgs ps -a
    Stop-WithError "docker compose up failed; inspect with: docker compose -f deploy/docker/docker-compose.yml logs <service>"
}

function Wait-Healthy([string]$Service) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ($true) {
        $cid = (& docker @ComposeArgs ps -q $Service) | Select-Object -First 1
        if ($cid) {
            $state = (& docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' $cid).Trim()
            if ($state -eq 'healthy') { return }
            if ($state -eq 'unhealthy' -or $state -eq 'exited') {
                & docker @ComposeArgs logs --tail 50 $Service
                Stop-WithError "$Service is $state"
            }
        }
        if ((Get-Date) -gt $deadline) { Stop-WithError "timed out waiting for $Service" }
        Start-Sleep -Seconds 3
    }
}
foreach ($svc in 'pki', 'emqx', 'registry', 'ota', 'anomaly', 'console', 'keycloak', 'grafana') { Wait-Healthy $svc }
Write-Step 'stack healthy'

# 3. Demo ---------------------------------------------------------------------------------------
function Invoke-Tools {
    $rest = @('--profile', 'tools', 'run', '--rm', '--no-deps', 'demo-tools') + @($args)
    & docker @ComposeArgs @rest
    if ($LASTEXITCODE -ne 0) { throw "demo-tools $($args -join ' ') failed with exit code $LASTEXITCODE" }
}
Write-Step "waiting for $FleetCount simulated devices to enroll (EST + attestation)"
Invoke-Tools wait-active $FleetCount --timeout-s $TimeoutSeconds
Write-Step 'uploading signed demo firmware and starting the staged campaign (1% -> 10% -> 100%)'
Invoke-Tools campaign
Write-Step 'waiting for the anomaly engine to auto-quarantine the misbehaving device'
Invoke-Tools wait-quarantine --timeout-s $TimeoutSeconds
try { Invoke-Tools status } catch { Write-Warning $_ }

$demoUser = Get-EnvValue 'IRONMESH_DEMO_USER'
$demoPassword = Get-EnvValue 'IRONMESH_DEMO_PASSWORD'
$grafanaPassword = Get-EnvValue 'GRAFANA_ADMIN_PASSWORD'
Write-Host @"

IronMesh is running.

  Console     http://localhost:3000
              user     $demoUser
              password $demoPassword
  Grafana     http://localhost:3001   (admin / $grafanaPassword)
  Prometheus  http://localhost:9090
  Registry    http://localhost:8000/openapi.json
  Broker      mqtts://localhost:8883  (mTLS, Device CA)

  Credentials live in deploy\docker\.env (git-ignored).
  Stop: docker compose -f deploy/docker/docker-compose.yml down   (add -v to wipe all state)
"@
