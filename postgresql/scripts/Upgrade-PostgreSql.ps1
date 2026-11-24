<#
.SYNOPSIS
  Upgrades PostgreSQL to another image version, with an automatic rollback if anything fails.
.DESCRIPTION
  Minor upgrade (same major, e.g. 19.0 -> 19.1): the data format doesn't change.
    Sets the new tag in compose.yaml, recreates the container and runs the tests.
    Rollback: the old tag goes back and the container is recreated on the same data.

  Major upgrade (e.g. 19.x -> 20.0): the new version can't read the old data files.
    1. Dumps everything (roles with their password hashes, databases, data) into a file
       inside the data volume - it never leaves Docker
    2. Starts the new version, which initialises its own folder in the volume
       (/var/lib/postgresql/<major>); the old version's folder isn't touched
    3. Restores the dump, so every role keeps its password and OpenBao carries on working
    4. Re-runs Initialize-PostgreSql.ps1 (server settings aren't part of a dump)
    5. Runs the tests
    Rollback: the old tag goes back, the old version starts on its untouched folder, and
    the new version's folder is deleted. Nothing written after the upgrade started is kept.

  Before changing anything it checks that the current setup passes its tests and that the
  new image can be pulled. Logs you in to OpenBao once; the scripts it runs reuse that login.

  After a major upgrade the old version's folder stays in the volume, so you can still go
  back by hand (README, "Upgrades"). Remove it with -RemoveOldVersions once you're happy.

  Refresh (-Refresh): the same tag is rebuilt upstream when Debian or its dependencies get
    security fixes. Pulls the latest build of the current tag; if it's new, recreates the
    container on it and runs the tests. Rollback: the previous build (kept by image ID) goes
    back under the tag and the container is recreated on it.
.EXAMPLE
  .\scripts\Upgrade-PostgreSql.ps1 -To 19.1
.EXAMPLE
  .\scripts\Upgrade-PostgreSql.ps1 -To 20.0-trixie
.EXAMPLE
  .\scripts\Upgrade-PostgreSql.ps1 -Refresh
.EXAMPLE
  .\scripts\Upgrade-PostgreSql.ps1 -RemoveOldVersions
#>
[CmdletBinding(DefaultParameterSetName = "Upgrade")]
param(
    [Parameter(Mandatory, ParameterSetName = "Upgrade")]
    [string]$To,                       # e.g. 19.1 or 20.0-trixie; without a suffix, the current one is kept
    [Parameter(Mandatory, ParameterSetName = "Refresh")]
    [switch]$Refresh,
    [Parameter(Mandatory, ParameterSetName = "Remove")]
    [switch]$RemoveOldVersions,
    [string]$Addr      = "http://localhost:8200",
    [string]$Container = "postgres",
    [string]$UserName  = ""      # default: settings.local.json
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "..\..\openbao\scripts\Connect-OpenBao.ps1")
$UserName = Resolve-StackUserName $UserName
$composeFile = Join-Path $PSScriptRoot "..\compose.yaml"
$initScript  = Join-Path $PSScriptRoot "Initialize-PostgreSql.ps1"
$testScript  = Join-Path $PSScriptRoot "..\tests\Test-PostgreSql.ps1"
$dataRoot    = "/var/lib/postgresql"   # the volume; each major version keeps its data in <major>/docker

# ---------- helpers ----------

function Write-Step([string]$Text) { Write-Host "`n== $Text" -ForegroundColor Cyan }
function Write-Ok([string]$Text)   { Write-Host "OK    $Text" -ForegroundColor Green }
function Write-Info([string]$Text) { Write-Host "INFO  $Text" -ForegroundColor Yellow }

function Stop-Upgrade([string]$Message) {
    Write-Host "STOP  $Message" -ForegroundColor Red
    Remove-Item Env:POSTGRES_BOOTSTRAP_PASSWORD -ErrorAction SilentlyContinue
    exit 1
}

# Runs a native command without Windows PowerShell 5.1 turning its stderr output into an error
function Invoke-Native([scriptblock]$Command) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { & $Command } finally { $ErrorActionPreference = $previous }
}

function New-Password {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    -join ($bytes | ForEach-Object { $_.ToString("x2") })
}

function Get-ImageTag {
    $match = [regex]::Match((Get-Content $composeFile -Raw), 'image:\s*postgres:(\S+)')
    if (-not $match.Success) { Stop-Upgrade "No 'image: postgres:<tag>' line found in $composeFile" }
    $match.Groups[1].Value
}

function Set-ImageTag([string]$Tag) {
    $text = [IO.File]::ReadAllText($composeFile)
    $text = [regex]::Replace($text, '(image:\s*postgres:)\S+', "`${1}$Tag")
    [IO.File]::WriteAllText($composeFile, $text)   # UTF-8 without BOM, line endings kept
}

function Get-Major([string]$Tag) { [int]([regex]::Match($Tag, '^(\d+)').Groups[1].Value) }

function Wait-ForHealthy([int]$TimeoutSeconds = 180) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $health = Invoke-Native { docker inspect -f '{{.State.Health.Status}}' $Container 2>$null }
        if ($health -eq 'healthy') { return $true }
        Start-Sleep -Seconds 2
    }
    return $false
}

function Start-Postgres {
    Invoke-Native { docker compose -f $composeFile up -d }
    if ($LASTEXITCODE -ne 0) { throw "docker compose up failed" }
    if (-not (Wait-ForHealthy)) { throw "PostgreSQL did not become healthy - check: docker logs $Container" }
}

function Invoke-InContainer([string[]]$Arguments) {
    $output = Invoke-Native { docker exec $Container @Arguments 2>&1 } | ForEach-Object { "$_" }
    [pscustomobject]@{ Ok = ($LASTEXITCODE -eq 0); Output = $output }
}

function Invoke-Tests([switch]$Quick) {
    $testArgs = @{ Addr = $Addr; Container = $Container; UserName = $UserName; SkipRotate = $true; SkipScan = $true }
    if ($Quick) { $testArgs.SkipRestart = $true }
    & $testScript @testArgs
    $LASTEXITCODE -eq 0
}

function Confirm-ReadyToChange {
    if ((Invoke-RestMethod "$Addr/v1/sys/seal-status").sealed) {
        Stop-Upgrade "OpenBao is sealed - unseal it first: docker exec -it openbao bao operator unseal -address=http://127.0.0.1:8200"
    }
    try { Connect-OpenBao -Addr $Addr -UserName $UserName | Out-Null } catch { Stop-Upgrade $_.Exception.Message }
    Write-Ok "Logged in to OpenBao"
    Write-Info "Checking the current setup passes its tests before changing anything..."
    if (-not (Invoke-Tests -Quick)) { Stop-Upgrade "The current setup fails its tests - fix that first, nothing has been changed" }
    Write-Ok "Current setup passes its tests"
}

function Get-VersionFolders {
    $listing = Invoke-InContainer @("sh", "-c", "ls -1 $dataRoot")
    @($listing.Output | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ })
}

# ---------- remove old versions ----------

if ($RemoveOldVersions) {
    $current = Get-Major (Get-ImageTag)
    $old = @(Get-VersionFolders | Where-Object { $_ -ne $current })
    if ($old.Count -eq 0) { Write-Ok "Only version $current's data is in the volume - nothing to remove"; exit 0 }
    Write-Info "Data folders for old versions: $($old -join ', ') (current: $current)"
    Write-Info "Once they're gone you can't roll back to those versions."
    if ((Read-Host "Type 'remove' to delete them") -ne "remove") { Write-Info "Nothing removed"; exit 0 }
    foreach ($major in $old) {
        $result = Invoke-InContainer @("rm", "-rf", "$dataRoot/$major")
        if (-not $result.Ok) { Stop-Upgrade "Could not remove $dataRoot/$major" }
        Write-Ok "Removed $dataRoot/$major"
    }
    exit 0
}

# ---------- refresh (same tag, newer build) ----------

if ($Refresh) {
    $tag   = Get-ImageTag
    $image = "postgres:$tag"
    Write-Step "Refresh postgres:$tag"
    Confirm-ReadyToChange

    $before = "$(Invoke-Native { docker image inspect -f '{{.Id}}' $image 2>$null })".Trim()
    Invoke-Native { docker pull $image }
    if ($LASTEXITCODE -ne 0) { Stop-Upgrade "Could not pull $image - nothing has been changed" }
    $after = "$(Invoke-Native { docker image inspect -f '{{.Id}}' $image 2>$null })".Trim()
    if ($after -eq $before) { Write-Ok "Already on the latest build of $image - nothing to do"; exit 0 }
    Write-Ok "Pulled a newer build of $image"

    function Invoke-RefreshRollback([string]$Reason) {
        Write-Host "`nFAIL  $Reason" -ForegroundColor Red
        Write-Step "Rolling back to the previous build"
        Invoke-Native { docker tag $before $image }
        Invoke-Native { docker compose -f $composeFile up -d --force-recreate }
        if (-not (Wait-ForHealthy)) { Write-Host "STOP  The previous build didn't come back - check: docker logs $Container" -ForegroundColor Red; exit 1 }
        if (Invoke-Tests -Quick) { Write-Host "`nRolled back - the previous build passes its tests" -ForegroundColor Yellow }
        else { Write-Host "`nRolled back, but the tests fail - check the output above" -ForegroundColor Red }
        exit 1
    }

    try { Start-Postgres } catch { Invoke-RefreshRollback $_.Exception.Message }
    Write-Ok "Container recreated on the new build"
    Write-Step "Tests"
    if (-not (Invoke-Tests)) { Invoke-RefreshRollback "The new build fails its tests" }

    Invoke-Native { docker image rm $before *>$null }   # the old build, now unused
    Write-Host "`nRefreshed $image to its latest build" -ForegroundColor Green
    exit 0
}

# ---------- plan ----------

$fromTag = Get-ImageTag
$suffix  = [regex]::Match($fromTag, '(-.+)$').Groups[1].Value          # e.g. -trixie
$toTag   = if ($To -match '-') { $To } else { "$To$suffix" }
$fromMajor = Get-Major $fromTag
$toMajor   = Get-Major $toTag

Write-Step "Plan"
if ($toTag -eq $fromTag) { Write-Ok "Already on postgres:$fromTag"; exit 0 }
if ($toMajor -lt $fromMajor) {
    Stop-Upgrade "Going down a major version isn't supported - see 'Upgrades' in the README for rolling back by hand"
}
$isMajor = $toMajor -gt $fromMajor
Write-Info "postgres:$fromTag -> postgres:$toTag ($(if ($isMajor) { 'major: dump and restore' } else { 'minor: same data files' }))"

# ---------- pre-flight ----------

Write-Step "Pre-flight"
Confirm-ReadyToChange

Invoke-Native { docker pull "postgres:$toTag" }
if ($LASTEXITCODE -ne 0) { Stop-Upgrade "Could not pull postgres:$toTag - check the tag exists. Nothing has been changed." }
Write-Ok "Pulled postgres:$toTag"

# ---------- rollback ----------

$dumpFile = "$dataRoot/upgrade-$fromMajor-to-$toMajor.sql"

function Invoke-Rollback([string]$Reason) {
    Write-Host "`nFAIL  $Reason" -ForegroundColor Red
    Write-Step "Rolling back to postgres:$fromTag"
    Remove-Item Env:POSTGRES_BOOTSTRAP_PASSWORD -ErrorAction SilentlyContinue
    Set-ImageTag $fromTag
    try { Start-Postgres } catch {
        Write-Host "STOP  Rollback could not start postgres:$fromTag - $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "      compose.yaml is back on $fromTag; check: docker logs $Container" -ForegroundColor Red
        exit 1
    }
    Write-Ok "postgres:$fromTag is running again"
    if ($isMajor) {
        [void](Invoke-InContainer @("rm", "-rf", "$dataRoot/$toMajor", $dumpFile))
        Write-Ok "Removed version $toMajor's data folder and the dump; version $fromMajor's data is as it was"
    }
    if (Invoke-Tests -Quick) { Write-Host "`nRolled back - postgres:$fromTag passes its tests" -ForegroundColor Yellow }
    else { Write-Host "`nRolled back, but the tests fail - check the output above" -ForegroundColor Red }
    exit 1
}

# ---------- minor upgrade ----------

if (-not $isMajor) {
    Write-Step "Upgrade"
    Set-ImageTag $toTag
    try { Start-Postgres } catch { Invoke-Rollback $_.Exception.Message }
    Write-Ok "postgres:$toTag is running on the existing data"

    Write-Step "Tests"
    if (-not (Invoke-Tests)) { Invoke-Rollback "postgres:$toTag fails its tests" }
    Write-Host "`nUpgraded to postgres:$toTag" -ForegroundColor Green
    exit 0
}

# ---------- major upgrade ----------

Write-Step "Dump"
$result = Invoke-InContainer @("pg_dumpall", "-U", "postgres", "--clean", "--if-exists", "--file=$dumpFile")
if (-not $result.Ok) { Stop-Upgrade "pg_dumpall failed: $($result.Output -join ' ') - nothing has been changed" }
Write-Ok "Everything dumped to $dumpFile (inside the volume)"

# Leftovers from an earlier attempt would stop the new version initialising cleanly
[void](Invoke-InContainer @("rm", "-rf", "$dataRoot/$toMajor"))

Write-Step "Start postgres:$toTag"
Set-ImageTag $toTag
try {
    # The new version initialises an empty folder, which needs a superuser password for a moment.
    # The restore below puts back the real (OpenBao-held) one.
    $env:POSTGRES_BOOTSTRAP_PASSWORD = New-Password
    Start-Postgres
} catch { Invoke-Rollback $_.Exception.Message }
Write-Ok "postgres:$toTag initialised its own data folder; version $fromMajor's folder is untouched"

Write-Step "Restore"
$result = Invoke-InContainer @("psql", "-U", "postgres", "-d", "postgres", "-f", $dumpFile)
# Expected: the restore can't drop or re-create the user it's running as
$expected   = 'current user cannot be dropped|role "postgres" already exists'
$unexpected = @($result.Output | Where-Object { $_ -match 'ERROR:' -and $_ -notmatch $expected })
if ($unexpected.Count -gt 0) {
    $unexpected | ForEach-Object { Write-Host "      $_" -ForegroundColor Red }
    Invoke-Rollback "The restore reported errors"
}
Write-Ok "Roles, passwords, databases and data restored"

Remove-Item Env:POSTGRES_BOOTSTRAP_PASSWORD
try { Start-Postgres } catch { Invoke-Rollback $_.Exception.Message }
Write-Ok "Container recreated without the bootstrap password"

Write-Step "Server settings (Initialize-PostgreSql.ps1)"
& $initScript -Addr $Addr -Container $Container -UserName $UserName
if ($LASTEXITCODE -ne 0) { Invoke-Rollback "Initialize-PostgreSql.ps1 failed" }

Write-Step "Tests"
if (-not (Invoke-Tests)) { Invoke-Rollback "postgres:$toTag fails its tests" }

[void](Invoke-InContainer @("rm", "-f", $dumpFile))
Write-Host "`nUpgraded to postgres:$toTag" -ForegroundColor Green
Write-Host "Version $fromMajor's data is still in the volume, so you can go back by hand (README, 'Upgrades')."
Write-Host "Once you're happy: .\scripts\Upgrade-PostgreSql.ps1 -RemoveOldVersions"
exit 0
