<#
.SYNOPSIS
  One-off setup: starts PostgreSQL and hands its credentials to OpenBao.
.DESCRIPTION
  1. Checks the shared Docker network and that OpenBao is on it
  2. Unseals OpenBao if needed (prompts for the unseal key) and logs you in with your
     own OpenBao user (see openbao\scripts\Initialize-OpenBao.ps1); the login is reused
     by the other scripts in this PowerShell window
  3. First run only:
     - generates a random bootstrap password, in memory only
     - starts PostgreSQL with it and waits for the healthcheck
     - creates the dev_app group role that owns the 'dev' database
     - configures OpenBao's database secrets engine with the bootstrap password
     - rotates the superuser password (rotate-root): from then on only OpenBao knows it
     - recreates the container without the bootstrap password in its environment
  4. Every run: makes sure the container is up, requires a password on every TCP
     connection, logs connections and disconnections, and (re)writes the OpenBao roles
       dev-readwrite  1-hour logins for apps, objects owned by dev_app
       dev-admin      15-minute superuser logins for admin work
       <username>-admin  your own superuser (<username>_admin): fixed username, password
                      held by OpenBao and rotated every 30 days
  Safe to run again. Nothing is written to disk.
.EXAMPLE
  .\scripts\Initialize-PostgreSql.ps1
#>
param(
    [string]$Addr         = "http://localhost:8200",
    [string]$Container    = "postgres",
    [string]$BaoContainer = "openbao",
    [string]$Network      = "local-dev-stack",
    [string]$Volume       = "postgresql_postgres-data",
    [string]$Connection   = "postgres",
    [ValidatePattern('^[a-z_][a-z0-9_]*$')]
    [string]$AdminUser    = "",   # default: <username>_admin
    [string]$AdminRole    = "",   # default: <username>-admin
    [int]$AdminRotationHours = 720,  # 30 days
    [string]$UserName     = ""   # your OpenBao login; default: settings.local.json
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "..\..\openbao\scripts\Connect-OpenBao.ps1")
$UserName = Resolve-StackUserName $UserName
if (-not $AdminUser) { $AdminUser = "${UserName}_admin" }
if (-not $AdminRole) { $AdminRole = "$UserName-admin" }
$composeFile     = Join-Path $PSScriptRoot "..\compose.yaml"
$script:token     = $null
$script:unsealKey = $null

# ---------- helpers ----------

function Write-Step([string]$Text) { Write-Host "`n== $Text" -ForegroundColor Cyan }
function Write-Ok([string]$Text)   { Write-Host "OK    $Text" -ForegroundColor Green }
function Write-Info([string]$Text) { Write-Host "INFO  $Text" -ForegroundColor Yellow }

function Clear-Secrets {
    $script:token     = $null
    $script:unsealKey = $null
    Remove-Item Env:POSTGRES_BOOTSTRAP_PASSWORD -ErrorAction SilentlyContinue
}

function Stop-Setup([string]$Message) {
    Write-Host "STOP  $Message" -ForegroundColor Red
    Clear-Secrets
    exit 1
}

# Runs a native command without Windows PowerShell 5.1 turning its stderr output into an error
function Invoke-Native([scriptblock]$Command) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { & $Command } finally { $ErrorActionPreference = $previous }
}

function Read-Secret([string]$Prompt) {
    $secure = Read-Host -Prompt $Prompt -AsSecureString
    [System.Net.NetworkCredential]::new("", $secure).Password
}

function New-Password {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    -join ($bytes | ForEach-Object { $_.ToString("x2") })   # 64 hex chars, URL-safe
}

function Wait-ForHealthy([int]$TimeoutSeconds = 120) {
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

# Runs SQL as the postgres superuser over the container's local socket (no password needed there)
function Invoke-SuperuserSql([string]$Sql) {
    $oneLine = $Sql -replace '\s+', ' '
    Invoke-Native { docker exec $Container psql -U postgres -d dev -v ON_ERROR_STOP=1 -qc $oneLine }
    if ($LASTEXITCODE -ne 0) { throw "SQL failed: $oneLine" }
}

function Invoke-Unseal {
    if (-not $script:unsealKey) { $script:unsealKey = Read-Secret "Unseal key" }
    $result = Invoke-RestMethod "$Addr/v1/sys/unseal" -Method Put `
        -Body (@{ key = $script:unsealKey } | ConvertTo-Json) -ContentType "application/json"
    -not $result.sealed
}

function Invoke-Bao([string]$Method, [string]$Path, $Body) {
    $params = @{
        Uri     = "$Addr/v1/$Path"
        Method  = $Method
        Headers = @{ "X-Vault-Token" = $script:token }
    }
    if ($Body) { $params.Body = $Body | ConvertTo-Json -Depth 5; $params.ContentType = "application/json" }
    Invoke-RestMethod @params
}

function Test-BaoPath([string]$Path) {
    try { Invoke-Bao Get $Path | Out-Null; return $true }
    catch {
        if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 404) { return $false }
        throw
    }
}

# Env vars outlive the script in your shell, so never leave the bootstrap password behind
trap { Clear-Secrets; break }

# ---------- 1. prerequisites ----------

Write-Step "Prerequisites"
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { Stop-Setup "Docker CLI not found" }

Invoke-Native { docker network inspect $Network *>$null }
if ($LASTEXITCODE -ne 0) {
    Invoke-Native { docker network create $Network | Out-Null }
    if ($LASTEXITCODE -ne 0) { Stop-Setup "Could not create the '$Network' network" }
    Write-Ok "Created Docker network '$Network'"
} else {
    Write-Ok "Docker network '$Network' exists"
}

$baoNetworks = Invoke-Native { docker inspect -f '{{json .NetworkSettings.Networks}}' $BaoContainer 2>$null }
if ($LASTEXITCODE -ne 0) { Stop-Setup "OpenBao container '$BaoContainer' not found - start it from the openbao folder: docker compose up -d" }
if (-not (($baoNetworks | ConvertFrom-Json).PSObject.Properties.Name -contains $Network)) {
    Stop-Setup "OpenBao isn't on the '$Network' network yet. From the openbao folder run 'docker compose up -d' (it restarts sealed, so unseal it), then run this script again."
}
Write-Ok "OpenBao is on the '$Network' network"

# ---------- 2. OpenBao ----------

Write-Step "OpenBao"
try { $status = Invoke-RestMethod "$Addr/v1/sys/seal-status" }
catch { Stop-Setup "OpenBao not reachable at $Addr" }
if (-not $status.initialized) { Stop-Setup "OpenBao is not initialised - see the OpenBao section of the README" }
if ($status.sealed) {
    Write-Info "OpenBao is sealed - unsealing"
    try { if (-not (Invoke-Unseal)) { Stop-Setup "Still sealed - check the key" } }
    catch { Stop-Setup "Unseal failed - check the key" }
}
Write-Ok "Unsealed"

try { $script:token = Connect-OpenBao -Addr $Addr -UserName $UserName } catch { Stop-Setup $_.Exception.Message }
$self = (Invoke-Bao Get "auth/token/lookup-self").data
Write-Ok "Logged in as $($self.display_name) (policies: $((@($self.policies) | Where-Object { $_ -ne 'default' }) -join ', '))"

# ---------- 3. work out where we are ----------

$configured = Test-BaoPath "database/config/$Connection"
Invoke-Native { docker volume inspect $Volume *>$null }
$hasData = ($LASTEXITCODE -eq 0)

if ($hasData -and -not $configured) {
    Stop-Setup ("PostgreSQL already has data, but OpenBao doesn't hold its credentials (an earlier run probably stopped part-way). " +
        "The bootstrap password is gone by design, so start fresh: from the postgresql folder run 'docker compose down -v', then run this script again.")
}
if ($configured -and -not $hasData) {
    Write-Info "OpenBao has a connection for a PostgreSQL volume that no longer exists - removing it"
    Invoke-Bao Delete "database/config/$Connection" | Out-Null
    # The static role points at a user in the old database: drop it so it is recreated (and its password set) below
    try { Invoke-Bao Delete "database/static-roles/$AdminRole" | Out-Null } catch { }
    $configured = $false
}

$setupSql = @'
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'dev_app') THEN
    CREATE ROLE dev_app NOLOGIN;
  END IF;
END
$$;
ALTER DATABASE dev OWNER TO dev_app;
'@

# ---------- 4a. first run ----------

if (-not $configured) {
    Write-Step "First-time start"
    try {
        $env:POSTGRES_BOOTSTRAP_PASSWORD = New-Password
        Start-Postgres
        Write-Ok "PostgreSQL started with a one-off bootstrap password"

        Invoke-SuperuserSql $setupSql
        Write-Ok "Group role dev_app owns the 'dev' database"

        $mounts = Invoke-Bao Get "sys/mounts"
        $names  = @($mounts.PSObject.Properties.Name) + @($mounts.data.PSObject.Properties.Name)
        if ($names -notcontains "database/") {
            Invoke-Bao Post "sys/mounts/database" @{ type = "database" } | Out-Null
            Write-Ok "Enabled the database secrets engine at database/"
        }

        Invoke-Bao Post "database/config/$Connection" @{
            plugin_name    = "postgresql-database-plugin"
            connection_url = "postgresql://{{username}}:{{password}}@${Container}:5432/dev?sslmode=disable"
            username       = "postgres"
            password       = $env:POSTGRES_BOOTSTRAP_PASSWORD
            allowed_roles  = "dev-readwrite,dev-admin,$AdminRole"
        } | Out-Null
        Write-Ok "OpenBao connected to PostgreSQL"

        Invoke-Bao Post "database/rotate-root/$Connection" | Out-Null
        Remove-Item Env:POSTGRES_BOOTSTRAP_PASSWORD
        Write-Ok "Superuser password rotated - only OpenBao knows it now"
    } catch {
        Write-Host "ERROR $($_.Exception.Message)" -ForegroundColor Red
        Stop-Setup "Setup stopped before OpenBao took over the credentials. From the postgresql folder run 'docker compose down -v', then run this script again."
    }

    # The environment changed, so compose recreates the container without the old password in it
    try { Start-Postgres } catch { Stop-Setup $_.Exception.Message }
    Write-Ok "Container recreated without the bootstrap password"
}

# ---------- 4b. later runs ----------

else {
    Write-Step "Start"
    try {
        Start-Postgres
        Invoke-SuperuserSql $setupSql
    } catch {
        # An empty volume (e.g. 'docker compose up' straight after 'down -v') can never start:
        # first-time setup needs the one-off bootstrap password only this script provides
        $logs = (Invoke-Native { docker logs --tail 30 $Container 2>&1 } | ForEach-Object { "$_" }) -join "`n"
        if ($logs -match 'Database is uninitialized') {
            Stop-Setup ("The data volume is empty, so PostgreSQL is waiting for first-time setup. Run 'docker compose down -v' " +
                "in the postgresql folder, then this script again (without 'docker compose up' first).")
        }
        Stop-Setup $_.Exception.Message
    }
    Write-Ok "PostgreSQL is up and OpenBao already manages it"
}

# ---------- 5. server settings ----------

# The image trusts TCP connections to 127.0.0.1 from inside the container without a password.
# Switch those to scram-sha-256 so every network login is checked. The local socket stays
# password-free as the documented break-glass route.
Write-Step "Server settings"
try {
    $trusted = Invoke-Native { docker exec $Container psql -U postgres -d dev -tAqc "SELECT count(*) FROM pg_hba_file_rules WHERE type LIKE 'host%' AND auth_method = 'trust'" }
    if ([int]"$trusted".Trim() -gt 0) {
        $hbaFile = "$(Invoke-Native { docker exec $Container psql -U postgres -d dev -tAqc 'SHOW hba_file' })".Trim()
        Invoke-Native { docker exec -u postgres $Container sed -i -E 's/^(host[[:space:]].*[[:space:]])trust[[:space:]]*$/\1scram-sha-256/' $hbaFile }
        if ($LASTEXITCODE -ne 0) { throw "could not update $hbaFile" }
        Invoke-SuperuserSql "SELECT pg_reload_conf();" | Out-Null
        Write-Ok "TCP connections inside the container now need a password too"
    } else {
        Write-Ok "Every TCP connection needs a password"
    }

    # Log every connection and disconnection (who, from where, how they authenticated).
    # ALTER SYSTEM can't share a transaction, hence one statement per call.
    $logConnections    = "$(Invoke-Native { docker exec $Container psql -U postgres -d dev -tAqc 'SHOW log_connections' })".Trim()
    $logDisconnections = "$(Invoke-Native { docker exec $Container psql -U postgres -d dev -tAqc 'SHOW log_disconnections' })".Trim()
    if ($logConnections -in @("off", "") -or $logDisconnections -ne "on") {
        Invoke-SuperuserSql "ALTER SYSTEM SET log_connections = 'on';"
        Invoke-SuperuserSql "ALTER SYSTEM SET log_disconnections = 'on';"
        Invoke-SuperuserSql "SELECT pg_reload_conf();" | Out-Null
        Write-Ok "Connections and disconnections are now logged (docker logs postgres)"
    } else {
        Write-Ok "Connections and disconnections are logged"
    }
} catch { Stop-Setup "Could not apply server settings - $($_.Exception.Message)" }

# ---------- 6. roles ----------

Write-Step "OpenBao roles"
Invoke-Bao Post "database/roles/dev-readwrite" @{
    db_name             = $Connection
    default_ttl         = "1h"
    max_ttl             = "24h"
    creation_statements = @(
        "CREATE ROLE ""{{name}}"" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' IN ROLE dev_app;"
        "ALTER ROLE ""{{name}}"" SET role = 'dev_app';"
    )
    revocation_statements = @(
        "REASSIGN OWNED BY ""{{name}}"" TO dev_app;"
        "DROP OWNED BY ""{{name}}"";"
        "DROP ROLE IF EXISTS ""{{name}}"";"
    )
} | Out-Null
Write-Ok "dev-readwrite: 1-hour logins, tables they create are owned by dev_app"

Invoke-Bao Post "database/roles/dev-admin" @{
    db_name             = $Connection
    default_ttl         = "15m"
    max_ttl             = "1h"
    creation_statements = @(
        "CREATE ROLE ""{{name}}"" WITH LOGIN SUPERUSER PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';"
        "ALTER ROLE ""{{name}}"" SET role = 'postgres';"
    )
    revocation_statements = @(
        "REASSIGN OWNED BY ""{{name}}"" TO postgres;"
        "DROP OWNED BY ""{{name}}"";"
        "DROP ROLE IF EXISTS ""{{name}}"";"
    )
} | Out-Null
Write-Ok "dev-admin: 15-minute superuser logins"

# ---------- 7. your admin login ----------

Write-Step "Your admin login ($AdminUser)"
try {
    # The PostgreSQL user, created without a password: OpenBao sets one in a moment
    Invoke-SuperuserSql (@'
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '__USER__') THEN
    CREATE ROLE __USER__ WITH LOGIN SUPERUSER;
  END IF;
END
$$;
'@ -replace '__USER__', $AdminUser)
    Write-Ok "PostgreSQL user $AdminUser exists (superuser)"

    # The connection only serves roles on its allow-list. This update leaves the
    # stored (rotated) superuser password alone, as nobody else knows it any more.
    $config  = (Invoke-Bao Get "database/config/$Connection").data
    $allowed = @($config.allowed_roles)
    if ($allowed -notcontains $AdminRole -and $allowed -notcontains "*") {
        Invoke-Bao Post "database/config/$Connection" @{
            plugin_name    = $config.plugin_name
            connection_url = $config.connection_details.connection_url
            username       = $config.connection_details.username
            allowed_roles  = (@($allowed | Where-Object { $_ }) + $AdminRole) -join ","
        } | Out-Null
        Write-Ok "Connection now allows $AdminRole"
    }

    # Hand the user to OpenBao. Creating the static role sets a new random password straight away.
    $existing = $null
    try { $existing = (Invoke-Bao Get "database/static-roles/$AdminRole").data } catch { }
    if ($existing -and $existing.username -eq $AdminUser -and [int]$existing.rotation_period -eq $AdminRotationHours * 3600) {
        Write-Ok "$AdminRole already managed by OpenBao (rotates every $AdminRotationHours hours)"
    } else {
        Invoke-Bao Post "database/static-roles/$AdminRole" @{
            db_name         = $Connection
            username        = $AdminUser
            rotation_period = "$($AdminRotationHours)h"
        } | Out-Null
        Write-Ok "$AdminRole managed by OpenBao: password set, rotates every $AdminRotationHours hours"
    }
} catch {
    Stop-Setup "Could not set up $AdminRole - $($_.Exception.Message)"
}

Clear-Secrets
Write-Host "`nDone. Next:" -ForegroundColor Green
Write-Host "  .\tests\Test-PostgreSql.ps1                         # check everything works"
Write-Host "  .\scripts\Get-PostgresCredentials.ps1               # a login for a SQL client or app"
Write-Host "  .\scripts\Get-PostgresCredentials.ps1 -Role dev-admin"
Write-Host "  .\scripts\Get-PostgresCredentials.ps1 -Role admin           # your saved admin login ($AdminUser)"
exit 0
