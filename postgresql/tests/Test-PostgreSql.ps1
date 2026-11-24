<#
.SYNOPSIS
  End-to-end smoke test for the local PostgreSQL container and its OpenBao integration.
.DESCRIPTION
  1. Container is running and healthy, runs as postgres rather than root, port 5432 answers on localhost, no
     password is left in the container's environment, every TCP connection
     needs a password, and connections are logged
  2. OpenBao is unsealed (prompts for the unseal key if not); you're logged in with
     your own OpenBao user, which can't change OpenBao policies; the database connection
     and roles exist
  3. App login (dev-readwrite): connects over TCP, server version matches the image
     in compose.yaml,
     create/insert/select round trip, new tables are owned by dev_app,
     and the login stops working once revoked
  4. Admin login (dev-admin): is a superuser acting as 'postgres', revoked afterwards
  5. Your admin login (<username>-admin): OpenBao manages <username>_admin with a 30-day rotation,
     the login is a superuser, and rotating it locks out the old password
     (skip the rotation with -SkipRotate, so a password saved in your SQL client keeps working)
  6. Data survives a container restart (skip with -SkipRestart)
  7. Image scan, for information only: a recommendation for every critical and high
     vulnerability in the image (no action / -Refresh / wait for a fix), and medium/low counts
     (needs Docker Scout and a Docker Hub sign-in; skipped otherwise, or with -SkipScan)
  Short-lived logins are revoked at the end. Nothing is written anywhere.
  The exit code is the number of failed checks.
.EXAMPLE
  .\tests\Test-PostgreSql.ps1
.EXAMPLE
  .\tests\Test-PostgreSql.ps1 -SkipRestart -SkipRotate -SkipScan
#>
param(
    [string]$Addr       = "http://localhost:8200",
    [string]$Container  = "postgres",
    [string]$Connection = "postgres",
    [int]$Port          = 5432,
    [string]$AdminRole  = "",        # default: <username>-admin
    [string]$AdminUser  = "",        # default: <username>_admin
    [int]$AdminRotationHours = 720,
    [string]$UserName   = "",        # your OpenBao login; default: settings.local.json
    [switch]$SkipRestart,
    [switch]$SkipRotate,
    [switch]$SkipScan
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "..\..\openbao\scripts\Connect-OpenBao.ps1")
$UserName = Resolve-StackUserName $UserName
if (-not $AdminUser) { $AdminUser = "${UserName}_admin" }
if (-not $AdminRole) { $AdminRole = "$UserName-admin" }
$composeFile = Join-Path $PSScriptRoot "..\compose.yaml"
$script:failed    = 0
$script:unsealKey = $null
$script:token     = $null
$script:leases    = New-Object System.Collections.Generic.List[string]
$suffix           = [guid]::NewGuid().ToString("N").Substring(0, 8)
$smokeTable       = "smoke_test_$suffix"
$persistTable     = "persistence_test_$suffix"

# ---------- helpers ----------

function Write-Step([string]$Text) { Write-Host "`n== $Text" -ForegroundColor Cyan }

function Check([string]$Name, [scriptblock]$Test) {
    try {
        if (& $Test) { Write-Host "PASS  $Name" -ForegroundColor Green; return $true }
        Write-Host "FAIL  $Name" -ForegroundColor Red
    } catch {
        Write-Host "FAIL  $Name - $($_.Exception.Message)" -ForegroundColor Red
    }
    $script:failed++
    return $false
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

function Wait-ForHealthy([int]$TimeoutSeconds = 60) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if ((Invoke-Native { docker inspect -f '{{.State.Health.Status}}' $Container 2>$null }) -eq 'healthy') { return $true }
        Start-Sleep -Seconds 2
    }
    return $false
}

function Test-Port([string]$Address = "127.0.0.1") {
    $family = if ($Address -like "*:*") { [System.Net.Sockets.AddressFamily]::InterNetworkV6 } else { [System.Net.Sockets.AddressFamily]::InterNetwork }
    $client = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient($family)
        $client.ConnectAsync($Address, $Port).Wait(3000) -and $client.Connected
    } finally { if ($client) { $client.Dispose() } }
}

# Logs in over TCP inside the container. The password travels in an environment
# variable (docker exec -e PGPASSWORD copies it from this process), never on a command line.
function Invoke-Psql($Creds, [string]$Sql) {
    $env:PGPASSWORD = $Creds.data.password
    try {
        $user = $Creds.data.username
        $out  = Invoke-Native { docker exec -e PGPASSWORD $Container psql -h 127.0.0.1 -U $user -d dev -v ON_ERROR_STOP=1 -tAqc $Sql 2>$null }
        [pscustomobject]@{ Ok = ($LASTEXITCODE -eq 0); Output = ($out | Out-String).Trim() }
    } finally {
        Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue
    }
}

function Get-Query($Creds, [string]$Sql) {
    $result = Invoke-Psql $Creds $Sql
    if (-not $result.Ok) { throw "query failed" }
    $result.Output
}

function Invoke-Unseal {
    if (-not $script:unsealKey) { $script:unsealKey = Read-Secret "Unseal key" }
    try {
        $result = Invoke-RestMethod "$Addr/v1/sys/unseal" -Method Put `
            -Body (@{ key = $script:unsealKey } | ConvertTo-Json) -ContentType "application/json"
    } catch {
        $script:unsealKey = $null
        throw
    }
    -not $result.sealed
}

function Invoke-Bao([string]$Method, [string]$Path, $Body) {
    $params = @{
        Uri     = "$Addr/v1/$Path"
        Method  = $Method
        Headers = @{ "X-Vault-Token" = $script:token }
    }
    if ($Body) { $params.Body = $Body | ConvertTo-Json; $params.ContentType = "application/json" }
    Invoke-RestMethod @params
}

function New-Login([string]$Role) {
    $creds = Invoke-Bao Get "database/creds/$Role"
    $script:leases.Add($creds.lease_id)
    $creds
}

function Revoke-Login($Creds) {
    Invoke-Bao Put "sys/leases/revoke" @{ lease_id = $Creds.lease_id } | Out-Null
    [void]$script:leases.Remove($Creds.lease_id)
}

function Invoke-Cleanup {
    foreach ($lease in @($script:leases)) {
        try { Invoke-Bao Put "sys/leases/revoke" @{ lease_id = $lease } | Out-Null } catch { }
    }
    $script:leases.Clear()
    Invoke-Native { docker exec $Container psql -U postgres -d dev -qc "DROP TABLE IF EXISTS $smokeTable, $persistTable;" *>$null }
    $script:unsealKey = $null
    $script:token     = $null
    Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue
}

function Write-Summary {
    if ($script:failed -eq 0) { Write-Host "`nAll checks passed" -ForegroundColor Green }
    else                      { Write-Host "`n$script:failed check(s) failed" -ForegroundColor Red }
}

function Stop-Test([string]$Message) {
    Write-Host "STOP  $Message" -ForegroundColor Yellow
    Invoke-Cleanup
    Write-Summary
    exit ([Math]::Max($script:failed, 1))
}

# ---------- 1. container ----------

Write-Step "Container"
if (-not (Check "Container '$Container' is running" {
        (Invoke-Native { docker inspect -f '{{.State.Running}}' $Container 2>$null }) -eq 'true' })) {
    Stop-Test "Run the one-off setup first: .\scripts\Initialize-PostgreSql.ps1"
}
[void](Check "Healthcheck reports healthy" { Wait-ForHealthy })
[void](Check "Port $Port answers on localhost over IPv4 (127.0.0.1)" { Test-Port "127.0.0.1" })
[void](Check "Port $Port answers on localhost over IPv6 (::1)" { Test-Port "::1" })
[void](Check "pg_isready over TCP" {
    Invoke-Native { docker exec $Container pg_isready -h 127.0.0.1 -U postgres -d dev *>$null }
    $LASTEXITCODE -eq 0
})
[void](Check "No password left in the container's environment" {
    $envVars = (Invoke-Native { docker inspect -f '{{json .Config.Env}}' $Container }) | ConvertFrom-Json
    $leftover = $envVars | Where-Object { $_ -like "POSTGRES_PASSWORD=?*" }
    -not $leftover
})
if ((Get-Content $composeFile -Raw) -match '(?m)^\s*user:\s*postgres\b') {
    [void](Check "Runs as postgres, not root (gosu never runs)" {
        $owner = "$(Invoke-Native { docker exec $Container stat -c %U /proc/1 2>$null })".Trim()   # PostgreSQL's main process
        $owner -eq "postgres"
    })
}
[void](Check "Every TCP connection needs a password" {
    # Only the container's local socket (break-glass) may skip it. Without this, logins the
    # test makes from inside the container would get in with any password.
    $trusted = Invoke-Native { docker exec $Container psql -U postgres -d dev -tAqc "SELECT count(*) FROM pg_hba_file_rules WHERE type LIKE 'host%' AND auth_method = 'trust'" 2>$null }
    $LASTEXITCODE -eq 0 -and [int]"$trusted".Trim() -eq 0
})
[void](Check "Connections and disconnections are logged" {
    $connections    = "$(Invoke-Native { docker exec $Container psql -U postgres -d dev -tAqc 'SHOW log_connections' 2>$null })".Trim()
    $disconnections = "$(Invoke-Native { docker exec $Container psql -U postgres -d dev -tAqc 'SHOW log_disconnections' 2>$null })".Trim()
    $connections -notin @("off", "") -and $disconnections -eq "on"
})

# ---------- 2. OpenBao ----------

Write-Step "OpenBao"
try { $status = Invoke-RestMethod "$Addr/v1/sys/seal-status" }
catch { Stop-Test "OpenBao not reachable at $Addr - start it from the openbao folder" }
if ($status.sealed) {
    Write-Host "INFO  OpenBao is sealed - unsealing" -ForegroundColor Yellow
    if (-not (Check "OpenBao unsealed" { Invoke-Unseal })) { Stop-Test "Could not unseal - check the key" }
} else {
    [void](Check "OpenBao unsealed" { $true })
}

try { $script:token = Connect-OpenBao -Addr $Addr -UserName $UserName } catch { Stop-Test $_.Exception.Message }
$self = $null
if (-not (Check "Logged in to OpenBao" { $script:self = (Invoke-Bao Get "auth/token/lookup-self").data; $script:self.id })) {
    Stop-Test "Login rejected"
}
$self = $script:self
if (@($self.policies) -contains "root") {
    Write-Host "SKIP  Policy checks - you're using the root token (unset `$env:BAO_TOKEN to log in as '$UserName')" -ForegroundColor Yellow
} else {
    [void](Check "Logged in as '$UserName' with the postgres-admin policy" {
        $self.display_name -eq "userpass-$UserName" -and @($self.policies) -contains "postgres-admin"
    })
    [void](Check "Your login can't do OpenBao admin (can't change policies)" {
        try { Invoke-Bao Put "sys/policies/acl/forbidden-probe" @{ policy = 'path "*" { capabilities = ["read"] }' } | Out-Null; $false }
        catch { $_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 403 }
    })
}

if (-not (Check "Database connection '$Connection' configured" {
        (Invoke-Bao Get "database/config/$Connection").data.plugin_name -eq "postgresql-database-plugin" })) {
    Stop-Test "Run the one-off setup first: .\scripts\Initialize-PostgreSql.ps1"
}
[void](Check "Role dev-readwrite exists" { (Invoke-Bao Get "database/roles/dev-readwrite").data.db_name -eq $Connection })
[void](Check "Role dev-admin exists"     { (Invoke-Bao Get "database/roles/dev-admin").data.db_name -eq $Connection })

# ---------- 3. app login ----------

Write-Step "App login (dev-readwrite)"
$app = $null
if (-not (Check "OpenBao issues a login" { $script:app = New-Login "dev-readwrite"; $script:app.data.username })) {
    Stop-Test "Could not get a login from OpenBao"
}
$app = $script:app
Write-Host "INFO  Logged in as $($app.data.username)" -ForegroundColor Yellow

if (-not (Check "Login connects and runs a query" { (Get-Query $app "SELECT 1") -eq "1" })) {
    Stop-Test "Could not connect with the issued login - check: docker logs $Container"
}
[void](Check "Server version matches the image in compose.yaml" {
    Write-Host "INFO  $(Get-Query $app 'SELECT version()')" -ForegroundColor Yellow
    $tag = [regex]::Match((Get-Content $composeFile -Raw), 'image:\s*postgres:(\S+)').Groups[1].Value   # e.g. 19.0-trixie
    $expected = [regex]::Match($tag, '^(\d+)(?:\.(\d+))?').Groups
    $num = [int](Get-Query $app "SHOW server_version_num")                                       # e.g. 190000
    $majorOk = [int]($num / 10000) -eq [int]$expected[1].Value
    $minorOk = (-not $expected[2].Success) -or ($num % 10000) -eq [int]$expected[2].Value
    $majorOk -and $minorOk
})
[void](Check "Session runs as dev_app" {
    (Get-Query $app "SELECT session_user || '|' || current_user") -eq "$($app.data.username)|dev_app"
})
[void](Check "Create/insert/select round trip" {
    $value = [guid]::NewGuid().ToString()
    (Get-Query $app "CREATE TABLE $smokeTable (id int PRIMARY KEY, value text); INSERT INTO $smokeTable VALUES (1, '$value'); SELECT value FROM $smokeTable WHERE id = 1;") -eq $value
})
[void](Check "New tables are owned by dev_app" {
    (Get-Query $app "SELECT tableowner FROM pg_tables WHERE tablename = '$smokeTable'") -eq "dev_app"
})
[void](Check "Login stops working once revoked" {
    Revoke-Login $app
    -not (Invoke-Psql $app "SELECT 1").Ok
})
[void](Check "Table outlives the revoked login" {
    $owner = Invoke-Native { docker exec $Container psql -U postgres -d dev -tAqc "SELECT tableowner FROM pg_tables WHERE tablename = '$smokeTable'" 2>$null }
    "$owner".Trim() -eq "dev_app"
})

# ---------- 4. admin login ----------

Write-Step "Admin login (dev-admin)"
[void](Check "Admin login is a superuser acting as postgres" {
    $admin = New-Login "dev-admin"
    try {
        (Get-Query $admin "SELECT rolsuper::text || '|' || current_user FROM pg_roles WHERE rolname = session_user") -eq "true|postgres"
    } finally {
        Revoke-Login $admin
    }
})

# ---------- 5. your admin login ----------

Write-Step "Your admin login ($AdminRole)"
[void](Check "OpenBao manages $AdminUser, rotating every $AdminRotationHours hours" {
    $roleInfo = (Invoke-Bao Get "database/static-roles/$AdminRole").data
    $roleInfo.username -eq $AdminUser -and [int]$roleInfo.rotation_period -eq $AdminRotationHours * 3600
})
$script:static = $null
if (Check "Login works and is a superuser" {
        $script:static = Invoke-Bao Get "database/static-creds/$AdminRole"
        (Get-Query $script:static "SELECT rolsuper::text || '|' || session_user || '|' || current_user FROM pg_roles WHERE rolname = session_user") -eq "true|$AdminUser|$AdminUser"
    }) {
    if ($SkipRotate) {
        Write-Host "SKIP  Rotation test (-SkipRotate)" -ForegroundColor Yellow
    } else {
        Write-Host "INFO  Rotating the $AdminUser password - update it in any saved connections afterwards" -ForegroundColor Yellow
        [void](Check "Rotation locks out the old password" {
            Invoke-Bao Post "database/rotate-role/$AdminRole" | Out-Null
            # The new password may reach PostgreSQL a moment after OpenBao answers, so allow a short wait
            $started  = Get-Date
            $deadline = $started.AddSeconds(15)
            while ((Get-Date) -lt $deadline) {
                if (-not (Invoke-Psql $script:static "SELECT 1").Ok) {
                    $seconds = [Math]::Round(((Get-Date) - $started).TotalSeconds, 1)
                    Write-Host "INFO  Old password rejected after $seconds s" -ForegroundColor Yellow
                    return $true
                }
                Start-Sleep -Milliseconds 500
            }
            Write-Host "INFO  Old password still accepted after 15 s" -ForegroundColor Yellow
            $false
        })
        [void](Check "New password works" {
            $fresh = Invoke-Bao Get "database/static-creds/$AdminRole"
            $fresh.data.password -ne $script:static.data.password -and (Get-Query $fresh "SELECT 1") -eq "1"
        })
    }
}
$script:static = $null

# ---------- 6. persistence ----------

if ($SkipRestart) {
    Write-Host "`nSKIP  Persistence test (-SkipRestart)" -ForegroundColor Yellow
} else {
    Write-Step "Persistence across restart"
    $marker = [guid]::NewGuid().ToString()
    $login  = New-Login "dev-readwrite"
    if (-not (Check "Write persistence marker" {
            Get-Query $login "CREATE TABLE $persistTable (value text); INSERT INTO $persistTable VALUES ('$marker');" | Out-Null; $true })) {
        Stop-Test "Could not write marker"
    }

    Write-Host "INFO  Restarting container..." -ForegroundColor Yellow
    Invoke-Native { docker restart $Container | Out-Null }

    if (-not (Check "Healthy again after restart" { Wait-ForHealthy 90 })) {
        Stop-Test "PostgreSQL did not come back - check: docker logs $Container"
    }
    [void](Check "Marker survived restart" { (Get-Query $login "SELECT value FROM $persistTable") -eq $marker })
}

# ---------- 7. image scan (information only) ----------

# Reads Docker Scout's findings and gives a recommendation for every critical and high one:
#   - in gosu (Go) while the container runs as postgres: gosu never runs, no action
#   - fix released and a newer build of the image is published: run -Refresh
#   - fix released but not in a published build yet: wait for the upstream rebuild
#   - no fix released: nothing to do yet
function Get-ScanRecommendations([string]$Image, [bool]$RunsAsPostgres) {
    $strip = { ("$_" -replace '\x1b\[[0-9;]*[A-Za-z]', '') }

    # Totals for every severity, from the per-package table ("...  4C  30H  3M  32L")
    $table = Invoke-Native { docker scout cves $Image --format only-packages --only-vuln-packages 2>&1 } | ForEach-Object $strip
    $totals = @{ C = 0; H = 0; M = 0; L = 0 }
    $tableRows = @($table | Where-Object { $_ -match '(\d+)C\s+(\d+)H\s+(\d+)M\s+(\d+)L' })
    foreach ($row in $tableRows) {
        $null = $row -match '(\d+)C\s+(\d+)H\s+(\d+)M\s+(\d+)L'
        $totals.C += [int]$Matches[1]; $totals.H += [int]$Matches[2]; $totals.M += [int]$Matches[3]; $totals.L += [int]$Matches[4]
    }
    if ($tableRows.Count -eq 0 -and -not ($table -match 'No vulnerable package|Vulnerabilities\s*$')) { return $null }

    # Critical and high findings in detail: package, its type, and each finding's fixed version
    $packages = [ordered]@{}
    if ($totals.C + $totals.H -gt 0) {
        $detail = Invoke-Native { docker scout cves $Image --only-severity critical,high 2>&1 } | ForEach-Object $strip
        $current = $null; $severity = $null
        foreach ($line in $detail) {
            if ($line -match '^\s*(\d+)C\s+(\d+)H\s+\d+M\s+\d+L\s+(\S+)\s+(\S+)\s*$') {
                $current = [pscustomobject]@{ Name = $Matches[3]; Version = $Matches[4]; C = [int]$Matches[1]; H = [int]$Matches[2]; Type = ""; Fixed = @(); Unfixed = 0 }
                $packages["$($Matches[3]) $($Matches[4])"] = $current
                continue
            }
            if (-not $current) { continue }
            if ($line -match '^\s*pkg:([^/]+)/') { $current.Type = $Matches[1]; continue }
            if ($line -match '^\s*\S+\s+(CRITICAL|HIGH)\s+\S+\s*$') { $severity = $Matches[1]; continue }
            if ($line -match 'Fixed version\s*:\s*(.+?)\s*$') {
                $value = $Matches[1]
                if ($value -match 'not fixed' -or $value -eq '') { $current.Unfixed++ } else { $current.Fixed += $value }
            }
        }
    }

    # Is a newer build of this tag published than the one you have? Only asked if it matters.
    $needsBuildCheck = @($packages.Values | Where-Object { $_.Fixed.Count -gt 0 -and $_.Type -ne 'golang' }).Count -gt 0
    $newerBuild = $null
    if ($needsBuildCheck) {
        $remote = "$(Invoke-Native { docker buildx imagetools inspect $Image --format '{{.Manifest.Digest}}' 2>$null })".Trim()
        $local  = "$(Invoke-Native { docker image inspect -f '{{join .RepoDigests " "}}' $Image 2>$null })"
        if ($remote -match '^sha256:') { $newerBuild = -not ($local -like "*$remote*") }
    }

    $recommendations = foreach ($package in $packages.Values) {
        $highestFix = $package.Fixed | Sort-Object { try { [version]($_ -replace '[^\d.].*$', '') } catch { [version]"0.0" } } | Select-Object -Last 1
        $label = "$($package.Name) $($package.Version)"
        if ($package.Type -eq 'golang') {
            if ($RunsAsPostgres) { $action = "none";   $text = "No action: it's inside gosu, which never runs here (the container runs as postgres)" }
            else                 { $action = "change"; $text = "Add 'user: postgres' to compose.yaml: it's inside gosu, which only runs when the container starts as root" }
            $label += " (Go, inside gosu)"
        } elseif ($package.Fixed.Count -eq 0) {
            $action = "none"; $text = "No fix released yet: nothing to do; it'll come with a future -Refresh or release"
        } elseif ($newerBuild -eq $true) {
            $action = "refresh"; $text = "Fixed in $highestFix and a newer image build is published: run .\scripts\Upgrade-PostgreSql.ps1 -Refresh"
        } else {
            $known = if ($newerBuild -eq $false) { "you already have the latest build" } else { "couldn't check for a newer build" }
            $action = "wait"; $text = "Fixed in $highestFix, but not in a published image yet ($known): try -Refresh in a few days"
            if ($package.Unfixed -gt 0) { $text += "; $($package.Unfixed) of its findings have no fix yet" }
        }
        [pscustomobject]@{ Label = $label; Counts = "$($package.C)C $($package.H)H"; Action = $action; Text = $text }
    }

    [pscustomobject]@{ Totals = $totals; Recommendations = @($recommendations) }
}

if ($SkipScan) {
    Write-Host "`nSKIP  Image scan (-SkipScan)" -ForegroundColor Yellow
} else {
    Write-Step "Image scan (information only)"
    Invoke-Native { docker scout version *>$null }
    if ($LASTEXITCODE -ne 0) {
        Write-Host "SKIP  Docker Scout isn't installed" -ForegroundColor Yellow
    } else {
        $image = "$(Invoke-Native { docker inspect -f '{{.Config.Image}}' $Container })".Trim()
        $runsAsPostgres = (Get-Content $composeFile -Raw) -match '(?m)^\s*user:\s*postgres\b'
        $scan = Get-ScanRecommendations $image $runsAsPostgres
        if ($null -eq $scan) {
            Write-Host "SKIP  Couldn't read the scan - are you signed in to Docker Hub? (docker login)" -ForegroundColor Yellow
        } else {
            $t = $scan.Totals
            Write-Host "INFO  $image : $($t.C) critical, $($t.H) high, $($t.M) medium, $($t.L) low"
            $width = ($scan.Recommendations | ForEach-Object { $_.Label.Length } | Measure-Object -Maximum).Maximum
            foreach ($r in $scan.Recommendations) {
                $colour = switch ($r.Action) { "none" { "Green" } "wait" { "Yellow" } default { "Red" } }
                Write-Host ("      {0}  {1,-7}  {2}" -f $r.Label.PadRight($width), $r.Counts, $r.Text) -ForegroundColor $colour
            }
            if ($t.M + $t.L -gt 0) {
                Write-Host "INFO  $($t.M) medium and $($t.L) low not analysed - review occasionally: docker scout cves $image --only-severity medium,low" -ForegroundColor DarkGray
            }
            $actions = @($scan.Recommendations | ForEach-Object { $_.Action })
            if     ($actions -contains "change")  { Write-Host "RESULT  Change needed: see the red line(s) above" -ForegroundColor Red }
            elseif ($actions -contains "refresh") { Write-Host "RESULT  Run .\scripts\Upgrade-PostgreSql.ps1 -Refresh" -ForegroundColor Red }
            elseif ($actions -contains "wait")    { Write-Host "RESULT  Fixes are on the way upstream - try -Refresh in a few days" -ForegroundColor Yellow }
            else                                  { Write-Host "RESULT  Nothing to act on right now" -ForegroundColor Green }
        }
    }
}

# ---------- cleanup ----------

Invoke-Cleanup
Write-Summary
exit $script:failed
