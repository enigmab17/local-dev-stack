<#
.SYNOPSIS
  End-to-end smoke test for the local OpenBao container.
.DESCRIPTION
  1. Checks the container is running and healthy
  2. Checks OpenBao is initialised and in server (file storage) mode
  3. Unseals it if needed (prompts for the unseal key)
  4. Logs in as your own user (from settings.local.json), or reuses this window's login.
     No root token is needed.
  5. Write/read round trip
  6. Audit log is on and records requests without secret values; policies match
     openbao\policies\*.hcl; your login has its policies and 8-hour sessions and
     can't change policies; no root token exists
  7. Writes a marker, restarts the container, confirms it reseals,
     unseals again and confirms the marker survived
  Keys are held in memory for this run only and never written anywhere.
.EXAMPLE
  .\tests\Test-OpenBao.ps1
.EXAMPLE
  .\tests\Test-OpenBao.ps1 -SkipRestart
#>
param(
    [string]$Addr = "http://localhost:8200",
    [string]$Container = "openbao",
    [string]$UserName = "",       # default: settings.local.json
    [string[]]$Policies = @("postgres-admin", "openbao-operator"),
    [string]$SessionTtl = "8h",
    [switch]$SkipRestart
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "..\scripts\Connect-OpenBao.ps1")
$UserName = Resolve-StackUserName $UserName
$script:failed    = 0
$script:unsealKey = $null
$script:token     = $null
$script:status    = $null

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

function Write-Summary {
    if ($script:failed -eq 0) { Write-Host "`nAll checks passed" -ForegroundColor Green }
    else                      { Write-Host "`n$script:failed check(s) failed" -ForegroundColor Red }
}

function Stop-Test([string]$Message) {
    Write-Host "STOP  $Message" -ForegroundColor Yellow
    Write-Summary
    exit ([Math]::Max($script:failed, 1))
}

function Read-Secret([string]$Prompt) {
    $secure = Read-Host -Prompt $Prompt -AsSecureString
    [System.Net.NetworkCredential]::new("", $secure).Password
}

function Get-SealStatus { Invoke-RestMethod "$Addr/v1/sys/seal-status" }

function Wait-ForServer([int]$TimeoutSeconds = 60) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try { return Get-SealStatus } catch { Start-Sleep -Seconds 1 }
    }
    throw "No response from $Addr within $TimeoutSeconds seconds"
}

function Wait-ForHealthy([int]$TimeoutSeconds = 60) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if ((docker inspect -f '{{.State.Health.Status}}' $Container 2>$null) -eq 'healthy') { return $true }
        Start-Sleep -Seconds 2
    }
    return $false
}

function Invoke-Unseal {
    if (-not $script:unsealKey) { $script:unsealKey = Read-Secret "Unseal key" }
    try {
        $result = Invoke-RestMethod "$Addr/v1/sys/unseal" -Method Put `
            -Body (@{ key = $script:unsealKey } | ConvertTo-Json) -ContentType "application/json"
    } catch {
        $script:unsealKey = $null   # wrong key - forget it so the next attempt re-prompts
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

# ---------- 1. container ----------

Write-Step "Container"
if (-not (Check "Container '$Container' is running" {
        (docker inspect -f '{{.State.Running}}' $Container 2>$null) -eq 'true' })) {
    Stop-Test "Start it with: docker compose up -d"
}
[void](Check "Healthcheck reports healthy" { Wait-ForHealthy })

# ---------- 2. server state ----------

Write-Step "Server state"
if (-not (Check "Server reachable at $Addr" { $script:status = Wait-ForServer 10; $true })) {
    Stop-Test "Check the container logs: docker logs $Container"
}
if (-not (Check "Initialised" { $script:status.initialized })) {
    Stop-Test "Run the one-off init first: docker exec -it $Container bao operator init -key-shares=1 -key-threshold=1 -address=http://127.0.0.1:8200"
}
[void](Check "Storage type is 'file' (not dev mode)" { $script:status.storage_type -eq 'file' })

if ($script:status.sealed) {
    Write-Host "INFO  Server is sealed - unsealing" -ForegroundColor Yellow
    if (-not (Check "Unsealed" { Invoke-Unseal })) { Stop-Test "Could not unseal - check the key" }
} else {
    [void](Check "Unsealed" { $true })
}

# ---------- 3. authentication ----------

Write-Step "Authentication"
try { $script:token = Connect-OpenBao -Addr $Addr -UserName $UserName }
catch { Stop-Test "$($_.Exception.Message)" }
if (-not (Check "Logged in as '$UserName'" { (Invoke-Bao Get "auth/token/lookup-self").data.display_name -eq "userpass-$UserName" })) {
    Stop-Test "Login rejected - run .\scripts\Initialize-OpenBao.ps1 first"
}

# ---------- 4. read/write ----------

Write-Step "Read/write"
[void](Check "Write/read round trip" {
    $value = [guid]::NewGuid().ToString()
    Invoke-Bao Post "cubbyhole/smoke-test" @{ value = $value } | Out-Null
    (Invoke-Bao Get "cubbyhole/smoke-test").data.value -eq $value
})

# ---------- 5. audit log, policies, your login ----------

Write-Step "Audit log, policies and your login"
$failedBefore = $script:failed

[void](Check "Audit log is on (file device to stdout, from config\openbao.hcl)" {
    $audit = Invoke-Bao Get "sys/audit"
    $names = @($audit.PSObject.Properties.Name) + @($audit.data.PSObject.Properties.Name) | Where-Object { $_ -like "*/" }
    $found = $false
    foreach ($name in $names) {
        $device = if ($audit.$name) { $audit.$name } else { $audit.data.$name }
        if ($device.type -eq "file" -and $device.options.file_path -in @("stdout", "/dev/stdout")) { $found = $true }
    }
    $found
})
[void](Check "Requests show up in the audit log" {
    $ErrorActionPreference = "Continue"   # docker logs writes the server log to stderr
    $path = "cubbyhole/audit-test-" + [guid]::NewGuid().ToString("N")
    Invoke-Bao Post $path @{ value = "x" } | Out-Null
    Invoke-Bao Delete $path | Out-Null
    $deadline = (Get-Date).AddSeconds(10)
    while ((Get-Date) -lt $deadline) {
        $logs = docker logs --since 2m $Container 2>$null | Out-String
        if ($logs -like "*$path*") { return $true }
        Start-Sleep -Seconds 1
    }
    $false
})
[void](Check "Audit log hashes secret values" {
    $ErrorActionPreference = "Continue"
    $secret = "audit-plaintext-" + [guid]::NewGuid().ToString("N")
    Invoke-Bao Post "cubbyhole/audit-hash-test" @{ value = $secret } | Out-Null
    Invoke-Bao Delete "cubbyhole/audit-hash-test" | Out-Null
    Start-Sleep -Seconds 1
    $logs = docker logs --since 2m $Container 2>$null | Out-String
    -not ($logs -like "*$secret*")
})

$policyDir = Join-Path $PSScriptRoot "..\policies"
foreach ($file in @(Get-ChildItem -Path $policyDir -Filter *.hcl -ErrorAction SilentlyContinue)) {
    [void](Check "Policy '$($file.BaseName)' matches policies\$($file.Name)" {
        $stored   = (Invoke-Bao Get "sys/policies/acl/$($file.BaseName)").data.policy
        $expected = Get-Content $file.FullName -Raw
        ($stored -replace "\r", "").Trim() -eq ($expected -replace "\r", "").Trim()
    })
}
[void](Check "Username/password logins enabled" {
    $auth = Invoke-Bao Get "sys/auth"
    $auth.'userpass/' -or $auth.data.'userpass/'
})
[void](Check "User '$UserName' has policies $($Policies -join ', ') and $SessionTtl sessions" {
    $user = (Invoke-Bao Get "auth/userpass/users/$UserName").data
    $ttl  = [int]($SessionTtl -replace 'h$', '') * 3600   # e.g. 8h -> 28800 seconds
    $missing = $Policies | Where-Object { @($user.token_policies) -notcontains $_ }
    -not $missing -and [int]$user.token_ttl -eq $ttl -and [int]$user.token_max_ttl -eq $ttl
})
[void](Check "Your login can't change policies" {
    try { Invoke-Bao Put "sys/policies/acl/forbidden-probe" @{ policy = 'path "*" { capabilities = ["read"] }' } | Out-Null; $false }
    catch { $_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 403 }
})
[void](Check "No root token exists" {
    $roots = 0
    foreach ($accessor in @((Invoke-Bao Get "auth/token/accessors?list=true").data.keys)) {
        try { $info = (Invoke-Bao Post "auth/token/lookup-accessor" @{ accessor = $accessor }).data } catch { continue }
        if (@($info.policies) -contains "root") { $roots++ }
    }
    if ($roots -gt 0) { Write-Host "INFO  $roots root token(s) found - run .\scripts\Initialize-OpenBao.ps1 to revoke them" -ForegroundColor Yellow }
    $roots -eq 0
})
if ($script:failed -gt $failedBefore) { Write-Host "INFO  If this is a fresh setup, run .\scripts\Initialize-OpenBao.ps1 first" -ForegroundColor Yellow }

# ---------- 6. persistence ----------

if ($SkipRestart) {
    Write-Host "`nSKIP  Persistence test (-SkipRestart)" -ForegroundColor Yellow
} else {
    Write-Step "Persistence across restart"
    $marker = [guid]::NewGuid().ToString()
    if (-not (Check "Write persistence marker" {
            Invoke-Bao Post "cubbyhole/persistence-test" @{ value = $marker } | Out-Null; $true })) {
        Stop-Test "Could not write marker"
    }

    Write-Host "INFO  Restarting container..." -ForegroundColor Yellow
    docker restart $Container | Out-Null

    if (-not (Check "Server back after restart" { $script:status = Wait-ForServer 60; $true })) {
        Stop-Test "Server did not come back - check: docker logs $Container"
    }
    [void](Check "Server resealed after restart" { $script:status.sealed })
    if (-not (Check "Unsealed after restart" { Invoke-Unseal })) { Stop-Test "Could not unseal after restart" }
    [void](Check "Marker survived restart" {
        (Invoke-Bao Get "cubbyhole/persistence-test").data.value -eq $marker })
}

# ---------- cleanup ----------

foreach ($path in "cubbyhole/smoke-test", "cubbyhole/persistence-test", "cubbyhole/persistence", "cubbyhole/audit-hash-test") {
    try { Invoke-Bao Delete $path | Out-Null } catch { }
}
$script:unsealKey = $null
$script:token     = $null

Write-Summary
exit $script:failed