<#
.SYNOPSIS
  OpenBao admin setup: audit log, policies and your own login. Leaves no root token behind.
.DESCRIPTION
  You never need to keep a root token. This script makes a temporary one, does its work
  and revokes it:
    - Usual run: you log in as your own user (see Resolve-StackUserName) and give the unseal key.
      OpenBao only issues a root token when it gets both.
    - First run (your user doesn't exist yet): you paste the root token printed by
      'bao operator init', one last time. Once your login is set up and checked, that
      token is revoked too.

  With that temporary root token it:
    1. checks the audit log is on. It's declared in config\openbao.hcl (OpenBao won't
       create audit devices through the API) and writes every request to stdout, so
       'docker logs openbao' shows it and Docker's log limits keep it to ~30 MB.
       Secret values are HMAC-hashed in the log, never written in plain text.
    2. loads every policy in openbao\policies\*.hcl (re-run after editing or adding one)
    3. enables username/password logins and creates or updates your user with its
       policies and 8-hour sessions. Prompts for a password the first time;
       -ResetPassword sets a new one.
    4. revokes every other root token, so none is left lying around
  and finally revokes itself.

  Afterwards your password manager only needs the unseal key and your OpenBao password.
  Safe to run again.
.EXAMPLE
  .\openbao\scripts\Initialize-OpenBao.ps1
.EXAMPLE
  .\openbao\scripts\Initialize-OpenBao.ps1 -ResetPassword
#>
param(
    [string]$Addr        = "http://localhost:8200",
    [string]$Container   = "openbao",
    [string]$UserName    = "",     # default: settings.local.json (asked for on first run)
    [string[]]$Policies  = @("postgres-admin", "openbao-operator"),
    [string]$SessionTtl  = "8h",
    [switch]$ResetPassword,
    [switch]$UseRootToken   # recovery: use an existing root token instead of your login
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "Connect-OpenBao.ps1")
$UserName = Resolve-StackUserName $UserName
$policyDir         = Join-Path $PSScriptRoot "..\policies"
$script:token      = $null    # the root token used for the setup
$script:tokenKind  = $null    # 'temporary' (generated here) or 'original' (pasted, first run)
$script:unsealKey  = $null
$script:succeeded  = $false

# ---------- helpers ----------

function Write-Step([string]$Text) { Write-Host "`n== $Text" -ForegroundColor Cyan }
function Write-Ok([string]$Text)   { Write-Host "OK    $Text" -ForegroundColor Green }
function Write-Info([string]$Text) { Write-Host "INFO  $Text" -ForegroundColor Yellow }

function Read-Secret([string]$Prompt) {
    $secure = Read-Host -Prompt $Prompt -AsSecureString
    [System.Net.NetworkCredential]::new("", $secure).Password
}

function Invoke-Bao([string]$Method, [string]$Path, $Body, [string]$Token = $script:token) {
    $params = @{
        Uri     = "$Addr/v1/$Path"
        Method  = $Method
        Headers = @{ "X-Vault-Token" = $Token }
    }
    if ($Body) { $params.Body = $Body | ConvertTo-Json -Depth 5; $params.ContentType = "application/json" }
    Invoke-RestMethod @params
}

function Get-StatusCode($ErrorRecord) {
    if ($ErrorRecord.Exception.Response) { [int]$ErrorRecord.Exception.Response.StatusCode } else { 0 }
}

# Newer endpoints wrap their fields in "data"; older ones return them at the top level
function Get-ResponseData($Response) {
    if ($Response.data -and $Response.data.PSObject.Properties.Name.Count -gt 0) { $Response.data } else { $Response }
}

# OpenBao's own explanation from an error response, e.g. "invalid key" or "permission denied"
function Get-ErrorText($ErrorRecord) {
    $body = "$($ErrorRecord.ErrorDetails.Message)"
    if ($body) {
        try { $errors = ($body | ConvertFrom-Json).errors; if ($errors) { return ($errors -join "; ") } } catch { }
        return $body
    }
    $ErrorRecord.Exception.Message
}

function Test-BaoPath([string]$Path) {
    try { Invoke-Bao Get $Path | Out-Null; return $true }
    catch { if ((Get-StatusCode $_) -eq 404) { return $false }; throw }
}

# Mount listings come back both at the top level and under .data, depending on the endpoint
function Get-MountNames($Response) {
    @($Response.PSObject.Properties.Name) + @($Response.data.PSObject.Properties.Name) | Where-Object { $_ -like "*/" }
}

# The new root token comes back XOR'd with a one-time password and base64-encoded
function ConvertFrom-EncodedToken([string]$Encoded, [string]$Otp) {
    $b64 = $Encoded.Replace('-', '+').Replace('_', '/')
    switch ($b64.Length % 4) { 2 { $b64 += '==' } 3 { $b64 += '=' } }
    $bytes    = [Convert]::FromBase64String($b64)
    $otpBytes = [Text.Encoding]::ASCII.GetBytes($Otp)
    if ($bytes.Length -eq $otpBytes.Length) {
        $out = New-Object byte[] $bytes.Length
        for ($i = 0; $i -lt $bytes.Length; $i++) { $out[$i] = $bytes[$i] -bxor $otpBytes[$i] }
        return [Text.Encoding]::ASCII.GetString($out)
    }
    # Different lengths: let the bao CLI in the container decode it
    $previous = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    try { $decoded = docker exec $Container bao operator generate-root -decode="$Encoded" -otp="$Otp" 2>$null }
    finally { $ErrorActionPreference = $previous }
    if ($LASTEXITCODE -ne 0 -or -not $decoded) { throw "Could not decode the new root token" }
    "$decoded".Trim()
}

function New-TemporaryRootToken([string]$LoginToken) {
    # Only one attempt can run at a time: clear any left over from an interrupted run
    try { Invoke-Bao Delete "sys/generate-root-token/attempt" -Token $LoginToken | Out-Null } catch { }
    try { $attempt = Get-ResponseData (Invoke-Bao Post "sys/generate-root-token/attempt" @{} -Token $LoginToken) }
    catch { throw "starting the attempt failed: HTTP $(Get-StatusCode $_) - $(Get-ErrorText $_)" }
    if (-not $attempt.nonce -or -not $attempt.otp) {
        throw "OpenBao's reply to starting the attempt had no nonce or one-time password (fields: $(@($attempt.PSObject.Properties.Name) -join ', '))"
    }
    try {
        $result = Get-ResponseData (Invoke-Bao Post "sys/generate-root-token/update" @{ key = $script:unsealKey; nonce = $attempt.nonce } -Token $LoginToken)
    } catch {
        $text = "HTTP $(Get-StatusCode $_) - $(Get-ErrorText $_)"
        try { Invoke-Bao Delete "sys/generate-root-token/attempt" -Token $LoginToken | Out-Null } catch { }
        throw "providing the unseal key failed: $text"
    }
    if (-not $result.complete) { throw "OpenBao wants more key shares ($($result.progress)/$($result.required))" }
    ConvertFrom-EncodedToken $result.encoded_token $attempt.otp
}

function Read-NewPassword {
    while ($true) {
        $first  = Read-Secret "New OpenBao password for '$UserName' (12+ characters)"
        $second = Read-Secret "Repeat it"
        if ($first -ne $second)   { Write-Info "They don't match - try again"; continue }
        if ($first.Length -lt 12) { Write-Info "Too short - use at least 12 characters"; continue }
        return $first
    }
}

# Runs at every exit: the temporary root token always goes; the original one (first run)
# only goes once the new login works, so a failed first run can simply be repeated.
function Complete-Setup {
    if ($script:token) {
        if ($script:tokenKind -eq "temporary" -or ($script:tokenKind -eq "original" -and $script:succeeded)) {
            try {
                Invoke-Bao Post "auth/token/revoke-self" | Out-Null
                Write-Ok "Revoked the $($script:tokenKind) root token used for this run"
            } catch {
                Write-Host "WARN  Could not revoke the $($script:tokenKind) root token - re-run this script to clean it up" -ForegroundColor Yellow
            }
        }
    }
    $script:token = $null; $script:unsealKey = $null
}

function Stop-Setup([string]$Message) {
    Write-Host "STOP  $Message" -ForegroundColor Red
    Complete-Setup
    exit 1
}

trap { Write-Host "ERROR $($_.Exception.Message)" -ForegroundColor Red; Complete-Setup; break }

# ---------- 1. unseal key ----------

Write-Step "OpenBao"
try { $status = Invoke-RestMethod "$Addr/v1/sys/seal-status" }
catch { Stop-Setup "OpenBao not reachable at $Addr - start it from the openbao folder: docker compose up -d" }
if (-not $status.initialized) { Stop-Setup "OpenBao is not initialised - see the OpenBao section of the README" }

$script:unsealKey = Read-Secret "Unseal key"
if ($status.sealed) {
    try {
        $result = Invoke-RestMethod "$Addr/v1/sys/unseal" -Method Put `
            -Body (@{ key = $script:unsealKey } | ConvertTo-Json) -ContentType "application/json"
    } catch { Stop-Setup "Unseal failed - check the key" }
    if ($result.sealed) { Stop-Setup "Still sealed - check the key" }
    Write-Ok "Unsealed"
} else {
    Write-Ok "Already unsealed"
}

# ---------- 2. a root token for this run ----------

Write-Step "Root token for this run"
$userpassEnabled = $false
try {
    Invoke-RestMethod "$Addr/v1/auth/userpass/login/__probe__" -Method Post `
        -Body (@{ password = "x" } | ConvertTo-Json) -ContentType "application/json" | Out-Null
} catch {
    # A missing user/password is a 400; a missing login method is a 404/405 or 'no handler'
    $userpassEnabled = (Get-StatusCode $_) -eq 400 -and "$($_.ErrorDetails.Message)" -notmatch "no handler"
}

$loginToken = $null
if ($userpassEnabled -and -not $UseRootToken) {
    try { $loginToken = Connect-OpenBao -Addr $Addr -UserName $UserName }
    catch { Write-Info $_.Exception.Message }
}

if ($loginToken) {
    try {
        $script:token     = New-TemporaryRootToken $loginToken
        $script:tokenKind = "temporary"
        Write-Ok "Created a temporary root token with your login and the unseal key"
    } catch {
        $message = $_.Exception.Message
        if ($message -match 'HTTP 403') {
            Stop-Setup ("Your login isn't allowed to create a root token ($message). Run once with the original root token: " +
                ".\scripts\Initialize-OpenBao.ps1 -UseRootToken")
        }
        Stop-Setup "Could not create a temporary root token - $message"
    }
} else {
    if (-not $UseRootToken) { Write-Info "No '$UserName' login yet - this looks like the first run" }
    $script:token     = Read-Secret "Root token from 'bao operator init' (revoked once your login works)"
    $script:tokenKind = "original"
}

try { $self = (Invoke-Bao Get "auth/token/lookup-self").data } catch { $script:tokenKind = $null; Stop-Setup "Token rejected" }
if (@($self.policies) -notcontains "root") { $script:tokenKind = $null; Stop-Setup "That isn't a root token" }
$currentAccessor = $self.accessor
Write-Ok "Working as root for this run only"

# ---------- 3. audit log ----------

# The audit log is declared in config\openbao.hcl: OpenBao won't create audit devices
# through the API. A SIGHUP makes it load a config change without sealing.
function Test-AuditLog {
    $audit = Invoke-Bao Get "sys/audit"
    foreach ($name in Get-MountNames $audit) {
        $device = if ($audit.$name) { $audit.$name } else { $audit.data.$name }
        if ($device.type -eq "file" -and $device.options.file_path -in @("stdout", "/dev/stdout")) { return $name }
    }
    $null
}

Write-Step "Audit log"
$auditDevice = Test-AuditLog
if (-not $auditDevice) {
    Write-Info "Not loaded yet - asking OpenBao to reload config\openbao.hcl"
    $previous = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    docker kill --signal HUP $Container *>$null
    $ErrorActionPreference = $previous
    $deadline = (Get-Date).AddSeconds(15)
    while (-not $auditDevice -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 1; $auditDevice = Test-AuditLog }
}
if (-not $auditDevice) {
    Stop-Setup "The audit log isn't on - check the 'audit' block in config\openbao.hcl and 'docker logs $Container'"
}
Write-Ok "On (declared in config\openbao.hcl) - every request goes to 'docker logs $Container'"

# ---------- 4. policies ----------

Write-Step "Policies"
$policyFiles = @(Get-ChildItem -Path $policyDir -Filter *.hcl -ErrorAction SilentlyContinue)
if ($policyFiles.Count -eq 0) { Stop-Setup "No policies found in $policyDir" }
foreach ($policy in $Policies) {
    if (-not ($policyFiles.BaseName -contains $policy)) { Stop-Setup "Policy '$policy' has no file in $policyDir" }
}
foreach ($file in $policyFiles) {
    Invoke-Bao Put "sys/policies/acl/$($file.BaseName)" @{ policy = (Get-Content $file.FullName -Raw) } | Out-Null
    Write-Ok "Loaded policy '$($file.BaseName)'"
}

# ---------- 5. your login ----------

Write-Step "Your login ($UserName)"
if ((Get-MountNames (Invoke-Bao Get "sys/auth")) -notcontains "userpass/") {
    Invoke-Bao Post "sys/auth/userpass" @{ type = "userpass"; description = "Logins for people" } | Out-Null
    Write-Ok "Enabled username/password logins"
}

$settings = @{
    token_policies = ($Policies -join ",")
    token_ttl      = $SessionTtl
    token_max_ttl  = $SessionTtl
}
$newPassword = $null
if (Test-BaoPath "auth/userpass/users/$UserName") {
    Invoke-Bao Post "auth/userpass/users/$UserName" $settings | Out-Null
    Write-Ok "User '$UserName' updated: policies $($Policies -join ', '), $SessionTtl sessions"
    if ($ResetPassword) {
        $newPassword = Read-NewPassword
        Invoke-Bao Post "auth/userpass/users/$UserName/password" @{ password = $newPassword } | Out-Null
        Write-Ok "Password changed"
    }
} else {
    Write-Info "Choose a password for your OpenBao login and store it in your password manager"
    $newPassword = Read-NewPassword
    $settings.password = $newPassword
    Invoke-Bao Post "auth/userpass/users/$UserName" $settings | Out-Null
    $settings.Remove("password")
    Write-Ok "User '$UserName' created: policies $($Policies -join ', '), $SessionTtl sessions"
}

# Prove the login works before any root token is revoked
if ($newPassword) {
    try {
        $login = Invoke-RestMethod "$Addr/v1/auth/userpass/login/$UserName" -Method Post `
            -Body (@{ password = $newPassword } | ConvertTo-Json) -ContentType "application/json"
    } catch { Stop-Setup "The new login doesn't work - nothing has been revoked, run the script again" }
    $env:BAO_TOKEN = $login.auth.client_token   # reused by the other scripts in this window
    $newPassword = $null
    Write-Ok "Logged in as '$UserName' with the new password"
}

# ---------- 6. prove you can get back in ----------

# Before the original root token goes, check your login plus the unseal key really can
# create a root token, so you're never locked out of admin changes.
if ($script:tokenKind -eq "original") {
    Write-Step "Admin access without the root token"
    try {
        $loginToken = Connect-OpenBao -Addr $Addr -UserName $UserName
        $probe = New-TemporaryRootToken $loginToken
        Invoke-Bao Post "auth/token/revoke-self" -Token $probe | Out-Null
        Write-Ok "Your login and the unseal key can create a temporary root token"
    } catch {
        Stop-Setup ("Your login can't create a root token yet ($($_.Exception.Message)). " +
            "The original root token has NOT been revoked - keep it until this is fixed.")
    }
}

# ---------- 7. no root tokens left behind ----------

Write-Step "Root tokens"
$revoked = 0
$accessors = @((Invoke-Bao Get "auth/token/accessors?list=true").data.keys)   # LIST, as a GET for Windows PowerShell
foreach ($accessor in $accessors) {
    if ($accessor -eq $currentAccessor) { continue }
    try { $info = (Invoke-Bao Post "auth/token/lookup-accessor" @{ accessor = $accessor }).data } catch { continue }
    if (@($info.policies) -contains "root") {
        Invoke-Bao Post "auth/token/revoke-accessor" @{ accessor = $accessor } | Out-Null
        $revoked++
    }
}
if ($revoked -gt 0) { Write-Ok "Revoked $revoked other root token(s)" } else { Write-Ok "No other root tokens" }

$script:succeeded = $true
Complete-Setup

Write-Host "`nDone. No root token is left: keep the unseal key and your '$UserName' password." -ForegroundColor Green
Write-Host "  .\openbao\tests\Test-OpenBao.ps1 -SkipRestart     # check the audit log, policies, your login and root tokens"
exit 0
