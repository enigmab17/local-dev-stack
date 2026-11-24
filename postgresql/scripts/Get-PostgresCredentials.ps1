<#
.SYNOPSIS
  Gets a PostgreSQL login from OpenBao, for a SQL client or an app.
.DESCRIPTION
  dev-readwrite  1-hour login; tables you create are owned by dev_app, so they outlive the login
  dev-admin      15-minute superuser login (acts as 'postgres') for admin work
  admin          your own superuser (<username>_admin): same username every time, password
                 rotated by OpenBao every 30 days. Save it in your SQL client and come
                 back here when it stops working. -Rotate changes it now.
  Short-lived logins are deleted from PostgreSQL when they expire, or straight away with -Revoke.
  Logs you in with your own OpenBao user, or reuses this PowerShell window's login.
  Nothing is written to disk.
.EXAMPLE
  .\scripts\Get-PostgresCredentials.ps1
.EXAMPLE
  .\scripts\Get-PostgresCredentials.ps1 -Role admin
.EXAMPLE
  .\scripts\Get-PostgresCredentials.ps1 -Role admin -Rotate
.EXAMPLE
  .\scripts\Get-PostgresCredentials.ps1 -Revoke "database/creds/dev-admin/AbC123..."
#>
param(
    [ValidateSet("dev-readwrite", "dev-admin", "admin")]
    [string]$Role = "dev-readwrite",
    [switch]$Rotate,     # static roles only: set a new password now
    [string]$Revoke,     # a lease id to revoke instead of issuing a login
    [string]$Addr = "http://localhost:8200",
    [string]$UserName = ""        # your OpenBao login; default: settings.local.json
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "..\..\openbao\scripts\Connect-OpenBao.ps1")
$UserName = Resolve-StackUserName $UserName
$isStatic = $Role -eq "admin"
# the OpenBao role behind it: "admin" is your static role, <username>-admin
$baoRole = if ($isStatic) { "$UserName-admin" } else { $Role }

# OpenBao timestamps carry nanoseconds, which [datetime] can't parse, so trim to 7 digits first
function Format-Time($Value) {
    if ($Value -is [datetime]) { $time = $Value }
    else {
        $text = "$Value" -replace '(\.\d{7})\d+', '$1'
        $time = [datetime]::Parse($text, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)
    }
    $time.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
}

if ($Rotate -and -not $isStatic) {
    Write-Host "-Rotate only applies to saved logins (-Role admin). Short-lived logins just expire." -ForegroundColor Yellow
    exit 1
}

if ((Invoke-RestMethod "$Addr/v1/sys/seal-status").sealed) {
    Write-Host "OpenBao is sealed - unseal it first: docker exec -it openbao bao operator unseal -address=http://127.0.0.1:8200" -ForegroundColor Yellow
    exit 1
}

try { $token = Connect-OpenBao -Addr $Addr -UserName $UserName }
catch { Write-Host $_.Exception.Message -ForegroundColor Red; exit 1 }
$headers = @{ "X-Vault-Token" = $token }

if ($Revoke) {
    Invoke-RestMethod "$Addr/v1/sys/leases/revoke" -Method Put -Headers $headers `
        -Body (@{ lease_id = $Revoke } | ConvertTo-Json) -ContentType "application/json" | Out-Null
    Write-Host "Revoked - the login has been deleted from PostgreSQL" -ForegroundColor Green
    exit 0
}

if ($isStatic) {
    if ($Rotate) {
        Invoke-RestMethod "$Addr/v1/database/rotate-role/$baoRole" -Method Post -Headers $headers | Out-Null
        Write-Host "Password rotated - update it in any saved connections" -ForegroundColor Green
    }
    $creds    = Invoke-RestMethod "$Addr/v1/database/static-creds/$baoRole" -Headers $headers
    $user     = $creds.data.username
    $password = $creds.data.password
    $lastRotation = Format-Time $creds.data.last_vault_rotation
    $nextRotation = Format-Time ((Get-Date).AddSeconds([int]$creds.data.ttl))
} else {
    $creds    = Invoke-RestMethod "$Addr/v1/database/creds/$baoRole" -Headers $headers
    $lease    = Invoke-RestMethod "$Addr/v1/sys/leases/lookup" -Method Put -Headers $headers `
        -Body (@{ lease_id = $creds.lease_id } | ConvertTo-Json) -ContentType "application/json"
    $user     = $creds.data.username
    $password = $creds.data.password
}

Write-Host ""
Write-Host "Host      localhost"
Write-Host "Port      5432"
Write-Host "Database  dev"
Write-Host "Username  $user"
Write-Host "Password  $password"
if ($isStatic) {
    Write-Host "Rotated   $lastRotation"
    Write-Host "Next      $nextRotation (automatic)"
} else {
    Write-Host "Expires   $(Format-Time $lease.data.expire_time)"
}
Write-Host ""
Write-Host "Connection string (Npgsql):"
Write-Host "  Host=localhost;Port=5432;Database=dev;Username=$user;Password=$password"
if (-not $isStatic) {
    Write-Host ""
    Write-Host "Revoke early:"
    Write-Host "  .\scripts\Get-PostgresCredentials.ps1 -Revoke `"$($creds.lease_id)`""
}
