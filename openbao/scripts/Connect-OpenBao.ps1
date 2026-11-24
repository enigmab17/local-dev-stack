<#
.SYNOPSIS
  Shared by the OpenBao and PostgreSQL scripts: works out your username and logs you
  in to OpenBao with it.
.DESCRIPTION
  Resolve-StackUserName returns your username, from the first of:
    1. the -UserName a script was given
    2. the LDS_USERNAME environment variable
    3. settings.local.json in the repo root (gitignored, so your name stays out of the repo)
    4. a prompt, the first time, which saves your answer to settings.local.json
  It's your OpenBao login, and your PostgreSQL admin login is <username>_admin.

  Dot-source it, then call Connect-OpenBao. It returns a token and keeps it in
  $env:BAO_TOKEN, so the other scripts in the same PowerShell window reuse it until
  the session ends (8 hours). An expired or revoked token is detected and you are
  asked to log in again. Close the window, or run Disconnect-OpenBao, to drop it.
.EXAMPLE
  . "<path>\openbao\scripts\Connect-OpenBao.ps1"
  $UserName = Resolve-StackUserName $UserName
  $token = Connect-OpenBao -Addr $Addr -UserName $UserName
#>

$script:StackSettingsFile = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\..\settings.local.json"))

function ConvertTo-StackUserName([string]$Name, [string]$Source) {
    $clean = $Name.Trim().ToLowerInvariant()
    if ($clean -notmatch '^[a-z][a-z0-9_]{0,39}$') {
        throw "Username '$Name' (from $Source) isn't usable: start with a letter, then up to 39 lowercase letters, digits or _"
    }
    $clean
}

function Resolve-StackUserName([string]$UserName) {
    if ($UserName)         { return ConvertTo-StackUserName $UserName "-UserName" }
    if ($env:LDS_USERNAME) { return ConvertTo-StackUserName $env:LDS_USERNAME "LDS_USERNAME" }

    if (Test-Path $script:StackSettingsFile) {
        $saved = (Get-Content $script:StackSettingsFile -Raw | ConvertFrom-Json).userName
        if ($saved) { return ConvertTo-StackUserName $saved $script:StackSettingsFile }
    }

    Write-Host "No username set yet. It's your OpenBao login; your PostgreSQL admin login will be <username>_admin." -ForegroundColor Yellow
    $name = ConvertTo-StackUserName (Read-Host -Prompt "Username (lowercase letters, digits, _)") "your answer"
    $json = @{ userName = $name } | ConvertTo-Json
    [IO.File]::WriteAllText($script:StackSettingsFile, $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
    Write-Host "INFO  Saved to $($script:StackSettingsFile) (gitignored)" -ForegroundColor Yellow
    $name
}

function Connect-OpenBao([string]$Addr, [string]$UserName) {
    if ($env:BAO_TOKEN) {
        try {
            Invoke-RestMethod "$Addr/v1/auth/token/lookup-self" -Headers @{ "X-Vault-Token" = $env:BAO_TOKEN } | Out-Null
            return $env:BAO_TOKEN
        } catch {
            Write-Host "INFO  Your OpenBao session has ended - log in again" -ForegroundColor Yellow
            Remove-Item Env:BAO_TOKEN -ErrorAction SilentlyContinue
        }
    }

    $secure   = Read-Host -Prompt "OpenBao password for '$UserName'" -AsSecureString
    $password = [System.Net.NetworkCredential]::new("", $secure).Password
    try {
        $login = Invoke-RestMethod "$Addr/v1/auth/userpass/login/$UserName" -Method Post `
            -Body (@{ password = $password } | ConvertTo-Json) -ContentType "application/json"
    } catch {
        throw "OpenBao login failed for '$UserName' - check the password (or run .\openbao\scripts\Initialize-OpenBao.ps1 to create the user)"
    } finally {
        $password = $null
    }

    $env:BAO_TOKEN = $login.auth.client_token
    $login.auth.client_token
}

function Disconnect-OpenBao([string]$Addr = "http://localhost:8200") {
    if ($env:BAO_TOKEN) {
        try {
            Invoke-RestMethod "$Addr/v1/auth/token/revoke-self" -Method Post -Headers @{ "X-Vault-Token" = $env:BAO_TOKEN } | Out-Null
        } catch { }
        Remove-Item Env:BAO_TOKEN -ErrorAction SilentlyContinue
    }
}
