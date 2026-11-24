# OpenBao

Part of [local-dev-stack](../README.md).

[OpenBao](https://openbao.org) is the open-source, Linux Foundation fork of HashiCorp Vault. It runs here in **server mode** with file storage, not dev mode, so:

- secrets persist across restarts in the `openbao-data` Docker volume (encrypted at rest)
- OpenBao starts **sealed** after every restart and must be unsealed before it serves requests, as in production

The container has `restart: unless-stopped`, so it comes back after a reboot, but sealed. Its logs are capped at 10 MB × 3 files.

Run the commands below from this `openbao` folder. To build the whole stack from nothing, follow [Set up from scratch](../README.md#set-up-from-scratch) in the main README; this page explains each part.

## First-time setup

One script does everything:

```powershell
.\scripts\Initialize-OpenBao.ps1
```

On the first run it:

1. creates the shared `local-dev-stack` Docker network if it's missing, and starts the container (`docker compose up -d`)
2. **initialises OpenBao** with one unseal key share, and shows the **unseal key** once. It waits until you type `saved`, then clears it from the screen. Store it in your password manager: it never goes in this repo, and the data can't be recovered without it. The **root token** is kept in memory for this run only and never shown
3. unseals OpenBao
4. checks the **audit log** is on. Every request goes to OpenBao's output, so `docker logs openbao` shows who asked for what and when. Secret values are HMAC-hashed in the log, never written in plain text. The audit log is declared in `config\openbao.hcl`, because OpenBao no longer lets the API create audit devices (a security fix); if it isn't loaded yet, the script makes OpenBao reload its config
5. loads every policy in `policies\*.hcl`
6. turns on username/password logins and creates your user, `<username>` (the name in `settings.local.json`, asked for on first run), with the `postgres-admin` and `openbao-operator` policies and 8-hour sessions. It asks you to choose a password; store it in your password manager
7. checks the new login works, then **revokes every root token**, including the one it used

If the first run stops part-way, OpenBao holds nothing yet: run `docker compose down -v` and the script again. The unseal key it showed won't be needed.

On later runs it starts the container if needed and asks for the unseal key.

## No root token

Once that's done, no root token exists, and you don't need one. Your password manager holds two things: the **unseal key** and your **`<username>` password**.

| You want to | You need |
|---|---|
| Use PostgreSQL, get logins, run the tests, upgrade | your `<username>` password |
| Unseal after a restart | the unseal key |
| Change OpenBao itself: edit or add a policy, change your login, reset your password (`-ResetPassword`) | both: run `Initialize-OpenBao.ps1` |

For admin changes, `Initialize-OpenBao.ps1` logs you in as `<username>` and asks for the unseal key. OpenBao only issues a root token when it gets both. The script does its work with that temporary token and revokes it before it finishes, along with any other root token it finds. It's safe to run again whenever you edit a policy.

This is the recommended production practice: revoke the root token after setup and generate a temporary one when it's needed. Here one unseal key is enough to generate it; in production it takes several key holders together.

**If you can't log in at all** (forgotten password, broken policy): the old unauthenticated way of generating a root token is turned off by default since OpenBao 2.5.3. Turn it on briefly with `disable_unauthed_generate_root_endpoints = false` in the `listener` block of `config\openbao.hcl`, restart, run `docker exec -it openbao bao operator generate-root -address=http://127.0.0.1:8200` with the unseal key, run `.\scripts\Initialize-OpenBao.ps1 -UseRootToken -ResetPassword`, then remove the setting and restart again.

## Your login

| Policy | Lets `<username>` |
|--------|--------------|
| `postgres-admin` | run every `postgresql` script: the database secrets engine, and looking up and revoking its logins |
| `openbao-operator` | see how OpenBao is set up (audit log, login methods, policies, whether root tokens exist) for the tests, and create a temporary root token *together with the unseal key*. It can't change anything by itself |

The scripts ask for your password the first time they run in a PowerShell window, then keep the session in `$env:BAO_TOKEN` so the other scripts in that window reuse it. It lasts 8 hours; after that they ask again. Close the window to drop it.

Apps never use `<username>`. Each app will get its own OpenBao identity (an AppRole) with a policy that reaches only its own database login: a static role whose password OpenBao rotates. The app fetches that password in the background and keeps it in memory, so requests never wait on OpenBao, and rotation doesn't drop pooled connections, because PostgreSQL checks the password only when a connection opens. The .NET client for this will live in its own repository, as a NuGet package.

## Unsealing after a restart

```powershell
docker exec -it openbao bao operator unseal -address=http://127.0.0.1:8200
```

The UI is at http://localhost:8200. Log in with **Username** as the method and your `<username>` login.

## Audit log

```powershell
docker logs openbao                       # everything, one JSON line per request and response
docker logs openbao --since 1h | Select-String '"path":"database/'   # credential requests in the last hour
```

## Testing

```powershell
.\tests\Test-OpenBao.ps1               # full run, including a container restart
.\tests\Test-OpenBao.ps1 -SkipRestart  # quick checks only
```

It logs in as `<username>`, or reuses this window's login. No root token is needed.

The script checks that:

- the container is running and healthy
- OpenBao is initialised and running in server mode with file storage
- it can be unsealed and authenticated against
- a secret can be written and read back
- the audit log is on, records requests and doesn't contain secret values in plain text
- the policies in OpenBao match the files in `policies\`
- your login exists with its policies and 8-hour sessions, and can't change policies
- no root token exists
- data survives a container restart, and the server reseals after the restart

It prompts for the unseal key and your password only when it needs them, keeps them in memory for that run only, and cleans up its test data. The exit code is the number of failed checks.
