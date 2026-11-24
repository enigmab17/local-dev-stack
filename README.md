# local-dev-stack

A local Docker environment for experimenting with .NET, Entity Framework Core and event-driven patterns. Along the way it practises enterprise-style secrets handling: containers and apps get their credentials from **OpenBao** at runtime, instead of from `.env` files or anything committed to the repo.

The stack is being built **incrementally**. Each service is added and tested on its own before the next one goes in.

## Current status

| Service    | Image                   | Port | Status   |
|------------|-------------------------|------|----------|
| [OpenBao](openbao/README.md)       | `openbao/openbao:2.6.6` | 8200 | Working  |
| [PostgreSQL](postgresql/README.md) | `postgres:19.0-trixie`  | 5432 | Working  |

Each service has its own README with the details: how it's set up, how to use it, upgrades and testing. This page covers the whole stack.

## Set up from scratch

The whole stack, from nothing to tested, in one PowerShell window (so you type your OpenBao password once). Each service's README explains its steps.

**Prerequisites:** Docker Desktop, PowerShell, and for the image scan a Docker Hub sign-in (`docker login`).

### 1. Start clean (only if something is already running)

This **deletes all data**: OpenBao's secrets and logins, and every PostgreSQL database.

```powershell
cd C:\Repositories\GitHub\local-dev-stack\postgresql
docker compose down -v
cd ..\openbao
docker compose down -v
```

The old unseal key, `<username>` password and `<username>_admin` password stop working. Remove them from your password manager once the new ones are saved.

### 2. Your username and the network (once per machine)

Every script works under one username of your choosing: it's your OpenBao login, and your PostgreSQL admin login is `<username>_admin`. The first script you run asks for it and saves it to `settings.local.json` in the repo root, which is gitignored, so your name never ends up in the repo (`settings.example.json` shows the format). Use lowercase letters, digits and `_`, starting with a letter. To override it, pass `-UserName` to any script or set the `LDS_USERNAME` environment variable.

```powershell
docker network create local-dev-stack     # "already exists" is fine
```

### 3. OpenBao

```powershell
cd C:\Repositories\GitHub\local-dev-stack\openbao
docker compose up -d
docker exec -it openbao bao operator init -key-shares=1 -key-threshold=1 -address=http://127.0.0.1:8200
```

Save the **unseal key** in your password manager. Keep the **root token** handy for the next two minutes only; never paste either anywhere else.

```powershell
.\scripts\Initialize-OpenBao.ps1
```

`Initialize-OpenBao.ps1` unseals OpenBao for you. It asks for the unseal key, the root token, and a new password for your `<username>` login. Generate the password in your password manager: 64 characters is plenty, and more than 72 won't work. When it finishes, it has revoked the root token, so delete it.

```powershell
.\tests\Test-OpenBao.ps1                  # restarts OpenBao once, so it asks for the unseal key again
```

### 4. PostgreSQL

```powershell
cd ..\postgresql
.\scripts\Initialize-PostgreSql.ps1
.\tests\Test-PostgreSql.ps1
```

`Initialize-PostgreSql.ps1` reuses your login from step 3. The test rotates the `<username>_admin` password once to prove rotation works.

### 5. SQL clients

```powershell
.\scripts\Get-PostgresCredentials.ps1 -Role admin
```

Put the `<username>_admin` password in DBeaver / VS Code (host `localhost`, port `5432`, database `dev`).

### Your password manager afterwards

| Entry | Used for |
|-------|----------|
| OpenBao unseal key | unsealing after every restart; admin changes (with your login) |
| OpenBao `<username>` password | every script, once per PowerShell window |
| (no root token) | revoked by `Initialize-OpenBao.ps1`; a temporary one is made when needed |

`<username>_admin`'s password lives only in OpenBao: fetch it with `Get-PostgresCredentials.ps1 -Role admin` whenever your SQL client says it has changed.

## Day to day

| After... | Do |
|----------|----|
| a reboot or Docker Desktop restart | Both containers start by themselves. Unseal OpenBao: `docker exec -it openbao bao operator unseal -address=http://127.0.0.1:8200` |
| your SQL client's login fails | `.\postgresql\scripts\Get-PostgresCredentials.ps1 -Role admin` and paste the new password |
| editing a policy in `openbao\policies` | `.\openbao\scripts\Initialize-OpenBao.ps1` |
| the image scan's RESULT line asks for something | do what it says: usually `.\postgresql\scripts\Upgrade-PostgreSql.ps1 -Refresh` |
| a new PostgreSQL release | `.\postgresql\scripts\Upgrade-PostgreSql.ps1 -To <version>` |

## Running

Every container has `restart: unless-stopped`: it comes back after a crash, a reboot or a Docker Desktop restart, and stays down if you stop it yourself. OpenBao comes back sealed; PostgreSQL keeps running without it. Container logs are capped at 10 MB × 3 files (about 30 MB) per container.

All services share the `local-dev-stack` Docker network, so they reach each other by name (OpenBao reaches PostgreSQL at `postgres:5432`).

## Layout

```
├── README.md
├── LICENSE
├── .gitignore
├── settings.example.json     # format of settings.local.json (your username; gitignored)
├── openbao/
│   ├── README.md
│   ├── compose.yaml          # OpenBao service, healthcheck, data volume, restart, log limits
│   ├── config/openbao.hcl    # server mode, file storage, UI enabled, audit log
│   ├── policies/
│   │   ├── postgres-admin.hcl          # your login: the PostgreSQL scripts
│   │   └── openbao-operator.hcl        # your login: checks, temporary root token (with the unseal key)
│   ├── scripts/
│   │   ├── Initialize-OpenBao.ps1      # audit log, policies, your login; leaves no root token
│   │   └── Connect-OpenBao.ps1         # shared: logs you in once per PowerShell window
│   └── tests/Test-OpenBao.ps1
└── postgresql/
    ├── README.md
    ├── compose.yaml          # PostgreSQL 19 as postgres, healthcheck, data volume, restart, shm, log limits
    ├── scripts/
    │   ├── Initialize-PostgreSql.ps1    # one-off: hand the credentials to OpenBao
    │   ├── Get-PostgresCredentials.ps1  # a login for a client or app
    │   └── Upgrade-PostgreSql.ps1       # change version or refresh, with rollback
    └── tests/Test-PostgreSql.ps1
```

## Local shortcuts

These are deliberate simplifications for a machine that only serves localhost:

| Here | Production |
|------|------------|
| TLS disabled | TLS on every listener |
| 1 unseal key share, which (with your login) is enough to generate a root token | Multiple shares held by different people, or auto-unseal via a cloud KMS; generating a root token needs several of them together |
| File storage, single instance | Raft (integrated) storage, clustered |
| PostgreSQL without TLS (`sslmode=disable`) | TLS between apps, OpenBao and the database |
| Password-free superuser over the container's local socket | Local socket access locked down too |
| Your OpenBao login is a username and password | People sign in through an identity provider (OIDC) with MFA |
| Audit log to the container's output, capped at ~30 MB | Audit log shipped to central, tamper-evident storage and kept for the retention period |
| Personal superuser with a 30-day password | Admins sign in to OpenBao with their own identity (OIDC) and get short-lived logins |

## Roadmap

Each item is added and tested on its own:

- [ ] Automate unsealing on startup
- [x] PostgreSQL, with credentials issued by OpenBao
- [x] Your own OpenBao login with a limited policy, and an audit log
- [ ] App logins: `New-AppDatabase.ps1` gives each app its own OpenBao identity (AppRole) and a static database login
- [ ] PostgreSQL backups, with a tested restore
- [ ] TLS for PostgreSQL and OpenBao
- [ ] Container hardening (no-new-privileges, dropped capabilities)
- [ ] RabbitMQ, with credentials issued by OpenBao
- [ ] Kafka
- [ ] A sample .NET app that gets its database credentials from OpenBao, using the client package (separate repository)