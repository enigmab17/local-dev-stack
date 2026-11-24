# PostgreSQL

Part of [local-dev-stack](../README.md). It needs [OpenBao](../openbao/README.md) running and unsealed. Run the commands below from this `postgresql` folder; to build the whole stack from nothing, follow [Set up from scratch](../README.md#set-up-from-scratch).

PostgreSQL 19 with **no stored password**. OpenBao owns the superuser and hands out logins through its [database secrets engine](https://openbao.org/docs/secrets/databases/postgresql/):

| OpenBao role    | Login lasts | What it can do |
|-----------------|-------------|----------------|
| `dev-readwrite` | 1 hour (max 24h) | Full use of the `dev` database. It acts as the `dev_app` group role, so tables it creates are owned by `dev_app` and outlive the login |
| `dev-admin`     | 15 minutes (max 1h) | Superuser, acting as `postgres` |
| `<username>-admin`   | Password rotates every 30 days | Your own superuser, `<username>_admin`. Same username every time, so you can save it in your SQL client |

`dev-readwrite` and `dev-admin` are **dynamic**: each login is a real PostgreSQL user that OpenBao creates when asked and deletes when it expires or is revoked. `<username>-admin` is **static**: the user `<username>_admin` stays, and OpenBao owns its password and changes it on a schedule.

## First-time setup

OpenBao must be running and unsealed, and `Initialize-OpenBao.ps1` must have created your login. Then:

```powershell
.\scripts\Initialize-PostgreSql.ps1
```

The script:

1. starts PostgreSQL with a random bootstrap password that exists only in memory for that run
2. gives the `dev` database to a `dev_app` group role
3. connects OpenBao to PostgreSQL with the bootstrap password, then calls `rotate-root`, so OpenBao changes the superuser password to one only it knows
4. recreates the container without the bootstrap password in its environment
5. requires a password on every TCP connection. The image trusts connections to `127.0.0.1` from inside the container by default; only the local socket is left password-free. It also turns on logging of every connection and disconnection
6. creates the `dev-readwrite` and `dev-admin` roles in OpenBao
7. creates the `<username>_admin` superuser and hands it to OpenBao as the `<username>-admin` static role, which sets a random password straight away

It is safe to run again: on later runs it starts the container and refreshes the roles. If it stops part-way through the first run, run `docker compose down -v` and start again. The bootstrap password is gone by then, by design.

After that, `docker compose up -d` is all that's needed. PostgreSQL only reads the password variable when its data volume is empty.

**On a new or emptied volume, always start with `Initialize-PostgreSql.ps1`, not `docker compose up -d`.** First-time setup needs the one-off bootstrap password that only the script provides; started without it, PostgreSQL waits forever with "Database is uninitialized and superuser password is not specified". If that happens, run `docker compose down -v`, then the script.

The container runs as the `postgres` user from the start (`user: postgres`), so nothing in it runs as root and the image's `gosu` helper never runs. The port is published on localhost only, over both IPv4 (`127.0.0.1`) and IPv6 (`::1`): some clients, such as VS Code's PostgreSQL extension, try `localhost` as `::1` first and give up rather than fall back. It has `restart: unless-stopped` and doesn't need OpenBao to keep running: saved logins such as `<username>_admin` work while OpenBao is sealed. Logs are capped at 10 MB × 3 files. The container has 256 MB of shared memory (`shm_size`), as Docker's 64 MB default is too small for parallel queries.

## Persistence

The data lives in the `postgresql_postgres-data` volume. `docker compose down` removes the container but keeps the volume, so the next `docker compose up -d` carries on where you left off. Only `docker compose down -v` (or `docker volume rm`) deletes the data.

## Getting a login

```powershell
.\scripts\Get-PostgresCredentials.ps1                    # dev-readwrite
.\scripts\Get-PostgresCredentials.ps1 -Role dev-admin    # 15-minute superuser
.\scripts\Get-PostgresCredentials.ps1 -Role admin        # your saved admin login
```

This prints the host, port, username, password and an Npgsql connection string, plus when the login expires, or for `<username>-admin` when the password last changed and when it changes next. You can also generate one in the OpenBao UI under **Secrets → database → Roles**.

## Root access

The real `postgres` password can't be read by anyone, including you. Instead:

- **Your day-to-day admin login:** `<username>_admin`. Save it in your SQL client once with the password from `Get-PostgresCredentials.ps1 -Role admin`. When OpenBao rotates it (every 30 days), new connections fail: run the same command and paste the new password in. Open connections aren't dropped. To change it straight away, for example if you think it has leaked, add `-Rotate`.
- **A throwaway admin session:** a `dev-admin` login. It's a superuser for 15 minutes, and anything it creates is owned by `postgres`.
- **Break-glass**, for example when OpenBao is down: `docker exec -it postgres psql -U postgres -d dev`. Connections over the container's local socket don't ask for a password (see [Local shortcuts](../README.md#local-shortcuts)).

## Logs

```powershell
docker logs postgres                                         # server log, including every connection
docker logs postgres --since 1h | Select-String 'authorized|failed'   # logins in the last hour
```

## Upgrades

Change the image version with the upgrade script, not by hand, so it's tested and can roll back:

```powershell
.\scripts\Upgrade-PostgreSql.ps1 -To 19.1          # minor: same data files
.\scripts\Upgrade-PostgreSql.ps1 -To 20.0          # major: dump and restore
.\scripts\Upgrade-PostgreSql.ps1 -Refresh           # latest build of the current version
.\scripts\Upgrade-PostgreSql.ps1 -RemoveOldVersions # after a major upgrade, once you're happy
```

The variant (`-trixie`) is kept unless you give another, for example `-To 20.0-bookworm`.

Before changing anything it checks that the current setup passes its tests and that the new image can be pulled. Then:

- **Minor versions** (19.0 → 19.1) use the same data files. The script sets the new tag in `compose.yaml`, recreates the container and runs the tests. If they fail, it puts the old tag back and recreates the container on the same data.
- **Major versions** (19 → 20) can't read each other's data files, so changing the tag alone isn't enough: the new version would start on an empty folder. The script dumps everything (roles with their password hashes, databases, data) to a file inside the volume, starts the new version, restores the dump and re-runs `Initialize-PostgreSql.ps1`, as server settings aren't part of a dump. Every login keeps its password, so OpenBao carries on working. If any step or the tests fail, it puts the old tag back, starts the old version on its untouched data and deletes the new version's folder.

After a major upgrade, the old version's folder (`/var/lib/postgresql/19`) stays in the volume. To go back by hand, set the old tag in `compose.yaml` and run `docker compose up -d`; anything written since the upgrade is lost. If `<username>_admin` stops working afterwards, `Get-PostgresCredentials.ps1 -Role admin -Rotate` puts OpenBao and PostgreSQL back in step. Once you're happy, `-RemoveOldVersions` deletes old folders after you confirm.

**Refresh** picks up security fixes between releases. Official images are rebuilt under the same tag whenever Debian or their dependencies get fixes, so `-Refresh` pulls the latest build of your current tag. If it's new, the script recreates the container on it and runs the tests; if they fail, it puts the previous build back. Run it every so often, or when the image scan's numbers go up.

Minor releases come out roughly every three months; a new major version each autumn.

## Image scan

The test script ends with an image scan from Docker Scout, for information only (it never fails the run). It gives a recommendation for **every critical and high finding**, grouped by package:

| Finding | Recommendation |
|---------|----------------|
| In `gosu` (Go), with the container running as `postgres` | **No action.** The official image contains `gosu`, a small Go program its startup script uses to step down from root to `postgres`. This setup runs as `postgres` from the start, so `gosu` never runs and its code can't be reached |
| In `gosu`, with the container starting as root | **Add `user: postgres`** to `compose.yaml` |
| Fix released, and a newer build of the image is published | **Run `Upgrade-PostgreSql.ps1 -Refresh`** |
| Fix released, but not in a published build yet | **Wait** for the image to be rebuilt upstream; try `-Refresh` in a few days |
| No fix released yet | **Nothing to do yet.** It'll come with a future refresh or release |

Medium and low findings are counted, not analysed; review them now and then with `docker scout cves postgres:19.0-trixie --only-severity medium,low`. The scan ends with a single **RESULT** line: "Nothing to act on right now", "Run -Refresh", "Fixes are on the way upstream" or "Change needed".

The scan needs Docker Scout and a Docker Hub sign-in (`docker login`); without them it's skipped.

## Querying

Any PostgreSQL client works. Paste in a login from `Get-PostgresCredentials.ps1` (host `localhost`, port `5432`, database `dev`):

- **VS Code:** Microsoft's PostgreSQL extension (`ms-ossdata.vscode-pgsql`). Object explorer, query editor and Copilot integration. It replaces Azure Data Studio, which was retired in February 2026.
- **DBeaver Community:** free desktop client, the closest thing to SSMS.
- **pgAdmin 4:** the official PostgreSQL admin tool.
- **Rider / DataGrip:** built-in database tools.
- **psql in the container:** `docker exec -it postgres psql -U postgres -d dev`.

For a connection you keep, use `<username>_admin`. The dynamic logins expire, so a connection saved with one needs a fresh login after an hour.

## Testing

```powershell
.\tests\Test-PostgreSql.ps1               # full run, including a container restart
.\tests\Test-PostgreSql.ps1 -SkipRestart  # quick checks only
.\tests\Test-PostgreSql.ps1 -SkipRotate   # leave the <username>_admin password alone
.\tests\Test-PostgreSql.ps1 -SkipScan     # skip the image scan
```

The script checks that:

- the container is running and healthy, port 5432 answers on localhost over both IPv4 (`127.0.0.1`) and IPv6 (`::1`), no password is left in the container's environment, every TCP connection needs a password, and connections are logged
- you're logged in to OpenBao as `<username>` with the `postgres-admin` policy, and that login can't do OpenBao admin
- OpenBao holds the connection and both dynamic roles
- an app login connects over TCP, the server version matches the image in `compose.yaml`, it can create, insert and select, and its tables are owned by `dev_app`
- a revoked login can no longer connect, and its tables survive
- an admin login is a superuser acting as `postgres`
- OpenBao manages `<username>_admin` with a 30-day rotation, the login is a superuser, and rotating it locks out the old password. Use `-SkipRotate` once the password is saved in your SQL client, or you'll need to paste in the new one after every run
- data survives a container restart
- the container runs as `postgres`, not root
- **image scan, for information only:** a recommendation for every critical and high vulnerability (see [Image scan](#image-scan)), medium/low counts, and a one-line RESULT. It never fails the run, and is skipped if Scout isn't installed or you aren't signed in to Docker Hub (`docker login`)

Like the [OpenBao test](../openbao/README.md#testing), it prompts only for what it needs (the unseal key if OpenBao is sealed, your password if this window has no login yet), revokes every login it creates, cleans up its test tables, and exits with the number of failed checks.
