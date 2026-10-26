# SentinelNet release runbook

## Release gates

1. Unit and security tests pass.
2. Real PostgreSQL integration and desktop/mobile browser acceptance tests pass.
3. Production configuration passes `python -m network_security_monitor.admin release-check`.
4. Deploy a Vercel preview, verify sign-in and `/ready`, and resolve a test incident.
5. Deploy production and repeat those checks. Keep the previous deployment for rollback.

The web app defaults to password authentication and refuses requests if no valid
account configuration or signing key is present. `X-NSM-Role` is ignored for signed-in
users. Role and password changes invalidate existing sessions. All mutating web
requests, including login and logout, require a CSRF token. Login attempts are
throttled persistently per account and client for 15-minute windows.

## Provision accounts

```bash
python -m network_security_monitor.admin create-user emmanuel --role admin
python -m network_security_monitor.admin create-user analyst --role analyst
python -m network_security_monitor.admin create-user reader --role viewer
```

Passwords are entered interactively and hashed with Werkzeug's scrypt default.
The generated `.runtime/users.json` contains password hashes; never commit it.
Use `--replace` to rotate a password or change a role. Update Vercel's
`NSM_USERS_JSON` value and redeploy after account changes. There is no public
registration or self-service password reset; an administrator provisions accounts.

For localhost development, set `NSM_USERS_FILE=.runtime/users.json`, generate a
random `NSM_SECRET_KEY` of at least 32 characters, and set
`NSM_COOKIE_SECURE=false` only for local HTTP. Use `python -m flask --app api.index run`.
Authentication bypass is explicitly opt-in (`NSM_AUTH_MODE=disabled`), works only
from loopback in nonproduction, and must not be used on a public deployment.
Header roles additionally require `NSM_TRUST_ROLE_HEADER=true` in that local mode.

## PostgreSQL and migration

Create separate PostgreSQL databases/branches for preview and production. Set
`NSM_STORAGE_BACKEND=postgres` and `NSM_DATABASE_URL` to the correct connection URL
for each environment. If both environments share one managed database, set
`NSM_DATABASE_SCHEMA=sentinelnet_preview` or `sentinelnet_production` to keep their
records separate. The configuration helper sets these namespaces automatically;
`init-db` creates the selected schema. Vercel integrations may supply `DATABASE_URL` or `POSTGRES_URL`;
the app accepts these automatically when `NSM_DATABASE_URL` is unset. Use TLS for external connections; pooled URLs suit Vercel.
Use a database owner credential for schema setup, then a restricted runtime role
with SELECT/INSERT/UPDATE/DELETE on these tables and USAGE on their sequences.
The application does not perform schema DDL during requests.

```bash
python -m network_security_monitor.admin init-db
python -m network_security_monitor.admin import-data \
  --incidents incidents.db --alerts alerts.jsonl \
  --reviews unauthorized_devices.jsonl --actions soc_actions.log
```

Only supply import paths that exist. Imports preserve existing incident and review
rows and deduplicate event payloads, so retrying does not overwrite later analyst
changes. Initialize schema before importing. Inventory and zone/policy configuration
remain version-controlled JSON files. Alerts, SOC actions, incidents, and device
reviews all use PostgreSQL when selected, including writes from the monitoring CLI.

## Vercel configuration

Link the intended project with `vercel link`. Configure these variables separately
for **preview** and **production** using the Vercel dashboard or `vercel env add`:

| Variable | Value |
| --- | --- |
| `NSM_ENV` | `production` |
| `NSM_AUTH_MODE` | `password` |
| `NSM_SECRET_KEY` | Random secret, at least 32 characters; different per environment |
| `NSM_USERS_JSON` | Contents of the private hashed account file |
| `NSM_COOKIE_SECURE` | `true` |
| `NSM_STORAGE_BACKEND` | `postgres` |
| `NSM_DATABASE_URL` | TLS-enabled external PostgreSQL URL |
| `NSM_SERVERLESS_READ_ONLY` | `false` after schema validation; `true` for maintenance |
| `NSM_DEVICE_INVENTORY_FILE` | Optional committed asset JSON path |
| `NSM_TOPOLOGY_FILE` | Optional committed zone/policy JSON path |

The prepared helper `python deploy/configure_vercel.py preview` uploads these
values from `.runtime/users.json`, a generated per-environment signing key, and
`NSM_DATABASE_URL` in the process environment. It sends secrets through stdin and
never prints their values. Its `production` mode runs release checks before changing
production variables. Use it only after authorizing the upload to the linked project.

Do not set `NSM_USERS_FILE` to a workstation path on Vercel. Supply the JSON through
an encrypted environment variable. Secrets and generated artifacts are excluded
by `.gitignore`, `.vercelignore`, and the function bundle exclusion rules.

```bash
python -m network_security_monitor.admin release-check
vercel deploy --yes
# Verify the preview before publishing:
vercel deploy --prod --yes
```

`/health` is a liveness check. `/ready` checks the authentication configuration and
required PostgreSQL tables, returning 503 on failure without exposing connection
information. Protect the full application using its sign-in flow; never treat a
successful liveness response as proof that the database is ready.

## Monitoring host

Vercel serves the web/API layer and does not capture packets. Run the collector
on an authorized VM or network host. Configure the same PostgreSQL backend and
production database URL there, and restrict that credential to the collector's
required tables. Start with simulation:

```bash
python -m network_security_monitor --simulate --no-dashboard
```

Then configure an interface and use the existing systemd/Windows service assets
for live capture. Keep database credentials and notification integrations in host
secrets. Do not run live collection inside Vercel functions.

## Backups, restore, and rollback

Enable scheduled backups and retention in the PostgreSQL provider. Before a schema
or data migration, take an additional database snapshot. Regularly restore a backup
into an isolated database, run `init-db` for additive tables if necessary, and verify
incident reads and a test update against that restored database. Record the restore
time and latest recoverable timestamp. Do not test restoration over production.

If the release fails, return the Vercel production alias to the previous successful
deployment using Vercel's rollback controls. Set `NSM_SERVERLESS_READ_ONLY=true` if
writes need to be paused. These schema additions do not remove existing tables;
rollback the app separately from database restoration. Preserve the signing key
unless intentionally invalidating all sessions.

## Validation commands

```bash
python -m pip install -r requirements-dev.txt
python -m playwright install chromium
# Set NSM_TEST_DATABASE_URL to an isolated test database first:
NSM_RUN_BROWSER_TESTS=1 python -m pytest -q
```

PostgreSQL tests create and drop a unique test schema. Browser acceptance runs a
real simulation, signs in, inspects an alert, persists a device review, assigns,
contains, and resolves an incident, then verifies viewer restrictions and mobile
layouts. Screenshots are saved to `.tmp/release-evidence/` and uploaded by CI.
Do not point `NSM_TEST_DATABASE_URL` at production.

## Implementation references

- [Flask session and web security guidance](https://flask.palletsprojects.com/en/stable/web-security/)
- [Psycopg transaction contexts](https://www.psycopg.org/psycopg3/docs/basic/transactions.html)
- [Vercel Flask entrypoints and static assets](https://vercel.com/docs/frameworks/backend/flask)

The Vercel build publishes package-owned browser assets into `public/static/`.
The explicit `api.index:app` entrypoint keeps API discovery separate from those
assets. The lockfile records runtime dependency versions for reproducible builds.
