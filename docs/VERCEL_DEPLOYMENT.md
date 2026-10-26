# Vercel deployment

For the current secure release flow, use [RELEASE_RUNBOOK.md](RELEASE_RUNBOOK.md).

The app supports signed-session login and durable PostgreSQL-backed alerts,
incidents, SOC actions, and device reviews. It defaults to requiring configured
accounts and a signing key. The old client-supplied role header is not trusted
for authenticated sessions.

With `NSM_STORAGE_BACKEND=postgres`, Vercel write routes work after the external
schema is initialized. Explicit `NSM_SERVERLESS_READ_ONLY=true` still disables
writes for maintenance. With file storage, Vercel remains read-only.

Live packet capture runs on a separate monitoring host; Vercel serves the web/API
layer. `/health` checks liveness; `/ready` checks authentication configuration and
required database tables. Never put workstation paths or generated secrets into
the deployment bundle.
