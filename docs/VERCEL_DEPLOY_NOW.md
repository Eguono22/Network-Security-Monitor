# Deploy SentinelNet to Vercel

Use the current [release runbook](RELEASE_RUNBOOK.md) to provision accounts,
initialize external PostgreSQL, validate preview, and publish production.

A deployment without a valid signing key and user configuration fails closed.
Keep preview and production databases and signing keys separate.
