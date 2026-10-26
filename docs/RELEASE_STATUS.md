# Release verification — 2026-10-26

Production: https://network-security-monitor.vercel.app

The production release uses password authentication and the free Neon PostgreSQL
resource `sentinelnet-postgres`, connected through the Vercel Marketplace.
Preview and production use separate `sentinelnet_preview` and
`sentinelnet_production` schemas. Both schemas were initialized before release.

Validation completed:

- 194 unit, security, real PostgreSQL, and desktop/mobile browser acceptance tests passed.
- Vercel preview and production builds completed successfully.
- Production `/ready` returned 200.
- An unauthenticated alert API request returned 401.
- The provisioned admin signed in successfully, loaded the workspace, and accessed
  alert and incident APIs.
- Sign-out removed access; the next alert API request returned 401.

Account hashes and session keys are stored as Vercel secrets. The initial admin
password is held only in the private, Git-ignored `.runtime/initial-admin.txt` file.
Do not upload that file or cookie jars to the repository.

The original preview URL shown before database setup is an older deployment and
does not inherit later environment changes. Use the production URL above.

The app is ready to receive telemetry. Live packet capture still runs on a separate,
authorized monitoring host; Vercel hosts the web/API layer. Follow the
[release runbook](RELEASE_RUNBOOK.md) for collector configuration, password rotation,
backup policy, restore drills, and rollback.
