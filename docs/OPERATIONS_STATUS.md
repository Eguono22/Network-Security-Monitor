# Operational verification — 2026-10-26

Production: https://network-security-monitor.vercel.app

Completed:

- The approved `sentinelnet_collector` and `sentinelnet_backup` database roles were
  provisioned. Permission checks confirmed that neither can manage schemas, the
  collector can write its application tables, and the backup role cannot insert.
- The root-owned Mac collector is installed and running on `en0` as
  `system/com.sentinelnet.collector`. Observed live packet counts increased from
  3,230 to 3,324 over six seconds with a fresh heartbeat. Raw capture files are not saved.
- The collector's optional Scapy disk cache was disabled after a native pickle-cache
  startup crash. Cache-free startup was verified before starting live monitoring.
- A labeled in-memory simulation using the restricted collector role reached the
  production alert dashboard. Its linked incident was assigned, contained, and
  resolved through the authenticated API. No attack packets were transmitted.
- The daily 03:15 encrypted backup job is installed under the current user's launchd
  session. Its first run completed successfully using the read-only database role.
  Seven encrypted archives are retained. Key material is separate from the archive
  directory and private configuration is owner-readable only.
- A production archive was restored into an isolated localhost database. Record
  counts matched, and incident assignment/resolution worked on the restored copy.
  Production was not overwritten.
- The five-minute local readiness job is installed and successful. The hourly
  external GitHub readiness workflow is installed on main.
- The admin password was rotated and verified on production. The current password
  remains only in the private initial-admin file; old sessions are invalidated.
- The obsolete `network-security-monitor-1dv1` Vercel project was removed. The active
  project and its database remain intact.
- 200 tests passed, including PostgreSQL, browser, backup/restore, tamper detection,
  and privileged-installer boundary coverage.

Operational limits:

- Live collection and local scheduled jobs require this Mac to be awake. User-level
  backup jobs also depend on the user's session. Use an always-on authorized host
  for continuous coverage.
- Backups are currently local. Off-device archive storage is not configured; retain
  a separately protected copy of archives and the encryption key for host-loss recovery.
- GitHub notification delivery follows the owner's account settings.

Operational source changes are pushed to `release/secure-postgres`. The GitHub app
connection could not create the follow-up pull request (403); the branch comparison
page can be used to merge these source changes into main. The live Mac services and
production deployment are already configured independently of that merge.
