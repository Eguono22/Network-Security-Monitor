# Operational verification — 2026-10-26

Completed:

- Production is deployed at https://network-security-monitor.vercel.app.
- The rotated admin password passed production sign-in, authenticated API access,
  and sign-out checks. The current password is in the private initial-admin file.
- The obsolete `network-security-monitor-1dv1` Vercel project was removed; the active
  project and its Neon database remain intact.
- A clearly marked `[SIMULATION]` replay produced a port-scan alert from a
  documentation-only IP, visible in the production dashboard. Its own linked case
  was assigned, contained, and resolved through the authenticated API. No attack
  packets were sent to the network.
- An encrypted snapshot containing 1 incident, 3 events, and 3 audit records was
  restored into an isolated localhost database. Row counts matched and incident
  assignment/resolution worked on the restored copy. Production was not overwritten.
- The five-minute current-user Mac readiness job is installed; its first run exited
  successfully. An hourly external GitHub readiness workflow is installed on main.
- 198 tests passed, including database, browser, backup, restore, and tamper checks.

Pending explicit authorization:

- Creating the two restricted database roles described in [OPERATIONS.md](OPERATIONS.md).
  Automatic action review rejected the initial role-provisioning request and required
  approval of those exact grants. No production roles were created.
- Installing the root-owned Mac live collector. Its runtime and installer source are
  prepared; installation requires the collector credentials and macOS administrator
  authorization. Live capture is not running.
- Installing the daily backup job with its dedicated read-only database role.
  Encrypted manual backups and restore verification are complete, but daily backup
  scheduling is not active. Off-device archive storage is not configured.

The operational changes are pushed to `release/secure-postgres`. The GitHub app
connection cannot create the follow-up pull request (403); use the branch comparison
page if a main-branch source merge is desired. The separate hourly uptime workflow
has already been committed to main through the authenticated Git connection.
