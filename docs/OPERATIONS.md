# Production operations

The web/API layer runs on Vercel; packet capture runs on an authorized host.
This repository includes a Mac launchd deployment prepared by
`deploy/macos/prepare.py` and an operational CLI:

```bash
python -m network_security_monitor.operations --help
```

## Collector

The collector uses an explicit network interface, non-promiscuous capture, the
`office_tuned` detection profile, and a dedicated database login. It does not
automatically contain devices or inherit outbound notification credentials.
Live alerts carry collector provenance in their metadata. An in-memory replay
uses documentation-only IP addresses and labels records `[SIMULATION]`.

The prepared Mac daemon installs a self-contained, root-owned runtime and source
under `/Library/Application Support/SentinelNet`; it does not execute privileged
code from the user-writable checkout. Its configuration is readable only by root.
`launchd` starts it at boot and restarts it on failure. macOS administrator
authorization is required to install it and open packet-capture devices.

After approved private collector/backup configuration is prepared:

```bash
python deploy/macos/prepare.py
python deploy/macos/install_user_jobs.py --jobs backup uptime
python deploy/macos/install_collector.py
```

The privileged installer stages the approved runtime in a protected temporary
folder before requesting native macOS authorization. This avoids privileged reads
from the Documents folder without changing privacy settings. Temporary installer
credentials are removed after installation. The collector disables Scapy's optional
disk cache because initial root startup on this host crashed in native pickle cache
creation; protocol data loads directly instead.


The daily backup and five-minute readiness jobs run as the current user from a
self-contained runtime in `~/Library/Application Support/SentinelNet`. Daily
backups are scheduled for 03:15 local host time. Local jobs depend on the Mac being
on and the user session being available; a laptop is not an always-on server.
The separate GitHub Actions workflow checks production readiness hourly even
when the Mac is offline. GitHub account notification preferences control delivery
of failed-workflow notifications.

## Database roles

- `sentinelnet_collector`: CONNECT, schema USAGE, SELECT/INSERT/UPDATE on incidents,
  events, and audit records, plus sequence USAGE. No schema-management permission.
- `sentinelnet_backup`: CONNECT, schema USAGE, SELECT on the four application-data
  tables. No write or schema-management permission.

These roles require explicit approval before provisioning. Do not substitute an
owner credential in a persistent collector or scheduled backup service.

## Backup and restore

Backups read the incidents, events, device reviews, and audit history in one
repeatable-read, read-only snapshot. Authentication-throttle state is transient and
is not archived. The archive format is versioned application data, not a complete
PostgreSQL cluster or role backup; `init-db` reconstructs the application schema.

Archives are compressed, encrypted, and authenticated using Fernet. The private
key is stored separately from the backup directory. Files use owner-only
permissions. Seven successful archives are retained; older managed archives are
removed only after a new one is saved. Keep an independent copy of the encryption
key and archives in separately protected storage: loss of this Mac alone would
otherwise lose both. No off-device archive destination is configured by default.

```bash
python -m network_security_monitor.operations backup --config /private/path/backup.json
python -m network_security_monitor.operations restore --config /private/path/backup.json \
  --archive /private/path/archive.fernet --schema restore_unique_name
```

Set `NSM_RESTORE_DATABASE_URL` to an isolated localhost database for a drill.
Restores reject application schemas, existing target namespaces, and remote
restore destinations. Verify row counts and an incident update after restoration.
Never run a drill over production.

## Uptime

`.github/workflows/uptime.yml` sends a read-only HTTPS request to production
`/ready`, retries transient failures, and fails the run if readiness is unavailable.
Its hourly schedule is deliberately staggered from the start of the hour. It needs
no database credentials, application password, or Vercel protection bypass.

## Password rotation

Provision a replacement account hash through `network_security_monitor.admin`,
update `NSM_USERS_JSON` in both Vercel environments, and redeploy. The account's
password-hash fingerprint changes, invalidating old sessions. The private initial
admin file holds the current generated password; never commit it.

## References

- [Fernet authenticated encryption](https://cryptography.io/en/latest/fernet/)
- [PostgreSQL snapshot isolation](https://www.postgresql.org/docs/current/transaction-iso.html)
- [GitHub workflow notifications](https://docs.github.com/en/actions/concepts/workflows-and-actions/notifications-for-workflow-runs)
