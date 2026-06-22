# Production Persistence Plan

This plan moves the app from demo/read-only Vercel storage to a production-safe
external persistence model without throwing away the current code structure.

## Current State

The repo currently stores operational state in local files:

- alerts: JSONL or parsed log files
- incidents: SQLite with JSONL migration support
- unauthorized device reviews: JSONL
- SOC actions: JSONL
- device inventory: JSON
- topology: JSON

This works locally, but it is not a good fit for Vercel because runtime writes
to repo files are not reliable there.

## Recommended Target

Use a phased architecture:

- PostgreSQL for mutable operational data
- optional object/blob storage for exports and snapshots
- JSON config files or database tables for inventory/topology, depending on how
  frequently they change

For this repo, the cleanest first production target is:

- incidents -> PostgreSQL
- unauthorized device lifecycle -> PostgreSQL
- alerts -> PostgreSQL append-only table
- SOC actions -> PostgreSQL append-only table
- inventory/topology -> keep as JSON files first, then migrate later if needed

## Why PostgreSQL First

The current models already look relational:

- incidents have workflow fields, filters, timestamps, assignees, and notes
- unauthorized device reviews are keyed by IP and have lifecycle status
- alerts and SOC actions are append-only event records

That maps naturally to tables and avoids trying to emulate database behavior on
top of JSONL files.

## Migration Strategy

### Phase 1: Keep Vercel read-only, move only write-heavy records

Build a new storage mode for:

- incident reads/writes
- unauthorized device reads/writes

Add new environment variables such as:

```text
NSM_STORAGE_BACKEND=postgres
NSM_DATABASE_URL=<postgres connection string>
```

Keep these as-is temporarily:

- `NSM_ALERTS_DATA_FILE`
- `NSM_DEVICE_INVENTORY_FILE`
- `NSM_TOPOLOGY_FILE`

Outcome:

- incident updates become production-safe
- unauthorized-device lifecycle updates become production-safe
- dashboards keep working with minimal code churn

### Phase 2: Move alerts and SOC action history

Add database-backed repositories for:

- alert reads
- SOC action audit reads

Suggested tables:

- `alerts`
- `soc_actions`

Outcome:

- `/dashboard`, `/network-watcher`, and `/api/alerts` stop depending on
  bundled sample files
- production telemetry becomes durable and queryable

### Phase 3: Move config data if operational teams need in-app updates

Only migrate these if the team needs runtime editing:

- device inventory
- topology/policy config

If they change rarely, it may be better to keep them version-controlled and
deployed from Git.

## Suggested Schema Shape

### `incidents`

Columns aligned with the current payload shape:

- `incident_id`
- `created_at`
- `updated_at`
- `status_changed_at`
- `assigned_at`
- `contained_at`
- `resolved_at`
- `status`
- `queue`
- `severity`
- `threat_type`
- `src_ip`
- `dst_ip`
- `dst_port`
- `description`
- `assignee`
- `owner`
- `notes`
- `metadata_json`

### `unauthorized_device_reviews`

- `ip`
- `status`
- `notes`
- `owner`
- `reviewed_at`
- `updated_at`
- `snapshot_json`

### `alerts`

- `id`
- `timestamp`
- `iso_time`
- `severity`
- `threat_type`
- `src_ip`
- `dst_ip`
- `dst_port`
- `description`
- `metadata_json`
- `incident_ids_json`
- `raw`

### `soc_actions`

- `id`
- `timestamp`
- `action_type`
- `severity`
- `incident_id`
- `src_ip`
- `details_json`

## Application Changes To Make

### Storage Abstraction

Introduce backend-specific repositories behind the existing facades:

- `AlertRepository`
- `IncidentManager` / `IncidentStore`
- `UnauthorizedDeviceManager`
- `JsonlStore` replacements for SOC actions

That lets the API keep most of its route logic while changing only the storage
implementation underneath.

### Config

Add env-driven backend selection in [`network_security_monitor/config.py`](../network_security_monitor/config.py):

```text
NSM_STORAGE_BACKEND=file|postgres
NSM_DATABASE_URL=
```

Optional later:

```text
NSM_ALERT_STORAGE_BACKEND=file|postgres
NSM_INCIDENT_STORAGE_BACKEND=file|postgres
```

### Migration Scripts

Add one-time import scripts that read:

- `incidents.jsonl`
- `alerts.jsonl`
- `unauthorized_devices.jsonl`
- `soc_actions.log` or JSONL equivalent

and insert them into Postgres.

## Recommended Rollout Order

1. Add Postgres repository classes behind the current interfaces.
2. Add migration/import scripts.
3. Run imports from existing local/demo data.
4. Switch Vercel production to Postgres for incidents and unauthorized-device state.
5. Verify PATCH routes work again in production.
6. Move alerts and SOC actions off file storage.
7. Decide whether inventory/topology should stay Git-managed or move to DB tables.

## Vercel-Friendly Service Options

Good fits for this app:

- Neon Postgres
- Supabase Postgres
- any managed Postgres reachable from Vercel

If you want the smoothest Vercel-native onboarding, a Vercel Marketplace
Postgres integration is the simplest place to start.

## What Not To Do

- do not keep production incident writes on `incidents.db` inside the Vercel deployment
- do not rely on repo-local JSONL files for mutable production state
- do not point Vercel env vars at workstation paths

## Suggested Next Implementation Slice

If we implement this next, the highest-value first slice is:

1. add `NSM_STORAGE_BACKEND`
2. add a Postgres-backed `IncidentStore`
3. add a Postgres-backed unauthorized-device review store
4. re-enable write routes only when the backend supports durable writes

That gets the production workflow unstuck before we tackle the lower-risk alert
history migration.
