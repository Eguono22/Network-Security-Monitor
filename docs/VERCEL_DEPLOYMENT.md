# Vercel Deployment Checklist

This repo deploys to Vercel as a Python serverless app through
[`api/index.py`](../api/index.py) and [`vercel.json`](../vercel.json).

For the fastest click-by-click deployment flow, see
[`docs/VERCEL_DEPLOY_NOW.md`](./VERCEL_DEPLOY_NOW.md).
For the post-demo external storage migration plan, see
[`docs/PRODUCTION_PERSISTENCE_PLAN.md`](./PRODUCTION_PERSISTENCE_PLAN.md).

## What This Deployment Supports

- Read-only Flask dashboards and JSON API routes
- Serverless routing for `/`, `/dashboard`, `/network-watcher`, and `/soc-management`
- Incident and asset views backed by committed JSON/JSONL/SQLite files

## Important Limitation

Vercel's serverless filesystem is read-only at runtime for this app's working
files. That means:

- `PATCH /api/incidents/<incident_id>` is disabled on Vercel
- `PATCH /api/devices/unauthorized/<ip>` is disabled on Vercel
- SOC update forms render as read-only on Vercel
- Live packet capture is not supported on Vercel

If you need mutable incidents, unauthorized-device reviews, or live monitoring,
run the app on a VM/container or move persistence to an external database or
storage service.

## Project Settings

Use these Vercel project settings:

- Framework Preset: `Other`
- Root Directory: repo root
- Build Command: leave empty unless your team has a custom build flow
- Output Directory: leave empty
- Install Command: leave default, or set `pip install -r requirements.txt`
- Production Branch: your main deployment branch

## Required Repo Files

These should exist in the deployed branch:

- [`vercel.json`](../vercel.json)
- [`api/index.py`](../api/index.py)
- [`requirements.txt`](../requirements.txt)

## Recommended Environment Variables

### Required for a useful dashboard deployment

- `NSM_API_DEFAULT_ROLE=viewer`
- `NSM_ALERTS_DATA_FILE=deploy/demo/alerts.jsonl`
- `NSM_INCIDENTS_LOG_FILE=deploy/demo/incidents.jsonl`

### Needed when you want richer asset context

- `NSM_DEVICE_INVENTORY_FILE=deploy/demo/devices.json`
- `NSM_UNAUTHORIZED_DEVICES_FILE=deploy/demo/unauthorized_devices.jsonl`
- `NSM_TOPOLOGY_FILE=deploy/demo/topology.json`

### Optional

- `NSM_ALERT_NOTIFY_MIN_SEVERITY=HIGH`
- `NSM_PORT_SCAN_TRUSTED_SOURCES=<comma-separated IPs>`
- `NSM_SERVERLESS_READ_ONLY=true`

`NSM_SERVERLESS_READ_ONLY` is optional because the app automatically detects
Vercel, but setting it explicitly can make behavior clearer across environments.

## Path Guidance

For Vercel, file-backed env vars should point at files that are committed into
the repo and shipped with the deployment.

Good examples:

- `NSM_ALERTS_DATA_FILE=deploy/demo/alerts.jsonl`
- `NSM_INCIDENTS_LOG_FILE=deploy/demo/incidents.jsonl`
- `NSM_DEVICE_INVENTORY_FILE=deploy/demo/devices.json`

The repo now includes a ready-to-use sample bundle in [`deploy/demo`](../deploy/demo/).

Avoid using local machine paths such as `C:\...` or files generated only on
your workstation. Those do not exist inside Vercel deployments.

## Env Vars You Usually Should Not Reuse From Local Runs

These defaults are fine locally but are usually not appropriate for Vercel
unless the target files are committed deployment assets:

- `NSM_SOC_AUTOMATION_LOG_FILE=soc_actions.log`
- `NSM_INCIDENTS_LOG_FILE=incidents.db`
- `NSM_UNAUTHORIZED_DEVICES_FILE=unauthorized_devices.jsonl`
- `NSM_SIEM_OUTPUT_FILE=siem/alerts.jsonl`

On Vercel, use committed read-only assets or external services instead.

## CLI Flow

```bash
vercel link --yes --project <project> --scope <team>
vercel env pull .env.local --yes --environment=production
vercel --prod
```

If your team deploys through CI:

```bash
vercel pull --yes --environment=production --token=$VERCEL_TOKEN
vercel build --prod --token=$VERCEL_TOKEN
vercel deploy --prebuilt --prod --token=$VERCEL_TOKEN
```

## Post-Deploy Checks

Verify these routes after each deployment:

- `/`
- `/health`
- `/dashboard`
- `/network-watcher`
- `/soc-management`
- `/api/alerts`
- `/api/incidents`
- `/api/devices`
- `/api/topology`

Expected behavior on Vercel:

- dashboards load successfully
- incident/device JSON routes return `200`
- write routes return a read-only response instead of crashing

## Troubleshooting

### 404 on `/` or dashboard pages

Check that [`vercel.json`](../vercel.json) is present and deployed. The rewrite
to `/api/index.py` is what makes non-API routes work.

### 500 on incident routes

Check `NSM_INCIDENTS_LOG_FILE`. On Vercel it must reference a bundled file or
an external data source strategy. Do not rely on runtime creation of
`incidents.db`.

### Write actions fail

This is expected on Vercel for the current architecture. The app now returns a
read-only error instead of attempting filesystem writes.

### Deployment works locally but not on Vercel

Compare local `.env` values against Vercel project env vars. Local absolute
paths and locally generated files are the most common mismatch.
