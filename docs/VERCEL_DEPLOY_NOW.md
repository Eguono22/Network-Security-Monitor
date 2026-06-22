# Deploy Now

This is the fastest path to a working Vercel deployment for the current repo.

## Before You Start

Make sure the branch you are deploying includes:

- [`vercel.json`](../vercel.json)
- [`api/index.py`](../api/index.py)
- [`deploy/demo`](../deploy/demo/)

## Vercel UI Steps

1. Push the current branch to GitHub.
2. In Vercel, create a new project or open the existing project.
3. Import the GitHub repository if it is not already linked.
4. Set these project settings:
   - Framework Preset: `Other`
   - Root Directory: repo root
   - Build Command: empty
   - Output Directory: empty
   - Install Command: default, or `pip install -r requirements.txt`
5. Open `Settings` -> `Environment Variables`.
6. Add the variables from [`.env.vercel.example`](../.env.vercel.example) for `Production`.
7. Save the env vars.
8. Trigger a redeploy.

## Production Env Vars

Use this exact block for the first stable deployment:

```text
NSM_API_DEFAULT_ROLE=viewer
NSM_SERVERLESS_READ_ONLY=true
NSM_ALERTS_DATA_FILE=deploy/demo/alerts.jsonl
NSM_INCIDENTS_LOG_FILE=deploy/demo/incidents.jsonl
NSM_DEVICE_INVENTORY_FILE=deploy/demo/devices.json
NSM_UNAUTHORIZED_DEVICES_FILE=deploy/demo/unauthorized_devices.jsonl
NSM_TOPOLOGY_FILE=deploy/demo/topology.json
```

If you also want these values available on preview deployments, add the same set
for `Preview` too.

## First Verification Pass

After the deployment turns `READY`, open these routes:

- `/`
- `/health`
- `/dashboard`
- `/network-watcher`
- `/soc-management`
- `/api/alerts`
- `/api/incidents`
- `/api/devices`
- `/api/topology`

Expected results:

- the dashboard pages render instead of 404ing
- `/health` returns `200`
- JSON API routes return populated demo data
- incident update actions are read-only instead of failing with a server error

## If Something Fails

### Build failed

Open the deployment in Vercel and inspect the build logs first.

Check:

- the repo root is correct
- `vercel.json` is present in the deployed commit
- Python dependencies installed cleanly from [`requirements.txt`](../requirements.txt)

### Dashboard route 404s

This usually means the rewrite in [`vercel.json`](../vercel.json) was not
picked up by the deployed commit.

### Incident routes 500

This usually means one of the file-path env vars is missing or points to a file
that does not exist in the deployment.

### Empty dashboards

Check that these env vars are present exactly as shown above:

- `NSM_ALERTS_DATA_FILE`
- `NSM_INCIDENTS_LOG_FILE`
- `NSM_DEVICE_INVENTORY_FILE`
- `NSM_UNAUTHORIZED_DEVICES_FILE`
- `NSM_TOPOLOGY_FILE`

## CLI Equivalent

If you prefer the CLI once the local Vercel install is healthy:

```bash
vercel link --yes --project <project> --scope <team>
vercel env pull .env.local --yes --environment=production
vercel --prod
```

## What To Do After This Works

Once the demo deployment is healthy, the next step is replacing the bundled
demo files with external persistent storage. The repo-specific plan is in
[`docs/PRODUCTION_PERSISTENCE_PLAN.md`](./PRODUCTION_PERSISTENCE_PLAN.md).
