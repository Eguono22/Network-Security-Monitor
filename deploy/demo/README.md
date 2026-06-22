# Demo Data Bundle

These files are safe, committed sample inputs for Vercel deployments.

Recommended Vercel environment variables:

```text
NSM_API_DEFAULT_ROLE=viewer
NSM_SERVERLESS_READ_ONLY=true
NSM_ALERTS_DATA_FILE=deploy/demo/alerts.jsonl
NSM_INCIDENTS_LOG_FILE=deploy/demo/incidents.jsonl
NSM_DEVICE_INVENTORY_FILE=deploy/demo/devices.json
NSM_UNAUTHORIZED_DEVICES_FILE=deploy/demo/unauthorized_devices.jsonl
NSM_TOPOLOGY_FILE=deploy/demo/topology.json
```

This keeps the dashboards and JSON routes populated without relying on runtime
filesystem writes.
