"""Vercel-compatible API entrypoint with alert dashboard and network watcher."""

from __future__ import annotations

import csv
import html
import json
import os
from collections import Counter
from datetime import datetime, timezone
from io import StringIO
from urllib.parse import urlencode

from flask import Flask, Response, jsonify, redirect, request

from network_security_monitor.incident_manager import (
    ACTIVE_INCIDENT_STATUSES,
    IncidentManager,
    IncidentValidationError,
)
from network_security_monitor.device_inventory import DeviceInventoryService
from network_security_monitor.unauthorized_devices import (
    UnauthorizedDeviceManager,
    UnauthorizedDeviceValidationError,
)
from network_security_monitor.network_topology import NetworkTopologyService
from network_security_monitor.storage import AlertRepository, JsonlStore
from network_security_monitor.threat_intel import ThreatIntelService
from network_security_monitor.config import Config


app = Flask(__name__)

_MAX_RECENT = 100
_VALID_API_ROLES = ("viewer", "analyst", "admin")
_ROLE_RANK = {role: index for index, role in enumerate(_VALID_API_ROLES)}


def _normalize_role(value) -> str:
    role = str(value or "").strip().lower()
    return role if role in _ROLE_RANK else ""


def _current_role() -> str:
    header_value = request.headers.get("X-NSM-Role", "")
    role = _normalize_role(header_value)
    if header_value and not role:
        return ""
    default_role = _normalize_role(Config().API_DEFAULT_ROLE)
    return role or default_role or "admin"


def _role_allowed(current_role: str, minimum_role: str) -> bool:
    current = _normalize_role(current_role)
    minimum = _normalize_role(minimum_role)
    if not current or not minimum:
        return False
    return _ROLE_RANK[current] >= _ROLE_RANK[minimum]


def _json_role_error(required_role: str, current_role: str, *, error: str) -> Response:
    message = (
        f"role '{current_role or 'unknown'}' does not satisfy required role '{required_role}'"
        if error == "insufficient_role"
        else f"role must be one of: {', '.join(_VALID_API_ROLES)}"
    )
    return (
        jsonify(
            {
                "error": error,
                "required_role": required_role,
                "current_role": current_role or "unknown",
                "allowed_roles": list(_VALID_API_ROLES),
                "message": message,
            }
        ),
        403,
    )


def _page_role_error(required_role: str, current_role: str) -> Response:
    body = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Access Denied</title>
  <style>
    body {{ margin: 0; font-family: "Segoe UI", sans-serif; background: #0f172a; color: #e2e8f0; }}
    main {{ max-width: 680px; margin: 64px auto; padding: 0 20px; }}
    .card {{ background: #111827; border: 1px solid #334155; border-radius: 16px; padding: 24px; }}
    h1 {{ margin-top: 0; }}
    p {{ color: #cbd5e1; line-height: 1.5; }}
    code {{ background: #1e293b; padding: 2px 6px; border-radius: 6px; }}
  </style>
</head>
<body>
  <main>
    <section class="card">
      <h1>Access denied</h1>
      <p>This SOC action requires the <code>{html.escape(required_role)}</code> role.</p>
      <p>Current role: <code>{html.escape(current_role or 'unknown')}</code></p>
    </section>
  </main>
</body>
</html>"""
    return Response(body, status=403, mimetype="text/html")


def _require_role(minimum_role: str, *, page: bool = False):
    current_role = _current_role()
    if not current_role:
        if page:
            return None, _page_role_error(minimum_role, current_role)
        return None, _json_role_error(minimum_role, current_role, error="invalid_role")
    if not _role_allowed(current_role, minimum_role):
        if page:
            return current_role, _page_role_error(minimum_role, current_role)
        return current_role, _json_role_error(minimum_role, current_role, error="insufficient_role")
    return current_role, None


def _load_recent_alerts(limit: int = _MAX_RECENT) -> list[dict]:
    repository = AlertRepository(
        structured_path=os.getenv("NSM_ALERTS_DATA_FILE", "").strip(),
        log_path=os.getenv("NSM_ALERT_LOG_FILE", "alerts.log"),
    )
    return repository.read_recent(limit)


def _load_soc_actions(limit: int = _MAX_RECENT) -> list[dict]:
    store = JsonlStore(os.getenv("NSM_SOC_AUTOMATION_LOG_FILE", "soc_actions.log"))
    return store.read_recent(limit)


def _load_incidents(limit: int = _MAX_RECENT) -> list[dict]:
    manager = IncidentManager(os.getenv("NSM_INCIDENTS_LOG_FILE", "incidents.db"))
    return manager.list_cases(limit=limit)


def _incident_manager() -> IncidentManager:
    return IncidentManager(os.getenv("NSM_INCIDENTS_LOG_FILE", "incidents.db"))


def _inventory_service() -> DeviceInventoryService:
    inventory_path = os.getenv("NSM_DEVICE_INVENTORY_FILE", "").strip()
    if not inventory_path:
        inventory_path = Config().DEVICE_INVENTORY_FILE
    return DeviceInventoryService(inventory_path)


def _unauthorized_device_manager() -> UnauthorizedDeviceManager:
    path = os.getenv("NSM_UNAUTHORIZED_DEVICES_FILE", "").strip()
    if not path:
        path = Config().UNAUTHORIZED_DEVICES_FILE
    return UnauthorizedDeviceManager(path)


def _topology_service() -> NetworkTopologyService:
    path = os.getenv("NSM_TOPOLOGY_FILE", "").strip()
    if not path:
        path = Config().TOPOLOGY_FILE
    return NetworkTopologyService(path)


def _incident_filter_args() -> dict[str, str]:
    return {
        "status": request.args.get("status", "").strip(),
        "severity": request.args.get("severity", "").strip(),
        "queue": request.args.get("queue", "").strip(),
        "threat_type": request.args.get("threat_type", "").strip(),
        "src_ip": request.args.get("src_ip", "").strip(),
        "assignee": request.args.get("assignee", "").strip(),
        "owner": request.args.get("owner", "").strip(),
    }


def _build_query(params: dict[str, str]) -> str:
    filtered = {key: value for key, value in params.items() if value not in ("", None)}
    return urlencode(filtered)


def _list_filtered_incidents(limit: int) -> list[dict]:
    manager = _incident_manager()
    return manager.list_cases(
        limit=limit,
        status=request.args.get("status", ""),
        severity=request.args.get("severity", ""),
        queue=request.args.get("queue", ""),
        threat_type=request.args.get("threat_type", ""),
        src_ip=request.args.get("src_ip", ""),
        assignee=request.args.get("assignee", ""),
        owner=request.args.get("owner", ""),
    )


def _incident_csv_response(incidents: list[dict]) -> Response:
    fields = [
        "incident_id",
        "created_at",
        "updated_at",
        "status_changed_at",
        "assigned_at",
        "contained_at",
        "resolved_at",
        "status",
        "queue",
        "severity",
        "threat_type",
        "src_ip",
        "dst_ip",
        "dst_port",
        "description",
        "assignee",
        "owner",
        "notes",
        "metadata",
    ]
    buffer = StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for incident in incidents:
        row = dict(incident)
        row["metadata"] = json.dumps(row.get("metadata") or {}, sort_keys=True)
        writer.writerow(row)

    filename = f"incidents-export-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.csv"
    return Response(
        buffer.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _load_devices(limit: int = _MAX_RECENT, *, risk_level: str = "", query: str = "") -> list[dict]:
    return _inventory_service().list_devices(
        alerts=_load_recent_alerts(limit=1000),
        incidents=_load_incidents(limit=1000),
        limit=limit,
        risk_level=risk_level,
        query=query,
    )


def _load_unauthorized_devices(limit: int = _MAX_RECENT, *, status: str = "", query: str = "") -> list[dict]:
    return _unauthorized_device_manager().list_findings(
        inventory=_inventory_service(),
        alerts=_load_recent_alerts(limit=1000),
        incidents=_load_incidents(limit=1000),
        limit=limit,
        status=status,
        query=query,
    )


def _load_topology(limit: int = _MAX_RECENT) -> dict:
    devices = _load_devices(limit=1000)
    incidents = _load_incidents(limit=1000)
    alerts = _load_recent_alerts(limit=1000)
    return _topology_service().summarize(
        devices=devices,
        alerts=alerts,
        incidents=incidents,
        limit=limit,
    )


def _isoish_to_display(value) -> str:
    if not value:
        return "n/a"
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (TypeError, ValueError, OSError):
        return html.escape(str(value))


def _render_incident_detail_list(items: dict) -> str:
    if not items:
        return "<li>No metadata</li>"
    return "".join(
        f"<li><strong>{html.escape(str(key))}</strong>: {html.escape(str(value))}</li>"
        for key, value in sorted(items.items())
    )


def _render_asset_summary(asset: dict | None) -> str:
    if not asset:
        return "<p class='asset-empty'>No asset context found for this source IP yet.</p>"
    open_ports = ", ".join(str(port) for port in asset.get("open_ports", [])) or "none"
    threat_types = ", ".join(asset.get("threat_types", [])) or "none"
    tags = ", ".join(asset.get("tags", [])) or "none"
    return (
        "<div class='asset-grid'>"
        f"<div><span>IP</span><strong>{html.escape(str(asset.get('ip', 'n/a')))}</strong></div>"
        f"<div><span>Hostname</span><strong>{html.escape(str(asset.get('hostname', '') or 'unknown'))}</strong></div>"
        f"<div><span>Vendor</span><strong>{html.escape(str(asset.get('vendor', '') or 'unknown'))}</strong></div>"
        f"<div><span>OS</span><strong>{html.escape(str(asset.get('os', '') or 'unknown'))}</strong></div>"
        f"<div><span>Risk</span><strong>{html.escape(str(asset.get('risk_level', 'low')))} ({int(asset.get('risk_score', 0))})</strong></div>"
        f"<div><span>Last Seen</span><strong>{html.escape(str(asset.get('last_seen', '') or 'n/a'))}</strong></div>"
        "</div>"
        "<ul class='asset-list'>"
        f"<li><strong>Open ports</strong>: {html.escape(open_ports)}</li>"
        f"<li><strong>Threats</strong>: {html.escape(threat_types)}</li>"
        f"<li><strong>Tags</strong>: {html.escape(tags)}</li>"
        f"<li><strong>Incidents</strong>: {int(asset.get('incident_count', 0))} | <strong>Alerts</strong>: {int(asset.get('alert_count', 0))}</li>"
        "</ul>"
    )


def _render_unauthorized_summary(finding: dict | None) -> str:
    if not finding:
        return "<p class='asset-empty'>This asset is currently not tracked as unauthorized.</p>"
    return (
        "<ul class='asset-list'>"
        f"<li><strong>Status</strong>: {html.escape(str(finding.get('status', 'new')))}</li>"
        f"<li><strong>Observation</strong>: {html.escape(str(finding.get('observation_status', 'observed')))}</li>"
        f"<li><strong>Owner</strong>: {html.escape(str(finding.get('owner', '') or 'unassigned'))}</li>"
        f"<li><strong>Queue</strong>: {html.escape(str(finding.get('queue', 'asset-security')))}</li>"
        f"<li><strong>Notes</strong>: {html.escape(str(finding.get('notes', '') or 'none'))}</li>"
        "</ul>"
    )


def _render_zone_summary(zone_context: dict | None) -> str:
    if not zone_context:
        return "<p class='asset-empty'>No zone context available for this incident yet.</p>"
    return (
        "<ul class='asset-list'>"
        f"<li><strong>Source zone</strong>: {html.escape(str(zone_context.get('src_zone', '') or 'unknown'))}</li>"
        f"<li><strong>Destination zone</strong>: {html.escape(str(zone_context.get('dst_zone', '') or 'unknown'))}</li>"
        f"<li><strong>Path status</strong>: {html.escape(str(zone_context.get('path_status', '') or 'unknown'))}</li>"
        f"<li><strong>Policy</strong>: {html.escape(str(zone_context.get('policy_name', '') or 'none'))}</li>"
        "</ul>"
    )


def _selected_value(current: str, option: str) -> str:
    return " selected" if current == option else ""


def _duration_to_display(value) -> str:
    if value in (None, ""):
        return "n/a"
    try:
        seconds = max(0, int(float(value)))
    except (TypeError, ValueError):
        return html.escape(str(value))
    if seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    hours = seconds / 3600
    return f"{hours:.1f}h"


def _trend_summary(trend: list[dict]) -> str:
    if not trend:
        return "n/a"
    return " | ".join(f"{item['date'][5:]}:{item['count']}" for item in trend)


def _network_watcher_summary() -> dict:
    alerts = _load_recent_alerts()
    actions = _load_soc_actions()
    by_severity = Counter(a["severity"] for a in alerts)
    by_threat = Counter(a["threat_type"] for a in alerts)
    by_src = Counter(a["src_ip"] for a in alerts)

    top_src = "none"
    if by_src:
        src, count = by_src.most_common(1)[0]
        top_src = f"{src} ({count})"

    now = datetime.now(timezone.utc).isoformat()
    health = "stable"
    if by_severity.get("CRITICAL", 0) > 0:
        health = "critical-events-present"
    elif by_severity.get("HIGH", 0) >= 5:
        health = "high-alert-volume"

    return {
        "timestamp_utc": now,
        "health": health,
        "recent_alerts": len(alerts),
        "recent_soc_actions": len(actions),
        "top_source": top_src,
        "alerts_by_severity": dict(by_severity),
        "alerts_by_threat": dict(by_threat),
    }


def _soc_management_snapshot() -> dict:
    alerts = _load_recent_alerts()
    actions = _load_soc_actions()
    manager = _incident_manager()
    inventory = _inventory_service()
    unauthorized_manager = _unauthorized_device_manager()
    incidents = manager.list_cases(limit=1000)
    metrics = manager.compute_metrics(limit=1000)
    topology = _topology_service().summarize(
        devices=inventory.list_devices(alerts=alerts, incidents=incidents, limit=1000),
        alerts=alerts,
        incidents=incidents,
        limit=1000,
    )
    unauthorized_devices = unauthorized_manager.list_findings(
        inventory=inventory,
        alerts=alerts,
        incidents=incidents,
        limit=1000,
    )
    open_incidents = sum(1 for i in incidents if i.get("status") == "open")
    active_incidents = sum(
        1 for i in incidents if str(i.get("status", "open")).lower() in ACTIVE_INCIDENT_STATUSES
    )
    critical_incidents = sum(1 for i in incidents if i.get("severity") == "CRITICAL")
    if not incidents:
        open_incidents = sum(1 for a in alerts if a["severity"] in {"HIGH", "CRITICAL"})
        active_incidents = open_incidents
        critical_incidents = sum(1 for a in alerts if a["severity"] == "CRITICAL")
    threat_queue = Counter(a["threat_type"] for a in alerts).most_common(6)
    analyst_queue = Counter(
        a.get("action", {}).get("queue", "soc-triage")
        for a in actions
        if isinstance(a, dict)
    ).most_common(6)
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "open_incidents": open_incidents,
        "active_incidents": active_incidents,
        "critical_incidents": critical_incidents,
        "automation_actions": len(actions),
        "recent_alerts": len(alerts),
        "recent_incidents": len(incidents),
        "unauthorized_devices": len(unauthorized_devices),
        "unauthorized_active": sum(
            1
            for finding in unauthorized_devices
            if str(finding.get("observation_status", "")).lower() == "observed"
            and str(finding.get("status", "")).lower() != "approved"
        ),
        "topology_violations": len(topology.get("violations", [])),
        "topology_zones": len(topology.get("zones", [])),
        "threat_queue": threat_queue,
        "analyst_queue": analyst_queue,
        "metrics": metrics,
    }


@app.get("/")
def root():
    html = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Network Security Monitoring System (NSMS)</title>
  <style>
    :root {
      --bg-1: #f4f8ff;
      --bg-2: #dbeafe;
      --card: #ffffff;
      --text: #0f172a;
      --muted: #334155;
      --accent: #0b7285;
      --accent-2: #0f766e;
      --border: #cbd5e1;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: "Fira Sans", "Trebuchet MS", "Segoe UI", sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle at 15% 20%, rgba(11, 114, 133, 0.14), transparent 34%),
        radial-gradient(circle at 85% 75%, rgba(15, 118, 110, 0.14), transparent 36%),
        linear-gradient(145deg, var(--bg-1), var(--bg-2));
      display: grid;
      place-items: center;
      padding: 24px;
    }
    .panel {
      width: min(760px, 100%);
      background: color-mix(in srgb, var(--card) 88%, #ffffff);
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 28px;
      box-shadow: 0 14px 40px rgba(15, 23, 42, 0.12);
    }
    h1 {
      margin: 0 0 8px;
      font-size: clamp(1.7rem, 4vw, 2.4rem);
      letter-spacing: 0.01em;
    }
    p {
      margin: 0 0 18px;
      color: var(--muted);
      line-height: 1.5;
    }
    .badge {
      display: inline-block;
      padding: 7px 11px;
      border-radius: 999px;
      background: rgba(11, 114, 133, 0.1);
      color: var(--accent);
      border: 1px solid rgba(11, 114, 133, 0.25);
      font-weight: 600;
      margin-bottom: 14px;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 12px;
      margin-top: 14px;
    }
    .item {
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 12px;
      background: rgba(255, 255, 255, 0.7);
    }
    .item strong { color: var(--accent-2); }
    code {
      background: #e2e8f0;
      padding: 2px 6px;
      border-radius: 6px;
    }
  </style>
</head>
<body>
  <main class="panel">
    <span class="badge">Serverless API Active</span>
    <h1>Network Security Monitoring System (NSMS)</h1>
    <p>
      This Vercel deployment provides lightweight API endpoints for status and
      integration checks. Live packet capture is not available in serverless runtime.
    </p>
    <div class="grid">
      <section class="item">
        <strong>Health Check</strong>
        <p>Use <code>/health</code> for uptime probes and platform monitoring.</p>
      </section>
      <section class="item">
        <strong>Alert Dashboard</strong>
        <p>Browse recent alerts at <code>/dashboard</code>.</p>
      </section>
      <section class="item">
        <strong>Network Watcher</strong>
        <p>View summary at <code>/network-watcher</code> or JSON at <code>/api/network-watcher</code>.</p>
      </section>
      <section class="item">
        <strong>SOC Management</strong>
        <p>Use <code>/soc-management</code> for KPI and incident queue operations.</p>
      </section>
      <section class="item">
        <strong>Incident API</strong>
        <p>Query incident cases at <code>/api/incidents</code> or export CSV at <code>/api/incidents/export.csv</code>.</p>
      </section>
      <section class="item">
        <strong>Threat Intel</strong>
        <p>Enrich an indicator at <code>/api/threat-intel?indicator=1.2.3.4</code>.</p>
      </section>
      <section class="item">
        <strong>Device Inventory</strong>
        <p>Inspect asset context at <code>/api/devices</code>.</p>
      </section>
      <section class="item">
        <strong>Unauthorized Devices</strong>
        <p>Review unmanaged observed assets at <code>/api/devices/unauthorized</code>.</p>
      </section>
      <section class="item">
        <strong>Topology</strong>
        <p>Inspect zones and observed cross-zone paths at <code>/api/topology</code>.</p>
      </section>
    </div>
  </main>
</body>
</html>
"""
    return Response(html, mimetype="text/html")


@app.get("/health")
def health():
    return jsonify({"ok": True})


@app.get("/api/alerts")
def api_alerts():
    return jsonify(
        {
            "count": len(_load_recent_alerts()),
            "alerts": _load_recent_alerts(),
        }
    )


@app.get("/api/network-watcher")
def api_network_watcher():
    return jsonify(_network_watcher_summary())


@app.get("/api/topology")
def api_topology():
    _, denial = _require_role("viewer")
    if denial is not None:
        return denial
    limit = _request_limit()
    return jsonify(_load_topology(limit=limit))


@app.get("/api/topology/violations")
def api_topology_violations():
    _, denial = _require_role("viewer")
    if denial is not None:
        return denial
    limit = _request_limit()
    topology = _load_topology(limit=limit)
    return jsonify({"count": len(topology.get("violations", [])), "violations": topology.get("violations", [])})


@app.get("/api/soc-summary")
def api_soc_summary():
    _, denial = _require_role("viewer")
    if denial is not None:
        return denial
    return jsonify(_soc_management_snapshot())


@app.get("/api/threat-intel")
def api_threat_intel():
    indicator = request.args.get("indicator", "").strip()
    if not indicator:
        return jsonify({"error": "missing_indicator", "message": "indicator query parameter is required"}), 400

    config = Config()
    service = ThreatIntelService(config.KNOWN_MALICIOUS_IPS)
    payload = service.lookup(
        indicator,
        indicator_type=request.args.get("type", ""),
        alerts=_load_recent_alerts(limit=200),
        incidents=_load_incidents(limit=200),
    )
    return jsonify(payload)


@app.get("/api/incidents")
def api_incidents():
    _, denial = _require_role("viewer")
    if denial is not None:
        return denial
    limit = _request_limit()
    try:
        incidents = _list_filtered_incidents(limit)
    except IncidentValidationError as exc:
        return jsonify({"error": "invalid_incident_filter", "message": str(exc)}), 400
    return jsonify({"count": len(incidents), "incidents": incidents})


@app.get("/api/incidents/export.csv")
def api_incidents_export_csv():
    _, denial = _require_role("analyst")
    if denial is not None:
        return denial
    limit = _request_limit(default=500)
    try:
        incidents = _list_filtered_incidents(limit)
    except IncidentValidationError as exc:
        return jsonify({"error": "invalid_incident_filter", "message": str(exc)}), 400
    return _incident_csv_response(incidents)


@app.get("/api/incidents/<incident_id>")
def api_incident_detail(incident_id: str):
    _, denial = _require_role("viewer")
    if denial is not None:
        return denial
    manager = _incident_manager()
    incident = manager.get_case(incident_id)
    if incident is None:
        return jsonify({"error": "incident_not_found", "incident_id": incident_id}), 404
    devices = _load_devices(limit=1000)
    enriched = _inventory_service().enrich_incident(
        incident,
        alerts=_load_recent_alerts(limit=1000),
        incidents=_load_incidents(limit=1000),
    )
    enriched["unauthorized_device"] = _unauthorized_device_manager().get_finding(
        str(incident.get("src_ip", "")).strip(),
        inventory=_inventory_service(),
        alerts=_load_recent_alerts(limit=1000),
        incidents=_load_incidents(limit=1000),
    )
    enriched = _topology_service().enrich_incident(enriched, devices=devices)
    return jsonify(enriched)


@app.get("/api/devices")
def api_devices():
    _, denial = _require_role("viewer")
    if denial is not None:
        return denial
    limit = _request_limit()
    devices = _load_devices(
        limit=limit,
        risk_level=request.args.get("risk_level", ""),
        query=request.args.get("q", ""),
    )
    return jsonify({"count": len(devices), "devices": devices})


@app.get("/api/devices/unauthorized")
def api_unauthorized_devices():
    _, denial = _require_role("viewer")
    if denial is not None:
        return denial
    limit = _request_limit()
    findings = _load_unauthorized_devices(
        limit=limit,
        status=request.args.get("status", ""),
        query=request.args.get("q", ""),
    )
    return jsonify({"count": len(findings), "devices": findings})


@app.get("/api/devices/unauthorized/<ip>")
def api_unauthorized_device_detail(ip: str):
    _, denial = _require_role("viewer")
    if denial is not None:
        return denial
    finding = _unauthorized_device_manager().get_finding(
        ip,
        inventory=_inventory_service(),
        alerts=_load_recent_alerts(limit=1000),
        incidents=_load_incidents(limit=1000),
    )
    if finding is None:
        return jsonify({"error": "unauthorized_device_not_found", "ip": ip}), 404
    return jsonify(finding)


@app.patch("/api/devices/unauthorized/<ip>")
def api_unauthorized_device_update(ip: str):
    _, denial = _require_role("analyst")
    if denial is not None:
        return denial
    payload = request.get_json(silent=True) or {}
    allowed = {"status", "notes", "owner"}
    changes = {key: value for key, value in payload.items() if key in allowed}
    try:
        finding = _unauthorized_device_manager().update_finding(
            ip,
            inventory=_inventory_service(),
            alerts=_load_recent_alerts(limit=1000),
            incidents=_load_incidents(limit=1000),
            status=changes.get("status"),
            notes=changes.get("notes"),
            owner=changes.get("owner"),
        )
    except UnauthorizedDeviceValidationError as exc:
        return jsonify({"error": "invalid_unauthorized_device_update", "message": str(exc)}), 400
    if finding is None:
        return jsonify({"error": "unauthorized_device_not_found", "ip": ip}), 404
    return jsonify(finding)


@app.get("/api/devices/<ip>")
def api_device_detail(ip: str):
    _, denial = _require_role("viewer")
    if denial is not None:
        return denial
    device = _inventory_service().get_device(
        ip,
        alerts=_load_recent_alerts(limit=1000),
        incidents=_load_incidents(limit=1000),
    )
    if device is None:
        return jsonify({"error": "device_not_found", "ip": ip}), 404
    return jsonify(device)


@app.patch("/api/incidents/<incident_id>")
def api_incident_update(incident_id: str):
    _, denial = _require_role("analyst")
    if denial is not None:
        return denial
    manager = _incident_manager()
    payload = request.get_json(silent=True) or {}
    allowed = {
        "status",
        "queue",
        "assignee",
        "owner",
        "notes",
        "metadata",
    }
    changes = {key: value for key, value in payload.items() if key in allowed}
    try:
        updated = manager.update_case(incident_id, **changes)
    except IncidentValidationError as exc:
        return jsonify({"error": "invalid_incident_update", "message": str(exc)}), 400
    if updated is None:
        return jsonify({"error": "incident_not_found", "incident_id": incident_id}), 404
    return jsonify(updated)


@app.post("/soc-management/incidents/<incident_id>/update")
def soc_management_incident_update(incident_id: str):
    current_role = _current_role()
    manager = _incident_manager()
    filters = {
        "status": request.form.get("filter_status", "").strip(),
        "severity": request.form.get("filter_severity", "").strip(),
        "queue": request.form.get("filter_queue", "").strip(),
        "threat_type": request.form.get("filter_threat_type", "").strip(),
        "src_ip": request.form.get("filter_src_ip", "").strip(),
        "assignee": request.form.get("filter_assignee", "").strip(),
        "owner": request.form.get("filter_owner", "").strip(),
    }
    selected_id = request.form.get("incident_id", incident_id).strip() or incident_id
    if not current_role or not _role_allowed(current_role, "analyst"):
        query = _build_query(
            {
                **filters,
                "incident_id": selected_id,
                "error": f"role '{current_role or 'unknown'}' cannot update incidents",
            }
        )
        location = "/soc-management"
        if query:
            location = f"{location}?{query}"
        return redirect(location, code=303)
    allowed = ("status", "queue", "assignee", "owner", "notes")
    changes = {key: request.form.get(key, "").strip() for key in allowed if request.form.get(key) is not None}
    changes = {key: value for key, value in changes.items() if value}

    message = ""
    error = ""
    try:
        updated = manager.update_case(incident_id, **changes)
    except IncidentValidationError as exc:
        updated = None
        error = str(exc)
    if updated is None and not error:
        error = f"incident not found: {incident_id}"
    if updated is not None:
        selected_id = updated["incident_id"]
        message = f"updated {updated['incident_id']}"

    query = _build_query(
        {
            **filters,
            "incident_id": selected_id,
            "message": message,
            "error": error,
        }
    )
    location = "/soc-management"
    if query:
        location = f"{location}?{query}"
    return redirect(location, code=303)


def _request_limit(default: int = _MAX_RECENT) -> int:
    raw = request.args.get("limit", str(default))
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return max(1, min(value, 500))


@app.get("/dashboard")
def dashboard():
    alerts = _load_recent_alerts()
    rows = []
    for alert in reversed(alerts[-50:]):
        sev = html.escape(alert["severity"])
        threat = html.escape(alert["threat_type"])
        src = html.escape(alert["src_ip"])
        ts = html.escape(alert["timestamp"])
        raw = html.escape(alert["raw"])
        rows.append(
            "<tr>"
            f"<td>{ts}</td>"
            f"<td><strong>{sev}</strong></td>"
            f"<td>{threat}</td>"
            f"<td>{src}</td>"
            f"<td><code>{raw}</code></td>"
            "</tr>"
        )
    if not rows:
        rows.append(
            "<tr><td colspan='5'>No alerts found yet. Run monitor and generate alerts first.</td></tr>"
        )

    page = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>NSM Alert Dashboard</title>
  <style>
    body {{ margin: 0; font-family: "Segoe UI", sans-serif; background: #f8fafc; color: #0f172a; }}
    main {{ max-width: 1200px; margin: 24px auto; padding: 0 16px; }}
    h1 {{ margin: 0 0 8px; }}
    p {{ color: #334155; }}
    .card {{ background: #fff; border: 1px solid #dbe4ee; border-radius: 12px; overflow: auto; }}
    table {{ width: 100%; border-collapse: collapse; min-width: 900px; }}
    th, td {{ padding: 10px; border-bottom: 1px solid #e2e8f0; text-align: left; vertical-align: top; }}
    th {{ background: #f1f5f9; }}
    code {{ white-space: pre-wrap; word-break: break-word; }}
    .links a {{ margin-right: 12px; }}
  </style>
</head>
<body>
  <main>
    <h1>Alert Dashboard</h1>
    <p>Recent alerts from <code>alerts.log</code>. Showing latest {len(alerts)} parsed records.</p>
    <p class="links"><a href="/api/alerts">JSON API</a><a href="/network-watcher">Network Watcher</a><a href="/">Home</a></p>
    <div class="card">
      <table>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Severity</th>
            <th>Threat</th>
            <th>Source</th>
            <th>Raw</th>
          </tr>
        </thead>
        <tbody>
          {''.join(rows)}
        </tbody>
      </table>
    </div>
  </main>
</body>
</html>"""
    return Response(page, mimetype="text/html")


@app.get("/network-watcher")
def network_watcher():
    summary = _network_watcher_summary()
    by_sev = summary["alerts_by_severity"]
    by_threat = summary["alerts_by_threat"]
    sev_lines = "".join(
        f"<li>{html.escape(str(k))}: <strong>{v}</strong></li>"
        for k, v in sorted(by_sev.items())
    ) or "<li>No alert data</li>"
    threat_lines = "".join(
        f"<li>{html.escape(str(k))}: <strong>{v}</strong></li>"
        for k, v in sorted(by_threat.items())
    ) or "<li>No threat data</li>"

    page = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>NSM Network Watcher</title>
  <style>
    body {{ margin: 0; font-family: "Segoe UI", sans-serif; background: #f8fafc; color: #0f172a; }}
    main {{ max-width: 980px; margin: 24px auto; padding: 0 16px; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; }}
    .card {{ background: #fff; border: 1px solid #dbe4ee; border-radius: 12px; padding: 14px; }}
    h1 {{ margin: 0 0 8px; }}
    h2 {{ margin: 0 0 8px; font-size: 1.05rem; }}
    p {{ margin: 6px 0; color: #334155; }}
    ul {{ margin: 0; padding-left: 18px; }}
  </style>
</head>
<body>
  <main>
    <h1>Network Watcher</h1>
    <p>Health: <strong>{html.escape(str(summary['health']))}</strong> | Updated: {html.escape(str(summary['timestamp_utc']))}</p>
    <div class="grid">
      <section class="card">
        <h2>Recent Totals</h2>
        <p>Alerts: <strong>{summary['recent_alerts']}</strong></p>
        <p>SOC Actions: <strong>{summary['recent_soc_actions']}</strong></p>
        <p>Top Source: <strong>{html.escape(str(summary['top_source']))}</strong></p>
      </section>
      <section class="card">
        <h2>By Severity</h2>
        <ul>{sev_lines}</ul>
      </section>
      <section class="card">
        <h2>By Threat</h2>
        <ul>{threat_lines}</ul>
      </section>
    </div>
    <p><a href="/api/network-watcher">JSON API</a> | <a href="/dashboard">Alert Dashboard</a> | <a href="/">Home</a></p>
  </main>
</body>
</html>"""
    return Response(page, mimetype="text/html")


@app.get("/soc-management")
def soc_management():
    current_role, denial = _require_role("viewer", page=True)
    if denial is not None:
        return denial
    snap = _soc_management_snapshot()
    manager = _incident_manager()
    inventory = _inventory_service()
    unauthorized_manager = _unauthorized_device_manager()
    metrics = snap.get("metrics", {})
    mttr = metrics.get("mttr", {})
    sla = metrics.get("sla", {})
    trends = metrics.get("trends", {})
    filters = _incident_filter_args()
    selected_id = request.args.get("incident_id", "").strip()
    message = request.args.get("message", "").strip()
    error = request.args.get("error", "").strip()
    incidents = manager.list_cases(limit=100, **filters)
    unauthorized_findings = unauthorized_manager.list_findings(
        inventory=inventory,
        alerts=_load_recent_alerts(limit=1000),
        incidents=_load_incidents(limit=1000),
        limit=10,
    )
    topology = _load_topology(limit=10)
    selected_incident = manager.get_case(selected_id) if selected_id else None
    if selected_incident is None and incidents:
        selected_incident = incidents[-1]
        selected_id = str(selected_incident.get("incident_id", ""))

    threat_items = "".join(
        f"<tr><td>{html.escape(str(name))}</td><td>{count}</td></tr>"
        for name, count in snap["threat_queue"]
    ) or "<tr><td colspan='2'>No queue data</td></tr>"
    analyst_items = "".join(
        f"<tr><td>{html.escape(str(name))}</td><td>{count}</td></tr>"
        for name, count in snap["analyst_queue"]
    ) or "<tr><td colspan='2'>No automation queue data</td></tr>"
    incident_items = "".join(
        "<tr>"
        f"<td><a href=\"/soc-management?{_build_query({**filters, 'incident_id': str(i.get('incident_id', ''))})}\">{html.escape(str(i.get('incident_id', 'n/a')))}</a></td>"
        f"<td>{html.escape(str(i.get('severity', 'UNKNOWN')))}</td>"
        f"<td>{html.escape(str(i.get('status', 'open')))}</td>"
        f"<td>{html.escape(str(i.get('queue', 'soc-triage')))}</td>"
        f"<td>{html.escape(str(i.get('assignee', 'unassigned') or 'unassigned'))}</td>"
        f"<td>{html.escape(str(i.get('src_ip', 'n/a')))}</td>"
        f"<td>{html.escape(str(i.get('threat_type', 'UNKNOWN')))}</td>"
        "</tr>"
        for i in reversed(incidents[-15:])
    ) or "<tr><td colspan='7'>No incidents matched the current filters.</td></tr>"
    active_filter_count = sum(1 for value in filters.values() if value)
    filter_query = _build_query(filters)
    can_export = _role_allowed(current_role, "analyst")
    can_update = _role_allowed(current_role, "analyst")
    unauthorized_rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(item.get('ip', 'n/a')))}</td>"
        f"<td>{html.escape(str(item.get('status', 'new')))}</td>"
        f"<td>{html.escape(str(item.get('observation_status', 'observed')))}</td>"
        f"<td>{html.escape(str(item.get('risk_level', 'low')))} ({int(item.get('risk_score', 0))})</td>"
        f"<td>{html.escape(str(item.get('owner', '') or 'unassigned'))}</td>"
        "</tr>"
        for item in unauthorized_findings
    ) or "<tr><td colspan='5'>No unauthorized devices tracked yet.</td></tr>"
    topology_rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(item.get('src_zone', 'unknown')))}</td>"
        f"<td>{html.escape(str(item.get('dst_zone', 'unknown')))}</td>"
        f"<td>{html.escape(str(item.get('status', 'unknown')))}</td>"
        f"<td>{int(item.get('observation_count', 0))}</td>"
        f"<td>{html.escape(', '.join(item.get('sample_threats', [])) or 'none')}</td>"
        "</tr>"
        for item in topology.get("violations", [])
    ) or "<tr><td colspan='5'>No cross-zone violations observed yet.</td></tr>"

    incident_detail = ""
    if selected_incident is not None:
        metadata_items = _render_incident_detail_list(selected_incident.get("metadata") or {})
        notes = html.escape(str(selected_incident.get("notes", "") or ""))
        source_asset = inventory.get_device(
            str(selected_incident.get("src_ip", "")).strip(),
            alerts=_load_recent_alerts(limit=1000),
            incidents=_load_incidents(limit=1000),
        )
        asset_summary = _render_asset_summary(source_asset)
        unauthorized_finding = unauthorized_manager.get_finding(
            str(selected_incident.get("src_ip", "")).strip(),
            inventory=inventory,
            alerts=_load_recent_alerts(limit=1000),
            incidents=_load_incidents(limit=1000),
        )
        unauthorized_summary = _render_unauthorized_summary(unauthorized_finding)
        zone_context = _topology_service().enrich_incident(
            dict(selected_incident),
            devices=_load_devices(limit=1000),
        ).get("zone_context", {})
        zone_summary = _render_zone_summary(zone_context)
        update_section = ""
        if can_update:
            update_section = f"""
        <form method="post" action="/soc-management/incidents/{html.escape(str(selected_incident.get('incident_id', '')))}/update" class="update-form">
          <input type="hidden" name="incident_id" value="{html.escape(str(selected_incident.get('incident_id', '')))}" />
          <input type="hidden" name="filter_status" value="{html.escape(filters['status'])}" />
          <input type="hidden" name="filter_severity" value="{html.escape(filters['severity'])}" />
          <input type="hidden" name="filter_queue" value="{html.escape(filters['queue'])}" />
          <input type="hidden" name="filter_threat_type" value="{html.escape(filters['threat_type'])}" />
          <input type="hidden" name="filter_src_ip" value="{html.escape(filters['src_ip'])}" />
          <input type="hidden" name="filter_assignee" value="{html.escape(filters['assignee'])}" />
          <input type="hidden" name="filter_owner" value="{html.escape(filters['owner'])}" />
          <div class="section-title">Update Incident</div>
          <div class="form-grid">
            <label>Status
              <select name="status">
                <option value="">No change</option>
                <option value="open"{_selected_value(str(selected_incident.get('status', 'open')), 'open')}>open</option>
                <option value="assigned"{_selected_value(str(selected_incident.get('status', 'open')), 'assigned')}>assigned</option>
                <option value="contained"{_selected_value(str(selected_incident.get('status', 'open')), 'contained')}>contained</option>
                <option value="resolved"{_selected_value(str(selected_incident.get('status', 'open')), 'resolved')}>resolved</option>
              </select>
            </label>
            <label>Queue
              <input type="text" name="queue" value="{html.escape(str(selected_incident.get('queue', 'soc-triage')))}" />
            </label>
            <label>Assignee
              <input type="text" name="assignee" value="{html.escape(str(selected_incident.get('assignee', '') or ''))}" />
            </label>
            <label>Owner
              <input type="text" name="owner" value="{html.escape(str(selected_incident.get('owner', '') or ''))}" />
            </label>
          </div>
          <label>Notes
            <textarea name="notes" rows="4">{notes}</textarea>
          </label>
          <div class="form-actions">
            <button type="submit">Save Incident Update</button>
            <a href="/api/incidents/{html.escape(str(selected_incident.get('incident_id', '')))}">Open JSON</a>
          </div>
        </form>"""
        else:
            update_section = f"""
        <div class="read-only-note">
          <div class="section-title">Update Incident</div>
          <p>Read-only access. Incident updates require the <code>analyst</code> role or higher.</p>
          <div class="form-actions">
            <a href="/api/incidents/{html.escape(str(selected_incident.get('incident_id', '')))}">Open JSON</a>
          </div>
        </div>"""
        incident_detail = f"""
      <article class="card detail-card">
        <div class="section-title">Incident Detail</div>
        <h3>{html.escape(str(selected_incident.get('incident_id', 'n/a')))}</h3>
        <div class="detail-grid">
          <div><span>Status</span><strong>{html.escape(str(selected_incident.get('status', 'open')))}</strong></div>
          <div><span>Severity</span><strong>{html.escape(str(selected_incident.get('severity', 'UNKNOWN')))}</strong></div>
          <div><span>Queue</span><strong>{html.escape(str(selected_incident.get('queue', 'soc-triage')))}</strong></div>
          <div><span>Assignee</span><strong>{html.escape(str(selected_incident.get('assignee', 'unassigned') or 'unassigned'))}</strong></div>
          <div><span>Owner</span><strong>{html.escape(str(selected_incident.get('owner', 'unassigned') or 'unassigned'))}</strong></div>
          <div><span>Source</span><strong>{html.escape(str(selected_incident.get('src_ip', 'n/a')))}</strong></div>
          <div><span>Created</span><strong>{_isoish_to_display(selected_incident.get('created_at'))}</strong></div>
          <div><span>Status Changed</span><strong>{_isoish_to_display(selected_incident.get('status_changed_at'))}</strong></div>
          <div><span>Assigned</span><strong>{_isoish_to_display(selected_incident.get('assigned_at'))}</strong></div>
          <div><span>Contained</span><strong>{_isoish_to_display(selected_incident.get('contained_at'))}</strong></div>
          <div><span>Resolved</span><strong>{_isoish_to_display(selected_incident.get('resolved_at'))}</strong></div>
          <div><span>Threat</span><strong>{html.escape(str(selected_incident.get('threat_type', 'UNKNOWN')))}</strong></div>
        </div>
        <p class="detail-description">{html.escape(str(selected_incident.get('description', 'No description provided.')))}</p>
        <div class="detail-columns">
          <section>
            <h4>Notes</h4>
            <p class="notes-box">{notes or 'No analyst notes yet.'}</p>
          </section>
          <section>
            <h4>Metadata</h4>
            <ul>{metadata_items}</ul>
          </section>
          <section>
            <h4>Source Asset</h4>
            {asset_summary}
          </section>
          <section>
            <h4>Unauthorized Device</h4>
            {unauthorized_summary}
          </section>
          <section>
            <h4>Zone Context</h4>
            {zone_summary}
          </section>
        </div>
        {update_section}
      </article>"""
    else:
        incident_detail = """
      <article class="card detail-card">
        <div class="section-title">Incident Detail</div>
        <p>Select an incident from the table to inspect it and apply updates.</p>
      </article>"""

    page = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>NSM SOC Management</title>
  <style>
    :root {{
      --bg: #0b1220;
      --panel: #111b2e;
      --panel-2: #13223a;
      --text: #e6edf7;
      --muted: #9cb2cf;
      --good: #2dd4bf;
      --warn: #fbbf24;
      --bad: #fb7185;
      --line: #274468;
      --brand: #38bdf8;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      color: var(--text);
      background:
        radial-gradient(circle at 20% 0%, rgba(56, 189, 248, 0.14), transparent 38%),
        radial-gradient(circle at 85% 100%, rgba(45, 212, 191, 0.12), transparent 35%),
        var(--bg);
      font-family: "Segoe UI", "Inter", sans-serif;
    }}
    main {{ max-width: 1180px; margin: 20px auto; padding: 0 16px 24px; }}
    .top {{
      display: flex; align-items: center; justify-content: space-between; gap: 12px;
      margin-bottom: 14px;
    }}
    .banner {{
      border-radius: 12px;
      padding: 12px 14px;
      margin-bottom: 12px;
      border: 1px solid var(--line);
    }}
    .banner.ok {{ background: rgba(45, 212, 191, 0.12); color: var(--good); }}
    .banner.err {{ background: rgba(251, 113, 133, 0.12); color: #fecdd3; }}
    h1 {{ margin: 0; letter-spacing: 0.01em; }}
    h3, h4 {{ margin: 0 0 10px; }}
    .meta {{ color: var(--muted); font-size: 0.95rem; }}
    .role-pill {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      margin-top: 8px;
      border-radius: 999px;
      border: 1px solid var(--line);
      padding: 6px 10px;
      color: var(--text);
      background: rgba(56, 189, 248, 0.12);
      font-size: 0.9rem;
    }}
    .kpis {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      gap: 10px;
      margin-bottom: 12px;
    }}
    .card {{
      background: linear-gradient(160deg, var(--panel), var(--panel-2));
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 12px;
    }}
    .k {{ color: var(--muted); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.06em; }}
    .v {{ font-size: 1.55rem; font-weight: 700; margin-top: 4px; }}
    .v.good {{ color: var(--good); }}
    .v.warn {{ color: var(--warn); }}
    .v.bad {{ color: var(--bad); }}
    .v.info {{ color: var(--brand); }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 12px;
    }}
    .workflow-grid {{
      display: grid;
      grid-template-columns: minmax(0, 1.4fr) minmax(320px, 1fr);
      gap: 12px;
      margin-top: 12px;
      align-items: start;
    }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid var(--line); }}
    th {{ color: var(--muted); font-weight: 600; }}
    .links a {{ color: var(--brand); margin-right: 10px; text-decoration: none; }}
    .links a:hover {{ text-decoration: underline; }}
    .disabled-link {{
      color: var(--muted);
      margin-right: 10px;
      text-decoration: none;
      cursor: default;
    }}
    .toolbar {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 10px;
    }}
    .toolbar label, .update-form label {{
      display: flex;
      flex-direction: column;
      gap: 6px;
      color: var(--muted);
      font-size: 0.92rem;
    }}
    .toolbar input, .toolbar select, .update-form input, .update-form select, .update-form textarea {{
      width: 100%;
      border-radius: 10px;
      border: 1px solid var(--line);
      background: rgba(7, 14, 26, 0.35);
      color: var(--text);
      padding: 10px 12px;
      font: inherit;
    }}
    .toolbar-actions, .form-actions {{
      display: flex;
      gap: 10px;
      align-items: center;
      flex-wrap: wrap;
      margin-top: 10px;
    }}
    button, .button-link {{
      border: 0;
      border-radius: 999px;
      padding: 10px 14px;
      background: linear-gradient(135deg, #0891b2, #0ea5a4);
      color: white;
      font: inherit;
      font-weight: 700;
      cursor: pointer;
      text-decoration: none;
    }}
    .button-link.secondary {{
      background: transparent;
      border: 1px solid var(--line);
      color: var(--text);
    }}
    .section-title {{
      color: var(--brand);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      font-size: 0.78rem;
      margin-bottom: 10px;
    }}
    .detail-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 10px;
      margin-bottom: 12px;
    }}
    .detail-grid span {{
      display: block;
      color: var(--muted);
      font-size: 0.82rem;
      margin-bottom: 4px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    .detail-description {{ color: var(--text); }}
    .detail-columns {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 12px;
      margin: 12px 0;
    }}
    .detail-columns ul {{ margin: 0; padding-left: 18px; color: var(--muted); }}
    .asset-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 8px;
      margin-bottom: 10px;
    }}
    .asset-grid span {{
      display: block;
      color: var(--muted);
      font-size: 0.8rem;
      margin-bottom: 4px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    .asset-list {{
      margin: 0;
      padding-left: 18px;
      color: var(--muted);
    }}
    .asset-empty {{
      color: var(--muted);
      margin: 0;
    }}
    .notes-box {{
      white-space: pre-wrap;
      background: rgba(7, 14, 26, 0.35);
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 10px 12px;
      min-height: 74px;
    }}
    .update-form {{ margin-top: 14px; }}
    .read-only-note {{
      margin-top: 14px;
      border: 1px dashed var(--line);
      border-radius: 12px;
      padding: 12px;
      color: var(--muted);
      background: rgba(7, 14, 26, 0.22);
    }}
    .form-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 10px;
      margin-bottom: 10px;
    }}
    .detail-card {{ min-height: 100%; }}
    .table-meta {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 8px;
      color: var(--muted);
      flex-wrap: wrap;
    }}
    .metrics-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 10px;
      margin-top: 12px;
    }}
    .metric-list {{
      margin: 0;
      padding-left: 18px;
      color: var(--muted);
    }}
    .trend-text {{
      color: var(--muted);
      line-height: 1.5;
      word-break: break-word;
    }}
    @media (max-width: 900px) {{
      .workflow-grid {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <main>
    <section class="top">
      <div>
        <h1>SOC Management Dashboard</h1>
        <div class="meta">Updated: {html.escape(snap["timestamp_utc"])}</div>
        <div class="role-pill">Role: <strong>{html.escape(current_role)}</strong></div>
      </div>
      <div class="links">
        <a href="/api/soc-summary">SOC JSON</a>
        <a href="/api/incidents">Incidents JSON</a>
        {f'<a href="/api/incidents/export.csv{f"?{filter_query}" if filter_query else ""}">Incidents CSV</a>' if can_export else '<span class="disabled-link">Incidents CSV (analyst+)</span>'}
        <a href="/api/devices">Devices JSON</a>
        <a href="/dashboard">Alerts</a>
        <a href="/network-watcher">Watcher</a>
        <a href="/">Home</a>
      </div>
    </section>

    {f'<div class="banner ok">{html.escape(message)}</div>' if message else ''}
    {f'<div class="banner err">{html.escape(error)}</div>' if error else ''}
    {'' if can_update else '<div class="banner ok">Read-only mode active. Use an analyst or admin role to update cases or export CSV.</div>'}

    <section class="kpis">
      <article class="card"><div class="k">Active Incidents</div><div class="v warn">{snap['active_incidents']}</div></article>
      <article class="card"><div class="k">Critical Incidents</div><div class="v bad">{snap['critical_incidents']}</div></article>
      <article class="card"><div class="k">Automation Actions</div><div class="v good">{snap['automation_actions']}</div></article>
      <article class="card"><div class="k">Recent Alerts</div><div class="v">{snap['recent_alerts']}</div></article>
      <article class="card"><div class="k">Recent Cases</div><div class="v">{snap['recent_incidents']}</div></article>
      <article class="card"><div class="k">Unauthorized Devices</div><div class="v bad">{snap['unauthorized_active']}</div></article>
      <article class="card"><div class="k">Topology Violations</div><div class="v warn">{snap['topology_violations']}</div></article>
    </section>

    <section class="metrics-grid">
      <article class="card">
        <div class="k">Avg Time To Assign</div>
        <div class="v info">{_duration_to_display(mttr.get('assignment_avg_seconds'))}</div>
      </article>
      <article class="card">
        <div class="k">Avg Time To Contain</div>
        <div class="v warn">{_duration_to_display(mttr.get('containment_avg_seconds'))}</div>
      </article>
      <article class="card">
        <div class="k">Avg Time To Resolve</div>
        <div class="v">{_duration_to_display(mttr.get('resolution_avg_seconds'))}</div>
      </article>
      <article class="card">
        <div class="k">SLA Breaches</div>
        <ul class="metric-list">
          <li>Assign: {sla.get('breaches', {}).get('assignment', 0)} / {sla.get('evaluated', {}).get('assignment', 0)}</li>
          <li>Contain: {sla.get('breaches', {}).get('containment', 0)} / {sla.get('evaluated', {}).get('containment', 0)}</li>
          <li>Resolve: {sla.get('breaches', {}).get('resolution', 0)} / {sla.get('evaluated', {}).get('resolution', 0)}</li>
        </ul>
      </article>
      <article class="card">
        <div class="k">Created Trend (7d)</div>
        <p class="trend-text">{html.escape(_trend_summary(trends.get('created', [])))}</p>
      </article>
      <article class="card">
        <div class="k">Resolved Trend (7d)</div>
        <p class="trend-text">{html.escape(_trend_summary(trends.get('resolved', [])))}</p>
      </article>
      <article class="card">
        <div class="k">Unauthorized Device Queue</div>
        <ul class="metric-list">
          <li>Tracked: {snap['unauthorized_devices']}</li>
          <li>Active unmanaged: {snap['unauthorized_active']}</li>
        </ul>
      </article>
      <article class="card">
        <div class="k">Topology Coverage</div>
        <ul class="metric-list">
          <li>Zones: {snap['topology_zones']}</li>
          <li>Violations: {snap['topology_violations']}</li>
        </ul>
      </article>
    </section>

    <section class="card">
      <div class="section-title">Unauthorized Devices</div>
      <div class="table-meta">
        <span>Recent unmanaged assets inferred from observed activity and missing inventory records.</span>
        <span><a href="/api/devices/unauthorized">Open JSON</a></span>
      </div>
      <table>
        <thead>
          <tr>
            <th>IP</th>
            <th>Status</th>
            <th>Observation</th>
            <th>Risk</th>
            <th>Owner</th>
          </tr>
        </thead>
        <tbody>{unauthorized_rows}</tbody>
      </table>
    </section>

    <section class="card">
      <div class="section-title">Cross-Zone Paths</div>
      <div class="table-meta">
        <span>Observed zone-to-zone traffic paths without an allow policy or with an explicit block.</span>
        <span><a href="/api/topology/violations">Open JSON</a></span>
      </div>
      <table>
        <thead>
          <tr>
            <th>Source Zone</th>
            <th>Destination Zone</th>
            <th>Status</th>
            <th>Obs</th>
            <th>Threats</th>
          </tr>
        </thead>
        <tbody>{topology_rows}</tbody>
      </table>
    </section>

    <section class="card">
      <div class="section-title">Incident Queue Filters</div>
      <form method="get" action="/soc-management">
        <div class="toolbar">
          <label>Status
            <select name="status">
              <option value="">All statuses</option>
              <option value="active"{_selected_value(filters['status'], 'active')}>active</option>
              <option value="open"{_selected_value(filters['status'], 'open')}>open</option>
              <option value="assigned"{_selected_value(filters['status'], 'assigned')}>assigned</option>
              <option value="contained"{_selected_value(filters['status'], 'contained')}>contained</option>
              <option value="resolved"{_selected_value(filters['status'], 'resolved')}>resolved</option>
            </select>
          </label>
          <label>Severity
            <select name="severity">
              <option value="">All severities</option>
              <option value="LOW"{_selected_value(filters['severity'], 'LOW')}>LOW</option>
              <option value="MEDIUM"{_selected_value(filters['severity'], 'MEDIUM')}>MEDIUM</option>
              <option value="HIGH"{_selected_value(filters['severity'], 'HIGH')}>HIGH</option>
              <option value="CRITICAL"{_selected_value(filters['severity'], 'CRITICAL')}>CRITICAL</option>
            </select>
          </label>
          <label>Queue
            <input type="text" name="queue" value="{html.escape(filters['queue'])}" placeholder="soc-triage" />
          </label>
          <label>Threat
            <input type="text" name="threat_type" value="{html.escape(filters['threat_type'])}" placeholder="PORT_SCAN" />
          </label>
          <label>Source
            <input type="text" name="src_ip" value="{html.escape(filters['src_ip'])}" placeholder="10.0.0.5" />
          </label>
          <label>Assignee
            <input type="text" name="assignee" value="{html.escape(filters['assignee'])}" placeholder="alice" />
          </label>
          <label>Owner
            <input type="text" name="owner" value="{html.escape(filters['owner'])}" placeholder="tier-2" />
          </label>
        </div>
        <div class="toolbar-actions">
          <button type="submit">Apply Filters</button>
          <a class="button-link secondary" href="/soc-management">Clear Filters</a>
          <span>{len(incidents)} incidents shown{f' with {active_filter_count} active filters' if active_filter_count else ''}</span>
        </div>
      </form>
    </section>

    <section class="grid">
      <article class="card">
        <h3>Threat Queue</h3>
        <table>
          <thead><tr><th>Threat Type</th><th>Items</th></tr></thead>
          <tbody>{threat_items}</tbody>
        </table>
      </article>
      <article class="card">
        <h3>Analyst Queue</h3>
        <table>
          <thead><tr><th>Queue</th><th>Items</th></tr></thead>
          <tbody>{analyst_items}</tbody>
        </table>
      </article>
    </section>

    <section class="workflow-grid">
      <article class="card">
        <div class="table-meta">
          <h3>Incident Cases</h3>
          <span>{'Filtered view' if filter_query else 'Latest view'}</span>
        </div>
        <table>
          <thead><tr><th>ID</th><th>Severity</th><th>Status</th><th>Queue</th><th>Assignee</th><th>Source</th><th>Threat</th></tr></thead>
          <tbody>{incident_items}</tbody>
        </table>
      </article>
      {incident_detail}
    </section>
  </main>
</body>
</html>"""
    return Response(page, mimetype="text/html")
