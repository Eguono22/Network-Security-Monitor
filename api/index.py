"""Vercel-compatible API entrypoint with alert dashboard and network watcher."""

from __future__ import annotations

import csv
import html
import json
import os
from collections import Counter
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from urllib.parse import urlencode

import psycopg

from flask import Flask, Response, jsonify, redirect, request, render_template, g

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
from network_security_monitor.storage import AlertRepository, JsonlStore, ReadOnlyStoreError, event_store
from network_security_monitor.threat_intel import ThreatIntelService
from network_security_monitor.config import Config
from network_security_monitor.auth import install_auth, csrf_token
from network_security_monitor.postgres import postgres_enabled


_WEB_ROOT = Path(__file__).resolve().parent.parent / "network_security_monitor" / "web"
app = Flask(__name__, template_folder=str(_WEB_ROOT / "templates"), static_folder=str(_WEB_ROOT / "static"))
install_auth(app)


@app.errorhandler(psycopg.Error)
def database_unavailable(error):
    app.logger.error("Database operation failed: %s", type(error).__name__)
    if request.path.startswith("/api/"):
        return jsonify(error="storage_unavailable", message="Storage is temporarily unavailable."), 503
    return render_template("error.html", message="Storage is temporarily unavailable. Please retry shortly."), 503

_MAX_RECENT = 100
_VALID_API_ROLES = ("viewer", "analyst", "admin")
_ROLE_RANK = {role: index for index, role in enumerate(_VALID_API_ROLES)}


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    return default


def _serverless_read_only_enabled() -> bool:
    explicit = os.getenv("NSM_SERVERLESS_READ_ONLY")
    if explicit is not None:
        return _env_bool("NSM_SERVERLESS_READ_ONLY")
    return bool(os.getenv("VERCEL") or os.getenv("VERCEL_ENV")) and not postgres_enabled()


def _read_only_mode_error() -> tuple[Response, int]:
    return (
        jsonify(
            {
                "error": "read_only_mode",
                "message": "This deployment is running in serverless read-only mode; write actions are disabled.",
            }
        ),
        503,
    )


def _normalize_role(value) -> str:
    role = str(value or "").strip().lower()
    return role if role in _ROLE_RANK else ""


def _current_role() -> str:
    if not getattr(g, "auth_disabled", False):
        return (getattr(g, "user", None) or {}).get("role", "")
    # Header overrides are explicitly opt-in and available only in local development.
    header_value = request.headers.get("X-NSM-Role", "") if _env_bool("NSM_TRUST_ROLE_HEADER") else ""
    role = _normalize_role(header_value)
    if header_value and not role:
        return ""
    return role or _normalize_role(Config().API_DEFAULT_ROLE) or "viewer"


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
    store = event_store(os.getenv("NSM_SOC_AUTOMATION_LOG_FILE", "soc_actions.log"), "soc_actions")
    return store.read_recent(limit)


def _load_incidents(limit: int = _MAX_RECENT) -> list[dict]:
    manager = IncidentManager(
        os.getenv("NSM_INCIDENTS_LOG_FILE", "incidents.db"),
        read_only=_serverless_read_only_enabled(),
    )
    return manager.list_cases(limit=limit)


def _incident_manager() -> IncidentManager:
    return IncidentManager(
        os.getenv("NSM_INCIDENTS_LOG_FILE", "incidents.db"),
        read_only=_serverless_read_only_enabled(),
    )


def _inventory_service() -> DeviceInventoryService:
    inventory_path = os.getenv("NSM_DEVICE_INVENTORY_FILE", "").strip()
    if not inventory_path:
        inventory_path = Config().DEVICE_INVENTORY_FILE
    return DeviceInventoryService(inventory_path)


def _unauthorized_device_manager() -> UnauthorizedDeviceManager:
    path = os.getenv("NSM_UNAUTHORIZED_DEVICES_FILE", "").strip()
    if not path:
        path = Config().UNAUTHORIZED_DEVICES_FILE
    return UnauthorizedDeviceManager(path, read_only=_serverless_read_only_enabled())


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

    incidents = _load_incidents(limit=1000)
    devices = _inventory_service().list_devices(alerts=alerts, incidents=incidents, limit=500)
    topology = _topology_service().summarize(devices=devices, alerts=alerts, incidents=incidents, limit=500)
    source_details = []
    for ip, count in by_src.most_common(20):
        source_alerts = [alert for alert in alerts if alert.get("src_ip") == ip]
        severities = Counter(alert.get("severity", "UNKNOWN") for alert in source_alerts)
        source_details.append({
            "ip": ip, "alert_count": count,
            "critical_count": severities.get("CRITICAL", 0),
            "high_count": severities.get("HIGH", 0),
            "threat_types": sorted({alert.get("threat_type", "UNKNOWN") for alert in source_alerts}),
        })

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
        "sources": source_details,
        "source_count": len(by_src),
        "topology": topology,
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
    role, denial = _require_role("viewer", page=True)
    if denial is not None:
        return denial
    alerts = _load_recent_alerts(limit=100)
    incidents = _load_incidents(limit=500)
    devices = _inventory_service().list_devices(alerts=alerts, incidents=incidents, limit=500)
    topology = _topology_service().summarize(devices=devices, alerts=alerts, incidents=incidents, limit=500)
    read_only = _serverless_read_only_enabled()
    return render_template(
        "home.html", active_page="home", role=role, read_only=read_only,
        serverless=bool(os.getenv("VERCEL") or os.getenv("VERCEL_ENV")),
        alert_count=len(alerts), incident_count=len(incidents), device_count=len(devices),
        managed_count=sum(bool(device.get("managed")) for device in devices),
        active_count=sum(case.get("status", "open") in ACTIVE_INCIDENT_STATUSES for case in incidents),
        zone_count=len(topology.get("zones", [])),
    )


@app.get("/health")
def health():
    return jsonify({"ok": True})


@app.get("/ready")
def ready():
    try:
        from network_security_monitor.auth import load_users
        from network_security_monitor.auth import auth_disabled
        if not auth_disabled(app):
            if len(app.config.get("SECRET_KEY") or "") < 32:
                raise ValueError("Missing signing key")
            load_users()
        if postgres_enabled():
            from network_security_monitor.postgres import connect
            with connect() as conn:
                for table in ("incidents", "events", "device_reviews", "auth_attempts", "change_audit"):
                    conn.execute(f"SELECT 1 FROM {table} LIMIT 1")
        return jsonify(ready=True)
    except Exception:
        return jsonify(ready=False), 503


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
    _, denial = _require_role("viewer")
    if denial is not None:
        return denial
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


def _lookup_threat_intel(indicator: str, indicator_type: str = "") -> dict:
    config = Config()
    return ThreatIntelService(config.KNOWN_MALICIOUS_IPS).lookup(
        indicator, indicator_type=indicator_type,
        alerts=_load_recent_alerts(limit=200), incidents=_load_incidents(limit=200),
    )


@app.get("/api/threat-intel")
def api_threat_intel():
    _, denial = _require_role("viewer")
    if denial is not None:
        return denial
    indicator = request.args.get("indicator", "").strip()
    if not indicator:
        return jsonify({"error": "missing_indicator", "message": "indicator query parameter is required"}), 400
    try:
        return jsonify(_lookup_threat_intel(indicator, request.args.get("type", "")))
    except ValueError as exc:
        return jsonify({"error": "invalid_indicator", "message": str(exc)}), 400


@app.get("/threat-intel")
def threat_intel_page():
    _, denial = _require_role("viewer", page=True)
    if denial is not None:
        return denial
    indicator = request.args.get("indicator", "").strip()
    indicator_type = request.args.get("type", "").strip().lower()
    result = None
    error = ""
    status = 200
    if indicator:
        try:
            result = _lookup_threat_intel(indicator, indicator_type)
        except ValueError as exc:
            error = str(exc)
            status = 400
    elif "indicator" in request.args:
        error = "Enter an indicator to look up."
        status = 400
    return render_template(
        "threat_intel.html", active_page="intel", indicator=indicator,
        indicator_type=indicator_type, result=result, error=error,
    ), status


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
    if _serverless_read_only_enabled():
        return _read_only_mode_error()
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify(error="invalid_payload", message="A JSON object is required."), 400
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
            reviewed_by=(getattr(g, "user", None) or {}).get("username", "local-development"),
        )
    except UnauthorizedDeviceValidationError as exc:
        return jsonify({"error": "invalid_unauthorized_device_update", "message": str(exc)}), 400
    except ReadOnlyStoreError:
        return _read_only_mode_error()
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
    if _serverless_read_only_enabled():
        return _read_only_mode_error()
    manager = _incident_manager()
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify(error="invalid_payload", message="A JSON object is required."), 400
    allowed = {
        "status",
        "queue",
        "assignee",
        "owner",
        "notes",
        "metadata",
    }
    changes = {key: value for key, value in payload.items() if key in allowed}
    changes["updated_by"] = (getattr(g, "user", None) or {}).get("username", "local-development")
    try:
        updated = manager.update_case(incident_id, **changes)
    except IncidentValidationError as exc:
        return jsonify({"error": "invalid_incident_update", "message": str(exc)}), 400
    except ReadOnlyStoreError:
        return _read_only_mode_error()
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
    if _serverless_read_only_enabled():
        query = _build_query(
            {
                **filters,
                "incident_id": selected_id,
                "error": "serverless read-only mode is active; incident updates are disabled on this deployment",
            }
        )
        location = "/soc-management"
        if query:
            location = f"{location}?{query}"
        return redirect(location, code=303)
    allowed = ("status", "queue", "assignee", "owner", "notes")
    changes = {key: request.form.get(key, "").strip() for key in allowed if request.form.get(key) is not None}
    changes = {key: value for key, value in changes.items() if value}
    changes["updated_by"] = (getattr(g, "user", None) or {}).get("username", "local-development")

    message = ""
    error = ""
    try:
        updated = manager.update_case(incident_id, **changes)
    except IncidentValidationError as exc:
        updated = None
        error = str(exc)
    except ReadOnlyStoreError:
        updated = None
        error = "serverless read-only mode is active; incident updates are disabled on this deployment"
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
    return render_template("dashboard.html", alerts=_load_recent_alerts(), active_page="overview")


@app.get("/devices")
def devices_page():
    _, denial = _require_role("viewer", page=True)
    if denial is not None:
        return denial
    query = request.args.get("q", "").strip()
    risk = request.args.get("risk_level", "").strip().lower()
    management = request.args.get("management", "").strip().lower()
    inventory = _inventory_service()
    alerts = _load_recent_alerts(limit=1000)
    incidents = _load_incidents(limit=1000)
    devices = inventory.list_devices(alerts=alerts, incidents=incidents, limit=500)
    filtered = inventory.list_devices(
        alerts=alerts, incidents=incidents, limit=500, query=query, risk_level=risk,
    )
    if management in {"managed", "unmanaged"}:
        filtered = [device for device in filtered if bool(device.get("managed")) == (management == "managed")]
    return render_template(
        "devices.html", active_page="devices", devices=filtered,
        total=len(devices), managed=sum(bool(device.get("managed")) for device in devices),
        high_risk=sum(device.get("risk_level") in {"high", "critical"} for device in devices),
        query=query, risk=risk, management=management,
    )


@app.get("/devices/<ip>")
def device_page(ip: str):
    role, denial = _require_role("viewer", page=True)
    if denial is not None:
        return denial
    alerts = _load_recent_alerts(limit=1000)
    incidents = _load_incidents(limit=1000)
    inventory = _inventory_service()
    device = inventory.get_device(ip, alerts=alerts, incidents=incidents)
    if device is None:
        return render_template("device.html", active_page="devices", device=None), 404
    finding = None
    if not device.get("managed"):
        finding = _unauthorized_device_manager().get_finding(
            ip, inventory=inventory, alerts=alerts, incidents=incidents,
        )
    return render_template(
        "device.html", active_page="devices", device=device, finding=finding,
        can_review=_role_allowed(role, "analyst") and not _serverless_read_only_enabled(),
        read_only=_serverless_read_only_enabled(),
        incidents=[case for case in incidents if case.get("src_ip") == ip],
    )


@app.get("/network-watcher")
def network_watcher():
    _, denial = _require_role("viewer", page=True)
    if denial is not None:
        return denial
    return render_template(
        "watcher.html", active_page="watcher", snapshot=_network_watcher_summary(),
    )


@app.get("/soc-management")
def soc_management():
    current_role, denial = _require_role("viewer", page=True)
    if denial is not None:
        return denial
    read_only_mode = _serverless_read_only_enabled()
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
    try:
        incidents = manager.list_cases(limit=100, **filters)
    except IncidentValidationError as exc:
        error = str(exc)
        incidents = []
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
        for i in reversed(incidents)
    ) or "<tr><td colspan='7'>No incidents matched the current filters.</td></tr>"
    active_filter_count = sum(1 for value in filters.values() if value)
    filter_query = _build_query(filters)
    can_export = _role_allowed(current_role, "analyst")
    can_update = _role_allowed(current_role, "analyst") and not read_only_mode
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
          <input type="hidden" name="csrf_token" value="{csrf_token() if not getattr(g, 'auth_disabled', False) else ''}" />
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
            update_help = (
                "Serverless read-only mode is active for this deployment, so incident updates are disabled."
                if read_only_mode
                else "Read-only access. Incident updates require the analyst role or higher."
            )
            update_section = f"""
        <div class="read-only-note">
          <div class="section-title">Update Incident</div>
          <p>{html.escape(update_help)}</p>
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

    page = f"""<div class="soc-workspace">
    <section class="top">
      <div>
        <div class="eyebrow">INCIDENT RESPONSE</div><h1>SOC Management Dashboard</h1>
        <div class="meta">Updated: {html.escape(snap["timestamp_utc"])}</div>
        <div class="role-pill">Role: <strong>{html.escape(current_role)}</strong></div>
      </div>
      <div class="links">
        <a href="/api/soc-summary">SOC JSON</a>
        <a href="/api/incidents">Incidents JSON</a>
        {f'<a href="/api/incidents/export.csv{f"?{filter_query}" if filter_query else ""}">Incidents CSV</a>' if can_export else '<span class="disabled-link">Incidents CSV (analyst+)</span>'}
        <a href="/devices">Device inventory</a>
        <a href="/dashboard">Alerts</a>
        <a href="/network-watcher">Watcher</a>
        <a href="/">Home</a>
      </div>
    </section>

    {f'<div class="banner ok">{html.escape(message)}</div>' if message else ''}
    {f'<div class="banner err">{html.escape(error)}</div>' if error else ''}
    {'' if can_update else ('<div class="banner ok">Serverless read-only mode active. Incident updates are disabled on this Vercel deployment.</div>' if read_only_mode else '<div class="banner ok">Read-only mode active. Use an analyst or admin role to update cases or export CSV.</div>')}

    <section class="kpis">
      <article class="card"><div class="k">Active Incidents</div><div class="v warn">{snap['active_incidents']}</div></article>
      <article class="card"><div class="k">Critical Incidents</div><div class="v bad">{snap['critical_incidents']}</div></article>
      <article class="card"><div class="k">Automation Actions</div><div class="v good">{snap['automation_actions']}</div></article>
      <article class="card"><div class="k">Recent Alerts</div><div class="v">{snap['recent_alerts']}</div></article>
      <article class="card"><div class="k">Recent Cases</div><div class="v">{snap['recent_incidents']}</div></article>
      <article class="card"><div class="k">Unauthorized Devices</div><div class="v bad">{snap['unauthorized_active']}</div></article>
      <article class="card"><div class="k">Topology Violations</div><div class="v warn">{snap['topology_violations']}</div></article>
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

    <section class="workflow-grid">
      <article class="card">
        <div class="table-meta">
          <h3>Incident Cases</h3>
          <span>{'Filtered view' if filter_query else 'Latest view'}</span>
        </div>
        <div class="table-scroll"><table>
          <thead><tr><th>ID</th><th>Severity</th><th>Status</th><th>Queue</th><th>Assignee</th><th>Source</th><th>Threat</th></tr></thead>
          <tbody>{incident_items}</tbody>
        </table></div>
      </article>
      {incident_detail}
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
      <div class="table-scroll"><table>
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
      </table></div>
    </section>

    <section class="card">
      <div class="section-title">Cross-Zone Paths</div>
      <div class="table-meta">
        <span>Observed zone-to-zone traffic paths without an allow policy or with an explicit block.</span>
        <span><a href="/api/topology/violations">Open JSON</a></span>
      </div>
      <div class="table-scroll"><table>
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
      </table></div>
    </section>

    <section class="grid">
      <article class="card">
        <h3>Threat Queue</h3>
        <div class="table-scroll"><table>
          <thead><tr><th>Threat Type</th><th>Items</th></tr></thead>
          <tbody>{threat_items}</tbody>
        </table></div>
      </article>
      <article class="card">
        <h3>Analyst Queue</h3>
        <div class="table-scroll"><table>
          <thead><tr><th>Queue</th><th>Items</th></tr></thead>
          <tbody>{analyst_items}</tbody>
        </table></div>
      </article>
    </section>

</div>"""
    return render_template("soc.html", active_page="soc", workspace_html=page)
