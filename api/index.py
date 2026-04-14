"""Vercel-compatible API entrypoint with alert dashboard and network watcher."""

from __future__ import annotations

import html
import os
from collections import Counter
from datetime import datetime, timezone

from flask import Flask, Response, jsonify, request

from network_security_monitor.incident_manager import IncidentManager
from network_security_monitor.storage import AlertRepository, JsonlStore


app = Flask(__name__)

_MAX_RECENT = 100


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
    manager = IncidentManager(os.getenv("NSM_INCIDENTS_LOG_FILE", "incidents.jsonl"))
    return manager.list_cases(limit=limit)


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
    incidents = _load_incidents()
    open_incidents = sum(1 for i in incidents if i.get("status") == "open")
    critical_incidents = sum(1 for i in incidents if i.get("severity") == "CRITICAL")
    if not incidents:
        open_incidents = sum(1 for a in alerts if a["severity"] in {"HIGH", "CRITICAL"})
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
        "critical_incidents": critical_incidents,
        "automation_actions": len(actions),
        "recent_alerts": len(alerts),
        "recent_incidents": len(incidents),
        "threat_queue": threat_queue,
        "analyst_queue": analyst_queue,
    }


@app.get("/")
def root():
    html = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Network Security Monitor</title>
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
    <h1>Network Security Monitor</h1>
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
        <p>Query incident cases at <code>/api/incidents</code>.</p>
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


@app.get("/api/soc-summary")
def api_soc_summary():
    return jsonify(_soc_management_snapshot())


@app.get("/api/incidents")
def api_incidents():
    limit = _request_limit()
    manager = IncidentManager(os.getenv("NSM_INCIDENTS_LOG_FILE", "incidents.jsonl"))
    incidents = manager.list_cases(
        limit=limit,
        status=request.args.get("status", ""),
        severity=request.args.get("severity", ""),
        queue=request.args.get("queue", ""),
        threat_type=request.args.get("threat_type", ""),
        src_ip=request.args.get("src_ip", ""),
    )
    return jsonify({"count": len(incidents), "incidents": incidents})


@app.get("/api/incidents/<incident_id>")
def api_incident_detail(incident_id: str):
    manager = IncidentManager(os.getenv("NSM_INCIDENTS_LOG_FILE", "incidents.jsonl"))
    incident = manager.get_case(incident_id)
    if incident is None:
        return jsonify({"error": "incident_not_found", "incident_id": incident_id}), 404
    return jsonify(incident)


@app.patch("/api/incidents/<incident_id>")
def api_incident_update(incident_id: str):
    manager = IncidentManager(os.getenv("NSM_INCIDENTS_LOG_FILE", "incidents.jsonl"))
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
    updated = manager.update_case(incident_id, **changes)
    if updated is None:
        return jsonify({"error": "incident_not_found", "incident_id": incident_id}), 404
    return jsonify(updated)


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
    snap = _soc_management_snapshot()
    incidents = _load_incidents(limit=25)
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
        f"<td>{html.escape(str(i.get('incident_id', 'n/a')))}</td>"
        f"<td>{html.escape(str(i.get('severity', 'UNKNOWN')))}</td>"
        f"<td>{html.escape(str(i.get('status', 'open')))}</td>"
        f"<td>{html.escape(str(i.get('queue', 'soc-triage')))}</td>"
        f"<td>{html.escape(str(i.get('src_ip', 'n/a')))}</td>"
        f"<td>{html.escape(str(i.get('threat_type', 'UNKNOWN')))}</td>"
        "</tr>"
        for i in reversed(incidents[-15:])
    ) or "<tr><td colspan='6'>No incidents created yet.</td></tr>"

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
    h1 {{ margin: 0; letter-spacing: 0.01em; }}
    .meta {{ color: var(--muted); font-size: 0.95rem; }}
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
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 12px;
    }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid var(--line); }}
    th {{ color: var(--muted); font-weight: 600; }}
    .links a {{ color: var(--brand); margin-right: 10px; text-decoration: none; }}
    .links a:hover {{ text-decoration: underline; }}
  </style>
</head>
<body>
  <main>
    <section class="top">
      <div>
        <h1>SOC Management Dashboard</h1>
        <div class="meta">Updated: {html.escape(snap["timestamp_utc"])}</div>
      </div>
      <div class="links">
        <a href="/api/soc-summary">SOC JSON</a>
        <a href="/api/incidents">Incidents JSON</a>
        <a href="/dashboard">Alerts</a>
        <a href="/network-watcher">Watcher</a>
        <a href="/">Home</a>
      </div>
    </section>

    <section class="kpis">
      <article class="card"><div class="k">Open Incidents</div><div class="v warn">{snap['open_incidents']}</div></article>
      <article class="card"><div class="k">Critical Incidents</div><div class="v bad">{snap['critical_incidents']}</div></article>
      <article class="card"><div class="k">Automation Actions</div><div class="v good">{snap['automation_actions']}</div></article>
      <article class="card"><div class="k">Recent Alerts</div><div class="v">{snap['recent_alerts']}</div></article>
      <article class="card"><div class="k">Recent Cases</div><div class="v">{snap['recent_incidents']}</div></article>
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
      <article class="card">
        <h3>Incident Cases</h3>
        <table>
          <thead><tr><th>ID</th><th>Severity</th><th>Status</th><th>Queue</th><th>Source</th><th>Threat</th></tr></thead>
          <tbody>{incident_items}</tbody>
        </table>
      </article>
    </section>
  </main>
</body>
</html>"""
    return Response(page, mimetype="text/html")
