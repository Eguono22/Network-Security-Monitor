"""Inventory pages use the existing asset context and review lifecycle."""

import json

import pytest


@pytest.fixture
def inventory_client(monkeypatch, tmp_path):
    pytest.importorskip("flask")
    from api.index import app

    inventory = tmp_path / "devices.json"
    inventory.write_text(json.dumps([{
        "ip": "10.0.0.10", "hostname": "office-server", "os": "Linux",
        "vendor": "Acme", "tags": ["production"], "risk_score": 10,
    }]))
    alerts = tmp_path / "alerts.jsonl"
    alerts.write_text(json.dumps({
        "timestamp": 1775344876.0, "severity": "CRITICAL", "threat_type": "PORT_SCAN",
        "src_ip": "10.0.0.99", "description": "Unmanaged scanner", "raw": "Scanner",
        "metadata": {"hostname": "<script>unsafe()</script>"},
    }) + "\n")
    incidents = tmp_path / "incidents.jsonl"
    incidents.write_text(json.dumps({
        "incident_id": "INC-ASSET1", "created_at": 1775344876.0,
        "status": "open", "severity": "CRITICAL", "threat_type": "PORT_SCAN",
        "src_ip": "10.0.0.99", "metadata": {},
    }) + "\n")
    for name, value in {
        "NSM_DEVICE_INVENTORY_FILE": inventory,
        "NSM_ALERTS_DATA_FILE": alerts,
        "NSM_INCIDENTS_LOG_FILE": incidents,
        "NSM_UNAUTHORIZED_DEVICES_FILE": tmp_path / "reviews.jsonl",
        "NSM_SERVERLESS_READ_ONLY": "false",
        "NSM_API_DEFAULT_ROLE": "admin",
    }.items():
        monkeypatch.setenv(name, str(value))
    return app.test_client()


def test_inventory_filters_and_device_context(inventory_client):
    response = inventory_client.get("/devices")
    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert "office-server" in page
    assert "10.0.0.99" in page
    assert "<script>unsafe()" not in page
    for query in ("?management=managed", "?q=production", "?risk_level=low"):
        page = inventory_client.get("/devices" + query).get_data(as_text=True)
        assert "office-server" in page
        assert "10.0.0.99" not in page
    page = inventory_client.get("/devices?management=unmanaged&risk_level=critical").get_data(as_text=True)
    assert "10.0.0.99" in page
    assert "office-server" not in page
    page = inventory_client.get("/devices/10.0.0.99").get_data(as_text=True)
    assert "INC-ASSET1" in page
    assert "Unmanaged device review" in page
    assert "&lt;script&gt;unsafe()&lt;/script&gt;" in page


def test_inventory_empty_and_missing_device(inventory_client):
    page = inventory_client.get("/devices?q=nonexistent").get_data(as_text=True)
    assert "No matching devices" in page
    response = inventory_client.get("/devices/192.0.2.1")
    assert response.status_code == 404
    assert "Device not found" in response.get_data(as_text=True)


def test_device_review_persists_and_renders_safely(inventory_client):
    response = inventory_client.patch("/api/devices/unauthorized/10.0.0.99", json={
        "status": "investigating", "owner": "asset-team", "notes": "<script>unsafe()</script>",
    })
    assert response.status_code == 200
    page = inventory_client.get("/devices/10.0.0.99").get_data(as_text=True)
    assert 'value="investigating" selected' in page
    assert 'value="asset-team"' in page
    assert "&lt;script&gt;unsafe()&lt;/script&gt;" in page
    assert "<script>unsafe()" not in page


def test_inventory_respects_viewer_role(inventory_client):
    headers = {"X-NSM-Role": "viewer"}
    response = inventory_client.get("/devices/10.0.0.99", headers=headers)
    assert response.status_code == 200
    assert 'id="device-review"' not in response.get_data(as_text=True)
    assert inventory_client.patch("/api/devices/unauthorized/10.0.0.99", headers=headers, json={"status": "approved"}).status_code == 403
    assert inventory_client.get("/devices", headers={"X-NSM-Role": "invalid"}).status_code == 403
    assert inventory_client.get("/devices/10.0.0.99", headers={"X-NSM-Role": "invalid"}).status_code == 403


def test_inventory_respects_read_only_mode(inventory_client, monkeypatch):
    monkeypatch.setenv("NSM_SERVERLESS_READ_ONLY", "true")
    response = inventory_client.get("/devices/10.0.0.99")
    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert "This deployment is read-only" in page
    assert 'id="device-review"' not in page
    assert inventory_client.patch("/api/devices/unauthorized/10.0.0.99", json={"status": "approved"}).status_code == 503


def test_watcher_sources_zones_and_policy_context(inventory_client, monkeypatch, tmp_path):
    topology = tmp_path / "topology.json"
    topology.write_text(json.dumps({
        "zones": [
            {"name": "office", "cidrs": ["10.0.0.0/24"]},
            {"name": "restricted", "cidrs": ["10.1.0.0/24"]},
        ],
        "policies": [{"name": "office-restriction", "src_zone": "office", "dst_zone": "restricted", "allowed": False}],
    }))
    monkeypatch.setenv("NSM_TOPOLOGY_FILE", str(topology))
    alerts = tmp_path / "alerts.jsonl"
    alert = json.loads(alerts.read_text())
    alert["dst_ip"] = "10.1.0.20"
    alerts.write_text(json.dumps(alert) + "\n")
    response = inventory_client.get("/api/network-watcher")
    assert response.status_code == 200
    data = response.get_json()
    assert data["source_count"] == 1
    assert data["sources"][0]["ip"] == "10.0.0.99"
    assert data["sources"][0]["critical_count"] == 1
    assert data["topology"]["violations"][0]["status"] == "blocked"
    assert data["topology"]["violations"][0]["policy_name"] == "office-restriction"
    response = inventory_client.get("/network-watcher")
    assert response.status_code == 200
    page = response.get_data(as_text=True)
    initial = page.split('<script id="watcher-data" type="application/json">')[1].split("</script>")[0]
    assert json.loads(initial)["sources"] == data["sources"]
    assert 'class="selected" aria-current="page">◎' in page


def test_watcher_empty_state_and_access(inventory_client, monkeypatch, tmp_path):
    alerts = tmp_path / "empty-alerts.jsonl"
    alerts.write_text("")
    monkeypatch.setenv("NSM_ALERTS_DATA_FILE", str(alerts))
    monkeypatch.setenv("NSM_ALERT_LOG_FILE", str(tmp_path / "missing.log"))
    monkeypatch.setenv("NSM_INCIDENTS_LOG_FILE", str(tmp_path / "missing-incidents.jsonl"))
    monkeypatch.setenv("NSM_SERVERLESS_READ_ONLY", "true")
    data = inventory_client.get("/api/network-watcher").get_json()
    assert data["sources"] == []
    assert data["source_count"] == 0
    assert data["topology"]["observed_paths"] == []
    for path in ["/network-watcher", "/api/network-watcher"]:
        assert inventory_client.get(path, headers={"X-NSM-Role": "viewer"}).status_code == 200
        assert inventory_client.get(path, headers={"X-NSM-Role": "invalid"}).status_code == 403


def test_soc_workspace_shows_all_loaded_matches(inventory_client, tmp_path):
    incidents = tmp_path / "incidents.jsonl"
    incidents.write_text("\n".join(json.dumps({
        "incident_id": f"INC-QUEUE-{index:02d}", "created_at": 1775344876.0 + index,
        "status": "open", "severity": "HIGH", "threat_type": "PORT_SCAN",
        "src_ip": "10.0.0.99", "metadata": {},
    }) for index in range(20)) + "\n")
    response = inventory_client.get("/soc-management")
    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert 'class="selected" aria-current="page">▤' in page
    assert 'href="/static/soc.css"' in page
    assert "20 incidents shown" in page
    for index in range(20):
        assert f"INC-QUEUE-{index:02d}" in page
    assert page.index("Incident Queue Filters") < page.index("Incident Cases") < page.index("Avg Time To Assign")
    assert inventory_client.get("/static/soc.css").status_code == 200


def test_intel_workspace_lookup_and_asset_link(inventory_client):
    response = inventory_client.get("/threat-intel")
    assert response.status_code == 200
    assert "Start with a signal" in response.get_data(as_text=True)
    response = inventory_client.get("/threat-intel?indicator=10.0.0.99&type=ip")
    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert "Malicious" in page
    assert "Port Scan" in page
    assert "sentinelnet-mock-intel" in page
    assert "not externally verified" in page
    assert 'class="selected" aria-current="page">◇' in page
    device = inventory_client.get("/devices/10.0.0.99").get_data(as_text=True)
    assert "Look up intelligence" in device
    assert "/threat-intel?indicator=10.0.0.99&amp;type=ip" in device


def test_intel_workspace_validation(inventory_client):
    for query in ("indicator=not-an-ip&type=ip", "indicator=", "indicator=" + "a" * 2049):
        assert inventory_client.get("/threat-intel?" + query).status_code == 400
        response = inventory_client.get("/api/threat-intel?" + query)
        assert response.status_code == 400
        assert "message" in response.get_json()
    response = inventory_client.get("/threat-intel?indicator=not-an-ip&type=ip")
    assert "valid IPv4 or IPv6" in response.get_data(as_text=True)


def test_intel_workspace_escapes_indicators_and_checks_access(inventory_client):
    response = inventory_client.get("/threat-intel", query_string={"indicator": "<script>unsafe()</script>"})
    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert "<script>unsafe()" not in page
    assert "&lt;script&gt;unsafe()&lt;/script&gt;" in page
    for path in ("/threat-intel?indicator=10.0.0.99", "/api/threat-intel?indicator=10.0.0.99"):
        assert inventory_client.get(path, headers={"X-NSM-Role": "viewer"}).status_code == 200
        assert inventory_client.get(path, headers={"X-NSM-Role": "invalid"}).status_code == 403


def test_home_shows_workspace_data_and_next_steps(inventory_client):
    response = inventory_client.get("/")
    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert "Your security workspace" in page
    assert "Generate a signal. Follow the evidence." in page
    assert "1 managed" in page
    assert 'href="/threat-intel"' in page
    assert 'class="selected" aria-current="page">⌂' in page
    assert "python -m network_security_monitor --simulate --no-dashboard" in page
    assert inventory_client.get("/static/home.js").status_code == 200


def test_home_first_run_and_serverless_guidance(inventory_client, monkeypatch, tmp_path):
    monkeypatch.setenv("NSM_ALERTS_DATA_FILE", str(tmp_path / "missing-alerts.jsonl"))
    monkeypatch.setenv("NSM_ALERT_LOG_FILE", str(tmp_path / "missing.log"))
    monkeypatch.setenv("NSM_INCIDENTS_LOG_FILE", str(tmp_path / "missing-incidents.jsonl"))
    monkeypatch.setenv("NSM_SERVERLESS_READ_ONLY", "true")
    monkeypatch.setenv("VERCEL", "1")
    page = inventory_client.get("/").get_data(as_text=True)
    assert "See your first security signal" in page
    assert "does not upload artifacts here" in page
    assert "Read-only storage mode" in page
    assert "incident and device review edits are disabled" in page
    assert not (tmp_path / "missing-incidents.db").exists()


def test_home_respects_viewer_access(inventory_client):
    response = inventory_client.get("/", headers={"X-NSM-Role": "viewer"})
    assert response.status_code == 200
    assert "Analyst or admin access is required" in response.get_data(as_text=True)
    assert inventory_client.get("/", headers={"X-NSM-Role": "invalid"}).status_code == 403
