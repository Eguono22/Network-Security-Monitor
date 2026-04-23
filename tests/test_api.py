"""Tests for Vercel API routes."""

import csv
import json
import os
import shutil
import uuid
from io import StringIO
from pathlib import Path

import pytest


class TestApiRoutes:
    def test_api_alerts_prefers_structured_alert_store(self):
        pytest.importorskip("flask")
        from api.index import app

        tmp_root = Path(".test_tmp") / f"api-alerts-{uuid.uuid4().hex}"
        tmp_root.mkdir(parents=True, exist_ok=True)
        alerts_path = tmp_root / "alerts.jsonl"
        alerts_path.write_text(
            json.dumps(
                {
                    "timestamp": 1775344876.0,
                    "iso_time": "2026-04-03T19:07:56+00:00",
                    "severity": "HIGH",
                    "threat_type": "PORT_SCAN",
                    "src_ip": "10.0.0.99",
                    "description": "Port scan detected",
                    "metadata": {},
                    "incident_ids": ["INC-PORTSCAN1"],
                    "raw": "[2026-04-03 00:07:53] [HIGH] [PORT_SCAN] src=10.0.0.99 Port scan detected",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        prior = os.environ.get("NSM_ALERTS_DATA_FILE")
        os.environ["NSM_ALERTS_DATA_FILE"] = str(alerts_path)
        try:
            client = app.test_client()
            res = client.get("/api/alerts")
            assert res.status_code == 200
            payload = res.get_json()
            assert payload["count"] == 1
            assert payload["alerts"][0]["src_ip"] == "10.0.0.99"
            assert payload["alerts"][0]["threat_type"] == "PORT_SCAN"
            assert payload["alerts"][0]["incident_ids"] == ["INC-PORTSCAN1"]
        finally:
            if prior is None:
                os.environ.pop("NSM_ALERTS_DATA_FILE", None)
            else:
                os.environ["NSM_ALERTS_DATA_FILE"] = prior
            shutil.rmtree(tmp_root, ignore_errors=True)

    def test_api_incidents_returns_payload_shape(self):
        pytest.importorskip("flask")
        from api.index import app

        tmp_root = Path(".test_tmp") / f"api-{uuid.uuid4().hex}"
        tmp_root.mkdir(parents=True, exist_ok=True)
        incidents_path = tmp_root / "incidents.jsonl"
        incidents_path.write_text(
            json.dumps(
                {
                    "incident_id": "INC-TEST123",
                    "status": "open",
                    "severity": "HIGH",
                    "queue": "soc-triage",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        prior = os.environ.get("NSM_INCIDENTS_LOG_FILE")
        os.environ["NSM_INCIDENTS_LOG_FILE"] = str(incidents_path)
        try:
            client = app.test_client()
            res = client.get("/api/incidents")
            assert res.status_code == 200
            payload = res.get_json()
            assert payload["count"] == 1
            assert payload["incidents"][0]["incident_id"] == "INC-TEST123"
        finally:
            if prior is None:
                os.environ.pop("NSM_INCIDENTS_LOG_FILE", None)
            else:
                os.environ["NSM_INCIDENTS_LOG_FILE"] = prior
            shutil.rmtree(tmp_root, ignore_errors=True)

    def test_api_devices_returns_inventory_with_seed_context(self):
        pytest.importorskip("flask")
        from api.index import app

        tmp_root = Path(".test_tmp") / f"api-devices-{uuid.uuid4().hex}"
        tmp_root.mkdir(parents=True, exist_ok=True)
        incidents_path = tmp_root / "incidents.jsonl"
        seed_path = tmp_root / "devices.json"
        alert_log_path = tmp_root / "alerts.log"
        incidents_path.write_text(
            json.dumps(
                {
                    "incident_id": "INC-DEV1",
                    "created_at": 1,
                    "updated_at": 2,
                    "status": "open",
                    "severity": "CRITICAL",
                    "queue": "soc-triage",
                    "threat_type": "MALICIOUS_IP",
                    "src_ip": "10.0.0.5",
                    "dst_port": 443,
                    "metadata": {"tags": ["production"]},
                }
            )
            + "\n",
            encoding="utf-8",
        )
        seed_path.write_text(
            json.dumps(
                {
                    "devices": [
                        {
                            "ip": "10.0.0.5",
                            "hostname": "db-01",
                            "vendor": "Dell",
                            "os": "Ubuntu",
                            "open_ports": [22],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        prior_incidents = os.environ.get("NSM_INCIDENTS_LOG_FILE")
        prior_inventory = os.environ.get("NSM_DEVICE_INVENTORY_FILE")
        prior_alert_log = os.environ.get("NSM_ALERT_LOG_FILE")
        os.environ["NSM_INCIDENTS_LOG_FILE"] = str(incidents_path)
        os.environ["NSM_DEVICE_INVENTORY_FILE"] = str(seed_path)
        os.environ["NSM_ALERT_LOG_FILE"] = str(tmp_root / "alerts.log")
        try:
            client = app.test_client()
            res = client.get("/api/devices?q=10.0.0.5", headers={"X-NSM-Role": "viewer"})
            assert res.status_code == 200
            payload = res.get_json()
            assert payload["count"] == 1
            device = payload["devices"][0]
            assert device["ip"] == "10.0.0.5"
            assert device["hostname"] == "db-01"
            assert device["vendor"] == "Dell"
            assert device["risk_level"] in {"high", "critical"}

            detail = client.get("/api/devices/10.0.0.5", headers={"X-NSM-Role": "viewer"})
            assert detail.status_code == 200
            detail_payload = detail.get_json()
            assert detail_payload["open_ports"] == [22, 443]
        finally:
            if prior_incidents is None:
                os.environ.pop("NSM_INCIDENTS_LOG_FILE", None)
            else:
                os.environ["NSM_INCIDENTS_LOG_FILE"] = prior_incidents
            if prior_inventory is None:
                os.environ.pop("NSM_DEVICE_INVENTORY_FILE", None)
            else:
                os.environ["NSM_DEVICE_INVENTORY_FILE"] = prior_inventory
            if prior_alert_log is None:
                os.environ.pop("NSM_ALERT_LOG_FILE", None)
            else:
                os.environ["NSM_ALERT_LOG_FILE"] = prior_alert_log
            shutil.rmtree(tmp_root, ignore_errors=True)

    def test_api_unauthorized_devices_lists_unmanaged_assets(self):
        pytest.importorskip("flask")
        from api.index import app

        tmp_root = Path(".test_tmp") / f"api-unauth-devices-{uuid.uuid4().hex}"
        tmp_root.mkdir(parents=True, exist_ok=True)
        incidents_path = tmp_root / "incidents.jsonl"
        alerts_path = tmp_root / "alerts.jsonl"
        seed_path = tmp_root / "devices.json"
        alert_log_path = tmp_root / "alerts.log"
        incidents_path.write_text(
            json.dumps(
                {
                    "incident_id": "INC-UNAUTH1",
                    "created_at": 1,
                    "updated_at": 2,
                    "status": "open",
                    "severity": "HIGH",
                    "queue": "soc-triage",
                    "threat_type": "PORT_SCAN",
                    "src_ip": "10.0.0.77",
                    "metadata": {},
                }
            )
            + "\n",
            encoding="utf-8",
        )
        alerts_path.write_text("", encoding="utf-8")
        seed_path.write_text(json.dumps({"devices": []}), encoding="utf-8")
        prior_incidents = os.environ.get("NSM_INCIDENTS_LOG_FILE")
        prior_alerts = os.environ.get("NSM_ALERTS_DATA_FILE")
        prior_inventory = os.environ.get("NSM_DEVICE_INVENTORY_FILE")
        prior_alert_log = os.environ.get("NSM_ALERT_LOG_FILE")
        try:
            os.environ["NSM_INCIDENTS_LOG_FILE"] = str(incidents_path)
            os.environ["NSM_ALERTS_DATA_FILE"] = str(alerts_path)
            os.environ["NSM_DEVICE_INVENTORY_FILE"] = str(seed_path)
            os.environ["NSM_ALERT_LOG_FILE"] = str(alert_log_path)

            client = app.test_client()
            res = client.get("/api/devices/unauthorized?q=10.0.0.77", headers={"X-NSM-Role": "viewer"})
            assert res.status_code == 200
            payload = res.get_json()
            assert payload["count"] == 1
            assert payload["devices"][0]["ip"] == "10.0.0.77"
            assert payload["devices"][0]["status"] == "new"
        finally:
            if prior_incidents is None:
                os.environ.pop("NSM_INCIDENTS_LOG_FILE", None)
            else:
                os.environ["NSM_INCIDENTS_LOG_FILE"] = prior_incidents
            if prior_alerts is None:
                os.environ.pop("NSM_ALERTS_DATA_FILE", None)
            else:
                os.environ["NSM_ALERTS_DATA_FILE"] = prior_alerts
            if prior_inventory is None:
                os.environ.pop("NSM_DEVICE_INVENTORY_FILE", None)
            else:
                os.environ["NSM_DEVICE_INVENTORY_FILE"] = prior_inventory
            if prior_alert_log is None:
                os.environ.pop("NSM_ALERT_LOG_FILE", None)
            else:
                os.environ["NSM_ALERT_LOG_FILE"] = prior_alert_log
            shutil.rmtree(tmp_root, ignore_errors=True)

    def test_api_unauthorized_device_update_persists_status(self):
        pytest.importorskip("flask")
        from api.index import app

        tmp_root = Path(".test_tmp") / f"api-unauth-update-{uuid.uuid4().hex}"
        tmp_root.mkdir(parents=True, exist_ok=True)
        incidents_path = tmp_root / "incidents.jsonl"
        alerts_path = tmp_root / "alerts.jsonl"
        seed_path = tmp_root / "devices.json"
        review_path = tmp_root / "unauthorized.jsonl"
        alert_log_path = tmp_root / "alerts.log"
        incidents_path.write_text(
            json.dumps(
                {
                    "incident_id": "INC-UNAUTH2",
                    "created_at": 1,
                    "updated_at": 2,
                    "status": "open",
                    "severity": "CRITICAL",
                    "queue": "soc-triage",
                    "threat_type": "MALICIOUS_IP",
                    "src_ip": "10.0.0.88",
                    "metadata": {},
                }
            )
            + "\n",
            encoding="utf-8",
        )
        alerts_path.write_text("", encoding="utf-8")
        seed_path.write_text(json.dumps({"devices": []}), encoding="utf-8")
        prior_incidents = os.environ.get("NSM_INCIDENTS_LOG_FILE")
        prior_alerts = os.environ.get("NSM_ALERTS_DATA_FILE")
        prior_inventory = os.environ.get("NSM_DEVICE_INVENTORY_FILE")
        prior_review = os.environ.get("NSM_UNAUTHORIZED_DEVICES_FILE")
        prior_alert_log = os.environ.get("NSM_ALERT_LOG_FILE")
        try:
            os.environ["NSM_INCIDENTS_LOG_FILE"] = str(incidents_path)
            os.environ["NSM_ALERTS_DATA_FILE"] = str(alerts_path)
            os.environ["NSM_DEVICE_INVENTORY_FILE"] = str(seed_path)
            os.environ["NSM_UNAUTHORIZED_DEVICES_FILE"] = str(review_path)
            os.environ["NSM_ALERT_LOG_FILE"] = str(alert_log_path)

            client = app.test_client()
            res = client.patch(
                "/api/devices/unauthorized/10.0.0.88",
                json={"status": "investigating", "notes": "triaging", "owner": "alice"},
                headers={"X-NSM-Role": "analyst"},
            )
            assert res.status_code == 200
            payload = res.get_json()
            assert payload["status"] == "investigating"
            assert payload["notes"] == "triaging"
            assert payload["owner"] == "alice"

            detail = client.get("/api/devices/unauthorized/10.0.0.88", headers={"X-NSM-Role": "viewer"})
            assert detail.status_code == 200
            detail_payload = detail.get_json()
            assert detail_payload["status"] == "investigating"
            assert detail_payload["owner"] == "alice"
        finally:
            if prior_incidents is None:
                os.environ.pop("NSM_INCIDENTS_LOG_FILE", None)
            else:
                os.environ["NSM_INCIDENTS_LOG_FILE"] = prior_incidents
            if prior_alerts is None:
                os.environ.pop("NSM_ALERTS_DATA_FILE", None)
            else:
                os.environ["NSM_ALERTS_DATA_FILE"] = prior_alerts
            if prior_inventory is None:
                os.environ.pop("NSM_DEVICE_INVENTORY_FILE", None)
            else:
                os.environ["NSM_DEVICE_INVENTORY_FILE"] = prior_inventory
            if prior_review is None:
                os.environ.pop("NSM_UNAUTHORIZED_DEVICES_FILE", None)
            else:
                os.environ["NSM_UNAUTHORIZED_DEVICES_FILE"] = prior_review
            if prior_alert_log is None:
                os.environ.pop("NSM_ALERT_LOG_FILE", None)
            else:
                os.environ["NSM_ALERT_LOG_FILE"] = prior_alert_log
            shutil.rmtree(tmp_root, ignore_errors=True)

    def test_api_topology_returns_zone_and_violation_summary(self):
        pytest.importorskip("flask")
        from api.index import app

        tmp_root = Path(".test_tmp") / f"api-topology-{uuid.uuid4().hex}"
        tmp_root.mkdir(parents=True, exist_ok=True)
        incidents_path = tmp_root / "incidents.jsonl"
        seed_path = tmp_root / "devices.json"
        topology_path = tmp_root / "topology.json"
        alert_log_path = tmp_root / "alerts.log"
        incidents_path.write_text(
            "\n".join(
                [
                    json.dumps(
                        {
                            "incident_id": "INC-TOP1",
                            "created_at": 1,
                            "updated_at": 2,
                            "status": "open",
                            "severity": "HIGH",
                            "queue": "soc-triage",
                            "threat_type": "PORT_SCAN",
                            "src_ip": "10.0.0.5",
                            "dst_ip": "10.0.1.10",
                        }
                    ),
                    json.dumps(
                        {
                            "incident_id": "INC-TOP2",
                            "created_at": 3,
                            "updated_at": 4,
                            "status": "open",
                            "severity": "CRITICAL",
                            "queue": "soc-triage",
                            "threat_type": "MALICIOUS_IP",
                            "src_ip": "10.0.2.9",
                            "dst_ip": "10.0.1.10",
                        }
                    ),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        seed_path.write_text(
            json.dumps(
                {
                    "devices": [
                        {"ip": "10.0.0.5", "zone": "corp"},
                        {"ip": "10.0.1.10", "zone": "dmz"},
                        {"ip": "10.0.2.9", "zone": "guest"},
                    ]
                }
            ),
            encoding="utf-8",
        )
        topology_path.write_text(
            json.dumps(
                {
                    "zones": [
                        {"name": "corp", "cidrs": ["10.0.0.0/24"]},
                        {"name": "dmz", "cidrs": ["10.0.1.0/24"]},
                        {"name": "guest", "cidrs": ["10.0.2.0/24"]},
                    ],
                    "policies": [
                        {"name": "corp-dmz", "src_zone": "corp", "dst_zone": "dmz", "allowed": True},
                        {"name": "guest-dmz-block", "src_zone": "guest", "dst_zone": "dmz", "allowed": False},
                    ],
                }
            ),
            encoding="utf-8",
        )
        prior_incidents = os.environ.get("NSM_INCIDENTS_LOG_FILE")
        prior_inventory = os.environ.get("NSM_DEVICE_INVENTORY_FILE")
        prior_topology = os.environ.get("NSM_TOPOLOGY_FILE")
        prior_alert_log = os.environ.get("NSM_ALERT_LOG_FILE")
        try:
            os.environ["NSM_INCIDENTS_LOG_FILE"] = str(incidents_path)
            os.environ["NSM_DEVICE_INVENTORY_FILE"] = str(seed_path)
            os.environ["NSM_TOPOLOGY_FILE"] = str(topology_path)
            os.environ["NSM_ALERT_LOG_FILE"] = str(alert_log_path)

            client = app.test_client()
            res = client.get("/api/topology", headers={"X-NSM-Role": "viewer"})
            assert res.status_code == 200
            payload = res.get_json()
            assert any(zone["name"] == "corp" for zone in payload["zones"])
            assert any(path["src_zone"] == "guest" and path["status"] == "blocked" for path in payload["observed_paths"])

            violations = client.get("/api/topology/violations", headers={"X-NSM-Role": "viewer"})
            assert violations.status_code == 200
            violations_payload = violations.get_json()
            assert violations_payload["count"] >= 1
            assert any(item["src_zone"] == "guest" for item in violations_payload["violations"])
        finally:
            if prior_incidents is None:
                os.environ.pop("NSM_INCIDENTS_LOG_FILE", None)
            else:
                os.environ["NSM_INCIDENTS_LOG_FILE"] = prior_incidents
            if prior_inventory is None:
                os.environ.pop("NSM_DEVICE_INVENTORY_FILE", None)
            else:
                os.environ["NSM_DEVICE_INVENTORY_FILE"] = prior_inventory
            if prior_topology is None:
                os.environ.pop("NSM_TOPOLOGY_FILE", None)
            else:
                os.environ["NSM_TOPOLOGY_FILE"] = prior_topology
            if prior_alert_log is None:
                os.environ.pop("NSM_ALERT_LOG_FILE", None)
            else:
                os.environ["NSM_ALERT_LOG_FILE"] = prior_alert_log
            shutil.rmtree(tmp_root, ignore_errors=True)

    def test_api_incidents_supports_filters(self):
        pytest.importorskip("flask")
        from api.index import app

        tmp_root = Path(".test_tmp") / f"api-incidents-{uuid.uuid4().hex}"
        tmp_root.mkdir(parents=True, exist_ok=True)
        incidents_path = tmp_root / "incidents.jsonl"
        incidents_path.write_text(
            "\n".join(
                [
                    json.dumps(
                        {
                            "incident_id": "INC-OPEN1",
                            "created_at": 1,
                            "updated_at": 1,
                            "status": "open",
                            "severity": "HIGH",
                            "queue": "soc-triage",
                            "threat_type": "PORT_SCAN",
                            "src_ip": "1.1.1.1",
                        }
                    ),
                    json.dumps(
                        {
                            "incident_id": "INC-RES1",
                            "created_at": 2,
                            "updated_at": 2,
                            "status": "resolved",
                            "severity": "CRITICAL",
                            "queue": "network-incident",
                            "threat_type": "DDOS",
                            "src_ip": "2.2.2.2",
                        }
                    ),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        prior = os.environ.get("NSM_INCIDENTS_LOG_FILE")
        os.environ["NSM_INCIDENTS_LOG_FILE"] = str(incidents_path)
        try:
            client = app.test_client()
            res = client.get("/api/incidents?status=resolved")
            assert res.status_code == 200
            payload = res.get_json()
            assert payload["count"] == 1
            assert payload["incidents"][0]["incident_id"] == "INC-RES1"
        finally:
            if prior is None:
                os.environ.pop("NSM_INCIDENTS_LOG_FILE", None)
            else:
                os.environ["NSM_INCIDENTS_LOG_FILE"] = prior
            shutil.rmtree(tmp_root, ignore_errors=True)

    def test_api_incidents_supports_active_and_assignee_filters(self):
        pytest.importorskip("flask")
        from api.index import app

        tmp_root = Path(".test_tmp") / f"api-incidents-{uuid.uuid4().hex}"
        tmp_root.mkdir(parents=True, exist_ok=True)
        incidents_path = tmp_root / "incidents.jsonl"
        incidents_path.write_text(
            "\n".join(
                [
                    json.dumps(
                        {
                            "incident_id": "INC-ACT1",
                            "created_at": 1,
                            "updated_at": 3,
                            "status": "assigned",
                            "severity": "HIGH",
                            "queue": "soc-triage",
                            "threat_type": "PORT_SCAN",
                            "src_ip": "1.1.1.1",
                            "assignee": "alice",
                        }
                    ),
                    json.dumps(
                        {
                            "incident_id": "INC-RES1",
                            "created_at": 2,
                            "updated_at": 4,
                            "status": "resolved",
                            "severity": "CRITICAL",
                            "queue": "network-incident",
                            "threat_type": "DDOS",
                            "src_ip": "2.2.2.2",
                            "assignee": "bob",
                        }
                    ),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        prior = os.environ.get("NSM_INCIDENTS_LOG_FILE")
        os.environ["NSM_INCIDENTS_LOG_FILE"] = str(incidents_path)
        try:
            client = app.test_client()
            active = client.get("/api/incidents?status=active")
            assert active.status_code == 200
            active_payload = active.get_json()
            assert active_payload["count"] == 1
            assert active_payload["incidents"][0]["incident_id"] == "INC-ACT1"

            assignee = client.get("/api/incidents?assignee=alice")
            assert assignee.status_code == 200
            assignee_payload = assignee.get_json()
            assert assignee_payload["count"] == 1
            assert assignee_payload["incidents"][0]["incident_id"] == "INC-ACT1"
        finally:
            if prior is None:
                os.environ.pop("NSM_INCIDENTS_LOG_FILE", None)
            else:
                os.environ["NSM_INCIDENTS_LOG_FILE"] = prior
            shutil.rmtree(tmp_root, ignore_errors=True)

    def test_api_incidents_export_csv_returns_filtered_rows(self):
        pytest.importorskip("flask")
        from api.index import app

        tmp_root = Path(".test_tmp") / f"api-incidents-export-{uuid.uuid4().hex}"
        tmp_root.mkdir(parents=True, exist_ok=True)
        incidents_path = tmp_root / "incidents.jsonl"
        incidents_path.write_text(
            "\n".join(
                [
                    json.dumps(
                        {
                            "incident_id": "INC-CSV1",
                            "created_at": 1,
                            "updated_at": 2,
                            "status": "assigned",
                            "severity": "HIGH",
                            "queue": "soc-triage",
                            "threat_type": "PORT_SCAN",
                            "src_ip": "1.1.1.1",
                            "assignee": "alice",
                            "owner": "tier-1",
                            "metadata": {"ticket_id": "SOC-101"},
                        }
                    ),
                    json.dumps(
                        {
                            "incident_id": "INC-CSV2",
                            "created_at": 3,
                            "updated_at": 4,
                            "status": "resolved",
                            "severity": "CRITICAL",
                            "queue": "network-incident",
                            "threat_type": "DDOS",
                            "src_ip": "2.2.2.2",
                            "assignee": "bob",
                            "owner": "tier-2",
                            "metadata": {"ticket_id": "SOC-102"},
                        }
                    ),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        prior = os.environ.get("NSM_INCIDENTS_LOG_FILE")
        os.environ["NSM_INCIDENTS_LOG_FILE"] = str(incidents_path)
        try:
            client = app.test_client()
            res = client.get(
                "/api/incidents/export.csv?status=assigned&assignee=alice",
                headers={"X-NSM-Role": "analyst"},
            )
            assert res.status_code == 200
            assert res.mimetype == "text/csv"
            assert "attachment; filename=" in res.headers["Content-Disposition"]

            rows = list(csv.DictReader(StringIO(res.get_data(as_text=True))))
            assert len(rows) == 1
            assert rows[0]["incident_id"] == "INC-CSV1"
            assert rows[0]["assignee"] == "alice"
            assert json.loads(rows[0]["metadata"]) == {"ticket_id": "SOC-101"}
        finally:
            if prior is None:
                os.environ.pop("NSM_INCIDENTS_LOG_FILE", None)
            else:
                os.environ["NSM_INCIDENTS_LOG_FILE"] = prior
            shutil.rmtree(tmp_root, ignore_errors=True)

    def test_api_incidents_export_csv_denies_viewer_role(self):
        pytest.importorskip("flask")
        from api.index import app

        client = app.test_client()
        res = client.get("/api/incidents/export.csv", headers={"X-NSM-Role": "viewer"})
        assert res.status_code == 403
        payload = res.get_json()
        assert payload["error"] == "insufficient_role"
        assert payload["required_role"] == "analyst"
        assert payload["current_role"] == "viewer"

    def test_api_incident_update_returns_updated_case(self):
        pytest.importorskip("flask")
        from api.index import app

        tmp_root = Path(".test_tmp") / f"api-incident-update-{uuid.uuid4().hex}"
        tmp_root.mkdir(parents=True, exist_ok=True)
        incidents_path = tmp_root / "incidents.jsonl"
        incidents_path.write_text(
            json.dumps(
                {
                    "incident_id": "INC-UPD1",
                    "created_at": 1,
                    "updated_at": 1,
                    "status": "open",
                    "severity": "HIGH",
                    "queue": "soc-triage",
                    "threat_type": "PORT_SCAN",
                    "src_ip": "1.1.1.1",
                    "metadata": {},
                }
            )
            + "\n",
            encoding="utf-8",
        )
        prior = os.environ.get("NSM_INCIDENTS_LOG_FILE")
        os.environ["NSM_INCIDENTS_LOG_FILE"] = str(incidents_path)
        try:
            client = app.test_client()
            res = client.patch(
                "/api/incidents/INC-UPD1",
                json={"status": "assigned", "assignee": "alice", "metadata": {"ticket_id": "SOC-9"}},
                headers={"X-NSM-Role": "analyst"},
            )
            assert res.status_code == 200
            payload = res.get_json()
            assert payload["status"] == "assigned"
            assert payload["assignee"] == "alice"
            assert payload["metadata"]["ticket_id"] == "SOC-9"

            detail = client.get("/api/incidents/INC-UPD1")
            assert detail.status_code == 200
            detail_payload = detail.get_json()
            assert detail_payload["status"] == "assigned"
            assert detail_payload["assignee"] == "alice"
        finally:
            if prior is None:
                os.environ.pop("NSM_INCIDENTS_LOG_FILE", None)
            else:
                os.environ["NSM_INCIDENTS_LOG_FILE"] = prior
            shutil.rmtree(tmp_root, ignore_errors=True)

    def test_api_incident_detail_includes_source_asset_context(self):
        pytest.importorskip("flask")
        from api.index import app

        tmp_root = Path(".test_tmp") / f"api-incident-device-{uuid.uuid4().hex}"
        tmp_root.mkdir(parents=True, exist_ok=True)
        incidents_path = tmp_root / "incidents.jsonl"
        alerts_path = tmp_root / "alerts.jsonl"
        seed_path = tmp_root / "devices.json"
        review_path = tmp_root / "unauthorized.jsonl"
        topology_path = tmp_root / "topology.json"
        incidents_path.write_text(
            json.dumps(
                {
                    "incident_id": "INC-ASSET1",
                    "created_at": 1,
                    "updated_at": 2,
                    "status": "open",
                    "severity": "HIGH",
                    "queue": "soc-triage",
                    "threat_type": "PORT_SCAN",
                    "src_ip": "10.0.0.8",
                    "metadata": {},
                }
            )
            + "\n",
            encoding="utf-8",
        )
        alerts_path.write_text(
            json.dumps(
                {
                    "timestamp": 10,
                    "severity": "HIGH",
                    "threat_type": "PORT_SCAN",
                    "src_ip": "10.0.0.8",
                    "description": "Port scan detected",
                    "metadata": {"hostname": "web-01", "os": "Windows Server"},
                    "incident_ids": ["INC-ASSET1"],
                    "raw": "raw",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        seed_path.write_text(
            json.dumps({"devices": [{"ip": "10.0.0.8", "vendor": "HP"}]}),
            encoding="utf-8",
        )
        topology_path.write_text(
            json.dumps({"zones": [{"name": "edge", "cidrs": ["10.0.0.0/24"]}]}),
            encoding="utf-8",
        )
        prior_incidents = os.environ.get("NSM_INCIDENTS_LOG_FILE")
        prior_alerts = os.environ.get("NSM_ALERTS_DATA_FILE")
        prior_inventory = os.environ.get("NSM_DEVICE_INVENTORY_FILE")
        prior_review = os.environ.get("NSM_UNAUTHORIZED_DEVICES_FILE")
        prior_topology = os.environ.get("NSM_TOPOLOGY_FILE")
        os.environ["NSM_INCIDENTS_LOG_FILE"] = str(incidents_path)
        os.environ["NSM_ALERTS_DATA_FILE"] = str(alerts_path)
        os.environ["NSM_DEVICE_INVENTORY_FILE"] = str(seed_path)
        os.environ["NSM_UNAUTHORIZED_DEVICES_FILE"] = str(review_path)
        os.environ["NSM_TOPOLOGY_FILE"] = str(topology_path)
        try:
            client = app.test_client()
            res = client.get("/api/incidents/INC-ASSET1", headers={"X-NSM-Role": "viewer"})
            assert res.status_code == 200
            payload = res.get_json()
            assert payload["source_asset"]["ip"] == "10.0.0.8"
            assert payload["source_asset"]["vendor"] == "HP"
            assert payload["source_asset"]["hostname"] == "web-01"
            assert payload["source_asset"]["os"] == "Windows Server"
            assert payload["unauthorized_device"] is None
            assert payload["zone_context"]["src_zone"] == "edge"
        finally:
            if prior_incidents is None:
                os.environ.pop("NSM_INCIDENTS_LOG_FILE", None)
            else:
                os.environ["NSM_INCIDENTS_LOG_FILE"] = prior_incidents
            if prior_alerts is None:
                os.environ.pop("NSM_ALERTS_DATA_FILE", None)
            else:
                os.environ["NSM_ALERTS_DATA_FILE"] = prior_alerts
            if prior_inventory is None:
                os.environ.pop("NSM_DEVICE_INVENTORY_FILE", None)
            else:
                os.environ["NSM_DEVICE_INVENTORY_FILE"] = prior_inventory
            if prior_review is None:
                os.environ.pop("NSM_UNAUTHORIZED_DEVICES_FILE", None)
            else:
                os.environ["NSM_UNAUTHORIZED_DEVICES_FILE"] = prior_review
            if prior_topology is None:
                os.environ.pop("NSM_TOPOLOGY_FILE", None)
            else:
                os.environ["NSM_TOPOLOGY_FILE"] = prior_topology
            shutil.rmtree(tmp_root, ignore_errors=True)

    def test_api_incident_update_denies_viewer_role(self):
        pytest.importorskip("flask")
        from api.index import app

        client = app.test_client()
        res = client.patch(
            "/api/incidents/INC-UPD1",
            json={"status": "assigned"},
            headers={"X-NSM-Role": "viewer"},
        )
        assert res.status_code == 403
        payload = res.get_json()
        assert payload["error"] == "insufficient_role"
        assert payload["required_role"] == "analyst"
        assert payload["current_role"] == "viewer"

    def test_api_incident_update_rejects_invalid_status(self):
        pytest.importorskip("flask")
        from api.index import app

        tmp_root = Path(".test_tmp") / f"api-incident-update-{uuid.uuid4().hex}"
        tmp_root.mkdir(parents=True, exist_ok=True)
        incidents_path = tmp_root / "incidents.jsonl"
        incidents_path.write_text(
            json.dumps(
                {
                    "incident_id": "INC-UPD2",
                    "created_at": 1,
                    "updated_at": 1,
                    "status": "open",
                    "severity": "HIGH",
                    "queue": "soc-triage",
                    "threat_type": "PORT_SCAN",
                    "src_ip": "1.1.1.1",
                    "metadata": {},
                }
            )
            + "\n",
            encoding="utf-8",
        )
        prior = os.environ.get("NSM_INCIDENTS_LOG_FILE")
        os.environ["NSM_INCIDENTS_LOG_FILE"] = str(incidents_path)
        try:
            client = app.test_client()
            res = client.patch(
                "/api/incidents/INC-UPD2",
                json={"status": "closed"},
                headers={"X-NSM-Role": "analyst"},
            )
            assert res.status_code == 400
            payload = res.get_json()
            assert payload["error"] == "invalid_incident_update"
        finally:
            if prior is None:
                os.environ.pop("NSM_INCIDENTS_LOG_FILE", None)
            else:
                os.environ["NSM_INCIDENTS_LOG_FILE"] = prior
            shutil.rmtree(tmp_root, ignore_errors=True)

    def test_api_incidents_rejects_invalid_role_header(self):
        pytest.importorskip("flask")
        from api.index import app

        client = app.test_client()
        res = client.get("/api/incidents", headers={"X-NSM-Role": "guest"})
        assert res.status_code == 403
        payload = res.get_json()
        assert payload["error"] == "invalid_role"

    def test_api_threat_intel_uses_local_context(self):
        pytest.importorskip("flask")
        from api.index import app

        tmp_root = Path(".test_tmp") / f"api-intel-{uuid.uuid4().hex}"
        tmp_root.mkdir(parents=True, exist_ok=True)
        alerts_path = tmp_root / "alerts.jsonl"
        incidents_path = tmp_root / "incidents.jsonl"
        alerts_path.write_text(
            json.dumps(
                {
                    "timestamp": 1775344876.0,
                    "iso_time": "2026-04-03T19:07:56+00:00",
                    "severity": "CRITICAL",
                    "threat_type": "MALICIOUS_IP",
                    "src_ip": "203.0.113.5",
                    "description": "Known bad host observed",
                    "metadata": {"incident_ids": ["INC-INTEL1"]},
                    "incident_ids": ["INC-INTEL1"],
                    "raw": "[2026-04-03 00:07:53] [CRITICAL] [MALICIOUS_IP] src=203.0.113.5 Known bad host observed",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        incidents_path.write_text(
            json.dumps(
                {
                    "incident_id": "INC-INTEL1",
                    "created_at": 1,
                    "updated_at": 2,
                    "status": "open",
                    "severity": "CRITICAL",
                    "queue": "threat-intel",
                    "threat_type": "MALICIOUS_IP",
                    "src_ip": "203.0.113.5",
                    "description": "Known bad host observed",
                    "metadata": {},
                }
            )
            + "\n",
            encoding="utf-8",
        )
        prior_alerts = os.environ.get("NSM_ALERTS_DATA_FILE")
        prior_incidents = os.environ.get("NSM_INCIDENTS_LOG_FILE")
        os.environ["NSM_ALERTS_DATA_FILE"] = str(alerts_path)
        os.environ["NSM_INCIDENTS_LOG_FILE"] = str(incidents_path)
        try:
            client = app.test_client()
            res = client.get("/api/threat-intel?indicator=203.0.113.5")
            assert res.status_code == 200
            payload = res.get_json()
            assert payload["indicator"] == "203.0.113.5"
            assert payload["indicator_type"] == "ip"
            assert payload["related"]["alerts"] == 1
            assert payload["related"]["incidents"] == 1
            assert payload["verdict"] in {"suspicious", "malicious"}
            assert "incident-linked" in payload["tags"]
        finally:
            if prior_alerts is None:
                os.environ.pop("NSM_ALERTS_DATA_FILE", None)
            else:
                os.environ["NSM_ALERTS_DATA_FILE"] = prior_alerts
            if prior_incidents is None:
                os.environ.pop("NSM_INCIDENTS_LOG_FILE", None)
            else:
                os.environ["NSM_INCIDENTS_LOG_FILE"] = prior_incidents
            shutil.rmtree(tmp_root, ignore_errors=True)

    def test_api_threat_intel_requires_indicator(self):
        pytest.importorskip("flask")
        from api.index import app

        client = app.test_client()
        res = client.get("/api/threat-intel")
        assert res.status_code == 400
        payload = res.get_json()
        assert payload["error"] == "missing_indicator"

    def test_api_soc_summary_exposes_mttr_sla_and_trends(self):
        pytest.importorskip("flask")
        from api.index import app

        tmp_root = Path(".test_tmp") / f"soc-summary-{uuid.uuid4().hex}"
        tmp_root.mkdir(parents=True, exist_ok=True)
        incidents_path = tmp_root / "incidents.jsonl"
        current_now = os.path.getmtime(__file__)
        incidents_path.write_text(
            "\n".join(
                [
                    json.dumps(
                        {
                            "incident_id": "INC-SUM1",
                            "created_at": current_now - 7200,
                            "updated_at": current_now - 3600,
                            "status": "resolved",
                            "status_changed_at": current_now - 3600,
                            "assigned_at": current_now - 6900,
                            "contained_at": current_now - 5400,
                            "resolved_at": current_now - 3600,
                            "severity": "HIGH",
                            "queue": "soc-triage",
                            "threat_type": "PORT_SCAN",
                            "src_ip": "1.1.1.1",
                            "metadata": {},
                        }
                    ),
                    json.dumps(
                        {
                            "incident_id": "INC-SUM2",
                            "created_at": current_now - 72000,
                            "updated_at": current_now - 1800,
                            "status": "open",
                            "status_changed_at": current_now - 72000,
                            "severity": "CRITICAL",
                            "queue": "soc-triage",
                            "threat_type": "DDOS",
                            "src_ip": "2.2.2.2",
                            "metadata": {},
                        }
                    ),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        prior = os.environ.get("NSM_INCIDENTS_LOG_FILE")
        os.environ["NSM_INCIDENTS_LOG_FILE"] = str(incidents_path)
        try:
            client = app.test_client()
            res = client.get("/api/soc-summary")
            assert res.status_code == 200
            payload = res.get_json()
            metrics = payload["metrics"]
            assert metrics["mttr"]["assignment_avg_seconds"] is not None
            assert metrics["sla"]["breaches"]["assignment"] >= 1
            assert metrics["sla"]["evaluated"]["resolution"] == 2
            assert len(metrics["trends"]["created"]) == 7
            assert len(metrics["trends"]["resolved"]) == 7
        finally:
            if prior is None:
                os.environ.pop("NSM_INCIDENTS_LOG_FILE", None)
            else:
                os.environ["NSM_INCIDENTS_LOG_FILE"] = prior
            shutil.rmtree(tmp_root, ignore_errors=True)

    def test_soc_management_supports_filters_and_detail_view(self):
        pytest.importorskip("flask")
        from api.index import app

        tmp_root = Path(".test_tmp") / f"soc-view-{uuid.uuid4().hex}"
        tmp_root.mkdir(parents=True, exist_ok=True)
        incidents_path = tmp_root / "incidents.jsonl"
        incidents_path.write_text(
            "\n".join(
                [
                    json.dumps(
                        {
                            "incident_id": "INC-SOC1",
                            "created_at": 1,
                            "updated_at": 2,
                            "status": "assigned",
                            "status_changed_at": 2,
                            "assigned_at": 2,
                            "severity": "HIGH",
                            "queue": "soc-triage",
                            "threat_type": "PORT_SCAN",
                            "src_ip": "1.1.1.1",
                            "assignee": "alice",
                            "owner": "tier-1",
                            "description": "Port scan against edge host",
                            "notes": "Needs review",
                            "metadata": {"ticket_id": "SOC-17"},
                        }
                    ),
                    json.dumps(
                        {
                            "incident_id": "INC-SOC2",
                            "created_at": 3,
                            "updated_at": 4,
                            "status": "resolved",
                            "status_changed_at": 4,
                            "resolved_at": 4,
                            "severity": "CRITICAL",
                            "queue": "network-incident",
                            "threat_type": "DDOS",
                            "src_ip": "2.2.2.2",
                            "assignee": "bob",
                            "owner": "tier-2",
                            "description": "Resolved DDoS spike",
                            "metadata": {},
                        }
                    ),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        prior = os.environ.get("NSM_INCIDENTS_LOG_FILE")
        os.environ["NSM_INCIDENTS_LOG_FILE"] = str(incidents_path)
        try:
            client = app.test_client()
            res = client.get(
                "/soc-management?status=assigned&assignee=alice&incident_id=INC-SOC1",
                headers={"X-NSM-Role": "viewer"},
            )
            assert res.status_code == 200
            body = res.get_data(as_text=True)
            assert "Incident Queue Filters" in body
            assert "Avg Time To Assign" in body
            assert "INC-SOC1" in body
            assert "Port scan against edge host" in body
            assert "SOC-17" in body
            assert "Needs review" in body
            assert "Read-only mode active" in body
            assert "Save Incident Update" not in body
            assert "Incidents CSV (analyst+)" in body
            assert "INC-SOC2" not in body
        finally:
            if prior is None:
                os.environ.pop("NSM_INCIDENTS_LOG_FILE", None)
            else:
                os.environ["NSM_INCIDENTS_LOG_FILE"] = prior
            shutil.rmtree(tmp_root, ignore_errors=True)

    def test_soc_management_update_form_redirects_and_persists_changes(self):
        pytest.importorskip("flask")
        from api.index import app

        tmp_root = Path(".test_tmp") / f"soc-update-{uuid.uuid4().hex}"
        tmp_root.mkdir(parents=True, exist_ok=True)
        incidents_path = tmp_root / "incidents.jsonl"
        incidents_path.write_text(
            json.dumps(
                {
                    "incident_id": "INC-SOC-UPD",
                    "created_at": 1,
                    "updated_at": 1,
                    "status": "open",
                    "status_changed_at": 1,
                    "severity": "HIGH",
                    "queue": "soc-triage",
                    "threat_type": "PORT_SCAN",
                    "src_ip": "1.1.1.1",
                    "metadata": {},
                }
            )
            + "\n",
            encoding="utf-8",
        )
        prior = os.environ.get("NSM_INCIDENTS_LOG_FILE")
        os.environ["NSM_INCIDENTS_LOG_FILE"] = str(incidents_path)
        try:
            client = app.test_client()
            res = client.post(
                "/soc-management/incidents/INC-SOC-UPD/update",
                data={
                    "status": "contained",
                    "queue": "tier-2",
                    "assignee": "alice",
                    "owner": "lead-analyst",
                    "notes": "Contained and monitoring.",
                    "filter_status": "active",
                    "filter_assignee": "alice",
                },
                headers={"X-NSM-Role": "analyst"},
                follow_redirects=False,
            )
            assert res.status_code == 303
            location = res.headers["Location"]
            assert "/soc-management?" in location
            assert "incident_id=INC-SOC-UPD" in location
            assert "status=active" in location
            assert "assignee=alice" in location
            assert "message=updated+INC-SOC-UPD" in location

            redirected = client.get(location)
            assert redirected.status_code == 200
            body = redirected.get_data(as_text=True)
            assert "updated INC-SOC-UPD" in body
            assert "Contained and monitoring." in body
            assert "lead-analyst" in body

            detail = client.get("/api/incidents/INC-SOC-UPD")
            payload = detail.get_json()
            assert payload["status"] == "contained"
            assert payload["queue"] == "tier-2"
            assert payload["assignee"] == "alice"
            assert payload["owner"] == "lead-analyst"
            assert payload["notes"] == "Contained and monitoring."
            assert payload["contained_at"] >= payload["created_at"]
        finally:
            if prior is None:
                os.environ.pop("NSM_INCIDENTS_LOG_FILE", None)
            else:
                os.environ["NSM_INCIDENTS_LOG_FILE"] = prior
            shutil.rmtree(tmp_root, ignore_errors=True)
