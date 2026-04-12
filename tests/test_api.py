"""Tests for Vercel API routes."""

import json
import os
import shutil
import uuid
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
