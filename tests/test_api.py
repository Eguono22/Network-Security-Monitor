"""Tests for Vercel API routes."""

import json
import os
import shutil
import uuid
from pathlib import Path

import pytest


class TestApiRoutes:
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
