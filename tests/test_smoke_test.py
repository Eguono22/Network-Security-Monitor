"""Tests for the first-run smoke test helper."""

import json
import shutil
import uuid
from pathlib import Path

import pytest

from network_security_monitor.smoke_test import run_smoke_test


class TestSmokeTest:
    def test_run_smoke_test_writes_demo_artifacts_and_summary(self):
        pytest.importorskip("flask")

        tmp_root = Path(".test_tmp") / f"smoke-{uuid.uuid4().hex}"
        try:
            summary = run_smoke_test(artifact_dir=tmp_root, profile="")

            assert summary["status"] == "ok"
            assert summary["packets_processed"] > 0
            assert summary["alert_count"] >= len(summary["threat_types"])
            assert summary["incident_count"] >= 1
            assert Path(summary["artifacts"]["structured_alerts"]).exists()
            assert Path(summary["artifacts"]["incidents_db"]).exists()

            payload = json.loads(Path(summary["summary_file"]).read_text(encoding="utf-8"))
            assert payload["status"] == "ok"
            assert payload["api"]["health_status"] == 200
            assert payload["api"]["alerts_count"] >= 1
        finally:
            shutil.rmtree(tmp_root, ignore_errors=True)
