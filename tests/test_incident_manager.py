"""Unit tests for incident case persistence."""

import shutil
import time
import uuid
from pathlib import Path

from network_security_monitor.incident_manager import IncidentManager
from network_security_monitor.models import Alert, AlertSeverity, ThreatType


def _make_alert() -> Alert:
    return Alert(
        threat_type=ThreatType.BRUTE_FORCE,
        severity=AlertSeverity.HIGH,
        src_ip="10.1.1.7",
        dst_ip="192.168.1.20",
        description="incident manager test",
        timestamp=time.time(),
    )


class TestIncidentManager:
    def test_create_and_list_cases(self):
        tmp_root = Path(".test_tmp") / f"incident-{uuid.uuid4().hex}"
        tmp_root.mkdir(parents=True, exist_ok=True)
        path = tmp_root / "incidents.jsonl"
        try:
            manager = IncidentManager(str(path))
            case = manager.create_case(_make_alert(), queue="identity-incident")
            assert case["incident_id"].startswith("INC-")
            assert case["status"] == "open"
            assert case["queue"] == "identity-incident"

            listed = manager.list_cases()
            assert len(listed) == 1
            assert listed[0]["incident_id"] == case["incident_id"]
        finally:
            shutil.rmtree(tmp_root, ignore_errors=True)
