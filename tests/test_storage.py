"""Tests for storage abstractions."""

import shutil
import time
import uuid
from pathlib import Path

from network_security_monitor.models import Alert, AlertSeverity, ThreatType
from network_security_monitor.storage import AlertRepository, IncidentStore


def _make_alert() -> Alert:
    return Alert(
        threat_type=ThreatType.PORT_SCAN,
        severity=AlertSeverity.HIGH,
        src_ip="10.0.0.7",
        dst_ip="192.168.1.10",
        description="storage test alert",
        timestamp=time.time(),
    )


class TestAlertRepository:
    def test_read_recent_falls_back_to_text_log(self):
        tmp_root = Path(".test_tmp") / f"storage-alerts-{uuid.uuid4().hex}"
        tmp_root.mkdir(parents=True, exist_ok=True)
        log_path = tmp_root / "alerts.log"
        log_path.write_text(
            "2026-04-14 12:00:00,000 ERROR [2026-04-14 12:00:00] [HIGH] [PORT_SCAN] src=10.0.0.7 storage test alert\n",
            encoding="utf-8",
        )
        try:
            repository = AlertRepository(log_path=str(log_path))
            alerts = repository.read_recent()
            assert len(alerts) == 1
            assert alerts[0]["severity"] == "HIGH"
            assert alerts[0]["threat_type"] == "PORT_SCAN"
            assert alerts[0]["src_ip"] == "10.0.0.7"
        finally:
            shutil.rmtree(tmp_root, ignore_errors=True)


class TestIncidentStore:
    def test_update_case_materializes_latest_record(self):
        tmp_root = Path(".test_tmp") / f"storage-incidents-{uuid.uuid4().hex}"
        tmp_root.mkdir(parents=True, exist_ok=True)
        path = tmp_root / "incidents.jsonl"
        try:
            store = IncidentStore(str(path))
            case = store.create_case(_make_alert(), queue="soc-triage")
            updated = store.update_case(
                case["incident_id"],
                status="assigned",
                assignee="alice",
                metadata={"ticket_id": "SOC-42"},
            )
            assert updated is not None
            fetched = store.get_case(case["incident_id"])
            assert fetched is not None
            assert fetched["status"] == "assigned"
            assert fetched["assignee"] == "alice"
            assert fetched["metadata"]["ticket_id"] == "SOC-42"
        finally:
            shutil.rmtree(tmp_root, ignore_errors=True)
