"""Tests for storage abstractions."""

import shutil
import time
import uuid
from pathlib import Path

from network_security_monitor.models import Alert, AlertSeverity, ThreatType
from network_security_monitor.storage import AlertRepository, IncidentStore
import json


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

    def test_migrates_legacy_jsonl_into_sqlite_store(self):
        tmp_root = Path(".test_tmp") / f"storage-incidents-{uuid.uuid4().hex}"
        tmp_root.mkdir(parents=True, exist_ok=True)
        legacy_path = tmp_root / "incidents.jsonl"
        legacy_path.write_text(
            "\n".join(
                [
                    json.dumps(
                        {
                            "incident_id": "INC-LEGACY1",
                            "created_at": 1.0,
                            "updated_at": 1.0,
                            "status": "open",
                            "queue": "soc-triage",
                            "severity": "HIGH",
                            "threat_type": "PORT_SCAN",
                            "src_ip": "10.0.0.9",
                            "description": "legacy case",
                            "metadata": {},
                        }
                    ),
                    json.dumps(
                        {
                            "incident_id": "INC-LEGACY1",
                            "created_at": 1.0,
                            "updated_at": 2.0,
                            "status": "assigned",
                            "queue": "soc-triage",
                            "severity": "HIGH",
                            "threat_type": "PORT_SCAN",
                            "src_ip": "10.0.0.9",
                            "description": "legacy case",
                            "assignee": "alice",
                            "metadata": {"ticket_id": "SOC-1"},
                        }
                    ),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        try:
            store = IncidentStore(str(legacy_path))
            cases = store.list_cases()
            assert len(cases) == 1
            assert cases[0]["incident_id"] == "INC-LEGACY1"
            assert cases[0]["status"] == "assigned"
            assert cases[0]["assignee"] == "alice"
            assert (tmp_root / "incidents.db").exists()
        finally:
            shutil.rmtree(tmp_root, ignore_errors=True)
