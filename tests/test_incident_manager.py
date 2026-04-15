"""Unit tests for incident case persistence."""

import shutil
import time
import uuid
from pathlib import Path

import pytest

from network_security_monitor.incident_manager import IncidentManager, IncidentValidationError
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

    def test_update_case_changes_materialized_state(self):
        tmp_root = Path(".test_tmp") / f"incident-{uuid.uuid4().hex}"
        tmp_root.mkdir(parents=True, exist_ok=True)
        path = tmp_root / "incidents.jsonl"
        try:
            manager = IncidentManager(str(path))
            case = manager.create_case(_make_alert(), queue="identity-incident")
            updated = manager.update_case(
                case["incident_id"],
                status="assigned",
                queue="tier-2",
                assignee="alice",
                metadata={"ticket_id": "SOC-123"},
            )
            assert updated is not None
            assert updated["status"] == "assigned"
            assert updated["queue"] == "tier-2"
            assert updated["assignee"] == "alice"
            assert updated["metadata"]["ticket_id"] == "SOC-123"

            fetched = manager.get_case(case["incident_id"])
            assert fetched is not None
            assert fetched["status"] == "assigned"
            assert fetched["queue"] == "tier-2"
            assert fetched["assignee"] == "alice"
        finally:
            shutil.rmtree(tmp_root, ignore_errors=True)

    def test_list_cases_supports_filters(self):
        tmp_root = Path(".test_tmp") / f"incident-{uuid.uuid4().hex}"
        tmp_root.mkdir(parents=True, exist_ok=True)
        path = tmp_root / "incidents.jsonl"
        try:
            manager = IncidentManager(str(path))
            case_a = manager.create_case(_make_alert(), queue="identity-incident")
            case_b = manager.create_case(_make_alert(), queue="soc-triage")
            manager.update_case(case_b["incident_id"], status="resolved")

            open_cases = manager.list_cases(status="open")
            resolved_cases = manager.list_cases(status="resolved")
            identity_cases = manager.list_cases(queue="identity-incident")

            assert [c["incident_id"] for c in open_cases] == [case_a["incident_id"]]
            assert [c["incident_id"] for c in resolved_cases] == [case_b["incident_id"]]
            assert [c["incident_id"] for c in identity_cases] == [case_a["incident_id"]]
        finally:
            shutil.rmtree(tmp_root, ignore_errors=True)

    def test_update_case_with_assignee_auto_sets_assigned_status(self):
        tmp_root = Path(".test_tmp") / f"incident-{uuid.uuid4().hex}"
        tmp_root.mkdir(parents=True, exist_ok=True)
        path = tmp_root / "incidents.jsonl"
        try:
            manager = IncidentManager(str(path))
            case = manager.create_case(_make_alert())
            updated = manager.update_case(case["incident_id"], assignee="alice")
            assert updated is not None
            assert updated["status"] == "assigned"
            assert updated["assignee"] == "alice"
            assert updated["assigned_at"] >= updated["created_at"]
        finally:
            shutil.rmtree(tmp_root, ignore_errors=True)

    def test_update_case_rejects_invalid_status(self):
        tmp_root = Path(".test_tmp") / f"incident-{uuid.uuid4().hex}"
        tmp_root.mkdir(parents=True, exist_ok=True)
        path = tmp_root / "incidents.jsonl"
        try:
            manager = IncidentManager(str(path))
            case = manager.create_case(_make_alert())
            with pytest.raises(IncidentValidationError):
                manager.update_case(case["incident_id"], status="closed")
        finally:
            shutil.rmtree(tmp_root, ignore_errors=True)

    def test_list_cases_supports_assignee_and_active_filters(self):
        tmp_root = Path(".test_tmp") / f"incident-{uuid.uuid4().hex}"
        tmp_root.mkdir(parents=True, exist_ok=True)
        path = tmp_root / "incidents.jsonl"
        try:
            manager = IncidentManager(str(path))
            case_a = manager.create_case(_make_alert(), queue="identity-incident")
            case_b = manager.create_case(_make_alert(), queue="soc-triage")
            manager.update_case(case_a["incident_id"], assignee="alice")
            manager.update_case(case_b["incident_id"], status="resolved", owner="tier-2")

            alice_cases = manager.list_cases(assignee="alice")
            active_cases = manager.list_cases(status="active")

            assert [c["incident_id"] for c in alice_cases] == [case_a["incident_id"]]
            assert [c["incident_id"] for c in active_cases] == [case_a["incident_id"]]
        finally:
            shutil.rmtree(tmp_root, ignore_errors=True)
