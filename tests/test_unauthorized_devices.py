"""Tests for unauthorized device lifecycle management."""

from __future__ import annotations

import shutil
import uuid
from pathlib import Path

from network_security_monitor.device_inventory import DeviceInventoryService
from network_security_monitor.unauthorized_devices import (
    UnauthorizedDeviceManager,
    UnauthorizedDeviceValidationError,
)


class TestUnauthorizedDeviceManager:
    def test_list_findings_returns_unmanaged_observed_assets(self):
        manager = UnauthorizedDeviceManager(path="")
        inventory = DeviceInventoryService()

        findings = manager.list_findings(
            inventory=inventory,
            alerts=[
                {
                    "timestamp": 100,
                    "severity": "CRITICAL",
                    "threat_type": "MALICIOUS_IP",
                    "src_ip": "10.0.0.50",
                    "metadata": {"hostname": "rogue-host"},
                }
            ],
            incidents=[
                {
                    "created_at": 90,
                    "updated_at": 110,
                    "severity": "HIGH",
                    "threat_type": "PORT_SCAN",
                    "src_ip": "10.0.0.50",
                }
            ],
        )

        assert len(findings) == 1
        finding = findings[0]
        assert finding["ip"] == "10.0.0.50"
        assert finding["status"] == "new"
        assert finding["observation_status"] == "observed"
        assert finding["source_asset"]["managed"] is False
        assert finding["hostname"] == "rogue-host"

    def test_update_finding_persists_lifecycle_state(self):
        tmp_root = Path(".test_tmp") / f"unauthorized-devices-{uuid.uuid4().hex}"
        tmp_root.mkdir(parents=True, exist_ok=True)
        store_path = tmp_root / "unauthorized.jsonl"
        manager = UnauthorizedDeviceManager(str(store_path))
        inventory = DeviceInventoryService()

        try:
            updated = manager.update_finding(
                "10.0.0.77",
                inventory=inventory,
                alerts=[
                    {
                        "timestamp": 100,
                        "severity": "HIGH",
                        "threat_type": "PORT_SCAN",
                        "src_ip": "10.0.0.77",
                    }
                ],
                incidents=[],
                status="investigating",
                notes="Needs MAC lookup",
                owner="tier-2",
            )
            assert updated is not None
            assert updated["status"] == "investigating"
            assert updated["notes"] == "Needs MAC lookup"
            assert updated["owner"] == "tier-2"

            fetched = manager.get_finding(
                "10.0.0.77",
                inventory=inventory,
                alerts=[],
                incidents=[],
            )
            assert fetched is not None
            assert fetched["status"] == "investigating"
            assert fetched["observation_status"] == "cleared"
        finally:
            shutil.rmtree(tmp_root, ignore_errors=True)

    def test_update_finding_rejects_invalid_status(self):
        manager = UnauthorizedDeviceManager(path="")
        inventory = DeviceInventoryService()

        try:
            manager.update_finding(
                "10.0.0.88",
                inventory=inventory,
                alerts=[
                    {
                        "timestamp": 100,
                        "severity": "HIGH",
                        "threat_type": "PORT_SCAN",
                        "src_ip": "10.0.0.88",
                    }
                ],
                incidents=[],
                status="closed",
            )
        except UnauthorizedDeviceValidationError as exc:
            assert "status must be one of" in str(exc)
        else:
            raise AssertionError("expected UnauthorizedDeviceValidationError")
