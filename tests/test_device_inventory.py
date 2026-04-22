"""Tests for device inventory and asset context."""

from __future__ import annotations

import json
import shutil
import uuid
from pathlib import Path

from network_security_monitor.device_inventory import DeviceInventoryService


class TestDeviceInventoryService:
    def test_list_devices_merges_seed_and_observed_context(self):
        tmp_root = Path(".test_tmp") / f"device-inventory-{uuid.uuid4().hex}"
        tmp_root.mkdir(parents=True, exist_ok=True)
        seed_path = tmp_root / "devices.json"
        seed_path.write_text(
            json.dumps(
                {
                    "devices": [
                        {
                            "ip": "10.0.0.5",
                            "hostname": "db-01",
                            "vendor": "Dell",
                            "os": "Ubuntu 24.04",
                            "open_ports": [22, 5432],
                            "tags": ["database"],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        service = DeviceInventoryService(str(seed_path))
        try:
            devices = service.list_devices(
                alerts=[
                    {
                        "timestamp": 100,
                        "severity": "CRITICAL",
                        "threat_type": "MALICIOUS_IP",
                        "src_ip": "10.0.0.5",
                        "dst_port": 443,
                        "metadata": {"tags": ["production"], "open_ports": [8443]},
                    }
                ],
                incidents=[
                    {
                        "created_at": 90,
                        "updated_at": 110,
                        "severity": "HIGH",
                        "threat_type": "PORT_SCAN",
                        "src_ip": "10.0.0.5",
                        "dst_port": 8080,
                        "metadata": {"zone": "dmz"},
                    }
                ],
            )
            assert len(devices) == 1
            device = devices[0]
            assert device["ip"] == "10.0.0.5"
            assert device["hostname"] == "db-01"
            assert device["vendor"] == "Dell"
            assert device["os"] == "Ubuntu 24.04"
            assert device["zone"] == "dmz"
            assert device["incident_count"] == 1
            assert device["alert_count"] == 1
            assert device["risk_level"] in {"high", "critical"}
            assert device["risk_score"] >= 55
            assert device["open_ports"] == [22, 443, 5432, 8080, 8443]
            assert device["tags"] == ["database", "production"]
            assert device["threat_types"] == ["MALICIOUS_IP", "PORT_SCAN"]
        finally:
            shutil.rmtree(tmp_root, ignore_errors=True)

    def test_enrich_incident_attaches_source_asset(self):
        service = DeviceInventoryService()
        enriched = service.enrich_incident(
            {
                "incident_id": "INC-1",
                "src_ip": "10.0.0.8",
                "severity": "HIGH",
            },
            alerts=[
                {
                    "timestamp": 100,
                    "severity": "HIGH",
                    "threat_type": "PORT_SCAN",
                    "src_ip": "10.0.0.8",
                    "metadata": {"hostname": "web-01", "os": "Windows Server"},
                }
            ],
            incidents=[
                {
                    "incident_id": "INC-1",
                    "created_at": 90,
                    "updated_at": 100,
                    "severity": "HIGH",
                    "threat_type": "PORT_SCAN",
                    "src_ip": "10.0.0.8",
                }
            ],
        )
        assert enriched is not None
        assert enriched["source_asset"]["ip"] == "10.0.0.8"
        assert enriched["source_asset"]["hostname"] == "web-01"
        assert enriched["source_asset"]["os"] == "Windows Server"
