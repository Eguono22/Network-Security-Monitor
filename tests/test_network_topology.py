"""Tests for topology and zone policy evaluation."""

from __future__ import annotations

import json
import shutil
import uuid
from pathlib import Path

from network_security_monitor.network_topology import NetworkTopologyService


class TestNetworkTopologyService:
    def test_summarize_infers_zones_and_flags_unknown_paths(self):
        tmp_root = Path(".test_tmp") / f"topology-{uuid.uuid4().hex}"
        tmp_root.mkdir(parents=True, exist_ok=True)
        topology_path = tmp_root / "topology.json"
        topology_path.write_text(
            json.dumps(
                {
                    "zones": [
                        {"name": "corp", "cidrs": ["10.0.0.0/24"]},
                        {"name": "dmz", "cidrs": ["10.0.1.0/24"]},
                    ],
                    "policies": [
                        {"name": "corp-to-dmz-web", "src_zone": "corp", "dst_zone": "dmz", "allowed": True}
                    ],
                }
            ),
            encoding="utf-8",
        )
        service = NetworkTopologyService(str(topology_path))
        try:
            summary = service.summarize(
                devices=[
                    {"ip": "10.0.0.5"},
                    {"ip": "10.0.1.20"},
                    {"ip": "10.0.2.9", "zone": "guest"},
                ],
                incidents=[
                    {"src_ip": "10.0.0.5", "dst_ip": "10.0.1.20", "threat_type": "PORT_SCAN"},
                    {"src_ip": "10.0.2.9", "dst_ip": "10.0.1.20", "threat_type": "MALICIOUS_IP"},
                ],
            )
            assert len(summary["zones"]) >= 3
            assert any(item["src_zone"] == "guest" and item["status"] == "unknown" for item in summary["violations"])
            assert any(item["src_zone"] == "corp" and item["status"] == "allowed" for item in summary["observed_paths"])
        finally:
            shutil.rmtree(tmp_root, ignore_errors=True)

    def test_enrich_incident_adds_zone_context(self):
        service = NetworkTopologyService()
        enriched = service.enrich_incident(
            {"src_ip": "10.0.0.5", "dst_ip": "10.0.1.10"},
            devices=[
                {"ip": "10.0.0.5", "zone": "corp"},
                {"ip": "10.0.1.10", "zone": "dmz"},
            ],
        )
        assert enriched is not None
        assert enriched["zone_context"]["src_zone"] == "corp"
        assert enriched["zone_context"]["dst_zone"] == "dmz"
