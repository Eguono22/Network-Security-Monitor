"""Tests for the NetworkSecurityMonitor orchestrator."""

from __future__ import annotations

import pytest
from datetime import datetime, timedelta

from nsm.monitor import NetworkSecurityMonitor
from nsm.packet import Packet


def _ts(offset: float = 0.0) -> datetime:
    return datetime(2024, 1, 1, 12, 0, 0) + timedelta(seconds=offset)


def _pkt(src_ip="10.0.0.1", dst_ip="10.0.0.2", dst_port=80, size=100,
         protocol="TCP", flags=None, ts_offset=0.0) -> Packet:
    return Packet(
        timestamp=_ts(ts_offset),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=50000,
        dst_port=dst_port,
        protocol=protocol,
        size=size,
        flags=flags or [],
    )


class TestNetworkSecurityMonitorIngestion:
    def setup_method(self):
        self.monitor = NetworkSecurityMonitor()

    def test_ingest_stores_packets(self):
        packets = [_pkt(), _pkt()]
        self.monitor.ingest(packets)
        assert len(self.monitor.get_packets()) == 2

    def test_ingest_one(self):
        self.monitor.ingest_one(_pkt())
        assert len(self.monitor.get_packets()) == 1

    def test_ingest_accumulates(self):
        self.monitor.ingest([_pkt() for _ in range(3)])
        self.monitor.ingest([_pkt() for _ in range(2)])
        assert len(self.monitor.get_packets()) == 5

    def test_get_packets_returns_copy(self):
        self.monitor.ingest([_pkt()])
        copy = self.monitor.get_packets()
        copy.clear()
        assert len(self.monitor.get_packets()) == 1

    def test_reset_clears_everything(self):
        self.monitor.ingest([_pkt() for _ in range(5)])
        self.monitor.reset()
        assert self.monitor.get_packets() == []
        assert self.monitor.alert_manager.count() == 0


class TestNetworkSecurityMonitorDetection:
    def setup_method(self):
        self.monitor = NetworkSecurityMonitor()

    def _port_scan_packets(self, src_ip="1.1.1.1") -> list:
        return [
            _pkt(src_ip=src_ip, dst_port=p, ts_offset=i * 0.5)
            for i, p in enumerate(range(1, 25))
        ]

    def _brute_force_packets(self, src_ip="2.2.2.2") -> list:
        return [
            _pkt(src_ip=src_ip, dst_port=22, ts_offset=i * 0.5)
            for i in range(30)
        ]

    def _ddos_packets(self, src_ip="3.3.3.3") -> list:
        return [
            _pkt(src_ip=src_ip, ts_offset=i * 0.05)
            for i in range(120)
        ]

    def test_port_scan_raises_alert(self):
        self.monitor.ingest(self._port_scan_packets())
        alerts = self.monitor.alert_manager.get_alerts(alert_type="PORT_SCAN")
        assert len(alerts) >= 1

    def test_brute_force_raises_alert(self):
        self.monitor.ingest(self._brute_force_packets())
        alerts = self.monitor.alert_manager.get_alerts(alert_type="BRUTE_FORCE")
        assert len(alerts) >= 1

    def test_ddos_raises_alert(self):
        self.monitor.ingest(self._ddos_packets())
        alerts = self.monitor.alert_manager.get_alerts(alert_type="DDOS")
        assert len(alerts) >= 1

    def test_suspicious_port_raises_alert(self):
        self.monitor.ingest([_pkt(dst_port=4444)])
        alerts = self.monitor.alert_manager.get_alerts(alert_type="SUSPICIOUS_PORT")
        assert len(alerts) >= 1

    def test_large_transfer_raises_alert(self):
        packets = [_pkt(size=600_000, ts_offset=i * 2) for i in range(20)]
        self.monitor.ingest(packets)
        alerts = self.monitor.alert_manager.get_alerts(alert_type="LARGE_TRANSFER")
        assert len(alerts) >= 1

    def test_clean_traffic_no_alerts(self):
        # Normal, sparse traffic
        packets = [_pkt(dst_port=443, size=500, ts_offset=i * 10) for i in range(5)]
        self.monitor.ingest(packets)
        assert self.monitor.alert_manager.count() == 0

    def test_multiple_attack_types_detected(self):
        self.monitor.ingest(self._port_scan_packets(src_ip="1.1.1.1"))
        self.monitor.ingest(self._brute_force_packets(src_ip="2.2.2.2"))
        types = {a.alert_type for a in self.monitor.alert_manager.get_all()}
        assert "PORT_SCAN" in types
        assert "BRUTE_FORCE" in types

    def test_analyze_returns_results(self):
        results = self.monitor.analyze(self._port_scan_packets())
        assert any(r.alert_type == "PORT_SCAN" for r in results)

    def test_analyze_uses_stored_packets_when_none_given(self):
        self.monitor.ingest(self._port_scan_packets())
        results = self.monitor.analyze()
        assert any(r.alert_type == "PORT_SCAN" for r in results)
