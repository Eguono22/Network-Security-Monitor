"""Tests for all suspicious traffic detectors."""

from __future__ import annotations

import pytest
from datetime import datetime, timedelta
from typing import List

from nsm.alert import AlertSeverity
from nsm.detector import (
    BruteForceDetector,
    DDoSDetector,
    LargeTransferDetector,
    PortScanDetector,
    SuspiciousPortDetector,
)
from nsm.packet import Packet


def _ts(offset_seconds: float = 0.0) -> datetime:
    return datetime(2024, 1, 1, 12, 0, 0) + timedelta(seconds=offset_seconds)


def _pkt(
    src_ip="10.0.0.1",
    dst_ip="10.0.0.2",
    src_port=50000,
    dst_port=80,
    protocol="TCP",
    size=100,
    flags=None,
    ts_offset=0.0,
) -> Packet:
    return Packet(
        timestamp=_ts(ts_offset),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        size=size,
        flags=flags or [],
    )


# ---------------------------------------------------------------------------
# PortScanDetector
# ---------------------------------------------------------------------------

class TestPortScanDetector:
    def setup_method(self):
        self.detector = PortScanDetector(threshold=10, window_seconds=60)

    def test_no_scan_few_ports(self):
        packets = [_pkt(dst_port=p, ts_offset=i) for i, p in enumerate([80, 443, 8080])]
        results = self.detector.analyze(packets)
        assert results == []

    def test_detects_scan_above_threshold(self):
        packets = [_pkt(dst_port=p, ts_offset=i * 0.5) for i, p in enumerate(range(1, 20))]
        results = self.detector.analyze(packets)
        assert len(results) == 1
        assert results[0].detected is True
        assert results[0].alert_type == "PORT_SCAN"
        assert results[0].severity == AlertSeverity.HIGH

    def test_scan_outside_window_not_detected(self):
        # 15 ports but spread over 120 s (window = 60 s)
        packets = [_pkt(dst_port=p, ts_offset=i * 8) for i, p in enumerate(range(1, 16))]
        results = self.detector.analyze(packets)
        assert results == []

    def test_one_alert_per_source_ip(self):
        # Same IP hits 30 ports — still only one alert
        packets = [_pkt(dst_port=p, ts_offset=i * 0.1) for i, p in enumerate(range(1, 31))]
        results = self.detector.analyze(packets)
        assert len(results) == 1

    def test_source_ip_in_result(self):
        packets = [_pkt(src_ip="192.168.1.1", dst_port=p, ts_offset=i) for i, p in enumerate(range(1, 20))]
        results = self.detector.analyze(packets)
        assert results[0].source_ip == "192.168.1.1"

    def test_multiple_scanners(self):
        p1 = [_pkt(src_ip="1.1.1.1", dst_port=p, ts_offset=i * 0.5) for i, p in enumerate(range(1, 20))]
        p2 = [_pkt(src_ip="2.2.2.2", dst_port=p, ts_offset=i * 0.5) for i, p in enumerate(range(100, 120))]
        results = self.detector.analyze(p1 + p2)
        ips = {r.source_ip for r in results}
        assert "1.1.1.1" in ips
        assert "2.2.2.2" in ips

    def test_details_contain_distinct_ports(self):
        packets = [_pkt(dst_port=p, ts_offset=i * 0.1) for i, p in enumerate(range(1, 20))]
        results = self.detector.analyze(packets)
        assert results[0].details["distinct_ports"] >= 10

    def test_empty_packets(self):
        assert self.detector.analyze([]) == []


# ---------------------------------------------------------------------------
# BruteForceDetector
# ---------------------------------------------------------------------------

class TestBruteForceDetector:
    def setup_method(self):
        self.detector = BruteForceDetector(threshold=10, window_seconds=30, target_ports={22, 3389})

    def test_no_brute_force_few_attempts(self):
        packets = [_pkt(dst_port=22, ts_offset=i * 3) for i in range(5)]
        assert self.detector.analyze(packets) == []

    def test_detects_ssh_brute_force(self):
        packets = [_pkt(dst_port=22, ts_offset=i * 1) for i in range(15)]
        results = self.detector.analyze(packets)
        assert len(results) == 1
        assert results[0].alert_type == "BRUTE_FORCE"
        assert results[0].severity == AlertSeverity.CRITICAL

    def test_detects_rdp_brute_force(self):
        packets = [_pkt(dst_port=3389, ts_offset=i * 1) for i in range(15)]
        results = self.detector.analyze(packets)
        assert len(results) == 1
        assert results[0].severity == AlertSeverity.CRITICAL

    def test_non_target_port_ignored(self):
        packets = [_pkt(dst_port=8080, ts_offset=i * 1) for i in range(30)]
        assert self.detector.analyze(packets) == []

    def test_outside_window_not_detected(self):
        # 12 attempts but spread over 90 s (window = 30 s)
        packets = [_pkt(dst_port=22, ts_offset=i * 8) for i in range(12)]
        assert self.detector.analyze(packets) == []

    def test_one_alert_per_ip(self):
        packets = [_pkt(dst_port=22, ts_offset=i * 1) for i in range(30)]
        results = self.detector.analyze(packets)
        assert len(results) == 1

    def test_details_contain_target_port(self):
        packets = [_pkt(dst_port=22, ts_offset=i * 1) for i in range(15)]
        results = self.detector.analyze(packets)
        assert results[0].details["target_port"] == 22

    def test_empty_packets(self):
        assert self.detector.analyze([]) == []

    def test_high_severity_for_non_ssh_rdp(self):
        detector = BruteForceDetector(threshold=5, window_seconds=30, target_ports={21})
        packets = [_pkt(dst_port=21, ts_offset=i * 1) for i in range(10)]
        results = detector.analyze(packets)
        assert results[0].severity == AlertSeverity.HIGH


# ---------------------------------------------------------------------------
# DDoSDetector
# ---------------------------------------------------------------------------

class TestDDoSDetector:
    def setup_method(self):
        self.detector = DDoSDetector(threshold=50, window_seconds=10)

    def test_no_ddos_normal_traffic(self):
        packets = [_pkt(ts_offset=i * 0.5) for i in range(20)]
        assert self.detector.analyze(packets) == []

    def test_detects_flood(self):
        packets = [_pkt(ts_offset=i * 0.1) for i in range(60)]
        results = self.detector.analyze(packets)
        assert len(results) == 1
        assert results[0].alert_type == "DDOS"
        assert results[0].severity == AlertSeverity.CRITICAL

    def test_flood_outside_window_not_detected(self):
        # 60 packets but 15 s gap between batches
        p1 = [_pkt(ts_offset=i * 0.1) for i in range(30)]
        p2 = [_pkt(ts_offset=15 + i * 0.1) for i in range(30)]
        assert self.detector.analyze(p1 + p2) == []

    def test_one_alert_per_source_ip(self):
        packets = [_pkt(ts_offset=i * 0.05) for i in range(200)]
        results = self.detector.analyze(packets)
        assert len(results) == 1

    def test_details_contain_target_ip(self):
        packets = [_pkt(dst_ip="172.16.0.1", ts_offset=i * 0.1) for i in range(60)]
        results = self.detector.analyze(packets)
        assert results[0].details["target_ip"] == "172.16.0.1"

    def test_empty_packets(self):
        assert self.detector.analyze([]) == []


# ---------------------------------------------------------------------------
# SuspiciousPortDetector
# ---------------------------------------------------------------------------

class TestSuspiciousPortDetector:
    def setup_method(self):
        self.detector = SuspiciousPortDetector(suspicious_ports={4444, 1337, 31337})

    def test_normal_port_no_alert(self):
        packets = [_pkt(dst_port=80), _pkt(dst_port=443), _pkt(dst_port=8080)]
        assert self.detector.analyze(packets) == []

    def test_detects_suspicious_port(self):
        packets = [_pkt(dst_port=4444)]
        results = self.detector.analyze(packets)
        assert len(results) == 1
        assert results[0].alert_type == "SUSPICIOUS_PORT"
        assert results[0].severity == AlertSeverity.MEDIUM

    def test_multiple_suspicious_ports(self):
        packets = [_pkt(dst_port=4444), _pkt(dst_port=1337), _pkt(dst_port=31337)]
        results = self.detector.analyze(packets)
        assert len(results) == 3

    def test_deduplicates_same_src_dst_port(self):
        packets = [_pkt(src_ip="1.1.1.1", dst_port=4444) for _ in range(5)]
        results = self.detector.analyze(packets)
        assert len(results) == 1

    def test_different_src_ips_each_alerted(self):
        packets = [
            _pkt(src_ip="1.1.1.1", dst_port=4444),
            _pkt(src_ip="2.2.2.2", dst_port=4444),
        ]
        results = self.detector.analyze(packets)
        assert len(results) == 2

    def test_details_contain_port(self):
        packets = [_pkt(dst_port=4444)]
        results = self.detector.analyze(packets)
        assert results[0].details["dst_port"] == 4444

    def test_empty_packets(self):
        assert self.detector.analyze([]) == []


# ---------------------------------------------------------------------------
# LargeTransferDetector
# ---------------------------------------------------------------------------

class TestLargeTransferDetector:
    def setup_method(self):
        self.detector = LargeTransferDetector(threshold_bytes=1_000_000, window_seconds=60)

    def test_no_alert_small_transfer(self):
        packets = [_pkt(size=1000, ts_offset=i * 5) for i in range(10)]
        assert self.detector.analyze(packets) == []

    def test_detects_large_transfer(self):
        # 10 × 200 KB = 2 MB  (threshold 1 MB)
        packets = [_pkt(size=200_000, ts_offset=i * 5) for i in range(10)]
        results = self.detector.analyze(packets)
        assert len(results) == 1
        assert results[0].alert_type == "LARGE_TRANSFER"
        assert results[0].severity == AlertSeverity.HIGH

    def test_outside_window_not_detected(self):
        # 10 × 200 KB spread at 20 s intervals — only 4 packets fit in the 60 s window
        # (offsets 0, 20, 40, 60 s), giving 4 × 200 KB = 800 KB < 1 MB threshold
        packets = [_pkt(size=200_000, ts_offset=i * 20) for i in range(10)]
        assert self.detector.analyze(packets) == []

    def test_one_alert_per_ip(self):
        packets = [_pkt(size=200_000, ts_offset=i * 5) for i in range(30)]
        results = self.detector.analyze(packets)
        assert len(results) == 1

    def test_multiple_exfiltrators(self):
        p1 = [_pkt(src_ip="1.1.1.1", size=200_000, ts_offset=i * 5) for i in range(10)]
        p2 = [_pkt(src_ip="2.2.2.2", size=200_000, ts_offset=i * 5) for i in range(10)]
        results = self.detector.analyze(p1 + p2)
        ips = {r.source_ip for r in results}
        assert "1.1.1.1" in ips
        assert "2.2.2.2" in ips

    def test_details_contain_total_bytes(self):
        packets = [_pkt(size=200_000, ts_offset=i * 5) for i in range(10)]
        results = self.detector.analyze(packets)
        assert results[0].details["total_bytes"] >= 1_000_000

    def test_empty_packets(self):
        assert self.detector.analyze([]) == []
