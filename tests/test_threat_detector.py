"""Unit tests for ThreatDetector and individual sub-detectors."""

import time

import pytest

from network_security_monitor.config import Config
from network_security_monitor.models import AlertSeverity, Packet, ThreatType
from network_security_monitor.threat_detector import (
    BruteForceDetector,
    DDoSDetector,
    DnsTunnelingDetector,
    MaliciousIPDetector,
    PortScanDetector,
    SuspiciousPortDetector,
    SynFloodDetector,
    ThreatDetector,
)


def _make_config(**overrides) -> Config:
    cfg = Config()
    for k, v in overrides.items():
        setattr(cfg, k, v)
    return cfg


def _pkt(src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol="TCP",
         src_port=12345, dst_port=80, size=60,
         flags="", payload=b"", ts=None) -> Packet:
    return Packet(
        timestamp=ts if ts is not None else time.time(),
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        size=size,
        flags=flags,
        payload=payload,
    )


# ---------------------------------------------------------------------------
# PortScanDetector
# ---------------------------------------------------------------------------

class TestPortScanDetector:
    def test_no_alert_below_threshold(self):
        cfg = _make_config(PORT_SCAN_THRESHOLD=20, PORT_SCAN_TIME_WINDOW=10)
        det = PortScanDetector(cfg)
        for port in range(1, 15):
            alerts = det.inspect(_pkt(dst_port=port))
            assert alerts == []

    def test_alert_at_threshold(self):
        cfg = _make_config(PORT_SCAN_THRESHOLD=10, PORT_SCAN_TIME_WINDOW=30)
        det = PortScanDetector(cfg)
        alerts = []
        for port in range(1, 15):
            alerts.extend(det.inspect(_pkt(dst_port=port)))
        assert any(a.threat_type == ThreatType.PORT_SCAN for a in alerts)

    def test_alert_has_correct_severity(self):
        cfg = _make_config(PORT_SCAN_THRESHOLD=5, PORT_SCAN_TIME_WINDOW=30)
        det = PortScanDetector(cfg)
        all_alerts = []
        for port in range(1, 10):
            all_alerts.extend(det.inspect(_pkt(dst_port=port)))
        port_scan_alerts = [a for a in all_alerts if a.threat_type == ThreatType.PORT_SCAN]
        assert port_scan_alerts[0].severity == AlertSeverity.HIGH

    def test_different_sources_no_crosstalk(self):
        cfg = _make_config(PORT_SCAN_THRESHOLD=5, PORT_SCAN_TIME_WINDOW=30)
        det = PortScanDetector(cfg)
        # Source A scans 3 ports, source B scans 3 ports → neither should trigger
        for port in range(1, 4):
            assert det.inspect(_pkt(src_ip="10.0.0.1", dst_port=port)) == []
            assert det.inspect(_pkt(src_ip="10.0.0.2", dst_port=port)) == []

    def test_alert_suppression_within_window(self):
        cfg = _make_config(PORT_SCAN_THRESHOLD=5, PORT_SCAN_TIME_WINDOW=30)
        det = PortScanDetector(cfg)
        alerts = []
        for port in range(1, 15):
            alerts.extend(det.inspect(_pkt(dst_port=port)))
        # Only one alert should be emitted for the same source within window
        port_scan_alerts = [a for a in alerts if a.threat_type == ThreatType.PORT_SCAN]
        assert len(port_scan_alerts) == 1


# ---------------------------------------------------------------------------
# SynFloodDetector
# ---------------------------------------------------------------------------

class TestSynFloodDetector:
    def test_no_alert_below_threshold(self):
        cfg = _make_config(SYN_FLOOD_THRESHOLD=100, SYN_FLOOD_TIME_WINDOW=1.0)
        det = SynFloodDetector(cfg)
        for _ in range(50):
            assert det.inspect(_pkt(flags="SYN")) == []

    def test_alert_at_threshold(self):
        cfg = _make_config(SYN_FLOOD_THRESHOLD=10, SYN_FLOOD_TIME_WINDOW=5.0)
        det = SynFloodDetector(cfg)
        alerts = []
        ts = time.time()
        for i in range(15):
            alerts.extend(det.inspect(_pkt(flags="SYN", ts=ts + i * 0.01)))
        assert any(a.threat_type == ThreatType.SYN_FLOOD for a in alerts)

    def test_alert_severity_critical(self):
        cfg = _make_config(SYN_FLOOD_THRESHOLD=5, SYN_FLOOD_TIME_WINDOW=5.0)
        det = SynFloodDetector(cfg)
        alerts = []
        ts = time.time()
        for i in range(10):
            alerts.extend(det.inspect(_pkt(flags="SYN", ts=ts + i * 0.01)))
        flood_alerts = [a for a in alerts if a.threat_type == ThreatType.SYN_FLOOD]
        assert flood_alerts[0].severity == AlertSeverity.CRITICAL

    def test_non_syn_packets_ignored(self):
        cfg = _make_config(SYN_FLOOD_THRESHOLD=5, SYN_FLOOD_TIME_WINDOW=5.0)
        det = SynFloodDetector(cfg)
        ts = time.time()
        for i in range(100):
            pkt = _pkt(flags="ACK", ts=ts + i * 0.001)
            assert det.inspect(pkt) == []

    def test_syn_ack_not_counted(self):
        cfg = _make_config(SYN_FLOOD_THRESHOLD=5, SYN_FLOOD_TIME_WINDOW=5.0)
        det = SynFloodDetector(cfg)
        ts = time.time()
        alerts = []
        for i in range(20):
            alerts.extend(det.inspect(_pkt(flags="SYN,ACK", ts=ts + i * 0.01)))
        assert not any(a.threat_type == ThreatType.SYN_FLOOD for a in alerts)


# ---------------------------------------------------------------------------
# BruteForceDetector
# ---------------------------------------------------------------------------

class TestBruteForceDetector:
    def test_no_alert_below_threshold(self):
        cfg = _make_config(BRUTE_FORCE_THRESHOLD=10, BRUTE_FORCE_TIME_WINDOW=60,
                           BRUTE_FORCE_PORTS={22})
        det = BruteForceDetector(cfg)
        for _ in range(5):
            assert det.inspect(_pkt(dst_port=22)) == []

    def test_alert_for_ssh_brute_force(self):
        cfg = _make_config(BRUTE_FORCE_THRESHOLD=5, BRUTE_FORCE_TIME_WINDOW=60,
                           BRUTE_FORCE_PORTS={22})
        det = BruteForceDetector(cfg)
        alerts = []
        ts = time.time()
        for i in range(10):
            alerts.extend(det.inspect(_pkt(dst_port=22, ts=ts + i * 0.5)))
        assert any(a.threat_type == ThreatType.BRUTE_FORCE for a in alerts)

    def test_non_auth_port_ignored(self):
        cfg = _make_config(BRUTE_FORCE_THRESHOLD=5, BRUTE_FORCE_TIME_WINDOW=60,
                           BRUTE_FORCE_PORTS={22})
        det = BruteForceDetector(cfg)
        ts = time.time()
        for i in range(20):
            alerts = det.inspect(_pkt(dst_port=80, ts=ts + i * 0.1))
            assert alerts == []

    def test_alert_severity_high(self):
        cfg = _make_config(BRUTE_FORCE_THRESHOLD=3, BRUTE_FORCE_TIME_WINDOW=60,
                           BRUTE_FORCE_PORTS={22})
        det = BruteForceDetector(cfg)
        alerts = []
        ts = time.time()
        for i in range(6):
            alerts.extend(det.inspect(_pkt(dst_port=22, ts=ts + i * 0.1)))
        bf_alerts = [a for a in alerts if a.threat_type == ThreatType.BRUTE_FORCE]
        assert bf_alerts[0].severity == AlertSeverity.HIGH


# ---------------------------------------------------------------------------
# DDoSDetector
# ---------------------------------------------------------------------------

class TestDDoSDetector:
    def test_no_alert_below_threshold(self):
        cfg = _make_config(DDOS_THRESHOLD=1000, DDOS_TIME_WINDOW=1.0)
        det = DDoSDetector(cfg)
        ts = time.time()
        for i in range(500):
            assert det.inspect(_pkt(ts=ts + i * 0.001)) == []

    def test_alert_at_threshold(self):
        cfg = _make_config(DDOS_THRESHOLD=50, DDOS_TIME_WINDOW=1.0)
        det = DDoSDetector(cfg)
        alerts = []
        ts = time.time()
        for i in range(60):
            alerts.extend(det.inspect(_pkt(ts=ts + i * 0.001)))
        assert any(a.threat_type == ThreatType.DDOS for a in alerts)

    def test_alert_severity_critical(self):
        cfg = _make_config(DDOS_THRESHOLD=10, DDOS_TIME_WINDOW=1.0)
        det = DDoSDetector(cfg)
        alerts = []
        ts = time.time()
        for i in range(15):
            alerts.extend(det.inspect(_pkt(ts=ts + i * 0.001)))
        ddos = [a for a in alerts if a.threat_type == ThreatType.DDOS]
        assert ddos[0].severity == AlertSeverity.CRITICAL


# ---------------------------------------------------------------------------
# DnsTunnelingDetector
# ---------------------------------------------------------------------------

class TestDnsTunnelingDetector:
    def test_small_dns_queries_ignored(self):
        cfg = _make_config(DNS_QUERY_SIZE_THRESHOLD=512, DNS_LARGE_QUERY_THRESHOLD=5,
                           DNS_TIME_WINDOW=60)
        det = DnsTunnelingDetector(cfg)
        for _ in range(20):
            pkt = _pkt(protocol="DNS", dst_port=53, payload=b"A" * 100)
            assert det.inspect(pkt) == []

    def test_alert_for_oversized_queries(self):
        cfg = _make_config(DNS_QUERY_SIZE_THRESHOLD=100, DNS_LARGE_QUERY_THRESHOLD=5,
                           DNS_TIME_WINDOW=60)
        det = DnsTunnelingDetector(cfg)
        alerts = []
        ts = time.time()
        for i in range(8):
            pkt = _pkt(protocol="DNS", dst_port=53,
                       payload=b"X" * 200, ts=ts + i * 0.1)
            alerts.extend(det.inspect(pkt))
        assert any(a.threat_type == ThreatType.DNS_TUNNELING for a in alerts)

    def test_non_dns_ignored(self):
        cfg = _make_config(DNS_QUERY_SIZE_THRESHOLD=100, DNS_LARGE_QUERY_THRESHOLD=2,
                           DNS_TIME_WINDOW=60)
        det = DnsTunnelingDetector(cfg)
        # Large HTTP payload should not trigger DNS tunneling
        for _ in range(10):
            pkt = _pkt(protocol="HTTP", dst_port=80, payload=b"X" * 600)
            assert det.inspect(pkt) == []


# ---------------------------------------------------------------------------
# SuspiciousPortDetector
# ---------------------------------------------------------------------------

class TestSuspiciousPortDetector:
    def test_alert_for_known_backdoor_port(self):
        cfg = _make_config(SUSPICIOUS_PORTS={4444, 1337})
        det = SuspiciousPortDetector(cfg)
        pkt = _pkt(dst_port=4444)
        alerts = det.inspect(pkt)
        assert len(alerts) == 1
        assert alerts[0].threat_type == ThreatType.SUSPICIOUS_PORT

    def test_no_alert_for_normal_port(self):
        cfg = _make_config(SUSPICIOUS_PORTS={4444})
        det = SuspiciousPortDetector(cfg)
        assert det.inspect(_pkt(dst_port=80)) == []
        assert det.inspect(_pkt(dst_port=443)) == []

    def test_alert_severity_medium(self):
        cfg = _make_config(SUSPICIOUS_PORTS={4444})
        det = SuspiciousPortDetector(cfg)
        alerts = det.inspect(_pkt(dst_port=4444))
        assert alerts[0].severity == AlertSeverity.MEDIUM

    def test_suppression_within_60s(self):
        cfg = _make_config(SUSPICIOUS_PORTS={4444})
        det = SuspiciousPortDetector(cfg)
        ts = time.time()
        a1 = det.inspect(_pkt(dst_port=4444, ts=ts))
        a2 = det.inspect(_pkt(dst_port=4444, ts=ts + 1))
        assert len(a1) == 1
        assert a2 == []  # suppressed


# ---------------------------------------------------------------------------
# MaliciousIPDetector
# ---------------------------------------------------------------------------

class TestMaliciousIPDetector:
    def test_alert_for_known_bad_src(self):
        cfg = _make_config(KNOWN_MALICIOUS_IPS={"6.6.6.6"})
        det = MaliciousIPDetector(cfg)
        alerts = det.inspect(_pkt(src_ip="6.6.6.6"))
        assert any(a.threat_type == ThreatType.MALICIOUS_IP for a in alerts)

    def test_alert_for_known_bad_dst(self):
        cfg = _make_config(KNOWN_MALICIOUS_IPS={"6.6.6.6"})
        det = MaliciousIPDetector(cfg)
        alerts = det.inspect(_pkt(dst_ip="6.6.6.6"))
        assert any(a.threat_type == ThreatType.MALICIOUS_IP for a in alerts)

    def test_no_alert_for_clean_traffic(self):
        cfg = _make_config(KNOWN_MALICIOUS_IPS={"6.6.6.6"})
        det = MaliciousIPDetector(cfg)
        alerts = det.inspect(_pkt(src_ip="1.1.1.1", dst_ip="8.8.8.8"))
        assert alerts == []

    def test_alert_severity_critical(self):
        cfg = _make_config(KNOWN_MALICIOUS_IPS={"6.6.6.6"})
        det = MaliciousIPDetector(cfg)
        alerts = det.inspect(_pkt(src_ip="6.6.6.6"))
        assert alerts[0].severity == AlertSeverity.CRITICAL


# ---------------------------------------------------------------------------
# ThreatDetector (composite)
# ---------------------------------------------------------------------------

class TestThreatDetector:
    def test_returns_empty_for_clean_packet(self):
        det = ThreatDetector()
        pkt = _pkt(dst_port=80, flags="ACK")
        assert det.inspect(pkt) == []

    def test_detects_suspicious_port(self):
        cfg = _make_config(SUSPICIOUS_PORTS={4444})
        det = ThreatDetector(cfg)
        alerts = det.inspect(_pkt(dst_port=4444))
        assert any(a.threat_type == ThreatType.SUSPICIOUS_PORT for a in alerts)

    def test_detects_malicious_ip(self):
        cfg = _make_config(KNOWN_MALICIOUS_IPS={"1.2.3.4"})
        det = ThreatDetector(cfg)
        alerts = det.inspect(_pkt(src_ip="1.2.3.4"))
        assert any(a.threat_type == ThreatType.MALICIOUS_IP for a in alerts)

    def test_can_detect_multiple_threat_types(self):
        """A single packet can trigger both a suspicious-port and malicious-IP alert."""
        cfg = _make_config(SUSPICIOUS_PORTS={4444}, KNOWN_MALICIOUS_IPS={"1.2.3.4"})
        det = ThreatDetector(cfg)
        alerts = det.inspect(_pkt(src_ip="1.2.3.4", dst_port=4444))
        types = {a.threat_type for a in alerts}
        assert ThreatType.SUSPICIOUS_PORT in types
        assert ThreatType.MALICIOUS_IP in types
