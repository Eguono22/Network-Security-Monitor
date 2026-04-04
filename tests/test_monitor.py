"""Unit tests for NetworkMonitor."""

import time

import pytest

from network_security_monitor.config import Config
from network_security_monitor.models import Packet, ThreatType
from network_security_monitor.monitor import NetworkMonitor


def _cfg(**overrides) -> Config:
    cfg = Config()
    cfg.ALERT_LOG_FILE = "/tmp/test_nsm_alerts.log"
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


class TestNetworkMonitorStats:
    def test_initial_stats_zero(self):
        monitor = NetworkMonitor(_cfg())
        stats = monitor.get_stats()
        assert stats.total_packets == 0
        assert stats.total_bytes == 0

    def test_stats_updated_after_packet(self):
        monitor = NetworkMonitor(_cfg())
        monitor.process_packet(_pkt(protocol="TCP", size=512))
        stats = monitor.get_stats()
        assert stats.total_packets == 1
        assert stats.total_bytes == 512
        assert stats.tcp_packets == 1

    def test_udp_packet_counted(self):
        monitor = NetworkMonitor(_cfg())
        monitor.process_packet(_pkt(protocol="UDP", size=100))
        assert monitor.get_stats().udp_packets == 1

    def test_http_counted_as_tcp(self):
        monitor = NetworkMonitor(_cfg())
        monitor.process_packet(_pkt(protocol="HTTP", dst_port=80, size=128))
        assert monitor.get_stats().tcp_packets == 1

    def test_icmp_packet_counted(self):
        monitor = NetworkMonitor(_cfg())
        monitor.process_packet(_pkt(protocol="ICMP", size=84))
        assert monitor.get_stats().icmp_packets == 1

    def test_dns_packet_counted(self):
        monitor = NetworkMonitor(_cfg())
        monitor.process_packet(_pkt(protocol="DNS", dst_port=53, size=80))
        assert monitor.get_stats().dns_packets == 1

    def test_other_protocol_counted(self):
        monitor = NetworkMonitor(_cfg())
        monitor.process_packet(_pkt(protocol="OTHER", size=40))
        assert monitor.get_stats().other_packets == 1

    def test_multiple_packets_accumulated(self):
        monitor = NetworkMonitor(_cfg())
        for _ in range(5):
            monitor.process_packet(_pkt(size=100))
        stats = monitor.get_stats()
        assert stats.total_packets == 5
        assert stats.total_bytes == 500

    def test_top_talkers_populated(self):
        monitor = NetworkMonitor(_cfg())
        for _ in range(3):
            monitor.process_packet(_pkt(src_ip="10.0.0.1"))
        for _ in range(5):
            monitor.process_packet(_pkt(src_ip="10.0.0.2"))
        stats = monitor.get_stats()
        assert stats.top_talkers["10.0.0.2"] == 5
        assert stats.top_talkers["10.0.0.1"] == 3

    def test_top_ports_populated(self):
        monitor = NetworkMonitor(_cfg())
        for _ in range(4):
            monitor.process_packet(_pkt(dst_port=443))
        stats = monitor.get_stats()
        assert stats.top_ports[443] == 4


class TestNetworkMonitorAlerts:
    def test_no_alert_for_clean_traffic(self):
        monitor = NetworkMonitor(_cfg())
        alerts = monitor.process_packet(_pkt(flags="ACK", dst_port=80))
        assert alerts == []

    def test_alert_emitted_for_suspicious_port(self):
        cfg = _cfg(SUSPICIOUS_PORTS={4444})
        monitor = NetworkMonitor(cfg)
        alerts = monitor.process_packet(_pkt(dst_port=4444))
        assert any(a.threat_type == ThreatType.SUSPICIOUS_PORT for a in alerts)

    def test_alert_stored_in_manager(self):
        cfg = _cfg(SUSPICIOUS_PORTS={4444})
        monitor = NetworkMonitor(cfg)
        monitor.process_packet(_pkt(dst_port=4444))
        am = monitor.get_alert_manager()
        assert am.get_stats()["total"] == 1

    def test_on_alert_callback(self):
        cfg = _cfg(SUSPICIOUS_PORTS={4444})
        monitor = NetworkMonitor(cfg)
        received = []
        monitor.on_alert(received.append)
        monitor.process_packet(_pkt(dst_port=4444))
        assert len(received) == 1
        assert received[0].threat_type == ThreatType.SUSPICIOUS_PORT

    def test_port_scan_detected(self):
        cfg = _cfg(PORT_SCAN_THRESHOLD=10, PORT_SCAN_TIME_WINDOW=30)
        monitor = NetworkMonitor(cfg)
        all_alerts = []
        for port in range(1, 15):
            all_alerts.extend(monitor.process_packet(_pkt(dst_port=port)))
        assert any(a.threat_type == ThreatType.PORT_SCAN for a in all_alerts)

    def test_syn_flood_detected(self):
        cfg = _cfg(SYN_FLOOD_THRESHOLD=10, SYN_FLOOD_TIME_WINDOW=5.0)
        monitor = NetworkMonitor(cfg)
        all_alerts = []
        ts = time.time()
        for i in range(15):
            all_alerts.extend(
                monitor.process_packet(_pkt(flags="SYN", ts=ts + i * 0.01))
            )
        assert any(a.threat_type == ThreatType.SYN_FLOOD for a in all_alerts)

    def test_malicious_ip_detected(self):
        cfg = _cfg(KNOWN_MALICIOUS_IPS={"9.9.9.9"})
        monitor = NetworkMonitor(cfg)
        alerts = monitor.process_packet(_pkt(src_ip="9.9.9.9"))
        assert any(a.threat_type == ThreatType.MALICIOUS_IP for a in alerts)


class TestNetworkMonitorLifecycle:
    def test_is_running_false_initially(self):
        monitor = NetworkMonitor(_cfg())
        assert monitor.is_running is False

    def test_get_alert_manager_returns_instance(self):
        from network_security_monitor.alert_manager import AlertManager
        monitor = NetworkMonitor(_cfg())
        assert isinstance(monitor.get_alert_manager(), AlertManager)

    def test_soc_automation_runs_for_generated_alert(self):
        cfg = _cfg(
            SUSPICIOUS_PORTS={4444},
            SOC_AUTOMATION_MIN_SEVERITY="MEDIUM",
            SOC_AUTOMATION_COOLDOWN_SECONDS=0,
        )
        monitor = NetworkMonitor(cfg)
        monitor.process_packet(_pkt(dst_port=4444))
        stats = monitor.get_soc_automation_stats()
        assert stats["executions"] >= 1
        assert stats["actions"] >= 1
