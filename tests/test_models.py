"""Unit tests for data models."""

import time

import pytest

from network_security_monitor.models import (
    Alert,
    AlertSeverity,
    Packet,
    ThreatType,
    TrafficStats,
)


class TestPacket:
    def test_basic_tcp_packet(self):
        pkt = Packet(
            timestamp=time.time(),
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            protocol="TCP",
            src_port=12345,
            dst_port=80,
            size=512,
            flags="SYN",
        )
        assert pkt.src_ip == "192.168.1.1"
        assert pkt.dst_port == 80
        assert pkt.protocol == "TCP"

    def test_has_flag_true(self):
        pkt = Packet(
            timestamp=0.0, src_ip="1.1.1.1", dst_ip="2.2.2.2",
            protocol="TCP", flags="SYN,ACK",
        )
        assert pkt.has_flag("SYN")
        assert pkt.has_flag("ACK")

    def test_has_flag_false(self):
        pkt = Packet(
            timestamp=0.0, src_ip="1.1.1.1", dst_ip="2.2.2.2",
            protocol="TCP", flags="SYN",
        )
        assert not pkt.has_flag("ACK")

    def test_is_syn_true(self):
        pkt = Packet(
            timestamp=0.0, src_ip="1.1.1.1", dst_ip="2.2.2.2",
            protocol="TCP", flags="SYN",
        )
        assert pkt.is_syn is True

    def test_is_syn_false_when_syn_ack(self):
        pkt = Packet(
            timestamp=0.0, src_ip="1.1.1.1", dst_ip="2.2.2.2",
            protocol="TCP", flags="SYN,ACK",
        )
        assert pkt.is_syn is False

    def test_is_dns_by_protocol(self):
        pkt = Packet(
            timestamp=0.0, src_ip="1.1.1.1", dst_ip="8.8.8.8",
            protocol="DNS", dst_port=53,
        )
        assert pkt.is_dns is True

    def test_is_dns_by_port(self):
        pkt = Packet(
            timestamp=0.0, src_ip="1.1.1.1", dst_ip="8.8.8.8",
            protocol="UDP", dst_port=53,
        )
        assert pkt.is_dns is True

    def test_repr(self):
        pkt = Packet(
            timestamp=0.0, src_ip="1.1.1.1", dst_ip="2.2.2.2",
            protocol="TCP", src_port=80, dst_port=8080, size=200,
        )
        r = repr(pkt)
        assert "TCP" in r
        assert "1.1.1.1" in r

    def test_default_payload(self):
        pkt = Packet(timestamp=0.0, src_ip="a", dst_ip="b", protocol="ICMP")
        assert pkt.payload == b""
        assert pkt.flags == ""


class TestAlert:
    def test_str_representation(self):
        alert = Alert(
            threat_type=ThreatType.PORT_SCAN,
            severity=AlertSeverity.HIGH,
            src_ip="10.0.0.1",
            description="Port scan detected",
            timestamp=time.time(),
        )
        s = str(alert)
        assert "PORT_SCAN" in s
        assert "HIGH" in s
        assert "10.0.0.1" in s

    def test_str_includes_dst_port(self):
        alert = Alert(
            threat_type=ThreatType.BRUTE_FORCE,
            severity=AlertSeverity.HIGH,
            src_ip="10.0.0.2",
            dst_ip="10.0.0.3",
            dst_port=22,
            description="Brute force",
        )
        s = str(alert)
        assert "22" in s

    def test_metadata_default_empty(self):
        alert = Alert(
            threat_type=ThreatType.UNKNOWN,
            severity=AlertSeverity.LOW,
            src_ip="1.1.1.1",
            description="test",
        )
        assert alert.metadata == {}

    def test_severity_ordering(self):
        levels = [AlertSeverity.LOW, AlertSeverity.MEDIUM, AlertSeverity.HIGH, AlertSeverity.CRITICAL]
        assert levels[0].value == "LOW"
        assert levels[-1].value == "CRITICAL"


class TestTrafficStats:
    def test_initial_values(self):
        stats = TrafficStats()
        assert stats.total_packets == 0
        assert stats.total_bytes == 0

    def test_packets_per_second(self):
        stats = TrafficStats()
        stats.total_packets = 100
        # elapsed will be ~0; avoid ZeroDivisionError check
        pps = stats.packets_per_second
        assert pps >= 0

    def test_bytes_per_second(self):
        stats = TrafficStats()
        stats.total_bytes = 1024
        bps = stats.bytes_per_second
        assert bps >= 0

    def test_elapsed_seconds_positive(self):
        stats = TrafficStats()
        time.sleep(0.01)
        assert stats.elapsed_seconds > 0
