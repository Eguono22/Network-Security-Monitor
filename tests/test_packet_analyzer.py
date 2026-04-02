"""Unit tests for PacketAnalyzer."""

import time

import pytest

from network_security_monitor.packet_analyzer import PacketAnalyzer


class TestPacketAnalyzerFlagDecoding:
    """Test the static TCP flag decoder without needing Scapy live packets."""

    def test_syn_flag(self):
        result = PacketAnalyzer._decode_tcp_flags("S")
        assert "SYN" in result

    def test_syn_ack_flags(self):
        result = PacketAnalyzer._decode_tcp_flags("SA")
        assert "SYN" in result
        assert "ACK" in result

    def test_fin_flag(self):
        result = PacketAnalyzer._decode_tcp_flags("F")
        assert "FIN" in result

    def test_rst_flag(self):
        result = PacketAnalyzer._decode_tcp_flags("R")
        assert "RST" in result

    def test_ack_flag(self):
        result = PacketAnalyzer._decode_tcp_flags("A")
        assert "ACK" in result

    def test_psh_flag(self):
        result = PacketAnalyzer._decode_tcp_flags("P")
        assert "PSH" in result

    def test_no_flags(self):
        result = PacketAnalyzer._decode_tcp_flags("")
        assert result == ""

    def test_all_flags(self):
        result = PacketAnalyzer._decode_tcp_flags("FSRPAUEC")
        for name in ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"):
            assert name in result


class TestPacketAnalyzerParseWithScapy:
    """Integration-style tests that exercise the full parse() path with Scapy."""

    @pytest.fixture(autouse=True)
    def _skip_without_scapy(self):
        pytest.importorskip("scapy")

    def test_parse_tcp_syn(self):
        from scapy.layers.inet import IP, TCP
        from scapy.packet import Packet as ScapyPkt

        raw = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, flags="S")
        analyzer = PacketAnalyzer()
        pkt = analyzer.parse(raw)

        assert pkt is not None
        assert pkt.src_ip == "192.168.1.1"
        assert pkt.dst_ip == "10.0.0.1"
        assert pkt.src_port == 12345
        assert pkt.dst_port == 80
        assert pkt.is_syn is True
        assert pkt.protocol in ("TCP", "HTTP", "HTTPS")

    def test_parse_udp(self):
        from scapy.layers.inet import IP, UDP

        raw = IP(src="1.1.1.1", dst="8.8.8.8") / UDP(sport=54321, dport=53)
        analyzer = PacketAnalyzer()
        pkt = analyzer.parse(raw)

        assert pkt is not None
        assert pkt.protocol in ("UDP", "DNS")
        assert pkt.dst_port == 53

    def test_parse_icmp(self):
        from scapy.layers.inet import IP, ICMP

        raw = IP(src="1.1.1.1", dst="2.2.2.2") / ICMP()
        analyzer = PacketAnalyzer()
        pkt = analyzer.parse(raw)

        assert pkt is not None
        assert pkt.protocol == "ICMP"

    def test_parse_http_classified(self):
        from scapy.layers.inet import IP, TCP

        raw = IP(src="10.0.0.1", dst="93.184.216.34") / TCP(sport=49152, dport=80, flags="S")
        analyzer = PacketAnalyzer()
        pkt = analyzer.parse(raw)

        assert pkt is not None
        assert pkt.protocol == "HTTP"

    def test_parse_returns_none_on_exception(self):
        analyzer = PacketAnalyzer()
        # Pass a non-packet object; _parse will raise, parse() must return None
        result = analyzer.parse(object())
        assert result is None
