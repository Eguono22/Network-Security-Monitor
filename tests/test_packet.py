"""Tests for the Packet data model."""

from __future__ import annotations

import pytest
from datetime import datetime

from nsm.packet import Packet


def _packet(**kwargs) -> Packet:
    defaults = dict(
        timestamp=datetime(2024, 1, 1, 12, 0, 0),
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=12345,
        dst_port=80,
        protocol="TCP",
        size=100,
        flags=["SYN"],
    )
    defaults.update(kwargs)
    return Packet(**defaults)


class TestPacketCreation:
    def test_basic_creation(self):
        p = _packet()
        assert p.src_ip == "10.0.0.1"
        assert p.dst_ip == "10.0.0.2"
        assert p.protocol == "TCP"
        assert p.size == 100

    def test_flags_default_empty(self):
        p = _packet(flags=[])
        assert p.flags == []

    def test_udp_protocol(self):
        p = _packet(protocol="UDP")
        assert p.protocol == "UDP"

    def test_icmp_protocol(self):
        p = _packet(protocol="ICMP")
        assert p.protocol == "ICMP"

    def test_other_protocol(self):
        p = _packet(protocol="OTHER")
        assert p.protocol == "OTHER"

    def test_zero_ports_valid(self):
        p = _packet(src_port=0, dst_port=0)
        assert p.src_port == 0

    def test_max_ports_valid(self):
        p = _packet(src_port=65535, dst_port=65535)
        assert p.src_port == 65535

    def test_zero_size(self):
        p = _packet(size=0)
        assert p.size == 0


class TestPacketValidation:
    def test_empty_src_ip_raises(self):
        with pytest.raises(ValueError, match="src_ip"):
            _packet(src_ip="")

    def test_empty_dst_ip_raises(self):
        with pytest.raises(ValueError, match="dst_ip"):
            _packet(dst_ip="")

    def test_invalid_src_port_negative(self):
        with pytest.raises(ValueError, match="src_port"):
            _packet(src_port=-1)

    def test_invalid_src_port_too_high(self):
        with pytest.raises(ValueError, match="src_port"):
            _packet(src_port=65536)

    def test_invalid_dst_port_too_high(self):
        with pytest.raises(ValueError, match="dst_port"):
            _packet(dst_port=70000)

    def test_negative_size_raises(self):
        with pytest.raises(ValueError, match="size"):
            _packet(size=-1)

    def test_unknown_protocol_raises(self):
        with pytest.raises(ValueError, match="Unsupported protocol"):
            _packet(protocol="XYZ")


class TestPacketProperties:
    def test_is_syn_true(self):
        p = _packet(flags=["SYN"])
        assert p.is_syn is True

    def test_is_syn_false_for_synack(self):
        p = _packet(flags=["SYN", "ACK"])
        assert p.is_syn is False

    def test_is_syn_false_for_ack(self):
        p = _packet(flags=["ACK"])
        assert p.is_syn is False

    def test_repr(self):
        p = _packet()
        r = repr(p)
        assert "10.0.0.1" in r
        assert "TCP" in r
