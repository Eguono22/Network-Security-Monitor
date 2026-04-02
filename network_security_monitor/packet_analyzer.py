"""Packet analyser – converts raw Scapy packets into normalised :class:`~network_security_monitor.models.Packet` objects."""

from __future__ import annotations

import time
from typing import Optional

from .models import Packet


class PacketAnalyzer:
    """Parse raw Scapy packet objects into normalised :class:`Packet` instances.

    The analyser is intentionally kept thin so that the rest of the system
    works with plain Python dataclasses and has no direct dependency on Scapy.
    When Scapy is not installed (or when testing), callers can construct
    :class:`Packet` objects directly instead of going through this class.
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse(self, raw_packet) -> Optional[Packet]:
        """Convert a Scapy packet *raw_packet* into a :class:`Packet`.

        Returns ``None`` if the packet cannot be parsed (e.g. corrupt data).
        """
        try:
            return self._parse(raw_packet)
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse(self, pkt) -> Packet:
        # Import lazily so the rest of the system can be tested without Scapy.
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.dns import DNS

        timestamp = float(getattr(pkt, "time", time.time()))
        size = len(pkt)
        protocol = "OTHER"
        src_ip = dst_ip = "0.0.0.0"
        src_port = dst_port = None
        flags = ""
        payload = b""

        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

        if pkt.haslayer(DNS):
            protocol = "DNS"
            if pkt.haslayer(UDP):
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
            dns_layer = pkt[DNS]
            try:
                payload = bytes(dns_layer)
            except Exception:
                payload = b""

        elif pkt.haslayer(TCP):
            protocol = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            flags = self._decode_tcp_flags(pkt[TCP].flags)
            try:
                payload = bytes(pkt[TCP].payload)
            except Exception:
                payload = b""
            # Classify HTTP/HTTPS
            if dst_port in (80, 8080) or src_port in (80, 8080):
                protocol = "HTTP"
            elif dst_port == 443 or src_port == 443:
                protocol = "HTTPS"

        elif pkt.haslayer(UDP):
            protocol = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            try:
                payload = bytes(pkt[UDP].payload)
            except Exception:
                payload = b""

        elif pkt.haslayer(ICMP):
            protocol = "ICMP"

        return Packet(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            size=size,
            flags=flags,
            payload=payload,
        )

    @staticmethod
    def _decode_tcp_flags(flags) -> str:
        """Return a comma-separated string of active TCP flag names."""
        flag_map = {
            "F": "FIN",
            "S": "SYN",
            "R": "RST",
            "P": "PSH",
            "A": "ACK",
            "U": "URG",
            "E": "ECE",
            "C": "CWR",
        }
        # Scapy flags can be an int or a FlagValue object; convert to string.
        flag_str = str(flags)
        active = [name for char, name in flag_map.items() if char in flag_str]
        return ",".join(active)
