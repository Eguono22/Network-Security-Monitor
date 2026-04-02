"""Packet data model representing a captured network packet."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import List


@dataclass
class Packet:
    """Represents a single captured network packet."""

    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # "TCP", "UDP", "ICMP", etc.
    size: int  # payload size in bytes
    flags: List[str] = field(default_factory=list)  # e.g. ["SYN"], ["ACK"], ["SYN","ACK"]

    def __post_init__(self) -> None:
        if not self.src_ip:
            raise ValueError("src_ip must not be empty")
        if not self.dst_ip:
            raise ValueError("dst_ip must not be empty")
        if not (0 <= self.src_port <= 65535):
            raise ValueError(f"Invalid src_port: {self.src_port}")
        if not (0 <= self.dst_port <= 65535):
            raise ValueError(f"Invalid dst_port: {self.dst_port}")
        if self.size < 0:
            raise ValueError(f"size must be non-negative, got {self.size}")
        if self.protocol not in {"TCP", "UDP", "ICMP", "OTHER"}:
            raise ValueError(f"Unsupported protocol: {self.protocol}")

    @property
    def is_syn(self) -> bool:
        """Return True if this packet has the SYN flag set (and not ACK)."""
        return "SYN" in self.flags and "ACK" not in self.flags

    def __repr__(self) -> str:
        return (
            f"Packet({self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} "
            f"{self.protocol} {self.size}B @ {self.timestamp.isoformat()})"
        )
