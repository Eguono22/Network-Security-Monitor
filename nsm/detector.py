"""Suspicious traffic detectors for the Network Security Monitor.

Each detector analyses a list of Packet objects and returns a list of
DetectionResult objects describing any suspicious behaviour found.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Set

from nsm.alert import AlertSeverity
from nsm.packet import Packet


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class DetectionResult:
    """Holds the outcome of a single detection rule evaluation."""

    detected: bool
    alert_type: str
    severity: AlertSeverity
    source_ip: str
    message: str
    details: Dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Port-scan detector
# ---------------------------------------------------------------------------

class PortScanDetector:
    """Detect port-scanning behaviour.

    An IP is considered to be scanning when it connects to more than
    *threshold* distinct destination ports within *window_seconds*.
    """

    def __init__(self, threshold: int = 15, window_seconds: int = 60) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds

    def analyze(self, packets: List[Packet]) -> List[DetectionResult]:
        """Return a DetectionResult for each IP that exceeds the port-scan threshold."""
        window = timedelta(seconds=self.window_seconds)
        # src_ip -> sorted list of (timestamp, dst_port)
        events: Dict[str, List] = defaultdict(list)
        for pkt in packets:
            events[pkt.src_ip].append((pkt.timestamp, pkt.dst_port))

        results: List[DetectionResult] = []
        for src_ip, ev_list in events.items():
            ev_list.sort(key=lambda x: x[0])
            # Sliding window
            for i, (ts_start, _) in enumerate(ev_list):
                window_ports: Set[int] = set()
                for ts, port in ev_list[i:]:
                    if ts - ts_start > window:
                        break
                    window_ports.add(port)
                if len(window_ports) >= self.threshold:
                    results.append(DetectionResult(
                        detected=True,
                        alert_type="PORT_SCAN",
                        severity=AlertSeverity.HIGH,
                        source_ip=src_ip,
                        message=(
                            f"Port scan detected: {src_ip} contacted "
                            f"{len(window_ports)} distinct ports in {self.window_seconds}s"
                        ),
                        details={
                            "distinct_ports": len(window_ports),
                            "window_seconds": self.window_seconds,
                            "sample_ports": sorted(window_ports)[:20],
                        },
                    ))
                    break  # one alert per source IP
        return results


# ---------------------------------------------------------------------------
# Brute-force detector
# ---------------------------------------------------------------------------

# Ports commonly targeted by brute-force attacks
_BRUTE_FORCE_PORTS: Set[int] = {21, 22, 23, 25, 110, 143, 389, 445, 1433, 3306, 3389, 5900}


class BruteForceDetector:
    """Detect brute-force login attempts.

    An IP is flagged when it sends more than *threshold* SYN packets to the
    same destination port (one of the well-known service ports) within
    *window_seconds*.
    """

    def __init__(
        self,
        threshold: int = 20,
        window_seconds: int = 30,
        target_ports: Set[int] = None,
    ) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.target_ports: Set[int] = target_ports if target_ports is not None else _BRUTE_FORCE_PORTS

    def analyze(self, packets: List[Packet]) -> List[DetectionResult]:
        """Return a DetectionResult for each (src_ip, dst_port) pair that is brute-forcing."""
        window = timedelta(seconds=self.window_seconds)
        # (src_ip, dst_port) -> sorted timestamps
        events: Dict[tuple, List[datetime]] = defaultdict(list)
        for pkt in packets:
            if pkt.dst_port in self.target_ports:
                events[(pkt.src_ip, pkt.dst_port)].append(pkt.timestamp)

        results: List[DetectionResult] = []
        seen_ips: Set[str] = set()
        for (src_ip, dst_port), timestamps in events.items():
            if src_ip in seen_ips:
                continue
            timestamps.sort()
            for i, ts_start in enumerate(timestamps):
                count = sum(1 for ts in timestamps[i:] if ts - ts_start <= window)
                if count >= self.threshold:
                    severity = (
                        AlertSeverity.CRITICAL if dst_port in {22, 3389}
                        else AlertSeverity.HIGH
                    )
                    results.append(DetectionResult(
                        detected=True,
                        alert_type="BRUTE_FORCE",
                        severity=severity,
                        source_ip=src_ip,
                        message=(
                            f"Brute-force detected: {src_ip} made {count} connection "
                            f"attempts to port {dst_port} in {self.window_seconds}s"
                        ),
                        details={
                            "target_port": dst_port,
                            "attempt_count": count,
                            "window_seconds": self.window_seconds,
                        },
                    ))
                    seen_ips.add(src_ip)
                    break
        return results


# ---------------------------------------------------------------------------
# DDoS detector
# ---------------------------------------------------------------------------

class DDoSDetector:
    """Detect Distributed Denial-of-Service traffic patterns.

    An IP is flagged when it sends more than *threshold* packets to a single
    destination within *window_seconds*.
    """

    def __init__(self, threshold: int = 100, window_seconds: int = 10) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds

    def analyze(self, packets: List[Packet]) -> List[DetectionResult]:
        """Return DetectionResults for IPs sending an excessive number of packets."""
        window = timedelta(seconds=self.window_seconds)
        # (src_ip, dst_ip) -> sorted timestamps
        events: Dict[tuple, List[datetime]] = defaultdict(list)
        for pkt in packets:
            events[(pkt.src_ip, pkt.dst_ip)].append(pkt.timestamp)

        results: List[DetectionResult] = []
        seen: Set[str] = set()
        for (src_ip, dst_ip), timestamps in events.items():
            if src_ip in seen:
                continue
            timestamps.sort()
            for i, ts_start in enumerate(timestamps):
                count = sum(1 for ts in timestamps[i:] if ts - ts_start <= window)
                if count >= self.threshold:
                    results.append(DetectionResult(
                        detected=True,
                        alert_type="DDOS",
                        severity=AlertSeverity.CRITICAL,
                        source_ip=src_ip,
                        message=(
                            f"DDoS flood detected: {src_ip} -> {dst_ip}: "
                            f"{count} packets in {self.window_seconds}s"
                        ),
                        details={
                            "target_ip": dst_ip,
                            "packet_count": count,
                            "window_seconds": self.window_seconds,
                        },
                    ))
                    seen.add(src_ip)
                    break
        return results


# ---------------------------------------------------------------------------
# Suspicious port detector
# ---------------------------------------------------------------------------

# Ports commonly associated with malware C2, backdoors, or well-known exploits
_SUSPICIOUS_PORTS: Set[int] = {
    1337, 4444, 5555, 6666, 6667, 6668, 6669,
    12345, 12346, 31337, 27374, 9999, 7777, 8888,
}


class SuspiciousPortDetector:
    """Detect connections to ports associated with malware or backdoors."""

    def __init__(self, suspicious_ports: Set[int] = None) -> None:
        self.suspicious_ports: Set[int] = (
            suspicious_ports if suspicious_ports is not None else _SUSPICIOUS_PORTS
        )

    def analyze(self, packets: List[Packet]) -> List[DetectionResult]:
        """Return a DetectionResult for each packet destined for a suspicious port."""
        # Deduplicate: one alert per (src_ip, dst_port) pair
        seen: Set[tuple] = set()
        results: List[DetectionResult] = []
        for pkt in packets:
            key = (pkt.src_ip, pkt.dst_port)
            if pkt.dst_port in self.suspicious_ports and key not in seen:
                seen.add(key)
                results.append(DetectionResult(
                    detected=True,
                    alert_type="SUSPICIOUS_PORT",
                    severity=AlertSeverity.MEDIUM,
                    source_ip=pkt.src_ip,
                    message=(
                        f"Connection to suspicious port: {pkt.src_ip} -> "
                        f"{pkt.dst_ip}:{pkt.dst_port}"
                    ),
                    details={
                        "dst_ip": pkt.dst_ip,
                        "dst_port": pkt.dst_port,
                        "protocol": pkt.protocol,
                    },
                ))
        return results


# ---------------------------------------------------------------------------
# Large-transfer detector
# ---------------------------------------------------------------------------

class LargeTransferDetector:
    """Detect unusually large outbound data transfers (potential data exfiltration)."""

    def __init__(
        self,
        threshold_bytes: int = 10_000_000,
        window_seconds: int = 60,
    ) -> None:
        self.threshold_bytes = threshold_bytes
        self.window_seconds = window_seconds

    def analyze(self, packets: List[Packet]) -> List[DetectionResult]:
        """Return DetectionResults for IPs transferring more than the threshold."""
        window = timedelta(seconds=self.window_seconds)
        # src_ip -> sorted list of (timestamp, size)
        events: Dict[str, List] = defaultdict(list)
        for pkt in packets:
            events[pkt.src_ip].append((pkt.timestamp, pkt.size))

        results: List[DetectionResult] = []
        seen: Set[str] = set()
        for src_ip, ev_list in events.items():
            if src_ip in seen:
                continue
            ev_list.sort(key=lambda x: x[0])
            for i, (ts_start, _) in enumerate(ev_list):
                total = sum(
                    sz for ts, sz in ev_list[i:]
                    if ts - ts_start <= window
                )
                if total >= self.threshold_bytes:
                    results.append(DetectionResult(
                        detected=True,
                        alert_type="LARGE_TRANSFER",
                        severity=AlertSeverity.HIGH,
                        source_ip=src_ip,
                        message=(
                            f"Large data transfer detected: {src_ip} sent "
                            f"{total / 1_000_000:.1f} MB in {self.window_seconds}s"
                        ),
                        details={
                            "total_bytes": total,
                            "threshold_bytes": self.threshold_bytes,
                            "window_seconds": self.window_seconds,
                        },
                    ))
                    seen.add(src_ip)
                    break
        return results
