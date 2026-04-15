"""Threat detection engine.

Each detector is a stateful object that maintains a sliding-window view of
recent traffic and emits :class:`~network_security_monitor.models.Alert`
objects when an anomaly is detected.

All detectors expose a single public method::

    alerts = detector.inspect(packet)   # returns list[Alert] (may be empty)
"""

from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from typing import List

from .config import Config
from .models import Alert, AlertSeverity, Packet, ThreatType


# ---------------------------------------------------------------------------
# Helper – time-bucketed counter
# ---------------------------------------------------------------------------

class _SlidingWindowCounter:
    """Track timestamped events in a sliding time window."""

    def __init__(self, window_seconds: float):
        self._window = window_seconds
        # deque of (timestamp, value) pairs
        self._events: deque = deque()

    def add(self, value=1, ts: float | None = None) -> None:
        ts = ts if ts is not None else time.time()
        self._events.append((ts, value))
        self._purge(ts)

    def total(self, ts: float | None = None) -> int:
        ts = ts if ts is not None else time.time()
        self._purge(ts)
        return sum(v for _, v in self._events)

    def _purge(self, now: float) -> None:
        cutoff = now - self._window
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()


# ---------------------------------------------------------------------------
# Port-scan detector
# ---------------------------------------------------------------------------

class PortScanDetector:
    """Detect horizontal or vertical port scans from a single source IP.

    A scan is flagged when a single source IP reaches or exceeds
    ``Config.PORT_SCAN_THRESHOLD`` *distinct* destination ports within
    ``Config.PORT_SCAN_TIME_WINDOW`` seconds.
    """

    def __init__(self, config: Config):
        self._cfg = config
        # src_ip → deque of (timestamp, dst_port) tuples
        self._port_windows: defaultdict = defaultdict(deque)
        # track which src IPs have already been alerted (reset periodically)
        self._alerted: dict = {}  # src_ip → last alert timestamp

    def inspect(self, packet: Packet) -> List[Alert]:
        if packet.dst_port is None:
            return []
        if packet.src_ip in self._cfg.PORT_SCAN_TRUSTED_SOURCES:
            return []

        now = packet.timestamp
        window = self._cfg.PORT_SCAN_TIME_WINDOW
        src = packet.src_ip
        dq = self._port_windows[src]

        dq.append((now, packet.dst_port))
        # Purge stale entries
        cutoff = now - window
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        distinct_ports = {port for _, port in dq}

        if len(distinct_ports) >= self._cfg.PORT_SCAN_THRESHOLD:
            # Suppress repeated alerts for the same source
            last = self._alerted.get(src, 0)
            if now - last < window:
                return []
            self._alerted[src] = now
            return [
                Alert(
                    threat_type=ThreatType.PORT_SCAN,
                    severity=AlertSeverity.HIGH,
                    src_ip=src,
                    dst_ip=packet.dst_ip,
                    description=(
                        f"Port scan detected: {len(distinct_ports)} distinct ports "
                        f"contacted within {window}s"
                    ),
                    timestamp=now,
                    metadata={"distinct_ports": len(distinct_ports), "sample_ports": sorted(distinct_ports)[:20]},
                )
            ]
        return []


# ---------------------------------------------------------------------------
# SYN-flood detector
# ---------------------------------------------------------------------------

class SynFloodDetector:
    """Detect SYN-flood attacks from a single source IP.

    Raises a CRITICAL alert when a source IP sends more than
    ``Config.SYN_FLOOD_THRESHOLD`` SYN packets within
    ``Config.SYN_FLOOD_TIME_WINDOW`` seconds.
    """

    def __init__(self, config: Config):
        self._cfg = config
        # src_ip → _SlidingWindowCounter
        self._counters: defaultdict = defaultdict(
            lambda: _SlidingWindowCounter(config.SYN_FLOOD_TIME_WINDOW)
        )
        self._alerted: dict = {}

    def inspect(self, packet: Packet) -> List[Alert]:
        if not packet.is_syn:
            return []

        now = packet.timestamp
        src = packet.src_ip
        counter = self._counters[src]
        counter.add(ts=now)
        count = counter.total(ts=now)

        if count >= self._cfg.SYN_FLOOD_THRESHOLD:
            last = self._alerted.get(src, 0)
            if now - last < self._cfg.SYN_FLOOD_TIME_WINDOW:
                return []
            self._alerted[src] = now
            return [
                Alert(
                    threat_type=ThreatType.SYN_FLOOD,
                    severity=AlertSeverity.CRITICAL,
                    src_ip=src,
                    dst_ip=packet.dst_ip,
                    dst_port=packet.dst_port,
                    description=(
                        f"SYN flood: {count} SYN packets in "
                        f"{self._cfg.SYN_FLOOD_TIME_WINDOW}s"
                    ),
                    timestamp=now,
                    metadata={"syn_count": count},
                )
            ]
        return []


# ---------------------------------------------------------------------------
# Brute-force detector
# ---------------------------------------------------------------------------

class BruteForceDetector:
    """Detect brute-force login attempts against authentication services.

    Watches connection attempts (SYN packets) to ports listed in
    ``Config.BRUTE_FORCE_PORTS`` and raises a HIGH alert when a source IP
    exceeds ``Config.BRUTE_FORCE_THRESHOLD`` attempts within
    ``Config.BRUTE_FORCE_TIME_WINDOW`` seconds.
    """

    def __init__(self, config: Config):
        self._cfg = config
        # (src_ip, dst_port) → _SlidingWindowCounter
        self._counters: defaultdict = defaultdict(
            lambda: _SlidingWindowCounter(config.BRUTE_FORCE_TIME_WINDOW)
        )
        self._alerted: dict = {}

    def inspect(self, packet: Packet) -> List[Alert]:
        if packet.dst_port not in self._cfg.BRUTE_FORCE_PORTS:
            return []
        # Only count fresh connection attempts (SYN or any TCP connection)
        if packet.protocol not in ("TCP", "HTTP", "HTTPS"):
            return []

        now = packet.timestamp
        key = (packet.src_ip, packet.dst_port)
        counter = self._counters[key]
        counter.add(ts=now)
        count = counter.total(ts=now)

        if count >= self._cfg.BRUTE_FORCE_THRESHOLD:
            last = self._alerted.get(key, 0)
            if now - last < self._cfg.BRUTE_FORCE_TIME_WINDOW:
                return []
            self._alerted[key] = now
            return [
                Alert(
                    threat_type=ThreatType.BRUTE_FORCE,
                    severity=AlertSeverity.HIGH,
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    dst_port=packet.dst_port,
                    description=(
                        f"Brute-force attempt: {count} connections to port "
                        f"{packet.dst_port} in {self._cfg.BRUTE_FORCE_TIME_WINDOW}s"
                    ),
                    timestamp=now,
                    metadata={"attempt_count": count, "target_port": packet.dst_port},
                )
            ]
        return []


# ---------------------------------------------------------------------------
# DDoS detector
# ---------------------------------------------------------------------------

class DDoSDetector:
    """Detect volumetric DDoS attacks from a single source IP.

    Raises a CRITICAL alert when a source IP sends more than
    ``Config.DDOS_THRESHOLD`` packets per ``Config.DDOS_TIME_WINDOW`` seconds.
    """

    def __init__(self, config: Config):
        self._cfg = config
        self._counters: defaultdict = defaultdict(
            lambda: _SlidingWindowCounter(config.DDOS_TIME_WINDOW)
        )
        self._alerted: dict = {}

    def inspect(self, packet: Packet) -> List[Alert]:
        now = packet.timestamp
        src = packet.src_ip
        counter = self._counters[src]
        counter.add(ts=now)
        count = counter.total(ts=now)

        if count >= self._cfg.DDOS_THRESHOLD:
            last = self._alerted.get(src, 0)
            if now - last < self._cfg.DDOS_TIME_WINDOW:
                return []
            self._alerted[src] = now
            return [
                Alert(
                    threat_type=ThreatType.DDOS,
                    severity=AlertSeverity.CRITICAL,
                    src_ip=src,
                    dst_ip=packet.dst_ip,
                    description=(
                        f"DDoS detected: {count} packets/s from {src}"
                    ),
                    timestamp=now,
                    metadata={"packet_rate": count},
                )
            ]
        return []


# ---------------------------------------------------------------------------
# DNS-tunneling detector
# ---------------------------------------------------------------------------

class DnsTunnelingDetector:
    """Detect DNS tunneling via oversized DNS payloads.

    Raises a MEDIUM alert when a source IP sends more than
    ``Config.DNS_LARGE_QUERY_THRESHOLD`` DNS queries with a payload exceeding
    ``Config.DNS_QUERY_SIZE_THRESHOLD`` bytes within
    ``Config.DNS_TIME_WINDOW`` seconds.
    """

    def __init__(self, config: Config):
        self._cfg = config
        self._counters: defaultdict = defaultdict(
            lambda: _SlidingWindowCounter(config.DNS_TIME_WINDOW)
        )
        self._alerted: dict = {}

    def inspect(self, packet: Packet) -> List[Alert]:
        if not packet.is_dns:
            return []
        if len(packet.payload) < self._cfg.DNS_QUERY_SIZE_THRESHOLD:
            return []

        now = packet.timestamp
        src = packet.src_ip
        self._counters[src].add(ts=now)
        count = self._counters[src].total(ts=now)

        if count >= self._cfg.DNS_LARGE_QUERY_THRESHOLD:
            last = self._alerted.get(src, 0)
            if now - last < self._cfg.DNS_TIME_WINDOW:
                return []
            self._alerted[src] = now
            return [
                Alert(
                    threat_type=ThreatType.DNS_TUNNELING,
                    severity=AlertSeverity.MEDIUM,
                    src_ip=src,
                    dst_ip=packet.dst_ip,
                    dst_port=packet.dst_port,
                    description=(
                        f"DNS tunneling suspected: {count} oversized DNS queries "
                        f"(>{self._cfg.DNS_QUERY_SIZE_THRESHOLD}B) in "
                        f"{self._cfg.DNS_TIME_WINDOW}s"
                    ),
                    timestamp=now,
                    metadata={
                        "large_query_count": count,
                        "payload_size": len(packet.payload),
                    },
                )
            ]
        return []


# ---------------------------------------------------------------------------
# Modbus command spike detector
# ---------------------------------------------------------------------------

class ModbusCommandSpikeDetector:
    """Detect bursts of repeated Modbus/TCP function codes against OT assets."""

    def __init__(self, config: Config):
        self._cfg = config
        self._counters: defaultdict = defaultdict(
            lambda: _SlidingWindowCounter(config.MODBUS_TIME_WINDOW)
        )
        self._alerted: dict = {}

    def inspect(self, packet: Packet) -> List[Alert]:
        if packet.dst_port not in self._cfg.MODBUS_PORTS and packet.src_port not in self._cfg.MODBUS_PORTS:
            return []
        if len(packet.payload) < 8:
            return []

        function_code = packet.payload[7]
        now = packet.timestamp
        target_ip = packet.dst_ip if packet.dst_port in self._cfg.MODBUS_PORTS else packet.src_ip
        key = (packet.src_ip, target_ip, function_code)
        counter = self._counters[key]
        counter.add(ts=now)
        count = counter.total(ts=now)

        if count < self._cfg.MODBUS_COMMAND_SPIKE_THRESHOLD:
            return []

        last = self._alerted.get(key, 0)
        if now - last < self._cfg.MODBUS_TIME_WINDOW:
            return []
        self._alerted[key] = now
        return [
            Alert(
                threat_type=ThreatType.MODBUS_COMMAND_SPIKE,
                severity=AlertSeverity.HIGH,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                dst_port=packet.dst_port,
                description=(
                    f"Modbus command spike: function 0x{function_code:02X} observed "
                    f"{count} times in {self._cfg.MODBUS_TIME_WINDOW}s"
                ),
                timestamp=now,
                metadata={
                    "function_code": function_code,
                    "function_code_hex": f"0x{function_code:02X}",
                    "command_count": count,
                    "target_ip": target_ip,
                },
            )
        ]


# ---------------------------------------------------------------------------
# Suspicious-port detector
# ---------------------------------------------------------------------------

class SuspiciousPortDetector:
    """Flag any connection to a well-known malicious / back-door port."""

    def __init__(self, config: Config):
        self._cfg = config
        self._alerted: dict = {}  # (src_ip, dst_port) → last alert ts

    def inspect(self, packet: Packet) -> List[Alert]:
        if packet.dst_port not in self._cfg.SUSPICIOUS_PORTS:
            return []

        now = packet.timestamp
        key = (packet.src_ip, packet.dst_port)
        last = self._alerted.get(key, 0)
        if now - last < 60:  # suppress same alert for 60 s
            return []
        self._alerted[key] = now
        return [
            Alert(
                threat_type=ThreatType.SUSPICIOUS_PORT,
                severity=AlertSeverity.MEDIUM,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                dst_port=packet.dst_port,
                description=(
                    f"Connection to suspicious port {packet.dst_port} from {packet.src_ip}"
                ),
                timestamp=now,
                metadata={"port": packet.dst_port},
            )
        ]


# ---------------------------------------------------------------------------
# Malicious-IP detector
# ---------------------------------------------------------------------------

class MaliciousIPDetector:
    """Flag traffic to or from IPs in the configured threat-intelligence list."""

    def __init__(self, config: Config):
        self._cfg = config
        self._alerted: dict = {}

    def inspect(self, packet: Packet) -> List[Alert]:
        alerts = []
        now = packet.timestamp

        for bad_ip in (packet.src_ip, packet.dst_ip):
            if bad_ip not in self._cfg.KNOWN_MALICIOUS_IPS:
                continue
            last = self._alerted.get(bad_ip, 0)
            if now - last < 60:
                continue
            self._alerted[bad_ip] = now
            alerts.append(
                Alert(
                    threat_type=ThreatType.MALICIOUS_IP,
                    severity=AlertSeverity.CRITICAL,
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    description=f"Traffic involving known-malicious IP {bad_ip}",
                    timestamp=now,
                    metadata={"malicious_ip": bad_ip},
                )
            )
        return alerts


# ---------------------------------------------------------------------------
# Phishing detector
# ---------------------------------------------------------------------------

class PhishingDetector:
    """Detect probable phishing traffic using simple domain/keyword IOC matching."""

    _KEYWORD_PATTERNS = (
        "verify your account",
        "password reset",
        "suspended account",
        "urgent action required",
        "confirm your identity",
    )

    def __init__(self, config: Config):
        self._cfg = config
        self._alerted: dict = {}  # src_ip -> last alert ts
        domains = sorted(d.lower() for d in config.PHISHING_DOMAINS)
        pattern = "|".join(re.escape(d) for d in domains)
        self._domain_re = re.compile(pattern) if pattern else None

    def inspect(self, packet: Packet) -> List[Alert]:
        if packet.protocol not in ("DNS", "HTTP", "HTTPS"):
            return []
        if not packet.payload:
            return []

        try:
            text = packet.payload.decode("utf-8", errors="ignore").lower()
        except Exception:
            return []

        hit = None
        if self._domain_re:
            m = self._domain_re.search(text)
            if m:
                hit = m.group(0)
        if hit is None:
            for keyword in self._KEYWORD_PATTERNS:
                if keyword in text:
                    hit = keyword
                    break
        if hit is None:
            return []

        now = packet.timestamp
        last = self._alerted.get(packet.src_ip, 0)
        if now - last < 300:
            return []
        self._alerted[packet.src_ip] = now
        return [
            Alert(
                threat_type=ThreatType.PHISHING_ATTEMPT,
                severity=AlertSeverity.HIGH,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                dst_port=packet.dst_port,
                description=f"Phishing indicator detected in traffic payload: '{hit}'",
                timestamp=now,
                metadata={"indicator": hit, "protocol": packet.protocol},
            )
        ]


# ---------------------------------------------------------------------------
# Data-exfiltration detector
# ---------------------------------------------------------------------------

class DataExfiltrationDetector:
    """Detect sustained large outbound transfer volumes from a single source."""

    def __init__(self, config: Config):
        self._cfg = config
        self._byte_counters: defaultdict = defaultdict(
            lambda: _SlidingWindowCounter(config.DATA_EXFIL_TIME_WINDOW)
        )
        self._alerted: dict = {}

    def inspect(self, packet: Packet) -> List[Alert]:
        now = packet.timestamp
        src = packet.src_ip
        counter = self._byte_counters[src]
        counter.add(value=packet.size, ts=now)
        total_bytes = counter.total(ts=now)

        if total_bytes < self._cfg.DATA_EXFIL_THRESHOLD_BYTES:
            return []

        last = self._alerted.get(src, 0)
        if now - last < self._cfg.DATA_EXFIL_TIME_WINDOW:
            return []
        self._alerted[src] = now
        mb = total_bytes / (1024 * 1024)
        return [
            Alert(
                threat_type=ThreatType.DATA_EXFILTRATION,
                severity=AlertSeverity.CRITICAL,
                src_ip=src,
                dst_ip=packet.dst_ip,
                dst_port=packet.dst_port,
                description=(
                    f"Potential data exfiltration: {mb:.2f} MB transmitted within "
                    f"{self._cfg.DATA_EXFIL_TIME_WINDOW}s"
                ),
                timestamp=now,
                metadata={"bytes_in_window": total_bytes},
            )
        ]


# ---------------------------------------------------------------------------
# Unusual-traffic detector
# ---------------------------------------------------------------------------

class UnusualTrafficDetector:
    """Detect packet-rate spikes per source IP compared with a rolling baseline."""

    def __init__(self, config: Config):
        self._cfg = config
        self._window_counts: defaultdict = defaultdict(
            lambda: _SlidingWindowCounter(config.TRAFFIC_ANOMALY_TIME_WINDOW)
        )
        self._baseline: dict = {}
        self._total_seen: defaultdict = defaultdict(int)
        self._alerted: dict = {}

    def inspect(self, packet: Packet) -> List[Alert]:
        now = packet.timestamp
        src = packet.src_ip

        self._total_seen[src] += 1
        counter = self._window_counts[src]
        counter.add(ts=now)
        current = counter.total(ts=now)

        prev_baseline = self._baseline.get(src, float(current))
        # Keep baseline stable during large bursts so anomalies remain visible.
        if current <= prev_baseline * self._cfg.TRAFFIC_ANOMALY_MULTIPLIER:
            self._baseline[src] = prev_baseline * 0.95 + float(current) * 0.05
        else:
            self._baseline[src] = prev_baseline

        # Warm-up to avoid flagging a source with insufficient baseline history.
        if self._total_seen[src] < self._cfg.TRAFFIC_ANOMALY_MIN_PACKETS * 2:
            return []
        if current < self._cfg.TRAFFIC_ANOMALY_MIN_PACKETS:
            return []
        if current < prev_baseline * self._cfg.TRAFFIC_ANOMALY_MULTIPLIER:
            return []

        last = self._alerted.get(src, 0)
        if now - last < self._cfg.TRAFFIC_ANOMALY_TIME_WINDOW:
            return []
        self._alerted[src] = now

        return [
            Alert(
                threat_type=ThreatType.UNUSUAL_TRAFFIC,
                severity=AlertSeverity.MEDIUM,
                src_ip=src,
                dst_ip=packet.dst_ip,
                description=(
                    f"Unusual traffic spike: {current} packets/{self._cfg.TRAFFIC_ANOMALY_TIME_WINDOW}s "
                    f"vs baseline {prev_baseline:.1f}"
                ),
                timestamp=now,
                metadata={
                    "window_packets": current,
                    "baseline_packets": round(prev_baseline, 2),
                    "multiplier": self._cfg.TRAFFIC_ANOMALY_MULTIPLIER,
                },
            )
        ]


# ---------------------------------------------------------------------------
# Composite detector
# ---------------------------------------------------------------------------

class ThreatDetector:
    """Runs all individual detectors and aggregates their alerts.

    Usage::

        detector = ThreatDetector(config)
        for alert in detector.inspect(packet):
            alert_manager.add(alert)
    """

    def __init__(self, config: Config | None = None):
        cfg = config or Config()
        self._detectors = [
            PortScanDetector(cfg),
            SynFloodDetector(cfg),
            BruteForceDetector(cfg),
            DDoSDetector(cfg),
            DnsTunnelingDetector(cfg),
            ModbusCommandSpikeDetector(cfg),
            SuspiciousPortDetector(cfg),
            MaliciousIPDetector(cfg),
            PhishingDetector(cfg),
            DataExfiltrationDetector(cfg),
            UnusualTrafficDetector(cfg),
        ]

    def inspect(self, packet: Packet) -> List[Alert]:
        """Return a (possibly empty) list of alerts generated for *packet*."""
        results: List[Alert] = []
        for detector in self._detectors:
            results.extend(detector.inspect(packet))
        return results
