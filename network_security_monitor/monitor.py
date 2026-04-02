"""Core monitoring engine – coordinates packet capture, analysis, and detection."""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from typing import Callable, List, Optional

from .alert_manager import AlertManager
from .config import Config
from .models import Alert, Packet, TrafficStats
from .packet_analyzer import PacketAnalyzer
from .threat_detector import ThreatDetector

logger = logging.getLogger("nsm.monitor")


class NetworkMonitor:
    """Orchestrates all NSM components.

    The monitor can run in two modes:

    1. **Live capture** – calls :meth:`start` to launch a background thread
       that uses Scapy to sniff packets on a real network interface.
    2. **Replay / testing** – calls :meth:`process_packet` directly with
       pre-built :class:`~network_security_monitor.models.Packet` objects.

    Usage (live capture)::

        monitor = NetworkMonitor()
        monitor.start(interface="eth0")
        ...
        monitor.stop()

    Usage (replay / test mode)::

        monitor = NetworkMonitor()
        for pkt in my_packet_stream:
            monitor.process_packet(pkt)
        stats = monitor.get_stats()
    """

    def __init__(self, config: Config | None = None):
        self._cfg = config or Config()
        self._analyzer = PacketAnalyzer()
        self._detector = ThreatDetector(self._cfg)
        self._alert_manager = AlertManager(self._cfg)

        self._stats = TrafficStats()
        self._protocol_counts: dict = defaultdict(int)
        self._src_ip_counts: dict = defaultdict(int)
        self._dst_port_counts: dict = defaultdict(int)

        self._running = False
        self._capture_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Optional callback fired for every new alert.
        self._alert_callbacks: List[Callable[[Alert], None]] = []

    # ------------------------------------------------------------------
    # Alert subscriptions
    # ------------------------------------------------------------------

    def on_alert(self, callback: Callable[[Alert], None]) -> None:
        """Register *callback* to be invoked whenever a new alert is generated."""
        self._alert_callbacks.append(callback)
        self._alert_manager.register_callback(callback)

    # ------------------------------------------------------------------
    # Packet processing (usable in both live and test mode)
    # ------------------------------------------------------------------

    def process_packet(self, packet: Packet) -> List[Alert]:
        """Analyse *packet*, update statistics, and return any alerts raised."""
        with self._lock:
            self._update_stats(packet)

        alerts = self._detector.inspect(packet)
        for alert in alerts:
            self._alert_manager.add(alert)

        return alerts

    def _process_raw(self, raw_pkt) -> None:
        """Callback passed to Scapy's ``sniff()``."""
        packet = self._analyzer.parse(raw_pkt)
        if packet is not None:
            self.process_packet(packet)

    def _update_stats(self, packet: Packet) -> None:
        self._stats.total_packets += 1
        self._stats.total_bytes += packet.size

        proto = packet.protocol
        if proto == "TCP":
            self._stats.tcp_packets += 1
        elif proto == "UDP":
            self._stats.udp_packets += 1
        elif proto == "ICMP":
            self._stats.icmp_packets += 1
        elif proto == "DNS":
            self._stats.dns_packets += 1
        else:
            self._stats.other_packets += 1

        self._src_ip_counts[packet.src_ip] += 1
        if packet.dst_port is not None:
            self._dst_port_counts[packet.dst_port] += 1

    # ------------------------------------------------------------------
    # Live-capture lifecycle
    # ------------------------------------------------------------------

    def start(self, interface: str = "") -> None:
        """Start capturing packets on *interface* in a background thread.

        Args:
            interface: Network interface name (e.g. ``"eth0"``).  When empty,
                       Scapy will pick the default interface.
        """
        if self._running:
            logger.warning("Monitor is already running.")
            return

        iface = interface or self._cfg.INTERFACE or None
        self._running = True
        self._capture_thread = threading.Thread(
            target=self._capture_loop,
            args=(iface,),
            daemon=True,
            name="nsm-capture",
        )
        self._capture_thread.start()
        logger.info("Network monitor started on interface %s.", iface or "default")

    def stop(self) -> None:
        """Stop the background capture thread."""
        self._running = False
        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=3)
        logger.info("Network monitor stopped.")

    def _capture_loop(self, interface: Optional[str]) -> None:
        try:
            from scapy.sendrecv import sniff
        except ImportError:
            logger.error("Scapy is not installed. Cannot capture live traffic.")
            self._running = False
            return

        while self._running:
            try:
                sniff(
                    iface=interface,
                    prn=self._process_raw,
                    store=False,
                    timeout=1,
                )
            except Exception as exc:
                logger.error("Capture error: %s", exc)
                time.sleep(1)

    # ------------------------------------------------------------------
    # Statistics / inspection
    # ------------------------------------------------------------------

    def get_stats(self) -> TrafficStats:
        """Return a snapshot of current traffic statistics."""
        with self._lock:
            stats = TrafficStats(
                total_packets=self._stats.total_packets,
                total_bytes=self._stats.total_bytes,
                tcp_packets=self._stats.tcp_packets,
                udp_packets=self._stats.udp_packets,
                icmp_packets=self._stats.icmp_packets,
                dns_packets=self._stats.dns_packets,
                other_packets=self._stats.other_packets,
                start_time=self._stats.start_time,
            )
            top_n = self._cfg.DASHBOARD_TOP_TALKERS_COUNT
            stats.top_talkers = dict(
                sorted(self._src_ip_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
            )
            stats.top_ports = dict(
                sorted(self._dst_port_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
            )
        return stats

    def get_alert_manager(self) -> AlertManager:
        """Return the underlying :class:`~network_security_monitor.alert_manager.AlertManager`."""
        return self._alert_manager

    @property
    def is_running(self) -> bool:
        return self._running
