#!/usr/bin/env python3
"""
Network Security Monitor – CLI entry point.

Examples
--------
Live capture on the default interface with a real-time dashboard::

    sudo python main.py --live

Capture on a specific interface::

    sudo python main.py --live --interface eth0

Run in simulation mode (no root required, useful for testing)::

    python main.py --simulate

Show recent alerts from a previous run's log file::

    python main.py --show-alerts alerts.log
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import time

from network_security_monitor.config import Config
from network_security_monitor.dashboard import Dashboard
from network_security_monitor.models import (
    Alert,
    AlertSeverity,
    Packet,
    ThreatType,
)
from network_security_monitor.monitor import NetworkMonitor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
)


# ---------------------------------------------------------------------------
# Simulation helpers
# ---------------------------------------------------------------------------

def _simulate_traffic(monitor: NetworkMonitor, duration: float = 30.0) -> None:
    """Feed simulated packets into *monitor* to demonstrate all detectors.

    Generates examples of:
      * Normal HTTP/DNS traffic
      * A port scan
      * A SYN flood
      * A brute-force SSH attempt
      * DNS tunneling
      * Traffic to a suspicious port
      * Traffic from a known-malicious IP (if configured)
    """
    import random

    print(
        "\nRunning simulation for {:.0f} seconds…  (Ctrl+C to stop)\n".format(duration)
    )

    cfg = monitor._cfg  # type: ignore[attr-defined]
    start = time.time()
    ts = start

    attacker_ip = "10.0.0.99"
    victim_ip = "192.168.1.1"

    def pkt(**kw) -> Packet:
        nonlocal ts
        ts += 0.01
        return Packet(timestamp=ts, **kw)

    # ---- normal background traffic ----------------------------------------
    normal_pkts = []
    for i in range(20):
        normal_pkts.append(
            pkt(src_ip=f"10.0.1.{i % 254 + 1}", dst_ip=victim_ip,
                protocol="TCP", src_port=random.randint(49152, 65535),
                dst_port=80, size=512)
        )
        normal_pkts.append(
            pkt(src_ip=f"10.0.2.{i % 254 + 1}", dst_ip="8.8.8.8",
                protocol="DNS", src_port=random.randint(49152, 65535),
                dst_port=53, size=64, payload=b"A" * 64)
        )

    for p in normal_pkts:
        monitor.process_packet(p)

    # ---- port scan --------------------------------------------------------
    for port in range(1, cfg.PORT_SCAN_THRESHOLD + 5):
        monitor.process_packet(
            pkt(src_ip=attacker_ip, dst_ip=victim_ip,
                protocol="TCP", src_port=55000, dst_port=port,
                size=60, flags="SYN")
        )

    # ---- SYN flood --------------------------------------------------------
    for _ in range(cfg.SYN_FLOOD_THRESHOLD + 10):
        monitor.process_packet(
            pkt(src_ip="10.0.99.1", dst_ip=victim_ip,
                protocol="TCP", src_port=random.randint(1024, 65535),
                dst_port=80, size=60, flags="SYN")
        )

    # ---- brute-force SSH --------------------------------------------------
    for _ in range(cfg.BRUTE_FORCE_THRESHOLD + 5):
        monitor.process_packet(
            pkt(src_ip="10.0.99.2", dst_ip=victim_ip,
                protocol="TCP", src_port=random.randint(1024, 65535),
                dst_port=22, size=60, flags="SYN")
        )

    # ---- DNS tunneling ----------------------------------------------------
    for _ in range(cfg.DNS_LARGE_QUERY_THRESHOLD + 2):
        monitor.process_packet(
            pkt(src_ip="10.0.99.3", dst_ip="8.8.8.8",
                protocol="DNS", src_port=random.randint(1024, 65535),
                dst_port=53, size=600,
                payload=b"X" * (cfg.DNS_QUERY_SIZE_THRESHOLD + 50))
        )

    # ---- suspicious port --------------------------------------------------
    monitor.process_packet(
        pkt(src_ip="10.0.99.4", dst_ip=victim_ip,
            protocol="TCP", src_port=55555, dst_port=4444,
            size=100, flags="SYN")
    )

    # ---- DDoS (1 source, many packets in 1 s window) ----------------------
    # Use a fixed base timestamp so all DDoS packets fall within the 1-second
    # detection window regardless of how long the previous steps took.
    ddos_ip = "10.0.99.5"
    ddos_base_ts = ts + 0.001  # start just after previous packets
    for i in range(cfg.DDOS_THRESHOLD + 50):
        ddos_pkt = Packet(
            timestamp=ddos_base_ts + i * 0.0005,  # 0.5 ms apart → all within 1 s
            src_ip=ddos_ip,
            dst_ip=victim_ip,
            protocol="UDP",
            src_port=random.randint(1024, 65535),
            dst_port=53,
            size=128,
        )
        monitor.process_packet(ddos_pkt)

    elapsed = time.time() - start
    print(f"\nSimulation finished in {elapsed:.2f}s.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nsm",
        description="Network Security Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--live",
        action="store_true",
        help="Capture live traffic (requires root / CAP_NET_RAW).",
    )
    mode.add_argument(
        "--simulate",
        action="store_true",
        help="Feed simulated attack traffic to demonstrate all detectors.",
    )
    mode.add_argument(
        "--show-alerts",
        metavar="LOG_FILE",
        help="Print alerts from an existing alerts.log file and exit.",
    )

    parser.add_argument("--interface", "-i", default="", help="Network interface name.")
    parser.add_argument(
        "--log-file",
        default="alerts.log",
        help="Path to the alert log file (default: alerts.log).",
    )
    parser.add_argument(
        "--no-dashboard",
        action="store_true",
        help="Disable the real-time dashboard; print alerts to stdout instead.",
    )
    parser.add_argument(
        "--simulate-duration",
        type=float,
        default=5.0,
        help="Simulation run time in seconds (default: 5).",
    )
    return parser


def _print_alerts_from_file(path: str) -> int:
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
    except FileNotFoundError:
        print(f"File not found: {path}", file=sys.stderr)
        return 1
    if not lines:
        print("No alerts found.")
        return 0
    for line in lines:
        print(line, end="")
    return 0


def main(argv: list | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.show_alerts:
        return _print_alerts_from_file(args.show_alerts)

    config = Config()
    config.ALERT_LOG_FILE = args.log_file
    if args.interface:
        config.INTERFACE = args.interface

    monitor = NetworkMonitor(config)

    if args.no_dashboard:
        # Just print each alert as it arrives.
        def _print_alert(alert: Alert) -> None:
            print(str(alert))
        monitor.on_alert(_print_alert)

    if args.simulate:
        _simulate_traffic(monitor, duration=args.simulate_duration)
        # Print summary.
        stats = monitor.get_stats()
        am = monitor.get_alert_manager()
        print(f"\n{'─'*60}")
        print(f"  Processed : {stats.total_packets:,} packets")
        print(f"  Alerts    : {am.get_stats()['total']:,} total")
        for sev, count in am.get_stats()["by_severity"].items():
            if count:
                print(f"              {sev}: {count}")
        print(f"{'─'*60}")

        if not args.no_dashboard:
            dashboard = Dashboard(monitor, config)
            print(dashboard.render_once())
        return 0

    # Live mode
    def _handle_signal(sig, frame):  # type: ignore[type-arg]
        print("\nShutting down…")
        monitor.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    monitor.start(interface=args.interface)

    if args.no_dashboard:
        print("Monitoring… press Ctrl+C to stop.")
        try:
            while monitor.is_running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        monitor.stop()
    else:
        dashboard = Dashboard(monitor, config)
        dashboard.run()
        monitor.stop()

    return 0


if __name__ == "__main__":
    sys.exit(main())
