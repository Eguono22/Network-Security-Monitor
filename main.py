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
import json
import logging
import signal
import sys
import time
from collections import Counter

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
      * Phishing indicator in web traffic
      * Data exfiltration burst
      * Unusual source traffic spike
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

    # ---- phishing indicator -----------------------------------------------
    monitor.process_packet(
        pkt(
            src_ip="10.0.99.6",
            dst_ip="198.51.100.10",
            protocol="HTTP",
            src_port=53111,
            dst_port=80,
            size=350,
            payload=b"GET /login HTTP/1.1\r\nHost: secure-login-verify.com\r\n\r\n",
        )
    )

    # ---- data exfiltration ------------------------------------------------
    exfil_ip = "10.0.99.7"
    for i in range(200):
        monitor.process_packet(
            pkt(
                src_ip=exfil_ip,
                dst_ip="203.0.113.50",
                protocol="HTTPS",
                src_port=50000 + (i % 1000),
                dst_port=443,
                size=64 * 1024,
            )
        )

    # ---- unusual traffic anomaly -----------------------------------------
    anomaly_ip = "10.0.99.8"
    # Build a low baseline over time
    for i in range(500):
        monitor.process_packet(
            Packet(
                timestamp=ts + 100 + i * 0.2,
                src_ip=anomaly_ip,
                dst_ip=victim_ip,
                protocol="TCP",
                src_port=40000 + (i % 500),
                dst_port=443,
                size=100,
            )
        )
    # Sudden burst in a short window
    burst_base = ts + 250
    for i in range(350):
        monitor.process_packet(
            Packet(
                timestamp=burst_base + i * 0.02,
                src_ip=anomaly_ip,
                dst_ip=victim_ip,
                protocol="TCP",
                src_port=41000 + (i % 500),
                dst_port=443,
                size=120,
            )
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
    mode = parser.add_mutually_exclusive_group(required=False)
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
        "--list-interfaces",
        action="store_true",
        help="List detected interfaces and exit.",
    )
    parser.add_argument(
        "--profile",
        default="",
        help="Baseline profile name from config_profiles.json (e.g. dev, office, datacenter).",
    )
    parser.add_argument(
        "--profile-file",
        default="config_profiles.json",
        help="Path to profile JSON file (default: config_profiles.json).",
    )
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
    parser.add_argument(
        "--live-duration",
        type=float,
        default=0.0,
        help="Stop live mode after N seconds (0 = run until Ctrl+C).",
    )
    parser.add_argument(
        "--save-tuning",
        default="",
        help="Write tuning guidance and suggested profile overrides to a JSON file.",
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


def _print_integration_status(config: Config) -> None:
    configured = []
    if config.SLACK_WEBHOOK_URL:
        configured.append("Slack webhook")
    if config.ALERT_WEBHOOK_URL:
        configured.append("Generic webhook")
    if config.SMTP_HOST and config.ALERT_EMAIL_TO:
        configured.append("SMTP email")
    if config.SIEM_OUTPUT_FILE:
        configured.append(f"SIEM file ({config.SIEM_OUTPUT_FILE})")

    print("\nIntegration status:")
    if configured:
        print(f"  Configured: {', '.join(configured)}")
    else:
        print("  Configured: none")
        print("  Tip: set NSM_SLACK_WEBHOOK_URL to forward alerts immediately.")


def _tuning_report(monitor: NetworkMonitor, config: Config) -> dict:
    am = monitor.get_alert_manager()
    stats = monitor.get_stats()
    alert_stats = am.get_stats()
    total = alert_stats["total"]
    runtime_minutes = max((time.time() - stats.start_time) / 60.0, 1 / 60.0)
    alerts_per_minute = total / runtime_minutes
    alerts = am.get_recent(max(total, 1))

    recent_5m = [a for a in alerts if a.timestamp >= (time.time() - 300)]
    top_offender = "none"
    if recent_5m:
        src, count = Counter(a.src_ip for a in recent_5m).most_common(1)[0]
        top_offender = f"{src} ({count})"

    suggestions = []
    overrides: dict = {}
    by_type = alert_stats["by_threat_type"]
    if alerts_per_minute > 20:
        suggestions.append(
            f"High alert volume: raise TRAFFIC_ANOMALY_MIN_PACKETS (current {config.TRAFFIC_ANOMALY_MIN_PACKETS}) "
            f"or TRAFFIC_ANOMALY_MULTIPLIER (current {config.TRAFFIC_ANOMALY_MULTIPLIER})."
        )
        overrides["TRAFFIC_ANOMALY_MIN_PACKETS"] = int(config.TRAFFIC_ANOMALY_MIN_PACKETS * 1.2)
        overrides["TRAFFIC_ANOMALY_MULTIPLIER"] = round(config.TRAFFIC_ANOMALY_MULTIPLIER + 0.3, 2)
    if by_type.get("DDOS", 0) >= 3:
        suggestions.append(
            f"Frequent DDoS alerts: consider increasing DDOS_THRESHOLD (current {config.DDOS_THRESHOLD})."
        )
        overrides["DDOS_THRESHOLD"] = int(config.DDOS_THRESHOLD * 1.2)
    if by_type.get("BRUTE_FORCE", 0) >= 3:
        suggestions.append(
            f"Frequent brute-force alerts: consider increasing BRUTE_FORCE_THRESHOLD (current {config.BRUTE_FORCE_THRESHOLD})."
        )
        overrides["BRUTE_FORCE_THRESHOLD"] = int(config.BRUTE_FORCE_THRESHOLD + 2)
    if total == 0:
        suggestions.append(
            "No alerts detected: lower PORT_SCAN_THRESHOLD / BRUTE_FORCE_THRESHOLD slightly to increase sensitivity."
        )
        overrides["PORT_SCAN_THRESHOLD"] = max(1, int(config.PORT_SCAN_THRESHOLD * 0.85))
        overrides["BRUTE_FORCE_THRESHOLD"] = max(1, int(config.BRUTE_FORCE_THRESHOLD * 0.85))
    if not suggestions:
        suggestions.append("Current thresholds look stable for this traffic sample.")
    return {
        "profile": config.PROFILE_NAME,
        "alerts_total": total,
        "alerts_per_minute": round(alerts_per_minute, 2),
        "top_offender_5m": top_offender,
        "suggestions": suggestions,
        "suggested_overrides": overrides,
    }


def _print_tuning_suggestions(monitor: NetworkMonitor, config: Config) -> dict:
    report = _tuning_report(monitor, config)
    print("\nTuning guidance:")
    print(f"  Alerts/min observed : {report['alerts_per_minute']:.2f}")
    print(f"  Top offender (5m)   : {report['top_offender_5m']}")
    for item in report["suggestions"]:
        print(f"  - {item}")
    return report


def _save_tuning_report(path: str, report: dict) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(f"Tuning report saved to: {path}")


def _list_interfaces() -> int:
    try:
        from scapy.interfaces import get_if_list
    except ImportError:
        print("Scapy is not installed. Cannot enumerate interfaces.", file=sys.stderr)
        return 1

    interfaces = get_if_list()
    if not interfaces:
        print("No interfaces found.")
        return 0
    for iface in interfaces:
        print(iface)
    return 0


def main(argv: list | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.list_interfaces:
        return _list_interfaces()

    if not (args.live or args.simulate or args.show_alerts):
        parser.error("One of --live, --simulate, or --show-alerts is required.")

    if args.show_alerts:
        return _print_alerts_from_file(args.show_alerts)

    config = Config()
    if args.profile:
        if not config.apply_profile(args.profile, args.profile_file):
            print(
                f"Failed to load profile '{args.profile}' from {args.profile_file}",
                file=sys.stderr,
            )
            return 1
        print(f"Loaded profile: {config.PROFILE_NAME}")
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
        print(f"\n{'-' * 60}")
        print(f"  Processed : {stats.total_packets:,} packets")
        print(f"  Alerts    : {am.get_stats()['total']:,} total")
        for sev, count in am.get_stats()["by_severity"].items():
            if count:
                print(f"              {sev}: {count}")
        print(f"{'-' * 60}")
        _print_integration_status(config)
        report = _print_tuning_suggestions(monitor, config)
        if args.save_tuning:
            _save_tuning_report(args.save_tuning, report)

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
        deadline = time.time() + args.live_duration if args.live_duration > 0 else None
        try:
            while monitor.is_running:
                if deadline and time.time() >= deadline:
                    break
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        monitor.stop()
        _print_integration_status(config)
        report = _print_tuning_suggestions(monitor, config)
        if args.save_tuning:
            _save_tuning_report(args.save_tuning, report)
    else:
        dashboard = Dashboard(monitor, config)
        run_duration = args.live_duration if args.live_duration > 0 else None
        dashboard.run(duration_seconds=run_duration)
        monitor.stop()
        _print_integration_status(config)
        report = _print_tuning_suggestions(monitor, config)
        if args.save_tuning:
            _save_tuning_report(args.save_tuning, report)

    return 0


if __name__ == "__main__":
    sys.exit(main())
