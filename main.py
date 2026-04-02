"""main.py — CLI entry point for the Network Security Monitor.

Usage
-----
  python main.py --simulate          Run end-to-end demo with synthetic traffic
  python main.py --simulate --charts Save PNG charts to ./charts/
  python main.py --help
"""

from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta
from typing import List

from nsm.monitor import NetworkSecurityMonitor
from nsm.packet import Packet
from nsm.visualization import print_dashboard, save_charts


# ---------------------------------------------------------------------------
# Synthetic traffic generator
# ---------------------------------------------------------------------------

def _rand_ip(prefix: str = "") -> str:
    octets = [str(random.randint(1, 254)) for _ in range(4)]
    return prefix + ".".join(octets) if not prefix else f"{prefix}.{'.'.join(octets[1:])}"


def generate_simulation_traffic() -> List[Packet]:
    """Return a list of Packets that includes several suspicious patterns."""
    packets: List[Packet] = []
    now = datetime.utcnow()

    # ---- Normal web traffic ----
    normal_clients = [f"10.0.1.{i}" for i in range(1, 20)]
    for client in normal_clients:
        for _ in range(random.randint(5, 15)):
            ts = now - timedelta(seconds=random.uniform(0, 120))
            packets.append(Packet(
                timestamp=ts,
                src_ip=client,
                dst_ip="203.0.113.1",
                src_port=random.randint(49152, 65535),
                dst_port=random.choice([80, 443]),
                protocol="TCP",
                size=random.randint(200, 2000),
                flags=["SYN", "ACK"],
            ))

    # ---- Port scan from 192.168.50.10 ----
    scanner_ip = "192.168.50.10"
    scan_start = now - timedelta(seconds=55)
    for port in range(1, 80):
        packets.append(Packet(
            timestamp=scan_start + timedelta(milliseconds=port * 30),
            src_ip=scanner_ip,
            dst_ip="10.0.0.1",
            src_port=random.randint(49152, 65535),
            dst_port=port,
            protocol="TCP",
            size=60,
            flags=["SYN"],
        ))

    # ---- SSH brute force from 172.16.99.5 ----
    bf_ip = "172.16.99.5"
    for i in range(35):
        packets.append(Packet(
            timestamp=now - timedelta(seconds=28 - i * 0.8),
            src_ip=bf_ip,
            dst_ip="10.0.0.22",
            src_port=random.randint(49152, 65535),
            dst_port=22,
            protocol="TCP",
            size=80,
            flags=["SYN"],
        ))

    # ---- DDoS flood from 198.51.100.200 ----
    ddos_ip = "198.51.100.200"
    for i in range(150):
        packets.append(Packet(
            timestamp=now - timedelta(seconds=9.9 - i * 0.06),
            src_ip=ddos_ip,
            dst_ip="10.0.0.5",
            src_port=random.randint(49152, 65535),
            dst_port=80,
            protocol="UDP",
            size=512,
            flags=[],
        ))

    # ---- Connection to suspicious port 4444 ----
    packets.append(Packet(
        timestamp=now - timedelta(seconds=5),
        src_ip="10.0.1.99",
        dst_ip="203.0.113.50",
        src_port=55000,
        dst_port=4444,
        protocol="TCP",
        size=200,
        flags=["SYN"],
    ))

    # ---- Large data exfiltration from 10.0.2.55 ----
    exfil_ip = "10.0.2.55"
    for _ in range(20):
        packets.append(Packet(
            timestamp=now - timedelta(seconds=random.uniform(0, 55)),
            src_ip=exfil_ip,
            dst_ip="203.0.113.99",
            src_port=random.randint(49152, 65535),
            dst_port=443,
            protocol="TCP",
            size=600_000,  # 600 KB each → 12 MB total
            flags=["ACK"],
        ))

    return packets


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Network Security Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--simulate",
        action="store_true",
        help="Run an end-to-end simulation with synthetic network traffic",
    )
    parser.add_argument(
        "--charts",
        action="store_true",
        help="Save visualization charts to the ./charts/ directory (requires matplotlib)",
    )
    args = parser.parse_args()

    if args.simulate:
        print("Generating synthetic network traffic...")
        packets = generate_simulation_traffic()
        print(f"  Generated {len(packets)} packets.\n")

        monitor = NetworkSecurityMonitor()
        monitor.ingest(packets)

        alerts = monitor.alert_manager.get_all()
        print_dashboard(packets, alerts)

        if args.charts:
            saved = save_charts(packets, alerts, output_dir="charts")
            if saved:
                print(f"\nCharts saved to: {', '.join(saved)}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
