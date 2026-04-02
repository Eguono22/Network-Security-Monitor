"""Visualization utilities for the Network Security Monitor.

Provides:
  - A text-based terminal dashboard (always available, no extra deps)
  - Matplotlib charts saved to PNG files (requires matplotlib)
"""

from __future__ import annotations

import os
from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Optional

from nsm.alert import Alert, AlertSeverity
from nsm.packet import Packet


# ---------------------------------------------------------------------------
# Terminal / text dashboard
# ---------------------------------------------------------------------------

_SEV_COLOR = {
    "LOW": "\033[94m",       # blue
    "MEDIUM": "\033[93m",    # yellow
    "HIGH": "\033[91m",      # red
    "CRITICAL": "\033[1;91m", # bold red
}
_RESET = "\033[0m"


def _sev_label(severity: AlertSeverity) -> str:
    name = str(severity)
    color = _SEV_COLOR.get(name, "")
    return f"{color}[{name}]{_RESET}"


def print_dashboard(packets: List[Packet], alerts: List[Alert]) -> None:
    """Print a text-based security dashboard to stdout."""
    now = datetime.utcnow()
    sep = "=" * 70

    print(sep)
    print("  NETWORK SECURITY MONITOR — DASHBOARD")
    print(f"  Generated: {now.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(sep)

    # ---- Traffic summary ----
    total_bytes = sum(p.size for p in packets)
    protocols: dict = defaultdict(int)
    for p in packets:
        protocols[p.protocol] += 1

    print("\n📡  TRAFFIC SUMMARY")
    print(f"    Total packets : {len(packets):,}")
    print(f"    Total bytes   : {total_bytes:,} ({total_bytes / 1_000_000:.2f} MB)")
    proto_str = "  ".join(f"{k}: {v}" for k, v in sorted(protocols.items()))
    print(f"    Protocols     : {proto_str}")

    # ---- Top source IPs ----
    src_counts: dict = defaultdict(int)
    src_bytes: dict = defaultdict(int)
    for p in packets:
        src_counts[p.src_ip] += 1
        src_bytes[p.src_ip] += p.size
    top_ips = sorted(src_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    if top_ips:
        print("\n🔝  TOP SOURCE IPs")
        for ip, count in top_ips:
            print(f"    {ip:<20} {count:>6} packets  {src_bytes[ip] / 1000:.1f} KB")

    # ---- Alert summary ----
    print(f"\n🚨  ALERTS  (total: {len(alerts)})")
    if not alerts:
        print("    No alerts.")
    else:
        by_sev: dict = defaultdict(int)
        for a in alerts:
            by_sev[str(a.severity)] += 1
        for sev_name in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            cnt = by_sev.get(sev_name, 0)
            if cnt:
                print(f"    {_sev_label(AlertSeverity[sev_name])}  {cnt}")

        print("\n    Recent alerts (latest 10):")
        for alert in sorted(alerts, key=lambda a: a.timestamp, reverse=True)[:10]:
            ts = alert.timestamp.strftime("%H:%M:%S")
            print(f"    {ts}  {_sev_label(alert.severity)}  {alert.alert_type:<20} {alert.source_ip}")

    print(sep)


# ---------------------------------------------------------------------------
# Matplotlib charts
# ---------------------------------------------------------------------------

def save_charts(
    packets: List[Packet],
    alerts: List[Alert],
    output_dir: str = ".",
) -> List[str]:
    """Generate and save PNG charts.  Returns the list of file paths written.

    Falls back gracefully if matplotlib is not installed.
    """
    try:
        import matplotlib
        matplotlib.use("Agg")  # non-interactive backend — safe in all environments
        import matplotlib.pyplot as plt
        import matplotlib.dates as mdates
    except ImportError:
        print("[visualization] matplotlib not installed — skipping chart generation.")
        return []

    os.makedirs(output_dir, exist_ok=True)
    saved: List[str] = []

    # ---- 1. Traffic volume over time ----
    if packets:
        fig, ax = plt.subplots(figsize=(10, 4))
        timestamps = [p.timestamp for p in packets]
        sizes = [p.size for p in packets]

        # Bucket into 10-second bins
        if timestamps:
            t_min = min(timestamps)
            t_max = max(timestamps)
            span = (t_max - t_min).total_seconds()
            bin_size = max(1, span / 30)
            bins: dict = defaultdict(int)
            for ts, sz in zip(timestamps, sizes):
                bucket = int((ts - t_min).total_seconds() / bin_size)
                bins[bucket] += sz

            if bins:
                xs = [t_min + timedelta(seconds=k * bin_size) for k in sorted(bins)]
                ys = [bins[k] / 1000 for k in sorted(bins)]
                ax.bar(xs, ys, width=timedelta(seconds=bin_size * 0.8), color="steelblue")
                ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))
                fig.autofmt_xdate()

        ax.set_title("Traffic Volume Over Time")
        ax.set_xlabel("Time")
        ax.set_ylabel("KB transferred")
        ax.grid(axis="y", alpha=0.4)
        path = os.path.join(output_dir, "traffic_volume.png")
        fig.tight_layout()
        fig.savefig(path)
        plt.close(fig)
        saved.append(path)

    # ---- 2. Top source IPs ----
    if packets:
        src_bytes: dict = defaultdict(int)
        for p in packets:
            src_bytes[p.src_ip] += p.size
        top = sorted(src_bytes.items(), key=lambda x: x[1], reverse=True)[:10]
        if top:
            fig, ax = plt.subplots(figsize=(10, 4))
            ips = [t[0] for t in top]
            vals = [t[1] / 1000 for t in top]
            ax.barh(ips[::-1], vals[::-1], color="steelblue")
            ax.set_title("Top Source IPs by Traffic Volume")
            ax.set_xlabel("KB transferred")
            ax.grid(axis="x", alpha=0.4)
            path = os.path.join(output_dir, "top_source_ips.png")
            fig.tight_layout()
            fig.savefig(path)
            plt.close(fig)
            saved.append(path)

    # ---- 3. Alert distribution by severity ----
    if alerts:
        sev_counts: dict = defaultdict(int)
        for a in alerts:
            sev_counts[str(a.severity)] += 1
        fig, ax = plt.subplots(figsize=(6, 6))
        labels = list(sev_counts.keys())
        values = [sev_counts[l] for l in labels]
        colors = {
            "LOW": "#5B9BD5",
            "MEDIUM": "#FFC000",
            "HIGH": "#FF4444",
            "CRITICAL": "#8B0000",
        }
        chart_colors = [colors.get(l, "gray") for l in labels]
        ax.pie(values, labels=labels, colors=chart_colors, autopct="%1.0f%%", startangle=90)
        ax.set_title("Alert Distribution by Severity")
        path = os.path.join(output_dir, "alert_severity.png")
        fig.tight_layout()
        fig.savefig(path)
        plt.close(fig)
        saved.append(path)

    # ---- 4. Alert types bar chart ----
    if alerts:
        type_counts: dict = defaultdict(int)
        for a in alerts:
            type_counts[a.alert_type] += 1
        fig, ax = plt.subplots(figsize=(8, 4))
        types = list(type_counts.keys())
        vals = [type_counts[t] for t in types]
        ax.bar(types, vals, color="tomato")
        ax.set_title("Alerts by Type")
        ax.set_ylabel("Count")
        ax.grid(axis="y", alpha=0.4)
        path = os.path.join(output_dir, "alert_types.png")
        fig.tight_layout()
        fig.savefig(path)
        plt.close(fig)
        saved.append(path)

    return saved
