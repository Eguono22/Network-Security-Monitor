"""Real-time CLI dashboard for the Network Security Monitor."""

from __future__ import annotations

import os
import shutil
import time
from typing import Optional

from .alert_manager import AlertManager
from .config import Config
from .models import Alert, AlertSeverity
from .monitor import NetworkMonitor

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    _COLORAMA = True
except ImportError:
    _COLORAMA = False


# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------

def _severity_colour(severity: AlertSeverity) -> str:
    if not _COLORAMA:
        return ""
    return {
        AlertSeverity.LOW: Fore.CYAN,
        AlertSeverity.MEDIUM: Fore.YELLOW,
        AlertSeverity.HIGH: Fore.RED,
        AlertSeverity.CRITICAL: Fore.RED + Style.BRIGHT,
    }.get(severity, "")


def _reset() -> str:
    return Style.RESET_ALL if _COLORAMA else ""


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

class Dashboard:
    """Renders a live terminal dashboard for a running :class:`~network_security_monitor.monitor.NetworkMonitor`.

    Usage::

        dashboard = Dashboard(monitor)
        dashboard.run()          # blocks; press Ctrl+C to exit
    """

    def __init__(self, monitor: NetworkMonitor, config: Config | None = None):
        self._monitor = monitor
        self._cfg = config or Config()
        self._alert_manager: AlertManager = monitor.get_alert_manager()
        self._last_alert_count = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Block and refresh the dashboard at :attr:`~Config.DASHBOARD_REFRESH_INTERVAL`."""
        try:
            while True:
                self._render()
                time.sleep(self._cfg.DASHBOARD_REFRESH_INTERVAL)
        except KeyboardInterrupt:
            self._clear_screen()
            print("Dashboard stopped.")

    def render_once(self) -> str:
        """Return the current dashboard as a plain string (useful for testing / logging)."""
        return self._build_output()

    # ------------------------------------------------------------------
    # Internal rendering
    # ------------------------------------------------------------------

    def _render(self) -> None:
        self._clear_screen()
        print(self._build_output(), end="", flush=True)

    @staticmethod
    def _clear_screen() -> None:
        os.system("cls" if os.name == "nt" else "clear")

    def _build_output(self) -> str:
        cols = shutil.get_terminal_size((80, 24)).columns
        sep = "─" * cols

        lines = []
        lines.append(sep)
        lines.append(self._centre("  🛡  NETWORK SECURITY MONITOR  🛡  ", cols))
        lines.append(self._centre(f"  {time.strftime('%Y-%m-%d  %H:%M:%S')}  ", cols))
        lines.append(sep)

        # Traffic stats
        stats = self._monitor.get_stats()
        lines.append("")
        lines.append("  TRAFFIC STATISTICS")
        lines.append(f"  Total packets   : {stats.total_packets:,}")
        lines.append(f"  Total bytes     : {self._human_bytes(stats.total_bytes)}")
        lines.append(f"  Packets/sec     : {stats.packets_per_second:.1f}")
        lines.append(f"  Bytes/sec       : {self._human_bytes(stats.bytes_per_second)}/s")
        lines.append(f"  TCP / UDP / ICMP: {stats.tcp_packets:,} / {stats.udp_packets:,} / {stats.icmp_packets:,}")
        lines.append(f"  DNS / Other     : {stats.dns_packets:,} / {stats.other_packets:,}")
        lines.append("")

        # Top talkers
        if stats.top_talkers:
            lines.append("  TOP SOURCE IPs")
            for ip, count in list(stats.top_talkers.items())[:5]:
                lines.append(f"    {ip:<20} {count:>8,} pkts")
        lines.append("")

        # Top destination ports
        if stats.top_ports:
            lines.append("  TOP DESTINATION PORTS")
            for port, count in list(stats.top_ports.items())[:5]:
                lines.append(f"    Port {port:<8}          {count:>8,} pkts")
        lines.append("")

        # Alert summary
        alert_stats = self._alert_manager.get_stats()
        lines.append("  ALERT SUMMARY")
        lines.append(f"  Total alerts    : {alert_stats['total']:,}")
        sev = alert_stats["by_severity"]
        lines.append(
            f"  Critical / High : {sev.get('CRITICAL', 0):,} / {sev.get('HIGH', 0):,}"
        )
        lines.append(
            f"  Medium / Low    : {sev.get('MEDIUM', 0):,} / {sev.get('LOW', 0):,}"
        )
        lines.append("")

        # Recent alerts
        recent = self._alert_manager.get_recent(10)
        if recent:
            lines.append("  RECENT ALERTS (newest last)")
            for alert in recent[-10:]:
                colour = _severity_colour(alert.severity)
                reset = _reset()
                lines.append(f"  {colour}{alert}{reset}")
        else:
            lines.append("  No alerts yet.")

        lines.append("")
        lines.append(sep)
        lines.append("  Press Ctrl+C to stop the monitor.")
        lines.append("")

        return "\n".join(lines) + "\n"

    @staticmethod
    def _centre(text: str, width: int) -> str:
        return text.center(width)

    @staticmethod
    def _human_bytes(n: float) -> str:
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} TB"
