"""Unit tests for Dashboard rendering."""

import time

from network_security_monitor.config import Config
from network_security_monitor.dashboard import Dashboard
from network_security_monitor.models import Alert, AlertSeverity, ThreatType
from network_security_monitor.monitor import NetworkMonitor


def _cfg() -> Config:
    cfg = Config()
    cfg.ALERT_LOG_FILE = "alerts.log"
    return cfg


class TestDashboard:
    def test_render_includes_alert_rate_and_top_offender(self):
        monitor = NetworkMonitor(_cfg())
        am = monitor.get_alert_manager()
        now = time.time()
        am.add(
            Alert(
                threat_type=ThreatType.DDOS,
                severity=AlertSeverity.CRITICAL,
                src_ip="10.10.10.10",
                description="critical",
                timestamp=now - 10,
            )
        )
        am.add(
            Alert(
                threat_type=ThreatType.PORT_SCAN,
                severity=AlertSeverity.HIGH,
                src_ip="10.10.10.10",
                description="scan",
                timestamp=now - 5,
            )
        )
        am.add(
            Alert(
                threat_type=ThreatType.SUSPICIOUS_PORT,
                severity=AlertSeverity.MEDIUM,
                src_ip="10.10.10.20",
                description="port",
                timestamp=now - 20,
            )
        )

        dashboard = Dashboard(monitor, _cfg())
        output = dashboard.render_once()
        assert "Alert rate/min" in output
        assert "Top offender 5m" in output
        assert "10.10.10.10" in output
