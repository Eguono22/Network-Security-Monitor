"""Unit tests for AlertManager."""

import json
import shutil
import time
import uuid
from pathlib import Path

import pytest

from network_security_monitor.alert_manager import AlertManager
from network_security_monitor.config import Config
from network_security_monitor.models import Alert, AlertSeverity, ThreatType


def _make_alert(severity=AlertSeverity.HIGH, threat_type=ThreatType.PORT_SCAN,
                src_ip="10.0.0.1") -> Alert:
    return Alert(
        threat_type=threat_type,
        severity=severity,
        src_ip=src_ip,
        description="Test alert",
        timestamp=time.time(),
    )


class TestAlertManager:
    def test_add_and_get_recent(self):
        am = AlertManager()
        am.add(_make_alert())
        recent = am.get_recent(10)
        assert len(recent) == 1

    def test_get_recent_respects_n(self):
        am = AlertManager()
        for _ in range(20):
            am.add(_make_alert())
        recent = am.get_recent(5)
        assert len(recent) == 5

    def test_get_recent_newest_last(self):
        am = AlertManager()
        for i in range(5):
            am.add(_make_alert(src_ip=f"10.0.0.{i}"))
        recent = am.get_recent(5)
        assert recent[-1].src_ip == "10.0.0.4"

    def test_get_by_severity(self):
        am = AlertManager()
        am.add(_make_alert(severity=AlertSeverity.HIGH))
        am.add(_make_alert(severity=AlertSeverity.CRITICAL))
        am.add(_make_alert(severity=AlertSeverity.MEDIUM))
        high = am.get_by_severity(AlertSeverity.HIGH)
        assert len(high) == 1
        assert high[0].severity == AlertSeverity.HIGH

    def test_get_by_threat_type(self):
        am = AlertManager()
        am.add(_make_alert(threat_type=ThreatType.PORT_SCAN))
        am.add(_make_alert(threat_type=ThreatType.DDOS))
        am.add(_make_alert(threat_type=ThreatType.PORT_SCAN))
        port_scans = am.get_by_threat_type(ThreatType.PORT_SCAN)
        assert len(port_scans) == 2

    def test_get_stats_counts(self):
        am = AlertManager()
        am.add(_make_alert(severity=AlertSeverity.CRITICAL, threat_type=ThreatType.DDOS))
        am.add(_make_alert(severity=AlertSeverity.HIGH, threat_type=ThreatType.PORT_SCAN))
        stats = am.get_stats()
        assert stats["total"] == 2
        assert stats["by_severity"]["CRITICAL"] == 1
        assert stats["by_severity"]["HIGH"] == 1
        assert stats["by_threat_type"]["DDOS"] == 1
        assert stats["by_threat_type"]["PORT_SCAN"] == 1

    def test_clear(self):
        am = AlertManager()
        am.add(_make_alert())
        am.add(_make_alert())
        am.clear()
        assert am.get_recent() == []

    def test_callback_is_invoked(self):
        am = AlertManager()
        received = []
        am.register_callback(received.append)
        alert = _make_alert()
        am.add(alert)
        assert len(received) == 1
        assert received[0] is alert

    def test_multiple_callbacks(self):
        am = AlertManager()
        results_a, results_b = [], []
        am.register_callback(results_a.append)
        am.register_callback(results_b.append)
        am.add(_make_alert())
        assert len(results_a) == 1
        assert len(results_b) == 1

    def test_max_history_respected(self):
        cfg = Config()
        cfg.MAX_ALERT_HISTORY = 5
        am = AlertManager(cfg)
        for _ in range(10):
            am.add(_make_alert())
        assert len(am.get_recent(100)) == 5

    def test_faulty_callback_does_not_crash(self):
        am = AlertManager()

        def bad_callback(alert):
            raise RuntimeError("broken")

        am.register_callback(bad_callback)
        # Should not raise
        am.add(_make_alert())
        assert am.get_stats()["total"] == 1

    def test_siem_output_file_callback_writes_jsonl(self):
        tmp_root = Path(".test_tmp") / f"siem-{uuid.uuid4().hex}"
        tmp_root.mkdir(parents=True, exist_ok=True)
        cfg = Config()
        cfg.SIEM_OUTPUT_FILE = str(tmp_root / "siem" / "alerts.jsonl")
        cfg.ALERT_NOTIFY_MIN_SEVERITY = "MEDIUM"
        am = AlertManager(cfg)
        am.add(_make_alert(severity=AlertSeverity.HIGH, threat_type=ThreatType.DDOS))

        try:
            lines = (tmp_root / "siem" / "alerts.jsonl").read_text(encoding="utf-8").splitlines()
            assert len(lines) == 1
            payload = json.loads(lines[0])
            assert payload["severity"] == "HIGH"
            assert payload["threat_type"] == "DDOS"
        finally:
            shutil.rmtree(tmp_root, ignore_errors=True)

    def test_siem_output_respects_min_notify_severity(self):
        tmp_root = Path(".test_tmp") / f"siem-{uuid.uuid4().hex}"
        tmp_root.mkdir(parents=True, exist_ok=True)
        cfg = Config()
        cfg.SIEM_OUTPUT_FILE = str(tmp_root / "siem" / "alerts.jsonl")
        cfg.ALERT_NOTIFY_MIN_SEVERITY = "CRITICAL"
        am = AlertManager(cfg)
        am.add(_make_alert(severity=AlertSeverity.HIGH))
        try:
            path = tmp_root / "siem" / "alerts.jsonl"
            assert not path.exists()
        finally:
            shutil.rmtree(tmp_root, ignore_errors=True)

    def test_structured_alert_store_writes_jsonl(self):
        tmp_root = Path(".test_tmp") / f"alerts-{uuid.uuid4().hex}"
        tmp_root.mkdir(parents=True, exist_ok=True)
        cfg = Config()
        cfg.ALERTS_DATA_FILE = str(tmp_root / "alerts.jsonl")
        am = AlertManager(cfg)
        am.add(_make_alert(severity=AlertSeverity.CRITICAL, threat_type=ThreatType.DDOS))

        try:
            lines = (tmp_root / "alerts.jsonl").read_text(encoding="utf-8").splitlines()
            assert len(lines) == 1
            payload = json.loads(lines[0])
            assert payload["severity"] == "CRITICAL"
            assert payload["threat_type"] == "DDOS"
            assert payload["raw"]
        finally:
            shutil.rmtree(tmp_root, ignore_errors=True)
