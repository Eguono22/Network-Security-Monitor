"""Tests for Alert and AlertManager."""

from __future__ import annotations

import pytest
from datetime import datetime, timedelta

from nsm.alert import Alert, AlertManager, AlertSeverity


def _alert(**kwargs) -> Alert:
    defaults = dict(
        alert_type="PORT_SCAN",
        severity=AlertSeverity.HIGH,
        source_ip="10.0.0.1",
        message="Test alert",
    )
    defaults.update(kwargs)
    return Alert(**defaults)


class TestAlertCreation:
    def test_basic_creation(self):
        a = _alert()
        assert a.alert_type == "PORT_SCAN"
        assert a.severity == AlertSeverity.HIGH
        assert a.source_ip == "10.0.0.1"
        assert a.id  # UUID assigned

    def test_auto_timestamp(self):
        before = datetime.utcnow()
        a = _alert()
        after = datetime.utcnow()
        assert before <= a.timestamp <= after

    def test_custom_timestamp(self):
        ts = datetime(2024, 6, 1, 0, 0, 0)
        a = _alert(timestamp=ts)
        assert a.timestamp == ts

    def test_details_default_empty(self):
        a = _alert()
        assert a.details == {}

    def test_custom_details(self):
        a = _alert(details={"port": 22})
        assert a.details["port"] == 22

    def test_str_representation(self):
        a = _alert()
        s = str(a)
        assert "PORT_SCAN" in s
        assert "10.0.0.1" in s

    def test_unique_ids(self):
        a1 = _alert()
        a2 = _alert()
        assert a1.id != a2.id


class TestAlertValidation:
    def test_empty_alert_type_raises(self):
        with pytest.raises(ValueError, match="alert_type"):
            _alert(alert_type="")

    def test_empty_source_ip_raises(self):
        with pytest.raises(ValueError, match="source_ip"):
            _alert(source_ip="")

    def test_empty_message_raises(self):
        with pytest.raises(ValueError, match="message"):
            _alert(message="")


class TestAlertSeverity:
    def test_ordering(self):
        assert AlertSeverity.LOW.value < AlertSeverity.MEDIUM.value
        assert AlertSeverity.MEDIUM.value < AlertSeverity.HIGH.value
        assert AlertSeverity.HIGH.value < AlertSeverity.CRITICAL.value

    def test_str(self):
        assert str(AlertSeverity.CRITICAL) == "CRITICAL"


class TestAlertManager:
    def setup_method(self):
        self.mgr = AlertManager()

    def test_empty_initially(self):
        assert self.mgr.count() == 0
        assert self.mgr.get_all() == []

    def test_add_alert(self):
        self.mgr.add_alert(_alert())
        assert self.mgr.count() == 1

    def test_add_multiple(self):
        for _ in range(5):
            self.mgr.add_alert(_alert())
        assert self.mgr.count() == 5

    def test_get_all(self):
        a = _alert()
        self.mgr.add_alert(a)
        all_alerts = self.mgr.get_all()
        assert len(all_alerts) == 1
        assert all_alerts[0].id == a.id

    def test_get_all_returns_copy(self):
        self.mgr.add_alert(_alert())
        r1 = self.mgr.get_all()
        r1.clear()
        assert self.mgr.count() == 1  # internal list unchanged

    def test_clear(self):
        self.mgr.add_alert(_alert())
        self.mgr.clear()
        assert self.mgr.count() == 0

    def test_filter_by_severity(self):
        self.mgr.add_alert(_alert(severity=AlertSeverity.HIGH))
        self.mgr.add_alert(_alert(severity=AlertSeverity.LOW))
        highs = self.mgr.get_alerts(severity=AlertSeverity.HIGH)
        assert len(highs) == 1
        assert highs[0].severity == AlertSeverity.HIGH

    def test_filter_by_type(self):
        self.mgr.add_alert(_alert(alert_type="PORT_SCAN"))
        self.mgr.add_alert(_alert(alert_type="BRUTE_FORCE"))
        r = self.mgr.get_alerts(alert_type="PORT_SCAN")
        assert len(r) == 1

    def test_filter_by_source_ip(self):
        self.mgr.add_alert(_alert(source_ip="1.2.3.4"))
        self.mgr.add_alert(_alert(source_ip="5.6.7.8"))
        r = self.mgr.get_alerts(source_ip="1.2.3.4")
        assert len(r) == 1

    def test_filter_by_since(self):
        past = datetime.utcnow() - timedelta(hours=1)
        future_ts = datetime.utcnow() + timedelta(seconds=1)
        old = _alert(timestamp=past)
        new = _alert()
        self.mgr.add_alert(old)
        self.mgr.add_alert(new)
        recent = self.mgr.get_alerts(since=datetime.utcnow() - timedelta(minutes=1))
        assert len(recent) == 1

    def test_combined_filters(self):
        self.mgr.add_alert(_alert(alert_type="PORT_SCAN", severity=AlertSeverity.HIGH))
        self.mgr.add_alert(_alert(alert_type="PORT_SCAN", severity=AlertSeverity.LOW))
        self.mgr.add_alert(_alert(alert_type="BRUTE_FORCE", severity=AlertSeverity.HIGH))
        r = self.mgr.get_alerts(alert_type="PORT_SCAN", severity=AlertSeverity.HIGH)
        assert len(r) == 1

    def test_get_summary_empty(self):
        s = self.mgr.get_summary()
        assert s["total"] == 0
        assert s["by_severity"] == {}
        assert s["by_type"] == {}

    def test_get_summary(self):
        self.mgr.add_alert(_alert(alert_type="PORT_SCAN", severity=AlertSeverity.HIGH))
        self.mgr.add_alert(_alert(alert_type="PORT_SCAN", severity=AlertSeverity.HIGH))
        self.mgr.add_alert(_alert(alert_type="BRUTE_FORCE", severity=AlertSeverity.CRITICAL))
        s = self.mgr.get_summary()
        assert s["total"] == 3
        assert s["by_type"]["PORT_SCAN"] == 2
        assert s["by_severity"]["HIGH"] == 2
        assert s["by_severity"]["CRITICAL"] == 1

    def test_get_top_sources(self):
        for _ in range(3):
            self.mgr.add_alert(_alert(source_ip="1.1.1.1"))
        for _ in range(2):
            self.mgr.add_alert(_alert(source_ip="2.2.2.2"))
        self.mgr.add_alert(_alert(source_ip="3.3.3.3"))
        top = self.mgr.get_top_sources(n=2)
        assert top[0] == ("1.1.1.1", 3)
        assert top[1] == ("2.2.2.2", 2)

    def test_get_top_sources_respects_n(self):
        for ip in ("1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"):
            self.mgr.add_alert(_alert(source_ip=ip))
        assert len(self.mgr.get_top_sources(n=2)) == 2
