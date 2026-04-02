"""Tests for the visualization module."""

from __future__ import annotations

import io
import sys
from datetime import datetime, timedelta
from typing import List

import pytest

from nsm.alert import Alert, AlertSeverity
from nsm.packet import Packet
from nsm.visualization import print_dashboard, save_charts


def _ts(offset: float = 0.0) -> datetime:
    return datetime(2024, 1, 1, 12, 0, 0) + timedelta(seconds=offset)


def _pkt(src_ip="10.0.0.1", dst_ip="10.0.0.2", dst_port=80, size=500,
         ts_offset=0.0) -> Packet:
    return Packet(
        timestamp=_ts(ts_offset),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=50000,
        dst_port=dst_port,
        protocol="TCP",
        size=size,
        flags=[],
    )


def _alert(**kwargs) -> Alert:
    defaults = dict(
        alert_type="PORT_SCAN",
        severity=AlertSeverity.HIGH,
        source_ip="10.0.0.1",
        message="Test alert",
    )
    defaults.update(kwargs)
    return Alert(**defaults)


# ---------------------------------------------------------------------------
# print_dashboard
# ---------------------------------------------------------------------------

class TestPrintDashboard:
    def _capture(self, packets: List[Packet], alerts: List[Alert]) -> str:
        buf = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = buf
        try:
            print_dashboard(packets, alerts)
        finally:
            sys.stdout = old_stdout
        return buf.getvalue()

    def test_prints_without_error(self):
        packets = [_pkt(ts_offset=i) for i in range(5)]
        alerts = [_alert()]
        output = self._capture(packets, alerts)
        assert len(output) > 0

    def test_shows_packet_count(self):
        packets = [_pkt(ts_offset=i) for i in range(7)]
        output = self._capture(packets, [])
        assert "7" in output

    def test_shows_alert_count(self):
        alerts = [_alert() for _ in range(3)]
        output = self._capture([], alerts)
        assert "3" in output

    def test_shows_no_alerts_when_empty(self):
        output = self._capture([], [])
        assert "No alerts" in output

    def test_shows_source_ip(self):
        packets = [_pkt(src_ip="192.168.1.1", ts_offset=i) for i in range(5)]
        output = self._capture(packets, [])
        assert "192.168.1.1" in output

    def test_shows_alert_type(self):
        alerts = [_alert(alert_type="DDOS")]
        output = self._capture([], alerts)
        assert "DDOS" in output

    def test_shows_alert_severity(self):
        alerts = [_alert(severity=AlertSeverity.CRITICAL)]
        output = self._capture([], alerts)
        assert "CRITICAL" in output

    def test_empty_packets_and_alerts(self):
        output = self._capture([], [])
        assert "TRAFFIC SUMMARY" in output

    def test_shows_protocol_distribution(self):
        packets = [_pkt(ts_offset=i) for i in range(3)]
        output = self._capture(packets, [])
        assert "TCP" in output

    def test_large_packet_set(self):
        packets = [_pkt(ts_offset=i, size=1000) for i in range(100)]
        alerts = [_alert() for _ in range(20)]
        output = self._capture(packets, alerts)
        assert "NETWORK SECURITY MONITOR" in output


# ---------------------------------------------------------------------------
# save_charts
# ---------------------------------------------------------------------------

class TestSaveCharts:
    def test_returns_list(self, tmp_path):
        packets = [_pkt(ts_offset=i) for i in range(5)]
        alerts = [_alert()]
        result = save_charts(packets, alerts, output_dir=str(tmp_path))
        assert isinstance(result, list)

    def test_creates_output_dir(self, tmp_path):
        import os
        charts_dir = str(tmp_path / "subdir" / "charts")
        save_charts([], [], output_dir=charts_dir)
        assert os.path.isdir(charts_dir)

    def test_saves_png_files(self, tmp_path):
        import os
        packets = [_pkt(ts_offset=i) for i in range(10)]
        alerts = [_alert(alert_type="PORT_SCAN"), _alert(alert_type="DDOS")]
        paths = save_charts(packets, alerts, output_dir=str(tmp_path))
        for path in paths:
            assert os.path.exists(path)
            assert path.endswith(".png")

    def test_empty_input_no_error(self, tmp_path):
        paths = save_charts([], [], output_dir=str(tmp_path))
        assert isinstance(paths, list)

    def test_no_alerts_skips_alert_charts(self, tmp_path):
        packets = [_pkt(ts_offset=i) for i in range(5)]
        paths = save_charts(packets, [], output_dir=str(tmp_path))
        saved_names = [p.split("/")[-1] for p in paths]
        assert "alert_severity.png" not in saved_names
        assert "alert_types.png" not in saved_names

    def test_chart_filenames(self, tmp_path):
        packets = [_pkt(ts_offset=i) for i in range(10)]
        alerts = [_alert()]
        paths = save_charts(packets, alerts, output_dir=str(tmp_path))
        names = {p.split("/")[-1] for p in paths}
        # At least traffic charts expected
        assert "traffic_volume.png" in names
