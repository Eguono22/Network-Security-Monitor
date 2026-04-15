"""Unit tests for SOC automation playbook engine."""

import json
import shutil
import time
import uuid
from pathlib import Path

from network_security_monitor.config import Config
from network_security_monitor.models import Alert, AlertSeverity, ThreatType
from network_security_monitor.soc_automation import SOCAutomationEngine


def _make_alert(
    threat_type=ThreatType.DDOS,
    severity=AlertSeverity.CRITICAL,
    src_ip="10.0.0.9",
) -> Alert:
    return Alert(
        threat_type=threat_type,
        severity=severity,
        src_ip=src_ip,
        dst_ip="192.168.1.10",
        description="automation test alert",
        timestamp=time.time(),
    )


class TestSOCAutomationEngine:
    def test_writes_actions_for_eligible_alert(self):
        tmp_root = Path(".test_tmp") / f"soc-{uuid.uuid4().hex}"
        tmp_root.mkdir(parents=True, exist_ok=True)
        try:
            cfg = Config()
            cfg.SOC_AUTOMATION_LOG_FILE = str(tmp_root / "soc" / "actions.jsonl")
            cfg.INCIDENTS_LOG_FILE = str(tmp_root / "soc" / "incidents.jsonl")
            cfg.SOC_AUTOMATION_MIN_SEVERITY = "HIGH"
            engine = SOCAutomationEngine(cfg)
            outputs = engine.handle_alert(_make_alert())
            assert len(outputs) >= 1

            lines = (tmp_root / "soc" / "actions.jsonl").read_text(encoding="utf-8").splitlines()
            assert len(lines) == len(outputs)
            payload = json.loads(lines[0])
            assert payload["threat_type"] == "DDOS"
            assert payload["severity"] == "CRITICAL"
            create_case = [o for o in outputs if o["action"]["type"] == "create_case"]
            assert create_case
            assert create_case[0]["action"]["incident_id"].startswith("INC-")
            assert (tmp_root / "soc" / "incidents.db").exists()
        finally:
            shutil.rmtree(tmp_root, ignore_errors=True)

    def test_respects_min_severity(self):
        tmp_root = Path(".test_tmp") / f"soc-{uuid.uuid4().hex}"
        tmp_root.mkdir(parents=True, exist_ok=True)
        try:
            cfg = Config()
            cfg.SOC_AUTOMATION_LOG_FILE = str(tmp_root / "soc" / "actions.jsonl")
            cfg.INCIDENTS_LOG_FILE = str(tmp_root / "soc" / "incidents.jsonl")
            cfg.SOC_AUTOMATION_MIN_SEVERITY = "CRITICAL"
            engine = SOCAutomationEngine(cfg)
            outputs = engine.handle_alert(
                _make_alert(threat_type=ThreatType.SUSPICIOUS_PORT, severity=AlertSeverity.MEDIUM)
            )
            assert outputs == []
            assert not (tmp_root / "soc" / "actions.jsonl").exists()
        finally:
            shutil.rmtree(tmp_root, ignore_errors=True)

    def test_suppresses_repeat_actions_within_cooldown(self):
        tmp_root = Path(".test_tmp") / f"soc-{uuid.uuid4().hex}"
        tmp_root.mkdir(parents=True, exist_ok=True)
        try:
            cfg = Config()
            cfg.SOC_AUTOMATION_LOG_FILE = str(tmp_root / "soc" / "actions.jsonl")
            cfg.INCIDENTS_LOG_FILE = str(tmp_root / "soc" / "incidents.jsonl")
            cfg.SOC_AUTOMATION_COOLDOWN_SECONDS = 999
            engine = SOCAutomationEngine(cfg)
            first = engine.handle_alert(_make_alert(src_ip="10.10.10.10"))
            second = engine.handle_alert(_make_alert(src_ip="10.10.10.10"))
            assert len(first) >= 1
            assert second == []
        finally:
            shutil.rmtree(tmp_root, ignore_errors=True)

    def test_optional_auto_contain_for_critical(self):
        tmp_root = Path(".test_tmp") / f"soc-{uuid.uuid4().hex}"
        tmp_root.mkdir(parents=True, exist_ok=True)
        try:
            cfg = Config()
            cfg.SOC_AUTOMATION_LOG_FILE = str(tmp_root / "soc" / "actions.jsonl")
            cfg.INCIDENTS_LOG_FILE = str(tmp_root / "soc" / "incidents.jsonl")
            cfg.SOC_AUTOMATION_AUTO_CONTAIN_CRITICAL = True
            engine = SOCAutomationEngine(cfg)
            outputs = engine.handle_alert(_make_alert(threat_type=ThreatType.DDOS))
            assert any(o["action"]["type"] == "auto_contain_host" for o in outputs)
        finally:
            shutil.rmtree(tmp_root, ignore_errors=True)
