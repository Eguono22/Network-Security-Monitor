"""SOC automation playbook engine.

Consumes alerts and emits structured response actions based on threat type and
severity. Actions are written to a JSONL audit log for downstream SOAR/SIEM use.
"""

from __future__ import annotations

import time
from typing import Dict, List, Tuple

from .config import Config
from .incident_manager import IncidentManager
from .models import Alert, AlertSeverity, ThreatType
from .storage import JsonlStore

_SEVERITY_RANK = {
    AlertSeverity.LOW: 0,
    AlertSeverity.MEDIUM: 1,
    AlertSeverity.HIGH: 2,
    AlertSeverity.CRITICAL: 3,
}


class SOCAutomationEngine:
    """Executes deterministic playbooks in response to security alerts."""

    def __init__(self, config: Config | None = None):
        self._cfg = config or Config()
        self._incident_manager = IncidentManager(self._cfg.INCIDENTS_LOG_FILE)
        self._action_store = JsonlStore(self._cfg.SOC_AUTOMATION_LOG_FILE)
        self._cooldowns: Dict[Tuple[str, str], float] = {}
        self._counts: Dict[str, int] = {"executions": 0, "actions": 0, "suppressed": 0}

    def handle_alert(self, alert: Alert) -> List[dict]:
        """Return executed action payloads for *alert* (may be empty)."""
        if not self._cfg.SOC_AUTOMATION_ENABLED:
            return []
        if not self._meets_min_severity(alert):
            return []
        if self._is_suppressed(alert):
            self._counts["suppressed"] += 1
            return []

        actions = self._build_playbook(alert)
        if not actions:
            return []

        outputs = []
        now = time.time()
        for action in actions:
            action_payload = dict(action)
            if action_payload.get("type") == "create_case":
                case = self._incident_manager.create_case(
                    alert, queue=action_payload.get("queue", "soc-triage")
                )
                action_payload["incident_id"] = case["incident_id"]
            payload = {
                "timestamp": now,
                "threat_type": alert.threat_type.value,
                "severity": alert.severity.value,
                "src_ip": alert.src_ip,
                "dst_ip": alert.dst_ip,
                "dst_port": alert.dst_port,
                "description": alert.description,
                "action": action_payload,
            }
            self._write_action(payload)
            outputs.append(payload)

        self._counts["executions"] += 1
        self._counts["actions"] += len(outputs)
        self._cooldowns[(alert.threat_type.value, alert.src_ip)] = now
        return outputs

    def get_stats(self) -> dict:
        return dict(self._counts)

    def _meets_min_severity(self, alert: Alert) -> bool:
        raw = self._cfg.SOC_AUTOMATION_MIN_SEVERITY.upper()
        try:
            threshold = AlertSeverity[raw]
        except KeyError:
            threshold = AlertSeverity.HIGH
        return _SEVERITY_RANK[alert.severity] >= _SEVERITY_RANK[threshold]

    def _is_suppressed(self, alert: Alert) -> bool:
        key = (alert.threat_type.value, alert.src_ip)
        last = self._cooldowns.get(key, 0.0)
        return (time.time() - last) < self._cfg.SOC_AUTOMATION_COOLDOWN_SECONDS

    def _build_playbook(self, alert: Alert) -> List[dict]:
        base_actions = {
            ThreatType.PORT_SCAN: [
                {"type": "enrich_ip", "provider": "local-intel-cache"},
                {"type": "create_case", "queue": "soc-triage"},
            ],
            ThreatType.BRUTE_FORCE: [
                {"type": "enrich_ip", "provider": "local-intel-cache"},
                {"type": "create_case", "queue": "identity-incident"},
                {"type": "recommend_rate_limit", "target": alert.src_ip},
            ],
            ThreatType.DDOS: [
                {"type": "enrich_ip", "provider": "local-intel-cache"},
                {"type": "create_case", "queue": "network-incident"},
                {"type": "recommend_edge_block", "target": alert.src_ip},
            ],
            ThreatType.MALICIOUS_IP: [
                {"type": "create_case", "queue": "threat-intel"},
                {"type": "recommend_edge_block", "target": alert.src_ip},
            ],
            ThreatType.PHISHING_ATTEMPT: [
                {"type": "create_case", "queue": "email-security"},
                {"type": "recommend_domain_takedown_review", "target": alert.src_ip},
            ],
            ThreatType.DATA_EXFILTRATION: [
                {"type": "create_case", "queue": "data-protection"},
                {"type": "recommend_host_isolation", "target": alert.src_ip},
            ],
            ThreatType.DNS_TUNNELING: [
                {"type": "create_case", "queue": "dns-security"},
                {"type": "recommend_dns_sinkhole_review", "target": alert.src_ip},
            ],
            ThreatType.SUSPICIOUS_PORT: [
                {"type": "create_case", "queue": "soc-triage"},
            ],
            ThreatType.SYN_FLOOD: [
                {"type": "create_case", "queue": "network-incident"},
                {"type": "recommend_edge_block", "target": alert.src_ip},
            ],
            ThreatType.UNUSUAL_TRAFFIC: [
                {"type": "create_case", "queue": "soc-triage"},
            ],
        }

        actions = list(base_actions.get(alert.threat_type, []))
        if alert.severity == AlertSeverity.CRITICAL and self._cfg.SOC_AUTOMATION_AUTO_CONTAIN_CRITICAL:
            actions.append({"type": "auto_contain_host", "target": alert.src_ip})
        return actions

    def _write_action(self, payload: dict) -> None:
        self._action_store.append(payload)
