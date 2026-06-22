"""First-run smoke test for the Network Security Monitor project."""

from __future__ import annotations

import argparse
import json
import os
import shutil
from pathlib import Path
from typing import Any

from main import _simulate_traffic

from .config import Config
from .incident_manager import IncidentManager
from .monitor import NetworkMonitor
from .storage import AlertRepository, JsonlStore

_DEFAULT_ARTIFACT_DIR = Path(".tmp") / "first-run-demo"
_EXPECTED_THREATS = {
    "BRUTE_FORCE",
    "DATA_EXFILTRATION",
    "DDOS",
    "DNS_TUNNELING",
    "PHISHING_ATTEMPT",
    "PORT_SCAN",
    "SUSPICIOUS_PORT",
    "SYN_FLOOD",
}


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _resolve_artifact_dir(path: str) -> Path:
    artifact_dir = Path(path)
    if not artifact_dir.is_absolute():
        artifact_dir = _project_root() / artifact_dir
    return artifact_dir


def _build_config(artifact_dir: Path, profile: str) -> Config:
    config = Config(env_file=None)
    if profile:
        config.apply_profile(profile, str(_project_root() / "config_profiles.json"))
    config.SYN_FLOOD_THRESHOLD = min(config.SYN_FLOOD_THRESHOLD, 50)
    config.DATA_EXFIL_THRESHOLD_BYTES = min(
        config.DATA_EXFIL_THRESHOLD_BYTES,
        10 * 1024 * 1024,
    )
    config.ALERT_LOG_FILE = str(artifact_dir / "alerts.log")
    config.ALERTS_DATA_FILE = str(artifact_dir / "alerts.jsonl")
    config.SOC_AUTOMATION_LOG_FILE = str(artifact_dir / "soc_actions.jsonl")
    config.INCIDENTS_LOG_FILE = str(artifact_dir / "incidents.db")
    config.SIEM_OUTPUT_FILE = str(artifact_dir / "siem" / "alerts.jsonl")
    config.ALERT_NOTIFY_MIN_SEVERITY = "MEDIUM"
    config.SOC_AUTOMATION_MIN_SEVERITY = "MEDIUM"
    config.SOC_AUTOMATION_COOLDOWN_SECONDS = 0
    return config


def _set_api_environment(config: Config) -> dict[str, str | None]:
    keys = {
        "NSM_ALERTS_DATA_FILE": config.ALERTS_DATA_FILE,
        "NSM_ALERT_LOG_FILE": config.ALERT_LOG_FILE,
        "NSM_INCIDENTS_LOG_FILE": config.INCIDENTS_LOG_FILE,
        "NSM_SOC_AUTOMATION_LOG_FILE": config.SOC_AUTOMATION_LOG_FILE,
        "NSM_API_DEFAULT_ROLE": "admin",
    }
    previous = {key: os.environ.get(key) for key in keys}
    for key, value in keys.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    return previous


def _restore_environment(previous: dict[str, str | None]) -> None:
    for key, value in previous.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


def run_smoke_test(
    *,
    artifact_dir: str | Path = _DEFAULT_ARTIFACT_DIR,
    profile: str = "office_tuned",
) -> dict[str, Any]:
    """Run the demo flow and return a verification summary."""
    artifact_path = _resolve_artifact_dir(str(artifact_dir))
    shutil.rmtree(artifact_path, ignore_errors=True)
    artifact_path.mkdir(parents=True, exist_ok=True)

    config = _build_config(artifact_path, profile)
    monitor = NetworkMonitor(config)
    _simulate_traffic(monitor, duration=5.0)

    alert_manager = monitor.get_alert_manager()
    alerts = alert_manager.get_recent(500)
    threat_types = sorted({alert.threat_type.value for alert in alerts})
    incidents = IncidentManager(config.INCIDENTS_LOG_FILE).list_cases(limit=500)
    action_log = JsonlStore(config.SOC_AUTOMATION_LOG_FILE).read_recent(500)
    repository = AlertRepository(
        structured_path=config.ALERTS_DATA_FILE,
        log_path=config.ALERT_LOG_FILE,
    )
    stored_alerts = repository.read_recent(500)

    missing_threats = sorted(_EXPECTED_THREATS.difference(threat_types))
    if missing_threats:
        raise RuntimeError(
            "Smoke test did not generate the expected detections: "
            + ", ".join(missing_threats)
        )
    if not incidents:
        raise RuntimeError("Smoke test did not create any incidents.")
    if not action_log:
        raise RuntimeError("Smoke test did not produce SOC automation actions.")
    if not stored_alerts:
        raise RuntimeError("Smoke test did not persist any alert records.")

    previous = _set_api_environment(config)
    try:
        from api.index import app

        client = app.test_client()
        health = client.get("/health")
        api_alerts = client.get("/api/alerts", headers={"X-NSM-Role": "viewer"})
        api_incidents = client.get("/api/incidents", headers={"X-NSM-Role": "viewer"})
    finally:
        _restore_environment(previous)

    if health.status_code != 200:
        raise RuntimeError(f"Health endpoint returned {health.status_code}.")
    if api_alerts.status_code != 200:
        raise RuntimeError(f"Alerts endpoint returned {api_alerts.status_code}.")
    if api_incidents.status_code != 200:
        raise RuntimeError(f"Incidents endpoint returned {api_incidents.status_code}.")

    alerts_payload = api_alerts.get_json() or {}
    incidents_payload = api_incidents.get_json() or {}
    if int(alerts_payload.get("count", 0)) < len(_EXPECTED_THREATS):
        raise RuntimeError("Alerts API did not expose the expected demo dataset.")
    if int(incidents_payload.get("count", 0)) < 1:
        raise RuntimeError("Incidents API did not expose any cases.")

    summary = {
        "status": "ok",
        "profile": config.PROFILE_NAME,
        "artifact_dir": str(artifact_path),
        "packets_processed": monitor.get_stats().total_packets,
        "alert_count": alert_manager.get_stats()["total"],
        "threat_types": threat_types,
        "incident_count": len(incidents),
        "soc_action_count": len(action_log),
        "api": {
            "health_status": health.status_code,
            "alerts_count": alerts_payload.get("count", 0),
            "incidents_count": incidents_payload.get("count", 0),
        },
        "artifacts": {
            "alert_log": config.ALERT_LOG_FILE,
            "structured_alerts": config.ALERTS_DATA_FILE,
            "soc_actions": config.SOC_AUTOMATION_LOG_FILE,
            "incidents_db": config.INCIDENTS_LOG_FILE,
        },
    }
    summary_path = artifact_path / "smoke_test_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    summary["summary_file"] = str(summary_path)
    return summary


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nsm-smoke",
        description="Run the first-run NSM demo flow and verify its artifacts.",
    )
    parser.add_argument(
        "--artifact-dir",
        default=str(_DEFAULT_ARTIFACT_DIR),
        help="Directory where demo artifacts and the smoke test summary are written.",
    )
    parser.add_argument(
        "--profile",
        default="office_tuned",
        help="Config profile from config_profiles.json to apply during the smoke run.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    summary = run_smoke_test(artifact_dir=args.artifact_dir, profile=args.profile)

    print("\nSmoke test passed.")
    print(f"  Profile       : {summary['profile']}")
    print(f"  Packets       : {summary['packets_processed']}")
    print(f"  Alerts        : {summary['alert_count']}")
    print(f"  Incidents     : {summary['incident_count']}")
    print(f"  Artifact dir  : {summary['artifact_dir']}")
    print(f"  Summary file  : {summary['summary_file']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
