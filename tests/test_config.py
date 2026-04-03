"""Unit tests for Config profile loading."""

import json
import os
import shutil
import uuid
from pathlib import Path

from network_security_monitor.config import Config


class TestConfigProfiles:
    def test_apply_profile_from_file(self):
        root = Path(".test_tmp") / f"profile-{uuid.uuid4().hex}"
        root.mkdir(parents=True, exist_ok=True)
        profile_file = root / "profiles.json"
        profile_file.write_text(
            json.dumps(
                {
                    "profiles": {
                        "test": {
                            "PORT_SCAN_THRESHOLD": 99,
                            "DDOS_THRESHOLD": 2222,
                            "SUSPICIOUS_PORTS": [4444, 31337],
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        cfg = Config()
        try:
            assert cfg.apply_profile("test", str(profile_file)) is True
            assert cfg.PORT_SCAN_THRESHOLD == 99
            assert cfg.DDOS_THRESHOLD == 2222
            assert 4444 in cfg.SUSPICIOUS_PORTS
            assert 31337 in cfg.SUSPICIOUS_PORTS
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_apply_profile_returns_false_for_missing(self):
        cfg = Config()
        assert cfg.apply_profile("missing", "does-not-exist.json") is False

    def test_loads_values_from_env_file(self):
        root = Path(".test_tmp") / f"env-{uuid.uuid4().hex}"
        root.mkdir(parents=True, exist_ok=True)
        env_file = root / ".env"
        env_file.write_text(
            "NSM_ALERT_NOTIFY_MIN_SEVERITY=CRITICAL\nNSM_ALERT_LOG_BACKUP_COUNT=7\n",
            encoding="utf-8",
        )
        try:
            os.environ.pop("NSM_ALERT_NOTIFY_MIN_SEVERITY", None)
            os.environ.pop("NSM_ALERT_LOG_BACKUP_COUNT", None)
            cfg = Config(env_file=str(env_file))
            assert cfg.ALERT_NOTIFY_MIN_SEVERITY == "CRITICAL"
            assert cfg.ALERT_LOG_BACKUP_COUNT == 7
        finally:
            shutil.rmtree(root, ignore_errors=True)
            os.environ.pop("NSM_ALERT_NOTIFY_MIN_SEVERITY", None)
            os.environ.pop("NSM_ALERT_LOG_BACKUP_COUNT", None)
