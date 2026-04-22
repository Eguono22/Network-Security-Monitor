"""Configuration for the Network Security Monitor."""

import json
import os
from pathlib import Path
from typing import Set


class Config:
    """Central configuration for detection thresholds and system settings."""

    # ---------------------------------------------------------------------------
    # Network interface
    # ---------------------------------------------------------------------------
    INTERFACE: str = ""  # Empty string = auto-detect default interface

    # ---------------------------------------------------------------------------
    # Port-scan detection
    # ---------------------------------------------------------------------------
    # How many distinct destination ports a single source IP must touch within
    # PORT_SCAN_TIME_WINDOW seconds before it is flagged as a port scan.
    PORT_SCAN_THRESHOLD: int = 25
    PORT_SCAN_TIME_WINDOW: int = 15  # seconds
    # Optional allowlist of source IPs that should not trigger port-scan alerts
    # (useful for known internal discovery/scanner infrastructure).
    PORT_SCAN_TRUSTED_SOURCES: Set[str] = set()

    # ---------------------------------------------------------------------------
    # SYN-flood detection
    # ---------------------------------------------------------------------------
    # SYN packets per second from a single source IP before raising an alert.
    SYN_FLOOD_THRESHOLD: int = 200
    SYN_FLOOD_TIME_WINDOW: float = 1.0  # seconds

    # ---------------------------------------------------------------------------
    # Brute-force detection
    # ---------------------------------------------------------------------------
    # Number of connection attempts to authentication services within
    # BRUTE_FORCE_TIME_WINDOW seconds before an alert is raised.
    BRUTE_FORCE_THRESHOLD: int = 12
    BRUTE_FORCE_TIME_WINDOW: int = 60  # seconds
    # Well-known authentication service ports
    BRUTE_FORCE_PORTS: Set[int] = {22, 21, 23, 25, 110, 143, 3389, 5900}

    # ---------------------------------------------------------------------------
    # DDoS detection
    # ---------------------------------------------------------------------------
    # Total packets per second originating from a single IP.
    DDOS_THRESHOLD: int = 1500
    DDOS_TIME_WINDOW: float = 1.0  # seconds

    # ---------------------------------------------------------------------------
    # DNS-tunneling detection
    # ---------------------------------------------------------------------------
    # DNS query payload size (bytes) above which traffic is treated as suspicious.
    DNS_QUERY_SIZE_THRESHOLD: int = 700
    # Number of large DNS queries within DNS_TIME_WINDOW seconds.
    DNS_LARGE_QUERY_THRESHOLD: int = 12
    DNS_TIME_WINDOW: int = 90  # seconds

    # ---------------------------------------------------------------------------
    # OT / Modbus monitoring
    # ---------------------------------------------------------------------------
    # Detect repeated Modbus/TCP function calls against a PLC or OT endpoint.
    MODBUS_PORTS: Set[int] = {502}
    MODBUS_COMMAND_SPIKE_THRESHOLD: int = 20
    MODBUS_TIME_WINDOW: int = 30  # seconds

    # ---------------------------------------------------------------------------
    # Suspicious ports
    # ---------------------------------------------------------------------------
    # Connections to these destination ports are flagged immediately.
    SUSPICIOUS_PORTS: Set[int] = {
        4444,   # Metasploit default
        1337,   # common backdoor
        31337,  # common backdoor / elite port
        6666,   # IRC / botnet C2
        6667,   # IRC
        7777,   # common backdoor
        8888,   # common backdoor
        9001,   # Tor relay
        9030,   # Tor directory
        12345,  # NetBus trojan
        27374,  # SubSeven trojan
    }

    # ---------------------------------------------------------------------------
    # Known-malicious IP addresses
    # (In production these would be loaded from threat-intelligence feeds.)
    # ---------------------------------------------------------------------------
    KNOWN_MALICIOUS_IPS: Set[str] = set()

    # ---------------------------------------------------------------------------
    # Phishing detection
    # ---------------------------------------------------------------------------
    # Domains / indicators often seen in phishing campaigns.
    PHISHING_DOMAINS: Set[str] = {
        "secure-login-verify.com",
        "update-your-account.net",
        "microsoft-security-check.com",
        "paypal-verification-alert.com",
    }

    # ---------------------------------------------------------------------------
    # Data-exfiltration detection
    # ---------------------------------------------------------------------------
    # Detect unusually large upload volume per source within the window.
    DATA_EXFIL_TIME_WINDOW: int = 300  # seconds
    DATA_EXFIL_THRESHOLD_BYTES: int = 50 * 1024 * 1024  # 50 MB / 5 minutes

    # ---------------------------------------------------------------------------
    # Unusual-traffic (anomaly) detection
    # ---------------------------------------------------------------------------
    # Compares short-term packet count to a rolling baseline per source IP.
    TRAFFIC_ANOMALY_TIME_WINDOW: int = 30  # seconds
    TRAFFIC_ANOMALY_MIN_PACKETS: int = 300
    TRAFFIC_ANOMALY_MULTIPLIER: float = 3.5

    # ---------------------------------------------------------------------------
    # Alert / logging
    # ---------------------------------------------------------------------------
    ALERT_LOG_FILE: str = "alerts.log"
    ALERT_LOG_MAX_BYTES: int = 5 * 1024 * 1024
    ALERT_LOG_BACKUP_COUNT: int = 5
    # Maximum number of alerts kept in memory before the oldest are discarded.
    MAX_ALERT_HISTORY: int = 10_000
    # Minimum severity level to write to the log file (DEBUG < INFO < WARNING …)
    MIN_LOG_SEVERITY: str = "INFO"
    # Minimum severity level for outbound notifications/integrations.
    ALERT_NOTIFY_MIN_SEVERITY: str = "HIGH"
    # Optional generic webhook integration (POSTs JSON payload per alert).
    ALERT_WEBHOOK_URL: str = ""
    # Optional Slack incoming webhook URL.
    SLACK_WEBHOOK_URL: str = ""
    # Optional email integration.
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""
    ALERT_EMAIL_FROM: str = "nsm@localhost"
    ALERT_EMAIL_TO: str = ""
    # Optional SIEM-style JSONL file output for alert forwarding.
    SIEM_OUTPUT_FILE: str = ""
    # Optional structured JSONL alert persistence for API/UI consumers.
    ALERTS_DATA_FILE: str = ""
    # ---------------------------------------------------------------------------
    # SOC automation
    # ---------------------------------------------------------------------------
    SOC_AUTOMATION_ENABLED: bool = True
    SOC_AUTOMATION_MIN_SEVERITY: str = "HIGH"
    SOC_AUTOMATION_COOLDOWN_SECONDS: int = 300
    SOC_AUTOMATION_LOG_FILE: str = "soc_actions.log"
    # SQLite-backed incident case persistence. Legacy ``incidents.jsonl`` files
    # are imported automatically when the sibling database is first created.
    INCIDENTS_LOG_FILE: str = "incidents.db"
    SOC_AUTOMATION_AUTO_CONTAIN_CRITICAL: bool = False
    # API/UI role defaults. Existing local behavior stays permissive unless this
    # is overridden by environment or an upstream proxy injects X-NSM-Role.
    API_DEFAULT_ROLE: str = "admin"

    # ---------------------------------------------------------------------------
    # Dashboard
    # ---------------------------------------------------------------------------
    DASHBOARD_REFRESH_INTERVAL: float = 1.0  # seconds
    DASHBOARD_TOP_TALKERS_COUNT: int = 10
    PROFILE_NAME: str = "custom"
    PROFILE_FILE: str = "config_profiles.json"

    def __init__(self, env_file: str | None = ".env"):
        self._load_dotenv(env_file)
        # Lightweight env-based overrides for deployment flexibility.
        self.ALERT_NOTIFY_MIN_SEVERITY = os.getenv(
            "NSM_ALERT_NOTIFY_MIN_SEVERITY", self.ALERT_NOTIFY_MIN_SEVERITY
        ).upper()
        self.ALERT_WEBHOOK_URL = os.getenv("NSM_ALERT_WEBHOOK_URL", self.ALERT_WEBHOOK_URL)
        self.SLACK_WEBHOOK_URL = os.getenv("NSM_SLACK_WEBHOOK_URL", self.SLACK_WEBHOOK_URL)
        self.SMTP_HOST = os.getenv("NSM_SMTP_HOST", self.SMTP_HOST)
        self.SMTP_PORT = int(os.getenv("NSM_SMTP_PORT", str(self.SMTP_PORT)))
        self.SMTP_USERNAME = os.getenv("NSM_SMTP_USERNAME", self.SMTP_USERNAME)
        self.SMTP_PASSWORD = os.getenv("NSM_SMTP_PASSWORD", self.SMTP_PASSWORD)
        self.ALERT_EMAIL_FROM = os.getenv("NSM_ALERT_EMAIL_FROM", self.ALERT_EMAIL_FROM)
        self.ALERT_EMAIL_TO = os.getenv("NSM_ALERT_EMAIL_TO", self.ALERT_EMAIL_TO)
        self.SIEM_OUTPUT_FILE = os.getenv("NSM_SIEM_OUTPUT_FILE", self.SIEM_OUTPUT_FILE)
        self.ALERTS_DATA_FILE = os.getenv("NSM_ALERTS_DATA_FILE", self.ALERTS_DATA_FILE)
        self.ALERT_LOG_MAX_BYTES = int(
            os.getenv("NSM_ALERT_LOG_MAX_BYTES", str(self.ALERT_LOG_MAX_BYTES))
        )
        self.ALERT_LOG_BACKUP_COUNT = int(
            os.getenv("NSM_ALERT_LOG_BACKUP_COUNT", str(self.ALERT_LOG_BACKUP_COUNT))
        )
        self.SOC_AUTOMATION_ENABLED = self._env_bool(
            os.getenv("NSM_SOC_AUTOMATION_ENABLED"),
            self.SOC_AUTOMATION_ENABLED,
        )
        self.SOC_AUTOMATION_MIN_SEVERITY = os.getenv(
            "NSM_SOC_AUTOMATION_MIN_SEVERITY", self.SOC_AUTOMATION_MIN_SEVERITY
        ).upper()
        self.SOC_AUTOMATION_COOLDOWN_SECONDS = int(
            os.getenv(
                "NSM_SOC_AUTOMATION_COOLDOWN_SECONDS",
                str(self.SOC_AUTOMATION_COOLDOWN_SECONDS),
            )
        )
        self.SOC_AUTOMATION_LOG_FILE = os.getenv(
            "NSM_SOC_AUTOMATION_LOG_FILE", self.SOC_AUTOMATION_LOG_FILE
        )
        self.INCIDENTS_LOG_FILE = os.getenv("NSM_INCIDENTS_LOG_FILE", self.INCIDENTS_LOG_FILE)
        self.SOC_AUTOMATION_AUTO_CONTAIN_CRITICAL = self._env_bool(
            os.getenv("NSM_SOC_AUTOMATION_AUTO_CONTAIN_CRITICAL"),
            self.SOC_AUTOMATION_AUTO_CONTAIN_CRITICAL,
        )
        self.API_DEFAULT_ROLE = os.getenv("NSM_API_DEFAULT_ROLE", self.API_DEFAULT_ROLE).strip().lower()
        trusted_sources = os.getenv("NSM_PORT_SCAN_TRUSTED_SOURCES", "")
        if trusted_sources.strip():
            self.PORT_SCAN_TRUSTED_SOURCES = {
                ip.strip() for ip in trusted_sources.split(",") if ip.strip()
            }

    @staticmethod
    def _load_dotenv(env_file: str | None) -> None:
        """Load simple KEY=VALUE lines into the process environment."""
        if not env_file:
            return
        path = Path(env_file)
        if not path.exists():
            return
        try:
            with open(path, encoding="utf-8") as fh:
                for raw in fh:
                    line = raw.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, value = line.split("=", 1)
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")
                    if key and key not in os.environ:
                        os.environ[key] = value
        except OSError:
            return

    def apply_profile(self, profile_name: str, profile_file: str | None = None) -> bool:
        """Apply threshold overrides from a named profile file.

        Returns ``True`` when the profile exists and is applied.
        """
        profile_path = Path(profile_file or self.PROFILE_FILE)
        if not profile_path.exists():
            return False

        try:
            with open(profile_path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return False

        profiles = data.get("profiles", data)
        values = profiles.get(profile_name)
        if not isinstance(values, dict):
            return False

        for key, value in values.items():
            if not hasattr(self, key):
                continue
            setattr(self, key, self._coerce_value(getattr(self, key), value))

        self.PROFILE_NAME = profile_name
        self.PROFILE_FILE = str(profile_path)
        return True

    @staticmethod
    def _coerce_value(current, value):
        if isinstance(current, set):
            return set(value) if isinstance(value, (list, set, tuple)) else current
        if isinstance(current, bool):
            return bool(value)
        if isinstance(current, int) and not isinstance(current, bool):
            return int(value)
        if isinstance(current, float):
            return float(value)
        if isinstance(current, str):
            return str(value)
        return value

    @staticmethod
    def _env_bool(raw: str | None, default: bool) -> bool:
        if raw is None:
            return default
        value = raw.strip().lower()
        if value in {"1", "true", "yes", "on"}:
            return True
        if value in {"0", "false", "no", "off"}:
            return False
        return default
