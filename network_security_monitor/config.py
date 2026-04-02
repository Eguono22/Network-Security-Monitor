"""Configuration for the Network Security Monitor."""

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
    # Maximum number of alerts kept in memory before the oldest are discarded.
    MAX_ALERT_HISTORY: int = 10_000
    # Minimum severity level to write to the log file (DEBUG < INFO < WARNING …)
    MIN_LOG_SEVERITY: str = "INFO"

    # ---------------------------------------------------------------------------
    # Dashboard
    # ---------------------------------------------------------------------------
    DASHBOARD_REFRESH_INTERVAL: float = 1.0  # seconds
    DASHBOARD_TOP_TALKERS_COUNT: int = 10
