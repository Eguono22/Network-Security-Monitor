"""
Network Security Monitor (NSM)

A system for continuously monitoring, analyzing, and detecting suspicious activity
across a network. Identifies threats such as port scans, SYN floods, brute-force
attempts, DDoS attacks, DNS tunneling, phishing indicators, data exfiltration,
and unusual traffic spikes.
"""

from .config import Config
from .models import Packet, Alert, AlertSeverity, TrafficStats
from .packet_analyzer import PacketAnalyzer
from .threat_detector import ThreatDetector
from .alert_manager import AlertManager
from .monitor import NetworkMonitor

__all__ = [
    "Config",
    "Packet",
    "Alert",
    "AlertSeverity",
    "TrafficStats",
    "PacketAnalyzer",
    "ThreatDetector",
    "AlertManager",
    "NetworkMonitor",
]
