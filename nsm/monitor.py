"""NetworkSecurityMonitor — orchestrates packet ingestion, detection, and alerting."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from nsm.alert import Alert, AlertManager
from nsm.detector import (
    BruteForceDetector,
    DDoSDetector,
    DetectionResult,
    LargeTransferDetector,
    PortScanDetector,
    SuspiciousPortDetector,
)
from nsm.packet import Packet


class NetworkSecurityMonitor:
    """High-level monitor that ingests packets, runs detectors, and stores alerts."""

    def __init__(self) -> None:
        self.alert_manager = AlertManager()
        self._packets: List[Packet] = []

        # Default detectors — can be replaced or extended
        self._detectors = [
            PortScanDetector(),
            BruteForceDetector(),
            DDoSDetector(),
            SuspiciousPortDetector(),
            LargeTransferDetector(),
        ]

    # ------------------------------------------------------------------
    # Packet ingestion
    # ------------------------------------------------------------------

    def ingest(self, packets: List[Packet]) -> None:
        """Add *packets* to the internal store and run all detectors."""
        self._packets.extend(packets)
        self._run_detectors(packets)

    def ingest_one(self, packet: Packet) -> None:
        """Convenience method to ingest a single packet."""
        self.ingest([packet])

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    def _run_detectors(self, packets: List[Packet]) -> None:
        """Run every configured detector against *packets* and persist results."""
        for detector in self._detectors:
            for result in detector.analyze(packets):
                if result.detected:
                    self._store_result(result)

    def _store_result(self, result: DetectionResult) -> None:
        alert = Alert(
            alert_type=result.alert_type,
            severity=result.severity,
            source_ip=result.source_ip,
            message=result.message,
            timestamp=datetime.utcnow(),
            details=result.details,
        )
        self.alert_manager.add_alert(alert)

    # ------------------------------------------------------------------
    # Analysis helpers
    # ------------------------------------------------------------------

    def analyze(self, packets: Optional[List[Packet]] = None) -> List[DetectionResult]:
        """Run all detectors against *packets* (or the full stored set) and return raw results."""
        target = packets if packets is not None else self._packets
        results: List[DetectionResult] = []
        for detector in self._detectors:
            results.extend(detector.analyze(target))
        return [r for r in results if r.detected]

    def get_packets(self) -> List[Packet]:
        """Return all ingested packets."""
        return list(self._packets)

    def reset(self) -> None:
        """Clear all stored packets and alerts."""
        self._packets.clear()
        self.alert_manager.clear()
