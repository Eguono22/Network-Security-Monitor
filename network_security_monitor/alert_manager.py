"""Alert management – stores, logs, and exposes security alerts."""

from __future__ import annotations

import logging
import os
from collections import deque
from typing import Callable, Deque, List, Optional

from .config import Config
from .models import Alert, AlertSeverity, ThreatType


# Map our AlertSeverity levels to Python logging levels.
_SEVERITY_TO_LOG_LEVEL = {
    AlertSeverity.LOW: logging.INFO,
    AlertSeverity.MEDIUM: logging.WARNING,
    AlertSeverity.HIGH: logging.ERROR,
    AlertSeverity.CRITICAL: logging.CRITICAL,
}


class AlertManager:
    """Central store and dispatcher for security alerts.

    Responsibilities
    ----------------
    * Persist alerts in a bounded in-memory ring-buffer.
    * Write alerts to a rotating log file (via Python's :mod:`logging`).
    * Invoke registered callback functions so other components (e.g. the
      dashboard or an email notifier) can react in real time.

    Usage::

        manager = AlertManager(config)
        manager.add(alert)
        recent = manager.get_recent(n=100)
    """

    def __init__(self, config: Config | None = None):
        self._cfg = config or Config()
        self._history: Deque[Alert] = deque(maxlen=self._cfg.MAX_ALERT_HISTORY)
        self._callbacks: List[Callable[[Alert], None]] = []
        self._logger = self._build_logger()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add(self, alert: Alert) -> None:
        """Record *alert*, write it to the log file, and notify callbacks."""
        self._history.append(alert)
        level = _SEVERITY_TO_LOG_LEVEL.get(alert.severity, logging.WARNING)
        self._logger.log(level, str(alert))
        for cb in self._callbacks:
            try:
                cb(alert)
            except Exception:
                pass  # Callbacks must not crash the monitor

    def register_callback(self, callback: Callable[[Alert], None]) -> None:
        """Register a function to be called whenever a new alert is added."""
        self._callbacks.append(callback)

    def get_recent(self, n: int = 50) -> List[Alert]:
        """Return the *n* most recent alerts (newest last)."""
        items = list(self._history)
        return items[-n:]

    def get_by_severity(self, severity: AlertSeverity) -> List[Alert]:
        """Return all stored alerts with the given *severity*."""
        return [a for a in self._history if a.severity == severity]

    def get_by_threat_type(self, threat_type: ThreatType) -> List[Alert]:
        """Return all stored alerts of the given *threat_type*."""
        return [a for a in self._history if a.threat_type == threat_type]

    def get_stats(self) -> dict:
        """Return a summary dict of alert counts per severity and threat type."""
        stats: dict = {
            "total": len(self._history),
            "by_severity": {s.value: 0 for s in AlertSeverity},
            "by_threat_type": {t.value: 0 for t in ThreatType},
        }
        for alert in self._history:
            stats["by_severity"][alert.severity.value] += 1
            stats["by_threat_type"][alert.threat_type.value] += 1
        return stats

    def clear(self) -> None:
        """Remove all alerts from the in-memory buffer."""
        self._history.clear()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_logger(self) -> logging.Logger:
        logger = logging.getLogger("nsm.alerts")
        logger.setLevel(logging.DEBUG)

        # Avoid adding duplicate handlers when the class is instantiated more
        # than once (common in unit tests).
        if logger.handlers:
            return logger

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)
        console_handler.setFormatter(
            logging.Formatter("%(levelname)s %(message)s")
        )
        logger.addHandler(console_handler)

        # File handler
        log_path = self._cfg.ALERT_LOG_FILE
        try:
            file_handler = logging.FileHandler(log_path, encoding="utf-8")
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(
                logging.Formatter("%(asctime)s %(levelname)s %(message)s")
            )
            logger.addHandler(file_handler)
        except OSError:
            # If we can't write to the file (e.g. in a read-only environment)
            # we silently fall back to console-only logging.
            pass

        return logger
