"""Alert management – stores, logs, and exposes security alerts."""

from __future__ import annotations

import json
import logging
import os
import smtplib
from collections import deque
from datetime import datetime, timezone
from email.message import EmailMessage
from logging.handlers import RotatingFileHandler
from typing import Callable, Deque, List
from urllib import request

from .config import Config
from .models import Alert, AlertSeverity, ThreatType


# Map our AlertSeverity levels to Python logging levels.
_SEVERITY_TO_LOG_LEVEL = {
    AlertSeverity.LOW: logging.INFO,
    AlertSeverity.MEDIUM: logging.WARNING,
    AlertSeverity.HIGH: logging.ERROR,
    AlertSeverity.CRITICAL: logging.CRITICAL,
}

_SEVERITY_RANK = {
    AlertSeverity.LOW: 0,
    AlertSeverity.MEDIUM: 1,
    AlertSeverity.HIGH: 2,
    AlertSeverity.CRITICAL: 3,
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
        self._register_builtin_integrations()

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
            file_handler = RotatingFileHandler(
                log_path,
                maxBytes=self._cfg.ALERT_LOG_MAX_BYTES,
                backupCount=self._cfg.ALERT_LOG_BACKUP_COUNT,
                encoding="utf-8",
            )
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

    def _register_builtin_integrations(self) -> None:
        if self._cfg.ALERT_WEBHOOK_URL:
            self.register_callback(self._webhook_callback(self._cfg.ALERT_WEBHOOK_URL))
        if self._cfg.SLACK_WEBHOOK_URL:
            self.register_callback(self._slack_callback(self._cfg.SLACK_WEBHOOK_URL))
        if self._cfg.SMTP_HOST and self._cfg.ALERT_EMAIL_TO:
            self.register_callback(self._email_callback())
        if self._cfg.SIEM_OUTPUT_FILE:
            self.register_callback(self._siem_file_callback(self._cfg.SIEM_OUTPUT_FILE))

    def _should_notify(self, alert: Alert) -> bool:
        min_sev = self._cfg.ALERT_NOTIFY_MIN_SEVERITY.upper()
        try:
            threshold = AlertSeverity[min_sev]
        except KeyError:
            threshold = AlertSeverity.HIGH
        return _SEVERITY_RANK[alert.severity] >= _SEVERITY_RANK[threshold]

    def _alert_payload(self, alert: Alert) -> dict:
        return {
            "timestamp": alert.timestamp,
            "threat_type": alert.threat_type.value,
            "severity": alert.severity.value,
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
            "dst_port": alert.dst_port,
            "description": alert.description,
            "metadata": alert.metadata,
        }

    def _webhook_callback(self, url: str) -> Callable[[Alert], None]:
        def _send(alert: Alert) -> None:
            if not self._should_notify(alert):
                return
            payload = json.dumps(self._alert_payload(alert)).encode("utf-8")
            req = request.Request(
                url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            request.urlopen(req, timeout=3).read()

        return _send

    def _slack_callback(self, url: str) -> Callable[[Alert], None]:
        def _send(alert: Alert) -> None:
            if not self._should_notify(alert):
                return
            message = {
                "text": (
                    f"[{alert.severity.value}] {alert.threat_type.value} "
                    f"src={alert.src_ip} {alert.description}"
                )
            }
            payload = json.dumps(message).encode("utf-8")
            req = request.Request(
                url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            request.urlopen(req, timeout=3).read()

        return _send

    def _email_callback(self) -> Callable[[Alert], None]:
        recipients = [r.strip() for r in self._cfg.ALERT_EMAIL_TO.split(",") if r.strip()]

        def _send(alert: Alert) -> None:
            if not recipients or not self._should_notify(alert):
                return
            msg = EmailMessage()
            msg["From"] = self._cfg.ALERT_EMAIL_FROM
            msg["To"] = ", ".join(recipients)
            msg["Subject"] = (
                f"NSM Alert: {alert.severity.value} {alert.threat_type.value} "
                f"from {alert.src_ip}"
            )
            msg.set_content(str(alert))

            with smtplib.SMTP(self._cfg.SMTP_HOST, self._cfg.SMTP_PORT, timeout=5) as smtp:
                smtp.starttls()
                if self._cfg.SMTP_USERNAME:
                    smtp.login(self._cfg.SMTP_USERNAME, self._cfg.SMTP_PASSWORD)
                smtp.send_message(msg)

        return _send

    def _siem_file_callback(self, path: str) -> Callable[[Alert], None]:
        def _send(alert: Alert) -> None:
            if not self._should_notify(alert):
                return
            payload = self._alert_payload(alert)
            payload["iso_time"] = datetime.fromtimestamp(
                alert.timestamp, tz=timezone.utc
            ).isoformat()
            directory = os.path.dirname(path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(payload))
                fh.write("\n")

        return _send
