"""Shared persistence helpers for alerts, incidents, and SOC artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone
from typing import Any

from .models import Alert


class JsonlStore:
    """Append-only JSONL storage with recent-record reads."""

    def __init__(self, path: str):
        self.path = path

    def append(self, payload: dict[str, Any]) -> None:
        if not self.path:
            return
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload))
            fh.write("\n")

    def read_recent(self, limit: int = 200) -> list[dict[str, Any]]:
        if not self.path or not os.path.exists(self.path):
            return []
        try:
            with open(self.path, encoding="utf-8") as fh:
                lines = fh.readlines()
        except OSError:
            return []

        records = []
        for raw in reversed(lines):
            try:
                records.append(json.loads(raw))
            except json.JSONDecodeError:
                continue
            if len(records) >= limit:
                break
        return list(reversed(records))

    def read_all(self) -> list[dict[str, Any]]:
        if not self.path or not os.path.exists(self.path):
            return []
        try:
            with open(self.path, encoding="utf-8") as fh:
                lines = fh.readlines()
        except OSError:
            return []

        records = []
        for raw in lines:
            try:
                records.append(json.loads(raw))
            except json.JSONDecodeError:
                continue
        return records


class AlertLogStore:
    """Parses recent alert records from the rotating text log."""

    _line_re = re.compile(
        r"\[(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s+"
        r"\[(?P<severity>[A-Z]+)\]\s+"
        r"\[(?P<threat>[A-Z_]+)\]\s+"
        r"src=(?P<src>\S+)"
    )

    def __init__(self, path: str):
        self.path = path

    def read_recent(self, limit: int = 200, *, max_lines: int = 400) -> list[dict[str, Any]]:
        if not self.path or not os.path.exists(self.path):
            return []
        try:
            with open(self.path, encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
        except OSError:
            return []

        records = []
        for raw in reversed(lines[-max_lines:]):
            match = self._line_re.search(raw)
            if not match:
                continue
            records.append(
                {
                    "timestamp": match.group("ts"),
                    "severity": match.group("severity"),
                    "threat_type": match.group("threat"),
                    "src_ip": match.group("src"),
                    "raw": raw.rstrip("\n"),
                }
            )
            if len(records) >= limit:
                break
        return list(reversed(records))


class AlertStore(JsonlStore):
    """Structured JSONL persistence for alert records."""

    def append_alert(self, alert: Alert) -> None:
        self.append(self.serialize_alert(alert))

    @staticmethod
    def serialize_alert(alert: Alert) -> dict[str, Any]:
        return {
            "timestamp": alert.timestamp,
            "iso_time": datetime.fromtimestamp(alert.timestamp, tz=timezone.utc).isoformat(),
            "threat_type": alert.threat_type.value,
            "severity": alert.severity.value,
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
            "dst_port": alert.dst_port,
            "description": alert.description,
            "metadata": alert.metadata,
            "raw": str(alert),
        }


class AlertRepository:
    """Loads recent alerts from structured JSONL storage with log fallback."""

    def __init__(self, structured_path: str = "", log_path: str = "alerts.log"):
        self._structured_store = AlertStore(structured_path) if structured_path else None
        self._log_store = AlertLogStore(log_path)

    def read_recent(self, limit: int = 200) -> list[dict[str, Any]]:
        if self._structured_store is not None:
            alerts = self._structured_store.read_recent(limit)
            if alerts:
                return alerts
        return self._log_store.read_recent(limit)


class IncidentStore(JsonlStore):
    """Structured append-only incident storage with materialized case reads."""

    def create_case(self, alert: Alert, queue: str = "soc-triage") -> dict[str, Any]:
        now = time.time()
        incident_id = self._build_id(alert, now)
        case = {
            "incident_id": incident_id,
            "created_at": now,
            "updated_at": now,
            "status": "open",
            "queue": queue,
            "severity": alert.severity.value,
            "threat_type": alert.threat_type.value,
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
            "dst_port": alert.dst_port,
            "description": alert.description,
            "metadata": alert.metadata,
        }
        self.append(case)
        return case

    def get_case(self, incident_id: str) -> dict[str, Any] | None:
        return self._materialize_cases().get(incident_id)

    def update_case(self, incident_id: str, **changes: Any) -> dict[str, Any] | None:
        current = self.get_case(incident_id)
        if current is None:
            return None

        updated = dict(current)
        if "metadata" in changes and isinstance(changes["metadata"], dict):
            merged_metadata = dict(updated.get("metadata") or {})
            merged_metadata.update(changes["metadata"])
            changes["metadata"] = merged_metadata
        updated.update({key: value for key, value in changes.items() if value is not None})
        updated["incident_id"] = incident_id
        updated["updated_at"] = time.time()
        self.append(updated)
        return updated

    def list_cases(
        self,
        limit: int = 200,
        *,
        status: str = "",
        severity: str = "",
        queue: str = "",
        threat_type: str = "",
        src_ip: str = "",
    ) -> list[dict[str, Any]]:
        cases = list(self._materialize_cases().values())
        if status:
            cases = [c for c in cases if str(c.get("status", "")).lower() == status.lower()]
        if severity:
            cases = [c for c in cases if str(c.get("severity", "")).upper() == severity.upper()]
        if queue:
            cases = [c for c in cases if str(c.get("queue", "")).lower() == queue.lower()]
        if threat_type:
            cases = [c for c in cases if str(c.get("threat_type", "")).upper() == threat_type.upper()]
        if src_ip:
            cases = [c for c in cases if str(c.get("src_ip", "")) == src_ip]

        cases.sort(key=lambda c: c.get("updated_at", c.get("created_at", 0.0)))
        return cases[-limit:]

    def _materialize_cases(self) -> dict[str, dict[str, Any]]:
        latest: dict[str, dict[str, Any]] = {}
        for record in self.read_all():
            incident_id = record.get("incident_id")
            if not incident_id:
                continue
            merged = dict(latest.get(incident_id, {}))
            merged.update(record)
            latest[incident_id] = merged
        return latest

    @staticmethod
    def _build_id(alert: Alert, now: float) -> str:
        base = f"{alert.threat_type.value}|{alert.src_ip}|{now}"
        digest = hashlib.sha1(base.encode("utf-8")).hexdigest()[:12]
        return f"INC-{digest.upper()}"
