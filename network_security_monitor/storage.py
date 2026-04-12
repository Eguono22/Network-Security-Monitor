"""Shared JSONL-backed persistence helpers."""

from __future__ import annotations

import json
import os
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
