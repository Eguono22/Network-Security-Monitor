"""Incident case persistence helpers."""

from __future__ import annotations

import hashlib
import time
from typing import List

from .models import Alert
from .storage import JsonlStore


class IncidentManager:
    """Stores and retrieves incident cases using JSONL persistence."""

    def __init__(self, path: str = "incidents.jsonl"):
        self._path = path
        self._store = JsonlStore(path)

    def create_case(self, alert: Alert, queue: str = "soc-triage") -> dict:
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
        self._store.append(case)
        return case

    def get_case(self, incident_id: str) -> dict | None:
        return self._materialize_cases().get(incident_id)

    def update_case(self, incident_id: str, **changes) -> dict | None:
        current = self.get_case(incident_id)
        if current is None:
            return None

        now = time.time()
        updated = dict(current)
        if "metadata" in changes and isinstance(changes["metadata"], dict):
            merged_metadata = dict(updated.get("metadata") or {})
            merged_metadata.update(changes["metadata"])
            changes["metadata"] = merged_metadata
        updated.update({k: v for k, v in changes.items() if v is not None})
        updated["incident_id"] = incident_id
        updated["updated_at"] = now
        self._store.append(updated)
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
    ) -> List[dict]:
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

    def _materialize_cases(self) -> dict[str, dict]:
        latest: dict[str, dict] = {}
        for record in self._store.read_all():
            incident_id = record.get("incident_id")
            if not incident_id:
                continue
            current = latest.get(incident_id, {})
            merged = dict(current)
            merged.update(record)
            latest[incident_id] = merged
        return latest

    @staticmethod
    def _build_id(alert: Alert, now: float) -> str:
        base = f"{alert.threat_type.value}|{alert.src_ip}|{now}"
        digest = hashlib.sha1(base.encode("utf-8")).hexdigest()[:12]
        return f"INC-{digest.upper()}"
