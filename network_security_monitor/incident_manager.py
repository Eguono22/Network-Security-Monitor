"""Incident case management facade."""

from __future__ import annotations

from typing import List

from .models import Alert
from .storage import IncidentStore


class IncidentManager:
    """Stores and retrieves incident cases using the configured backing store."""

    def __init__(self, path: str = "incidents.jsonl"):
        self._path = path
        self._store = IncidentStore(path)

    def create_case(self, alert: Alert, queue: str = "soc-triage") -> dict:
        return self._store.create_case(alert, queue=queue)

    def get_case(self, incident_id: str) -> dict | None:
        return self._store.get_case(incident_id)

    def update_case(self, incident_id: str, **changes) -> dict | None:
        return self._store.update_case(incident_id, **changes)

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
        return self._store.list_cases(
            limit=limit,
            status=status,
            severity=severity,
            queue=queue,
            threat_type=threat_type,
            src_ip=src_ip,
        )
