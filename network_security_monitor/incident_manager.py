"""Incident case management facade."""

from __future__ import annotations

import time
from typing import List

from .models import Alert
from .storage import IncidentStore

VALID_INCIDENT_STATUSES = ("open", "assigned", "contained", "resolved")
ACTIVE_INCIDENT_STATUSES = frozenset({"open", "assigned", "contained"})


class IncidentValidationError(ValueError):
    """Raised when incident workflow input is invalid."""


class IncidentManager:
    """Stores and retrieves incident cases using the configured backing store."""

    def __init__(self, path: str = "incidents.db"):
        self._path = path
        self._store = IncidentStore(path)

    def create_case(self, alert: Alert, queue: str = "soc-triage") -> dict:
        return self._store.create_case(alert, queue=queue)

    def get_case(self, incident_id: str) -> dict | None:
        return self._store.get_case(incident_id)

    def update_case(self, incident_id: str, **changes) -> dict | None:
        current = self.get_case(incident_id)
        if current is None:
            return None

        normalized = self._normalize_changes(current, changes)
        return self._store.update_case(incident_id, **normalized)

    def list_cases(
        self,
        limit: int = 200,
        *,
        status: str = "",
        severity: str = "",
        queue: str = "",
        threat_type: str = "",
        src_ip: str = "",
        assignee: str = "",
        owner: str = "",
    ) -> List[dict]:
        normalized_status = self._normalize_status_filter(status)
        return self._store.list_cases(
            limit=limit,
            status=normalized_status,
            severity=severity,
            queue=queue,
            threat_type=threat_type,
            src_ip=src_ip,
            assignee=assignee.strip(),
            owner=owner.strip(),
        )

    def _normalize_changes(self, current: dict, changes: dict) -> dict:
        normalized = {key: value for key, value in changes.items() if value is not None}
        assignee = self._clean_optional_string(normalized.get("assignee"))
        owner = self._clean_optional_string(normalized.get("owner"))
        raw_status = normalized.get("status")

        if assignee is not None:
            normalized["assignee"] = assignee
        if owner is not None:
            normalized["owner"] = owner

        status = self._normalize_status(raw_status) if raw_status is not None else None
        if status is None and assignee and current.get("status") == "open":
            status = "assigned"
        if status is not None:
            normalized["status"] = status

        previous_status = str(current.get("status", "open")).lower()
        if status is not None and status != previous_status:
            now = time.time()
            normalized["status_changed_at"] = now
            if status == "assigned":
                normalized.setdefault("assigned_at", now)
            elif status == "contained":
                normalized.setdefault("contained_at", now)
            elif status == "resolved":
                normalized.setdefault("resolved_at", now)

        return normalized

    def _normalize_status_filter(self, raw_status: str) -> str:
        value = (raw_status or "").strip().lower()
        if not value:
            return ""
        if value == "active":
            return ",".join(sorted(ACTIVE_INCIDENT_STATUSES))

        statuses = []
        for part in value.split(","):
            statuses.append(self._normalize_status(part))
        return ",".join(statuses)

    @staticmethod
    def _clean_optional_string(value) -> str | None:
        if value is None:
            return None
        if isinstance(value, str):
            return value.strip()
        return str(value)

    @staticmethod
    def _normalize_status(raw_status: str) -> str:
        value = str(raw_status).strip().lower()
        if value not in VALID_INCIDENT_STATUSES:
            allowed = ", ".join(VALID_INCIDENT_STATUSES)
            raise IncidentValidationError(f"status must be one of: {allowed}")
        return value
