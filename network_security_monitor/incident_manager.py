"""Incident case management facade."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import List

from .models import Alert
from .storage import IncidentStore

VALID_INCIDENT_STATUSES = ("open", "assigned", "contained", "resolved")
ACTIVE_INCIDENT_STATUSES = frozenset({"open", "assigned", "contained"})
SLA_TARGET_SECONDS = {
    "assignment": 15 * 60,
    "containment": 60 * 60,
    "resolution": 4 * 60 * 60,
}


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

    def compute_metrics(self, limit: int = 1000, *, now: float | None = None) -> dict:
        incidents = self.list_cases(limit=limit)
        now_ts = time.time() if now is None else float(now)

        durations = {
            "assignment": self._collect_durations(incidents, "assigned_at", now_ts),
            "containment": self._collect_durations(incidents, "contained_at", now_ts),
            "resolution": self._collect_durations(incidents, "resolved_at", now_ts),
        }
        averages = {
            name: (sum(values) / len(values) if values else None)
            for name, values in durations.items()
        }

        created_trend, resolved_trend = self._build_trend(incidents, days=7)
        status_counts: dict[str, int] = {}
        for incident in incidents:
            status = str(incident.get("status", "open")).lower()
            status_counts[status] = status_counts.get(status, 0) + 1

        return {
            "status_counts": status_counts,
            "mttr": {
                "assignment_avg_seconds": averages["assignment"],
                "containment_avg_seconds": averages["containment"],
                "resolution_avg_seconds": averages["resolution"],
            },
            "sla": {
                "targets_seconds": dict(SLA_TARGET_SECONDS),
                "breaches": {
                    name: self._count_breaches(incidents, field, threshold, now_ts)
                    for name, field, threshold in (
                        ("assignment", "assigned_at", SLA_TARGET_SECONDS["assignment"]),
                        ("containment", "contained_at", SLA_TARGET_SECONDS["containment"]),
                        ("resolution", "resolved_at", SLA_TARGET_SECONDS["resolution"]),
                    )
                },
                "evaluated": {
                    name: self._count_evaluated(incidents, field)
                    for name, field in (
                        ("assignment", "assigned_at"),
                        ("containment", "contained_at"),
                        ("resolution", "resolved_at"),
                    )
                },
            },
            "trends": {
                "window_days": 7,
                "created": created_trend,
                "resolved": resolved_trend,
            },
        }

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

    @staticmethod
    def _to_timestamp(value) -> float | None:
        if value in (None, ""):
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def _collect_durations(self, incidents: list[dict], field: str, now_ts: float) -> list[float]:
        durations: list[float] = []
        for incident in incidents:
            created_at = self._to_timestamp(incident.get("created_at"))
            if created_at is None:
                continue
            completed_at = self._to_timestamp(incident.get(field))
            effective_end = completed_at
            if effective_end is None and str(incident.get("status", "open")).lower() in ACTIVE_INCIDENT_STATUSES:
                effective_end = now_ts
            if effective_end is None:
                continue
            durations.append(max(0.0, effective_end - created_at))
        return durations

    def _count_breaches(
        self,
        incidents: list[dict],
        field: str,
        threshold_seconds: int,
        now_ts: float,
    ) -> int:
        breaches = 0
        for duration in self._collect_durations(incidents, field, now_ts):
            if duration > threshold_seconds:
                breaches += 1
        return breaches

    def _count_evaluated(self, incidents: list[dict], field: str) -> int:
        count = 0
        for incident in incidents:
            created_at = self._to_timestamp(incident.get("created_at"))
            if created_at is None:
                continue
            if self._to_timestamp(incident.get(field)) is not None:
                count += 1
            elif str(incident.get("status", "open")).lower() in ACTIVE_INCIDENT_STATUSES:
                count += 1
        return count

    def _build_trend(self, incidents: list[dict], days: int = 7) -> tuple[list[dict], list[dict]]:
        today = datetime.now(timezone.utc).date()
        buckets = [today - timedelta(days=offset) for offset in reversed(range(days))]
        created_counts = {bucket.isoformat(): 0 for bucket in buckets}
        resolved_counts = {bucket.isoformat(): 0 for bucket in buckets}

        for incident in incidents:
            created_at = self._to_timestamp(incident.get("created_at"))
            resolved_at = self._to_timestamp(incident.get("resolved_at"))
            if created_at is not None:
                created_key = datetime.fromtimestamp(created_at, tz=timezone.utc).date().isoformat()
                if created_key in created_counts:
                    created_counts[created_key] += 1
            if resolved_at is not None:
                resolved_key = datetime.fromtimestamp(resolved_at, tz=timezone.utc).date().isoformat()
                if resolved_key in resolved_counts:
                    resolved_counts[resolved_key] += 1

        created = [{"date": key, "count": created_counts[key]} for key in created_counts]
        resolved = [{"date": key, "count": resolved_counts[key]} for key in resolved_counts]
        return created, resolved
