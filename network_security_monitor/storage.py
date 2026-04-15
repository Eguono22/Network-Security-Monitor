"""Shared persistence helpers for alerts, incidents, and SOC artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
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
        metadata = dict(alert.metadata or {})
        incident_ids = AlertStore._incident_ids_from_metadata(metadata)
        return {
            "timestamp": alert.timestamp,
            "iso_time": datetime.fromtimestamp(alert.timestamp, tz=timezone.utc).isoformat(),
            "threat_type": alert.threat_type.value,
            "severity": alert.severity.value,
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
            "dst_port": alert.dst_port,
            "description": alert.description,
            "metadata": metadata,
            "incident_ids": incident_ids,
            "raw": str(alert),
        }

    @staticmethod
    def _incident_ids_from_metadata(metadata: dict[str, Any]) -> list[str]:
        raw = metadata.get("incident_ids", [])
        if isinstance(raw, str):
            raw = [raw]
        if not isinstance(raw, list):
            return []
        seen: set[str] = set()
        incident_ids: list[str] = []
        for item in raw:
            value = str(item).strip()
            if not value or value in seen:
                continue
            seen.add(value)
            incident_ids.append(value)
        return incident_ids


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
    """SQLite-backed incident storage with legacy JSONL migration."""

    def __init__(self, path: str):
        self.path = path
        self._legacy_path = self._resolve_legacy_path(path)
        self._db_path = self._resolve_db_path(path)
        self._ensure_database()

    def create_case(self, alert: Alert, queue: str = "soc-triage") -> dict[str, Any]:
        now = time.time()
        incident_id = self._build_id(alert, now)
        case = {
            "incident_id": incident_id,
            "created_at": now,
            "updated_at": now,
            "status_changed_at": now,
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
        self._upsert_case(case)
        return case

    def get_case(self, incident_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload_json FROM incidents WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
        if row is None:
            return None
        return json.loads(row["payload_json"])

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
        self._upsert_case(updated)
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
        assignee: str = "",
        owner: str = "",
    ) -> list[dict[str, Any]]:
        clauses = []
        params: list[Any] = []

        if status:
            statuses = [raw.strip().lower() for raw in str(status).split(",") if raw.strip()]
            if statuses:
                placeholders = ", ".join("?" for _ in statuses)
                clauses.append(f"status IN ({placeholders})")
                params.extend(statuses)
        if severity:
            clauses.append("severity = ?")
            params.append(str(severity).upper())
        if queue:
            clauses.append("LOWER(queue) = ?")
            params.append(str(queue).lower())
        if threat_type:
            clauses.append("threat_type = ?")
            params.append(str(threat_type).upper())
        if src_ip:
            clauses.append("src_ip = ?")
            params.append(str(src_ip))
        if assignee:
            clauses.append("LOWER(COALESCE(assignee, '')) = ?")
            params.append(str(assignee).lower())
        if owner:
            clauses.append("LOWER(COALESCE(owner, '')) = ?")
            params.append(str(owner).lower())

        query = "SELECT payload_json FROM incidents"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY updated_at DESC LIMIT ?"
        params.append(max(1, int(limit)))

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [json.loads(row["payload_json"]) for row in reversed(rows)]

    def _connect(self) -> sqlite3.Connection:
        if self._db_path != ":memory:":
            directory = os.path.dirname(self._db_path)
            if directory:
                os.makedirs(directory, exist_ok=True)
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_database(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    status_changed_at REAL,
                    assigned_at REAL,
                    contained_at REAL,
                    resolved_at REAL,
                    status TEXT NOT NULL,
                    queue TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT,
                    dst_port INTEGER,
                    description TEXT NOT NULL,
                    assignee TEXT,
                    owner TEXT,
                    notes TEXT,
                    metadata_json TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_incidents_updated_at ON incidents(updated_at)"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_queue ON incidents(queue)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity)")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_incidents_threat_type ON incidents(threat_type)"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_src_ip ON incidents(src_ip)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_assignee ON incidents(assignee)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_owner ON incidents(owner)")
            row = conn.execute("SELECT COUNT(*) AS count FROM incidents").fetchone()
            if row and int(row["count"]) == 0:
                self._migrate_legacy_jsonl(conn)
            conn.commit()

    def _migrate_legacy_jsonl(self, conn: sqlite3.Connection) -> None:
        if not self._legacy_path or not os.path.exists(self._legacy_path):
            return
        legacy_cases: dict[str, dict[str, Any]] = {}
        for record in JsonlStore(self._legacy_path).read_all():
            incident_id = record.get("incident_id")
            if not incident_id:
                continue
            merged = dict(legacy_cases.get(incident_id, {}))
            merged.update(record)
            legacy_cases[incident_id] = merged
        for case in legacy_cases.values():
            conn.execute(
                """
                INSERT OR REPLACE INTO incidents (
                    incident_id,
                    created_at,
                    updated_at,
                    status_changed_at,
                    assigned_at,
                    contained_at,
                    resolved_at,
                    status,
                    queue,
                    severity,
                    threat_type,
                    src_ip,
                    dst_ip,
                    dst_port,
                    description,
                    assignee,
                    owner,
                    notes,
                    metadata_json,
                    payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                self._record_values(case),
            )

    def _upsert_case(self, case: dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO incidents (
                    incident_id,
                    created_at,
                    updated_at,
                    status_changed_at,
                    assigned_at,
                    contained_at,
                    resolved_at,
                    status,
                    queue,
                    severity,
                    threat_type,
                    src_ip,
                    dst_ip,
                    dst_port,
                    description,
                    assignee,
                    owner,
                    notes,
                    metadata_json,
                    payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                self._record_values(case),
            )
            conn.commit()

    @staticmethod
    def _record_values(case: dict[str, Any]) -> tuple[Any, ...]:
        payload = dict(case)
        payload["metadata"] = dict(payload.get("metadata") or {})
        return (
            payload["incident_id"],
            payload.get("created_at", 0.0),
            payload.get("updated_at", payload.get("created_at", 0.0)),
            payload.get("status_changed_at"),
            payload.get("assigned_at"),
            payload.get("contained_at"),
            payload.get("resolved_at"),
            payload.get("status", "open"),
            payload.get("queue", "soc-triage"),
            payload.get("severity", "UNKNOWN"),
            payload.get("threat_type", "UNKNOWN"),
            payload.get("src_ip", ""),
            payload.get("dst_ip"),
            payload.get("dst_port"),
            payload.get("description", ""),
            payload.get("assignee"),
            payload.get("owner"),
            payload.get("notes"),
            json.dumps(payload.get("metadata") or {}),
            json.dumps(payload),
        )

    @staticmethod
    def _resolve_db_path(path: str) -> str:
        if not path:
            return "incidents.db"
        if path == ":memory:":
            return path
        root, ext = os.path.splitext(path)
        if ext.lower() == ".jsonl":
            return f"{root}.db"
        return path

    @staticmethod
    def _resolve_legacy_path(path: str) -> str:
        if not path or path == ":memory:":
            return ""
        root, ext = os.path.splitext(path)
        if ext.lower() == ".jsonl":
            return path
        candidate = f"{root}.jsonl"
        return candidate if os.path.exists(candidate) else ""

    @staticmethod
    def _build_id(alert: Alert, now: float) -> str:
        base = f"{alert.threat_type.value}|{alert.src_ip}|{now}"
        digest = hashlib.sha1(base.encode("utf-8")).hexdigest()[:12]
        return f"INC-{digest.upper()}"
