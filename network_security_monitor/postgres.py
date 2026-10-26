"""PostgreSQL repositories. Schema is installed explicitly by the release CLI."""
from __future__ import annotations

import hashlib
import json
import os
import time
from contextlib import contextmanager
from urllib.parse import urlsplit, parse_qs

from .storage import AlertStore, IncidentStore, ReadOnlyStoreError


def postgres_enabled() -> bool:
    backend = os.getenv("NSM_STORAGE_BACKEND", "file").lower()
    if backend not in {"file", "postgres"}:
        raise ValueError("NSM_STORAGE_BACKEND must be file or postgres")
    return backend == "postgres"


@contextmanager
def connect():
    import psycopg
    from psycopg.rows import dict_row
    url = os.getenv("NSM_DATABASE_URL") or os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL", "")
    if not url:
        raise ValueError("NSM_DATABASE_URL or a Vercel PostgreSQL connection URL is required")
    parsed = urlsplit(url)
    if parsed.scheme not in {"postgres", "postgresql"}:
        raise ValueError("NSM_DATABASE_URL must be a PostgreSQL URL")
    options = {}
    if parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        mode = parse_qs(parsed.query).get("sslmode", ["require"])[0]
        if mode not in {"require", "verify-ca", "verify-full"}:
            raise ValueError("External PostgreSQL connections require TLS")
        options["sslmode"] = mode
    with psycopg.connect(url, row_factory=dict_row, connect_timeout=10, **options) as conn:
        conn.execute("SET LOCAL statement_timeout = '15s'")
        yield conn


def initialize_database() -> None:
    with connect() as conn:
        # Serialize schema setup across concurrently starting containers.
        conn.execute("SELECT pg_advisory_xact_lock(7263462)")
        conn.execute("""CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY, created_at DOUBLE PRECISION NOT NULL,
            updated_at DOUBLE PRECISION NOT NULL, payload JSONB NOT NULL
        )""")
        conn.execute("CREATE INDEX IF NOT EXISTS incidents_updated ON incidents(updated_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS incidents_status ON incidents ((payload->>'status'))")
        conn.execute("""CREATE TABLE IF NOT EXISTS events (
            id BIGSERIAL PRIMARY KEY, stream TEXT NOT NULL, digest TEXT NOT NULL,
            payload JSONB NOT NULL, UNIQUE(stream, digest)
        )""")
        conn.execute("CREATE INDEX IF NOT EXISTS events_stream ON events(stream, id DESC)")
        conn.execute("""CREATE TABLE IF NOT EXISTS device_reviews (
            ip TEXT PRIMARY KEY, payload JSONB NOT NULL
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS change_audit (
            id BIGSERIAL PRIMARY KEY, recorded_at DOUBLE PRECISION NOT NULL,
            kind TEXT NOT NULL, record_key TEXT NOT NULL, payload JSONB NOT NULL
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS auth_attempts (
            key TEXT PRIMARY KEY, attempts INTEGER NOT NULL, started_at DOUBLE PRECISION NOT NULL
        )""")


def _json(payload):
    from psycopg.types.json import Jsonb
    return Jsonb(payload)


class PostgresIncidentStore(IncidentStore):
    def __init__(self, *, read_only=False):
        self.read_only = read_only
        self.path = "postgres"

    def get_case(self, incident_id):
        with connect() as conn:
            row = conn.execute("SELECT payload FROM incidents WHERE incident_id = %s", (incident_id,)).fetchone()
        return row["payload"] if row else None

    def _upsert_case(self, case):
        if self.read_only:
            raise ReadOnlyStoreError("Incident storage is read-only")
        with connect() as conn:
            conn.execute("""INSERT INTO incidents VALUES (%s, %s, %s, %s)
                ON CONFLICT (incident_id) DO UPDATE SET updated_at=EXCLUDED.updated_at, payload=EXCLUDED.payload
            """, (case["incident_id"], case.get("created_at", 0), case.get("updated_at", case.get("created_at", 0)), _json(case)))

    def update_case(self, incident_id, **changes):
        if self.read_only:
            raise ReadOnlyStoreError("Incident storage is read-only")
        with connect() as conn:
            row = conn.execute("SELECT payload FROM incidents WHERE incident_id=%s FOR UPDATE", (incident_id,)).fetchone()
            if not row:
                return None
            updated = row["payload"]
            if isinstance(changes.get("metadata"), dict):
                changes["metadata"] = {**(updated.get("metadata") or {}), **changes["metadata"]}
            updated.update({key: value for key, value in changes.items() if value is not None})
            updated.update(incident_id=incident_id, updated_at=time.time())
            conn.execute("UPDATE incidents SET updated_at=%s, payload=%s WHERE incident_id=%s", (updated["updated_at"], _json(updated), incident_id))
            conn.execute("INSERT INTO change_audit(recorded_at, kind, record_key, payload) VALUES (%s, 'incident', %s, %s)", (time.time(), incident_id, _json(updated)))
        return updated

    def list_cases(self, limit=200, **filters):
        clauses = []
        params = []
        # Column names are fixed here; all filter values remain parameters.
        for key in ("status", "severity", "queue", "threat_type", "src_ip", "assignee", "owner"):
            value = filters.get(key)
            if not value:
                continue
            if key == "status":
                clauses.append("LOWER(payload->>'status') = ANY(%s)")
                params.append([s.strip().lower() for s in value.split(",")])
            else:
                clauses.append(f"LOWER(payload->>'{key}') = %s")
                params.append(str(value).lower())
        query = "SELECT payload FROM incidents"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY updated_at DESC, incident_id DESC LIMIT %s"
        params.append(max(1, int(limit)))
        with connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [row["payload"] for row in reversed(rows)]


class PostgresEventStore:
    def __init__(self, stream, *, read_only=False):
        if stream not in {"alerts", "soc_actions", "device_reviews"}:
            raise ValueError("Invalid event stream")
        self.stream = stream
        self.read_only = read_only
        self.path = "postgres"

    def append(self, payload):
        if self.read_only:
            raise ReadOnlyStoreError("Event storage is read-only")
        with connect() as conn:
            if self.stream == "device_reviews":
                conn.execute("""INSERT INTO device_reviews VALUES (%s, %s)
                    ON CONFLICT(ip) DO UPDATE SET payload=EXCLUDED.payload
                """, (payload["ip"], _json(payload)))
                conn.execute("INSERT INTO change_audit(recorded_at, kind, record_key, payload) VALUES (%s, 'device_review', %s, %s)", (time.time(), payload["ip"], _json(payload)))
            else:
                digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
                conn.execute("INSERT INTO events(stream, digest, payload) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING", (self.stream, digest, _json(payload)))

    def append_alert(self, alert):
        self.append(AlertStore.serialize_alert(alert))

    def read_recent(self, limit=200):
        if self.stream == "device_reviews":
            return self.read_all()[-max(1, int(limit)):]
        with connect() as conn:
            rows = conn.execute("SELECT payload FROM events WHERE stream=%s ORDER BY id DESC LIMIT %s", (self.stream, max(1, int(limit)))).fetchall()
        return [row["payload"] for row in reversed(rows)]

    def read_all(self):
        with connect() as conn:
            if self.stream == "device_reviews":
                rows = conn.execute("SELECT payload FROM device_reviews ORDER BY ip").fetchall()
            else:
                rows = conn.execute("SELECT payload FROM events WHERE stream=%s ORDER BY id", (self.stream,)).fetchall()
        return [row["payload"] for row in rows]
