"""Real PostgreSQL round-trips; isolated schema, never shared production tables."""
import json
import os
import uuid
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

import pytest


@pytest.fixture
def postgres_runtime(monkeypatch):
    url = os.getenv("NSM_TEST_DATABASE_URL")
    if not url:
        pytest.skip("Set NSM_TEST_DATABASE_URL to run PostgreSQL integration tests")
    import psycopg
    from psycopg import sql
    schema = "test_" + uuid.uuid4().hex
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query))
    query["options"] = "-csearch_path=" + schema
    isolated = urlunsplit(parts._replace(query=urlencode(query)))
    monkeypatch.setenv("NSM_STORAGE_BACKEND", "postgres")
    monkeypatch.setenv("NSM_DATABASE_URL", isolated)
    from network_security_monitor.postgres import initialize_database
    initialize_database()
    try:
        yield isolated
    finally:
        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


def alert():
    from network_security_monitor.models import Alert, AlertSeverity, ThreatType
    return Alert(threat_type=ThreatType.PORT_SCAN, severity=AlertSeverity.HIGH, src_ip="10.0.0.99", dst_ip="10.1.0.1", description="Integration scan", metadata={"sample": 1})


def test_incidents_persist_filter_and_audit(postgres_runtime):
    from network_security_monitor.incident_manager import IncidentManager
    from network_security_monitor.postgres import connect
    manager = IncidentManager()
    case = manager.create_case(alert())
    manager.update_case(case["incident_id"], assignee="alice", updated_by="operator", metadata={"ticket": "SOC-1"})
    manager = IncidentManager()
    saved = manager.get_case(case["incident_id"])
    assert saved["status"] == "assigned"
    assert saved["metadata"] == {"sample": 1, "ticket": "SOC-1"}
    assert manager.list_cases(assignee="ALICE", status="active")[0]["incident_id"] == case["incident_id"]
    assert manager.list_cases(assignee="' OR true --") == []
    manager.update_case(case["incident_id"], status="contained")
    manager.update_case(case["incident_id"], status="resolved")
    assert manager.get_case(case["incident_id"])["resolved_at"] > 0
    with connect() as conn:
        assert conn.execute("SELECT count(*) AS n FROM change_audit").fetchone()["n"] == 3


def test_events_and_device_review_persist(postgres_runtime):
    from network_security_monitor.storage import event_store, AlertRepository
    from network_security_monitor.unauthorized_devices import UnauthorizedDeviceManager
    from network_security_monitor.device_inventory import DeviceInventoryService
    from network_security_monitor.postgres import connect
    store = event_store("", "alerts")
    store.append_alert(alert())
    assert AlertRepository().read_recent()[0]["src_ip"] == "10.0.0.99"
    observed = AlertRepository().read_recent()
    UnauthorizedDeviceManager().update_finding("10.0.0.99", inventory=DeviceInventoryService(), alerts=observed, owner="alice", status="investigating", reviewed_by="operator")
    finding = UnauthorizedDeviceManager().get_finding("10.0.0.99", inventory=DeviceInventoryService(), alerts=observed)
    assert finding["owner"] == "alice"
    assert finding["reviewed_by"] == "operator"
    with connect() as conn:
        assert conn.execute("SELECT count(*) AS n FROM change_audit").fetchone()["n"] == 1


def test_postgres_serverless_writes_and_read_only_override(postgres_runtime, monkeypatch):
    from api.index import app
    from network_security_monitor.incident_manager import IncidentManager
    case = IncidentManager().create_case(alert())
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.delenv("NSM_SERVERLESS_READ_ONLY", raising=False)
    client = app.test_client()
    assert client.patch(f"/api/incidents/{case['incident_id']}", json={"status": "resolved"}).status_code == 200
    monkeypatch.setenv("NSM_SERVERLESS_READ_ONLY", "true")
    assert client.patch(f"/api/incidents/{case['incident_id']}", json={"status": "open"}).status_code == 503


def test_import_is_idempotent_and_preserves_existing_changes(postgres_runtime, tmp_path):
    from network_security_monitor.admin import import_data
    from network_security_monitor.incident_manager import IncidentManager
    path = tmp_path / "incidents.jsonl"
    path.write_text(json.dumps({"incident_id": "INC-IMPORT", "status": "open", "created_at": 1, "metadata": {}}) + "\n")
    import_data(incidents_path=str(path))
    IncidentManager().update_case("INC-IMPORT", status="resolved")
    import_data(incidents_path=str(path))
    assert IncidentManager().get_case("INC-IMPORT")["status"] == "resolved"


def test_vercel_database_url_is_accepted(postgres_runtime, monkeypatch):
    from network_security_monitor.incident_manager import IncidentManager
    monkeypatch.delenv("NSM_DATABASE_URL")
    monkeypatch.setenv("DATABASE_URL", postgres_runtime)
    case = IncidentManager().create_case(alert())
    assert IncidentManager().get_case(case["incident_id"])["src_ip"] == "10.0.0.99"


def test_database_schema_is_explicit_and_idempotent(postgres_runtime, monkeypatch):
    from network_security_monitor.postgres import connect, initialize_database
    schema = parse_qsl(urlsplit(postgres_runtime).query)[0][1].split("=", 1)[1]
    monkeypatch.setenv("NSM_DATABASE_SCHEMA", schema)
    initialize_database()
    with connect() as conn:
        assert conn.execute("SELECT current_schema() AS name").fetchone()["name"] == schema
    monkeypatch.setenv("NSM_DATABASE_SCHEMA", 'public; DROP TABLE incidents')
    with pytest.raises(ValueError, match="valid lowercase"):
        with connect():
            pass
