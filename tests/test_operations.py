"""Operational backups restore into isolation and preserve incident workflows."""
import json
import os
import stat
import uuid
from pathlib import Path

import pytest
from cryptography.fernet import Fernet, InvalidToken
from tests.test_postgres import postgres_runtime, alert  # noqa: F401
from network_security_monitor.operations import backup, restore


def test_encrypted_backup_restore_and_retention(postgres_runtime, tmp_path):
    from network_security_monitor.incident_manager import IncidentManager
    from network_security_monitor.storage import event_store
    from network_security_monitor.postgres import connect
    config = {"schema": "test", "backup_key": str(tmp_path / "key"), "backup_dir": str(tmp_path / "backups"), "retention": 2}
    case = IncidentManager().create_case(alert())
    event_store("", "alerts").append_alert(alert())
    for _ in range(3):
        saved = backup(config)
    archives = list((tmp_path / "backups").glob("*.fernet"))
    assert len(archives) == 2
    assert b"10.0.0.99" not in Path(saved["archive"]).read_bytes()
    assert stat.S_IMODE(Path(saved["archive"]).stat().st_mode) == 0o600
    assert saved["counts"]["incidents"] == 1
    schema = "restore_" + uuid.uuid4().hex
    restored = restore(config, saved["archive"], os.environ["NSM_TEST_DATABASE_URL"], schema)
    assert restored["verified"]
    previous_url = os.environ["NSM_DATABASE_URL"]
    previous_schema = os.environ.get("NSM_DATABASE_SCHEMA")
    os.environ.update(NSM_DATABASE_URL=os.environ["NSM_TEST_DATABASE_URL"], NSM_DATABASE_SCHEMA=schema)
    try:
        manager = IncidentManager()
        assert manager.get_case(case["incident_id"])["src_ip"] == "10.0.0.99"
        manager.update_case(case["incident_id"], status="resolved")
        assert manager.get_case(case["incident_id"])["status"] == "resolved"
        with connect() as conn:
            from psycopg import sql
            conn.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))
    finally:
        os.environ["NSM_DATABASE_URL"] = previous_url
        if previous_schema is None: os.environ.pop("NSM_DATABASE_SCHEMA", None)
        else: os.environ["NSM_DATABASE_SCHEMA"] = previous_schema


def test_restore_rejects_production_and_remote_targets(tmp_path):
    config = {"backup_key": str(tmp_path / "key")}
    with pytest.raises(ValueError, match="Restore schema"):
        restore(config, "missing", "postgresql://localhost/test", "sentinelnet_production")
    with pytest.raises(ValueError, match="localhost"):
        restore(config, "missing", "postgresql://remote.example/test", "restore_test")


def test_tampered_archive_cannot_be_restored(tmp_path):
    key = Fernet.generate_key()
    (tmp_path / "key").write_bytes(key)
    archive = tmp_path / "backup"
    token = Fernet(key).encrypt(b"test")
    archive.write_bytes(token[:-5] + b"other")
    with pytest.raises(InvalidToken):
        restore({"backup_key": str(tmp_path / "key")}, archive, "postgresql://localhost/test", "restore_tamper")


def test_simulated_alerts_carry_verification_context(tmp_path):
    from network_security_monitor.config import Config
    from network_security_monitor.monitor import NetworkMonitor
    from network_security_monitor.models import Packet
    config = Config(env_file=None)
    config.PORT_SCAN_THRESHOLD = 2
    config.ALERT_LOG_FILE = str(tmp_path / "alerts.log")
    config.INCIDENTS_LOG_FILE = str(tmp_path / "incidents.db")
    config.SOC_AUTOMATION_LOG_FILE = str(tmp_path / "soc.jsonl")
    config.ALERTS_DATA_FILE = str(tmp_path / "alerts.jsonl")
    monitor = NetworkMonitor(config, alert_context={"mode": "simulation", "verification_id": "acceptance"})
    import time
    for port in (1, 2, 3):
        monitor.process_packet(Packet(timestamp=time.time(), src_ip="192.0.2.99", dst_ip="192.0.2.1", protocol="TCP", dst_port=port, size=60, flags="SYN"))
    records = [json.loads(line) for line in Path(config.ALERTS_DATA_FILE).read_text().splitlines()]
    assert records[0]["metadata"]["verification_id"] == "acceptance"
    assert records[0]["description"].startswith("[SIMULATION]")


def test_privileged_installer_stages_outside_checkout(tmp_path):
    import shutil
    from deploy.macos.install_collector import stage_bundle
    root = tmp_path / "Documents" / "Project With Spaces"
    service = root / ".runtime" / "macos-service"
    service.mkdir(parents=True)
    host = root / ".runtime" / "host"
    for name in ("runtime", "app"):
        (host / name).mkdir(parents=True)
        (host / name / "marker").write_text("installation payload")
    config = service / "collector.json"
    config.write_text('{"database_url":"private-placeholder"}')
    config.chmod(0o600)
    (service / "com.sentinelnet.collector.plist").write_text("placeholder")
    (service / "install.sh").write_text("#!/bin/sh\nSTAGE='" + str(service) + "'\nHOST='" + str(host) + "'\n")
    bundle = stage_bundle(root)
    try:
        assert root not in bundle.parents
        assert str(root) not in (bundle / "install.sh").read_text()
        assert stat.S_IMODE(bundle.stat().st_mode) == 0o700
        assert stat.S_IMODE((bundle / "collector.json").stat().st_mode) == 0o600
        assert (bundle / "runtime" / "marker").read_text() == "installation payload"
    finally:
        shutil.rmtree(bundle)


def test_collector_install_requires_prepared_credentials(tmp_path):
    from deploy.macos.install_collector import stage_bundle
    with pytest.raises(ValueError, match="approved collector credentials"):
        stage_bundle(tmp_path)
