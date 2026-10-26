"""Collector operation, authenticated backups, isolated restore, and uptime checks."""
from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import signal
import time
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import urlopen

from .postgres import connect, initialize_database, _json

TABLES = {
    "incidents": ("incident_id", "created_at", "updated_at", "payload"),
    "events": ("id", "stream", "digest", "payload"),
    "device_reviews": ("ip", "payload"),
    "change_audit": ("id", "recorded_at", "kind", "record_key", "payload"),
}


def load_configuration(path):
    config = json.loads(Path(path).read_text())
    if "database_url" in config:
        os.environ.update(NSM_STORAGE_BACKEND="postgres", NSM_DATABASE_URL=config["database_url"], NSM_DATABASE_SCHEMA=config["schema"])
    return config


def private_write(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(content if isinstance(content, bytes) else content.encode())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)



def backup(config):
    from cryptography.fernet import Fernet
    key = Path(config["backup_key"])
    if not key.exists():
        private_write(key, Fernet.generate_key())
    with connect() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        tables = {table: conn.execute(f"SELECT {', '.join(columns)} FROM {table}").fetchall() for table, columns in TABLES.items()}
    now = datetime.now(timezone.utc)
    document = {"version": 1, "created_at": now.isoformat(), "schema": config["schema"], "tables": tables}
    encrypted = Fernet(key.read_bytes()).encrypt(gzip.compress(json.dumps(document).encode()))
    target = Path(config["backup_dir"]) / ("sentinelnet-" + now.strftime("%Y%m%dT%H%M%S%fZ") + ".fernet")
    private_write(target, encrypted)
    # Remove only this utility's encrypted archives after a successful replacement.
    archives = sorted(target.parent.glob("sentinelnet-*.fernet"), reverse=True)
    for old in archives[max(1, int(config.get("retention", 7))):]:
        old.unlink(missing_ok=True)
    result = {"archive": str(target), "created_at": document["created_at"], "counts": {table: len(rows) for table, rows in tables.items()}}
    private_write(target.parent / "latest.json", json.dumps(result))
    return result


def restore(config, archive, target_url, schema):
    """Restore into a NEW isolated namespace; never overwrite application schemas."""
    from cryptography.fernet import Fernet
    from psycopg import sql
    from urllib.parse import urlsplit
    if not re.fullmatch(r"restore_[a-z0-9_]{1,48}", schema):
        raise ValueError("Restore schema must start with restore_ and identify a new namespace")
    if urlsplit(target_url).hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("Restore drills require an isolated localhost database")
    document = json.loads(gzip.decompress(Fernet(Path(config["backup_key"]).read_bytes()).decrypt(Path(archive).read_bytes())))
    if document.get("version") != 1 or set(document.get("tables", {})) != set(TABLES):
        raise ValueError("Unsupported archive format")
    previous = {key: os.environ.get(key) for key in ("NSM_DATABASE_URL", "NSM_DATABASE_SCHEMA")}
    os.environ.update(NSM_DATABASE_URL=target_url, NSM_DATABASE_SCHEMA=schema)
    try:
        with connect() as conn:
            exists = conn.execute("SELECT 1 FROM pg_namespace WHERE nspname=%s", (schema,)).fetchone()
            if exists:
                raise ValueError("Restore target namespace already exists")
        initialize_database()
        with connect() as conn:
            for table, columns in TABLES.items():
                statement = sql.SQL("INSERT INTO {} ({}) VALUES ({})").format(
                    sql.Identifier(table), sql.SQL(", ").join(map(sql.Identifier, columns)),
                    sql.SQL(", ").join(sql.Placeholder() for _ in columns),
                )
                for row in document["tables"][table]:
                    conn.execute(statement, [_json(row[column]) if column == "payload" else row[column] for column in columns])
            for table in ("events", "change_audit"):
                conn.execute("SELECT setval(pg_get_serial_sequence(%s, 'id'), COALESCE((SELECT MAX(id) FROM " + table + "), 1), EXISTS(SELECT 1 FROM " + table + "))", (table,))
            counts = {table: conn.execute(f"SELECT count(*) AS n FROM {table}").fetchone()["n"] for table in TABLES}
        expected = {table: len(rows) for table, rows in document["tables"].items()}
        if counts != expected:
            raise ValueError("Restored record counts do not match the archive")
        return {"schema": schema, "counts": counts, "verified": True}
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def check_uptime(url):
    if not url.startswith("https://"):
        raise ValueError("Uptime targets must use HTTPS")
    with urlopen(url.rstrip("/") + "/ready", timeout=30) as response:
        ready = response.status == 200 and json.load(response).get("ready") is True
    if not ready:
        raise ValueError("Production readiness check failed")
    return {"ready": True, "checked_at": datetime.now(timezone.utc).isoformat()}


def collector(config, *, duration=0, simulate=False):
    from .config import Config
    from .monitor import NetworkMonitor
    from .models import Packet
    os.umask(0o077)
    cfg = Config(env_file=None)
    cfg.apply_profile(config.get("profile", "office_tuned"), config.get("profile_file", "config_profiles.json"))
    cfg.ALERT_LOG_FILE = config["alert_log"]
    cfg.SOC_AUTOMATION_AUTO_CONTAIN_CRITICAL = False
    # Outbound notifications are configured separately, never inherited from shell state.
    cfg.ALERT_WEBHOOK_URL = cfg.SLACK_WEBHOOK_URL = cfg.SMTP_HOST = ""
    context = {"mode": "simulation" if simulate else "live", "collector_id": config.get("collector_id", "mac-collector")}
    if simulate:
        context["verification_id"] = config.get("verification_id", "operational-verification")
    monitor = NetworkMonitor(cfg, alert_context=context)
    if simulate:
        # An inert replay: no packets are transmitted to any network.
        run = config.get("verification_id", "operational-verification")
        for port in range(1, cfg.PORT_SCAN_THRESHOLD + 3):
            monitor.process_packet(Packet(timestamp=time.time(), src_ip="192.0.2.99", dst_ip="192.0.2.1", protocol="TCP", src_port=55000, dst_port=port, size=60, flags="SYN"))
        return {"mode": "simulation", "verification_id": run, "packets": monitor.get_stats().total_packets, "alerts": monitor.get_alert_manager().get_stats()["total"]}
    # Root startup on this Mac crashed inside the optional native pickle cache.
    # Load static protocol data directly; the collector does not need disk caches.
    import scapy.main
    scapy.main.SCAPY_CACHE_FOLDER = None
    from scapy.all import conf
    socket = conf.L2listen(iface=config["interface"], promisc=False)
    socket.close()  # Fail immediately if the interface or capture privileges are missing.
    stop = False
    def terminate(*_):
        nonlocal stop
        stop = True
    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    monitor.start(interface=config["interface"])
    started = time.monotonic()
    status = {"mode": "live", "interface": config["interface"], "packets": 0, "bytes": 0, "updated_at": time.time()}
    try:
        while not stop and (not duration or time.monotonic() - started < duration):
            if not monitor.is_running:
                raise RuntimeError("Capture stopped unexpectedly")
            stats = monitor.get_stats()
            status = {"mode": "live", "interface": config["interface"], "packets": stats.total_packets, "bytes": stats.total_bytes, "updated_at": time.time()}
            private_write(config["status_file"], json.dumps(status))
            time.sleep(5)
    finally:
        monitor.stop()
    return status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["backup", "restore", "check", "collector"])
    parser.add_argument("--config", required=True)
    parser.add_argument("--archive")
    parser.add_argument("--schema")
    parser.add_argument("--target-url-env", default="NSM_RESTORE_DATABASE_URL")
    parser.add_argument("--duration", type=int, default=0)
    parser.add_argument("--simulate", action="store_true")
    args = parser.parse_args()
    try:
        config = load_configuration(args.config)
        if args.command == "backup":
            result = backup(config)
        elif args.command == "restore":
            result = restore(config, args.archive, os.environ[args.target_url_env], args.schema)
        elif args.command == "check":
            result = check_uptime(config["url"])
        else:
            result = collector(config, duration=args.duration, simulate=args.simulate)
        print(json.dumps(result), flush=True)
    except Exception as error:
        # Do not print database errors, URLs, packet content, or credentials.
        print(json.dumps({"ok": False, "error_type": type(error).__name__}), flush=True)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
