"""Offline account provisioning, database migration, and release checks."""
from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import secrets
import sqlite3
from pathlib import Path

from werkzeug.security import generate_password_hash


def create_user(path: Path, username: str, role: str, password: str, *, replace=False):
    if role not in {"viewer", "analyst", "admin"}:
        raise ValueError("Role must be viewer, analyst, or admin")
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}", username):
        raise ValueError("Use 1–128 letters, digits, or _.@- for the username")
    if len(password) < 12:
        raise ValueError("Passwords must contain at least 12 characters")
    users = json.loads(path.read_text()) if path.exists() else {}
    if username in users and not replace:
        raise ValueError("Account exists; use --replace to rotate its password or role")
    users[username] = {"role": role, "password_hash": generate_password_hash(password)}
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as file:
        json.dump(users, file, indent=2)
    os.replace(temporary, path)


def import_data(incidents_path=None, alerts_path=None, reviews_path=None, actions_path=None):
    from .postgres import connect, _json, PostgresEventStore
    from .storage import JsonlStore
    count = 0
    if incidents_path:
        path = Path(incidents_path)
        if not path.exists():
            raise ValueError("Incident import file does not exist")
        if path.suffix == ".jsonl":
            latest = {}
            for record in JsonlStore(str(path)).read_all():
                if record.get("incident_id"):
                    latest[record["incident_id"]] = {**latest.get(record["incident_id"], {}), **record}
            cases = latest.values()
        else:
            with sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True) as conn:
                cases = [json.loads(row[0]) for row in conn.execute("SELECT payload_json FROM incidents")]
        with connect() as conn:
            for case in cases:
                conn.execute("""INSERT INTO incidents VALUES (%s, %s, %s, %s)
                    ON CONFLICT (incident_id) DO NOTHING
                """, (case["incident_id"], case.get("created_at", 0), case.get("updated_at", case.get("created_at", 0)), _json(case)))
                count += 1
    for stream, path in (("alerts", alerts_path), ("soc_actions", actions_path)):
        if path:
            if not Path(path).exists():
                raise ValueError(f"{stream} import file does not exist")
            for record in JsonlStore(path).read_all():
                PostgresEventStore(stream).append(record)
                count += 1
    if reviews_path:
        if not Path(reviews_path).exists():
            raise ValueError("Review import file does not exist")
        latest = {record["ip"]: record for record in JsonlStore(reviews_path).read_all() if record.get("ip")}
        with connect() as conn:
            for ip, payload in latest.items():
                conn.execute("INSERT INTO device_reviews VALUES (%s, %s) ON CONFLICT DO NOTHING", (ip, _json(payload)))
                count += 1
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    user = sub.add_parser("create-user", help="Provision a hashed account file; never prints passwords")
    user.add_argument("username")
    user.add_argument("--role", choices=["viewer", "analyst", "admin"], required=True)
    user.add_argument("--file", type=Path, default=Path(".runtime/users.json"))
    user.add_argument("--replace", action="store_true")
    sub.add_parser("init-db")
    migration = sub.add_parser("import-data", help="Idempotent import; existing database state is preserved")
    for flag in ("incidents", "alerts", "reviews", "actions"):
        migration.add_argument("--" + flag)
    sub.add_parser("release-check")
    args = parser.parse_args()
    from .config import Config
    Config()
    try:
        if args.command == "create-user":
            password = getpass.getpass("Password (minimum 12 characters): ")
            if password != getpass.getpass("Confirm password: "):
                raise ValueError("Passwords did not match")
            create_user(args.file, args.username, args.role, password, replace=args.replace)
            print("Account saved. Store this file securely; it contains password hashes.")
        elif args.command == "init-db":
            from .postgres import initialize_database
            initialize_database()
            print("PostgreSQL schema initialized.")
        elif args.command == "import-data":
            print(f"Processed {import_data(args.incidents, args.alerts, args.reviews, args.actions)} source records.")
        else:
            from .auth import load_users
            from .postgres import connect, postgres_enabled
            if os.getenv("NSM_AUTH_MODE", "password") != "password":
                raise ValueError("Production requires password authentication")
            if len(os.getenv("NSM_SECRET_KEY", "")) < 32:
                raise ValueError("NSM_SECRET_KEY must contain at least 32 characters")
            load_users()
            if not postgres_enabled():
                raise ValueError("Production release requires PostgreSQL storage")
            if os.getenv("NSM_COOKIE_SECURE", "true").lower() == "false":
                raise ValueError("Production sessions require HTTPS cookies")
            with connect() as conn:
                for table in ("incidents", "events", "device_reviews", "auth_attempts", "change_audit"):
                    conn.execute(f"SELECT 1 FROM {table} LIMIT 1")
            print("Release configuration and database checks passed.")
    except Exception as exc:
        # Driver exceptions may contain hostnames, usernames, and connection details.
        if isinstance(exc, ValueError):
            parser.exit(1, str(exc) + "\n")
        parser.exit(1, "Operation failed. Check configuration, connectivity, and the database schema.\n")


if __name__ == "__main__":
    main()
