"""Upload release configuration through stdin without printing secret values."""
from pathlib import Path
import argparse
import os
import secrets
import subprocess
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("environment", choices=["preview", "production"])
args = parser.parse_args()
private = Path(".runtime")
users = private / "users.json"
if not users.exists():
    parser.error("Provision accounts first using network_security_monitor.admin create-user")
key = private / (args.environment + "-session-key.txt")
if not key.exists():
    fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as output:
        output.write(secrets.token_urlsafe(48))
values = {
    "NSM_ENV": "production", "NSM_AUTH_MODE": "password",
    "NSM_COOKIE_SECURE": "true", "NSM_STORAGE_BACKEND": "postgres",
    "NSM_SERVERLESS_READ_ONLY": "false",
    "NSM_DATABASE_SCHEMA": "sentinelnet_" + args.environment,
    "NSM_USERS_JSON": users.read_text(), "NSM_SECRET_KEY": key.read_text(),
}
if os.getenv("NSM_DATABASE_URL"):
    values["NSM_DATABASE_URL"] = os.environ["NSM_DATABASE_URL"]
if args.environment == "production":
    environment = {**os.environ, **values}
    environment.pop("NSM_USERS_FILE", None)
    checked = subprocess.run([sys.executable, "-m", "network_security_monitor.admin", "release-check"], env=environment)
    if checked.returncode:
        parser.exit(1, "Production configuration was not uploaded because release checks failed.\n")
for name, value in values.items():
    command = ["vercel", "env", "add", name, args.environment, "--yes", "--force"]
    command.append("--sensitive" if name in {"NSM_USERS_JSON", "NSM_SECRET_KEY", "NSM_DATABASE_URL"} else "--no-sensitive")
    result = subprocess.run(command, input=value, text=True, capture_output=True)
    if result.returncode:
        parser.exit(1, f"Could not configure {name}. Secret values have been withheld.\n")
    print("Configured", name, "for", args.environment, flush=True)
if "NSM_DATABASE_URL" not in values:
    print("Database variables were not changed. Readiness requires a connected PostgreSQL database.")
