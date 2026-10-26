"""Install the prepared current-user backup/uptime jobs without root privileges."""
from pathlib import Path
import argparse
import json
import os
import shutil
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--jobs", nargs="+", choices=["uptime", "backup"], required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
source = root / ".runtime"
base = Path.home() / "Library" / "Application Support" / "SentinelNet"
for kind in args.jobs:
    if not (source / "ops" / (kind + ".json")).exists():
        parser.error("Private configuration is not ready for " + kind)
base.mkdir(parents=True, exist_ok=True, mode=0o700)
for name in ("runtime", "app"):
    shutil.copytree(source / "host" / name, base / name, dirs_exist_ok=True)
ops = base / "ops"
ops.mkdir(exist_ok=True, mode=0o700)
for kind in args.jobs:
    config = json.loads((source / "ops" / (kind + ".json")).read_text())
    if kind == "backup":
        config.update(backup_dir=str(ops / "backups"), backup_key=str(ops / "backup.key"))
        shutil.copyfile(source / "ops" / "backup.key", ops / "backup.key")
        (ops / "backup.key").chmod(0o600)
        shutil.copytree(source / "ops" / "backups", ops / "backups", dirs_exist_ok=True)
    target = ops / (kind + ".json")
    target.write_text(json.dumps(config, indent=2))
    target.chmod(0o600)
    agents = Path.home() / "Library" / "LaunchAgents"
    agents.mkdir(parents=True, exist_ok=True)
    plist = agents / ("com.sentinelnet." + kind + ".plist")
    shutil.copyfile(source / "macos-service" / plist.name, plist)
    plist.chmod(0o644)
    subprocess.run(["launchctl", "bootout", "gui/" + str(os.getuid()), str(plist)], capture_output=True)
    subprocess.run(["launchctl", "bootstrap", "gui/" + str(os.getuid()), str(plist)], check=True)
    print("Installed current-user job:", kind)
