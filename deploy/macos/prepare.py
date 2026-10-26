"""Prepare a self-contained Mac collector and reviewable launchd installation files."""
from __future__ import annotations
import argparse
import json
import os
import plistlib
import shlex
import shutil
import sys
import sysconfig
from pathlib import Path


def prepare(root: Path):
    private = root / ".runtime"
    host = private / "host"
    host.mkdir(parents=True, exist_ok=True, mode=0o700)
    runtime = host / "runtime"
    if not runtime.exists():
        shutil.copytree(sys.base_prefix, runtime, ignore=shutil.ignore_patterns("__pycache__", ".DS_Store"))
    source = Path(sysconfig.get_paths()["purelib"])
    site = runtime / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
    site.mkdir(parents=True, exist_ok=True)
    prefixes = ("scapy", "psycopg", "psutil", "colorama", "cryptography", "_cffi_backend", "cffi", "pycparser", "typing_extensions")
    for item in source.iterdir():
        if item.name.startswith(prefixes):
            target = site / item.name
            if item.is_dir(): shutil.copytree(item, target, dirs_exist_ok=True)
            else: shutil.copy2(item, target)
    app = host / "app"
    app.mkdir(exist_ok=True)
    shutil.copytree(root / "network_security_monitor", app / "network_security_monitor", dirs_exist_ok=True, ignore=shutil.ignore_patterns("__pycache__", "web"))
    shutil.copy2(root / "config_profiles.json", app / "config_profiles.json")
    staged = private / "macos-service"
    staged.mkdir(exist_ok=True, mode=0o700)
    collector = None
    if (private / "ops" / "collector.json").exists():
        collector = json.loads((private / "ops" / "collector.json").read_text())
        target = Path("/Library/Application Support/SentinelNet")
        collector.update(profile_file=str(target / "app/config_profiles.json"), alert_log="/Library/Logs/SentinelNet/alerts.log", status_file=str(target / "collector-status.json"))
        staged = private / "macos-service"
        staged.mkdir(exist_ok=True, mode=0o700)
        collector_file = staged / "collector.json"
        collector_file.write_text(json.dumps(collector, indent=2))
        collector_file.chmod(0o600)
        daemon = {
            "Label": "com.sentinelnet.collector",
            "ProgramArguments": [str(target / "runtime/bin/python3.12"), "-Es", "-m", "network_security_monitor.operations", "collector", "--config", str(target / "collector.json")],
            "WorkingDirectory": str(target / "app"), "RunAtLoad": True, "KeepAlive": True,
            "ThrottleInterval": 30, "ProcessType": "Background", "Umask": 63,
            "StandardOutPath": "/Library/Logs/SentinelNet/collector.log",
            "StandardErrorPath": "/Library/Logs/SentinelNet/collector-error.log",
        }
        (staged / "com.sentinelnet.collector.plist").write_bytes(plistlib.dumps(daemon))
        script = f'''#!/bin/sh
    set -eu
    STAGE={shlex.quote(str(staged))}
    HOST={shlex.quote(str(host))}
    DEST='/Library/Application Support/SentinelNet'
    PLIST='/Library/LaunchDaemons/com.sentinelnet.collector.plist'
    [ "$(/usr/bin/id -u)" -eq 0 ] || exit 1
    /bin/mkdir -p "$DEST" /Library/Logs/SentinelNet
    /bin/launchctl bootout system "$PLIST" >/dev/null 2>&1 || true
    /usr/bin/ditto "$HOST/runtime" "$DEST/runtime"
    /usr/bin/ditto "$HOST/app" "$DEST/app"
    /bin/cp "$STAGE/collector.json" "$DEST/collector.json"
    /usr/sbin/chown -R root:wheel "$DEST" /Library/Logs/SentinelNet
    /bin/chmod -R go-w "$DEST"
    /bin/chmod 600 "$DEST/collector.json"
    /bin/cp "$STAGE/com.sentinelnet.collector.plist" "$PLIST"
    /usr/sbin/chown root:wheel "$PLIST"
    /bin/chmod 644 "$PLIST"
    /bin/launchctl bootstrap system "$PLIST"
    /bin/launchctl kickstart system/com.sentinelnet.collector
    '''
        (staged / "install.sh").write_text(script)
        (staged / "install.sh").chmod(0o700)
    userbase = Path.home() / "Library" / "Application Support" / "SentinelNet"
    for kind in ("backup", "uptime"):
        config = userbase / "ops" / ("backup.json" if kind == "backup" else "uptime.json")
        arguments = [str(userbase / "runtime/bin/python3.12"), "-Es", "-m", "network_security_monitor.operations", "backup" if kind == "backup" else "check", "--config", str(config)]
        agent = {"Label": "com.sentinelnet." + kind, "ProgramArguments": arguments, "WorkingDirectory": str(userbase / "app"), "RunAtLoad": True, "Umask": 63, "StandardOutPath": str(userbase / "ops" / (kind + "-job.log")), "StandardErrorPath": str(userbase / "ops" / (kind + "-error.log"))}
        if kind == "backup": agent["StartCalendarInterval"] = {"Hour": 3, "Minute": 15}
        else: agent["StartInterval"] = 300
        (staged / ("com.sentinelnet." + kind + ".plist")).write_bytes(plistlib.dumps(agent))
    return {"host_runtime": str(runtime), "staged_service": str(staged), "interface": collector["interface"] if collector else "pending role configuration"}


if __name__ == "__main__":
    print(json.dumps(prepare(Path(__file__).resolve().parents[2])))
