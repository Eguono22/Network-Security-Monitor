"""Install the reviewed collector through native macOS administrator authorization."""
from pathlib import Path
import argparse
import json
import shlex
import shutil
import subprocess
import tempfile


def stage_bundle(root):
    source = root / ".runtime" / "macos-service"
    if not (source / "collector.json").exists():
        raise ValueError("Prepare the approved collector credentials and service files first")
    bundle = Path(tempfile.mkdtemp(prefix="sentinelnet-install-", dir="/private/tmp" if Path("/private/tmp").exists() else None))
    bundle.chmod(0o700)
    for name in ("runtime", "app"):
        shutil.copytree(root / ".runtime" / "host" / name, bundle / name)
    for name in ("collector.json", "com.sentinelnet.collector.plist"):
        shutil.copy2(source / name, bundle / name)
    lines = []
    for line in (source / "install.sh").read_text().splitlines():
        if line.strip().startswith("STAGE="):
            line = "STAGE=" + shlex.quote(str(bundle))
        if line.strip().startswith("HOST="):
            line = "HOST=" + shlex.quote(str(bundle))
        lines.append(line)
    script = bundle / "install.sh"
    script.write_text("\n".join(lines) + "\n")
    script.chmod(0o700)
    subprocess.run(["/bin/sh", "-n", str(script)], check=True)
    return bundle


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage-only", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    bundle = stage_bundle(root)
    if args.stage_only:
        print("Prepared protected installer bundle:", bundle)
        return
    try:
        command = "/bin/sh " + shlex.quote(str(bundle / "install.sh"))
        result = subprocess.run(["/usr/bin/osascript", "-e", "do shell script " + json.dumps(command) + " with administrator privileges"], capture_output=True, text=True)
        if result.returncode:
            raise SystemExit("macOS collector installation did not complete: " + result.stderr.strip())
        print("Collector service installed. Verify launchd state and fresh capture statistics.")
    finally:
        shutil.rmtree(bundle)


if __name__ == "__main__":
    main()
