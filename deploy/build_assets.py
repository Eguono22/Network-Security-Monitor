"""Publish only package-owned UI assets to Vercel's public CDN directory."""
from pathlib import Path
import shutil

root = Path(__file__).resolve().parent.parent
source = root / "network_security_monitor" / "web" / "static"
target = root / "public" / "static"
target.mkdir(parents=True, exist_ok=True)
for asset in source.iterdir():
    if asset.is_file() and asset.suffix in {".css", ".js"}:
        shutil.copyfile(asset, target / asset.name)
print("Prepared SentinelNet browser assets.")
