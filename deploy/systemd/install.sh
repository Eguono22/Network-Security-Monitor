#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="nsm.service"
SERVICE_SRC="$(cd "$(dirname "$0")" && pwd)/nsm.service"
SERVICE_DST="/etc/systemd/system/${SERVICE_NAME}"

echo "Installing ${SERVICE_NAME} to ${SERVICE_DST}"
sudo cp "${SERVICE_SRC}" "${SERVICE_DST}"
sudo systemctl daemon-reload
sudo systemctl enable --now "${SERVICE_NAME}"
echo "Service installed and started."
