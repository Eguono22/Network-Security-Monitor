#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
artifact_dir="$repo_root/.tmp/first-run-demo"

write_cli_shim() {
  local path="$1"
  local python_path="$2"
  local module_name="$3"
  cat >"$path" <<EOF
#!/usr/bin/env bash
"$python_path" -m $module_name "\$@"
EOF
  chmod +x "$path"
}

if [[ -x ".venv/bin/python" ]]; then
  python_bin=".venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  python3 -m venv .venv
  python_bin=".venv/bin/python"
elif command -v python >/dev/null 2>&1; then
  python -m venv .venv
  python_bin=".venv/bin/python"
else
  echo "Python 3 is required to bootstrap this project." >&2
  exit 1
fi

if "$python_bin" -c "import importlib.util, sys; sys.exit(0 if importlib.util.find_spec('setuptools') else 1)"; then
  if ! "$python_bin" -m pip install --no-build-isolation -e .; then
    echo "Editable install unavailable in this environment. Falling back to repo-local execution."
    write_cli_shim "$repo_root/.venv/bin/nsm" "$python_bin" "network_security_monitor"
    write_cli_shim "$repo_root/.venv/bin/nsm-smoke" "$python_bin" "network_security_monitor.smoke_test"
  fi
else
  echo "Setuptools is unavailable in this environment. Falling back to repo-local execution."
  mkdir -p "$repo_root/.venv/bin"
  write_cli_shim "$repo_root/.venv/bin/nsm" "$python_bin" "network_security_monitor"
  write_cli_shim "$repo_root/.venv/bin/nsm-smoke" "$python_bin" "network_security_monitor.smoke_test"
fi
export PYTHONPATH="$repo_root${PYTHONPATH:+:$PYTHONPATH}"
"$python_bin" -m network_security_monitor.smoke_test --artifact-dir "$artifact_dir"
