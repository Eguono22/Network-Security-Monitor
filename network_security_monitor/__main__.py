"""Module entrypoint for ``python -m network_security_monitor``."""

from __future__ import annotations

from .cli import run_cli


if __name__ == "__main__":
    run_cli()
