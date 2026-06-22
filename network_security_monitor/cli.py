"""Console entrypoints for the Network Security Monitor package."""

from __future__ import annotations

from main import main as main_cli

from .smoke_test import main as smoke_test_cli


def run_cli() -> None:
    """Run the main NSM CLI."""
    raise SystemExit(main_cli())


def run_smoke_cli() -> None:
    """Run the first-run smoke test CLI."""
    raise SystemExit(smoke_test_cli())
