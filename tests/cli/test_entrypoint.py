"""Integration tests for the user-facing CLI module entry point."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from vulnclaw import __version__

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _run_module(*args: str) -> subprocess.CompletedProcess[str]:
    """Invoke the CLI through the same module boundary used by the TUI."""
    env = os.environ.copy()
    env["NO_COLOR"] = "1"
    env["PYTHONUTF8"] = "1"
    env["TERM"] = "dumb"
    return subprocess.run(
        [sys.executable, "-m", "vulnclaw", *args],
        cwd=PROJECT_ROOT,
        env=env,
        capture_output=True,
        encoding="utf-8",
        text=True,
        timeout=30,
        check=False,
    )


def test_module_entrypoint_reports_version():
    result = _run_module("--version")

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == __version__


def test_module_entrypoint_exposes_root_help():
    result = _run_module("--help")

    assert result.returncode == 0, result.stderr
    assert "VulnClaw" in result.stdout
    assert "run" in result.stdout
    assert "doctor" in result.stdout


def test_console_script_targets_cli_app():
    """Guard the wheel's console-script mapping against entry-point drift."""
    import toml

    metadata = toml.load(PROJECT_ROOT / "pyproject.toml")

    assert metadata["project"]["scripts"]["vulnclaw"] == "vulnclaw.cli.main:app"
