"""🦞 VulnClaw — AI-powered penetration testing CLI tool."""

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

try:
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    version_line = next(
        line
        for line in pyproject.read_text(encoding="utf-8").splitlines()
        if line.startswith("version = ")
    )
    __version__ = version_line.split('"')[1]
except Exception:
    try:
        __version__ = version("vulnclaw")
    except PackageNotFoundError:
        __version__ = "0.3.0"

__author__ = "VulnClaw Team"
