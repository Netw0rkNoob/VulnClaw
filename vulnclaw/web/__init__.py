"""Web UI backend package for VulnClaw."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

__all__ = ["__version__"]

try:
    __version__ = version("vulnclaw")
except PackageNotFoundError:
    __version__ = "0.3.0"
