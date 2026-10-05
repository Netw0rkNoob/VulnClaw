"""🦞 VulnClaw — AI-powered penetration testing CLI tool."""

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

_FALLBACK_VERSION = "0.4.1"


def _read_pyproject_version() -> str | None:
    """Return the ``[project]`` version from the repo-root pyproject.toml.

    In a source checkout pyproject.toml is the source of truth for the version:
    ``__version__`` must track a freshly bumped value without a reinstall, and
    installed metadata can lag behind (the release/version tests assert
    ``__version__ == pyproject version``). Parsing is dependency-free — no
    ``toml`` import on every package import — but tolerant of quote style and
    surrounding whitespace. Returns ``None`` when pyproject.toml is absent (the
    installed-wheel case) or has no ``version`` key.
    """
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    if not pyproject.is_file():
        return None
    try:
        lines = pyproject.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for raw in lines:
        key, sep, val = raw.partition("=")
        if sep and key.strip() == "version":
            return val.strip().strip("\"'") or None
    return None


def _resolve_version() -> str:
    # Source checkout: pyproject.toml is authoritative.
    from_pyproject = _read_pyproject_version()
    if from_pyproject:
        return from_pyproject
    # Installed distribution (a wheel ships no pyproject.toml): read the version
    # baked into the package metadata, falling back to a pinned default.
    try:
        return version("vulnclaw")
    except PackageNotFoundError:
        return _FALLBACK_VERSION


__version__ = _resolve_version()
__author__ = "VulnClaw Team"
