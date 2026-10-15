"""VulnClaw basic integration tests: verify imports and version."""

import pytest


def test_import_vulnclaw():
    """Test that the main package can be imported."""
    from pathlib import Path

    import toml

    import vulnclaw

    # Read version from pyproject.toml to avoid hardcoding
    pyproject_path = Path(__file__).resolve().parents[2] / "pyproject.toml"
    pyproject = toml.load(pyproject_path)
    expected_version = pyproject["project"]["version"]

    assert vulnclaw.__version__ == expected_version


def test_no_import_errors():
    """Verify no module raises on import."""
    import importlib

    modules = [
        "vulnclaw",
        "vulnclaw.config.schema",
        "vulnclaw.config.settings",
        "vulnclaw.agent.context",
        "vulnclaw.agent.memory",
        "vulnclaw.agent.prompts",
        "vulnclaw.agent.core",
        "vulnclaw.mcp.registry",
        "vulnclaw.mcp.router",
        "vulnclaw.mcp.lifecycle",
        "vulnclaw.skills.loader",
        "vulnclaw.skills.dispatcher",
        "vulnclaw.kb.store",
        "vulnclaw.kb.retriever",
        "vulnclaw.kb.updater",
        "vulnclaw.report.generator",
        "vulnclaw.findings.intake",
        "vulnclaw.findings.evidence",
        "vulnclaw.findings.poc",
        "vulnclaw.findings.verification",
        "vulnclaw.cli.main",
    ]
    for mod_name in modules:
        try:
            importlib.import_module(mod_name)
        except ImportError as e:
            pytest.fail(f"Failed to import {mod_name}: {e}")
