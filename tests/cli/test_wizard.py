"""Tests for the first-run /wizard command and config helpers."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from vulnclaw.cli.wizard import (
    detect_setup_status,
    enable_burp_mcp,
    enable_burp_mcp_stdio,
    enable_chrome_devtools,
    find_burp_jar,
)
from vulnclaw.config.schema import VulnClawConfig


class TestEnableChromeDevtools:
    def test_creates_server_with_browser_url(self):
        cfg = VulnClawConfig()
        cfg.mcp.servers.pop("chrome-devtools", None)
        out = enable_chrome_devtools(cfg, browser_url="http://127.0.0.1:9333")
        srv = out.mcp.servers["chrome-devtools"]
        assert srv.enabled is True
        assert srv.transport.command == "npx"
        assert "--browser-url=http://127.0.0.1:9333" in (srv.transport.args or [])

    def test_updates_existing_server(self):
        cfg = VulnClawConfig()
        out = enable_chrome_devtools(cfg, browser_url="http://127.0.0.1:9222")
        assert out.mcp.servers["chrome-devtools"].enabled is True
        assert out.mcp.servers["chrome-devtools"].transport.args[-1].startswith(
            "--browser-url="
        )


class TestEnableBurp:
    def test_enables_sse(self):
        cfg = VulnClawConfig()
        out = enable_burp_mcp(cfg, sse_url="http://127.0.0.1:9999")
        srv = out.mcp.servers["burp"]
        assert srv.enabled is True
        assert srv.transport.url == "http://127.0.0.1:9999"

    def test_stdio_form_points_at_jar(self, tmp_path: Path):
        jar = tmp_path / "burp-mcp-all.jar"
        jar.write_bytes(b"pk")
        cfg = VulnClawConfig()
        out = enable_burp_mcp_stdio(cfg, jar=jar, sse_url="http://127.0.0.1:9876")
        srv = out.mcp.servers["burp"]
        assert srv.enabled is True
        assert srv.transport.type == "stdio"
        assert srv.transport.command == "java"
        assert str(jar) in (srv.transport.args or [])


class TestDetectSetupStatus:
    def test_marks_llm_ready(self):
        cfg = VulnClawConfig()
        cfg.llm.api_key = "sk-test"
        # Prefer real helper if available
        try:
            from vulnclaw.config.token_provider import has_llm_credentials as real_has

            assert real_has(cfg.llm)
        except Exception:
            pass
        with patch("vulnclaw.cli.wizard.port_open", return_value=False):
            status = detect_setup_status(cfg)
        assert status.llm_ready is True

    def test_marks_devtools_enabled(self):
        cfg = VulnClawConfig()
        enable_chrome_devtools(cfg, browser_url="http://127.0.0.1:9222")
        with patch("vulnclaw.cli.wizard.port_open", return_value=False):
            status = detect_setup_status(cfg)
        assert status.chrome_devtools_enabled is True
        assert "9222" in status.chrome_devtools_url

    def test_find_burp_jar(self, tmp_path: Path, monkeypatch):
        tools = tmp_path / "tools"
        tools.mkdir()
        jar = tools / "burp-mcp-all.jar"
        jar.write_bytes(b"x")
        monkeypatch.setattr("vulnclaw.cli.wizard.TOOLS_DIR", tools)
        monkeypatch.setattr(
            "vulnclaw.cli.wizard.BURP_MCP_DIR", tools / "burp-mcp"
        )
        assert find_burp_jar() == jar


class TestJavaHome:
    def test_java_home_from_binary_windows_style(self, tmp_path: Path):
        from vulnclaw.cli.wizard import java_home_from_binary

        java = tmp_path / "jdk-17" / "bin" / "java.exe"
        java.parent.mkdir(parents=True)
        java.write_bytes(b"")
        assert java_home_from_binary(str(java)) == str(tmp_path / "jdk-17")

    def test_detect_java_from_common_path(self, tmp_path: Path, monkeypatch):
        from vulnclaw.cli import wizard as wiz

        jdk = tmp_path / "Eclipse Adoptium" / "jdk-17.0.0" / "bin" / "java.exe"
        jdk.parent.mkdir(parents=True)
        jdk.write_bytes(b"")
        monkeypatch.setattr(wiz.shutil, "which", lambda _: None)
        monkeypatch.setattr(wiz.os, "environ", {"PROGRAMFILES": str(tmp_path), "PROGRAMFILES(X86)": str(tmp_path), "LOCALAPPDATA": str(tmp_path)})
        monkeypatch.setattr(wiz.platform, "system", lambda: "Windows")
        found = wiz.detect_java_path()
        assert found is not None
        assert found.endswith("java.exe")


class TestPlanFromStatus:
    def test_ready_list(self):
        from vulnclaw.cli.wizard import SetupStatus, plan_from_status

        st = SetupStatus(
            llm_ready=True,
            language="en",
            chrome_debug_live=True,
            chrome_devtools_enabled=True,
            burp_enabled=False,
        )
        plan = plan_from_status(st)
        assert "LLM credentials" in plan["ready"]
        assert "Burp MCP" in plan["todo"]

    def test_repl_slash_routes_to_command(self):
        from vulnclaw.cli.tui import dispatch_repl_slash

        result = dispatch_repl_slash("/wizard")
        assert result.kind == "command"
        assert result.value == "wizard"

    def test_palette_lists_wizard(self):
        from vulnclaw.cli.tui import REPL_COMMANDS, list_repl_palette_entries

        assert "wizard" in REPL_COMMANDS
        entries = list_repl_palette_entries()
        assert any(cmd == "wizard" for cmd, _ in entries)
