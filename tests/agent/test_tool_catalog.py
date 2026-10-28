"""Tests for host pentest toolchain discovery (vulnclaw.agent.tool_catalog).

All offline: the flag matrix is driven through monkeypatched env/Kali probes,
the cache tests point ``CACHE_FILE`` at a temp dir, and the auto-trust tests
inject a fake catalog instead of walking a real PATH.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from types import SimpleNamespace

from vulnclaw.agent import exec_gate as exec_gate_module
from vulnclaw.agent import tool_catalog as tc


def _config(enabled: bool) -> SimpleNamespace:
    """Minimal persisted-config stand-in carrying safety.shell_tool_catalog."""
    return SimpleNamespace(safety=SimpleNamespace(shell_tool_catalog=enabled))


def _catalog(names: list[str]) -> dict:
    """Wrap tool names in the cached-catalog schema (one flat category)."""
    return {
        "version": 1,
        "generated_at": time.time(),
        "categories": {
            "misc": [{"name": name, "description": ""} for name in names],
        },
    }


class TestFlagPrecedence:
    """Priority: env var > kali-rolling auto-on > persisted config > off."""

    def test_env_var_beats_kali_and_config(self, monkeypatch):
        monkeypatch.setattr(tc, "is_kali_rolling", lambda: True)
        monkeypatch.setenv("VULNCLAW_SHELL_TOOL_CATALOG", "0")
        assert tc.toolchain_enabled(_config(True)) is False

        monkeypatch.setattr(tc, "is_kali_rolling", lambda: False)
        monkeypatch.setenv("VULNCLAW_SHELL_TOOL_CATALOG", "true")
        assert tc.toolchain_enabled(_config(False)) is True

    def test_env_var_accepts_truthy_spellings_and_rejects_others(self, monkeypatch):
        monkeypatch.setattr(tc, "is_kali_rolling", lambda: False)
        for raw in ("1", "TRUE", " yes ", "on"):
            monkeypatch.setenv("VULNCLAW_SHELL_TOOL_CATALOG", raw)
            assert tc.toolchain_enabled() is True
        for raw in ("0", "false", "off", "", "maybe"):
            monkeypatch.setenv("VULNCLAW_SHELL_TOOL_CATALOG", raw)
            assert tc.toolchain_enabled(_config(True)) is False

    def test_kali_auto_on_beats_persisted_config(self, monkeypatch):
        monkeypatch.delenv("VULNCLAW_SHELL_TOOL_CATALOG", raising=False)
        monkeypatch.setattr(tc, "is_kali_rolling", lambda: True)
        assert tc.toolchain_enabled(_config(False)) is True

    def test_persisted_config_decides_when_env_unset_and_not_kali(self, monkeypatch):
        monkeypatch.delenv("VULNCLAW_SHELL_TOOL_CATALOG", raising=False)
        monkeypatch.setattr(tc, "is_kali_rolling", lambda: False)
        assert tc.toolchain_enabled(_config(True)) is True
        assert tc.toolchain_enabled(_config(False)) is False

    def test_default_is_off(self, monkeypatch):
        monkeypatch.delenv("VULNCLAW_SHELL_TOOL_CATALOG", raising=False)
        monkeypatch.setattr(tc, "is_kali_rolling", lambda: False)
        assert tc.toolchain_enabled() is False
        assert tc.host_toolchain_prompt_block() == ""

    def test_env_override_helper(self, monkeypatch):
        monkeypatch.delenv("VULNCLAW_SHELL_TOOL_CATALOG", raising=False)
        assert tc.env_override() is None
        monkeypatch.setenv("VULNCLAW_SHELL_TOOL_CATALOG", "yes")
        assert tc.env_override() is True
        monkeypatch.setenv("VULNCLAW_SHELL_TOOL_CATALOG", "no")
        assert tc.env_override() is False


class TestCacheLoading:
    """A stale/version-mismatched/garbage cache must never be trusted."""

    def _load(self, monkeypatch, tmp_path, payload: object):
        cache_file = tmp_path / "tool_catalog.json"
        cache_file.write_text(json.dumps(payload), encoding="utf-8")
        monkeypatch.setattr(tc, "CACHE_FILE", cache_file)
        return tc._load_cache()

    def test_stale_ttl_returns_none(self, monkeypatch, tmp_path):
        payload = {
            "version": 1,
            "generated_at": time.time() - tc._CACHE_TTL_SECONDS - 60,
            "categories": {"recon": [{"name": "nmap", "description": ""}]},
        }
        assert self._load(monkeypatch, tmp_path, payload) is None

    def test_wrong_version_returns_none(self, monkeypatch, tmp_path):
        payload = {
            "version": 0,
            "generated_at": time.time(),
            "categories": {"recon": [{"name": "nmap", "description": ""}]},
        }
        assert self._load(monkeypatch, tmp_path, payload) is None

    def test_non_dict_payload_returns_none(self, monkeypatch, tmp_path):
        assert self._load(monkeypatch, tmp_path, ["nmap", "sqlmap"]) is None
        assert self._load(monkeypatch, tmp_path, "nmap") is None

    def test_missing_categories_returns_none(self, monkeypatch, tmp_path):
        payload = {"version": 1, "generated_at": time.time(), "categories": "nmap"}
        assert self._load(monkeypatch, tmp_path, payload) is None

    def test_absent_or_corrupt_file_returns_none(self, monkeypatch, tmp_path):
        monkeypatch.setattr(tc, "CACHE_FILE", tmp_path / "absent.json")
        assert tc._load_cache() is None
        broken = tmp_path / "broken.json"
        broken.write_text("{not json", encoding="utf-8")
        monkeypatch.setattr(tc, "CACHE_FILE", broken)
        assert tc._load_cache() is None

    def test_fresh_valid_cache_is_returned(self, monkeypatch, tmp_path):
        payload = {
            "version": 1,
            "generated_at": time.time(),
            "categories": {"recon": [{"name": "nmap", "description": "scan"}]},
        }
        assert self._load(monkeypatch, tmp_path, payload) == payload


class TestPromptRendering:
    def test_empty_catalog_renders_nothing(self):
        assert tc.format_catalog_for_prompt({}) == ""

    def test_catalog_with_no_tools_renders_nothing(self):
        assert tc.format_catalog_for_prompt({"categories": {"recon": []}}) == ""

    def test_catalog_renders_names_and_descriptions(self):
        catalog = {
            "categories": {
                "recon": [{"name": "nmap", "description": "port scan"}],
                "web": [{"name": "ffuf", "description": ""}],
            }
        }
        block = tc.format_catalog_for_prompt(catalog)
        assert "Host pentest toolchain (2 tools" in block
        assert "nmap — port scan" in block
        assert "ffuf" in block


class TestAutoTrustSurface:
    def test_banned_names_dropped_known_tools_kept(self, monkeypatch):
        names = sorted(tc._NO_AUTO_TRUST) + ["nmap", "sqlmap", "ffuf"]
        monkeypatch.setattr(tc, "build_catalog", lambda *a, **kw: _catalog(names))
        trusted = tc.catalog_auto_trusted_names()
        lowered = {name.lower() for name in trusted}
        for banned in tc._NO_AUTO_TRUST:
            assert banned not in lowered
        assert {"nmap", "sqlmap", "ffuf"} <= lowered
        assert len(trusted) == len(names) - len(tc._NO_AUTO_TRUST)

    def test_exclusion_is_case_insensitive(self, monkeypatch):
        monkeypatch.setattr(
            tc, "build_catalog", lambda *a, **kw: _catalog(["CURL", "Wget", "nmap"])
        )
        assert tc.catalog_auto_trusted_names() == ["nmap"]

    def test_full_registry_equals_registry_minus_banned(self, monkeypatch):
        monkeypatch.setattr(tc, "build_catalog", lambda *a, **kw: _catalog(sorted(tc._TOOLS)))
        expected = {name for name in tc._TOOLS if name.lower() not in tc._NO_AUTO_TRUST}
        assert set(tc.catalog_auto_trusted_names()) == expected
        assert set(tc.catalog_tool_names()) == set(tc._TOOLS)

    def test_empty_catalog_yields_nothing(self, monkeypatch):
        monkeypatch.setattr(tc, "build_catalog", lambda *a, **kw: {})
        assert tc.catalog_auto_trusted_names() == []
        assert tc.catalog_tool_names() == []

    def test_exec_gate_trusts_catalog_names_lowercased(self, monkeypatch):
        monkeypatch.setattr(exec_gate_module, "_default_gate", None)
        monkeypatch.setattr(tc, "toolchain_enabled", lambda *_a, **_kw: True)
        monkeypatch.setattr(
            tc,
            "catalog_auto_trusted_names",
            lambda: ["nmap", "SQLMAP", "CURL"],
        )
        config = SimpleNamespace(
            safety=SimpleNamespace(
                approval_timeout_seconds=30,
                permission_mode="auto_review",
                trusted_commands=[],
            )
        )
        gate = exec_gate_module.get_execution_gate(config)
        prefixes = {entry[0] for entry in gate.trusted_commands}
        assert {"nmap", "sqlmap", "curl"} <= prefixes
        assert all(name == name.lower() for name in prefixes)


class TestDpkgProbe:
    def test_missing_dpkg_returns_empty(self, monkeypatch):
        monkeypatch.setattr(tc.shutil, "which", lambda _name: None)
        assert tc._dpkg_installed_names() == set()

    def test_failing_dpkg_oserror_returns_empty(self, monkeypatch):
        monkeypatch.setattr(tc.shutil, "which", lambda _name: "/usr/bin/dpkg")

        def _boom(*_args, **_kwargs):
            raise OSError("dpkg not runnable")

        monkeypatch.setattr(tc.subprocess, "run", _boom)
        assert tc._dpkg_installed_names() == set()

    def test_subprocess_error_returns_empty(self, monkeypatch):
        monkeypatch.setattr(tc.shutil, "which", lambda _name: "/usr/bin/dpkg")

        def _boom(*_args, **_kwargs):
            raise subprocess.TimeoutExpired(cmd=["dpkg", "-l"], timeout=2)

        monkeypatch.setattr(tc.subprocess, "run", _boom)
        assert tc._dpkg_installed_names() == set()

    def test_installed_names_parsed(self, monkeypatch):
        class _Proc:
            stdout = (
                "Desired=Unknown/Install/Remove/Purge/Hold\n"
                "||/ Name                 Version      Architecture Description\n"
                "+++-==================== ============ ============ ============\n"
                "ii  metasploit-framework 2.0          amd64        framework\n"
                "ii  python3-impacket:amd64 1.0        amd64        impacket\n"
                "rc  removed-pkg          1.0          amd64        leftovers\n"
            )

        monkeypatch.setattr(tc.shutil, "which", lambda _name: "/usr/bin/dpkg")
        monkeypatch.setattr(tc.subprocess, "run", lambda *_a, **_kw: _Proc())
        assert tc._dpkg_installed_names() == {"metasploit-framework", "python3-impacket"}


class TestPathScanDeadline:
    def _make_bin(self, root, folder: str, binary: str):
        directory = root / folder
        directory.mkdir()
        path = directory / binary
        path.write_text("#!/bin/sh\n", encoding="utf-8")
        path.chmod(0o755)
        return directory

    def test_scan_stops_once_deadline_passes(self, monkeypatch, tmp_path):
        first = self._make_bin(tmp_path, "bin1", "alpha")
        second = self._make_bin(tmp_path, "bin2", "beta")
        monkeypatch.setenv("PATH", os.pathsep.join([str(first), str(second)]))
        ticks = iter([0.0, 10.0, 10.0])
        monkeypatch.setattr(tc.time, "monotonic", lambda: next(ticks))
        assert tc._scan_path_executables(deadline=1.0) == {"alpha"}

    def test_scan_walks_all_entries_within_budget(self, monkeypatch, tmp_path):
        first = self._make_bin(tmp_path, "bin1", "alpha")
        second = self._make_bin(tmp_path, "bin2", "beta")
        monkeypatch.setenv("PATH", os.pathsep.join([str(first), str(second)]))
        monkeypatch.setattr(tc.time, "monotonic", lambda: 0.0)
        assert tc._scan_path_executables(deadline=100.0) == {"alpha", "beta"}

    def test_scan_ignores_unreadable_entries(self, monkeypatch, tmp_path):
        good = self._make_bin(tmp_path, "bin1", "alpha")
        monkeypatch.setenv("PATH", os.pathsep.join([str(tmp_path / "nope"), str(good)]))
        monkeypatch.setattr(tc.time, "monotonic", lambda: 0.0)
        assert tc._scan_path_executables(deadline=100.0) == {"alpha"}

    def test_discover_names_keeps_known_tools_only(self, monkeypatch, tmp_path):
        directory = self._make_bin(tmp_path, "bin", "nmap")
        other = self._make_bin(tmp_path, "other", "totally-unknown-tool")
        monkeypatch.setenv("PATH", os.pathsep.join([str(directory), str(other)]))
        monkeypatch.setattr(tc, "_dpkg_installed_names", lambda: set())
        monkeypatch.setattr(tc.time, "monotonic", lambda: 0.0)
        assert tc._discover_names(deadline=100.0) == ["nmap"]

    def test_low_confidence_names_dropped_from_registries(self):
        for name in ("urls", "hs", "httplist_sorter", "exploit", "wsuspie", "dfscache"):
            assert name not in tc._TOOLS
            assert name not in tc._TOOL_DESCRIPTIONS
        assert "responder" in tc._TOOLS
