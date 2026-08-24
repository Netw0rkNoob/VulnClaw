"""L3 hardening: sanitized child env, hardened shell argv, tree kill."""

from __future__ import annotations

import os
import sys
import time

import pytest

from vulnclaw.agent.builtin_tools import (
    _kill_process_tree,
    _shell_argv,
    _spawn_captured,
    sanitized_exec_env,
)

posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX process groups")


class TestSanitizedExecEnv:
    def test_blocks_interpreter_hijack_vars(self, monkeypatch):
        monkeypatch.setenv("BASH_ENV", "/tmp/evil")
        monkeypatch.setenv("PYTHONPATH", "/tmp/evil")
        monkeypatch.setenv("NODE_OPTIONS", "--require evil.js")
        monkeypatch.setenv("GIT_ASKPASS", "/tmp/steal")
        monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/agent")
        env = sanitized_exec_env()
        for key in ("BASH_ENV", "PYTHONPATH", "NODE_OPTIONS", "GIT_ASKPASS", "SSH_AUTH_SOCK"):
            assert key not in env

    def test_blocks_loader_injection_prefixes(self, monkeypatch):
        monkeypatch.setenv("LD_PRELOAD", "/tmp/evil.so")
        monkeypatch.setenv("DYLD_INSERT_LIBRARIES", "/tmp/evil.dylib")
        monkeypatch.setenv("DYLD_LIBRARY_PATH", "/tmp")
        env = sanitized_exec_env()
        assert not any(k.startswith("DYLD_") for k in env)
        assert "LD_PRELOAD" not in env

    def test_case_insensitive_on_all_platforms(self):
        base = {"bash_env": "/evil", "Path": "/usr/bin", "ld_preload": "x"}
        env = sanitized_exec_env(base)
        assert "bash_env" not in env and "BASH_ENV" not in env
        assert "ld_preload" not in env
        assert env["Path"] == "/usr/bin"

    def test_keeps_benign_vars_and_pythonioencoding(self, monkeypatch):
        monkeypatch.setenv("HOME", "/home/u")
        monkeypatch.setenv("TERM", "xterm")
        env = sanitized_exec_env()
        assert env["HOME"] == "/home/u"
        assert env["PYTHONIOENCODING"] == "utf-8"

    def test_explicit_base_overrides_environ(self, monkeypatch):
        monkeypatch.setenv("INJECTED", "from-parent")
        env = sanitized_exec_env({"ONLY": "this"})
        assert env == {"ONLY": "this", "PYTHONIOENCODING": "utf-8"}


class TestShellArgvHardening:
    def test_no_execution_policy_bypass_anywhere(self):
        for shell in ("", "powershell", "pwsh", "cmd"):
            argv = _shell_argv("Write-Output hi", shell) if os.name == "nt" else []
            if not argv:
                continue
            flat = " ".join(argv).lower()
            assert "executionpolicy" not in flat
            assert "bypass" not in flat

    @pytest.mark.skipif(os.name != "nt", reason="Windows argv shapes")
    def test_cmd_uses_system_dir_with_autorun_disabled(self):
        argv = _shell_argv("dir", "cmd")
        exe = argv[0].lower()
        system32 = (os.environ.get("SystemRoot") or r"C:\Windows").lower() + r"\system32\cmd.exe"
        assert exe.endswith(system32)
        # /D disables AutoRun registry injection; /S fixes quote handling.
        assert argv[1:4] == ["/D", "/S", "/C"]

    @pytest.mark.skipif(os.name != "nt", reason="Windows argv shapes")
    def test_powershell_hardened_flags(self):
        argv = _shell_argv("Get-Date", "")
        for flag in ("-NoLogo", "-NoProfile", "-NonInteractive", "-Command"):
            assert flag in argv

    @pytest.mark.skipif(os.name == "nt", reason="POSIX shell shape")
    def test_posix_uses_explicit_shell_argv(self):
        argv = _shell_argv("id", "")
        assert argv == ["/bin/sh", "-c", "id"]


@posix_only
class TestTreeKill:
    def test_timeout_kills_whole_tree_quickly(self):
        marker = "vulnclaw-tree-kill-marker"
        # Child forks a grandchild that would outlive a naive single-pid kill.
        script = f'sleep 30 & echo {marker} & wait'
        started = time.monotonic()
        rc, out, err, timed_out = _spawn_captured(
            ["/bin/sh", "-c", script], cwd="/tmp", timeout_s=1.0
        )
        elapsed = time.monotonic() - started
        assert timed_out is True
        assert elapsed < 5, "tree kill must not wait out the full child sleep"

    def test_orphaned_grandchildren_are_gone_after_timeout(self):
        marker = "vc-orphan-check"
        script = f"sleep 41 & echo {marker} & wait"
        _spawn_captured(["/bin/sh", "-c", script], cwd="/tmp", timeout_s=0.8)
        deadline = time.time() + 3
        survivors = -1
        while time.time() < deadline:
            probe = os.popen("pgrep -f '^sleep 41' || true").read().strip()
            survivors = len([ln for ln in probe.splitlines() if ln])
            if survivors == 0:
                break
            time.sleep(0.2)
        assert survivors == 0, "sleep 41 grandchild survived the tree kill"

    def test_normal_exit_still_reports_output(self):
        rc, out, err, timed_out = _spawn_captured(
            [sys.executable, "-c", "print('fine')"], cwd="/tmp", timeout_s=10
        )
        assert (rc, timed_out) in {(0, False), (None, False)} or rc == 0
        assert "fine" in out

    def test_kill_process_tree_is_idempotent_on_exited_proc(self):
        proc = __import__("subprocess").Popen(["/bin/sh", "-c", "exit 0"])
        proc.wait()
        _kill_process_tree(proc)  # must not raise
