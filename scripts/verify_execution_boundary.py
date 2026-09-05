#!/usr/bin/env python3
"""Mechanical execution-boundary verifier for C-1/C-2 hardening.

Scans every module under ``vulnclaw/`` for process-spawn call sites and
checks each against a reviewed allowlist. Any *new* spawn site must be
added to the allowlist together with an owner and a purpose statement —
the script exits 1 otherwise, so review of new execution paths cannot be
skipped silently.

This is an architectural regression alarm, not a sandbox: it documents and
freezes the current attack surface. The model-reachable sites listed here
(shell_command / python_execute / PHP diff probe / generated-PoC verifier)
are the exact paths the ExecutionGate must cover.

Usage:
    python scripts/verify_execution_boundary.py            # scan vulnclaw/
    python scripts/verify_execution_boundary.py --json     # machine output
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCAN_ROOT = REPO_ROOT / "vulnclaw"

# Callables that create (or can create) an OS process.
_SPAWN_CALLS = {
    # subprocess module
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",
    # os family
    "os.system",
    "os.popen",
    "os.exec",
    "os.execv",
    "os.execve",
    "os.execvp",
    "os.execvpe",
    "os.execl",
    "os.execle",
    "os.execlp",
    "os.execlpe",
    "os.spawnl",
    "os.spawnle",
    "os.spawnlp",
    "os.spawnlpe",
    "os.spawnv",
    "os.spawnve",
    "os.spawnvp",
    "os.spawnvpe",
    "os.posix_spawn",
    "os.posix_spawnp",
    # asyncio / multiprocessing / pty
    "asyncio.create_subprocess_exec",
    "asyncio.create_subprocess_shell",
    "multiprocessing.Process",
    "pty.spawn",
    "pty.fork",
}

# Reviewed baseline, keyed by exact ``file:line:call`` so adding another spawn
# to an already-reviewed file still fails CI and requires an owner decision.
# "model-reachable" sites are exactly those the ExecutionGate must gate;
# "operator control plane" sites run fixed commands chosen by the local
# operator (doctor probes, TUI launcher).
ALLOWED_SPAWN_SITES: dict[str, str] = {
    "vulnclaw/agent/builtin_tools.py:437:subprocess.Popen": (
        "shared gated process runner for shell/python/PHP execution"
    ),
    "vulnclaw/agent/builtin_tools.py:622:subprocess.run": (
        "fixed Windows taskkill fallback for the gated process runner"
    ),
    "vulnclaw/agent/builtin_tools.py:1618:subprocess.run": (
        "fixed Windows nmap path lookup"
    ),
    "vulnclaw/agent/builtin_tools.py:1697:subprocess.run": (
        "structured argv nmap execution constrained by the nmap tool schema"
    ),
    "vulnclaw/agent/builtin_tools.py:1705:subprocess.run": (
        "structured argv non-privileged nmap retry"
    ),
    "vulnclaw/report/verifier.py:487:subprocess.run": (
        "generated-PoC verification after synchronous ExecutionGate approval"
    ),
    "vulnclaw/cli/tui.py:499:subprocess.call": (
        "operator control plane: native TUI binary launcher"
    ),
    "vulnclaw/cli/tui.py:1734:subprocess.run": (
        "operator control plane: fixed version diagnostic"
    ),
    "vulnclaw/cli/main.py:2581:subprocess.run": (
        "operator control plane: fixed Node.js version diagnostic"
    ),
    # First-run setup wizard (merged from dev): operator-driven fixed argv
    # probes/installers; never model-reachable.
    "vulnclaw/cli/wizard.py:100:os.system": (
        "operator control plane: Windows terminal clear (cls)"
    ),
    "vulnclaw/cli/wizard.py:102:os.system": (
        "operator control plane: POSIX terminal clear (clear)"
    ),
    "vulnclaw/cli/wizard.py:300:subprocess.run": (
        "fixed java -version probe during wizard Java detection"
    ),
    "vulnclaw/cli/wizard.py:360:subprocess.run": (
        "fixed winget install of Temurin JDK 17 package on user confirm"
    ),
    "vulnclaw/cli/wizard.py:877:subprocess.run": (
        "git clone of the constant PortSwigger mcp-server repo"
    ),
    "vulnclaw/cli/wizard.py:912:subprocess.run": (
        "gradlew embedProxyJar in the cloned constant repo (Windows shell)"
    ),
    "vulnclaw/cli/wizard.py:922:subprocess.run": (
        "gradlew embedProxyJar in the cloned constant repo (POSIX argv)"
    ),
    "vulnclaw/cli/wizard.py:1085:subprocess.Popen": (
        "launch local Chrome with fixed argv for remote debugging"
    ),
    "vulnclaw/cli/wizard.py:1104:subprocess.Popen": (
        "macOS open-URL launcher with fixed argv"
    ),
    "vulnclaw/cli/wizard.py:1106:subprocess.Popen": (
        "Linux xdg-open URL launcher with fixed argv"
    ),
    "vulnclaw/cli/wizard.py:1116:subprocess.Popen": (
        "macOS open-path launcher with fixed argv"
    ),
    "vulnclaw/cli/wizard.py:1118:subprocess.Popen": (
        "Linux xdg-open path launcher with fixed argv"
    ),
    "vulnclaw/agent/network_scan.py:452:subprocess.run": (
        "fixed local wireless-interface diagnostic"
    ),
    "vulnclaw/agent/network_scan.py:493:subprocess.run": (
        "fixed local IPv4-interface diagnostic"
    ),
}


@dataclass(frozen=True)
class SpawnSite:
    file: str
    line: int
    call: str

    def key(self) -> str:
        return f"{self.file}:{self.line}:{self.call}"

    def as_dict(self) -> dict[str, object]:
        return {"file": self.file, "line": self.line, "call": self.call}


def _dotted_name(node: ast.AST) -> str | None:
    """Return 'a.b.c' for a pure attribute/name chain, else None."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _call_target(call: ast.Call) -> str | None:
    name = _dotted_name(call.func)
    if name is None:
        return None
    if name in _SPAWN_CALLS:
        return name
    # subprocess.getoutput("cmd") style is covered above; os.spawn* variants
    # with suffixes we did not enumerate still end in "spawn" via os.
    if name.startswith(("os.exec", "os.spawn")):
        return name
    return None


def scan_file(path: Path) -> list[SpawnSite]:
    # utf-8-sig accepts the BOM present in a few legacy modules. Real parse or
    # decode errors must fail CI rather than silently hiding every spawn in the
    # affected file.
    tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
    rel = path.relative_to(REPO_ROOT).as_posix()
    sites: list[SpawnSite] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            target = _call_target(node)
            if target is not None:
                sites.append(SpawnSite(file=rel, line=node.lineno, call=target))
    return sites


def scan_tree() -> list[SpawnSite]:
    all_sites: list[SpawnSite] = []
    for path in sorted(SCAN_ROOT.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        all_sites.extend(scan_file(path))
    return all_sites


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit JSON report")
    args = parser.parse_args()

    sites = scan_tree()
    violations = [s for s in sites if s.key() not in ALLOWED_SPAWN_SITES]

    if args.json:
        print(
            json.dumps(
                {
                    "ok": not violations,
                    "reviewed_sites": [
                        {**s.as_dict(), "purpose": ALLOWED_SPAWN_SITES[s.key()]}
                        for s in sites
                        if s.key() in ALLOWED_SPAWN_SITES
                    ],
                    "violations": [s.as_dict() for s in violations],
                    "allowlist": ALLOWED_SPAWN_SITES,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0 if not violations else 1

    if violations:
        print("execution-boundary check FAILED — unreviewed spawn sites:\n")
        for v in violations:
            print(f"  {v.file}:{v.line}  {v.call}()")
        print(
            "\nEvery new process-spawn call site must be reviewed and added to\n"
            "ALLOWED_SPAWN_SITES in scripts/verify_execution_boundary.py with an\n"
            "owner/purpose note before it can merge.\n"
        )
        return 1

    print(
        f"execution-boundary OK — {len(sites)} spawn site(s), "
        f"all inside the reviewed allowlist."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
