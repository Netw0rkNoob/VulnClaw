"""Opt-in Docker container execution backend for shell_command/python_execute.

Why this exists: `execute_shell_command`/`execute_python` in builtin_tools.py
run directly on the host by default — the only controls are static source
checks (regex/AST, easily incomplete by construction in a Turing-complete
language) and POSIX rlimits (CPU/memory/nproc/fd caps, which bound resource
*consumption* but do not confine filesystem or network access). Real
filesystem/network/capability confinement requires OS-level isolation, which
on Linux means namespaces + cgroups — i.e. a container. This module is that
backend: off by default (SafetyConfig.container_sandbox_mode == "off"), and
opt-in per the SafetyConfig.container_sandbox_mode toggle in config/schema.py.

Design choices, and why:
- Disposable, `--rm` containers, one per call. No pooling/reuse: a reused
  container is a container that can accumulate state/files across calls from
  a target the model doesn't fully trust yet.
- `--network none` by default (SafetyConfig.container_sandbox_network=True
  opts back into `--network bridge` for tasks that genuinely need to reach
  the target from inside the sandbox, e.g. python_execute doing its own HTTP
  probing). This is the single highest-value containment property for a
  pentest tool: even a fully-compromised or malicious code path inside the
  sandbox cannot exfiltrate data or reach anything on the host network by
  default.
- `--read-only` rootfs + a size-capped tmpfs `/tmp` and a single writable
  bind-mount (`/workspace`, the per-call scratch dir) — code cannot persist
  or tamper with anything outside that one directory.
- `--cap-drop=ALL --security-opt=no-new-privileges --user <uid>:<gid>` — no
  Linux capabilities, no privilege escalation via setuid binaries, and never
  runs as root inside the container even though the image's default user
  might be root.
- Docker's own cgroup-backed `--memory`/`--pids-limit` are used instead of
  (or, harmlessly, in addition to) the POSIX rlimits in builtin_tools.py —
  cgroup memory limits trigger the kernel OOM killer against the whole
  container, which a process cannot catch or work around the way it might
  retry past a plain rlimit.
- If Docker is unavailable when a mode requires it, this raises rather than
  silently falling back to unsandboxed host execution — a silent downgrade
  would defeat the entire point of the user opting into container mode.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class SandboxUnavailableError(RuntimeError):
    """Raised when container_sandbox_mode requires Docker but it isn't usable."""


@dataclass
class SandboxResult:
    ok: bool
    stdout: str
    stderr: str
    exit_code: int | None
    timed_out: bool
    elapsed_ms: int
    detail: str = ""


_DOCKER_CHECKED: bool = False
_DOCKER_AVAILABLE: bool = False


def docker_available(*, force_recheck: bool = False) -> bool:
    """Cache a cheap `docker version` probe; Docker daemon checks are not free."""
    global _DOCKER_CHECKED, _DOCKER_AVAILABLE
    if _DOCKER_CHECKED and not force_recheck:
        return _DOCKER_AVAILABLE
    _DOCKER_CHECKED = True
    if shutil.which("docker") is None:
        _DOCKER_AVAILABLE = False
        return False
    try:
        proc = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        _DOCKER_AVAILABLE = proc.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        _DOCKER_AVAILABLE = False
    return _DOCKER_AVAILABLE


def _docker_base_args(safety: Any, *, memory_mb: int, pids_headroom: int) -> list[str]:
    network_mode = "bridge" if getattr(safety, "container_sandbox_network", False) else "none"
    uid = os.getuid() if hasattr(os, "getuid") else 1000
    gid = os.getgid() if hasattr(os, "getgid") else 1000
    return [
        "docker", "run", "--rm",
        "--network", network_mode,
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--read-only",
        "--tmpfs", "/tmp:rw,size=64m,mode=1777",
        f"--memory={memory_mb}m",
        f"--memory-swap={memory_mb}m",
        f"--pids-limit={pids_headroom}",
        "--user", f"{uid}:{gid}",
    ]


async def run_python_in_container(
    code: str,
    *,
    safety: Any,
    timeout_s: float,
    preamble: str = "",
) -> SandboxResult:
    """Execute `code` inside a disposable, isolated container. Raises
    SandboxUnavailableError if Docker isn't reachable — never silently falls
    back to running unsandboxed on the host."""
    if not docker_available():
        raise SandboxUnavailableError(
            "container_sandbox_mode requires Docker but the `docker` CLI/daemon "
            "is not reachable. Either start Docker, or set "
            "safety.container_sandbox_mode back to 'off' to run on the host "
            "directly (loses the network/filesystem isolation this mode provides)."
        )

    image = getattr(safety, "container_sandbox_image", "python:3.13-slim")
    memory_mb = int(getattr(safety, "container_sandbox_memory_mb", 512) or 512)
    pids_headroom = int(getattr(safety, "resource_limit_max_processes", 32) or 32)

    with tempfile.TemporaryDirectory(prefix="vulnclaw-sandbox-") as scratch:
        script_path = Path(scratch) / "script.py"
        script_path.write_text(preamble + code, encoding="utf-8")
        os.chmod(scratch, 0o777)  # container runs as host uid:gid, needs to read its own mount

        args = _docker_base_args(safety, memory_mb=memory_mb, pids_headroom=pids_headroom)
        args += ["-v", f"{scratch}:/workspace:ro", "-w", "/workspace", image, "python", "/workspace/script.py"]

        started = time.perf_counter()
        try:
            loop = asyncio.get_running_loop()
            proc = await loop.run_in_executor(
                None,
                lambda: subprocess.run(args, capture_output=True, text=True, timeout=timeout_s),
            )
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            return SandboxResult(
                ok=proc.returncode == 0,
                stdout=proc.stdout,
                stderr=proc.stderr,
                exit_code=proc.returncode,
                timed_out=False,
                elapsed_ms=elapsed_ms,
            )
        except subprocess.TimeoutExpired as exc:
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            return SandboxResult(
                ok=False,
                stdout=str(exc.stdout or ""),
                stderr=str(exc.stderr or ""),
                exit_code=None,
                timed_out=True,
                elapsed_ms=elapsed_ms,
                detail=f"container timed out after {timeout_s:.0f}s",
            )


async def run_shell_in_container(
    command: str,
    *,
    safety: Any,
    timeout_s: float,
    workdir: str | None = None,
) -> SandboxResult:
    """Execute a shell command inside a disposable, isolated container."""
    if not docker_available():
        raise SandboxUnavailableError(
            "container_sandbox_mode requires Docker but the `docker` CLI/daemon "
            "is not reachable. Either start Docker, or set "
            "safety.container_sandbox_mode back to 'off' to run on the host "
            "directly (loses the network/filesystem isolation this mode provides)."
        )

    image = getattr(safety, "container_sandbox_image", "python:3.13-slim")
    memory_mb = int(getattr(safety, "container_sandbox_memory_mb", 512) or 512)
    pids_headroom = int(getattr(safety, "resource_limit_max_processes", 32) or 32)

    # A read-only bind mount of the caller's workdir (if any) — the sandboxed
    # command can read files there for context (e.g. inspecting downloaded
    # source) but cannot write back into the host filesystem outside /tmp.
    mount_args: list[str] = []
    effective_workdir = "/workspace"
    if workdir and Path(workdir).is_dir():
        mount_args = ["-v", f"{workdir}:/workspace:ro"]
    else:
        effective_workdir = "/tmp"

    args = _docker_base_args(safety, memory_mb=memory_mb, pids_headroom=pids_headroom)
    args += mount_args + ["-w", effective_workdir, image, "sh", "-c", command]

    started = time.perf_counter()
    try:
        loop = asyncio.get_running_loop()
        proc = await loop.run_in_executor(
            None,
            lambda: subprocess.run(args, capture_output=True, text=True, timeout=timeout_s),
        )
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return SandboxResult(
            ok=proc.returncode == 0,
            stdout=proc.stdout,
            stderr=proc.stderr,
            exit_code=proc.returncode,
            timed_out=False,
            elapsed_ms=elapsed_ms,
        )
    except subprocess.TimeoutExpired as exc:
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return SandboxResult(
            ok=False,
            stdout=str(exc.stdout or ""),
            stderr=str(exc.stderr or ""),
            exit_code=None,
            timed_out=True,
            elapsed_ms=elapsed_ms,
            detail=f"container timed out after {timeout_s:.0f}s",
        )
