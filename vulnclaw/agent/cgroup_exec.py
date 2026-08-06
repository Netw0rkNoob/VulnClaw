"""Live-system-aware cgroup resource confinement for the direct-host execution path.

Why this exists, and why it's a different mechanism from the POSIX rlimits
already applied via `_resource_limit_preexec_fn` in builtin_tools.py:
RLIMIT_AS/RLIMIT_CPU/RLIMIT_NOFILE bound what a *single process* may claim,
but they are static numbers chosen in advance -- they know nothing about how
much memory/CPU the *host* can actually spare right now. RLIMIT_NPROC turned
out to be worse than static: it's a system-wide-per-UID counter on Linux, not
scoped to the calling process's own subtree (see
builtin_tools._current_uid_task_count's docstring for the concrete failure
this caused -- a hardcoded cap of 16 broke a single benign
`threading.Thread()` on a host already running ~220 processes for one user).

cgroups v2, via a transient `systemd-run --user --scope` unit, fix both
problems at once:
  - MemoryMax/MemorySwapMax/CPUQuota/TasksMax are enforced by the kernel
    against *this one cgroup only*. An OOM kill or CPU throttle here cannot
    cascade into starving unrelated processes on the same host -- unlike a
    raw RLIMIT_NPROC's system-wide accounting, TasksMax counts only tasks
    inside this specific scope, so no "current count + headroom" workaround
    is needed the way it was for the rlimit path.
  - MemoryMax is sized dynamically against /proc/meminfo's MemAvailable at
    call time, so the cap adapts to whatever the host can actually spare
    *right now* instead of a number chosen once, in advance, that might
    exceed currently-free memory on a busy day -- which is exactly what
    would risk tipping the whole system into swapping/thrashing, the
    concrete failure mode this module exists to prevent.
  - CPUWeight is *proportional*, not absolute: under real contention this
    workload automatically yields to other real work via the kernel's own
    fair-share scheduler, instead of us trying to hand-guess "how busy is
    the system right now" and hard-coding a threshold around that guess.

Falls back to leaving argv unchanged if `systemd-run` isn't on PATH, cgroups
v2 isn't mounted, or a live smoke test fails (e.g. no active `systemd --user`
instance for this session) -- the POSIX rlimit preexec_fn in
builtin_tools.py still applies underneath as a portable, if cruder, backstop
on hosts where this path isn't available.
"""

from __future__ import annotations

import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any

_SYSTEMD_RUN_CHECKED = False
_SYSTEMD_RUN_AVAILABLE = False


def systemd_cgroup_available(*, force_recheck: bool = False) -> bool:
    """Cache a real smoke test, not just a binary/path existence check --
    `systemd-run --user --scope` additionally needs a live user systemd
    instance (an active login session with DBus), which a bare `which
    systemd-run` cannot tell us about."""
    global _SYSTEMD_RUN_CHECKED, _SYSTEMD_RUN_AVAILABLE
    if _SYSTEMD_RUN_CHECKED and not force_recheck:
        return _SYSTEMD_RUN_AVAILABLE
    _SYSTEMD_RUN_CHECKED = True

    if shutil.which("systemd-run") is None:
        _SYSTEMD_RUN_AVAILABLE = False
        return False
    if not Path("/sys/fs/cgroup/cgroup.controllers").exists():
        _SYSTEMD_RUN_AVAILABLE = False
        return False

    try:
        probe = subprocess.run(
            ["systemd-run", "--user", "--scope", "--quiet", "--collect", "--", "true"],
            capture_output=True,
            timeout=5,
        )
        _SYSTEMD_RUN_AVAILABLE = probe.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        _SYSTEMD_RUN_AVAILABLE = False
    return _SYSTEMD_RUN_AVAILABLE


def _read_available_memory_mb() -> int | None:
    """Best-effort read of /proc/meminfo's MemAvailable, in MB."""
    try:
        with open("/proc/meminfo", encoding="utf-8") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return int(parts[1]) // 1024
    except (OSError, ValueError):
        pass
    return None


def _dynamic_memory_cap_mb(configured_max_mb: int, safety: Any) -> int:
    """Never let a call claim more than a safe fraction of what's *currently*
    free on the host, even when the configured ceiling is higher -- that
    ceiling is a maximum, not a promise that this much is actually free
    today. Falls back to the static configured value if /proc/meminfo can't
    be read (e.g. non-Linux)."""
    fraction = float(getattr(safety, "resource_limit_dynamic_memory_fraction", 0.5) or 0.5)
    floor_mb = int(getattr(safety, "resource_limit_min_memory_mb", 64) or 64)
    available_mb = _read_available_memory_mb()
    if available_mb is None:
        return configured_max_mb
    dynamic_ceiling = max(floor_mb, int(available_mb * fraction))
    return min(configured_max_mb, dynamic_ceiling)


def wrap_argv_for_cgroup(argv: list[str], *, safety: Any, label: str) -> list[str]:
    """Prefix argv with a transient `systemd-run --user --scope` wrapper
    carrying live-adjusted cgroup limits. Returns argv unchanged if the
    cgroup path isn't usable on this host -- callers keep relying on the
    POSIX rlimit preexec_fn underneath either way, this only adds a
    stronger, host-aware layer on top when it's available."""
    if safety is not None and not getattr(safety, "resource_limits_enabled", True):
        return argv
    if not systemd_cgroup_available():
        return argv

    memory_mb = max(
        1,
        _dynamic_memory_cap_mb(
            int(getattr(safety, "resource_limit_max_memory_mb", 512) or 512), safety
        ),
    )
    max_procs = int(getattr(safety, "resource_limit_max_processes", 32) or 32)
    cpu_quota_pct = int(getattr(safety, "resource_limit_cpu_quota_percent", 100) or 100)
    cpu_weight = int(getattr(safety, "resource_limit_cpu_weight", 50) or 50)
    swap_mb = min(memory_mb, int(getattr(safety, "resource_limit_max_swap_mb", 128) or 128))
    unit_name = f"vulnclaw-{label}-{uuid.uuid4().hex[:8]}"

    return [
        "systemd-run", "--user", "--scope", "--quiet", "--collect",
        f"--unit={unit_name}",
        "-p", "MemoryAccounting=yes",
        "-p", f"MemoryMax={memory_mb}M",
        "-p", f"MemorySwapMax={swap_mb}M",
        "-p", f"CPUQuota={cpu_quota_pct}%",
        "-p", f"CPUWeight={cpu_weight}",
        "-p", f"TasksMax={max_procs}",
        "--",
        *argv,
    ]
