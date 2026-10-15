"""Headless / non-interactive scan support.

This module owns the three things a CI operator needs and nothing else:

- **Scan-mode presets** (``quick``/``standard``/``deep``) — named bundles of the
  existing effort knobs (``solve_max_steps``/legacy ``solve_max_directions``/
  legacy ``solve_max_tool_rounds``/``max_rounds``) plus the fan-out cap
  (``solve_max_parallel``). Legacy fields are retained for compatibility and
  mode scaling; the default model-led solve no longer performs direction
  planning. Presets seed from today's ``config.session`` values so a user who
  tuned their config keeps that tuning in ``standard``; ``quick`` and ``deep``
  scale it down/up. Explicit CLI flags override the preset.
- **The exit-code contract** — ``run --non-interactive`` maps the resulting
  finding set onto a distinct exit code so a pipeline can tell a clean scan
  from a broken one from one that confirmed a real vulnerability.
- **Run artifacts** — a machine-readable ``summary.json`` written into the run
  directory so downstream CI steps have structured output to consume.

Deliberately provider/engine-agnostic and free of Typer/Rich imports: the CLI
`run` command drives it today, and keeping it dependency-free keeps it trivially
unit-testable (and reusable if the Web layer ever needs the same contract).
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional

# ── Exit-code contract ──────────────────────────────────────────────
#
#   0  ran clean, nothing confirmed          → CI pass
#   1  error (crash / bad config / missing    → CI fail (breakage)
#      LLM creds / bad target)
#   2  >=1 verified finding                    → CI blocks
#   3  only unverified candidates             → CI warn
#
# A crashed/misconfigured scan exits 1, never 0 — no silent green CI.

EXIT_CLEAN = 0
EXIT_ERROR = 1
EXIT_VERIFIED = 2
EXIT_CANDIDATES = 3

# ── Vocabularies ────────────────────────────────────────────────────

SCAN_MODES: tuple[str, ...] = ("quick", "standard", "deep")
FAIL_ON_MODES: tuple[str, ...] = ("verified", "any", "never")
# ``auto`` diff-scopes to changed code (owned by the Target model); ``full``
# tests the whole surface. This module only validates and records the choice.
SCOPE_MODES: tuple[str, ...] = ("auto", "full")

DEFAULT_SCAN_MODE = "standard"
DEFAULT_FAIL_ON = "verified"
DEFAULT_SCOPE_MODE = "full"


# ── Scan-mode presets ───────────────────────────────────────────────


@dataclass
class ScanProfile:
    """Resolved effort knobs + compatibility caps for a single ``run``.

    ``scan_mode`` seeds every field; explicit CLI flags then override individual
    ones via :func:`resolve_scan_profile`. ``max_directions`` is a legacy field:
    model-led solve accepts it but does not use it for direction planning.
    """

    max_steps: int
    max_directions: int
    max_tool_rounds: int
    max_parallel: int
    max_rounds: int
    scan_mode: str = DEFAULT_SCAN_MODE

    @property
    def max_intents(self) -> int:
        """Backward-compatible alias for older callers."""

        return self.max_directions

    @max_intents.setter
    def max_intents(self, value: int) -> None:
        self.max_directions = int(value)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def scan_mode_profile(config: Any, scan_mode: str = DEFAULT_SCAN_MODE) -> ScanProfile:
    """Return the base :class:`ScanProfile` for a scan-mode preset.

    ``standard`` mirrors today's ``config.session`` values verbatim, so anyone
    who tuned their config keeps that tuning. ``quick`` shrinks effort and turns
    the fan-out off (single agent); ``deep`` deepens effort and opens the
    fan-out cap to its full width (~12 concurrent).
    """
    session = config.session
    steps = int(session.solve_max_steps)
    directions = int(session.solve_max_directions)
    tool_rounds = int(session.solve_max_tool_rounds)
    parallel = int(session.solve_max_parallel)
    rounds = int(session.max_rounds)

    mode = scan_mode if scan_mode in SCAN_MODES else DEFAULT_SCAN_MODE

    if mode == "quick":
        # Shallow, single-agent, fast: fan-out off.
        return ScanProfile(
            max_steps=max(1, steps // 3),
            max_directions=max(1, directions - 1),
            max_tool_rounds=max(1, tool_rounds // 2),
            max_parallel=1,
            max_rounds=max(1, rounds // 2),
            scan_mode=mode,
        )
    if mode == "deep":
        # High rounds/steps, full fan-out (~12 concurrent).
        return ScanProfile(
            max_steps=steps * 2,
            max_directions=directions + 2,
            max_tool_rounds=tool_rounds + 2,
            max_parallel=max(parallel * 4, 12),
            max_rounds=rounds * 2,
            scan_mode=mode,
        )
    # standard: today's config values, light fan-out as configured.
    return ScanProfile(
        max_steps=steps,
        max_directions=directions,
        max_tool_rounds=tool_rounds,
        max_parallel=parallel,
        max_rounds=rounds,
        scan_mode="standard",
    )


def resolve_scan_profile(
    config: Any,
    scan_mode: str = DEFAULT_SCAN_MODE,
    *,
    max_steps: Optional[int] = None,
    max_directions: Optional[int] = None,
    max_intents: Optional[int] = None,
    max_tool_rounds: Optional[int] = None,
    max_parallel: Optional[int] = None,
    max_rounds: Optional[int] = None,
) -> ScanProfile:
    """Resolve the final knobs: scan-mode preset, then explicit-flag overrides.

    Any ``max_*`` argument that is not ``None`` wins over the preset value — this
    is how ``--max-steps`` etc. override ``--scan-mode`` on the CLI.
    """
    profile = scan_mode_profile(config, scan_mode)
    if max_steps is not None:
        profile.max_steps = max_steps
    direction_override = max_directions if max_directions is not None else max_intents
    if direction_override is not None:
        profile.max_directions = direction_override
    if max_tool_rounds is not None:
        profile.max_tool_rounds = max_tool_rounds
    if max_parallel is not None:
        profile.max_parallel = max_parallel
    if max_rounds is not None:
        profile.max_rounds = max_rounds
    return profile


# ── Exit-code contract ──────────────────────────────────────────────


@dataclass
class FindingClassification:
    """How many findings landed in each class that the exit code cares about."""

    verified: int
    candidates: int

    @property
    def has_verified(self) -> bool:
        return self.verified > 0

    @property
    def has_candidates(self) -> bool:
        return self.candidates > 0


def classify_report_findings(document: dict[str, Any]) -> FindingClassification:
    """Use the assessed findings artifact shared by the report and SARIF."""
    return FindingClassification(
        verified=len(document["verified"]),
        candidates=sum(
            finding["assessment"]["outcome"] in {"suspected_high", "suspected_low"}
            for finding in document["findings"]
        ),
    )


def determine_exit_code(
    classification: FindingClassification,
    fail_on: str = DEFAULT_FAIL_ON,
) -> int:
    """Map a finding classification onto an exit code under a ``--fail-on`` policy.

    ``fail_on`` tunes which finding class trips a nonzero exit:

    - ``never``    → always :data:`EXIT_CLEAN` (0), even with verified findings.
    - ``verified`` → verified findings trip :data:`EXIT_VERIFIED` (2); unverified
      candidates do **not** trip (0), so a PR gate isn't blocked by guesses.
    - ``any``      → verified trip 2, and unverified candidates trip
      :data:`EXIT_CANDIDATES` (3).

    This never returns :data:`EXIT_ERROR` (1) — code 1 is reserved for the caller
    to signal a crash / misconfiguration, which is orthogonal to findings.
    """
    policy = fail_on if fail_on in FAIL_ON_MODES else DEFAULT_FAIL_ON
    if policy == "never":
        return EXIT_CLEAN
    if classification.has_verified:
        return EXIT_VERIFIED
    if policy == "any" and classification.has_candidates:
        return EXIT_CANDIDATES
    return EXIT_CLEAN


def exit_code_meaning(code: int) -> str:
    """Human-readable label for an exit code (for log lines / summaries)."""
    return {
        EXIT_CLEAN: "clean — nothing confirmed",
        EXIT_ERROR: "error — scan did not complete",
        EXIT_VERIFIED: "verified finding(s) present",
        EXIT_CANDIDATES: "unverified candidate(s) present",
    }.get(code, f"unknown ({code})")


# ── Run artifacts ───────────────────────────────────────────────────


def effective_scope_mode(scope_mode: str) -> str:
    """The scope actually applied to the scan.

    ``auto`` diff-scoping is owned by the Target diff-scope model (#35); until
    that lands the scan runs full-surface, so ``auto`` degrades to ``full`` here.
    Recording the effective value keeps the run summary honest rather than
    reporting a diff-scoped run that did not happen.
    """
    return "full" if scope_mode == "auto" else scope_mode


def _slugify_target(target: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", (target or "target").strip()).strip("-")
    return (slug or "target")[:80]


def run_directory(runs_root: Path, target: str, run_id: str) -> Path:
    """Deterministic run-directory path for a target + run id (no I/O)."""
    return Path(runs_root) / f"{_slugify_target(target)}-{run_id}"


def build_run_summary(
    *,
    target: str,
    scan_mode: str,
    scope_mode: str,
    fail_on: str,
    profile: ScanProfile,
    classification: FindingClassification,
    exit_code: int,
    report_path: Optional[str] = None,
) -> dict[str, Any]:
    """Assemble the machine-readable summary object written to the run directory."""
    return {
        "target": target,
        "scan_mode": scan_mode,
        "scope_mode": scope_mode,
        "scope_mode_effective": effective_scope_mode(scope_mode),
        "fail_on": fail_on,
        "profile": profile.as_dict(),
        "findings": {
            "verified": classification.verified,
            "candidates": classification.candidates,
            "total": classification.verified + classification.candidates,
        },
        "exit_code": exit_code,
        "exit_code_meaning": exit_code_meaning(exit_code),
        "report_path": report_path,
    }


def write_run_artifacts(run_dir: Path, summary: dict[str, Any]) -> Path:
    """Write ``summary.json`` into ``run_dir`` (creating it) and return its path."""
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    summary_path = run_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    return summary_path
