"""VulnClaw CodeScan engine — local source-code static analysis.

Pure-Python, zero extra dependencies. Layered like DeepSec shield:

- L1: instant regex + entropy detection (default on)
- L2: structural taint-ish checks (default on)
- L3: LLM-assisted semantic review (opt-in; requires configured provider)

The scanner walks a directory (or single file), skips noise (node_modules,
.git, binaries, lockfiles), and emits `CodeFinding` records compatible with
the existing `VulnerabilityFinding` schema so reports/streams integrate with
the rest of VulnClaw unchanged.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from vulnclaw.codescan.rules import (
    L1_RULES,
    L2_RULES,
    CodeFinding,
    L1Rule,
    detect_language,
    should_scan_file,
)


@dataclass
class ScanResult:
    """Aggregated outcome of a code scan."""

    path: str
    files_scanned: int = 0
    files_skipped: int = 0
    findings: list[CodeFinding] = field(default_factory=list)
    duration_ms: float = 0.0
    layers: list[str] = field(default_factory=lambda: ["L1", "L2"])

    @property
    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def summary(self) -> str:
        counts = self.severity_counts
        parts = [
            f"{counts.get(k, 0)} {k.lower()}" for k in ("Critical", "High", "Medium", "Low", "Info") if counts.get(k)
        ]
        detail = ", ".join(parts) if parts else "no findings"
        return (
            f"Scanned {self.files_scanned} file(s) in {self.duration_ms:.1f} ms; "
            f"{len(self.findings)} finding(s) ({detail})."
        )


def _iter_source_files(path: str) -> tuple[list[str], int]:
    """Yield source files to scan. Returns (files, skipped_count)."""
    files: list[str] = []
    skipped = 0
    if os.path.isfile(path):
        if should_scan_file(path):
            files.append(path)
        else:
            skipped = 1
        return files, skipped

    for root, dirs, names in os.walk(path):
        # Prune noise directories in place (os.walk mutates `dirs`).
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS_SET and not d.startswith(".")]
        for name in names:
            full = os.path.join(root, name)
            if should_scan_file(full):
                files.append(full)
            else:
                skipped += 1
    files.sort()
    return files, skipped


# Local copy to avoid importing the private set name from rules each call.
from vulnclaw.codescan.rules import SKIP_DIRS as _SKIP_DIRS_SET  # noqa: E402


def _scan_lines(
    file_path: str,
    language: Optional[str],
    lines: list[str],
    rules: Iterable[L1Rule],
    layer: str,
) -> list[CodeFinding]:
    findings: list[CodeFinding] = []
    for idx, line in enumerate(lines, start=1):
        # Keep only the highest-priority rule per line to avoid duplicate
        # noise (e.g. a key literal matches both the OpenAI-key rule and the
        # generic credential rule).
        best: Optional[tuple[int, L1Rule, "re.Match[str]"]] = None
        for rule in rules:
            if rule.language_hint is not None and rule.language_hint != language:
                continue
            # Rules tagged for a different layer are skipped by other layers.
            if rule.detection_layer != layer:
                continue
            m = rule.match(line)
            if m is None:
                continue
            priority = _RULE_PRIORITY.get(rule.rule_id, 50)
            if best is None or priority < best[0]:
                best = (priority, rule, m)
        if best is None:
            continue
        _prio, rule, m = best
        evidence = line.strip()[:160]
        findings.append(
            CodeFinding(
                rule_id=rule.rule_id,
                title=rule.title,
                severity=rule.severity,
                file=file_path,
                line=idx,
                column=m.start() + 1,
                evidence=evidence,
                description=rule.description,
                remediation=rule.remediation,
                cwe=rule.cwe,
                detection_layer=layer,
                confidence=rule.entropy_min if rule.entropy_min > 0 else 0.9,
            )
        )
    return findings


# Explicit per-line rule priority (lower = wins when several rules hit one line).
_RULE_PRIORITY: dict[str, int] = {
    "hardcoded_openai_key": 10,
    "hardcoded_aws_key": 10,
    "hardcoded_private_key": 10,
    "hardcoded_password": 20,
    "ai_placeholder_secret": 30,
    "dangerous_eval": 10,
    "xss_inner_html": 10,
    "command_injection": 10,
    "sql_string_concat": 10,
    "path_traversal": 10,
    "ssrf_url_fetch": 10,
    "insecure_deserialization": 10,
    "weak_crypto": 20,
    "insecure_http": 40,
    "unsafe_debug_true": 30,
    "missing_auth_check": 60,
    "ai_hallucinated_dependency": 70,
}


def scan_code(
    path: str,
    *,
    layers: Iterable[str] = ("L1", "L2"),
    progress: Optional[Any] = None,
) -> ScanResult:
    """Scan a file or directory for code vulnerabilities.

    Args:
        path: file or directory to scan.
        layers: which detection layers to run ("L1", "L2", "L3").
        progress: optional callable(file_path, findings_so_far) for streaming UI.
    """
    start = time.perf_counter()
    layer_set = {lyr.upper() for lyr in layers}
    result = ScanResult(path=path, layers=sorted(layer_set))

    files, skipped = _iter_source_files(path)
    result.files_skipped = skipped

    # Choose rule sets by layer. L3 is LLM-assisted; handled in `scan_code_llm`.
    rules: list[L1Rule] = []
    if "L1" in layer_set:
        rules.extend(L1_RULES)
    if "L2" in layer_set:
        rules.extend(L2_RULES)

    for file_path in files:
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            result.files_skipped += 1
            continue
        result.files_scanned += 1
        language = detect_language(file_path)
        # Run each layer's rule set independently so the layer tag is accurate.
        l1_hits = _scan_lines(file_path, language, lines, L1_RULES, layer="L1") if "L1" in layer_set else []
        l2_hits = _scan_lines(file_path, language, lines, L2_RULES, layer="L2") if "L2" in layer_set else []
        result.findings.extend(l1_hits)
        result.findings.extend(l2_hits)
        if progress is not None:
            progress(file_path, len(result.findings))

    result.duration_ms = (time.perf_counter() - start) * 1000.0
    return result


def scan_code_llm(
    path: str,
    *,
    findings: list[CodeFinding],
    llm_client: Any,
    progress: Optional[Any] = None,
) -> list[CodeFinding]:
    """L3 LLM-assisted review.

    The LLM inspects the same files and reports semantic issues (missing auth,
    business-logic flaws, authorization gaps) that regex cannot see.
    Opt-in only: the caller must have configured an LLM provider.

    Returns the combined finding list (original + LLM findings).
    """
    if llm_client is None:
        return findings

    files, _skipped = _iter_source_files(path)
    combined = list(findings)
    for file_path in files[:20]:  # cap at 20 files for cost control
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                code = fh.read(16_000)
        except OSError:
            continue
        if not code.strip():
            continue
        prompt = (
            "You are a code-security auditor. Review this source file and report "
            "security issues in JSON array format with fields: rule_id, title, "
            "severity (Critical/High/Medium/Low), line, evidence, remediation, cwe. "
            "Focus on missing authorization, insecure logic, and semantic flaws. "
            "Return only the JSON array, no prose.\n\n"
            f"File: {file_path}\n\n```\n{code}\n```"
        )
        try:
            resp = llm_client.complete(prompt)  # adapter — see cli wiring
            parsed = _parse_llm_findings(resp, file_path)
            combined.extend(parsed)
        except Exception:  # noqa: BLE001 — L3 must never break the scan
            continue
        if progress is not None:
            progress(file_path, len(combined))
    return combined


def _parse_llm_findings(raw: Any, file_path: str) -> list[CodeFinding]:
    """Best-effort parse of the LLM JSON response into CodeFinding records."""
    import json
    import re

    text = raw if isinstance(raw, str) else str(raw)
    m = re.search(r"\[.*\]", text, re.DOTALL)
    if not m:
        return []
    try:
        items = json.loads(m.group(0))
    except json.JSONDecodeError:
        return []
    out: list[CodeFinding] = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        out.append(
            CodeFinding(
                rule_id=str(item.get("rule_id", "llm_semantic")),
                title=str(item.get("title", "LLM semantic finding")),
                severity=str(item.get("severity", "Medium")),
                file=file_path,
                line=int(item.get("line", 0) or 0),
                evidence=str(item.get("evidence", "")),
                description=str(item.get("description", "")),
                remediation=str(item.get("remediation", "")),
                cwe=str(item.get("cwe", "")),
                detection_layer="L3",
                confidence=0.7,
            )
        )
    return out
