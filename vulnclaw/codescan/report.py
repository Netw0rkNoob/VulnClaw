"""VulnClaw CodeScan report formatting.

Formats `ScanResult` as:

- ``text``: rich terminal table (default)
- ``json``: full finding JSON (VulnerabilityFinding-compatible)
- ``sarif``: SARIF 2.1.0 static-analysis artifact (CI friendly)
- ``markdown``: readable markdown report
"""

from __future__ import annotations

import json
import time
from typing import Any

from vulnclaw.codescan.rules import CodeFinding
from vulnclaw.codescan.scanner import ScanResult


def _sanitize(value: Any) -> Any:
    """Recursively replace control chars that would break JSON string literals."""
    if isinstance(value, str):
        return (
            value.replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")
        )
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    return value


def _finding_to_vuln_dict(f: CodeFinding) -> dict[str, Any]:
    """Map CodeFinding -> VulnerabilityFinding-style dict (dedup id + location)."""
    return {
        "title": _sanitize(f.title),
        "severity": f.severity,
        "vuln_type": f.rule_id,
        "description": _sanitize(f.description or f.title),
        "evidence": _sanitize(f.evidence),
        "cwe": f.cwe or None,
        "remediation": _sanitize(f.remediation),
        "target": f.file,
        "code_location": f"{f.file}:{f.line}",
        "line": f.line,
        "column": f.column,
        "finding_id": f"{f.rule_id}:{f.file}:{f.line}",
        "detection_layer": f.detection_layer,
        "confidence": f.confidence,
    }


def format_text(result: ScanResult) -> str:
    """Render a rich terminal table (or a one-line summary when empty)."""
    if not result.findings:
        return result.summary()

    from rich.console import Console
    from rich.table import Table

    table = Table(title="VulnClaw Code Scan", show_lines=False)
    table.add_column("Severity", style="bold", no_wrap=True)
    table.add_column("Layer", no_wrap=True)
    table.add_column("Rule")
    table.add_column("Location", no_wrap=True)
    table.add_column("Evidence", max_width=70)

    for f in sorted(result.findings, key=lambda x: _SEV_ORDER.get(x.severity, 99)):
        sev_style = {
            "Critical": "bold red",
            "High": "red",
            "Medium": "yellow",
            "Low": "cyan",
            "Info": "dim",
        }.get(f.severity, "")
        loc = f"{f.file}:{f.line}"
        if f.line and f.column:
            loc = f"{f.file}:{f.line}:{f.column}"
        table.add_row(
            f.severity,
            f.detection_layer,
            f.rule_id,
            loc,
            f.evidence,
            style=sev_style,
        )

    console = Console(force_terminal=False)
    with console.capture() as capture:
        console.print(table)
    return capture.get() + "\n" + result.summary()


_SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def format_json(result: ScanResult) -> str:
    """Full JSON document (VulnerabilityFinding-compatible findings)."""
    findings_list: list[dict[str, Any]] = []
    for f in result.findings:
        findings_list.append(_sanitize(_finding_to_vuln_dict(f)))
    return json.dumps(
        {
            "tool": "vulnclaw",
            "command": "code scan",
            "path": result.path,
            "files_scanned": result.files_scanned,
            "files_skipped": result.files_skipped,
            "duration_ms": round(result.duration_ms, 1),
            "layers": result.layers,
            "summary": _sanitize(result.summary()),
            "findings": findings_list,
        },
        ensure_ascii=False,
        indent=2,
    )


def format_markdown(result: ScanResult) -> str:
    """Readable markdown report."""
    lines: list[str] = [
        "# VulnClaw Code Scan Report",
        "",
        f"- **Path**: `{result.path}`",
        f"- **Files scanned**: {result.files_scanned} (skipped {result.files_skipped})",
        f"- **Duration**: {result.duration_ms:.1f} ms",
        f"- **Layers**: {', '.join(result.layers)}",
        "",
    ]
    if not result.findings:
        lines.append("_No findings._")
        return "\n".join(lines) + "\n"

    lines.append(f"## Findings ({len(result.findings)})")
    lines.append("")
    lines.append("| Severity | Layer | Rule | File:Line | Evidence |")
    lines.append("|---|---|---|---|---|")
    for f in sorted(result.findings, key=lambda x: _SEV_ORDER.get(x.severity, 99)):
        ev = f.evidence.replace("|", "\\|")[:80]
        lines.append(f"| {f.severity} | {f.detection_layer} | `{f.rule_id}` | `{f.file}:{f.line}` | {ev} |")
    lines.append("")
    lines.append("## Details")
    lines.append("")
    for i, f in enumerate(sorted(result.findings, key=lambda x: _SEV_ORDER.get(x.severity, 99)), 1):
        lines.append(f"### {i}. [{f.severity}] {f.title}")
        lines.append("")
        lines.append(f"- **Rule**: `{f.rule_id}` (layer {f.detection_layer})")
        lines.append(f"- **Location**: `{f.file}:{f.line}:{f.column}`")
        lines.append(f"- **CWE**: {f.cwe or '—'}")
        lines.append(f"- **Evidence**: `{f.evidence}`")
        if f.description:
            lines.append(f"- **Description**: {f.description}")
        if f.remediation:
            lines.append(f"- **Fix**: {f.remediation}")
        lines.append("")
    return "\n".join(lines)


def format_sarif(result: ScanResult) -> str:
    """SARIF 2.1.0 document for CI pipelines."""
    rules_seen: dict[str, CodeFinding] = {}
    for f in result.findings:
        rules_seen.setdefault(f.rule_id, f)

    rules = [
        {
            "id": f.rule_id,
            "name": f.rule_id,
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.description or f.title},
            "defaultConfiguration": {"level": _sarif_level(f.severity)},
            "helpUri": f"https://cwe.mitre.org/data/definitions/{f.cwe.split('-')[-1]}.html"
            if f.cwe and f.cwe.startswith("CWE-")
            else None,
            "properties": {"severity": f.severity, "layer": f.detection_layer},
        }
        for f in rules_seen.values()
    ]

    results = []
    for f in result.findings:
        region = {}
        if f.line:
            region["startLine"] = f.line
        if f.column:
            region["startColumn"] = f.column
        results.append(
            {
                "ruleId": f.rule_id,
                "level": _sarif_level(f.severity),
                "message": {"text": f.title},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file.replace("\\", "/")},
                            "region": region,
                        }
                    }
                ],
                "partialFingerprints": {"primaryLocationLineHash": f"{f.rule_id}:{f.file}:{f.line}"},
                "properties": {"cwe": f.cwe, "evidence": f.evidence, "remediation": f.remediation},
            }
        )

    return json.dumps(
        {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "VulnClaw",
                            "informationUri": "https://github.com/Netw0rkNoob/VulnClaw",
                            "version": "0.3.8",
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        }
                    ],
                }
            ],
        },
        ensure_ascii=False,
        indent=2,
    )


def _sarif_level(severity: str) -> str:
    return {
        "Critical": "error",
        "High": "error",
        "Medium": "warning",
        "Low": "note",
        "Info": "note",
    }.get(severity, "warning")


def format_result(result: ScanResult, fmt: str) -> str:
    """Dispatch to a formatter by name."""
    fmt = (fmt or "text").lower()
    if fmt == "json":
        return format_json(result)
    if fmt == "sarif":
        return format_sarif(result)
    if fmt == "markdown" or fmt == "md":
        return format_markdown(result)
    return format_text(result)
