"""VulnClaw CodeScan TUI streaming adapter.

Bridges the VulnClaw Python JSONL sink protocol so code-scan results
appear live inside the Rust TUI (same as run/scan/exploit/recon).

The Rust TUI protocol vocabulary consumed here:
  - status   {"type": "status", "status": "..."}
  - finding  {"type": "finding", "finding": {...}}
  - complete {"type": "complete", "summary": "...", "result": {"findings": [...]}}
"""

from __future__ import annotations

import json
import sys
from typing import Any

from vulnclaw.codescan.scanner import ScanResult


def _sanitize(value: Any) -> Any:
    """Recursively replace control chars that would break JSON string literals."""
    if isinstance(value, str):
        return value.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    return value


def _emit(event: dict, stream: Any) -> None:
    stream.write(json.dumps(_sanitize(event), ensure_ascii=False, separators=(",", ":")) + "\n")
    stream.flush()


def emit_code_scan_stream(
    result: ScanResult,
    stream: Any = None,
) -> None:
    """Stream a ScanResult to stdout (TUI JSONL protocol).

    The Rust TUI parses:
      - status messages during the scan
      - one finding event per finding
      - a complete event with all finding ids
    """
    if stream is None:
        stream = sys.stdout

    _emit({"type": "status", "status": f"Code scanning {result.path}..."}, stream)
    for f in result.findings:
        _emit(
            {
                "type": "finding",
                "finding": {
                    "id": f"{f.rule_id}:{f.file}:{f.line}",
                    "severity": f.severity,
                    "title": f.title,
                    "target": f.file,
                    "line": f.line,
                    "chain_depends_on": [],
                    # Extended fields the Rust Finding struct will ignore
                    # but useful for tools consuming the stream directly.
                    "rule_id": f.rule_id,
                    "evidence": f.evidence,
                    "cwe": f.cwe,
                    "detection_layer": f.detection_layer,
                    "description": f.description,
                    "remediation": f.remediation,
                },
            },
            stream,
        )

    _emit(
        {
            "type": "complete",
            "summary": result.summary(),
            "result": {
                "findings": [
                    {"id": f"{f.rule_id}:{f.file}:{f.line}", "severity": f.severity, "title": f.title}
                    for f in result.findings
                ]
            },
        },
        stream,
    )
