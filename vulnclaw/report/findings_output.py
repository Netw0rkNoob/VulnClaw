"""Structured findings output — canonical ``findings.json`` + SARIF 2.1.0 emitter.

Every run emits two machine-consumable artifacts alongside the human report:

- ``findings.json`` — *all* findings with their lifecycle/verification status, for
  audit and downstream tooling. Rejected / candidate / needs-manual-review findings
  appear here with their status; nothing is silently dropped.
- ``findings.sarif`` — only the **verified** findings (the report inclusion gate),
  shaped for GitHub code-scanning and other SARIF 2.1.0 consumers.

Only findings independently assessed as verified by a current, saved PoC audit are
included. Saved historical flags never bypass current finding assessment.

The SARIF emitter uses stdlib ``json``; the mapping is defined in this module.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from vulnclaw.agent.context import SessionState, VulnerabilityFinding

SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
FINDINGS_SCHEMA_VERSION = "1.2"
TOOL_NAME = "VulnClaw"
TOOL_URI = "https://github.com/JMAN730/VulnClaw"
# Stable (non-random) GUID for the CWE taxonomy component.
CWE_TAXONOMY_GUID = "25f72d7e-8a92-459d-ad67-64853f788765"

# severity → SARIF result level
_SEVERITY_TO_LEVEL = {
    "Critical": "error",
    "High": "error",
    "Medium": "warning",
    "Low": "note",
    "Info": "note",
}

_LIFECYCLE_BUCKETS = (
    "candidate",
    "pending_verification",
    "needs_manual_review",
    "verified",
    "rejected",
)


# ── Inclusion gate ────────────────────────────────────────────────────────────


def is_report_included(finding: VulnerabilityFinding) -> bool:
    """Include only conclusive current PoC assessments."""
    from vulnclaw.findings.types import finding_input_digest

    assessment = finding.assessment
    return bool(assessment and assessment.input_digest == finding_input_digest(finding)
                and assessment.complete and assessment.method == "poc"
                and assessment.outcome == "verified" and finding.verified)



def _verified_set(session: SessionState) -> list[VulnerabilityFinding]:
    """Deduplicated verified findings — the shared feed for report/SARIF/json."""
    from vulnclaw.findings.types import require_assessed
    from vulnclaw.report.filter import deduplicate_report_findings

    require_assessed(session)
    verified = [f for f in session.findings if is_report_included(f)]
    return deduplicate_report_findings(verified)


# ── findings.json ─────────────────────────────────────────────────────────────


def _finding_to_dict(finding: VulnerabilityFinding) -> dict[str, Any]:
    return finding.model_dump(mode="json")


def _lifecycle_counts(findings: list[VulnerabilityFinding]) -> dict[str, int]:
    counts = {bucket: 0 for bucket in _LIFECYCLE_BUCKETS}
    for finding in findings:
        status = finding.lifecycle_status or "candidate"
        if status in counts:
            counts[status] += 1
    return counts


def build_findings_document(
    session: SessionState,
    *,
    version: Optional[str] = None,
    generated_at: Optional[str] = None,
) -> dict[str, Any]:
    """Build the canonical ``findings.json`` document for a session.

    Contains every finding (with status) plus the deduplicated verified subset.
    """
    from vulnclaw import __version__

    version = version or __version__
    generated_at = generated_at or datetime.now().isoformat()

    all_findings = list(session.findings)
    verified = _verified_set(session)

    # Lifecycle buckets count the raw (un-deduplicated) findings, but summary.verified
    # must track the deduplicated ``verified`` array and the SARIF result count — so
    # override the raw "verified" bucket with the deduplicated length. Otherwise a
    # session with duplicate verified findings would report summary.verified larger
    # than len(verified), breaking consumers that trust the totals.
    lifecycle = _lifecycle_counts(all_findings)
    lifecycle["verified"] = len(verified)
    summary = {"total": len(all_findings), **lifecycle,
               **{outcome: sum(f.assessment.outcome == outcome for f in all_findings)
                  for outcome in ("rejected", "suspected_high", "suspected_low")}}

    return {
        "schema_version": FINDINGS_SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": version, "informationUri": TOOL_URI},
        "target": session.target or "",
        "generated_at": generated_at,
        "summary": summary,
        "findings": [_finding_to_dict(f) for f in all_findings],
        "verified": [_finding_to_dict(f) for f in verified],
    }


# ── SARIF 2.1.0 ───────────────────────────────────────────────────────────────


def _slug(text: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", (text or "").strip()).strip("-").lower()
    return slug or "finding"


def _rule_id_for(finding: VulnerabilityFinding) -> str:
    return "vulnclaw/" + _slug(finding.vuln_type or finding.title)


def _parse_code_location(code_location: str) -> tuple[str, dict[str, int]]:
    """Parse a ``file:line[:col]`` string into (uri, region).

    Tolerates Windows drive prefixes (``C:/path/app.py:42``) by only treating a
    trailing numeric segment as a line/column.
    """
    segs = code_location.rsplit(":", 2)
    if len(segs) == 3 and segs[1].isdigit() and segs[2].isdigit():
        return segs[0], {"startLine": int(segs[1]), "startColumn": int(segs[2])}
    if len(segs) >= 2 and segs[-1].isdigit():
        return code_location.rsplit(":", 1)[0], {"startLine": int(segs[-1])}
    return code_location, {}


def _synthetic_uri(finding: VulnerabilityFinding, target: str) -> str:
    anchor = finding.finding_id or _slug(finding.title)
    return f"vulnclaw://{_slug(target) or 'target'}/{anchor}"


def _build_location(finding: VulnerabilityFinding, target: str) -> dict[str, Any]:
    """Code findings → real ``physicalLocation``; web findings → ``logicalLocations``
    plus a synthetic ``physicalLocation`` anchor (SARIF requires a physical anchor
    for most consumers)."""
    if finding.code_location:
        uri, region = _parse_code_location(finding.code_location)
        physical: dict[str, Any] = {"artifactLocation": {"uri": uri}}
        if region:
            physical["region"] = region
        return {"physicalLocation": physical}

    anchor = finding.endpoint or _synthetic_uri(finding, target)
    logical_name = finding.endpoint or finding.vuln_type or finding.title
    fq_name = f"{finding.method} {finding.endpoint}".strip() if finding.endpoint else logical_name
    return {
        "physicalLocation": {"artifactLocation": {"uri": anchor}},
        "logicalLocations": [
            {"name": logical_name, "fullyQualifiedName": fq_name, "kind": "member"}
        ],
    }


def _build_attachments(finding: VulnerabilityFinding) -> list[dict[str, Any]]:
    """Each ``EvidenceRef`` becomes a SARIF ``artifactLocation`` attachment."""
    attachments: list[dict[str, Any]] = []
    for ref in finding.evidence_refs:
        artifact: dict[str, Any] = {"uri": ref.path}
        if ref.request_id:
            artifact["description"] = {"text": f"request_id={ref.request_id}"}
        attachments.append({"description": {"text": ref.kind}, "artifactLocation": artifact})
    return attachments


def _result_message(finding: VulnerabilityFinding) -> str:
    tail = finding.impact or finding.description
    parts = [p for p in (finding.title, tail) if p]
    return " — ".join(parts) if parts else (finding.title or finding.vuln_type or "finding")


def _build_result_properties(finding: VulnerabilityFinding) -> dict[str, Any]:
    props: dict[str, Any] = {
        "severity": finding.severity,
        "verification_status": finding.verification_status,
        "lifecycle_status": finding.lifecycle_status,
        "evidence_level": finding.evidence_level,
        "finding_id": finding.finding_id,
    }
    if finding.cvss is not None:
        props["cvss"] = finding.cvss
    if finding.cve:
        props["cve"] = finding.cve
    if finding.cwe:
        props["cwe"] = finding.cwe
    if finding.method:
        props["http_method"] = finding.method
    if finding.endpoint:
        props["endpoint"] = finding.endpoint
    if finding.impact:
        props["impact"] = finding.impact
    if finding.skill_provenance:
        props["skill_provenance"] = finding.skill_provenance
    if finding.subagent_provenance:
        props["subagent_provenance"] = finding.subagent_provenance
    if finding.evidence_refs:
        props["evidence_refs"] = [ref.model_dump(mode="json") for ref in finding.evidence_refs]
    return props


def _build_rule(finding: VulnerabilityFinding, rule_id: str) -> dict[str, Any]:
    name = finding.vuln_type or finding.title
    rule: dict[str, Any] = {
        "id": rule_id,
        "name": name,
        "shortDescription": {"text": name[:200]},
    }
    tags = ["security"]
    props: dict[str, Any] = {}
    if finding.cwe:
        props["cwe"] = finding.cwe
        tags.append("external/cwe/" + finding.cwe.lower())
        rule["relationships"] = [
            {
                "target": {"id": finding.cwe, "toolComponent": {"name": "CWE"}},
                "kinds": ["superset"],
            }
        ]
    props["tags"] = tags
    rule["properties"] = props
    return rule


def _build_result(
    finding: VulnerabilityFinding, rule_id: str, rule_index: int, target: str
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": rule_id,
        "ruleIndex": rule_index,
        "level": _SEVERITY_TO_LEVEL.get(finding.severity, "warning"),
        "message": {"text": _result_message(finding)},
        "locations": [_build_location(finding, target)],
        "properties": _build_result_properties(finding),
    }
    attachments = _build_attachments(finding)
    if attachments:
        result["attachments"] = attachments
    if finding.cwe:
        result["taxa"] = [{"id": finding.cwe, "toolComponent": {"name": "CWE"}}]
    return result


def _build_cwe_taxon(cwe: str) -> dict[str, Any]:
    return {"id": cwe, "name": cwe}


def to_sarif(
    findings: list[VulnerabilityFinding],
    *,
    target: str = "",
    version: Optional[str] = None,
) -> dict[str, Any]:
    """Render verified findings into a SARIF 2.1.0 log (stdlib-only, no external lib)."""
    from vulnclaw import __version__
    from vulnclaw.findings.types import finding_input_digest

    if any(f.assessment is None or f.assessment.input_digest != finding_input_digest(f)
           for f in findings):
        raise ValueError("SARIF requires an independent assessment for every finding")
    findings = [f for f in findings if is_report_included(f)]

    version = version or __version__

    rules: list[dict[str, Any]] = []
    rule_index: dict[str, int] = {}
    results: list[dict[str, Any]] = []
    cwe_taxa: dict[str, dict[str, Any]] = {}

    for finding in findings:
        rule_id = _rule_id_for(finding)
        if rule_id not in rule_index:
            rule_index[rule_id] = len(rules)
            rules.append(_build_rule(finding, rule_id))
        results.append(_build_result(finding, rule_id, rule_index[rule_id], target))
        if finding.cwe:
            cwe_taxa.setdefault(finding.cwe, _build_cwe_taxon(finding.cwe))

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "version": version,
                "informationUri": TOOL_URI,
                "rules": rules,
            }
        },
        "results": results,
    }
    if cwe_taxa:
        run["taxonomies"] = [
            {
                "name": "CWE",
                "guid": CWE_TAXONOMY_GUID,
                "informationUri": "https://cwe.mitre.org/",
                "isComprehensive": False,
                "taxa": list(cwe_taxa.values()),
            }
        ]

    return {"$schema": SARIF_SCHEMA_URI, "version": SARIF_VERSION, "runs": [run]}


# ── Emit both artifacts ───────────────────────────────────────────────────────


def write_findings_artifacts(
    session: SessionState,
    findings_dir: Path | str,
    *,
    version: Optional[str] = None,
    generated_at: Optional[str] = None,
) -> dict[str, Path]:
    """Write ``findings.json`` (all findings) and ``findings.sarif`` (verified only).

    Returns a mapping of artifact name → written path.
    """
    findings_dir = Path(findings_dir)
    findings_dir.mkdir(parents=True, exist_ok=True)

    document = build_findings_document(session, version=version, generated_at=generated_at)
    json_path = findings_dir / "findings.json"
    json_path.write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8")

    sarif = to_sarif(_verified_set(session), target=session.target or "", version=version)
    sarif_path = findings_dir / "findings.sarif"
    sarif_path.write_text(json.dumps(sarif, ensure_ascii=False, indent=2), encoding="utf-8")

    return {"findings_json": json_path, "findings_sarif": sarif_path}
