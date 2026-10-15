"""Explicit audited inputs for renderer tests; no verification calls are patched."""

from vulnclaw.findings.types import FindingAssessment, apply_assessment, finding_input_digest


def assessed_findings(findings):
    for finding in findings:
        if finding.assessment is None:
            outcome = ("verified" if finding.verified else
                       "rejected" if finding.verification_status == "rejected" else "suspected_low")
            finding.assessment = FindingAssessment(
                outcome=outcome, method="poc" if outcome in {"verified", "rejected"} else "evidence_review",
                reason="Controlled assessment fixture",
            )
        finding.assessment.input_digest = finding_input_digest(finding)
        apply_assessment(finding, finding.assessment)
    return findings


def assessed_snapshot(session):
    assessed_findings(session.findings)
    session._vulnerabilities.findings = session.findings
    return session
