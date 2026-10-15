"""A verified finding with an http_capture ref inlines its raw request/response."""

from __future__ import annotations

from tests.reporting_fixtures import assessed_snapshot
from vulnclaw.agent.context import EvidenceRef, SessionState, VulnerabilityFinding
from vulnclaw.i18n import current_lang, init_i18n
from vulnclaw.report.generator import generate_report
from vulnclaw.traffic import (
    CapturedExchange,
    CapturedRequest,
    CapturedResponse,
    ScopeChecker,
    ScopeMode,
    Target,
    TrafficCapture,
    TrafficStore,
)


async def test_verified_finding_inlines_http_capture(tmp_path):
    # Assertions below check for the Chinese heading text explicitly, so pin the
    # active UI language regardless of the ambient LANG/VULNCLAW_LANG env vars
    # (mirrors the explicit-language convention in tests/test_phase_i18n.py).
    previous_lang = current_lang()
    init_i18n(lang="zh")
    try:
        await _run_http_capture_inlining_assertions(tmp_path)
    finally:
        init_i18n(lang=previous_lang)


async def _run_http_capture_inlining_assertions(tmp_path):
    # Capture a request/response into the run's evidence/traffic store.
    run_dir = tmp_path / "run"
    store = TrafficStore(run_dir / "evidence" / "traffic")
    capture = TrafficCapture(
        store, ScopeChecker([Target(host="app.test")], mode=ScopeMode.STRICT)
    )
    request_id = capture.capture(
        CapturedExchange(
            request=CapturedRequest(
                method="GET",
                url="http://app.test/user?id=1'",
                headers={"Host": "app.test"},
            ),
            response=CapturedResponse(status=500, body=b"SQL syntax error near ''1'"),
        ),
        source="proxy",
    )
    assert request_id

    # A verified finding referencing that capture.
    finding = VulnerabilityFinding(
        title="SQL Injection in /user",
        severity="High",
        vuln_type="SQLi",
        evidence="id parameter is injectable",
        remediation="Use parameterized queries",
        evidence_refs=[EvidenceRef(kind="http_capture", request_id=request_id)],
    )
    finding.mark_verified(note="confirmed via error-based injection")

    session = SessionState(target="http://app.test")
    session.add_finding(finding)

    report_path = await generate_report(assessed_snapshot(session), output_path=str(run_dir / "report.md"))
    text = report_path.read_text(encoding="utf-8")

    assert "抓包复现证据" in text
    assert request_id in text
    assert "```http" in text
    assert "GET /user?id=1' HTTP/1.1" in text
    assert "SQL syntax error near" in text


async def test_verified_finding_inlines_http_capture_english(tmp_path):
    """Same as above under the English UI language: the heading and body

    translate, but the raw request/response bytes (not translated content)
    still land verbatim in the report.
    """
    previous_lang = current_lang()
    init_i18n(lang="en")
    try:
        run_dir = tmp_path / "run"
        store = TrafficStore(run_dir / "evidence" / "traffic")
        capture = TrafficCapture(
            store, ScopeChecker([Target(host="app.test")], mode=ScopeMode.STRICT)
        )
        request_id = capture.capture(
            CapturedExchange(
                request=CapturedRequest(
                    method="GET",
                    url="http://app.test/user?id=1'",
                    headers={"Host": "app.test"},
                ),
                response=CapturedResponse(status=500, body=b"SQL syntax error near ''1'"),
            ),
            source="proxy",
        )
        assert request_id

        finding = VulnerabilityFinding(
            title="SQL Injection in /user",
            severity="High",
            vuln_type="SQLi",
            evidence="id parameter is injectable",
            remediation="Use parameterized queries",
            evidence_refs=[EvidenceRef(kind="http_capture", request_id=request_id)],
        )
        finding.mark_verified(note="confirmed via error-based injection")

        session = SessionState(target="http://app.test")
        session.add_finding(finding)

        report_path = await generate_report(assessed_snapshot(session), output_path=str(run_dir / "report.md"))
        text = report_path.read_text(encoding="utf-8")

        assert "Captured-traffic reproduction evidence" in text
        assert request_id in text
        assert "```http" in text
        assert "GET /user?id=1' HTTP/1.1" in text
        assert "SQL syntax error near" in text
    finally:
        init_i18n(lang=previous_lang)


def test_shared_resolver_finds_config_default_when_no_run_captures(tmp_path, monkeypatch):
    """The report reader and agent writer share one resolver seam.

    When the agent wrote captures to the config-default store (no per-run dir),
    the report generator's resolver still finds them.
    """
    from vulnclaw.traffic.paths import (
        resolve_report_traffic_store,
        resolve_traffic_store,
    )

    evidence_root = tmp_path / "config-evidence"
    monkeypatch.setenv("VULNCLAW_EVIDENCE_DIR", str(evidence_root))

    # Agent-side write: no run dir -> lands in the config default.
    writer = resolve_traffic_store(None)
    capture = TrafficCapture(
        writer, ScopeChecker([Target(host="app.test")], mode=ScopeMode.STRICT)
    )
    request_id = capture.capture(
        CapturedExchange(
            request=CapturedRequest(method="GET", url="http://app.test/x"),
            response=CapturedResponse(status=200, body=b"ok"),
        ),
        source="proxy",
    )

    # Report-side read for a run dir that has no captures of its own: falls back
    # to the same config default and finds the agent's capture.
    reader = resolve_report_traffic_store(tmp_path / "run-with-no-captures")
    assert reader.find(request_id) is not None


def test_write_resolver_never_falls_back_to_stale_store(tmp_path, monkeypatch):
    """A fresh run's writes go to its own dir, not a stale global store."""
    from vulnclaw.traffic.paths import resolve_traffic_store

    evidence_root = tmp_path / "config-evidence"
    monkeypatch.setenv("VULNCLAW_EVIDENCE_DIR", str(evidence_root))

    # Seed the config-default store with an unrelated earlier run's capture.
    default = resolve_traffic_store(None)
    TrafficCapture(
        default, ScopeChecker([Target(host="old.test")], mode=ScopeMode.STRICT)
    ).capture(
        CapturedExchange(request=CapturedRequest(url="http://old.test/")),
        source="proxy",
    )

    # A brand-new run resolves to ITS OWN dir even though the default has an index.
    run_dir = tmp_path / "fresh-run"
    writer = resolve_traffic_store(run_dir)
    assert writer.base_dir == (run_dir / "evidence" / "traffic")
    assert writer.entries() == []  # fresh run starts empty, not mixed with old.test


async def test_report_without_captures_is_unaffected(tmp_path):
    run_dir = tmp_path / "run"
    finding = VulnerabilityFinding(
        title="Reflected XSS",
        severity="Medium",
        vuln_type="XSS",
        evidence="payload reflected",
        remediation="encode output",
    )
    finding.mark_verified()
    session = SessionState(target="http://app.test")
    session.add_finding(finding)

    report_path = await generate_report(assessed_snapshot(session), output_path=str(run_dir / "report.md"))
    text = report_path.read_text(encoding="utf-8")
    assert "Reflected XSS" in text
    assert "```http" not in text
