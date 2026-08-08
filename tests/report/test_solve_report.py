from pathlib import Path

from vulnclaw.agent.agent_state import AgentState
from vulnclaw.i18n import current_lang, init_i18n
from vulnclaw.report.solve_report import (
    extract_reproduction_requests,
    generate_solve_report,
    render_solve_report,
)


def _completed_state() -> AgentState:
    state = AgentState(origin="https://example.challenge.ctf.show/", goal="capture flag")
    state.pin_fact("Linked endpoint: select-waf.php", evidence_id="e001")
    state.pin_fact("JS/API endpoint: api/?id=", evidence_id="e002")
    state.pin_fact(
        "Source SQL: select id,username,password from ctfshow_user "
        "where username !='flag' and id = '$_GET[id]' limit 1",
        evidence_id="e003",
    )
    state.record_step(
        reason="Read page and script endpoints",
        observation="select-waf.php and api/?id found",
        tool_calls=["fetch"],
    )
    state.record_step(
        reason="Replay minimal SQL expression payload",
        observation="flag row returned",
        tool_calls=["http_probe_batch"],
    )
    output = """
# http_probe_batch results (2 request(s))
[1] GET baseline 200 len=111 hash=aaa 10ms type=text/html
    url=https://example.challenge.ctf.show/api/?id=1
    body_length=111
    body:
{"code":0,"data":[{"id":"1","username":"admin","password":"admin"}]}
[2] GET concat-no-comment 200 len=151 hash=bbb 10ms type=text/html
    url=https://example.challenge.ctf.show/api/?id=0%27%7C%7Cusername%3D%27flag
    body_length=151
    body:
{"code":0,"data":[{"id":"26","username":"flag","password":"ctfshow{report-ok}"}]}
"""
    evidence = state.remember_tool_result(
        tool="http_probe_batch",
        arguments={"requests": []},
        output=output,
        status=200,
    )
    state.record_tool_call(
        tool="http_probe_batch",
        arguments={"requests": []},
        status=200,
        evidence_id=evidence.id,
        summary=evidence.summary,
    )
    state.mark_complete(
        "verified flag from recorded evidence: ctfshow{report-ok}",
        final_answer="FINAL: ctfshow{report-ok}",
        evidence_ids=[evidence.id],
    )
    return state


def test_extract_reproduction_requests_prefers_flag_response():
    state = _completed_state()

    requests = extract_reproduction_requests(state)

    assert len(requests) == 2
    assert requests[1].url.endswith("username%3D%27flag")
    assert "ctfshow{report-ok}" in requests[1].body
    assert "GET /api/?id=0%27%7C%7Cusername%3D%27flag HTTP/1.1" in requests[
        1
    ].request_packet()


def test_render_solve_report_contains_replay_and_reasoning():
    previous_lang = current_lang()
    init_i18n(lang="zh")  # headings are localized; pin Chinese for this assertion
    try:
        report = render_solve_report(_completed_state())

        assert "# VulnClaw Solve Report" in report
        assert "ctfshow{report-ok}" in report
        assert "select-waf.php" in report
        assert "api/?id=" in report
        assert "Raw HTTP request" in report
        assert "curl -k -i" in report
        assert "解题思路" in report
        assert "Source SQL" in report
    finally:
        init_i18n(lang=previous_lang)


def test_generate_solve_report_writes_markdown(tmp_path):
    previous_lang = current_lang()
    init_i18n(lang="zh")  # pin Chinese: "复现请求包" is the localized heading
    try:
        output = generate_solve_report(_completed_state(), tmp_path / "solve.md")
    finally:
        init_i18n(lang=previous_lang)

    assert output == Path(tmp_path / "solve.md")
    assert output.exists()
    assert "复现请求包" in output.read_text(encoding="utf-8")
