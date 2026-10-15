"""Local-server tests for the approved PoC execution path in findings/poc.py."""

import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from types import SimpleNamespace
from urllib.parse import unquote_plus, urlsplit

import pytest

from vulnclaw.agent.context import SessionState, TaskConstraints
from vulnclaw.config.schema import VulnClawConfig
from vulnclaw.findings.intake import submit_finding
from vulnclaw.findings.types import EvidenceReview
from vulnclaw.findings.verification import verify_findings

# Per-test handler behavior: query string -> (status, body, headers).
_BEHAVIOR = {}


class _Handler(BaseHTTPRequestHandler):
    hits = 0

    def log_message(self, *args):
        pass

    def do_GET(self):
        type(self).hits += 1
        status, body, headers = _BEHAVIOR["run"](urlsplit(self.path).query)
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())


@pytest.fixture(autouse=True)
def isolated_gate():
    # The execution gate is a process-level singleton; earlier suites may have
    # initialized it in "ask" mode, which would mask the full_access approval
    # these tests configure.
    from vulnclaw.agent.exec_gate import reset_execution_gate

    reset_execution_gate()
    yield
    reset_execution_gate()


@pytest.fixture
def receiver(monkeypatch):
    # The PoC program already disables proxy env; clear it for the harness too
    # so an ambient HTTP_PROXY can never route the loopback assertions.
    for var in ("http_proxy", "https_proxy", "all_proxy",
                "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.delenv(var, raising=False)
    _Handler.hits = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _candidate(tmp_path, base, url, output, *, vuln_type="RCE", constraints=None, method=None):
    config = VulnClawConfig()
    config.session.output_dir = tmp_path
    config.session.auto_save = False
    config.safety.permission_mode = "full_access"
    state = SessionState(target=base)
    state.agent_state.remember_tool_result(
        tool="fetch", arguments={"url": url}, target=state.target, output=output,
    )
    if constraints is not None:
        state.task_constraints = constraints
    agent = SimpleNamespace(config=config, context=SimpleNamespace(state=state),
                            session_state=state)
    submission = {
        "title": "Recorded candidate", "description": "Reproduce from the recorded request",
        "vuln_type": vuln_type, "severity": "High", "evidence_ids": ["e001"],
        "endpoint": url,
    }
    if method is not None:
        submission["method"] = method
    submit_finding(agent, submission)
    return config, state


def _recorded(url, body):
    return f"Request: GET {url}\nStatus: 200\nBody ({len(body)} chars): {body}"


def _review():
    return EvidenceReview(confidence="high", reason="Direct observation on the exact target",
                          observations=[{"evidence_id": "e001", "quote": "Status: 200"}])


async def test_conclusive_rce_poc_marks_verified_and_archives_artifacts(tmp_path, receiver):
    def execute_printf(query):
        # Simulate the vulnerable endpoint: run the recorded printf control
        # server-side and return its constructed nonce.
        match = re.search(r"printf 'VC_%s%s' '([0-9a-f]{16})' '([0-9a-f]{16})'",
                          unquote_plus(query))
        return (200, f"VC_{match.group(1)}{match.group(2)}" if match else "plain", {})

    _BEHAVIOR["run"] = execute_printf
    url = f"{receiver}/cmd?file=notes%20id"
    config, state = _candidate(tmp_path, receiver, url, _recorded(url, "notes id"))
    view = await verify_findings(state, config=config, poc_verify=True)
    assessment = view.findings[0].assessment
    assert assessment.outcome == "verified" and assessment.method == "poc"
    assert state.findings[0].verified and state.findings[0].verification_status == "verified"
    assert assessment.artifacts and all(Path(path).exists() for path in assessment.artifacts)


async def test_conclusive_sqli_poc_rejects_the_claim(tmp_path, receiver):
    baseline = '{"rows": ["a"]}'
    _BEHAVIOR["run"] = lambda query: (200, baseline, {})
    url = f"{receiver}/search?id=1%20AND%201=1"
    config, state = _candidate(tmp_path, receiver, url, _recorded(url, baseline),
                               vuln_type="SQLi")
    view = await verify_findings(state, config=config, poc_verify=True)
    assessment = view.findings[0].assessment
    assert assessment.outcome == "rejected" and assessment.method == "poc"
    assert state.findings[0].verification_status == "rejected"
    assert not state.findings[0].verified


async def test_inconclusive_poc_falls_back_to_evidence_review(tmp_path, receiver, monkeypatch):
    # The target never echoes the constructed nonce: the controlled check is
    # inconclusive and must not be read as exclusion.
    _BEHAVIOR["run"] = lambda query: (200, "plain", {})
    url = f"{receiver}/cmd?file=notes%20id"
    config, state = _candidate(tmp_path, receiver, url, _recorded(url, "notes id"))
    monkeypatch.setattr("vulnclaw.findings.verification._review_with_llm", lambda *args: _review())
    view = await verify_findings(state, config=config, poc_verify=True)
    assessment = view.findings[0].assessment
    assert assessment.method == "evidence_review" and assessment.outcome == "suspected_low"
    assert not assessment.complete
    assert assessment.failure_reason
    assert not state.findings[0].verified


async def test_action_restriction_blocks_poc_before_any_request(tmp_path, receiver, monkeypatch):
    _BEHAVIOR["run"] = lambda query: (200, "plain", {})
    url = f"{receiver}/cmd?file=notes%20id"
    config, state = _candidate(
        tmp_path, receiver, url, _recorded(url, "notes id"),
        constraints=TaskConstraints(blocked_actions=["exploit"]),
    )
    monkeypatch.setattr("vulnclaw.findings.verification._review_with_llm", lambda *args: _review())
    view = await verify_findings(state, config=config, poc_verify=True)
    assessment = view.findings[0].assessment
    assert assessment.method == "evidence_review" and assessment.outcome == "suspected_low"
    assert not assessment.complete
    assert assessment.failure_reason
    assert _Handler.hits == 0  # the plan never reached the target


async def test_redirects_are_not_followed_and_fall_back(tmp_path, receiver, monkeypatch):
    _BEHAVIOR["run"] = lambda query: (302, "", {"Location": "/elsewhere"})
    url = f"{receiver}/cmd?file=notes%20id"
    config, state = _candidate(tmp_path, receiver, url, _recorded(url, "notes id"))
    monkeypatch.setattr("vulnclaw.findings.verification._review_with_llm", lambda *args: _review())
    view = await verify_findings(state, config=config, poc_verify=True)
    assessment = view.findings[0].assessment
    assert assessment.method == "evidence_review"
    assert "200" in assessment.failure_reason
    assert not state.findings[0].verified


async def test_get_replay_cannot_confirm_a_post_candidate(tmp_path, receiver, monkeypatch):
    # The endpoint is command-executable over GET, but the candidate claims a
    # POST method and cites both a GET and a POST request to the same path.
    # The GET-only replay must not be borrowed to confirm the POST candidate.
    def execute_printf(query):
        match = re.search(r"printf 'VC_%s%s' '([0-9a-f]{16})' '([0-9a-f]{16})'",
                          unquote_plus(query))
        return (200, f"VC_{match.group(1)}{match.group(2)}" if match else "plain", {})

    _BEHAVIOR["run"] = execute_printf
    url = f"{receiver}/cmd?file=notes%20id"
    config = VulnClawConfig()
    config.session.output_dir = tmp_path
    config.session.auto_save = False
    config.safety.permission_mode = "full_access"
    state = SessionState(target=receiver)
    state.agent_state.remember_tool_result(
        tool="fetch", arguments={"url": url}, target=receiver,
        output=_recorded(url, "notes id"),
    )
    state.agent_state.remember_tool_result(
        tool="fetch", arguments={"url": url, "method": "POST", "data": "file=notes id"},
        target=receiver, output=_recorded(url, "notes id"),
    )
    agent = SimpleNamespace(config=config, context=SimpleNamespace(state=state),
                            session_state=state)
    submit_finding(agent, {
        "title": "Recorded candidate", "description": "Reproduce from the recorded request",
        "vuln_type": "RCE", "severity": "High", "evidence_ids": ["e001", "e002"],
        "endpoint": url, "method": "POST",
    })
    monkeypatch.setattr("vulnclaw.findings.verification._review_with_llm", lambda *args: _review())
    view = await verify_findings(state, config=config, poc_verify=True)
    assessment = view.findings[0].assessment
    assert assessment.method == "evidence_review" and assessment.outcome == "suspected_high"
    assert assessment.failure_reason
    assert not state.findings[0].verified
    assert _Handler.hits == 0  # the vulnerable GET path was never replayed


async def test_declared_get_candidate_still_verifies_via_poc(tmp_path, receiver):
    def execute_printf(query):
        match = re.search(r"printf 'VC_%s%s' '([0-9a-f]{16})' '([0-9a-f]{16})'",
                          unquote_plus(query))
        return (200, f"VC_{match.group(1)}{match.group(2)}" if match else "plain", {})

    _BEHAVIOR["run"] = execute_printf
    url = f"{receiver}/cmd?file=notes%20id"
    config, state = _candidate(tmp_path, receiver, url, _recorded(url, "notes id"), method="GET")
    view = await verify_findings(state, config=config, poc_verify=True)
    assessment = view.findings[0].assessment
    assert assessment.outcome == "verified" and assessment.method == "poc"
