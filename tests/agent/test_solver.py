from types import SimpleNamespace

import pytest

from vulnclaw.agent.context import ContextManager
from vulnclaw.agent.solver import extract_json, solve
from vulnclaw.config.domain_models import VulnerabilityFinding


class _Parser:
    def parse(self, text):
        self.last = text


class _Agent:
    def __init__(self):
        self.context = ContextManager()
        self.session_state = self.context.state
        self.config = SimpleNamespace()
        self._observation_parser = _Parser()


def test_extract_json_accepts_noisy_model_output():
    assert extract_json('prefix {"action": "continue"} suffix') == {"action": "continue"}


@pytest.mark.asyncio
async def test_solve_rejects_unverified_flag_then_completes(monkeypatch):
    agent = _Agent()
    calls = {"n": 0}

    async def fake_call_llm_auto(agent_arg, system_prompt, round_context, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return "FINAL: flag{fake} evidence e001"
        record = agent_arg.context.state.agent_state.remember_tool_result(
            tool="fetch",
            arguments={"url": "http://t/"},
            output="Status: 200\nflag{real}",
            status=200,
        )
        agent_arg.context.state.agent_state.record_tool_call(
            tool="fetch",
            arguments={"url": "http://t/"},
            evidence_id=record.id,
            summary=record.summary,
        )
        return "FINAL: flag{real} evidence e001"

    monkeypatch.setattr("vulnclaw.agent.solver.call_llm_auto", fake_call_llm_auto)

    result = await solve(agent, origin="http://t", goal="capture flag", max_steps=3)

    assert result.completed is True
    assert "flag{real}" in result.reason
    assert agent.context.state.agent_state.completion_rejections


@pytest.mark.asyncio
async def test_evidence_gated_final_completes_without_promoting_findings(monkeypatch):
    agent = _Agent()
    sql = VulnerabilityFinding(
        title="SQL injection in id",
        vuln_type="SQLi",
        endpoint="/item",
        evidence="candidate",
        remediation="parameterize queries",
    )
    xss = VulnerabilityFinding(
        title="XSS candidate",
        vuln_type="XSS",
        endpoint="/search",
        evidence="candidate",
        remediation="encode output",
    )
    agent.context.state.add_finding(sql)
    agent.context.state.add_finding(xss)

    async def fake_call_llm_auto(agent_arg, *args, **kwargs):
        state = agent_arg.context.state.agent_state
        record = state.remember_tool_result(
            tool="http_probe_batch",
            arguments={"requests": [{"url": "/item?id=1'"}]},
            output="SQL injection confirmed by a reproducible response delta",
            status=200,
        )
        state.record_tool_call(
            tool="http_probe_batch",
            arguments={"requests": [{"url": "/item?id=1'"}]},
            evidence_id=record.id,
            summary=record.summary,
        )
        return f"FINAL: SQL injection confirmed at /item evidence {record.id}"

    monkeypatch.setattr("vulnclaw.agent.solver.call_llm_auto", fake_call_llm_auto)

    result = await solve(
        agent, origin="http://target.local", goal="verify vulnerabilities", max_steps=1
    )

    assert result.completed is True
    assert sql.verified is False
    assert sql.verification_status == "pending"
    assert xss.verified is False




@pytest.mark.asyncio
async def test_solve_stops_for_user_question(monkeypatch):
    agent = _Agent()

    async def fake_call_llm_auto(*args, **kwargs):
        return "Need scope clarification\nASK_USER: May I test the admin path?"

    monkeypatch.setattr("vulnclaw.agent.solver.call_llm_auto", fake_call_llm_auto)

    result = await solve(agent, origin="http://t", goal="test target", max_steps=3)

    assert result.needs_user is True
    assert result.reason == "waiting for user input"
    assert "admin path" in agent.context.state.agent_state.pending_questions[0]


@pytest.mark.asyncio
async def test_solve_records_step_observation(monkeypatch):
    agent = _Agent()

    async def fake_call_llm_auto(agent_arg, *args, **kwargs):
        record = agent_arg.context.state.agent_state.remember_tool_result(
            tool="fetch",
            arguments={"url": "http://t/"},
            output="Status: 200\nlogin form",
            status=200,
        )
        agent_arg.context.state.agent_state.record_tool_call(
            tool="fetch",
            arguments={"url": "http://t/"},
            evidence_id=record.id,
            summary=record.summary,
        )
        return "I will inspect the login form next."

    monkeypatch.setattr("vulnclaw.agent.solver.call_llm_auto", fake_call_llm_auto)

    result = await solve(agent, origin="http://t", goal="find vuln", max_steps=1)

    assert result.completed is False
    assert result.evidence == 1
    assert agent.context.state.agent_state.steps[0].tool_calls == ["fetch"]


@pytest.mark.asyncio
async def test_solve_context_does_not_expose_fixed_step_count(monkeypatch):
    agent = _Agent()
    seen_contexts: list[str] = []
    seen_events: list[tuple[str, dict]] = []

    async def fake_call_llm_auto(agent_arg, system_prompt, round_context, **kwargs):
        seen_contexts.append(round_context)
        return "ASK_USER: need more authorization details"

    monkeypatch.setattr("vulnclaw.agent.solver.call_llm_auto", fake_call_llm_auto)

    await solve(
        agent,
        origin="http://t",
        goal="test target",
        max_steps=80,
        on_event=lambda kind, payload: seen_events.append((kind, payload)),
    )

    assert seen_contexts
    assert "Autonomous turn 1" in seen_contexts[0]
    assert "Step 1/80" not in seen_contexts[0]
    agent_step_events = [payload for kind, payload in seen_events if kind == "agent_step"]
    assert agent_step_events
    assert "max_steps" not in agent_step_events[0]


@pytest.mark.asyncio
async def test_solve_stops_repeated_evidence_only_stall(monkeypatch):
    agent = _Agent()
    calls = {"n": 0}

    async def fake_call_llm_auto(agent_arg, *args, **kwargs):
        calls["n"] += 1
        agent_arg.context.state.agent_state.record_tool_call(
            tool="evidence_view",
            arguments={"evidence_id": "e001", "offset": 0, "limit": 12000},
            summary="reviewed saved evidence",
        )
        return "Reviewing the same saved evidence again."

    monkeypatch.setattr("vulnclaw.agent.solver.call_llm_auto", fake_call_llm_auto)

    result = await solve(agent, origin="http://t", goal="capture flag", max_steps=20)

    assert result.needs_user is True
    assert result.reason == "stalled after repeated evidence-only turns"
    assert calls["n"] == 6
    assert "repeatedly reread saved evidence" in agent.context.state.agent_state.pending_questions[0]


@pytest.mark.asyncio
async def test_solve_rejects_premature_no_path_near_high_signal_evidence(monkeypatch):
    agent = _Agent()
    calls = {"n": 0}
    events: list[tuple[str, dict]] = []

    async def fake_call_llm_auto(agent_arg, *args, **kwargs):
        calls["n"] += 1
        state = agent_arg.context.state.agent_state
        if calls["n"] == 1:
            record = state.remember_tool_result(
                tool="source_extract",
                arguments={"evidence_id": "e001"},
                output=(
                    "L4: $input = $_COOKIE['user'];\n"
                    "L5: $obj = unserialize($input);\n"
                    "L6: eval($obj->code);\n"
                    "# http_probe_batch results\n"
                    "Same-body groups: 1,2\n"
                    "request=GET https://target/?username=a&password=b\n"
                ),
                status=200,
            )
            state.pin_fact("Source sink: cookie-controlled input reaches eval", evidence_id=record.id)
            state.record_progress_signal(
                kind="tool_observation",
                detail="same-body probe with request surface observed",
                tool="http_probe_batch",
                evidence_id=record.id,
            )
            return "I tried one remote payload and saw no visible response.\nNO_PATH: remote same-body payload failed to trigger"
        return "FINAL: Source sink remains exploitable enough to report; evidence e001"

    monkeypatch.setattr("vulnclaw.agent.solver.call_llm_auto", fake_call_llm_auto)

    result = await solve(
        agent,
        origin="https://target/",
        goal="find vulnerability",
        max_steps=3,
        on_event=lambda kind, payload: events.append((kind, payload)),
    )

    assert calls["n"] == 2
    assert result.completed is True
    assert any(kind == "no_path_rejected" for kind, _ in events)
    assert any(
        hint.startswith("Near-miss guard:")
        for hint in agent.context.state.agent_state.correction_hints
    )


@pytest.mark.asyncio
async def test_solve_rejects_premature_ask_user_for_writeup_near_parser_filter(monkeypatch):
    agent = _Agent()
    calls = {"n": 0}
    events: list[tuple[str, dict]] = []

    async def fake_call_llm_auto(agent_arg, *args, **kwargs):
        calls["n"] += 1
        state = agent_arg.context.state.agent_state
        if calls["n"] == 1:
            record = state.remember_tool_result(
                tool="source_extract",
                arguments={"evidence_id": "e001"},
                output=(
                    r"if(!preg_match('/[oc]:\d+:/i', $_COOKIE['user'])){"
                    "\n$user = unserialize($_COOKIE['user']);\n}"
                    "\nclass backDoor{function getInfo(){eval($this->code);}}"
                ),
                status=200,
            )
            state.pin_fact(
                "Parser/filter boundary: PHP serialized input is checked by a regex/string "
                "filter before unserialize; validate parser-accepted lexical variants locally.",
                evidence_id=record.id,
            )
            state.pin_fact("Source sink: cookie-controlled input reaches eval", evidence_id=record.id)
            return "ASK_USER: 是否允许我结合公开题解/外部资料继续？"

        record = state.remember_tool_result(
            tool="http_probe_batch",
            arguments={"requests": [{"url": "/"}]},
            output="Status: 200\nctfshow{runtime-diff-ok}",
            status=200,
        )
        state.record_tool_call(
            tool="http_probe_batch",
            arguments={"requests": [{"url": "/"}]},
            evidence_id=record.id,
            summary=record.summary,
        )
        return f"FINAL: ctfshow{{runtime-diff-ok}} evidence {record.id}"

    monkeypatch.setattr("vulnclaw.agent.solver.call_llm_auto", fake_call_llm_auto)

    result = await solve(
        agent,
        origin="https://target/",
        goal="capture CTF flag",
        max_steps=3,
        on_event=lambda kind, payload: events.append((kind, payload)),
    )

    assert calls["n"] == 2
    assert result.completed is True
    assert any(kind == "ask_user_rejected" for kind, _ in events)
    assert not agent.context.state.agent_state.pending_questions
    assert any(
        hint.startswith("Premature ASK_USER guard:")
        for hint in agent.context.state.agent_state.correction_hints
    )


@pytest.mark.asyncio
async def test_solve_keeps_rejecting_external_writeup_asks_near_parser_filter(monkeypatch):
    agent = _Agent()
    calls = {"n": 0}
    events: list[tuple[str, dict]] = []

    async def fake_call_llm_auto(agent_arg, *args, **kwargs):
        calls["n"] += 1
        state = agent_arg.context.state.agent_state
        if calls["n"] == 1:
            record = state.remember_tool_result(
                tool="source_extract",
                arguments={"evidence_id": "e001"},
                output=(
                    r"if(!preg_match('/[oc]:\d+:/i', $_COOKIE['user'])){"
                    "\n$user = unserialize($_COOKIE['user']);\n}"
                    "\nclass backDoor{function getInfo(){eval($this->code);}}"
                ),
                status=200,
            )
            state.pin_fact(
                "Parser/filter boundary: PHP serialized input is checked by a regex/string "
                "filter before unserialize.",
                evidence_id=record.id,
            )
            return "ASK_USER: Can I use a public writeup or external solution?"
        if calls["n"] == 2:
            return "ASK_USER: Can I search the web for a hint?"

        record = state.remember_tool_result(
            tool="http_probe_batch",
            arguments={"requests": [{"url": "/"}]},
            output="Status: 200\nctfshow{repeated-ask-guard}",
            status=200,
        )
        state.record_tool_call(
            tool="http_probe_batch",
            arguments={"requests": [{"url": "/"}]},
            evidence_id=record.id,
            summary=record.summary,
        )
        return f"FINAL: ctfshow{{repeated-ask-guard}} evidence {record.id}"

    monkeypatch.setattr("vulnclaw.agent.solver.call_llm_auto", fake_call_llm_auto)

    result = await solve(
        agent,
        origin="https://target/",
        goal="capture CTF flag",
        max_steps=4,
        on_event=lambda kind, payload: events.append((kind, payload)),
    )

    assert calls["n"] == 3
    assert result.completed is True
    assert sum(1 for kind, _ in events if kind == "ask_user_rejected") == 2
    assert not agent.context.state.agent_state.pending_questions


@pytest.mark.asyncio
async def test_solve_stops_repeated_tool_less_turns(monkeypatch):
    """Model keeps producing text but no tool calls should trigger the spin guard."""
    agent = _Agent()
    calls = {"n": 0}
    events: list[tuple[str, dict]] = []

    async def fake_call_llm_auto(agent_arg, *args, **kwargs):
        calls["n"] += 1
        return "Let me think about the next step carefully."

    monkeypatch.setattr("vulnclaw.agent.solver.call_llm_auto", fake_call_llm_auto)

    result = await solve(
        agent,
        origin="http://t",
        goal="capture flag",
        max_steps=20,
        on_event=lambda kind, payload: events.append((kind, payload)),
    )

    assert result.needs_user is True
    assert result.completed is False
    assert result.reason == "stopped after repeated turns without tool calls"
    assert calls["n"] == 3
    assert any(kind == "ask_user" for kind, _ in events)
    assert any(kind == "agent_observation" for kind, _ in events)
    assert "stopped issuing tool calls" in agent.context.state.agent_state.pending_questions[0]


@pytest.mark.asyncio
async def test_solve_spin_guard_surfaces_last_reply_and_hints_model(monkeypatch):
    """The spin guard must show the model's own last reply in the event and
    inject a correction hint from the second tool-less turn onward."""
    agent = _Agent()
    calls = {"n": 0}
    events: list[tuple[str, dict]] = []
    replies = ["thinking about payload choice", "still reasoning quietly", "nearly decided"]

    async def fake_call_llm_auto(agent_arg, *args, **kwargs):
        calls["n"] += 1
        return replies[calls["n"] - 1]

    monkeypatch.setattr("vulnclaw.agent.solver.call_llm_auto", fake_call_llm_auto)

    result = await solve(
        agent,
        origin="http://t",
        goal="capture flag",
        max_steps=20,
        on_event=lambda kind, payload: events.append((kind, payload)),
    )

    assert result.reason == "stopped after repeated turns without tool calls"
    ask_events = [payload for kind, payload in events if kind == "ask_user"]
    assert ask_events
    assert ask_events[0]["last_reply"] == "nearly decided"
    assert ask_events[0]["consecutive_no_tool_turns"] == 3
    hints = agent.context.state.agent_state.correction_hints
    assert any("consecutive turns produced no tool call" in hint for hint in hints)
    assert any("still reasoning quietly" in hint for hint in hints)


@pytest.mark.asyncio
async def test_solve_spin_guard_handles_empty_model_reply(monkeypatch):
    """A mock endpoint that returns empty completions should still trip the
    guard with an explicit '(empty)' marker instead of a blank question."""
    agent = _Agent()
    events: list[tuple[str, dict]] = []

    async def fake_call_llm_auto(agent_arg, *args, **kwargs):
        return ""

    monkeypatch.setattr("vulnclaw.agent.solver.call_llm_auto", fake_call_llm_auto)

    result = await solve(
        agent,
        origin="http://t",
        goal="capture flag",
        max_steps=20,
        on_event=lambda kind, payload: events.append((kind, payload)),
    )

    assert result.needs_user is True
    assert "(empty)" in agent.context.state.agent_state.pending_questions[0]
    ask_events = [payload for kind, payload in events if kind == "ask_user"]
    assert ask_events and ask_events[0]["last_reply"] == "(empty)"
