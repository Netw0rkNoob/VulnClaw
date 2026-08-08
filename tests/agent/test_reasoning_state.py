from vulnclaw.agent.reasoning_state import (
    ConstraintCategory,
    ConstraintSeverity,
    PathStatus,
    PathStep,
    ReasoningState,
    StepStatus,
)


def test_add_fact_same_value_increases_confidence_and_merges_sources():
    state = ReasoningState()

    fact = state.add_fact("framework", "thinkphp", source="fingerprint", confidence=0.5)
    updated = state.add_fact("framework", "thinkphp", source="error_page", confidence=0.5)

    assert fact is updated
    assert len(state.facts) == 1
    assert updated.confidence > 0.5
    assert updated.source == "fingerprint, error_page"


def test_add_fact_conflict_lowers_old_value_and_adds_new_fact():
    state = ReasoningState()

    old = state.add_fact("db", "mysql", source="banner", confidence=0.8)
    new = state.add_fact("db", "postgresql", source="error", confidence=0.6)

    assert len(state.facts) == 2
    assert old.confidence < 0.8
    assert new.value == "postgresql"
    assert new.confidence == 0.6


def test_constraints_and_blocking_filter():
    state = ReasoningState()

    state.add_constraint(
        "union keyword blocked",
        category=ConstraintCategory.WAF,
        severity=ConstraintSeverity.BLOCKING,
    )
    state.add_constraint(
        "login required",
        category="auth",
        severity="high",
    )

    blocking = state.get_blocking_constraints()

    assert len(blocking) == 1
    assert blocking[0].description == "union keyword blocked"
    assert blocking[0].category == ConstraintCategory.WAF


def test_add_set_update_and_abandon_path():
    state = ReasoningState()
    state.add_path(
        "sql injection",
        [
            PathStep(action="find parameter", target="/search"),
            PathStep(action="test boolean payload", vuln_type="sqli"),
        ],
        priority=5,
    )
    state.add_path("ssti", [PathStep(action="test template marker")], priority=3)

    active = state.set_active_path("sql injection")
    step = state.update_step("sql injection", 0, StepStatus.SUCCESS, "q parameter found")
    failed_path = state.update_path("ssti", status=PathStatus.FAILED, result="no reflection")
    abandoned = state.abandon_path("sql injection", reason="waf blocks all payloads")

    assert active.status == PathStatus.ABANDONED
    assert step.status == StepStatus.SUCCESS
    assert step.result == "q parameter found"
    assert failed_path.status == PathStatus.FAILED
    assert abandoned.result == "waf blocks all payloads"
    assert state.active_path_index == -1


def test_auto_prioritize_sorts_paths_and_preserves_active_path():
    state = ReasoningState()
    state.add_path("low success", [PathStep(action="a")], priority=10)
    state.add_path("high success", [PathStep(action="b")], priority=10)
    state.set_active_path("low success")

    state.auto_prioritize({"high success": 0.9, "low success": 0.1})

    assert [path.name for path in state.paths] == ["high success", "low success"]
    assert state.paths[state.active_path_index].name == "low success"
    assert state.paths[0].priority > state.paths[1].priority


def test_to_prompt_block_empty_state_returns_empty_string():
    assert ReasoningState().to_prompt_block() == ""


def test_prompt_block_and_summary_include_state():
    from vulnclaw.i18n import init_i18n

    init_i18n(lang="zh")  # prompt-block headings are localized; pin Chinese
    state = ReasoningState()
    state.add_fact("server", "nginx", confidence=0.9)
    state.add_constraint("403 on admin", category="auth", severity="blocking")
    state.add_path("auth bypass", [PathStep(action="compare users")], priority=4)
    state.set_active_path("auth bypass")

    prompt = state.to_prompt_block()
    summary = state.get_summary()

    assert "🧭 当前推理状态" in prompt
    assert "server=nginx" in prompt
    assert "[auth/blocking] 403 on admin" in prompt
    assert "[active] auth bypass" in prompt
    assert summary["facts"] == 1
    assert summary["blocking_constraints"] == 1
    assert summary["active_path"] == "auth bypass"


def test_model_dump_and_validate_roundtrip():
    state = ReasoningState()
    state.add_fact("port", "443", source="nmap", confidence=0.7)
    state.add_constraint("rate limited", category="rate_limit", severity="medium")
    state.add_path("tls checks", [PathStep(action="inspect certificate")], priority=2)

    loaded = ReasoningState.model_validate(state.model_dump(mode="json"))

    assert loaded == state
    assert loaded.facts[0].key == "port"
    assert loaded.constraints[0].category == ConstraintCategory.RATE_LIMIT
    assert loaded.paths[0].steps[0].action == "inspect certificate"
