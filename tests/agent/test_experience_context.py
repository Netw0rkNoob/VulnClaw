"""Regression tests for approved cross-session experience injection."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from vulnclaw.agent.experience_context import build_experience_context
from vulnclaw.agent.system_prompt import build_dynamic_system_prompt
from vulnclaw.i18n import current_lang, init_i18n
from vulnclaw.kb.experience import ExperienceStore, Lesson
from vulnclaw.targets import parse_target


def _lesson(lesson_id: str, *, service: str = "nginx", vuln_type: str = "sqli", **overrides):
    values = {
        "id": lesson_id,
        "scope": "technique",
        "signal": "success",
        "tags": {
            "tech": ["php"],
            "vuln_type": vuln_type,
            "waf": "",
            "service": service,
        },
        "context": f"{service} {vuln_type} validation",
        "lesson": f"Use the approved {lesson_id} workflow.",
        "evidence_refs": {"run_id": "run-1"},
        "confidence": 0.8,
        "source_runs": ["run-1"],
    }
    values.update(overrides)
    return Lesson(**values)


def _target_context():
    return SimpleNamespace(
        target="demo.example",
        recon_data={"services": ["nginx/1.24"], "technologies": ["php"]},
        findings=[SimpleNamespace(vuln_type="sqli")],
    )


def test_experience_context_injects_only_matching_approved_lessons(tmp_path):
    store = ExperienceStore(store_dir=tmp_path)
    approved = store.add(_lesson("approved-match"))
    store.approve(approved.id)
    store.add(_lesson("pending-match"))
    rejected = store.add(_lesson("rejected-match"))
    store.reject(rejected.id)
    approved_other_target = store.add(
        _lesson(
            "approved-other",
            service="smtp",
            vuln_type="xss",
            tags={"tech": ["java"], "vuln_type": "xss", "waf": "", "service": "smtp"},
        )
    )
    store.approve(approved_other_target.id)

    context = build_experience_context(_target_context(), store)

    assert context.startswith("## Prior Experience / Lessons")
    assert "approved-match" in context
    assert "pending-match" not in context
    assert "rejected-match" not in context
    assert "approved-other" not in context


def test_experience_ranking_favors_tag_overlap_and_relevance(tmp_path):
    store = ExperienceStore(store_dir=tmp_path)
    sqli = store.add(_lesson("nginx-sqli", lesson="Validate nginx SQL injection with a parameterized probe."))
    xss = store.add(
        _lesson("nginx-xss", vuln_type="xss", lesson="Review nginx pages for reflected XSS.")
    )
    store.approve(sqli.id)
    store.approve(xss.id)

    context = build_experience_context(_target_context(), store)

    assert context.index("SQL injection") < context.index("reflected XSS")


def test_experience_ranking_applies_confidence_decay(tmp_path):
    store = ExperienceStore(store_dir=tmp_path, confidence_half_life_days=10)
    stale = _lesson(
        "stale",
        lesson="Use the stale procedure.",
        reinforced_at=datetime.now(timezone.utc) - timedelta(days=30),
    )
    fresh = _lesson("fresh", lesson="Use the fresh procedure.")
    store.add(stale)
    store.add(fresh)
    store.approve(stale.id)
    store.approve(fresh.id)

    context = build_experience_context(_target_context(), store)

    assert context.index("fresh procedure") < context.index("stale procedure")


def test_experience_ranking_uses_an_injected_reference_time(tmp_path):
    store = ExperienceStore(store_dir=tmp_path, confidence_half_life_days=10)
    reference = datetime(2026, 1, 31, tzinfo=timezone.utc)
    older = _lesson(
        "older",
        lesson="Use the older procedure.",
        confidence=0.9,
        reinforced_at=reference - timedelta(days=40),
    )
    newer = _lesson(
        "newer",
        lesson="Use the newer procedure.",
        confidence=0.5,
        reinforced_at=reference - timedelta(days=1),
    )
    for lesson in (older, newer):
        store.add(lesson)
        store.approve(lesson.id)

    # At the reference time the older lesson has decayed below the newer one.
    at_reference = build_experience_context(_target_context(), store, now=reference)
    assert at_reference.index("newer procedure") < at_reference.index("older procedure")

    # Evaluated when both were fresh, raw confidence decides the order instead.
    when_fresh = build_experience_context(
        _target_context(), store, now=reference - timedelta(days=40)
    )
    assert when_fresh.index("older procedure") < when_fresh.index("newer procedure")


def test_experience_ranking_treats_a_naive_reference_time_as_utc(tmp_path):
    store = ExperienceStore(store_dir=tmp_path, confidence_half_life_days=10)
    reference = datetime(2026, 1, 31, tzinfo=timezone.utc)
    lesson = store.add(
        _lesson(
            "naive-reference",
            reinforced_at=reference - timedelta(days=1),
        )
    )
    store.approve(lesson.id)

    context = build_experience_context(
        _target_context(), store, now=reference.replace(tzinfo=None)
    )

    assert "naive-reference" in context


def test_reinforcing_a_stale_lesson_restores_its_ranking(tmp_path):
    store = ExperienceStore(store_dir=tmp_path, confidence_half_life_days=10)
    stale = _lesson(
        "stale",
        lesson="Use the stale procedure.",
        reinforced_at=datetime.now(timezone.utc) - timedelta(days=40),
    )
    fresh = _lesson("fresh", lesson="Use the fresh procedure.", confidence=0.4)
    for lesson in (stale, fresh):
        store.add(lesson)
        store.approve(lesson.id)

    before = build_experience_context(_target_context(), store)
    assert before.index("fresh procedure") < before.index("stale procedure")

    reinforced = store.merge(
        stale.id,
        _lesson("reinforcing", confidence=0.5, evidence_refs={"run_id": "run-2"}),
    )
    assert reinforced is not None
    store.approve(stale.id)

    after = build_experience_context(_target_context(), store)
    assert after.index("stale procedure") < after.index("fresh procedure")


def test_experience_context_is_not_suppressed_for_english_runs(tmp_path):
    store = ExperienceStore(store_dir=tmp_path)
    lesson = store.add(_lesson("english-approved"))
    store.approve(lesson.id)

    previous_lang = current_lang()
    init_i18n(lang="en")
    try:
        experience_context = build_experience_context(_target_context(), store)
        prompt = build_dynamic_system_prompt(
            target="demo.example",
            phase=None,
            skill_context=None,
            mcp_tools=[],
            enable_personnel_dim=False,
            auto_mode=False,
            user_input="test SQL injection",
            kb_context="",
            experience_context=experience_context,
        )
    finally:
        init_i18n(lang=previous_lang)

    assert "## Prior Experience / Lessons" in experience_context
    assert "english-approved" in prompt


def test_experience_retrieval_failure_degrades_to_an_empty_block():
    class _BrokenStore:
        def list_by_status(self, status):
            raise OSError("store unavailable")

    assert build_experience_context(_target_context(), _BrokenStore()) == ""


def test_target_scoped_lesson_matches_the_persisted_target_identifier(tmp_path):
    store = ExperienceStore(store_dir=tmp_path)
    target_lesson = store.add(
        _lesson(
            "target-only",
            scope="target",
            target_key=parse_target("demo.example").target_id,
            tags={"tech": [], "vuln_type": "", "waf": "", "service": ""},
        )
    )
    store.approve(target_lesson.id)

    context = build_experience_context(
        SimpleNamespace(target="demo.example", recon_data={}, findings=[]), store
    )

    assert "target-only" in context

def test_create_approve_injects_via_agent_core_production_path(tmp_path):
    """Regression: store write → approve → AgentCore prompt builder injection."""
    from vulnclaw.agent.core import AgentCore
    from vulnclaw.config.schema import VulnClawConfig

    store = ExperienceStore(store_dir=tmp_path)
    pending = store.add(
        _lesson(
            "core-path-lesson",
            lesson="Favor parameter-stable probes on matching stacks.",
        )
    )
    store.approve(pending.id)

    config = VulnClawConfig()
    config.session.output_dir = tmp_path / "session-out"
    agent = AgentCore(config)
    agent._experience_store = store
    agent.context.state.target = "demo.example"
    agent.context.state.recon_data = {
        "services": ["nginx/1.24"],
        "technologies": ["php"],
    }
    agent.context.state.findings = [SimpleNamespace(vuln_type="sqli")]

    prompt = agent._build_system_prompt(user_input="sqli", target="demo.example")

    assert "## Prior Experience / Lessons" in prompt
    assert "Favor parameter-stable probes" in prompt

