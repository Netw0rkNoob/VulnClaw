from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from vulnclaw.agent.distiller import (
    _LESSON_SCHEMA,
    DEFAULT_MERGE_THRESHOLD,
    MERGE_THRESHOLD_ENV,
    RunArtifacts,
    default_merge_threshold,
    distill_run,
    persist_distilled_lessons,
    schedule_run_distillation,
)
from vulnclaw.agent.reasoning_state import AttackPath, PathStatus, ReasoningState
from vulnclaw.kb.experience import ExperienceStore, LessonStatus


def _artifacts(run_id: str = "run-1") -> RunArtifacts:
    return RunArtifacts(
        run_id=run_id,
        target_key="target-123",
        language="en",
        verified_findings=[{"finding_id": "finding-1", "vuln_type": "sqli"}],
        reflexion_snapshot={"failed_paths": ["sqli-union"]},
        reasoning_paths=[{"path": "sqli-union", "status": "failed"}],
        step_summary=[{"action": "probe", "status": "success"}],
    )


def _candidate(payload: dict) -> dict:
    assert payload["run_id"]
    return {
        "lessons": [
            {
                "scope": "technique",
                "signal": "success",
                "tags": {"tech": ["mysql"], "vuln_type": "sqli"},
                "context": "A MySQL error-based SQL injection is verified.",
                "lesson": "Validate the error condition before escalating extraction.",
                "confidence": 0.7,
                "evidence_refs": {"finding_id": "finding-1"},
            },
            {
                "scope": "technique",
                "signal": "success",
                "tags": {},
                "context": "unverified assertion",
                "lesson": "This must never be persisted.",
                "evidence_refs": {},
            },
        ]
    }


def _near_duplicate(payload: dict) -> dict:
    """A candidate that restates the same tactic with partly different wording."""
    assert payload["run_id"]
    return {
        "lessons": [
            {
                "scope": "technique",
                "signal": "success",
                "tags": {"tech": ["mysql"], "vuln_type": "sqli"},
                "context": "A MySQL error-based SQL injection is confirmed.",
                "lesson": "Validate the error condition before extracting table rows.",
                "confidence": 0.7,
                "evidence_refs": {"finding_id": "finding-1"},
            }
        ]
    }


def test_distill_run_accepts_only_candidates_with_recorded_provenance():
    lessons = distill_run(_artifacts(), _candidate)

    assert len(lessons) == 1
    assert lessons[0].status is LessonStatus.PENDING
    assert lessons[0].evidence_refs.run_id == "run-1"
    assert lessons[0].evidence_refs.finding_id == "finding-1"
    assert lessons[0].id.startswith("lesson-")


def test_distill_run_accepts_a_recorded_failed_path_as_provenance():
    lessons = distill_run(
        _artifacts(),
        lambda _payload: {
            "lessons": [
                {
                    "scope": "target",
                    "signal": "deadend",
                    "tags": {"waf": "example-waf"},
                    "context": "The target blocks the UNION probe.",
                    "lesson": "Switch attack surfaces after this WAF block.",
                    "evidence_refs": {"path": "sqli-union"},
                }
            ]
        },
    )

    assert len(lessons) == 1
    assert lessons[0].target_key == "target-123"
    assert lessons[0].evidence_refs.path == "sqli-union"


def test_distill_run_accepts_a_failed_structured_reasoning_path_as_provenance():
    session = SimpleNamespace(
        findings=[],
        step_records=[],
        reasoning=ReasoningState(
            paths=[AttackPath(name="blocked-login-sqli", status=PathStatus.FAILED)]
        ),
        reflexion_snapshot={},
    )
    artifacts = RunArtifacts.from_session("run-1", session, target_key="target-123")

    lessons = distill_run(
        artifacts,
        lambda _payload: {
            "lessons": [
                {
                    "scope": "target",
                    "signal": "deadend",
                    "tags": {"waf": "example-waf"},
                    "context": "The login SQL injection path was blocked.",
                    "lesson": "Use a different attack surface after the block.",
                    "confidence": 0.6,
                    "evidence_refs": {"path": "blocked-login-sqli"},
                }
            ]
        },
    )

    assert artifacts.failed_paths() == {"blocked-login-sqli"}
    assert len(lessons) == 1
    assert lessons[0].evidence_refs.path == "blocked-login-sqli"


def test_persist_distilled_lessons_merges_near_duplicates(tmp_path: Path):
    store = ExperienceStore(tmp_path)
    first = persist_distilled_lessons(_artifacts("run-1"), _candidate, store, merge_threshold=0.6)
    second = persist_distilled_lessons(_artifacts("run-2"), _candidate, store, merge_threshold=0.6)

    assert len(first) == len(second) == 1
    pending = store.list_by_status("pending")
    assert len(pending) == 1
    assert pending[0].source_runs == ["run-1", "run-2"]
    assert pending[0].confidence > 0.7


def _near_duplicate_similarity() -> float:
    original = distill_run(_artifacts("run-1"), _candidate)[0]
    variant = distill_run(_artifacts("run-2"), _near_duplicate)[0]
    return ExperienceStore._similarity(
        ExperienceStore._terms(original), ExperienceStore._terms(variant)
    )


def _persist_pair(store: ExperienceStore, threshold: float) -> list:
    persist_distilled_lessons(_artifacts("run-1"), _candidate, store, merge_threshold=threshold)
    return persist_distilled_lessons(
        _artifacts("run-2"), _near_duplicate, store, merge_threshold=threshold
    )


def test_merge_threshold_boundary_decides_whether_near_duplicates_merge(tmp_path: Path):
    score = _near_duplicate_similarity()
    assert 0.0 < score < 1.0

    below = ExperienceStore(tmp_path / "below")
    merged = _persist_pair(below, score - 0.01)

    assert len(below.list_by_status("pending")) == 1
    assert merged[0].source_runs == ["run-1", "run-2"]

    above = ExperienceStore(tmp_path / "above")
    separate = _persist_pair(above, score + 0.01)

    assert len(above.list_by_status("pending")) == 2
    assert separate[0].source_runs == ["run-2"]


def test_merge_threshold_exactly_at_the_similarity_score_merges(tmp_path: Path):
    store = ExperienceStore(tmp_path)

    merged = _persist_pair(store, _near_duplicate_similarity())

    assert len(store.list_by_status("pending")) == 1
    assert merged[0].source_runs == ["run-1", "run-2"]


def test_default_merge_threshold_is_environment_configurable(monkeypatch):
    monkeypatch.setenv(MERGE_THRESHOLD_ENV, "0.42")
    assert default_merge_threshold() == 0.42

    for invalid in ("not-a-number", "1.5", "-0.1", "   "):
        monkeypatch.setenv(MERGE_THRESHOLD_ENV, invalid)
        assert default_merge_threshold() == DEFAULT_MERGE_THRESHOLD

    monkeypatch.delenv(MERGE_THRESHOLD_ENV)
    assert default_merge_threshold() == DEFAULT_MERGE_THRESHOLD


def test_persist_uses_the_configured_default_when_no_threshold_is_passed(tmp_path: Path, monkeypatch):
    monkeypatch.setenv(MERGE_THRESHOLD_ENV, "0.05")
    store = ExperienceStore(tmp_path)

    persist_distilled_lessons(_artifacts("run-1"), _candidate, store)
    merged = persist_distilled_lessons(_artifacts("run-2"), _near_duplicate, store)

    assert len(store.list_by_status("pending")) == 1
    assert merged[0].source_runs == ["run-1", "run-2"]


def test_background_distillation_logs_and_swallows_errors(tmp_path: Path):
    class RunContext:
        def __init__(self) -> None:
            self.events: list[tuple[str, dict]] = []
            self.status = "completed"

        def append_event(self, kind: str, payload: dict) -> None:
            self.events.append((kind, payload))

    context = RunContext()
    thread = schedule_run_distillation(
        artifacts=_artifacts(),
        llm=lambda _payload: (_ for _ in ()).throw(RuntimeError("unavailable")),
        store=ExperienceStore(tmp_path),
        run_context=context,
    )
    thread.join(timeout=2)

    assert not thread.is_alive()
    assert thread.daemon is False
    assert context.status == "completed"
    assert context.events == [("distillation_failed", {"error": "RuntimeError"})]


def test_learn_command_distills_an_existing_run_into_pending_lessons(tmp_path: Path, monkeypatch):
    """`vulnclaw learn <run>` reconstructs a finished run and writes pending lessons."""

    from typer.testing import CliRunner

    import vulnclaw.agent.distiller as distiller_module
    import vulnclaw.cli.main as cli_main
    import vulnclaw.kb.experience as experience_module
    from vulnclaw.agent.context import SessionState
    from vulnclaw.run_context import create_run_context
    from vulnclaw.targets import build_targets

    run_context = create_run_context(
        command="run",
        targets=build_targets("https://example.com"),
        runs_dir=tmp_path,
        run_name="learn-run",
    )
    state_path = run_context.state_path()
    state_path.parent.mkdir(parents=True, exist_ok=True)
    session = SessionState(
        target="https://example.com",
        findings=[
            {"title": "SQLi", "finding_id": "finding-1", "verified": True, "vuln_type": "sqli"}
        ],
    )
    state_path.write_text(session.model_dump_json(), encoding="utf-8")

    store = ExperienceStore(tmp_path / "kb")

    def _llm(payload: dict) -> dict:
        assert payload["run_id"] == "learn-run"
        return {
            "lessons": [
                {
                    "scope": "technique",
                    "signal": "success",
                    "tags": {"tech": ["mysql"], "vuln_type": "sqli"},
                    "context": "A verified MySQL SQL injection.",
                    "lesson": "Validate the error condition before extraction.",
                    "confidence": 0.7,
                    "evidence_refs": {"finding_id": "finding-1"},
                }
            ]
        }

    monkeypatch.setattr(cli_main, "has_llm_credentials", lambda _config: True)
    monkeypatch.setattr(distiller_module, "configured_distiller", lambda _config: _llm)
    monkeypatch.setattr(experience_module, "ExperienceStore", lambda *args, **kwargs: store)

    result = CliRunner().invoke(cli_main.app, ["learn", "learn-run", "--runs-dir", str(tmp_path)])

    assert result.exit_code == 0, result.output
    pending = store.list_by_status(LessonStatus.PENDING)
    assert len(pending) == 1
    assert pending[0].status is LessonStatus.PENDING
    assert pending[0].evidence_refs.finding_id == "finding-1"


def test_openai_strict_schema_requires_every_object_property():
    candidate = _LESSON_SCHEMA["properties"]["lessons"]["items"]

    assert set(candidate["properties"]) == set(candidate["required"])
    assert set(candidate["properties"]["tags"]["properties"]) == set(
        candidate["properties"]["tags"]["required"]
    )
    assert set(candidate["properties"]["evidence_refs"]["properties"]) == set(
        candidate["properties"]["evidence_refs"]["required"]
    )
