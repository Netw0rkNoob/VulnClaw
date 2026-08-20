"""CLI coverage for the human experience-review gate."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from vulnclaw.cli.main import app
from vulnclaw.kb.experience import (
    EvidenceRefs,
    ExperienceStore,
    Lesson,
    LessonScope,
    LessonSignal,
    LessonStatus,
    LessonTags,
)


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def experience_store(monkeypatch, tmp_path) -> ExperienceStore:
    import vulnclaw.kb.experience as experience_module

    monkeypatch.setattr(experience_module, "KB_DIR", tmp_path)
    return ExperienceStore()


def _lesson(lesson_id: str, *, status: LessonStatus = LessonStatus.PENDING) -> Lesson:
    return Lesson(
        id=lesson_id,
        scope=LessonScope.TECHNIQUE,
        status=status,
        signal=LessonSignal.SUCCESS,
        tags=LessonTags(tech=["http"], vuln_type="xss", service="nginx"),
        context="Nginx application reflects a query parameter",
        lesson="Confirm reflection before attempting a context-appropriate payload.",
        evidence_refs=EvidenceRefs(run_id="run-123", finding_id="finding-456", path="/search?q=x"),
        confidence=0.8,
        source_runs=["run-123"],
    )


def test_experience_list_shows_only_pending_lessons(runner, experience_store):
    experience_store.add(_lesson("pending-one"))
    approved = experience_store.add(_lesson("approved-one"))
    experience_store.approve(approved.id)

    result = runner.invoke(app, ["experience", "list"])

    assert result.exit_code == 0
    assert "pending-one" in result.output
    assert "approved-one" not in result.output


def test_experience_review_alias_lists_pending_lessons(runner, experience_store):
    experience_store.add(_lesson("pending-one"))

    result = runner.invoke(app, ["experience", "review"])

    assert result.exit_code == 0
    assert "pending-one" in result.output


def test_experience_show_includes_provenance(runner, experience_store):
    experience_store.add(_lesson("detail-one"))

    result = runner.invoke(app, ["experience", "show", "detail-one"])

    assert result.exit_code == 0
    assert "run-123" in result.output
    assert "finding-456" in result.output
    assert "/search?q=x" in result.output
    assert "Confirm reflection" in result.output


@pytest.mark.parametrize(("command", "expected"), [("approve", LessonStatus.APPROVED), ("reject", LessonStatus.REJECTED)])
def test_experience_review_decisions_are_durable(runner, experience_store, command, expected):
    experience_store.add(_lesson("review-one"))

    result = runner.invoke(app, ["experience", command, "review-one"])

    assert result.exit_code == 0
    assert experience_store.get("review-one").status is expected
    reloaded = ExperienceStore(store_dir=experience_store.store_dir)
    assert reloaded.get("review-one").status is expected


def test_experience_edit_persists_amended_text(runner, experience_store):
    experience_store.add(_lesson("edit-one"))

    result = runner.invoke(
        app,
        [
            "experience",
            "edit",
            "edit-one",
            "--context",
            "Updated matching condition",
            "--lesson",
            "Updated operator guidance",
        ],
    )

    assert result.exit_code == 0
    edited = experience_store.get("edit-one")
    assert edited.context == "Updated matching condition"
    assert edited.lesson == "Updated operator guidance"
    assert edited.status is LessonStatus.PENDING
    assert edited.evidence_refs.run_id == "run-123"


@pytest.mark.parametrize("command", ["show", "approve", "reject", "edit"])
def test_experience_unknown_id_fails_cleanly(runner, experience_store, command):
    args = ["experience", command, "missing-id"]
    if command == "edit":
        args.extend(["--lesson", "Replacement text"])

    result = runner.invoke(app, args)

    assert result.exit_code == 1
    assert "Lesson not found: missing-id" in result.output
