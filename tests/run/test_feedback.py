from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from vulnclaw.agent.context import SessionState
from vulnclaw.feedback import FeedbackError, feedback_for_distillation, load_feedback, save_feedback
from vulnclaw.run_context import create_run_context, mark_run_status
from vulnclaw.target_state.store import save_target_state
from vulnclaw.targets import parse_target


def test_feedback_is_replaced_in_place_and_keeps_its_original_creation_time(tmp_path):
    run_dir = tmp_path / "completed-run"
    run_dir.mkdir()

    first = save_feedback(run_dir, rating=2, notes="missed the relevant endpoint")
    second = save_feedback(run_dir, rating=5, notes="the revised approach was correct")

    assert first.created_at == second.created_at
    assert second.rating == 5
    assert second.notes == "the revised approach was correct"
    assert len(list(run_dir.glob("feedback*.json"))) == 1
    assert json.loads((run_dir / "feedback.json").read_text(encoding="utf-8"))["rating"] == 5
    assert feedback_for_distillation(run_dir) == {
        "rating": 5,
        "notes": "the revised approach was correct",
    }


@pytest.mark.parametrize("rating", [0, 6])
def test_feedback_rejects_out_of_range_ratings(tmp_path, rating):
    run_dir = tmp_path / "completed-run"
    run_dir.mkdir()

    with pytest.raises(FeedbackError):
        save_feedback(run_dir, rating=rating, notes="operator assessment")


def test_invalid_feedback_is_ignored_for_optional_distillation_signal(tmp_path):
    run_dir = tmp_path / "completed-run"
    run_dir.mkdir()
    (run_dir / "feedback.json").write_text("{not json", encoding="utf-8")

    assert load_feedback(run_dir) is None
    assert feedback_for_distillation(run_dir) is None


def test_feedback_command_persists_and_updates_completed_run(runner, monkeypatch, tmp_path):
    from vulnclaw.cli.main import app

    target = parse_target("https://example.com")
    context = create_run_context(
        command="run", targets=[target], runs_dir=tmp_path, run_name="completed-run"
    )
    session = SessionState(target=target.raw)
    save_target_state(
        target.raw,
        session,
        command="run",
        run_context=context,
        target_model=target,
        checkpoint_reason="test",
    )
    mark_run_status(context, "completed")
    first = runner.invoke(
        app,
        [
            "feedback",
            "completed-run",
            "--rating",
            "2",
            "--notes",
            "needs better coverage",
            "--runs-dir",
            str(tmp_path),
        ],
    )
    updated = runner.invoke(
        app,
        [
            "feedback",
            "completed-run",
            "--rating",
            "4",
            "--notes",
            "follow-up fixed it",
            "--runs-dir",
            str(tmp_path),
        ],
    )

    assert first.exit_code == 0, first.output
    assert updated.exit_code == 0, updated.output
    assert feedback_for_distillation(context.run_dir) == {
        "rating": 4,
        "notes": "follow-up fixed it",
    }


@pytest.fixture
def runner():
    return CliRunner()
