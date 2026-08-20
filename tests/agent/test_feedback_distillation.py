from __future__ import annotations

from vulnclaw.agent.distiller import RunArtifacts, distill_run


def _candidate() -> dict:
    return {
        "lessons": [
            {
                "scope": "technique",
                "signal": "success",
                "tags": {"tech": ["http"]},
                "context": "authorized web target",
                "lesson": "Validate the endpoint before escalating.",
                "confidence": 0.8,
                "evidence_refs": {"finding_id": "finding-1"},
            }
        ]
    }


def test_distiller_receives_operator_feedback_as_an_additional_signal():
    seen: list[dict] = []
    artifacts = RunArtifacts(
        run_id="run-1",
        verified_findings=[{"id": "finding-1"}],
        operator_feedback={"rating": 1, "notes": "The tactic was a false positive."},
    )

    lessons = distill_run(artifacts, lambda payload: seen.append(payload) or _candidate())

    assert len(lessons) == 1
    assert seen[0]["operator_feedback"] == {
        "rating": 1,
        "notes": "The tactic was a false positive.",
    }


def test_distiller_payload_is_unchanged_when_no_feedback_is_attached():
    seen: list[dict] = []
    artifacts = RunArtifacts(run_id="run-1", verified_findings=[{"id": "finding-1"}])

    distill_run(artifacts, lambda payload: seen.append(payload) or _candidate())

    assert "operator_feedback" not in seen[0]
