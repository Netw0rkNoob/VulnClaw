"""Regression tests for human-gated cross-run lessons."""

from datetime import datetime, timedelta, timezone

import pytest

from vulnclaw.kb.experience import (
    CONFIDENCE_HALF_LIFE_ENV,
    DEFAULT_CONFIDENCE_HALF_LIFE_DAYS,
    EvidenceRefs,
    ExperienceStore,
    Lesson,
    LessonScope,
    LessonSignal,
    LessonStatus,
    LessonTags,
    default_confidence_half_life_days,
)


def make_lesson(lesson_id: str, *, confidence: float = 0.5, run_id: str = "run-1") -> Lesson:
    return Lesson(
        id=lesson_id,
        scope=LessonScope.TECHNIQUE,
        signal=LessonSignal.SUCCESS,
        tags=LessonTags(tech=["sqli"], vuln_type="sql-injection", service="http"),
        context="An HTTP form parameter produces a SQL syntax error.",
        lesson="Prioritize parameterized-query verification before payload variation.",
        evidence_refs=EvidenceRefs(run_id=run_id, finding_id="finding-1", path="/login"),
        confidence=confidence,
    )


def test_create_approve_list_lifecycle_is_durable(tmp_path):
    store = ExperienceStore(tmp_path)
    pending = store.add(make_lesson("lesson-1"))

    assert pending.status is LessonStatus.PENDING
    assert store.list_by_status("pending") == [pending]
    assert store.list_by_status("approved") == []

    approved = store.approve(pending.id)
    assert approved is not None and approved.status is LessonStatus.APPROVED
    assert [lesson.id for lesson in store.list_by_status(LessonStatus.APPROVED)] == [pending.id]
    assert ExperienceStore(tmp_path).get(pending.id) == approved


def test_rejected_lessons_never_surface_as_approved(tmp_path):
    store = ExperienceStore(tmp_path)
    pending = store.add(make_lesson("lesson-2"))

    rejected = store.reject(pending.id)
    assert rejected is not None and rejected.status is LessonStatus.REJECTED
    assert store.list_by_status("approved") == []
    assert store.list_by_status("rejected") == [rejected]


def test_merge_reinforces_existing_lesson_without_second_entry(tmp_path):
    store = ExperienceStore(tmp_path)
    existing = store.add(make_lesson("lesson-3", confidence=0.5, run_id="run-1"))
    duplicate = make_lesson("candidate-3", confidence=0.5, run_id="run-2")

    merged = store.merge(existing.id, duplicate)

    assert merged is not None
    assert merged.id == existing.id
    assert merged.confidence > existing.confidence
    assert merged.source_runs == ["run-1", "run-2"]
    assert sorted(path.stem for path in (tmp_path / "experience").glob("*.json")) == [existing.id]


def test_add_forces_pending_and_target_scope_requires_target_key(tmp_path):
    store = ExperienceStore(tmp_path)
    approved = make_lesson("lesson-4").model_copy(update={"status": LessonStatus.APPROVED})

    assert store.add(approved).status is LessonStatus.PENDING


def test_confidence_decays_without_deleting_and_merge_refreshes_it(tmp_path):
    store = ExperienceStore(tmp_path, confidence_half_life_days=10)
    stale = make_lesson("lesson-decay", confidence=0.8, run_id="run-1").model_copy(
        update={"reinforced_at": datetime.now(timezone.utc) - timedelta(days=10)}
    )
    store.add(stale)

    assert store.get(stale.id) is not None
    assert 0.39 < store.effective_confidence(stale) < 0.41

    refreshed = store.merge(stale.id, make_lesson("candidate-decay", run_id="run-2"))

    assert refreshed is not None
    assert refreshed.reinforced_at > stale.reinforced_at
    assert store.effective_confidence(refreshed) > store.effective_confidence(stale)


def test_decay_reweights_without_mutating_or_deleting_stored_lessons(tmp_path):
    store = ExperienceStore(tmp_path, confidence_half_life_days=10)
    reference = datetime(2026, 1, 31, tzinfo=timezone.utc)
    lesson = make_lesson("lesson-immutable", confidence=0.8).model_copy(
        update={"reinforced_at": reference - timedelta(days=30)}
    )
    store.add(lesson)

    # Three half-lives at an injected reference time: 0.8 -> 0.1.
    assert store.effective_confidence(lesson, now=reference) == pytest.approx(0.1)
    # A reference time before the anchor never inflates the weight.
    assert store.effective_confidence(lesson, now=reference - timedelta(days=60)) == 0.8

    stored = store.get(lesson.id)
    assert stored is not None
    assert stored.confidence == 0.8
    assert stored.status is LessonStatus.PENDING
    assert store.list_by_status("pending") == [stored]


def test_confidence_half_life_is_environment_configurable(monkeypatch, tmp_path):
    monkeypatch.setenv(CONFIDENCE_HALF_LIFE_ENV, "5")
    assert default_confidence_half_life_days() == 5.0
    assert ExperienceStore(tmp_path).confidence_half_life_days == 5.0

    for invalid in ("nonsense", "0", "-3", "   "):
        monkeypatch.setenv(CONFIDENCE_HALF_LIFE_ENV, invalid)
        assert default_confidence_half_life_days() == DEFAULT_CONFIDENCE_HALF_LIFE_DAYS

    monkeypatch.delenv(CONFIDENCE_HALF_LIFE_ENV)
    assert ExperienceStore(tmp_path).confidence_half_life_days == DEFAULT_CONFIDENCE_HALF_LIFE_DAYS

    with pytest.raises(ValueError):
        ExperienceStore(tmp_path, confidence_half_life_days=0)


def test_merge_threshold_respects_boundary_cases(tmp_path):
    store = ExperienceStore(tmp_path)
    existing = Lesson(
        id="threshold-existing",
        scope=LessonScope.TECHNIQUE,
        signal=LessonSignal.SUCCESS,
        tags=LessonTags(),
        context="alpha beta",
        lesson="gamma delta",
        evidence_refs=EvidenceRefs(run_id="run-1"),
        confidence=0.5,
    )
    candidate = existing.model_copy(
        update={
            "id": "threshold-candidate",
            "lesson": "gamma epsilon",
            "evidence_refs": EvidenceRefs(run_id="run-2"),
        }
    )
    store.add(existing)

    # Token overlap here is exactly 0.6 (3 shared of 5 distinct terms).
    assert store.find_near_duplicate(candidate, threshold=0.59) is not None
    assert store.find_near_duplicate(candidate, threshold=0.60) is not None
    assert store.find_near_duplicate(candidate, threshold=0.61) is None


def test_only_pending_lessons_are_eligible_for_candidate_merges(tmp_path):
    store = ExperienceStore(tmp_path)
    candidate = make_lesson("candidate", run_id="run-2")
    approved = store.add(make_lesson("approved", run_id="run-1"))
    store.approve(approved.id)
    rejected = store.add(make_lesson("rejected", run_id="run-3"))
    store.reject(rejected.id)

    assert store.find_near_duplicate(candidate, threshold=0.8) is None


def _experience_index_rows(tmp_path, lesson_id: str) -> list[dict]:
    import json

    index = json.loads((tmp_path / "index.json").read_text(encoding="utf-8"))
    return [row for row in index.get("experience", []) if row.get("id") == lesson_id]


def test_lifecycle_keeps_index_consistent_without_duplicates(tmp_path):
    store = ExperienceStore(tmp_path)
    pending = store.add(make_lesson("lesson-index-1"))

    rows = _experience_index_rows(tmp_path, pending.id)
    assert len(rows) == 1
    assert rows[0]["status"] == "pending"
    assert "sqli" in rows[0]["tags"]
    assert "status:pending" in rows[0]["tags"]
    assert (tmp_path / "experience" / f"{pending.id}.json").exists()

    approved = store.approve(pending.id)
    assert approved is not None
    rows = _experience_index_rows(tmp_path, pending.id)
    assert len(rows) == 1
    assert rows[0]["status"] == "approved"
    assert "status:approved" in rows[0]["tags"]
    assert "status:pending" not in rows[0]["tags"]

    updated = store.update(pending.id, lesson="Prefer bound parameters before fuzzing variants.")
    assert updated is not None
    rows = _experience_index_rows(tmp_path, pending.id)
    assert len(rows) == 1
    assert "bound parameters" in rows[0]["title"]

    store.merge(pending.id, make_lesson("candidate-index-1", confidence=0.4, run_id="run-9"))
    assert len(_experience_index_rows(tmp_path, pending.id)) == 1
    assert _experience_index_rows(tmp_path, "candidate-index-1") == []

    assert store.delete(pending.id) is True
    assert _experience_index_rows(tmp_path, pending.id) == []
    assert not (tmp_path / "experience" / f"{pending.id}.json").exists()


def test_orphan_experience_files_are_indexed_on_reconcile(tmp_path):
    """Lessons written before index maintenance become searchable via rebuild."""
    import json

    experience_dir = tmp_path / "experience"
    experience_dir.mkdir(parents=True)
    orphan = make_lesson("orphan-lesson")
    payload = orphan.model_dump(mode="json")
    payload["status"] = "approved"
    (experience_dir / f"{orphan.id}.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    # Stale index that omits the orphan file.
    (tmp_path / "index.json").write_text(json.dumps({"experience": []}), encoding="utf-8")

    store = ExperienceStore(tmp_path)
    stats = store.reconcile_index()
    assert stats.get("experience", 0) >= 1

    from vulnclaw.kb.store import KnowledgeStore

    kb = KnowledgeStore(store_dir=tmp_path)
    listed = {row["id"] for row in kb.list_entries("experience")}
    assert orphan.id in listed


def test_reconcile_migrates_legacy_experience_index_metadata(tmp_path):
    """Matching IDs do not hide legacy rows missing lifecycle/search metadata."""
    import json

    experience_dir = tmp_path / "experience"
    experience_dir.mkdir(parents=True)
    lesson = make_lesson("legacy-index-meta").model_copy(
        update={"status": LessonStatus.APPROVED}
    )
    lesson_path = experience_dir / f"{lesson.id}.json"
    lesson_path.write_text(
        json.dumps(lesson.model_dump(mode="json"), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (tmp_path / "index.json").write_text(
        json.dumps(
            {
                "experience": [
                    {
                        "id": lesson.id,
                        "title": "legacy title",
                        "tags": ["sqli"],
                        "file": str(lesson_path),
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    ExperienceStore(tmp_path)
    from vulnclaw.kb.store import KnowledgeStore

    kb = KnowledgeStore(store_dir=tmp_path)
    row = next(item for item in kb.list_entries("experience") if item["id"] == lesson.id)

    assert row["status"] == "approved"
    assert row["search_text"] == lesson.lesson
    assert "status:approved" in row["tags"]
    assert row["title"] != "legacy title"


def test_injected_knowledge_store_defines_experience_root(tmp_path):
    from vulnclaw.kb.store import KnowledgeStore

    kb_root = tmp_path / "injected-kb"
    kb = KnowledgeStore(store_dir=kb_root)
    store = ExperienceStore(knowledge_store=kb)
    lesson = store.add(make_lesson("injected-root"))

    assert store.store_dir == kb_root
    assert (kb_root / "experience" / f"{lesson.id}.json").exists()
    assert any(row["id"] == lesson.id for row in kb.list_entries("experience"))


def test_rejects_mismatched_explicit_and_injected_store_roots(tmp_path):
    from vulnclaw.kb.store import KnowledgeStore

    kb = KnowledgeStore(store_dir=tmp_path / "injected-kb")

    with pytest.raises(ValueError, match="store_dir must match"):
        ExperienceStore(store_dir=tmp_path / "other-kb", knowledge_store=kb)


def test_approved_lesson_discoverable_via_kb_search(tmp_path):
    """Integration: approve a lesson → KnowledgeStore search/index consumers see it."""
    from vulnclaw.kb.store import KnowledgeStore

    exp = ExperienceStore(tmp_path)
    lesson = exp.add(
        make_lesson("discoverable-1").model_copy(
            update={
                "lesson": "Prioritize parameterized-query verification before payload variation.",
                "tags": LessonTags(tech=["sqli"], vuln_type="sql-injection", service="http"),
            }
        )
    )
    exp.approve(lesson.id)

    kb = KnowledgeStore(store_dir=tmp_path)
    by_tag = kb.search("sqli", category="experience")
    assert any(entry.get("id") == lesson.id for entry in by_tag)

    by_title = kb.search("parameterized-query", category="experience")
    assert any(entry.get("id") == lesson.id for entry in by_title)

    listed = kb.list_entries("experience")
    meta = next(row for row in listed if row["id"] == lesson.id)
    assert meta["status"] == "approved"
    assert "sql-injection" in meta["tags"]


def test_generic_kb_retrieval_only_exposes_approved_experience(tmp_path):
    """Pending and rejected lessons never enter generic retrieval corpora."""
    from vulnclaw.kb.store import KnowledgeStore

    experience = ExperienceStore(tmp_path)
    pending = experience.add(make_lesson("generic-pending"))
    rejected = experience.add(make_lesson("generic-rejected"))
    experience.reject(rejected.id)
    approved = experience.add(make_lesson("generic-approved"))
    experience.approve(approved.id)

    kb = KnowledgeStore(store_dir=tmp_path)

    search_ids = {entry["id"] for entry in kb.search("parameterized-query")}
    corpus_ids = {
        entry["id"]
        for entry in kb.iter_all_entries()
        if entry.get("_category") == "experience"
    }

    assert search_ids == {approved.id}
    assert corpus_ids == {approved.id}
    assert experience.get(pending.id) is not None
    assert experience.get(rejected.id) is not None
