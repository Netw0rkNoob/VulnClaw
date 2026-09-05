"""Canonical durable experience lessons for the self-learning loop.

This module is the single production schema and store for cross-run lessons:

* ``Lesson`` / ``EvidenceRefs`` / status enums — lesson documents on disk
* ``ExperienceStore`` — add / get / approve / reject / merge / list_by_status

Companion production surfaces (do not add a second store or CLI):

* Distillation: ``vulnclaw.agent.distiller`` (``distill_run``, ``persist_distilled_lessons``)
* Prompt injection: ``vulnclaw.agent.experience_context.build_experience_context``
  (wired from ``AgentCore``; not language-gated with the legacy KB corpus)
* CLI: ``vulnclaw experience`` / ``vulnclaw learn`` / ``vulnclaw feedback`` in
  ``vulnclaw.cli.main``

Lessons remain ``pending`` until a human approves them, so automated
distillation cannot teach later runs an unreviewed tactic.  Files live at
``<KB_DIR>/experience/<lesson-id>.json``.
"""

from __future__ import annotations

import json
import os
import re
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterator, Mapping, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator, model_validator

from vulnclaw.config.settings import KB_DIR
from vulnclaw.kb.store import KnowledgeStore


class LessonScope(str, Enum):
    TARGET = "target"
    TECHNIQUE = "technique"


class LessonStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class LessonSignal(str, Enum):
    SUCCESS = "success"
    DEADEND = "deadend"


class LessonTags(BaseModel):
    """Signals used to match a lesson to a future run."""

    tech: list[str] = Field(default_factory=list)
    vuln_type: str = ""
    waf: str = ""
    service: str = ""

    @field_validator("tech")
    @classmethod
    def normalize_tech(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(value.strip() for value in values if value.strip()))


class EvidenceRefs(BaseModel):
    """Pointers to evidence that supports an extracted lesson."""

    run_id: str = Field(min_length=1, max_length=256)
    finding_id: Optional[str] = Field(default=None, max_length=256)
    path: Optional[str] = Field(default=None, max_length=2048)


class Lesson(BaseModel):
    """A transferable lesson from one or more authorized pentest runs."""

    id: str = Field(min_length=1, max_length=128)
    scope: LessonScope
    status: LessonStatus = LessonStatus.PENDING
    signal: LessonSignal
    tags: LessonTags = Field(default_factory=LessonTags)
    context: str = Field(min_length=1, max_length=16_000)
    lesson: str = Field(min_length=1, max_length=16_000)
    evidence_refs: EvidenceRefs
    confidence: float = Field(ge=0.0, le=1.0)
    source_runs: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reinforced_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    target_key: Optional[str] = Field(default=None, max_length=512)

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not _SAFE_ID.fullmatch(value):
            raise ValueError("lesson id must be a safe filename component")
        return value

    @field_validator("source_runs")
    @classmethod
    def normalize_source_runs(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(value.strip() for value in values if value.strip()))

    @model_validator(mode="after")
    def validate_scope(self) -> "Lesson":
        if self.scope is LessonScope.TARGET and not self.target_key:
            raise ValueError("target_key is required for target-scoped lessons")
        if self.scope is LessonScope.TECHNIQUE and self.target_key is not None:
            raise ValueError("target_key is only permitted for target-scoped lessons")
        return self


_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_PROCESS_LOCK = threading.RLock()

DEFAULT_CONFIDENCE_HALF_LIFE_DAYS = 90.0
CONFIDENCE_HALF_LIFE_ENV = "VULNCLAW_EXPERIENCE_HALF_LIFE_DAYS"


def default_confidence_half_life_days() -> float:
    """Return the operator-tunable decay half-life, in days.

    Read at call time rather than import time so a deployment can retune decay
    without reinstalling.  An unparsable or non-positive override is ignored
    instead of raising: learning is best-effort and must not break a run.
    """
    raw = os.environ.get(CONFIDENCE_HALF_LIFE_ENV, "").strip()
    if not raw:
        return DEFAULT_CONFIDENCE_HALF_LIFE_DAYS
    try:
        value = float(raw)
    except ValueError:
        return DEFAULT_CONFIDENCE_HALF_LIFE_DAYS
    return value if value > 0 else DEFAULT_CONFIDENCE_HALF_LIFE_DAYS


@contextmanager
def _file_lock(path: Path) -> Iterator[None]:
    """Serialize writers across threads and processes on Windows and POSIX."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with _PROCESS_LOCK, open(path, "a+b") as handle:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


class ExperienceStore:
    """File-backed lifecycle store for human-reviewed lessons.

    Each lesson is stored as ``<kb>/experience/<lesson-id>.json``.  Writes
    use a lock plus atomic replacement, avoiding partially written JSON when
    multiple completed runs are distilled at the same time.  Every create,
    update, status flip, merge, and delete also upserts or removes the
    shared KB ``index.json`` row so index/search consumers see the same
    set of files as disk.
    """

    CATEGORY = "experience"

    def __init__(
        self,
        store_dir: Optional[Path] = None,
        *,
        confidence_half_life_days: Optional[float] = None,
        knowledge_store: Optional[KnowledgeStore] = None,
    ) -> None:
        if confidence_half_life_days is None:
            confidence_half_life_days = default_confidence_half_life_days()
        elif confidence_half_life_days <= 0:
            raise ValueError("confidence_half_life_days must be positive")
        requested_store_dir = Path(store_dir) if store_dir else None
        if knowledge_store is not None:
            knowledge_store_dir = Path(knowledge_store.store_dir)
            if requested_store_dir is not None and requested_store_dir != knowledge_store_dir:
                raise ValueError("store_dir must match knowledge_store.store_dir")
            self.store_dir = knowledge_store_dir
        else:
            self.store_dir = requested_store_dir or KB_DIR
        self.experience_dir = self.store_dir / "experience"
        self.experience_dir.mkdir(parents=True, exist_ok=True)
        self.confidence_half_life_days = confidence_half_life_days
        self._kb = knowledge_store or KnowledgeStore(store_dir=self.store_dir)
        self.reconcile_index()

    def add(self, lesson: Lesson | Mapping[str, Any]) -> Lesson:
        """Persist a new lesson as pending, regardless of caller-supplied status."""
        candidate = self._coerce_lesson(lesson)
        pending = candidate.model_copy(update={"status": LessonStatus.PENDING})
        with _file_lock(self.experience_dir / ".experience.lock"):
            if self._lesson_path(pending.id).exists():
                raise ValueError(f"lesson {pending.id!r} already exists")
            self._write_lesson(pending)
        return pending

    def get(self, lesson_id: str) -> Optional[Lesson]:
        """Return one lesson, or ``None`` when it has not been stored."""
        path = self._lesson_path(lesson_id)
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return Lesson.model_validate(json.load(handle))
        except (OSError, json.JSONDecodeError, ValueError):
            return None

    def list_by_status(self, status: LessonStatus | str) -> list[Lesson]:
        """List only lessons in the requested lifecycle state."""
        wanted = LessonStatus(status)
        lessons = [lesson for path in self.experience_dir.glob("*.json") if (lesson := self._read(path))]
        return sorted((lesson for lesson in lessons if lesson.status is wanted), key=lambda item: item.created_at)

    def approve(self, lesson_id: str) -> Optional[Lesson]:
        """Durably mark a pending lesson as approved."""
        return self._set_status(lesson_id, LessonStatus.APPROVED)

    def reject(self, lesson_id: str) -> Optional[Lesson]:
        """Durably mark a pending lesson as rejected."""
        return self._set_status(lesson_id, LessonStatus.REJECTED)

    def update(
        self,
        lesson_id: str,
        *,
        context: Optional[str] = None,
        lesson: Optional[str] = None,
    ) -> Optional[Lesson]:
        """Durably amend the reviewable text of an existing lesson.

        Reviewers may correct retrieval context or transferable guidance, but
        cannot alter provenance, scope, or lifecycle state through this path.
        """
        if context is None and lesson is None:
            raise ValueError("context or lesson must be supplied")
        changes: dict[str, Any] = {}
        if context is not None:
            changes["context"] = context
        if lesson is not None:
            changes["lesson"] = lesson
        with _file_lock(self.experience_dir / ".experience.lock"):
            existing = self.get(lesson_id)
            if existing is None:
                return None
            updated = existing.model_copy(update=changes)
            # Revalidate user-supplied text rather than relying on model_copy.
            updated = Lesson.model_validate(updated.model_dump())
            self._write_lesson(updated)
        return updated

    def find_near_duplicate(self, lesson: Lesson | Mapping[str, Any], *, threshold: float = 0.8) -> Optional[Lesson]:
        """Return the closest comparable lesson when token overlap meets ``threshold``.

        This intentionally uses deterministic token overlap rather than an LLM,
        leaving callers in control of whether to merge the candidate.
        """
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("threshold must be between 0 and 1")
        candidate = self._coerce_lesson(lesson)
        best: tuple[float, Lesson] | None = None
        candidate_terms = self._terms(candidate)
        for existing in self.list_by_status(LessonStatus.PENDING):
            if existing.scope is not candidate.scope:
                continue
            if existing.scope is LessonScope.TARGET and existing.target_key != candidate.target_key:
                continue
            score = self._similarity(candidate_terms, self._terms(existing))
            if score >= threshold and (best is None or score > best[0]):
                best = (score, existing)
        return best[1] if best else None

    def merge(self, existing_id: str, duplicate: Lesson | Mapping[str, Any]) -> Optional[Lesson]:
        """Fold a duplicate's confidence and run provenance into an existing lesson."""
        incoming = self._coerce_lesson(duplicate)
        with _file_lock(self.experience_dir / ".experience.lock"):
            existing = self.get(existing_id)
            if existing is None:
                return None
            if existing.scope is not incoming.scope:
                raise ValueError("only lessons with the same scope can be merged")
            if existing.scope is LessonScope.TARGET and existing.target_key != incoming.target_key:
                raise ValueError("target-scoped lessons must have the same target_key")
            source_runs = list(dict.fromkeys([*existing.source_runs, existing.evidence_refs.run_id, *incoming.source_runs, incoming.evidence_refs.run_id]))
            merged = existing.model_copy(update={
                "confidence": self.combine_confidence(existing.confidence, incoming.confidence),
                "source_runs": source_runs,
                "reinforced_at": datetime.now(timezone.utc),
            })
            self._write_lesson(merged)
        return merged

    def delete(self, lesson_id: str) -> bool:
        """Remove a lesson file and its shared KB index row.

        Returns ``True`` when a lesson file was present and removed.
        Missing lessons return ``False`` after a best-effort index cleanup.
        """
        with _file_lock(self.experience_dir / ".experience.lock"):
            path = self._lesson_path(lesson_id)
            removed = False
            if path.exists():
                path.unlink()
                removed = True
            self._remove_from_index(lesson_id)
            return removed

    def reconcile_index(self) -> dict[str, int]:
        """Ensure every on-disk lesson JSON appears once in ``index.json``.

        Used on store construction (migration for lessons written before
        index maintenance) and can be called again after manual filesystem
        changes. Returns category counts from the rebuilt index when a
        rebuild was required, otherwise the current stats.
        """
        self._kb._load_index()
        expected: dict[str, dict[str, Any]] = {}
        for path in self.experience_dir.glob("*.json"):
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    payload = json.load(handle)
                if not isinstance(payload, dict):
                    continue
                meta = self._kb.index_meta_for(payload, path)
                expected[str(meta["id"])] = meta
            except (OSError, json.JSONDecodeError, TypeError, ValueError):
                continue

        rows = self._kb.list_entries(self.CATEGORY)
        indexed = {
            str(meta.get("id")): meta
            for meta in rows
            if meta.get("id")
        }
        duplicate_rows = len(indexed) != len(rows)
        stale_metadata = any(indexed.get(entry_id) != meta for entry_id, meta in expected.items())
        if (
            set(expected) != set(indexed)
            or duplicate_rows
            or stale_metadata
            or not (self.store_dir / "index.json").exists()
        ):
            return self._kb.rebuild_index()
        return self._kb.get_stats()

    def combine_confidence(self, existing: float, incoming: float) -> float:
        """Combine confidence for reinforcement; subclasses may supply a policy."""
        return min(1.0, existing + incoming * (1.0 - existing))

    def effective_confidence(self, lesson: Lesson, *, now: Optional[datetime] = None) -> float:
        """Return time-decayed retrieval weight without mutating stored lessons.

        Each half-life halves the strength of an unreinforced lesson.  Merging a
        lesson refreshes ``reinforced_at``; decay never deletes or changes its
        review status or persisted base confidence.
        """
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        reinforced = lesson.reinforced_at
        if reinforced.tzinfo is None:
            reinforced = reinforced.replace(tzinfo=timezone.utc)
        age_seconds = max(0.0, (current - reinforced).total_seconds())
        age_days = age_seconds / 86_400
        return lesson.confidence * (0.5 ** (age_days / self.confidence_half_life_days))

    def _set_status(self, lesson_id: str, status: LessonStatus) -> Optional[Lesson]:
        with _file_lock(self.experience_dir / ".experience.lock"):
            lesson = self.get(lesson_id)
            if lesson is None:
                return None
            updated = lesson.model_copy(update={"status": status})
            self._write_lesson(updated)
        return updated

    def _write_lesson(self, lesson: Lesson) -> None:
        path = self._lesson_path(lesson.id)
        temporary = self.experience_dir / f".{lesson.id}.{os.getpid()}.{uuid4().hex}.tmp"
        payload = lesson.model_dump(mode="json")
        try:
            with open(temporary, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        finally:
            temporary.unlink(missing_ok=True)
        self._upsert_index(lesson.id, path, payload)

    def _upsert_index(self, lesson_id: str, path: Path, payload: Mapping[str, Any]) -> None:
        """Upsert the shared KB index row for a lesson (no duplicate rows)."""
        self._kb.upsert_index_entry(self.CATEGORY, lesson_id, path, dict(payload))

    def _remove_from_index(self, lesson_id: str) -> None:
        self._kb.remove_index_entry(self.CATEGORY, lesson_id)

    def _lesson_path(self, lesson_id: str) -> Path:
        if not isinstance(lesson_id, str) or not _SAFE_ID.fullmatch(lesson_id):
            raise ValueError("lesson id must be a safe filename component")
        return self.experience_dir / f"{lesson_id}.json"

    @staticmethod
    def _coerce_lesson(lesson: Lesson | Mapping[str, Any]) -> Lesson:
        return lesson if isinstance(lesson, Lesson) else Lesson.model_validate(lesson)

    @staticmethod
    def _read(path: Path) -> Optional[Lesson]:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return Lesson.model_validate(json.load(handle))
        except (OSError, json.JSONDecodeError, ValueError):
            return None

    def _all(self) -> list[Lesson]:
        return [lesson for path in self.experience_dir.glob("*.json") if (lesson := self._read(path))]

    @staticmethod
    def _terms(lesson: Lesson) -> set[str]:
        raw = " ".join([lesson.context, lesson.lesson, *lesson.tags.tech, lesson.tags.vuln_type, lesson.tags.waf, lesson.tags.service])
        return set(re.findall(r"[a-z0-9][a-z0-9_-]*", raw.lower()))

    @staticmethod
    def _similarity(left: set[str], right: set[str]) -> float:
        if not left or not right:
            return 0.0
        return len(left & right) / len(left | right)
