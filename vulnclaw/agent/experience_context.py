"""Approved cross-session experience retrieval for agent prompts.

Canonical production retrieval for lessons stored by
``vulnclaw.kb.experience.ExperienceStore``.  AgentCore injects the result via
``build_dynamic_system_prompt(..., experience_context=...)``.

Experience is deliberately separate from the legacy knowledge-base context:
the latter is language-gated because its corpus is Chinese, whereas approved
lessons are explicitly reviewed before they can influence a future run.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Mapping
from datetime import datetime
from typing import Any, Optional

from vulnclaw.kb.experience import ExperienceStore
from vulnclaw.kb.retriever import _tokenize
from vulnclaw.targets import parse_target

_MAX_LESSONS = 5
_MAX_LESSON_CHARS = 800


def build_experience_context(
    target_ctx: Any,
    store: ExperienceStore,
    *,
    now: Optional[datetime] = None,
) -> str:
    """Return approved, target-relevant lessons as a distinct prompt block.

    Failures are intentionally contained: learning must never prevent a scan
    from starting or a turn from completing.  This function never consults
    ``current_lang``; approved experience is a separate path from the
    language-gated legacy KB corpus.

    ``now`` overrides the reference time used for confidence decay so callers
    and tests can rank against a fixed instant instead of the wall clock.
    """
    try:
        lessons = [
            lesson
            for lesson in store.list_by_status("approved")
            if _value(lesson, "status") == "approved"
        ]
        if not lessons:
            return ""

        live_tags, query, target_key = _live_target_context(target_ctx)
        ranked = _rank_lessons(lessons, live_tags, query, target_key, store, now=now)
        if not ranked:
            return ""

        lines = [
            "## Prior Experience / Lessons",
            "Human-approved lessons from relevant prior engagements:",
        ]
        for lesson in ranked[:_MAX_LESSONS]:
            instruction = _single_line(_value(lesson, "lesson"))[:_MAX_LESSON_CHARS]
            if not instruction:
                continue
            signal = _single_line(_value(lesson, "signal")) or "lesson"
            condition = _single_line(_value(lesson, "context"))[:240]
            prefix = f"- [{signal}]"
            lines.append(f"{prefix} {condition}: {instruction}" if condition else f"{prefix} {instruction}")

        return "\n".join(lines) if len(lines) > 2 else ""
    except Exception:
        # Experience is an optional enhancement, not a dependency of the
        # agent loop.  Do not leak store paths or lesson content in errors.
        return ""


def _live_target_context(target_ctx: Any) -> tuple[set[str], str, str]:
    """Extract stable retrieval terms from SessionState or an equivalent view."""
    state = getattr(getattr(target_ctx, "context", None), "state", target_ctx)
    recon = _value(state, "recon_data", {})
    if not isinstance(recon, Mapping):
        recon = {}

    target = str(_value(state, "target", "") or "").strip()
    try:
        target_key = parse_target(target).target_id if target else ""
    except ValueError:
        target_key = ""
    tags: set[str] = set()
    for key in ("services", "technologies", "tech", "tech_stack", "detected_tech", "fingerprints", "waf"):
        for item in _as_items(recon.get(key)):
            tags.update(_terms(item))

    for finding in _as_items(_value(state, "findings", [])):
        tags.update(_terms(_value(finding, "vuln_type", "")))

    query = " ".join(sorted(tags | _terms(target)))
    return tags, query, target_key


def _rank_lessons(
    lessons: list[Any],
    live_tags: set[str],
    query: str,
    target_key: str,
    store: ExperienceStore,
    *,
    now: Optional[datetime] = None,
) -> list[Any]:
    """Rank tag-matched lessons by overlap, then TF-IDF text similarity."""
    candidates: list[tuple[Any, set[str], bool]] = []
    documents: list[str] = []
    for lesson in lessons:
        lesson_tags = _lesson_tags(lesson)
        target_match = bool(target_key and _value(lesson, "target_key", "") == target_key)
        if not (lesson_tags & live_tags) and not target_match:
            continue
        candidates.append((lesson, lesson_tags, target_match))
        documents.append(
            " ".join(
                (
                    _value(lesson, "context", "") or "",
                    _value(lesson, "lesson", "") or "",
                    " ".join(lesson_tags),
                )
            )
        )

    similarities = _tfidf_similarity(query, documents)
    scored = []
    for (lesson, lesson_tags, target_match), similarity in zip(candidates, similarities):
        overlap = len(lesson_tags & live_tags)
        # Exact target-scoped lessons are relevant even before recon has
        # accumulated tags; tag overlap remains the primary ranking signal.
        # Confidence is intentionally decayed by the store at retrieval time:
        # old lessons remain auditable and retrievable, but fresh/reinforced
        # evidence ranks ahead when relevance is otherwise comparable.
        confidence = store.effective_confidence(lesson, now=now)
        score = (overlap * 10.0 + similarity + (1.0 if target_match else 0.0)) * confidence
        scored.append((score, str(_value(lesson, "id", "")), lesson))
    scored.sort(key=lambda item: (-item[0], item[1]))
    return [lesson for _, _, lesson in scored]


def _tfidf_similarity(query: str, documents: list[str]) -> list[float]:
    """Use the KB keyword retriever's TF-IDF weighting model for ranking."""
    query_counts = Counter(_tokenize(query))
    if not query_counts or not documents:
        return [0.0] * len(documents)

    document_counts = [Counter(_tokenize(document)) for document in documents]
    document_frequency: Counter[str] = Counter()
    for counts in document_counts:
        document_frequency.update(counts.keys())
    total = len(document_counts)
    idf = {
        token: math.log((total + 1) / (frequency + 1)) + 1.0
        for token, frequency in document_frequency.items()
    }

    def weighted_norm(counts: Counter[str]) -> float:
        return math.sqrt(sum((count * idf.get(token, 1.0)) ** 2 for token, count in counts.items()))

    query_norm = weighted_norm(query_counts)
    if not query_norm:
        return [0.0] * len(documents)
    scores: list[float] = []
    for counts in document_counts:
        document_norm = weighted_norm(counts)
        if not document_norm:
            scores.append(0.0)
            continue
        dot_product = sum(
            query_count * counts.get(token, 0) * idf.get(token, 1.0) ** 2
            for token, query_count in query_counts.items()
        )
        scores.append(dot_product / (query_norm * document_norm))
    return scores


def _lesson_tags(lesson: Any) -> set[str]:
    tags = _as_mapping(_value(lesson, "tags", {}))
    values: list[Any] = []
    for key in ("tech", "vuln_type", "waf", "service"):
        values.extend(_as_items(tags.get(key)))
    return {term for value in values for term in _terms(value)}


def _value(obj: Any, name: str, default: Any = "") -> Any:
    return obj.get(name, default) if isinstance(obj, Mapping) else getattr(obj, name, default)


def _as_mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    model_dump = getattr(value, "model_dump", None)
    dumped = model_dump() if callable(model_dump) else {}
    return dumped if isinstance(dumped, Mapping) else {}


def _as_items(value: Any) -> list[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple, set)) else [value]


def _terms(value: Any) -> set[str]:
    if isinstance(value, Mapping):
        return {term for nested in value.values() for term in _terms(nested)}
    return set(_tokenize(str(value)))


def _single_line(value: Any) -> str:
    return " ".join(str(value or "").split())
