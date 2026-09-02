"""Durable, operator-supplied feedback for completed run directories.

Feedback is deliberately a single bounded document per run.  Replacing that
document makes repeated operator submissions an update, rather than an
additional unreviewed signal for the distiller.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from vulnclaw.run_context import atomic_write_json

logger = logging.getLogger(__name__)

FEEDBACK_FILENAME = "feedback.json"
FEEDBACK_SCHEMA_VERSION = 1
MAX_NOTES_LENGTH = 4_000


class FeedbackError(ValueError):
    """Raised when feedback cannot be safely persisted."""


class OperatorFeedback(BaseModel):
    """A bounded operator assessment that can be safely sent to the distiller."""

    schema_version: int = FEEDBACK_SCHEMA_VERSION
    rating: int = Field(strict=True, ge=1, le=5)
    notes: str = Field(strict=True, max_length=MAX_NOTES_LENGTH)
    created_at: str
    updated_at: str


def feedback_path(run_dir: str | Path) -> Path:
    """Return the fixed feedback location beneath an existing run directory."""

    return Path(run_dir) / FEEDBACK_FILENAME


def load_feedback(run_dir: str | Path) -> OperatorFeedback | None:
    """Load valid feedback, returning ``None`` for absent or malformed files.

    A malformed optional operator artifact must never prevent distillation of
    otherwise valid run evidence.  The CLI validates writes before this path.
    """

    path = feedback_path(run_dir)
    if not path.exists():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise FeedbackError("feedback document must be an object")
        return OperatorFeedback.model_validate(raw)
    except (OSError, json.JSONDecodeError, ValidationError, FeedbackError):
        logger.warning("ignoring invalid feedback artifact at %s", path)
        return None


def save_feedback(
    run_dir: str | Path,
    *,
    rating: int,
    notes: str,
) -> OperatorFeedback:
    """Atomically create or replace the one feedback record for ``run_dir``."""

    directory = Path(run_dir)
    if not directory.is_dir():
        raise FeedbackError(f"run directory does not exist: {directory}")

    now = _now_iso()
    existing = load_feedback(directory)
    try:
        feedback = OperatorFeedback(
            rating=rating,
            notes=notes,
            created_at=existing.created_at if existing is not None else now,
            updated_at=now,
        )
    except ValidationError as exc:
        detail = "; ".join(error["msg"] for error in exc.errors())
        raise FeedbackError(detail) from exc

    atomic_write_json(feedback_path(directory), feedback.model_dump(mode="json"))
    return feedback


def feedback_for_distillation(run_dir: str | Path) -> dict[str, Any] | None:
    """Return only the signal fields relevant to a distillation prompt."""

    feedback = load_feedback(run_dir)
    if feedback is None:
        return None
    return {"rating": feedback.rating, "notes": feedback.notes}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
