"""Model-led autonomous-agent state.

This module is intentionally not a planner.  It stores what the model and tools
actually did: tool calls, evidence, compact step notes, completion decisions and
manual compaction summaries.  The solve engine reads this state as memory while
the model remains responsible for choosing the next action.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Any

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, model_validator

DEFAULT_EVIDENCE_PREVIEW_CHARS = 6000
DEFAULT_EVIDENCE_VIEW_CHARS = 0
FULL_EVIDENCE_RANGE_END = 2**63 - 1
MAX_STORED_EVIDENCE = 240
MAX_STORED_TOOL_CALLS = 400
MAX_STORED_STEPS = 400
MAX_STORED_PROGRESS_SIGNALS = 160
MAX_STORED_PINNED_FACTS = 80
MAX_STORED_CORRECTION_HINTS = 24
MAX_STORED_CONTEXT_COMPACTIONS = 32
OBSERVATION_ONLY_TOOLS = frozenset({"evidence_list", "evidence_view", "evidence_search"})

_FLAG_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{1,20}\{[^{}\n]{1,200}\}")
_STATUS_RE = re.compile(r"(?:Status|HTTP/\d(?:\.\d)?)\s*:?\s*(\d{3})", re.IGNORECASE)


def clip_text(value: str, limit: int, *, marker: str = "...[truncated]...") -> str:
    """Return a deterministic head/tail preview for oversized text.

    A non-positive limit means "unlimited" so callers can opt out of clipping
    without needing a separate code path.
    """

    text = str(value or "")
    if limit <= 0 or len(text) <= limit:
        return text
    head = max(1, limit // 2)
    tail = max(1, limit - head - len(marker) - 2)
    return f"{text[:head].rstrip()}\n{marker}\n{text[-tail:].lstrip()}"


def one_line(value: str, limit: int = 240) -> str:
    """Collapse whitespace and clip to one prompt-safe line."""

    return clip_text(re.sub(r"\s+", " ", str(value or "")).strip(), limit)


def parse_status_code(output: str) -> int:
    """Extract an HTTP status when the tool output exposes one."""

    match = _STATUS_RE.search(output or "")
    return int(match.group(1)) if match else 0


def extract_flags(text: str) -> list[str]:
    """Extract common CTF flag-looking tokens without asserting validity."""

    return list(dict.fromkeys(_FLAG_RE.findall(text or "")))


def _important_lines(text: str, limit: int = 18) -> list[str]:
    """Pick lines that are likely useful when building a large-output preview."""

    markers = (
        "flag",
        "ctf{",
        "status:",
        "headers:",
        "location:",
        "set-cookie",
        "error",
        "exception",
        "sql",
        "union",
        "select",
        "form",
        "<input",
        "href=",
        "script",
        "token",
        "secret",
        "key",
        "password",
        "admin",
        "endpoint",
        "api/",
        "highlight_file",
        "show_source",
        "source",
        "<?php",
        "$_get",
        "$_post",
        "$_request",
        "$_cookie",
        "unserialize",
        "serialize",
        "__wakeup",
        "__destruct",
        "__tostring",
        "class ",
        "function ",
        "eval(",
        "assert(",
        "system(",
        "shell_exec",
        "preg_match",
    )
    selected: list[str] = []
    for line_no, line in enumerate(str(text or "").splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        lower = stripped.lower()
        if any(marker in lower for marker in markers):
            selected.append(f"L{line_no}: {one_line(stripped, 260)}")
        if len(selected) >= limit:
            break
    return selected


def make_evidence_preview(content: str, limit: int = DEFAULT_EVIDENCE_PREVIEW_CHARS) -> str:
    """Build bounded prompt-facing evidence while preserving raw content separately.

    The preview is an active-context working set, not the evidence source of
    truth. Large raw outputs stay available through evidence_view/evidence_search;
    this function keeps the model from repeatedly carrying entire HTML bodies,
    command logs or response blobs in every subsequent LLM request.
    """

    text = str(content or "")
    if limit <= 0:
        return text
    if len(text) <= limit:
        return text
    lines = _important_lines(text, limit=36)
    header = (
        "[active-context high-signal preview]\n"
        f"raw_size={len(text)} chars; full raw evidence is stored separately; "
        "use evidence_view/evidence_search if a missing byte or wider span matters."
    )
    marker = "...[raw omitted from active context; inspect saved evidence for full body]..."
    if not lines:
        return "\n".join([header, "", "[head/tail context]", clip_text(text, limit, marker=marker)])

    signal_block = "\n".join(["[signal lines]", *lines])
    remaining = max(1000, limit - len(header) - len(signal_block) - 80)
    preview = "\n".join(
        [
            header,
            "",
            signal_block,
            "",
            "[head/tail context]",
            clip_text(text, remaining, marker=marker),
        ]
    )
    return clip_text(preview, limit, marker="...[preview clipped; inspect saved evidence]...")


class EvidenceRecord(BaseModel):
    """Raw tool evidence plus prompt-safe preview."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    target: str = ""
    tool: str = ""
    arguments: dict[str, Any] = Field(default_factory=dict)
    key_args: str = ""
    status: int = 0
    summary: str = ""
    preview: str = ""
    content: str = ""
    truncated: bool = False
    fingerprint: str = ""
    content_hash: str = ""
    duplicate_of: str = ""
    created_at: str = Field(default_factory=lambda: datetime.now().isoformat())

    @property
    def size(self) -> int:
        return len(self.content or "")


class ToolCallRecord(BaseModel):
    """A compact record of a model-selected tool call."""

    tool: str
    key_args: str = ""
    status: int = 0
    evidence_id: str = ""
    summary: str = ""
    duration_ms: int = 0
    ok: bool = True
    error_type: str = ""
    created_at: str = Field(default_factory=lambda: datetime.now().isoformat())


class AgentStep(BaseModel):
    """One visible model-led action step."""

    index: int
    reason: str = ""
    observation: str = ""
    tool_calls: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now().isoformat())


class VerifiedClaim(BaseModel):
    """Completion or finding claim that passed the evidence gate."""

    id: str
    claim: str
    evidence_ids: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now().isoformat())


class ToolHealth(BaseModel):
    """Rolling health signal for a callable tool."""

    tool: str
    status: str = "healthy"
    successes: int = 0
    failures: int = 0
    consecutive_failures: int = 0
    last_error: str = ""
    last_duration_ms: int = 0
    updated_at: str = Field(default_factory=lambda: datetime.now().isoformat())


class ProgressSignal(BaseModel):
    """Small post-tool signal used by the correction layer."""

    kind: str
    detail: str
    tool: str = ""
    evidence_id: str = ""
    created_at: str = Field(default_factory=lambda: datetime.now().isoformat())


class PinnedFact(BaseModel):
    """A durable, compact fact that should stay visible in prompt memory."""

    text: str
    evidence_id: str = ""
    created_at: str = Field(default_factory=lambda: datetime.now().isoformat())


class ContextDigest(BaseModel):
    """Bounded durable memory produced by automatic context compaction."""

    version: int = 1
    summary: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    updated_at: str = Field(default_factory=lambda: datetime.now().isoformat())


class ContextCompactionEvent(BaseModel):
    """Metadata-only record for one context compaction operation."""

    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    purpose: str = ""
    reason: str = ""
    before_tokens: int = 0
    after_tokens: int = 0
    tool_tokens: int = 0
    removed_message_groups: int = 0
    retained_message_groups: int = 0
    evidence_ids: list[str] = Field(default_factory=list)


class AgentState(BaseModel):
    """Durable state for the default model-led solve engine."""

    model_config = ConfigDict(populate_by_name=True)

    origin: str = ""
    goal: str = ""
    evidence: list[EvidenceRecord] = Field(
        default_factory=list,
        validation_alias=AliasChoices("evidence", "memories"),
    )
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    steps: list[AgentStep] = Field(default_factory=list)
    verified_claims: list[VerifiedClaim] = Field(
        default_factory=list,
        validation_alias=AliasChoices("verified_claims", "verified_facts", "facts"),
    )
    pinned_facts: list[PinnedFact] = Field(default_factory=list)
    progress_signals: list[ProgressSignal] = Field(default_factory=list)
    correction_hints: list[str] = Field(default_factory=list)
    tool_health: dict[str, ToolHealth] = Field(default_factory=dict)
    pending_questions: list[str] = Field(default_factory=list)
    compact_summary: str = ""
    context_digest: ContextDigest = Field(default_factory=ContextDigest)
    context_compactions: list[ContextCompactionEvent] = Field(default_factory=list)
    completion_rejections: list[str] = Field(default_factory=list)
    completed: bool = False
    complete_reason: str = ""
    final_answer: str = ""
    evidence_seq: int = Field(default=0, exclude=True)
    step_seq: int = Field(default=0, exclude=True)
    claim_seq: int = Field(default=0, exclude=True)

    @model_validator(mode="before")
    @classmethod
    def _coerce_legacy_state(cls, data: Any) -> Any:
        """Load old snapshots without keeping the removed direction model."""

        if not isinstance(data, dict):
            return data
        legacy_facts = data.get("verified_facts") or data.get("facts")
        if "verified_claims" not in data and isinstance(legacy_facts, list):
            claims: list[dict[str, Any]] = []
            for index, item in enumerate(legacy_facts, start=1):
                if isinstance(item, dict):
                    claim = item.get("claim") or item.get("description") or ""
                    raw_id = str(item.get("id") or "")
                else:
                    claim = str(item)
                    raw_id = ""
                claims.append(
                    {
                        "id": raw_id if raw_id.startswith("c") else f"c{index:03d}",
                        "claim": claim,
                        "evidence_ids": [],
                    }
                )
            data = {**data, "verified_claims": claims}
        return data

    def model_post_init(self, __context: Any) -> None:
        if self.evidence and self.evidence_seq == 0:
            self.evidence_seq = self._restore_seq([item.id for item in self.evidence], "e")
        if self.steps and self.step_seq == 0:
            self.step_seq = max((item.index for item in self.steps), default=len(self.steps))
        if self.verified_claims and self.claim_seq == 0:
            self.claim_seq = self._restore_seq([item.id for item in self.verified_claims], "c")

    @staticmethod
    def _restore_seq(values: list[str], prefix: str) -> int:
        nums = [
            int(value[len(prefix) :])
            for value in values
            if isinstance(value, str)
            and value.startswith(prefix)
            and value[len(prefix) :].isdigit()
        ]
        return max(nums) if nums else len(values)

    def reset_for_goal(self, *, origin: str, goal: str) -> None:
        """Start a new solve goal without carrying stale engine-internal state."""

        if self.origin == origin and self.goal == goal and not self.completed:
            return
        self.origin = origin
        self.goal = goal
        self.evidence = []
        self.tool_calls = []
        self.steps = []
        self.verified_claims = []
        self.pinned_facts = []
        self.progress_signals = []
        self.correction_hints = []
        self.tool_health = {}
        self.pending_questions = []
        self.compact_summary = ""
        self.context_digest = ContextDigest()
        self.context_compactions = []
        self.completion_rejections = []
        self.completed = False
        self.complete_reason = ""
        self.final_answer = ""
        self.evidence_seq = 0
        self.step_seq = 0
        self.claim_seq = 0

    def record_step(
        self,
        *,
        reason: str = "",
        observation: str = "",
        tool_calls: list[str] | None = None,
    ) -> AgentStep:
        self.step_seq += 1
        step = AgentStep(
            index=self.step_seq,
            reason=one_line(reason, 260),
            observation=one_line(observation, 420),
            tool_calls=list(tool_calls or []),
        )
        self.steps.append(step)
        if len(self.steps) > MAX_STORED_STEPS:
            del self.steps[: MAX_STORED_STEPS // 2]
        return step

    def remember_tool_result(
        self,
        *,
        tool: str,
        arguments: dict[str, Any] | None,
        output: Any,
        status: int = 0,
        target: str = "",
        preview_chars: int = DEFAULT_EVIDENCE_PREVIEW_CHARS,
    ) -> EvidenceRecord:
        raw = str(output or "")
        args = dict(arguments or {})
        serialized_args = json.dumps(args, ensure_ascii=False, sort_keys=True)
        key_args = serialized_args[:500]
        content_hash = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:24]
        duplicate_of = ""
        for item in self.evidence:
            if item.content_hash == content_hash:
                duplicate_of = item.id
                break
        digest = hashlib.sha256(
            f"{tool}\0{serialized_args}\0{raw}".encode("utf-8", errors="replace")
        ).hexdigest()[:24]
        self.evidence_seq += 1
        if duplicate_of:
            preview = (
                f"[same raw output as {duplicate_of}; content_hash={content_hash}; "
                f"raw_size={len(raw)} chars]\n"
                "Body not repeated in active context. Use evidence_view on this id or the "
                "original evidence id if exact bytes are needed."
            )
        else:
            preview = make_evidence_preview(raw, preview_chars)
        record = EvidenceRecord(
            id=f"e{self.evidence_seq:03d}",
            target=target,
            tool=tool,
            arguments=args,
            key_args=key_args,
            status=status or parse_status_code(raw),
            summary=one_line(preview, 300),
            preview=preview,
            content=raw,
            truncated=bool(duplicate_of) or len(raw) > len(preview),
            fingerprint=digest,
            content_hash=content_hash,
            duplicate_of=duplicate_of,
        )
        self.evidence.append(record)
        if len(self.evidence) > MAX_STORED_EVIDENCE:
            del self.evidence[: MAX_STORED_EVIDENCE // 2]
        return record

    def record_tool_call(
        self,
        *,
        tool: str,
        arguments: dict[str, Any] | None,
        status: int = 0,
        evidence_id: str = "",
        summary: str = "",
        duration_ms: int = 0,
        ok: bool = True,
        error_type: str = "",
    ) -> ToolCallRecord:
        key_args = json.dumps(dict(arguments or {}), ensure_ascii=False, sort_keys=True)[:500]
        record = ToolCallRecord(
            tool=tool,
            key_args=key_args,
            status=status,
            evidence_id=evidence_id,
            summary=one_line(summary, 220),
            duration_ms=max(0, int(duration_ms or 0)),
            ok=bool(ok),
            error_type=one_line(error_type, 120),
        )
        self.tool_calls.append(record)
        if len(self.tool_calls) > MAX_STORED_TOOL_CALLS:
            del self.tool_calls[: MAX_STORED_TOOL_CALLS // 2]
        return record

    def count_recent_tool_call(
        self,
        *,
        tool: str,
        arguments: dict[str, Any] | None,
        window: int = 8,
    ) -> int:
        key_args = json.dumps(dict(arguments or {}), ensure_ascii=False, sort_keys=True)[:500]
        recent = self.tool_calls[-max(1, int(window or 1)) :]
        return sum(1 for item in recent if item.tool == tool and item.key_args == key_args)

    @staticmethod
    def _evidence_view_range(arguments: dict[str, Any] | None) -> tuple[str, int, int] | None:
        args = dict(arguments or {})
        evidence_id = str(args.get("evidence_id", "") or "").strip()
        if not evidence_id:
            return None
        try:
            start = max(0, int(args.get("offset", 0) or 0))
        except (TypeError, ValueError):
            start = 0
        try:
            limit = int(args.get("limit", DEFAULT_EVIDENCE_VIEW_CHARS))
        except (TypeError, ValueError):
            limit = DEFAULT_EVIDENCE_VIEW_CHARS
        if limit <= 0:
            return evidence_id, start, FULL_EVIDENCE_RANGE_END
        return evidence_id, start, start + limit

    def evidence_view_redundancy_reason(
        self,
        arguments: dict[str, Any] | None,
        *,
        window: int = 24,
    ) -> str:
        """Return a reason when an evidence_view range was already shown recently."""

        current = self._evidence_view_range(arguments)
        if current is None:
            return ""
        evidence_id, start, end = current
        for call in reversed(self.tool_calls[-max(1, int(window or 1)) :]):
            if call.tool != "evidence_view":
                continue
            try:
                previous_args = json.loads(call.key_args)
            except (TypeError, ValueError):
                continue
            previous = self._evidence_view_range(previous_args)
            if previous is None:
                continue
            previous_id, previous_start, previous_end = previous
            if previous_id == evidence_id and previous_start <= start and previous_end >= end:
                return (
                    f"evidence_view for {evidence_id} range {start}:{end} is already covered "
                    f"by recently viewed range {previous_start}:{previous_end}; use a new offset "
                    "or take a non-evidence action based on the existing content."
                )
        return ""

    def record_tool_health(
        self,
        *,
        tool: str,
        ok: bool,
        duration_ms: int = 0,
        error: str = "",
    ) -> ToolHealth:
        current = self.tool_health.get(tool) or ToolHealth(tool=tool)
        current.last_duration_ms = max(0, int(duration_ms or 0))
        current.updated_at = datetime.now().isoformat()
        if ok:
            current.status = "healthy"
            current.successes += 1
            current.consecutive_failures = 0
            current.last_error = ""
        else:
            current.status = "degraded"
            current.failures += 1
            current.consecutive_failures += 1
            current.last_error = one_line(error, 220)
        self.tool_health[tool] = current
        return current

    def record_progress_signal(
        self,
        *,
        kind: str,
        detail: str,
        tool: str = "",
        evidence_id: str = "",
    ) -> ProgressSignal:
        signal = ProgressSignal(
            kind=one_line(kind, 80),
            detail=one_line(detail, 260),
            tool=tool,
            evidence_id=evidence_id,
        )
        self.progress_signals.append(signal)
        if len(self.progress_signals) > MAX_STORED_PROGRESS_SIGNALS:
            del self.progress_signals[: MAX_STORED_PROGRESS_SIGNALS // 2]
        return signal

    def pin_fact(self, text: str, *, evidence_id: str = "") -> PinnedFact | None:
        fact_text = one_line(text, 260)
        if not fact_text:
            return None
        normalized = fact_text.lower()
        if any(item.text.lower() == normalized for item in self.pinned_facts[-MAX_STORED_PINNED_FACTS:]):
            return None
        fact = PinnedFact(text=fact_text, evidence_id=evidence_id)
        self.pinned_facts.append(fact)
        if len(self.pinned_facts) > MAX_STORED_PINNED_FACTS:
            del self.pinned_facts[: MAX_STORED_PINNED_FACTS // 2]
        return fact

    def add_correction_hint(self, hint: str) -> None:
        text = one_line(hint, 320)
        if not text:
            return
        if any(item.lower() == text.lower() for item in self.correction_hints):
            return
        self.correction_hints.append(text)
        self.correction_hints = self.correction_hints[-MAX_STORED_CORRECTION_HINTS:]

    def update_context_digest(self, summary: str, evidence_ids: list[str]) -> None:
        """Persist the latest prompt-safe context digest."""
        text = clip_text(summary.strip(), 14_000)
        self.context_digest = ContextDigest(
            summary=text,
            evidence_ids=list(dict.fromkeys(evidence_ids))[-32:],
        )
        # Keep the legacy field populated for restored sessions and old callers.
        self.compact_summary = text

    def record_context_compaction(
        self,
        *,
        purpose: str,
        reason: str,
        before_tokens: int,
        after_tokens: int,
        tool_tokens: int,
        removed_message_groups: int,
        retained_message_groups: int,
        evidence_ids: list[str],
    ) -> None:
        self.context_compactions.append(
            ContextCompactionEvent(
                purpose=one_line(purpose, 80),
                reason=one_line(reason, 160),
                before_tokens=max(0, int(before_tokens)),
                after_tokens=max(0, int(after_tokens)),
                tool_tokens=max(0, int(tool_tokens)),
                removed_message_groups=max(0, int(removed_message_groups)),
                retained_message_groups=max(0, int(retained_message_groups)),
                evidence_ids=list(dict.fromkeys(evidence_ids))[-32:],
            )
        )
        self.context_compactions = self.context_compactions[-MAX_STORED_CONTEXT_COMPACTIONS:]

    def record_verified_claim(self, claim: str, evidence_ids: list[str]) -> VerifiedClaim:
        self.claim_seq += 1
        record = VerifiedClaim(
            id=f"c{self.claim_seq:03d}",
            claim=claim.strip(),
            evidence_ids=[item for item in evidence_ids if self.get_evidence(item) is not None],
        )
        self.verified_claims.append(record)
        return record

    def reject_completion(self, reason: str) -> None:
        self.completion_rejections.append(one_line(reason, 320))
        self.completion_rejections = self.completion_rejections[-8:]

    def mark_complete(self, reason: str, *, final_answer: str = "", evidence_ids: list[str] | None = None) -> None:
        self.completed = True
        self.complete_reason = reason.strip()
        self.final_answer = final_answer.strip() or reason.strip()
        if evidence_ids:
            self.record_verified_claim(reason, evidence_ids)

    def ask_user(self, question: str) -> None:
        if question:
            self.pending_questions.append(question.strip())
            self.pending_questions = self.pending_questions[-8:]

    def get_evidence(self, evidence_id: str) -> EvidenceRecord | None:
        wanted = str(evidence_id or "").strip()
        return next((item for item in self.evidence if item.id == wanted), None)

    def evidence_ids(self) -> list[str]:
        return [item.id for item in self.evidence]

    def evidence_text(self) -> str:
        return "\n".join(item.content for item in self.evidence if item.content)

    def tool_call_summary(self, max_lines: int = 18) -> str:
        lines = [
            f"- {item.tool}({item.key_args}) -> {item.evidence_id or 'no-evidence'}"
            + (f" {item.duration_ms}ms" if item.duration_ms else "")
            + ("" if item.ok else f" failed:{item.error_type or item.status}")
            + (f": {item.summary}" if item.summary else "")
            for item in self.tool_calls[-max_lines:]
        ]
        return "\n".join(lines)

    def repeated_call_hint(self) -> str:
        """Return a soft loop hint; never acts as a stop condition."""

        if len(self.tool_calls) < 3:
            return ""
        recent = self.tool_calls[-6:]
        counts: dict[tuple[str, str], int] = {}
        for item in recent:
            key = (item.tool, item.key_args)
            counts[key] = counts.get(key, 0) + 1
        repeated = [key for key, count in counts.items() if count >= 3]
        if not repeated:
            return ""
        tool, key_args = repeated[-1]
        return (
            f"Loop hint: the recent action {tool}({key_args}) has repeated. "
            "Use a different argument, inspect saved evidence, or explain why repetition is necessary."
        )

    def format_evidence_list(self, limit: int = 20) -> str:
        items = self.evidence[-max(1, int(limit)) :]
        if not items:
            return "No evidence has been recorded yet."
        lines = []
        for item in items:
            size = f"{item.size} chars"
            truncated = ", preview truncated" if item.truncated else ""
            lines.append(
                f"{item.id}: tool={item.tool} status={item.status} size={size}{truncated}"
                + (f", same_as={item.duplicate_of}" if item.duplicate_of else "")
                + f" hash={item.content_hash or item.fingerprint}\n"
                f"  args={one_line(item.key_args, 180)}\n"
                f"  summary={item.summary}"
            )
        return "\n".join(lines)

    def format_evidence_search(
        self,
        query: str,
        *,
        evidence_id: str = "",
        regex: bool = False,
        context_chars: int = 180,
        limit: int = 12,
    ) -> str:
        """Search raw saved evidence and return bounded snippets with offsets."""

        pattern = str(query or "")
        if not pattern:
            return "evidence_search requires a non-empty query."
        try:
            max_hits = max(1, min(50, int(limit or 12)))
        except (TypeError, ValueError):
            max_hits = 12
        try:
            ctx = max(0, min(2000, int(context_chars or 180)))
        except (TypeError, ValueError):
            ctx = 180

        items = [self.get_evidence(evidence_id)] if evidence_id else list(self.evidence)
        records = [item for item in items if item is not None]
        hits: list[str] = []
        compiled: re.Pattern[str] | None = None
        if regex:
            try:
                compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            except re.error as exc:
                return f"Invalid regex for evidence_search: {exc}"

        for item in records:
            raw = item.content or ""
            if compiled is not None:
                matches = compiled.finditer(raw)
            else:
                escaped = re.escape(pattern)
                matches = re.finditer(escaped, raw, re.IGNORECASE)
            for match in matches:
                start = max(0, match.start() - ctx)
                end = min(len(raw), match.end() + ctx)
                snippet = raw[start:end].replace("\r\n", "\n")
                hits.append(
                    f"{item.id}@{match.start()}:{match.end()} tool={item.tool} "
                    f"status={item.status} hash={item.content_hash or item.fingerprint}\n"
                    f"{snippet}"
                )
                if len(hits) >= max_hits:
                    break
            if len(hits) >= max_hits:
                break

        if not hits:
            scope = f" in {evidence_id}" if evidence_id else ""
            return f"No raw evidence matches {pattern!r}{scope}."
        return (
            f"# evidence_search query={pattern!r} hits={len(hits)} "
            f"(context_chars={ctx})\n\n" + "\n\n---\n\n".join(hits)
        )

    def format_evidence_view(
        self,
        evidence_id: str,
        *,
        offset: int = 0,
        limit: int = DEFAULT_EVIDENCE_VIEW_CHARS,
    ) -> str:
        item = self.get_evidence(evidence_id)
        if item is None:
            return f"Evidence not found: {evidence_id}"
        start = max(0, int(offset or 0))
        raw = item.content or ""
        try:
            max_chars = int(limit)
        except (TypeError, ValueError):
            max_chars = DEFAULT_EVIDENCE_VIEW_CHARS
        if max_chars <= 0:
            max_chars = max(0, len(raw) - start)
        chunk = raw[start : start + max_chars]
        end = start + len(chunk)
        header = (
            f"{item.id}: tool={item.tool} status={item.status} "
            f"bytes={len(raw)} range={start}:{end}"
        )
        if end < len(raw):
            header += f" next_offset={end}"
        return f"{header}\n{chunk}"

    def to_prompt_summary(self, *, max_evidence: int = 12, max_steps: int = 10) -> str:
        """A bounded memory block for the model-led solver."""

        sections = [
            f"Goal: {self.goal or '(unset)'}",
            f"Origin: {self.origin or '(unset)'}",
        ]
        digest = getattr(self, "context_digest", None)
        if digest and digest.summary:
            sections.append(f"\nContext digest:\n{clip_text(digest.summary, 1800)}")
        elif self.compact_summary:
            sections.append(f"\nManual compact summary:\n{clip_text(self.compact_summary, 1800)}")
        if self.verified_claims:
            sections.append("\nVerified claims:")
            sections.extend(
                f"- {claim.id}: {one_line(claim.claim, 260)} "
                f"(evidence: {', '.join(claim.evidence_ids) or 'none'})"
                for claim in self.verified_claims[-8:]
            )
        if self.pinned_facts:
            sections.append("\nHigh-signal pinned facts:")
            sections.extend(
                f"- {fact.text}" + (f" ({fact.evidence_id})" if fact.evidence_id else "")
                for fact in self.pinned_facts[-16:]
            )
        degraded = [item for item in self.tool_health.values() if item.status == "degraded"]
        if degraded:
            sections.append("\nTool health:")
            sections.extend(
                f"- {item.tool}: degraded, failures={item.consecutive_failures}, "
                f"last={item.last_error or 'unknown'}"
                for item in sorted(degraded, key=lambda x: x.tool)[-8:]
            )
        if self.correction_hints:
            sections.append("\nDiagnostic notes (optional, not instructions):")
            sections.extend(f"- {item}" for item in self.correction_hints[-6:])
        if self.progress_signals:
            sections.append("\nRecent progress signals:")
            sections.extend(
                f"- {signal.kind}: {signal.detail}"
                + (f" ({signal.evidence_id})" if signal.evidence_id else "")
                for signal in self.progress_signals[-6:]
            )
        if self.completion_rejections:
            sections.append("\nEvidence-gate reminders:")
            sections.extend(f"- {item}" for item in self.completion_rejections[-4:])
        if self.steps:
            sections.append("\nRecent agent steps:")
            sections.extend(
                f"- #{step.index} reason={step.reason or '(not stated)'} "
                f"finding={step.observation or '(none)'} "
                f"tools={', '.join(step.tool_calls) or 'none'}"
                for step in self.steps[-max_steps:]
            )
        if self.evidence:
            sections.append("\nRecent evidence:")
            for item in self.evidence[-max_evidence:]:
                sections.append(
                    f"- {item.id} tool={item.tool} status={item.status} "
                    f"summary={item.summary} raw={item.size} chars"
                    + (f" same_as={item.duplicate_of}" if item.duplicate_of else "")
                    + f" hash={item.content_hash or item.fingerprint}"
                    + ("; use evidence_view/evidence_search for raw/chunks" if item.truncated else "")
                )
        else:
            sections.append("\nRecent evidence: none yet")
        call_summary = self.tool_call_summary(12)
        if call_summary:
            sections.append("\nRecent tool calls:")
            sections.append(call_summary)
        hint = self.repeated_call_hint()
        if hint:
            sections.append(f"\n{hint}")
        return "\n".join(sections)

    def get_summary(self) -> dict[str, object]:
        return {
            "completed": self.completed,
            "evidence": len(self.evidence),
            "tool_calls": len(self.tool_calls),
            "steps": len(self.steps),
            "verified_claims": len(self.verified_claims),
            "pinned_facts": len(self.pinned_facts),
            "progress_signals": len(self.progress_signals),
            "correction_hints": len(self.correction_hints),
            "pending_questions": len(self.pending_questions),
            "complete_reason": self.complete_reason,
        }
