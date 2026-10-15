"""Domain model leaf types — shared across all layers.

These types are pure data models with no dependencies on agent/ internals.
They were extracted from agent/context.py to eliminate reverse dependencies
where infrastructure layers (report/, plugins/, target_state/) imported
directly from the domain layer (agent/).

修改者: Nyaecho
修改时间: 2026-07-08
修改原因: 消除 V2/V3/V4 违规 — 基础设施层不应反向依赖领域层，
         将叶子类型提取到基础设施层 config/ 包中。
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, model_validator

from vulnclaw.findings.identity import canonical_endpoint, structured_finding_id
from vulnclaw.findings.types import EvidenceSnapshotRef, FindingAssessment, replace_snapshot_refs
from vulnclaw.i18n import I18nLoader, _

# ──────────────────────────────────────────────────────────────
# Enums
# ──────────────────────────────────────────────────────────────


class PentestPhase(str, Enum):
    """Language-neutral penetration-test phase identities."""

    IDLE = "idle"
    RECON = "recon"
    VULN_DISCOVERY = "vuln_discovery"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"

    @classmethod
    def _missing_(cls, value: object) -> Optional[PentestPhase]:
        """Migrate persisted display labels without making them identities.

        Older session files serialized localized enum values. Resolve those
        values through the translation catalog at the persistence boundary;
        every newly serialized value remains a canonical id.
        """
        if not isinstance(value, str):
            return None

        normalized = value.strip().lower().replace("-", "_").replace(" ", "_")
        for phase in cls:
            if normalized in {phase.value, phase.name.lower()}:
                return phase


        for lang in ("zh", "en"):
            translator = I18nLoader(lang)
            for phase in cls:
                if value == translator.t(f"phase.{phase.value}"):
                    return phase
        return None


def phase_canonical_id(phase: PentestPhase | str | None) -> Optional[str]:
    """Return the canonical id for a phase-like value, if valid.

    Only accepts canonical ids and enum members. Localized display labels are
    migrated to identities exclusively at the persistence boundary (see
    ``PentestPhase._missing_``); routing this runtime canonicalizer through
    that migration would leak translations back into phase identity.
    """
    if phase is None:
        return None
    if isinstance(phase, PentestPhase):
        return phase.value
    if not isinstance(phase, str):
        return None
    resolved = phase_from_canonical_id(phase)
    return resolved.value if resolved else None


def phase_from_canonical_id(canonical_id: str) -> Optional[PentestPhase]:
    """Resolve a canonical phase id, returning ``None`` for unknown ids."""
    normalized = canonical_id.strip().lower().replace("-", "_").replace(" ", "_")
    return next((phase for phase in PentestPhase if phase.value == normalized), None)


def phase_display_name(
    phase: PentestPhase | str,
    lang: Optional[str] = None,
) -> str:
    """Resolve a localized display label from a canonical phase identity."""
    canonical_id = phase_canonical_id(phase)
    if canonical_id is None:
        return str(phase)

    key = f"phase.{canonical_id}"
    if lang is None:

        return _(key)


    return I18nLoader(lang).t(key)


class StepStatus(str, Enum):
    """步骤执行状态."""

    SUCCESS = "success"  # 成功
    FAILURE = "failure"  # 失败
    SKIPPED = "skipped"  # 跳过
    INFO = "info"  # 信息收集


# ──────────────────────────────────────────────────────────────
# Pydantic Models
# ──────────────────────────────────────────────────────────────

# Typed evidence-reference kinds. ``sandbox_output`` refs land under
# ``evidence/sandbox/`` (produced by the sandbox PRD), ``http_capture`` refs are
# resolved against the traffic store via ``request_id`` (traffic-store PRD), and
# ``file`` refs point at any other artifact inside the per-run ``evidence/`` tree.
EvidenceKind = Literal["sandbox_output", "http_capture", "file"]


class EvidenceRef(BaseModel):
    """A typed pointer from a finding into the per-run ``evidence/`` tree.

    ``path`` is always relative to that tree so evidence stays portable across
    machines. ``request_id`` is the optional hook a traffic store resolves an
    ``http_capture`` against; it is ``None`` for refs that are self-contained
    files (``sandbox_output`` / ``file``).
    """

    kind: EvidenceKind = Field(description="sandbox_output | http_capture | file")
    path: str = Field(default="", description="Path relative to the per-run evidence/ tree")
    request_id: Optional[str] = Field(
        default=None, description="Traffic-store request id for http_capture refs"
    )


class VulnerabilityFinding(BaseModel):
    """A single vulnerability finding."""

    title: str = Field(description="Vulnerability title")
    severity: str = Field(default="Medium", description="Critical/High/Medium/Low/Info")
    vuln_type: str = Field(default="", description="Vulnerability type (SQLi, XSS, RCE, etc.)")
    description: str = Field(default="", description="Detailed description (what/where)")
    impact: str = Field(
        default="", description="Consequence / business risk (distinct from description)"
    )
    evidence: str = Field(default="", description="Proof/evidence of the finding")
    cve: Optional[str] = Field(default=None, description="Associated CVE ID")
    cvss: Optional[float] = Field(default=None, description="CVSS base score (0.0-10.0)")
    cwe: Optional[str] = Field(default=None, description="CWE identifier, e.g. 'CWE-89'")
    remediation: str = Field(default="", description="Fix recommendation")
    # ★ Structured location — ties findings to a concrete request/route or code site.
    target: str = Field(default="", description="Owning target (ties to the Target model)")
    endpoint: Optional[str] = Field(default=None, description="Affected URL/endpoint")
    method: Optional[str] = Field(default=None, description="HTTP method, e.g. 'POST'")
    code_location: Optional[str] = Field(
        default=None, description="file:line for repo/SAST-style findings"
    )
    # ★ Typed evidence references into the per-run evidence/ tree (alongside the
    # free-text ``evidence`` blob, which is retained for backward compatibility).
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    submission_id: str = Field(default="", description="Application-owned structured submission id")
    evidence_snapshots: list[EvidenceSnapshotRef] = Field(default_factory=list)
    verification_history: list[FindingAssessment] = Field(default_factory=list)
    assessment: FindingAssessment | None = None
    previous_verification: dict[str, Any] = Field(default_factory=dict)
    # ★ Optional skill-loading provenance (reserved by the skill-loading PRD);
    # mapped into finding metadata / SARIF ``properties`` when present.
    skill_provenance: Optional[dict[str, Any]] = Field(default=None)
    subagent_provenance: Optional[dict[str, Any]] = Field(
        default=None,
        description="Owning sub-agent task identity when this finding was merged",
    )
    poc_script: Optional[str] = Field(default=None, description="Generated PoC script path")
    evidence_level: str = Field(default="L1", description="L1-L4 evidence strength")
    lifecycle_status: str = Field(
        default="candidate",
        description="candidate/pending_verification/verified/rejected/needs_manual_review",
    )

    # ★ 漏洞验证状态追踪
    verified: bool = Field(default=False, description="是否已通过 PoC 验证")
    verification_status: str = Field(
        default="pending", description="验证状态: pending/verified/rejected"
    )
    verified_at: Optional[str] = Field(default=None, description="验证时间")
    verification_note: str = Field(default="", description="验证备注/排除原因")

    # ★ 漏洞唯一标识（用于去重）
    finding_id: str = Field(default="", description="漏洞唯一标识：vuln_type + target + location")

    @model_validator(mode="before")
    @classmethod
    def migrate_assessment(cls, value: Any) -> Any:
        if isinstance(value, dict) and "report_assessment" in value:
            value = dict(value)
            previous = value.pop("report_assessment")
            value.setdefault("assessment", previous)
        return value

    def model_post_init(self, *args, **kwargs) -> None:
        # Also recover saved findings whose references reused IDs across sessions.
        replace_snapshot_refs(self, self.evidence_snapshots)
        if self.submission_id:
            from vulnclaw.config.finding_similarity import normalize_vuln_type

            self.vuln_type = normalize_vuln_type(self.vuln_type)
            if self.endpoint:
                self.endpoint = canonical_endpoint(self.endpoint)
            if self.method:
                self.method = self.method.upper()
            self.finding_id = structured_finding_id(
                self.vuln_type, self.target, self.endpoint or self.code_location or self.target,
                self.method,
            )
        # ★ Generate the dedup identity FIRST, from the caller-supplied fields —
        # before the intake quarantine below rewrites the description. Otherwise the
        # injected warning text (which contains "/vuln_type/…") is picked up as a
        # bogus location and every bare finding collides on the same nonsense id.
        if not self.finding_id:
            self.finding_id = self._generate_finding_id()

        # ★ Intake quarantine (no hard rejection).
        # A finding with no evidence, no vuln_type and no remediation carries no
        # substantiating signal. For ANY severity we prefix the title, annotate the
        # description, and quarantine it as ``needs_manual_review`` — it stays in run
        # state / audit trail but is excluded from the report/SARIF gate until an
        # actual evidence chain is attached. (Previously this fired for High/Critical
        # only and did not set a lifecycle status.) The whole unit is skipped for a
        # finding that is already verified/rejected — an explicitly promoted finding
        # keeps its terminal status and is never re-stamped "[未验证]".
        is_bare = not self.evidence and not self.vuln_type and not self.remediation
        is_terminal = self.verified or self.verification_status in ("verified", "rejected")
        if is_bare and not is_terminal:
            prefix = _("finding.quarantine.prefix")
            if not self.title.startswith(("[未验证]", "[Unverified]")):
                self.title = f"{prefix} {self.title}"
            # Idempotency markers from both locales, so a finding stamped in one
            # language is never re-stamped when revalidated in the other.
            stamped = ("缺少验证证据" in self.description
                       or "no actual test result was attached" in self.description)
            if not stamped:
                self.description = (
                    _("finding.quarantine.description")
                    + (f" {self.description}" if self.description else "")
                )
            self.lifecycle_status = "needs_manual_review"

        self._sync_status_fields()

    def _sync_status_fields(self) -> None:
        """Keep lifecycle and evidence metadata consistent with verification state."""
        if self.verified or self.verification_status == "verified":
            self.verified = True
            self.verification_status = "verified"
            self.lifecycle_status = "verified"
            if self.evidence_level in ("", "L1", "L2", "L3"):
                self.evidence_level = "L4"
            return

        if self.verification_status == "rejected":
            self.verified = False
            self.lifecycle_status = "rejected"
            if self.evidence_level in ("", "L1", "L2"):
                self.evidence_level = "L3"
            return

        self.verified = False
        self.verification_status = "pending"
        if self.lifecycle_status == "needs_manual_review":
            if self.evidence_level in ("", "L1"):
                self.evidence_level = "L2"
            return
        if self.lifecycle_status == "candidate":
            self.evidence_level = self.evidence_level or "L1"
            return
        if self.evidence_level in ("", "L1"):
            self.lifecycle_status = "candidate"
            self.evidence_level = "L1"
        else:
            self.lifecycle_status = "pending_verification"

    def mark_manual_review(self, note: str = "", evidence_level: str = "L2") -> None:
        """Mark a finding as requiring manual review."""
        self.verified = False
        self.verification_status = "pending"
        self.lifecycle_status = "needs_manual_review"
        self.evidence_level = evidence_level
        if note:
            self.verification_note = note

    def _generate_finding_id(self) -> str:
        """Generate unique vulnerability identifier for deduplication.

        Key improvement: also checks the evidence field (populated by Layer 2
        auto-detection) in addition to description, since auto-detected findings
        put URLs/paths in evidence, not description.
        """
        location = ""
        # Try description first, then evidence (Layer 2 auto-findings put URLs there)
        for field in (self.description, self.evidence):
            if not field:
                continue
            url_match = re.search(r'https?://[^\s<>"\')\]]+', field)
            if url_match:
                location = url_match.group(0)
                break
            path_match = re.search(r'/[^\s<>"\')\]]+', field)
            if path_match:
                location = path_match.group(0)
                break

        # Use vuln_type as dedup key; location only if non-empty (avoids "SQL注入_")
        if location:
            return f"{self.vuln_type}_{location}"[:50]
        if self.vuln_type:
            return self.vuln_type[:50]
        # Bare finding (no vuln_type, no location): fall back to a title-derived key
        # so distinct placeholders stay distinct in state / findings.json audit.
        base_title = re.sub(r"^\[(?:未验证|Unverified)\]\s*", "", self.title).strip()
        return base_title[:50]

    def mark_verified(self, note: str = "", evidence_level: str = "L4") -> None:
        """标记漏洞为已验证."""
        self.verified = True
        self.verification_status = "verified"
        self.lifecycle_status = "verified"
        self.evidence_level = evidence_level
        self.verified_at = datetime.now().isoformat()
        self.verification_note = note

    def mark_rejected(self, reason: str, evidence_level: str = "L3") -> None:
        """标记漏洞为已拒绝（误报）."""
        self.verified = False
        self.verification_status = "rejected"
        self.lifecycle_status = "rejected"
        self.evidence_level = evidence_level
        self.verified_at = datetime.now().isoformat()
        self.verification_note = reason


class TaskConstraints(BaseModel):
    """Structured hard constraints for an autonomous pentest task."""

    allowed_ports: list[int] = Field(default_factory=list)
    blocked_ports: list[int] = Field(default_factory=list)
    allowed_hosts: list[str] = Field(default_factory=list)
    blocked_hosts: list[str] = Field(default_factory=list)
    allowed_paths: list[str] = Field(default_factory=list)
    blocked_paths: list[str] = Field(default_factory=list)
    allowed_actions: list[str] = Field(default_factory=list)
    blocked_actions: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    strict_mode: bool = Field(default=False)

    def is_empty(self) -> bool:
        return not any(
            [
                self.allowed_ports,
                self.blocked_ports,
                self.allowed_hosts,
                self.blocked_hosts,
                self.allowed_paths,
                self.blocked_paths,
                self.allowed_actions,
                self.blocked_actions,
                self.notes,
                self.strict_mode,
            ]
        )

    def to_prompt_block(self) -> str:
        """Render constraints into a stable prompt block for every round."""
        if self.is_empty():
            return ""

        lines = ["## 当前任务硬约束"]
        if self.allowed_ports:
            lines.append(f"- 仅允许测试端口: {', '.join(str(p) for p in self.allowed_ports)}")
        if self.blocked_ports:
            lines.append(f"- 禁止测试端口: {', '.join(str(p) for p in self.blocked_ports)}")
        if self.allowed_hosts:
            lines.append(f"- 仅允许测试主机: {', '.join(self.allowed_hosts)}")
        if self.blocked_hosts:
            lines.append(f"- 禁止测试主机: {', '.join(self.blocked_hosts)}")
        if self.allowed_paths:
            lines.append(f"- 仅允许测试路径: {', '.join(self.allowed_paths)}")
        if self.blocked_paths:
            lines.append(f"- 禁止测试路径: {', '.join(self.blocked_paths)}")
        if self.allowed_actions:
            lines.append(f"- 仅允许动作: {', '.join(self.allowed_actions)}")
        if self.blocked_actions:
            lines.append(f"- 禁止动作: {', '.join(self.blocked_actions)}")
        if self.notes:
            lines.append(f"- 其他限制: {'; '.join(self.notes)}")
        if self.strict_mode:
            lines.append("- 严格模式: 超出范围时只记录，不主动测试，不调用工具执行。")
        return "\n".join(lines)


class ConstraintViolationEvent(BaseModel):
    """Structured audit event for a blocked constraint violation."""

    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    kind: str = Field(default="constraint_violation")
    code: str = Field(default="", description="Stable violation code")
    severity: str = Field(default="medium", description="low | medium | high")
    source: str = Field(default="", description="command | phase | tool")
    action: str = Field(default="", description="Normalized action name")
    tool_name: str = Field(default="", description="Tool name when source=tool")
    phase: str = Field(default="", description="Current phase label")
    summary: str = Field(default="", description="Human-readable summary")
    detail: str = Field(default="", description="Detailed diagnostic message")


class StepRecord(BaseModel):
    """单个渗透步骤的结构化记录."""

    phase: PentestPhase = Field(description="所属阶段")
    round: int = Field(default=0, description="轮次")
    action: str = Field(default="", description="执行的动作（如端口扫描、漏洞探测）")
    target: str = Field(default="", description="目标（IP/URL/路径等）")
    result: str = Field(default="", description="执行结果摘要")
    status: StepStatus = Field(default=StepStatus.INFO, description="执行状态")
    detail: str = Field(default="", description="详细信息（可选）")

    def to_summary(self) -> str:
        """转换为可读的摘要行."""
        status_icon = {
            StepStatus.SUCCESS: "✅",
            StepStatus.FAILURE: "❌",
            StepStatus.SKIPPED: "⏭️",
            StepStatus.INFO: "ℹ️",
        }.get(self.status, "")

        result = self.result[:60] + ("..." if len(self.result) > 60 else "")
        return f"{status_icon} Round {self.round}: {self.action} → {result}"

    def to_brief(self) -> str:
        """转换为简短摘要（用于列表显示）."""
        return f"{self.action}: {self.result}"[:80]

    def to_legacy_string(self) -> str:
        """生成向后兼容的原始字符串格式."""
        status_icon = {
            StepStatus.SUCCESS: "✅",
            StepStatus.FAILURE: "❌",
            StepStatus.SKIPPED: "⏭️",
            StepStatus.INFO: "ℹ️",
        }.get(self.status, "")
        return f"Round {self.round}: {status_icon} {self.action} → {self.result}"

    @classmethod
    def from_legacy_string(cls, step_str: str, phase: PentestPhase = PentestPhase.IDLE) -> StepRecord:
        """从旧版字符串格式创建 StepRecord."""
        # 提取 Round 号
        round_match = re.search(r"Round\s*(\d+)", step_str)
        round_num = int(round_match.group(1)) if round_match else 0

        # 提取状态图标
        status = StepStatus.INFO
        if "✅" in step_str:
            status = StepStatus.SUCCESS
        elif "❌" in step_str:
            status = StepStatus.FAILURE
        elif "⏭️" in step_str:
            status = StepStatus.SKIPPED

        # 提取动作和结果
        action_match = re.search(r"[✅❌⏭️ℹ️]\s*(.+?)→", step_str)
        action = action_match.group(1).strip() if action_match else ""

        result_match = re.search(r"→\s*(.+)$", step_str)
        result = result_match.group(1).strip() if result_match else ""

        # 推断阶段
        inferred_phase = phase
        if "阶段切换" in step_str:
            for candidate in PentestPhase:
                if phase_display_name(candidate, "zh") in step_str:
                    inferred_phase = candidate
                    break

        return cls(
            phase=inferred_phase,
            round=round_num,
            action=action or step_str[:60],
            result=result,
            status=status,
            detail=step_str,
        )


# ──────────────────────────────────────────────────────────────
# Pure policy functions (no agent/ dependencies)
# ──────────────────────────────────────────────────────────────

PHASE_TO_ACTION: dict[PentestPhase, str] = {
    PentestPhase.RECON: "recon",
    PentestPhase.VULN_DISCOVERY: "scan",
    PentestPhase.EXPLOITATION: "exploit",
    PentestPhase.POST_EXPLOITATION: "post_exploitation",
    PentestPhase.REPORTING: "report",
}


def normalize_action_name(action: str) -> str:
    """Normalize action aliases into a shared policy namespace."""
    lowered = (action or "").strip().lower()
    aliases = {
        "run": "run",
        "recon": "recon",
        "scan": "scan",
        "exploit": "exploit",
        "post": "post_exploitation",
        "post_exploitation": "post_exploitation",
        "report": "report",
        "reporting": "report",
        "persistent": "persistent",
    }
    return aliases.get(lowered, lowered)


def validate_action_constraints(action: str, constraints: TaskConstraints) -> str | None:
    """Return a constraint violation message when a task action is out of scope."""
    if constraints.is_empty():
        return None

    normalized = normalize_action_name(action)
    allowed = [normalize_action_name(item) for item in constraints.allowed_actions]
    blocked = [normalize_action_name(item) for item in constraints.blocked_actions]

    # Composite commands (run, persistent) include all phases;
    # fine-grained enforcement happens inside the loop via phase/tool checks.
    if normalized in ("run", "persistent"):
        if normalized in blocked:
            return f"constraint_violation: command '{normalized}' is blocked by task constraints"
        return None

    if allowed and normalized not in allowed:
        return f"constraint_violation: command '{normalized}' is outside allowed actions [{', '.join(allowed)}]"

    if normalized in blocked:
        return f"constraint_violation: command '{normalized}' is blocked by task constraints"

    return None
