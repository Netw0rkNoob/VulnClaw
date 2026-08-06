"""VulnClaw session context management — track pentest state across turns."""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

from pydantic import AliasChoices, BaseModel, Field, PrivateAttr

from vulnclaw.agent.agent_state import AgentState
from vulnclaw.agent.reasoning_state import ReasoningState
from vulnclaw.config.secret_redaction import redact_secrets

# ──────────────────────────────────────────────────────────────
# 叶子类型已提取到 config/domain_models.py，此处重新导出以保持兼容。
# 修改者: Nyaecho
# 修改时间: 2026-07-08
# 修改原因: 消除 V2/V3/V4 违规 — 基础设施层不应反向依赖领域层。
# ──────────────────────────────────────────────────────────────
from vulnclaw.config.domain_models import (  # noqa: F401 — re-export
    PHASE_TO_ACTION,
    ConstraintViolationEvent,
    EvidenceKind,
    EvidenceRef,
    PentestPhase,
    StepRecord,
    StepStatus,
    TaskConstraints,
    VulnerabilityFinding,
    normalize_action_name,
    phase_canonical_id,
    phase_display_name,
    phase_from_canonical_id,
    validate_action_constraints,
)
from vulnclaw.i18n import _

logger = logging.getLogger(__name__)

# ==============================================================================
# [P17 重构] 子状态类定义
# 修改者: Nyaecho
# 修改时间: 2026-07-08
# 修改原因: SessionState 字段过多（20+），违反单一职责原则
#          拆分为 6 个子状态类，每个类负责一个明确的职责域
# 辅助注释: 这些子状态类通过组合模式被 SessionState 持有，
#          外部代码通过 @property 代理访问，保持向后兼容
# ==============================================================================

class SessionConfig(BaseModel):
    """会话基本配置 — 管理会话的生命周期和目标信息。

    职责域:
    - 会话目标 (target)
    - 当前阶段 (phase)
    - 时间戳 (started_at)
    - 恢复信息 (resume_summary, resume_meta)
    - 任务约束 (task_constraints)
    """

    target: Optional[str] = None
    phase: PentestPhase = PentestPhase.IDLE
    started_at: str = Field(default_factory=lambda: datetime.now().isoformat())
    resume_summary: str = Field(default="", description="恢复时注入的历史成果摘要")
    resume_meta: dict[str, Any] = Field(default_factory=dict, description="恢复元信息")
    task_constraints: TaskConstraints = Field(default_factory=TaskConstraints)


class VulnerabilityStore(BaseModel):
    """漏洞查询视图 — 按验证/生命周期状态过滤 findings。

    职责域:
    - 漏洞列表 (findings)：由 SessionState 写入并同步
    - ID 缓存用于精确去重 (_finding_ids_cache)

    说明:
    新增与去重的唯一实现位于 ``SessionState.add_finding``。本类只提供只读的
    分类查询（get_verified/pending/... ），由 ``SessionState`` 委托调用。
    """

    target: Optional[str] = None
    findings: list[VulnerabilityFinding] = Field(default_factory=list)
    semantic_dedup_threshold: float = Field(
        default=0.75, description="语义去重的相似度阈值（0-1）"
    )
    # PrivateAttr 不受 Pydantic 字段命名限制，用于内部去重追踪
    _finding_ids_cache: set[str] = PrivateAttr(default_factory=set)

    def get_verified_findings(self) -> list[VulnerabilityFinding]:
        """获取已验证的漏洞列表。"""
        return [f for f in self.findings if f.verified]

    def get_rejected_findings(self) -> list[VulnerabilityFinding]:
        """获取已拒绝的漏洞列表（误报）。"""
        return [f for f in self.findings if f.verification_status == "rejected"]

    def get_pending_findings(self) -> list[VulnerabilityFinding]:
        """获取待验证的漏洞列表。"""
        return [f for f in self.findings if f.verification_status == "pending"]

    def get_candidate_findings(self) -> list[VulnerabilityFinding]:
        """获取低置信度候选漏洞。"""
        return [f for f in self.findings if f.lifecycle_status == "candidate"]

    def get_pending_verification_findings(self) -> list[VulnerabilityFinding]:
        """获取有待验证证据的漏洞。"""
        return [f for f in self.findings if f.lifecycle_status == "pending_verification"]

    def get_manual_review_findings(self) -> list[VulnerabilityFinding]:
        """获取需要人工审核的漏洞。"""
        return [
            f
            for f in self.findings
            if (
                f.lifecycle_status == "needs_manual_review"
                or (
                    not f.verified
                    and f.verification_status != "rejected"
                    and f.severity in {"Critical", "High"}
                    and f.lifecycle_status in {"candidate", "pending_verification"}
                )
            )
        ]


class ReconState(BaseModel):
    """侦察状态管理 — 跟踪信息收集进度。

    职责域:
    - 侦察数据 (recon_data)
    - 四维模型完成度 (recon_dimensions_completed)
    - 维度四激活状态 (recon_dimension4_active)

    四维模型:
    - 维度一: 服务器信息（端口/真实 IP/OS/中间件/数据库）
    - 维度二: 网站信息（架构/指纹/WAF/敏感目录/源码泄露/旁站/C 段）
    - 维度三: 域名信息（WHOIS/ICP 备案/子域名/DNS/证书透明度）
    - 维度四: 人员信息（条件触发 — 仅明确社工需求时激活）
    """

    recon_data: dict[str, Any] = Field(default_factory=dict)
    recon_dimensions_completed: dict[str, bool] = Field(
        default_factory=lambda: {
            "server": False,
            "website": False,
            "domain": False,
            "personnel": False,
        },
        description="信息收集四维模型完成度追踪",
    )
    recon_dimension4_active: bool = Field(
        default=False, description="维度四（人员信息）是否被激活"
    )

    def add_recon_subdomain(self, subdomain: str) -> None:
        """记录发现的子域名到 recon_data['subdomains']。"""
        if "subdomains" not in self.recon_data:
            self.recon_data["subdomains"] = []
        if subdomain and subdomain not in self.recon_data["subdomains"]:
            self.recon_data["subdomains"].append(subdomain)

    def mark_recon_dimension(self, dimension: str) -> None:
        """标记侦察维度为已完成。

        Args:
            dimension: 'server', 'website', 'domain', 'personnel' 之一
        """
        if dimension in self.recon_dimensions_completed:
            self.recon_dimensions_completed[dimension] = True

    def is_recon_complete(self) -> bool:
        """检查所有活跃的侦察维度是否至少完成一次。

        维度四（人员信息）仅在激活时检查。
        """
        for dim, completed in self.recon_dimensions_completed.items():
            if dim == "personnel" and not self.recon_dimension4_active:
                continue
            if not completed:
                return False
        return True

    def get_recon_status_text(self) -> str:
        """获取人类可读的侦察维度完成状态。"""

        parts = []
        for dim, completed in self.recon_dimensions_completed.items():
            if dim == "personnel" and not self.recon_dimension4_active:
                continue
            # Use i18n catalog for dimension names so they localize properly
            name = _(f"agent.recon.dimension.{dim}")
            parts.append(f"{'✅' if completed else '❌'} {name}")
        incomplete = [
            dim
            for dim, done in self.recon_dimensions_completed.items()
            if (dim != "personnel" or self.recon_dimension4_active) and not done
        ]
        status = " | ".join(parts)
        if incomplete:
            # Localize the incomplete status instruction
            status += "\n" + _("agent.recon.status_incomplete_instruction", count=len(incomplete))
        return status


class ReasoningSnapshot(BaseModel):
    """推理状态快照 — 存储推理引擎的核心数据。

    职责域:
    - 推理状态 (reasoning)
    - 研究状态 (research)
    - 反思快照 (reflexion_snapshot)
    - 已确认事实 (confirmed_facts)
    - 未验证假设 (unverified_assumptions)
    """

    reasoning: ReasoningState = Field(default_factory=ReasoningState)
    agent_state: AgentState = Field(
        default_factory=AgentState,
        validation_alias=AliasChoices("agent_state", "research", "board"),
    )
    reflexion_snapshot: dict[str, Any] = Field(default_factory=dict)
    confirmed_facts: list[str] = Field(
        default_factory=list, description="已通过工具验证确认的事实"
    )
    unverified_assumptions: list[str] = Field(
        default_factory=list, description="推理中基于但未验证的假设"
    )

    def add_confirmed_fact(self, fact: str) -> None:
        """添加已确认事实（通过工具输出验证）。"""
        if fact and fact not in self.confirmed_facts:
            self.confirmed_facts.append(fact)
        if fact:
            self.reasoning.add_fact(
                key=self._fact_key_from_text(fact),
                value=fact,
                source="confirmed_fact",
                confidence=0.9,
            )

    def _fact_key_from_text(self, fact: str) -> str:
        """从事实文本推断事实类型键。"""
        text = fact.lower()
        if "cve-" in text:
            return "cve"
        if "http://" in text or "https://" in text:
            return "url"
        if "port" in text or "端口" in fact:
            return "port"
        if "server" in text or "x-powered-by" in text:
            return "service"
        if "waf" in text:
            return "waf"
        return "confirmed_fact"

    def add_assumption(self, assumption: str) -> None:
        """添加未验证假设。"""
        if assumption and assumption not in self.unverified_assumptions:
            self.unverified_assumptions.append(assumption)

    @property
    def research(self) -> AgentState:
        """Backward-compatible alias for old serialized snapshot names."""

        return self.agent_state

    @research.setter
    def research(self, value: AgentState | dict[str, Any]) -> None:
        self.agent_state = value if isinstance(value, AgentState) else AgentState.model_validate(value)


class ConstraintManager(BaseModel):
    """约束管理 — 追踪约束违规事件。

    职责域:
    - 约束违规消息列表 (constraint_violations)
    - 结构化约束违规事件 (constraint_violation_events)
    """

    constraint_violations: list[str] = Field(default_factory=list)
    constraint_violation_events: list[ConstraintViolationEvent] = Field(
        default_factory=list
    )

    def add_constraint_violation(self, message: str) -> None:
        """记录约束违规审计事件。"""
        if not message:
            return
        if message not in self.constraint_violations:
            self.constraint_violations.append(message)
        elif self.constraint_violations and self.constraint_violations[-1] != message:
            self.constraint_violations.append(message)
        # 保留最近 20 条
        self.constraint_violations = self.constraint_violations[-20:]

    def add_constraint_violation_event(
        self,
        *,
        source: str,
        action: str = "",
        tool_name: str = "",
        code: str = "",
        severity: str = "medium",
        summary: str,
        detail: str = "",
        phase: str = "",
    ) -> None:
        """记录结构化约束违规审计事件。"""
        event = ConstraintViolationEvent(
            source=source,
            action=action,
            tool_name=tool_name,
            code=code,
            severity=severity,
            phase=phase,
            summary=summary,
            detail=detail or summary,
        )
        self.constraint_violation_events.append(event)
        self.constraint_violation_events = self.constraint_violation_events[-20:]
        self.add_constraint_violation(summary)


class ExecutionHistory(BaseModel):
    """执行历史 — 记录渗透测试的执行步骤和笔记。

    [P18 重构] 采用 step_records 作为主要记录格式：
    - step_records: 结构化步骤记录（主要数据源）
    - executed_steps: @property 兼容层，从 step_records 派生
    - notes: 会话笔记

    修改者: Nyaecho
    修改时间: 2026-07-08
    修改原因: 统一三套并行状态追踪系统，消除数据冗余
    辅助注释: executed_steps 现为只读属性，所有写入应通过 add_step() 进行
    """

    # [P18 修改] 移除 executed_steps 字段，改为 @property
    step_records: list[StepRecord] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    @property
    def executed_steps(self) -> list[str]:
        """[P18 兼容层] 从 step_records 生成原始字符串列表。

        向后兼容所有消费者（prompt构建、报告生成、持久化等）。
        每次访问时动态生成，确保数据一致性。
        """
        return [r.to_legacy_string() for r in self.step_records]

    def add_step(
        self,
        step: str,
        action: str = "",
        target: str = "",
        result: str = "",
        status: StepStatus = StepStatus.INFO,
        detail: str = "",
        phase: PentestPhase = PentestPhase.IDLE,
    ) -> None:
        """记录执行步骤。

        [P18 修改] 只写入 step_records，不再写入 executed_steps。
        executed_steps 通过 @property 从 step_records 动态生成。

        Args:
            step: 原始步骤字符串（向后兼容）
            action: 简短动作描述
            target: 动作目标
            result: 结果摘要
            status: 执行状态
            detail: 详细信息
            phase: 当前阶段
        """
        # 保留原始步骤（向后兼容），连续去重避免标题刷屏
        if not self.executed_steps or self.executed_steps[-1] != step:
            self.executed_steps.append(step)

        # 创建结构化记录
        if action:
            record = StepRecord(
                phase=phase,
                round=len(self.executed_steps),
                action=action,
                target=target,
                result=result or step[:60],
                status=status,
                detail=detail,
            )
            self.step_records.append(record)
        self._notify_checkpoint("step_complete")

    def add_note(self, note: str) -> None:
        """添加会话笔记，过滤代码/符号噪音。"""
        # 拒绝主要是代码/符号的笔记 — 这些会污染证据提取
        chinese = re.findall(r"[\u4e00-\u9fff]", note)
        code_symbols = re.findall(
            r"[{}()=+*/<>\-\\[\\]|;|import |def |return |print\(|requests\.|socket\.|re\.|sys\.]",
            note,
        )
        if len(note) > 20 and len(code_symbols) > len(chinese) * 0.5:
            return
        # 拒绝非常短的笔记
        if len(note) < 5 or note in ("---", "**", ">>>", "..."):
            return
        self.notes.append(note)

    def get_step_summary(self) -> dict[str, Any]:
        """生成攻击路径摘要。

        [P18 修改] 移除回退逻辑，只使用 step_records。
        executed_steps 现为 @property，从 step_records 派生。
        """
        if self.step_records:
            return self._build_step_summary_from_records()
        return {"total_steps": 0, "phases": {}, "key_findings": []}

    def _build_step_summary_from_records(self) -> dict[str, Any]:
        """从结构化 step_records 构建摘要。"""
        phases: dict[str, list[StepRecord]] = {}
        for record in self.step_records:
            phase_id = record.phase.value
            if phase_id not in phases:
                phases[phase_id] = []
            phases[phase_id].append(record)

        phase_summaries = {}
        for phase_id, records in phases.items():
            phase_summaries[phase_id] = {
                "display": phase_display_name(phase_id),
                "count": len(records),
                "actions": list(set(r.action for r in records)),
                "success_count": len([r for r in records if r.status == StepStatus.SUCCESS]),
                "failure_count": len([r for r in records if r.status == StepStatus.FAILURE]),
                "key_results": [r.to_brief() for r in records if r.status == StepStatus.SUCCESS][
                    :5
                ],
            }

        key_findings = [
            r.to_brief() for r in self.step_records if r.status == StepStatus.SUCCESS and r.result
        ][:10]

        return {
            "total_steps": len(self.step_records),
            "phases": phase_summaries,
            "key_findings": key_findings,
        }




# ==============================================================================
# [P17 重构结束] 子状态类定义
# ==============================================================================


# ==============================================================================
# [P17 重构] SessionState 使用组合模式重构
# 修改者: Nyaecho
# 修改时间: 2026-07-08
# 修改原因: SessionState 原有 22 个字段，违反单一职责原则
#          采用组合模式，将职责委托给 6 个子状态类
# 辅助注释: 保持所有原有字段的 @property 代理，确保向后兼容
#          子状态实例作为 PrivateAttr，不影响序列化
#          save()/load() 方法保持不变，JSON 格式兼容
# ==============================================================================

class SessionState(BaseModel):
    """Full session state for a pentest engagement.

    [P17 重构] 采用组合模式，内部使用 6 个子状态类:
    - SessionConfig: 会话配置
    - VulnerabilityStore: 漏洞管理
    - ReconState: 侦察状态
    - ReasoningSnapshot: 推理状态
    - ConstraintManager: 约束管理
    - ExecutionHistory: 执行历史

    所有原有字段通过 @property 代理保持向后兼容。
    """

    # ★ 子状态实例（PrivateAttr，不影响序列化）
    _config: SessionConfig = PrivateAttr(default_factory=SessionConfig)
    _vulnerabilities: VulnerabilityStore = PrivateAttr(default_factory=VulnerabilityStore)
    _recon: ReconState = PrivateAttr(default_factory=ReconState)
    _reasoning_snapshot: ReasoningSnapshot = PrivateAttr(default_factory=ReasoningSnapshot)
    _constraints: ConstraintManager = PrivateAttr(default_factory=ConstraintManager)
    _history: ExecutionHistory = PrivateAttr(default_factory=ExecutionHistory)

    # ★ 原有字段保留用于序列化兼容，实际值存储在子状态中
    # 注意: 这些字段在 model_dump() 时会被序列化，但实际读写通过 @property 代理

    def model_post_init(self, __context: Any) -> None:
        """初始化后同步字段值到子状态。"""
        # 从序列化数据恢复子状态
        self._config = SessionConfig(
            target=self.target,
            phase=self.phase,
            started_at=self.started_at,
            resume_summary=self.resume_summary,
            resume_meta=self.resume_meta,
            task_constraints=self.task_constraints,
        )
        self._vulnerabilities = VulnerabilityStore(
            target=self.target,
            findings=self.findings,
            semantic_dedup_threshold=self.semantic_dedup_threshold,
        )
        self._recon = ReconState(
            recon_data=self.recon_data,
            recon_dimensions_completed=self.recon_dimensions_completed,
            recon_dimension4_active=self.recon_dimension4_active,
        )
        self._reasoning_snapshot = ReasoningSnapshot(
            reasoning=self.reasoning,
            agent_state=self.agent_state,
            reflexion_snapshot=self.reflexion_snapshot,
            confirmed_facts=self.confirmed_facts,
            unverified_assumptions=self.unverified_assumptions,
        )
        self._constraints = ConstraintManager(
            constraint_violations=self.constraint_violations,
            constraint_violation_events=self.constraint_violation_events,
        )
        self._history = ExecutionHistory(
            step_records=self.step_records,
            notes=self.notes,
        )

    # ==========================================================================
    # 字段定义（用于序列化兼容）
    # ==========================================================================

    target: Optional[str] = None
    phase: PentestPhase = PentestPhase.IDLE
    started_at: str = Field(default_factory=lambda: datetime.now().isoformat())
    resume_summary: str = Field(default="", description="恢复时注入的历史成果摘要")
    resume_meta: dict[str, Any] = Field(default_factory=dict, description="恢复元信息")
    task_constraints: TaskConstraints = Field(default_factory=TaskConstraints)
    constraint_violations: list[str] = Field(default_factory=list)
    constraint_violation_events: list[ConstraintViolationEvent] = Field(default_factory=list)
    reasoning: ReasoningState = Field(default_factory=ReasoningState)
    agent_state: AgentState = Field(
        default_factory=AgentState,
        validation_alias=AliasChoices("agent_state", "research", "board"),
    )
    reflexion_snapshot: dict[str, Any] = Field(default_factory=dict)
    findings: list[VulnerabilityFinding] = Field(default_factory=list)
    recon_data: dict[str, Any] = Field(default_factory=dict)
    # [P18 修改] executed_steps 改为 @property，从 step_records 派生
    # 不再作为字段定义，而是通过 @property 动态生成
    step_records: list[StepRecord] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    confirmed_facts: list[str] = Field(default_factory=list, description="已通过工具验证确认的事实")
    unverified_assumptions: list[str] = Field(
        default_factory=list, description="推理中基于但未验证的假设"
    )
    recon_dimensions_completed: dict[str, bool] = Field(
        default_factory=lambda: {
            "server": False,
            "website": False,
            "domain": False,
            "personnel": False,
        },
        description="信息收集四维模型完成度追踪",
    )
    recon_dimension4_active: bool = Field(default=False, description="维度四（人员信息）是否被激活")
    # ★ Active skill selection for this turn/child task — structured provenance
    # source. Stored as a plain dict to avoid importing the resolver here.
    active_skill_selection: Optional[dict[str, Any]] = Field(
        default=None, description="Active SkillSelection.to_provenance() for the current turn"
    )
    # ★ Run events emitted whenever the active skill selection changes.
    skill_selection_events: list[dict[str, Any]] = Field(
        default_factory=list, description="Audit log of skill-selection changes"
    )
    subagent_events: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Bounded durable projection of sub-agent runtime events",
    )
    subagent_evidence_provenance: dict[str, dict[str, Any]] = Field(
        default_factory=dict,
        description="Parent evidence id to originating sub-agent task identity",
    )
    semantic_dedup_threshold: float = Field(
        default=0.75, description="语义去重的相似度阈值（0-1）"
    )
    session_kind: str = Field(
        default="parent", description="Session owner kind: parent, group_leader, or leaf"
    )
    run_id: str = Field(default="", description="Owning solve/runtime identifier")
    parent_session_id: str = Field(
        default="", description="Parent session identifier for sub-agent checkpoints"
    )
    task_id: str = Field(default="", description="Sub-agent task identifier")
    lifecycle_status: str = Field(
        default="", description="Last persisted sub-agent lifecycle status"
    )

    # ★ 漏洞去重追踪（PrivateAttr）
    _finding_ids_cache: set[str] = PrivateAttr(default_factory=set)
    _content_hash: str = PrivateAttr(default="")
    _save_path: Optional[Path] = PrivateAttr(default=None)
    _checkpoint_transform: Callable[
        ["SessionState", dict[str, Any]], dict[str, Any]
    ] | None = PrivateAttr(default=None)
    _checkpoint_callback: Callable[["SessionState", str], None] | None = PrivateAttr(
        default=None
    )

    def set_checkpoint_callback(
        self, callback: Callable[["SessionState", str], None] | None
    ) -> None:
        """Install a persistence callback fired at durable state boundaries."""
        self._checkpoint_callback = callback

    def _notify_checkpoint(self, reason: str) -> None:
        if self._checkpoint_callback is None:
            return
        self._checkpoint_callback(self, reason)

    @property
    def research(self) -> AgentState:
        """Compatibility alias for pre-AgentState integrations."""

        return self.agent_state

    @research.setter
    def research(self, value: AgentState | dict[str, Any]) -> None:
        self.agent_state = value if isinstance(value, AgentState) else AgentState.model_validate(value)
        self._reasoning_snapshot.agent_state = self.agent_state

    # ==========================================================================
    # @property 代理（保持向后兼容）
    # ==========================================================================

    @property
    def executed_steps(self) -> list[str]:
        """[P18 兼容层] 从 step_records 生成原始字符串列表。

        向后兼容所有消费者（prompt构建、报告生成、持久化等）。
        每次访问时动态生成，确保数据一致性。
        """
        return [r.to_legacy_string() for r in self.step_records]

    @executed_steps.setter
    def executed_steps(self, value: list[str]) -> None:
        """[P18 兼容层] 允许设置 executed_steps（向后兼容）。

        将旧格式字符串列表转换为 step_records。
        """
        self.step_records = [
            StepRecord.from_legacy_string(s, self.phase) for s in value
        ]
        # 同步到子状态
        self._history.step_records = self.step_records

    # 注意: 其他字段已经是直接可访问的
    # 子状态类的方法将通过委托方法调用

    # ==========================================================================
    # 委托方法（委托给子状态类）
    # ==========================================================================

    def add_finding(self, finding: VulnerabilityFinding) -> bool:
        """添加漏洞发现，自动去重（新增/去重的唯一实现所在处）。

        去重策略:
        1. finding_id 精确 hash 匹配（快）
        2. 语义相似度匹配（捕获同一漏洞的不同表述），命中后保留证据更强者

        写入 self.findings / self._finding_ids_cache，并把同一引用同步给
        VulnerabilityStore（只读查询视图）。成功新增或替换时触发 checkpoint，
        使「发现漏洞」成为一个可持久化的进度边界。
        """
        # 生成 finding_id（如果还没有）
        if hasattr(finding, "_sync_status_fields"):
            finding._sync_status_fields()
        if not finding.finding_id:
            finding.finding_id = finding._generate_finding_id()

        # Tie the finding to the owning target when the caller didn't set one.
        if not finding.target and self.target:
            finding.target = self.target

        # 第一层：finding_id 精确去重
        if finding.finding_id in self._finding_ids_cache:
            logger.debug("跳过重复漏洞: %s (ID: %s)", finding.title, finding.finding_id)
            return False

        # 第二层：语义相似度去重
        from vulnclaw.agent.finding_similarity import (
            _evidence_strength,
            finding_similarity,
        )

        for idx, existing in enumerate(self.findings):
            if finding_similarity(finding, existing) >= self.semantic_dedup_threshold:
                # 命中语义重复：保留证据更强者
                if _evidence_strength(finding) > _evidence_strength(existing):
                    logger.debug(
                        "语义重复，替换为证据更强的漏洞: %s 取代 %s",
                        finding.title,
                        existing.title,
                    )
                    self._finding_ids_cache.discard(existing.finding_id)
                    self._finding_ids_cache.add(finding.finding_id)
                    self.findings[idx] = finding
                    self._notify_checkpoint("finding_updated")
                else:
                    logger.debug("跳过语义重复漏洞: %s", finding.title)
                return False

        # 附加 skill 溯源（若未显式提供且当前有活跃选择）。深拷贝以免其中的
        # references_loaded 列表与 active_skill_selection 共享 —— 否则之后
        # record_loaded_reference() 会追溯性地修改已记录漏洞的溯源。
        if finding.skill_provenance is None and self.active_skill_selection is not None:
            finding.skill_provenance = copy.deepcopy(self.active_skill_selection)

        # 添加到追踪集合和列表
        self._finding_ids_cache.add(finding.finding_id)
        self.findings.append(finding)

        # 同步到子状态
        self._vulnerabilities.findings = self.findings
        self._vulnerabilities._finding_ids_cache = self._finding_ids_cache

        self._notify_checkpoint("finding_added")
        return True

    def get_verified_findings(self) -> list[VulnerabilityFinding]:
        """获取已验证的漏洞列表，委托给 VulnerabilityStore。"""
        return self._vulnerabilities.get_verified_findings()

    def get_rejected_findings(self) -> list[VulnerabilityFinding]:
        """获取已拒绝的漏洞列表，委托给 VulnerabilityStore。"""
        return self._vulnerabilities.get_rejected_findings()

    def get_pending_findings(self) -> list[VulnerabilityFinding]:
        """获取待验证的漏洞列表，委托给 VulnerabilityStore。"""
        return self._vulnerabilities.get_pending_findings()

    def get_candidate_findings(self) -> list[VulnerabilityFinding]:
        """获取候选漏洞，委托给 VulnerabilityStore。"""
        return self._vulnerabilities.get_candidate_findings()

    def get_pending_verification_findings(self) -> list[VulnerabilityFinding]:
        """获取待验证漏洞，委托给 VulnerabilityStore。"""
        return self._vulnerabilities.get_pending_verification_findings()

    def get_manual_review_findings(self) -> list[VulnerabilityFinding]:
        """获取需要人工审核的漏洞，委托给 VulnerabilityStore。"""
        return self._vulnerabilities.get_manual_review_findings()

    def add_recon_subdomain(self, subdomain: str) -> None:
        """记录发现的子域名。

        [P17 重构] 同时更新 self.recon_data，保持向后兼容性。
        """
        if "subdomains" not in self.recon_data:
            self.recon_data["subdomains"] = []
        if subdomain and subdomain not in self.recon_data["subdomains"]:
            self.recon_data["subdomains"].append(subdomain)
        # 同步到子状态
        self._recon.recon_data = self.recon_data

    def mark_recon_dimension(self, dimension: str) -> None:
        """标记侦察维度为已完成。

        [P17 重构] 同时更新 self.recon_dimensions_completed，保持向后兼容性。
        """
        if dimension in self.recon_dimensions_completed:
            self.recon_dimensions_completed[dimension] = True
            # 同步到子状态
            self._recon.recon_dimensions_completed = self.recon_dimensions_completed

    def is_recon_complete(self) -> bool:
        """检查侦察是否完成，委托给 ReconState。"""
        return self._recon.is_recon_complete()

    def get_recon_status_text(self) -> str:
        """获取侦察状态文本，委托给 ReconState。"""
        return self._recon.get_recon_status_text()

    def add_constraint_violation(self, message: str) -> None:
        """记录约束违规。

        [P17 重构] 同时更新 self.constraint_violations，保持向后兼容性。
        """
        if not message:
            return
        if message not in self.constraint_violations:
            self.constraint_violations.append(message)
        elif self.constraint_violations and self.constraint_violations[-1] != message:
            self.constraint_violations.append(message)
        # 保留最近 20 条
        self.constraint_violations = self.constraint_violations[-20:]
        # 同步到子状态
        self._constraints.constraint_violations = self.constraint_violations

    def add_constraint_violation_event(
        self,
        *,
        source: str,
        action: str = "",
        tool_name: str = "",
        code: str = "",
        severity: str = "medium",
        summary: str,
        detail: str = "",
    ) -> None:
        """记录结构化约束违规事件。

        [P17 重构] 同时更新 self.constraint_violation_events，保持向后兼容性。
        """
        phase_str = self.phase.value if hasattr(self.phase, "value") else str(self.phase)
        event = ConstraintViolationEvent(
            source=source,
            action=action,
            tool_name=tool_name,
            code=code,
            severity=severity,
            phase=phase_str,
            summary=summary,
            detail=detail or summary,
        )
        self.constraint_violation_events.append(event)
        self.constraint_violation_events = self.constraint_violation_events[-20:]
        self.add_constraint_violation(summary)
        # 同步到子状态
        self._constraints.constraint_violation_events = self.constraint_violation_events

    def add_step(
        self,
        step: str,
        action: str = "",
        target: str = "",
        result: str = "",
        status: StepStatus = StepStatus.INFO,
        detail: str = "",
    ) -> None:
        """记录执行步骤。

        [P18 修改] 只写入 step_records，不再写入 executed_steps。
        executed_steps 现为 @property，从 step_records 动态生成。
        """
        # [P18 修改] 始终创建结构化记录，使用 step 作为 action 的默认值
        record = StepRecord(
            phase=self.phase,
            round=len(self.step_records) + 1,
            action=action or step[:60],
            target=target,
            result=result or step[:60],
            status=status,
            detail=detail,
        )
        self.step_records.append(record)
        # 同步到子状态
        self._history.step_records = self.step_records

    def get_step_summary(self) -> dict[str, Any]:
        """生成攻击路径摘要，委托给 ExecutionHistory。"""
        return self._history.get_step_summary()

    def add_note(self, note: str) -> None:
        """添加会话笔记。

        [P17 重构] 同时更新 self.notes，保持向后兼容性。
        """
        # 拒绝主要是代码/符号的笔记
        chinese = re.findall(r"[\u4e00-\u9fff]", note)
        code_symbols = re.findall(
            r"[{}()=+*/<>\-\\[\\]|;|import |def |return |print\(|requests\.|socket\.|re\.|sys\.]",
            note,
        )
        if len(note) > 20 and len(code_symbols) > len(chinese) * 0.5:
            return
        # 拒绝非常短的笔记
        if len(note) < 5 or note in ("---", "**", ">>>", "..."):
            return
        self.notes.append(note)
        # 同步到子状态
        self._history.notes = self.notes

    def set_active_skill_selection(self, provenance: Optional[dict[str, Any]]) -> bool:
        """Record the active skill selection; emit a run event when it changes.

        Args:
            provenance: A ``SkillSelection.to_provenance()`` dict (or None).

        Returns:
            True if the selection changed from the previous turn.
        """
        prev = self.active_skill_selection
        changed = (prev or {}).get("primary") != (provenance or {}).get("primary") or (
            (prev or {}).get("supporting") != (provenance or {}).get("supporting")
        )
        # Same bundle as last turn: carry over references already loaded under it
        # so provenance keeps a complete record across turns.
        if not changed and prev is not None and provenance is not None:
            loaded = prev.get("references_loaded")
            if loaded and not provenance.get("references_loaded"):
                provenance = {**provenance, "references_loaded": list(loaded)}
        self.active_skill_selection = provenance
        if changed:
            event = {
                "kind": "skill_selection_changed" if provenance is not None else "skill_selection_cleared",
                "timestamp": datetime.now().isoformat(),
                "primary": (provenance or {}).get("primary"),
                "supporting": (provenance or {}).get("supporting", []),
                "reason": (provenance or {}).get("reason", ""),
                "confidence": (provenance or {}).get("confidence", 0.0),
            }
            self.skill_selection_events.append(event)
            self.skill_selection_events = self.skill_selection_events[-50:]
        self._notify_checkpoint("skill_selection_changed")
        return changed

    def record_loaded_reference(self, skill_name: str, ref_name: str) -> None:
        """Track a reference loaded under the current skill selection."""
        if self.active_skill_selection is None:
            return
        entry = f"{skill_name}/{ref_name}" if skill_name else ref_name
        loaded = self.active_skill_selection.setdefault("references_loaded", [])
        if entry and entry not in loaded:
            loaded.append(entry)

    def add_confirmed_fact(self, fact: str) -> None:
        """添加已确认事实。

        [P17 重构] 同时更新 self.confirmed_facts 和 self.reasoning，
        保持向后兼容性。
        """
        if fact and fact not in self.confirmed_facts:
            self.confirmed_facts.append(fact)
        if fact:
            self.reasoning.add_fact(
                key=self._fact_key_from_text(fact),
                value=fact,
                source="confirmed_fact",
                confidence=0.9,
            )
        # 同步到子状态
        self._reasoning_snapshot.confirmed_facts = self.confirmed_facts
        self._reasoning_snapshot.reasoning = self.reasoning

    def _fact_key_from_text(self, fact: str) -> str:
        """从事实文本推断事实类型键。"""
        text = fact.lower()
        if "cve-" in text:
            return "cve"
        if "http://" in text or "https://" in text:
            return "url"
        if "port" in text or "端口" in fact:
            return "port"
        if "server" in text or "x-powered-by" in text:
            return "service"
        if "waf" in text:
            return "waf"
        return "confirmed_fact"

    def add_assumption(self, assumption: str) -> None:
        """添加未验证假设。"""
        if assumption and assumption not in self.unverified_assumptions:
            self.unverified_assumptions.append(assumption)
        # 同步到子状态
        self._reasoning_snapshot.unverified_assumptions = self.unverified_assumptions

    def get_constraints_prompt_block(self) -> str:
        """获取约束提示块，委托给 TaskConstraints。"""
        return self.task_constraints.to_prompt_block()

    def advance_phase(self, phase: PentestPhase) -> None:
        """切换到新阶段。"""

        old_phase = self.phase
        self.phase = phase
        old_display = phase_display_name(old_phase)
        new_display = phase_display_name(phase)
        # 记录阶段切换
        self.add_step(
            step=_("step.phase_transition", phase=new_display),
            action=_("step.phase_transition.action"),
            target=f"{old_display} → {new_display}",
            result=_("step.phase_transition.result", phase=new_display),
            status=StepStatus.INFO,
        )
        self._notify_checkpoint("phase_transition")

    def save(self, path: Optional[Path] = None) -> Path:
        """保存会话状态到 JSON 文件。

        [P18 修改] 确保 executed_steps 被序列化到 JSON 中，
        保持向后兼容性。
        [Perf] 对比 MD5 内容哈希，跳过未变更的写入。
        """
        if path is None and self._save_path is not None:
            path = self._save_path
        if path is None:
            from vulnclaw.config.settings import SESSIONS_DIR

            safe_target = (self.target or "unknown").replace("/", "_").replace(":", "_")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = SESSIONS_DIR / f"{timestamp}_{safe_target}.json"
        else:
            path = Path(path)
        self._save_path = path

        path.parent.mkdir(parents=True, exist_ok=True)
        # [P18 兼容] 获取序列化数据并添加 executed_steps
        data = self.model_dump(mode="json")
        if self._checkpoint_transform is not None:
            data = self._checkpoint_transform(self, data)
        data["executed_steps"] = self.executed_steps
        content = json.dumps(data, ensure_ascii=False, indent=2)
        # 修改者: security-hardening pass (plaintext credential persistence fix)
        # 修改原因: this session dump includes raw tool call arguments/results
        # verbatim -- a captured Authorization header, Set-Cookie, or a
        # brute_force_login success carries a real, reusable credential for
        # the target straight onto disk with zero redaction. Applied once
        # here (not per-field) so it covers wherever a secret ended up in
        # this deeply nested, varied structure -- see
        # config/secret_redaction.py for the exact patterns and their limits.
        content = redact_secrets(content)

        content_hash = hashlib.md5(content.encode("utf-8")).hexdigest()
        if content_hash == self._content_hash:
            return path
        self._content_hash = content_hash

        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    def set_save_path(self, path: Path) -> None:
        """Pin future no-argument saves to one collision-free checkpoint."""

        self._save_path = Path(path)

    @classmethod
    def load(cls, path: Path) -> "SessionState":
        """从 JSON 文件加载会话状态。

        [P18 修改] 处理旧格式 JSON（包含 executed_steps 字段），
        将其转换为 step_records 格式。
        """
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # [P18 兼容] 如果只有 executed_steps，转换为 step_records
        if "executed_steps" in data and "step_records" not in data:
            data["step_records"] = [
                StepRecord.from_legacy_string(s) for s in data["executed_steps"]
            ]

        # [P18 兼容] 移除 executed_steps 字段，避免 Pydantic 验证错误
        data.pop("executed_steps", None)

        state = cls(**data)
        state.set_save_path(path)
        return state

# ==============================================================================
# [P17 重构结束] SessionState 组合模式重构
# ==============================================================================


class ContextManager:
    """Manages conversation context and session state."""

    def __init__(
        self,
        max_history: int = 200,
        memory_store: Any = None,
        *,
        max_tokens: int = 32000,
        search_max_chars: int = 6000,
    ) -> None:
        self.max_history = max(1, int(max_history))
        self.max_tokens = max(256, int(max_tokens))
        self.search_max_chars = max(256, int(search_max_chars))
        self.messages: list[dict[str, Any]] = []
        self.state = SessionState()
        self.memory_store = memory_store

    def add_user_message(self, content: str) -> None:
        """Add a user message to context."""
        self.messages.append({"role": "user", "content": content})
        self._trim()

    def add_assistant_message(self, content: str) -> None:
        """Add an assistant message to context."""
        self.messages.append({"role": "assistant", "content": content})
        self._trim()

    def add_message(self, message: dict[str, Any]) -> None:
        """Add a raw chat message to context.

        Tool-call transcripts need fields such as ``tool_calls`` and
        ``tool_call_id``.  Keeping the original Chat Completions message shape
        lets later model turns see the same cause/effect structure that produced
        the evidence, instead of only a lossy text summary.
        """
        if not isinstance(message, dict):
            return
        role = str(message.get("role", "") or "").strip()
        if not role:
            return
        stored_message = copy.deepcopy(message)
        if role == "tool":
            stored_message = self._offload_large_tool_message(stored_message)
        self.messages.append(stored_message)
        self._trim()

    def add_system_message(self, content: str) -> None:
        """Add a system message (inserted at beginning)."""
        # System messages are handled separately in the API call
        pass

    def get_messages(self) -> list[dict[str, Any]]:
        """Get conversation messages for API call."""
        return copy.deepcopy(self.messages)

    def reset(self) -> None:
        """Reset context and session state."""
        self.messages = []
        self.state = SessionState()
        if self.memory_store is not None:
            new_scope = getattr(self.memory_store, "new_scope", None)
            if callable(new_scope):
                new_scope()

    def _memory_scope(self) -> str:
        return str(getattr(self.memory_store, "session_id", "") or "")

    def _archive_messages(self, messages: list[dict[str, Any]], *, kind: str) -> str:
        if not messages or self.memory_store is None:
            return ""
        try:
            return str(
                self.memory_store.archive_messages(
                    copy.deepcopy(messages),
                    scope=self._memory_scope(),
                    target=str(self.state.target or ""),
                    kind=kind,
                )
                or ""
            )
        except (OSError, ValueError, TypeError) as exc:
            logger.warning("Cold-memory archive failed; retaining hot history: %s", exc)
            return ""

    def _offload_large_tool_message(self, message: dict[str, Any]) -> dict[str, Any]:
        from vulnclaw.agent.token_counter import estimate_message_tokens

        if self.memory_store is None or estimate_message_tokens(message) <= self.max_tokens // 2:
            return message
        record_id = self._archive_messages([message], kind="large_tool_result")
        if not record_id:
            return message
        content = str(message.get("content", "") or "")
        preview = content[:2000]
        if len(content) > len(preview):
            preview += "..."
        message["content"] = (
            f"[cold-memory:{record_id}] Large tool result archived. "
            f"Use memory_search with query '{record_id}' for a bounded excerpt.\n{preview}"
        )
        return message

    def _over_hot_limit(self, messages: list[dict[str, Any]]) -> bool:
        from vulnclaw.agent.token_counter import estimate_tokens

        return len(messages) > self.max_history or estimate_tokens(messages) > self.max_tokens

    def _trim(self) -> None:
        """Spill old messages to cold memory at the hot-history cap.

        Normal request-time compaction is driven by the token budget manager.
        This remains a safety net for callers that keep adding messages without
        issuing an LLM request.
        """
        if not self._over_hot_limit(self.messages):
            return

        from vulnclaw.agent.token_counter import group_conversation_turns, group_tool_exchanges

        candidate = list(self.messages)
        turns = group_conversation_turns(candidate)
        archived_messages: list[dict[str, Any]] = []
        while self._over_hot_limit(candidate) and len(turns) > 1:
            archived = turns.pop(0)
            archived_messages.extend(archived)
            candidate = candidate[len(archived) :]

        # A single automated subtask can itself contain hundreds of tool
        # exchanges. Keep its user instruction as a hot anchor, then spill the
        # oldest complete exchanges until the window is bounded.
        exchanges = group_tool_exchanges(candidate)
        while self._over_hot_limit(candidate) and len(exchanges) > 2:
            remove_at = 1 if exchanges[0][0].get("role") == "user" else 0
            archived = exchanges.pop(remove_at)
            archived_messages.extend(archived)
            candidate = [message for exchange in exchanges for message in exchange]

        if not archived_messages:
            return
        if self.memory_store is not None and not self._archive_messages(
            archived_messages, kind="history"
        ):
            return
        self.messages = candidate

    def search_cold_memory(self, query: str, *, limit: int = 5) -> list[dict[str, Any]]:
        """Retrieve relevant archived turns only when explicitly requested."""
        if self.memory_store is None:
            return []
        return self.memory_store.search_messages(
            query,
            limit=limit,
            max_chars=self.search_max_chars,
            scope=self._memory_scope(),
            target=str(self.state.target or ""),
        )

    @staticmethod
    def _is_context_digest_message(message: dict[str, Any]) -> bool:
        content = str(message.get("content", "") or "")
        return message.get("role") == "system" and content.startswith("[context digest")

    def replace_history_with_digest(
        self,
        digest_message: dict[str, Any],
        recent_messages: list[dict[str, Any]],
    ) -> None:
        """Atomically replace older history with a prompt-safe context digest."""
        cleaned_recent = [
            copy.deepcopy(message)
            for message in recent_messages
            if isinstance(message, dict) and not self._is_context_digest_message(message)
        ]
        self.messages = [copy.deepcopy(digest_message), *cleaned_recent]

    def compact_messages(self, *, max_recent: int = 24, note: str = "") -> str:
        """Compact older conversation message groups for `/compact` or safety fallback."""
        from vulnclaw.agent.token_counter import group_messages

        groups = group_messages(self.messages)
        if len(groups) <= max_recent:
            return "No compaction needed."

        recent_groups: list[list[dict[str, Any]]] = []
        recent_count = 0
        while groups and recent_count < max_recent:
            group = groups.pop()
            recent_groups.insert(0, group)
            recent_count += len(group)
        recent = [message for group in recent_groups for message in group]
        old = [message for group in groups for message in group]
        summary = self._compress_messages(old) or "(older conversation omitted)"
        if note:
            summary = f"{note}\n{summary}"
        digest = {"role": "system", "content": f"[context digest v1]\n{summary}"}
        self.replace_history_with_digest(digest, recent)
        agent_state = getattr(self.state, "agent_state", None)
        if agent_state is not None:
            evidence_ids = [item.id for item in getattr(agent_state, "evidence", [])[-12:]]
            if hasattr(agent_state, "update_context_digest"):
                agent_state.update_context_digest(summary, evidence_ids)
            else:
                agent_state.compact_summary = summary
        return summary

    @staticmethod
    def _compress_messages(messages: list[dict[str, Any]]) -> str:
        """Compress a list of messages into a concise summary.

        Extracts key findings, tool results, and discoveries from the
        conversation history so the LLM doesn't completely lose context.
        """
        key_parts = []

        for msg in messages:
            content = msg.get("content", "")
            # Extract tool call/result information — these contain actual findings
            if "调用工具:" in content or "工具结果:" in content:
                key_parts.append(content[:300])

            # Extract lines that look like findings/discoveries
            for line in content.split("\n"):
                stripped = line.strip()
                if any(
                    marker in stripped
                    for marker in [
                        "[+]",
                        "[!]",
                        "[-]",
                        "发现",
                        "漏洞",
                        "flag",
                        "CVE",
                        "端口",
                        "开放",
                        "服务",
                        "路径",
                        "泄露",
                        "注入",
                        "Status:",
                        "Headers:",
                        "Body",
                        # ★ Negative/failure markers — critical for CTF to avoid repeating
                        "失败",
                        "无效",
                        "没有",
                        "返回相同",
                        "被拦截",
                        "未成功",
                        "不存在",
                        "错误",
                        "404",
                        "timeout",
                        # ★ Confirmed fact markers — verified by actual tool output
                        "已确认",
                        "确认",
                        "验证成功",
                        "verified",
                        "confirmed",
                        # ★ Assumption markers — things the LLM assumed but didn't verify
                        "假设",
                        "应该",
                        "可能",
                        "推测",
                        "猜测",
                        "估计",
                    ]
                ):
                    key_parts.append(stripped[:200])

        if not key_parts:
            return ""

        # Limit total summary size to avoid context bloat
        summary = "\n".join(key_parts)
        if len(summary) > 3000:
            summary = summary[:3000] + "\n...(更多历史记录已省略)"

        return summary

    def trim_messages(self, max_messages: int = 20) -> None:
        """Forcefully trim conversation history to a specific size.

        Used when context overflow causes repeated LLM errors.
        """
        original_limit = self.max_history
        try:
            self.max_history = max(1, max_messages)
            self._trim()
        finally:
            self.max_history = original_limit
