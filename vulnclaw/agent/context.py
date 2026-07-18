"""VulnClaw session context management — track pentest state across turns."""

from __future__ import annotations

import copy
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

from pydantic import BaseModel, Field, PrivateAttr

from vulnclaw.agent.blackboard import Blackboard
from vulnclaw.agent.reasoning_state import ReasoningState

# ──────────────────────────────────────────────────────────────
# 叶子类型已提取到 config/domain_models.py，此处重新导出以保持兼容。
# 修改者: Nyaecho
# 修改时间: 2026-07-08
# 修改原因: 消除 V2/V3/V4 违规 — 基础设施层不应反向依赖领域层。
# ──────────────────────────────────────────────────────────────
from vulnclaw.config.domain_models import (  # noqa: F401 — re-export
    CANONICAL_ID_TO_PHASE,
    PHASE_CANONICAL_ID,
    PHASE_DISPLAY_BY_LANG,
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
    """漏洞存储管理 — 负责漏洞的增删改查和去重。

    职责域:
    - 漏洞列表 (findings)
    - ID 缓存用于精确去重 (_finding_ids_cache)
    - 语义去重阈值 (semantic_dedup_threshold)

    去重策略:
    1. finding_id 精确 hash 匹配（快）
    2. 语义相似度匹配（捕获同一漏洞的不同表述），命中后保留证据更强者
    """

    target: Optional[str] = None
    findings: list[VulnerabilityFinding] = Field(default_factory=list)
    semantic_dedup_threshold: float = Field(
        default=0.75, description="语义去重的相似度阈值（0-1）"
    )
    # PrivateAttr 不受 Pydantic 字段命名限制，用于内部去重追踪
    _finding_ids_cache: set[str] = PrivateAttr(default_factory=set)

    def set_checkpoint_callback(
        self, callback: Callable[["SessionState", str], None] | None
    ) -> None:
        """Install a persistence callback fired at durable state boundaries."""
        self._checkpoint_callback = callback

    def _notify_checkpoint(self, reason: str) -> None:
        if self._checkpoint_callback is None:
            return
        self._checkpoint_callback(self, reason)

    def add_finding(self, finding: VulnerabilityFinding) -> bool:
        """添加漏洞发现，自动去重。

        Returns:
            True if finding was added, False if duplicate (skipped).
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
            print(f"[DEDUP] 跳过重复漏洞: {finding.title} (ID: {finding.finding_id})")
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
                    print(
                        f"[DEDUP-SEM] 语义重复，替换为证据更强的漏洞: "
                        f"{finding.title} 取代 {existing.title}"
                    )
                    self._finding_ids_cache.discard(existing.finding_id)
                    self._finding_ids_cache.add(finding.finding_id)
                    self.findings[idx] = finding
                    self._notify_checkpoint("finding_updated")
                else:
                    print(f"[DEDUP-SEM] 跳过语义重复漏洞: {finding.title}")
                return False

        # 附加 skill 溯源（若未显式提供且当前有活跃选择）。深拷贝以免其中的
        # references_loaded 列表与 active_skill_selection 共享 —— 否则之后
        # record_loaded_reference() 会追溯性地修改已记录漏洞的溯源。
        if finding.skill_provenance is None and self.active_skill_selection is not None:
            finding.skill_provenance = copy.deepcopy(self.active_skill_selection)

        # 添加到追踪集合和列表
        self._finding_ids_cache.add(finding.finding_id)
        self.findings.append(finding)
        self._notify_checkpoint("finding_added")
        return True

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
        return changed

    def record_loaded_reference(self, skill_name: str, ref_name: str) -> None:
        """Record a reference loaded via ``load_skill_reference`` onto provenance.

        Findings created after this call inherit the reference in their
        ``skill_provenance['references_loaded']``.
        """
        if self.active_skill_selection is None:
            return
        entry = f"{skill_name}/{ref_name}" if skill_name else ref_name
        loaded = self.active_skill_selection.setdefault("references_loaded", [])
        if entry and entry not in loaded:
            loaded.append(entry)

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
        dim_names = {
            "server": "维度一(服务器)",
            "website": "维度二(网站)",
            "domain": "维度三(域名)",
            "personnel": "维度四(人员)",
        }
        for dim, completed in self.recon_dimensions_completed.items():
            if dim == "personnel" and not self.recon_dimension4_active:
                continue
            name = dim_names.get(dim, dim)
            parts.append(f"{'✅' if completed else '❌'} {name}")
        incomplete = [
            dim
            for dim, done in self.recon_dimensions_completed.items()
            if (dim != "personnel" or self.recon_dimension4_active) and not done
        ]
        status = " | ".join(parts)
        if incomplete:
            status += f"\n→ 还有 {len(incomplete)} 个维度未检查，继续收集，不要标记 [DONE]"
        return status


class ReasoningSnapshot(BaseModel):
    """推理状态快照 — 存储推理引擎的核心数据。

    职责域:
    - 推理状态 (reasoning)
    - 黑板图 (board)
    - 反思快照 (reflexion_snapshot)
    - 已确认事实 (confirmed_facts)
    - 未验证假设 (unverified_assumptions)
    """

    reasoning: ReasoningState = Field(default_factory=ReasoningState)
    board: Blackboard = Field(default_factory=Blackboard)
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
            phase_name = record.phase.value
            if phase_name not in phases:
                phases[phase_name] = []
            phases[phase_name].append(record)

        phase_summaries = {}
        for phase_name, records in phases.items():
            phase_summaries[phase_name] = {
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
            board=self.board,
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
    board: Blackboard = Field(default_factory=Blackboard)
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
    semantic_dedup_threshold: float = Field(
        default=0.75, description="语义去重的相似度阈值（0-1）"
    )

    # ★ 漏洞去重追踪（PrivateAttr）
    _finding_ids_cache: set[str] = PrivateAttr(default_factory=set)
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
        """添加漏洞发现。

        [P17 重构] 同时更新 self.findings 和 self._finding_ids_cache，
        保持向后兼容性。去重逻辑委托给 VulnerabilityStore。
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
            print(f"[DEDUP] 跳过重复漏洞: {finding.title} (ID: {finding.finding_id})")
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
                    print(
                        f"[DEDUP-SEM] 语义重复，替换为证据更强的漏洞: "
                        f"{finding.title} 取代 {existing.title}"
                    )
                    self._finding_ids_cache.discard(existing.finding_id)
                    self._finding_ids_cache.add(finding.finding_id)
                    self.findings[idx] = finding
                else:
                    print(f"[DEDUP-SEM] 跳过语义重复漏洞: {finding.title}")
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
        # 记录阶段切换
        self.add_step(
            step=f"阶段切换 → {phase.value}",
            action="阶段切换",
            target=f"{old_phase.value} → {phase.value}",
            result=f"进入{phase.value}阶段",
            status=StepStatus.INFO,
        )
        self._notify_checkpoint("phase_transition")

    def save(self, path: Optional[Path] = None) -> Path:
        """保存会话状态到 JSON 文件。

        [P18 修改] 确保 executed_steps 被序列化到 JSON 中，
        保持向后兼容性。
        """
        if path is None:
            from vulnclaw.config.settings import SESSIONS_DIR

            safe_target = (self.target or "unknown").replace("/", "_").replace(":", "_")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = SESSIONS_DIR / f"{timestamp}_{safe_target}.json"

        path.parent.mkdir(parents=True, exist_ok=True)
        # [P18 兼容] 获取序列化数据并添加 executed_steps
        data = self.model_dump(mode="json")
        data["executed_steps"] = self.executed_steps
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return path

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

        return cls(**data)

# ==============================================================================
# [P17 重构结束] SessionState 组合模式重构
# ==============================================================================


class ContextManager:
    """Manages conversation context and session state."""

    def __init__(self, max_history: int = 200) -> None:
        self.max_history = max_history
        self.messages: list[dict[str, str]] = []
        self.state = SessionState()

    def add_user_message(self, content: str) -> None:
        """Add a user message to context."""
        self.messages.append({"role": "user", "content": content})
        self._trim()

    def add_assistant_message(self, content: str) -> None:
        """Add an assistant message to context."""
        self.messages.append({"role": "assistant", "content": content})
        self._trim()

    def add_system_message(self, content: str) -> None:
        """Add a system message (inserted at beginning)."""
        # System messages are handled separately in the API call
        pass

    def get_messages(self) -> list[dict[str, str]]:
        """Get conversation messages for API call."""
        return self.messages.copy()

    def reset(self) -> None:
        """Reset context and session state."""
        self.messages = []
        self.state = SessionState()

    def _trim(self) -> None:
        """Trim old messages to stay within limit.

        Instead of blindly dropping old messages, we compress them
        into a summary to preserve key discoveries for multi-round loops.
        """
        if len(self.messages) <= self.max_history:
            return

        # Keep the most recent 70% of messages intact
        keep_count = int(self.max_history * 0.7)
        recent = self.messages[-keep_count:]
        old = self.messages[:-keep_count]

        # Compress old messages into a summary instead of discarding
        summary = self._compress_messages(old)

        self.messages = []
        if summary:
            self.messages.append(
                {
                    "role": "system",
                    "content": f"[之前的会话摘要]\n{summary}",
                }
            )
        self.messages.extend(recent)

    @staticmethod
    def _compress_messages(messages: list[dict[str, str]]) -> str:
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
        if len(self.messages) > max_messages:
            self.messages = self.messages[-max_messages:]
