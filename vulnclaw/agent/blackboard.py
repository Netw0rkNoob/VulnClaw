"""黑板图模型 — Fact / Intent 双原语驱动的状态空间搜索。

渗透测试视为从 origin 向 goal 的有向状态空间搜索：
- Fact:   已确认的客观事实（探索的落脚点）
- Intent: 声明的探索方向（尚未执行的一步）；从一个或多个 Fact 出发，结论后产出一个新 Fact
- 终止条件由「目标达成 / 探索前沿耗尽 / 安全预算」决定，而非固定轮数

该模型是纯数据结构，挂载到 SessionState 持久化，由 solver.py 的 OODA 循环驱动。
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class IntentStatus(str, Enum):
    OPEN = "open"  # 已声明，待探索
    EXPLORING = "exploring"  # 正在探索
    CONCLUDED = "concluded"  # 已结论，产出了 Fact
    ABANDONED = "abandoned"  # 探索后未推进目标，放弃


class BoardFact(BaseModel):
    id: str
    description: str
    source: str = ""  # 来源（bootstrap / explore:i003 / hint ...）


class BoardIntent(BaseModel):
    id: str
    from_facts: list[str] = Field(default_factory=list)  # 出发的 Fact id
    description: str
    status: IntentStatus = IntentStatus.OPEN
    result_fact: str | None = None  # 结论后产出的 Fact id
    note: str = ""  # 放弃原因 / 备注


class ToolCallRecord(BaseModel):
    """已执行工具调用的紧凑记录——防止跨 intent 重复调用同一工具+同一参数。"""
    tool: str
    key_args: str = ""
    intent_id: str = ""
    status: int = 0
    note: str = ""


class Blackboard(BaseModel):
    """Fact/Intent 图。从 origin 增长到 goal。

    参考 Cairn：除了 Fact/Intent，还维护一份 **tool_calls 执行日志**，
    每次 explore 中调用的工具都会记录到这里。Reason 和 Explore 的上下文
    prompt 均包含此日志的摘要，使 LLM 能看到"已经做过什么"并避免重复。
    """

    origin: str = ""
    goal: str = ""
    facts: list[BoardFact] = Field(default_factory=list)
    intents: list[BoardIntent] = Field(default_factory=list)
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    completed: bool = False
    complete_reason: str = ""
    fact_seq: int = Field(default=0, exclude=True)
    intent_seq: int = Field(default=0, exclude=True)

    def model_post_init(self, __context: Any) -> None:
        if self.facts and self.fact_seq == 0:
            nums = [int(f.id[1:]) for f in self.facts if f.id[1:].isdigit()]
            self.fact_seq = max(nums) if nums else len(self.facts)
        if self.intents and self.intent_seq == 0:
            nums = [int(i.id[1:]) for i in self.intents if i.id[1:].isdigit()]
            self.intent_seq = max(nums) if nums else len(self.intents)

    # ── Fact ────────────────────────────────────────────────────────
    def add_fact(self, description: str, source: str = "") -> BoardFact:
        self.fact_seq += 1
        fact = BoardFact(id=f"f{self.fact_seq:03d}", description=description.strip(), source=source)
        self.facts.append(fact)
        return fact

    def get_fact(self, fact_id: str) -> BoardFact | None:
        return next((f for f in self.facts if f.id == fact_id), None)

    def fact_ids(self) -> list[str]:
        return [f.id for f in self.facts]

    # ── Intent ──────────────────────────────────────────────────────
    def add_intent(self, description: str, from_facts: list[str] | None = None) -> BoardIntent:
        self.intent_seq += 1
        valid_from = [fid for fid in (from_facts or []) if self.get_fact(fid)]
        intent = BoardIntent(
            id=f"i{self.intent_seq:03d}",
            from_facts=valid_from,
            description=description.strip(),
        )
        self.intents.append(intent)
        return intent

    def get_intent(self, intent_id: str) -> BoardIntent | None:
        return next((i for i in self.intents if i.id == intent_id), None)

    def open_intents(self) -> list[BoardIntent]:
        return [i for i in self.intents if i.status == IntentStatus.OPEN]

    def active_intents(self) -> list[BoardIntent]:
        """未结论的 Intent（open + exploring），用于判断探索前沿是否耗尽。"""
        return [i for i in self.intents if i.status in (IntentStatus.OPEN, IntentStatus.EXPLORING)]

    def claim_intent(self, intent_id: str) -> BoardIntent | None:
        intent = self.get_intent(intent_id)
        if intent and intent.status == IntentStatus.OPEN:
            intent.status = IntentStatus.EXPLORING
        return intent

    def conclude_intent(self, intent_id: str, fact_description: str, source: str = "") -> BoardFact | None:
        """探索得到了有价值的结论 → 产出一个 Fact 并链接。"""
        intent = self.get_intent(intent_id)
        if intent is None:
            return None
        fact = self.add_fact(fact_description, source=source or f"explore:{intent_id}")
        intent.status = IntentStatus.CONCLUDED
        intent.result_fact = fact.id
        return fact

    def abandon_intent(self, intent_id: str, note: str = "") -> BoardIntent | None:
        intent = self.get_intent(intent_id)
        if intent is not None:
            intent.status = IntentStatus.ABANDONED
            if note:
                intent.note = note
        return intent

    def mark_complete(self, reason: str) -> None:
        self.completed = True
        self.complete_reason = reason.strip()

    # ── Tool call memory ───────────────────────────────────────────
    def record_tool_call(
        self, tool: str, key_args: str, intent_id: str = "",
        status: int = 0, note: str = "",
    ) -> None:
        self.tool_calls.append(ToolCallRecord(
            tool=tool, key_args=key_args[:200], intent_id=intent_id,
            status=status, note=note[:120],
        ))
        if len(self.tool_calls) > 200:
            del self.tool_calls[:100]

    def has_called(self, tool: str, key_args: str) -> bool:
        return any(
            tc.tool == tool and tc.key_args == key_args[:200]
            for tc in self.tool_calls
        )

    def tool_call_summary(self, max_lines: int = 40) -> str:
        if not self.tool_calls:
            return ""
        seen: dict[str, str] = {}
        for tc in self.tool_calls:
            key = f"{tc.tool}({tc.key_args})"
            if key not in seen:
                seen[key] = f"  {tc.intent_id or '-'}: {tc.tool}({tc.key_args})" + (
                    f" → {tc.note}" if tc.note else ""
                )
        lines = list(seen.values())[-max_lines:]
        return "\n".join(lines)

    # ── 渲染 ────────────────────────────────────────────────────────
    def to_prompt_graph(self, *, include_concluded: bool = True) -> str:
        """把图渲染成给 LLM 阅读的紧凑文本（YAML 风格）。"""
        lines: list[str] = [f"goal: {self.goal or '(未设定)'}", f"origin: {self.origin or '(未设定)'}"]

        lines.append("facts:")
        if self.facts:
            for fact in self.facts:
                src = f"  ({fact.source})" if fact.source else ""
                lines.append(f"  - {fact.id}: {fact.description}{src}")
        else:
            lines.append("  (暂无)")

        lines.append("intents:")
        shown = self.intents if include_concluded else self.active_intents()
        if shown:
            for intent in shown:
                frm = f" from={','.join(intent.from_facts)}" if intent.from_facts else ""
                res = f" -> {intent.result_fact}" if intent.result_fact else ""
                note = f"  // {intent.note}" if intent.note else ""
                lines.append(f"  - {intent.id} [{intent.status.value}]{frm}{res}: {intent.description}{note}")
        else:
            lines.append("  (暂无)")

        tc_summary = self.tool_call_summary(30)
        if tc_summary:
            lines.append("executed_tools (禁止重复调用已执行的工具+参数):")
            lines.append(tc_summary)

        return "\n".join(lines)

    def get_summary(self) -> dict[str, object]:
        status_counts: dict[str, int] = {}
        for intent in self.intents:
            status_counts[intent.status.value] = status_counts.get(intent.status.value, 0) + 1
        return {
            "completed": self.completed,
            "facts": len(self.facts),
            "intents": len(self.intents),
            "open_intents": len(self.open_intents()),
            "intent_status_counts": status_counts,
            "complete_reason": self.complete_reason,
        }
