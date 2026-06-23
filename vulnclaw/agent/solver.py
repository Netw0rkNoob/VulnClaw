"""目标驱动的 OODA 求解循环 — 用黑板图替代固定轮数工作流。

循环结构（无固定轮数）：
  1. 用 origin/goal 播种初始 Fact。
  2. REASON：读全图 → 判断目标是否达成 / 提出新的探索 Intent / 不提出。
  3. EXPLORE：领取一个 Intent，用工具实际执行，把确认的结论写回为一个新 Fact。
  4. 终止条件：目标达成 / 探索前沿耗尽（无 Intent 且 Reason 不再提出）/ 触达安全预算。

安全预算（max_steps）只是防止失控的兜底上限，不是工作流阶段计数；
正常情况下循环会在「目标达成」或「前沿耗尽」时提前结束。
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from vulnclaw.agent.blackboard import Blackboard, BoardIntent, IntentStatus
from vulnclaw.agent.llm_client import build_chat_completion_kwargs, call_llm_auto
from vulnclaw.agent.think_filter import strip_think_tags

# 探索阶段判定「已推进/已确认结论」的信号（宽泛匹配，避免漏判有进展的 intent）
_ADVANCE_MARKERS = [
    "确认",
    "成功",
    "拿到",
    "获取到",
    "提取到",
    "flag{",
    "flag ",
    "绕过成功",
    "回显",
    "漏洞存在",
    "发现",
    "返回200",
    "返回 200",
    "status: 200",
    "未授权",
    "无需认证",
    "接口可访问",
    "信息泄露",
    "关键发现",
    "重大发现",
    "暴露",
    "泄露",
    "200 ok",
    "cors",
    "可写入",
    "可上传",
    "可下载",
    "弱口令",
    "注入点",
    "xss",
    "sql inject",
]
# 探索阶段判定「该方向走不通」的信号
_DEAD_END_MARKERS = [
    "不存在",
    "无法",
    "失败",
    "走不通",
    "没有发现",
    "无注入",
    "无回显",
    "排除",
]
# 完成理由里的否定表述——模型把「未达成」写进完成字段时据此识别并拒绝
_NEGATION_MARKERS = [
    "未达到",
    "未达成",
    "未记录",
    "未发现",
    "未完成",
    "未能",
    "尚未",
    "没有",
    "不足以",
    "无法证明",
    "无法确认",
    "不能证明",
    "不满足",
]


def _has_negation(text: str) -> bool:
    """完成理由中是否含否定表述（说明实际未达成）。"""
    return any(m in (text or "") for m in _NEGATION_MARKERS)


_current_worker: contextvars.ContextVar["ExploreWorker | None"] = contextvars.ContextVar(
    "_current_worker", default=None
)


@dataclass
class ExploreWorker:
    intent_id: str
    evidence_buffer: list[str] = field(default_factory=list)
    tc_start: int = 0


class BoardGuard:
    """Serialise mutating Blackboard operations with an asyncio.Lock."""

    def __init__(self, board: Blackboard) -> None:
        self._board = board
        self._lock = asyncio.Lock()

    async def add_fact(self, description: str, source: str = "") -> Any:
        async with self._lock:
            return self._board.add_fact(description, source)

    async def conclude_intent(self, intent_id: str, fact_desc: str, source: str = "") -> Any:
        async with self._lock:
            return self._board.conclude_intent(intent_id, fact_desc, source)

    async def abandon_intent(self, intent_id: str, note: str = "") -> Any:
        async with self._lock:
            return self._board.abandon_intent(intent_id, note)

    async def record_tool_call(self, **kwargs: Any) -> None:
        async with self._lock:
            self._board.record_tool_call(**kwargs)


class IntentStreamSink:
    """Wraps a StreamSink to prefix output with ``[i00x]``."""

    def __init__(self, inner: Any, intent_id: str) -> None:
        self._inner = inner
        self._prefix = f"[{intent_id}] "
        self._first = True

    def on_status(self, message: str) -> None:
        if self._inner:
            self._inner.on_status(f"{self._prefix}{message}")

    def on_thinking_token(self, token: str) -> None:
        if self._inner:
            self._inner.on_thinking_token(token)

    def on_content_token(self, token: str) -> None:
        if self._inner:
            if self._first:
                self._inner.on_content_token(self._prefix)
                self._first = False
            self._inner.on_content_token(token)

    def on_tool_call(self, tool_name: str, args: str) -> None:
        if self._inner:
            self._inner.on_tool_call(f"{self._prefix}{tool_name}", args)

    def on_tool_result(self, result_summary: str) -> None:
        if self._inner:
            self._inner.on_tool_result(result_summary)

    def on_stream_end(self) -> None:
        if self._inner:
            self._inner.on_stream_end()
        self._first = True


@dataclass
class SolveResult:
    completed: bool
    reason: str
    steps: int
    facts: int
    board: Blackboard


# 形如 flag{...} / ctfshow{...} / NSSCTF{...} 的旗标
_FLAG_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{1,20}\{[^{}\n]{1,200}\}")


def _extract_flags(text: str) -> list[str]:
    """抽取文本中所有 flag 形态的 token（去重保序）。"""
    return list(dict.fromkeys(_FLAG_RE.findall(text or "")))


def _goal_wants_flag(goal: str) -> bool:
    g = (goal or "").lower()
    return any(k in g for k in ("flag", "夺旗", "ctf", "shell", "getshell"))


def _unverified_flags(claim: str, evidence: str) -> list[str]:
    """返回在 claim 中声称、但未在真实工具证据中出现的 flag（疑似幻觉）。"""
    return [f for f in _extract_flags(claim) if f not in evidence]


def _completion_is_grounded(goal: str, evidence: str) -> tuple[bool, str]:
    """完成判定的证据校验：若目标要求 flag，则真实工具输出里必须真的出现过 flag。"""
    if not _goal_wants_flag(goal):
        return True, ""
    if _extract_flags(evidence):
        return True, ""
    return False, "目标要求 flag，但任何真实工具输出中都没有出现 flag，判定为未验证/疑似幻觉"


def _extract_json(text: str) -> Optional[dict]:
    """从 LLM 回复中稳健地抽取一个 JSON 对象。"""
    if not text:
        return None
    cleaned = strip_think_tags(text).strip()
    # 去掉 ```json ... ``` 代码围栏
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, re.DOTALL)
    if fence:
        cleaned = fence.group(1)
    # 直接尝试
    try:
        obj = json.loads(cleaned)
        return obj if isinstance(obj, dict) else None
    except (ValueError, TypeError):
        pass
    # 退化：抓取第一个平衡花括号块
    start = cleaned.find("{")
    if start < 0:
        return None
    depth = 0
    for idx in range(start, len(cleaned)):
        ch = cleaned[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                with_suppress = cleaned[start : idx + 1]
                try:
                    obj = json.loads(with_suppress)
                    return obj if isinstance(obj, dict) else None
                except (ValueError, TypeError):
                    return None
    return None


async def _structured_call(agent: Any, prompt: str, *, max_tokens: int = 900) -> str:
    """无工具的结构化 LLM 调用（用于 Reason / Conclude）。"""
    client = agent._get_client()
    messages = [{"role": "user", "content": prompt}]
    kwargs = build_chat_completion_kwargs(agent, messages, max_tokens=max_tokens, temperature=0.2)
    response = client.chat.completions.create(**kwargs)
    if response and response.choices:
        return response.choices[0].message.content or ""
    return ""


def _reason_prompt(board: Blackboard, max_intents: int) -> str:
    # 参考 Cairn reason.md：显式列出 open intents 和 abandoned intents，防重复提出
    open_list = board.open_intents()
    abandoned = [i for i in board.intents if i.status == IntentStatus.ABANDONED]
    concluded = [i for i in board.intents if i.status == IntentStatus.CONCLUDED]

    open_block = ""
    if open_list:
        open_block = "当前处于 OPEN 状态的 intents（正在探索或等待探索）：\n"
        for i in open_list:
            open_block += f"  - {i.id}: {i.description}\n"
        open_block += "如果 open intents 已覆盖所有有价值的方向，不要提新的。\n\n"

    abandoned_block = ""
    if abandoned:
        abandoned_block = "已放弃的 intents（走不通或已验证过）：\n"
        for i in abandoned[-10:]:
            note = f" — {i.note[:60]}" if i.note else ""
            abandoned_block += f"  - {i.id}: {i.description}{note}\n"
        abandoned_block += "⚠ **严禁重复提出与上述 abandoned intents 相同或高度重叠的方向。** 它们已被验证为走不通。\n\n"

    concluded_block = ""
    if concluded:
        concluded_block = "已完成的 intents（有结论的）：\n"
        for i in concluded[-5:]:
            concluded_block += f"  - {i.id} → {i.result_fact}: {i.description}\n"
        concluded_block += "\n"

    return (
        "你是该领域的资深渗透专家。下面是当前任务的「黑板图」快照：facts 是已确认的客观事实，"
        "intents 是探索方向。图从 facts 出发、通过 intent 探索得到新的 fact，逐步逼近 goal。\n\n"
        f"{open_block}{abandoned_block}{concluded_block}"
        "请判断两件事：① 现有 facts 是否已满足 goal；② 若未满足，是否应提出新的探索方向。\n\n"
        "只返回一个 JSON 对象，不要输出别的内容：\n"
        '- 若 goal 已达成： {"complete": true, "reason": "说明为何已达成", "evidence": ["f002"]}'
        "（complete 必须是布尔 true；evidence 必须引用证明达成的真实 fact id，至少一个）\n"
        '- 若未达成且应提出新方向： {"complete": false, "intents": [{"from": ["f001"], "description": "高价值且独立的探索方向"}]}\n'
        '- 若未达成但当前不必新增方向： {"complete": false}\n\n'
        "规则：\n"
        "- **complete 字段只能是布尔 true 或 false**。\n"
        "- **完成判定必须基于 facts 里已确认的客观事实**，不得基于猜测或愿望，且 evidence 必须引用真实 fact id。\n"
        "- 若某条 fact 标注了 [未验证]/[拒绝完成]/疑似幻觉，绝对不能据此判定达成。\n"
        "- **严禁重复提出与 abandoned intents 相同或高度重叠的方向**——它们已被探索过且走不通。\n"
        "- 若还有处于 open 的 intent 且当前 facts 没有揭示比 open intents 更有价值的新方向，"
        "返回 {\"complete\": false}（不提新方向），让 open intents 继续推进。\n"
        f"- 一次最多提出 {max_intents} 个高价值、互不重叠、可独立推进的方向，每个聚焦核心思路。\n"
        "- description 简洁聚焦，不要冗长；不同 intent 覆盖不同维度。\n\n"
        "## 黑板图\n```\n" + board.to_prompt_graph() + "\n```\n"
    )


def _conclude_prompt(board: Blackboard, intent: BoardIntent, evidence: str) -> str:
    return (
        "现在是「结论阶段」。它覆盖之前一切让你继续探索/继续发请求/继续等待结果的指令——立即停止动作，只做总结。\n"
        "你只能基于「真实工具输出」里**已经实际确认**的信息来总结，不得继续调用工具、不得等待未完成的结果。\n\n"
        "只返回一个 JSON 对象：\n"
        '{"advanced": true/false, "fact": "本次新确认的客观事实（增量）"}\n\n'
        "## advanced 判定标准（宽泛偏向 true）\n"
        "advanced=true 的情况（有**任何一项**即算推进）：\n"
        "- 发现了新的可访问接口/端点（即便只是确认 200 返回）\n"
        "- 确认了未授权可访问的 API（无需 token 即返回数据）\n"
        "- 发现了技术栈/版本/配置信息（Server 头、错误页泄露等）\n"
        "- 发现了安全配置问题（CORS 通配符、缺失安全头、敏感路径 403 等）\n"
        "- 确认了漏洞存在（注入点/XSS/SSRF/文件读取等）\n"
        "- 获取到了真实的 flag/shell/凭据\n\n"
        "advanced=false 仅当**完全没有任何新发现**：所有请求都是 404/超时/已知信息重复。\n\n"
        "## 铁律\n"
        "- fact 必须是**已被真实工具输出证实**的客观事实，不得是计划、猜测、推断。\n"
        "- **严禁编造 flag/shell/密码/数据**——工具输出里没出现过就不能声称拿到。\n"
        "- fact 只写增量信息，不要重复图里已有的内容。\n\n"
        f"## 当前探索方向 {intent.id}\n{intent.description}\n\n"
        "## 本次探索的真实工具输出（你唯一可信的事实来源）\n```\n" + (evidence.strip() or "(无工具输出)") + "\n```\n\n"
        "## 黑板图\n```\n" + board.to_prompt_graph() + "\n```\n"
    )


def _explore_context(board: Blackboard, intent: BoardIntent, step: int, max_rounds: int) -> str:
    from_desc = ""
    if intent.from_facts:
        refs = [board.get_fact(fid) for fid in intent.from_facts]
        from_desc = "\n".join(f"  - {f.id}: {f.description}" for f in refs if f)
        from_desc = f"\n基于已知事实：\n{from_desc}"

    # 已执行工具摘要——防跨 intent 重复
    tc_summary = board.tool_call_summary(20)
    tc_block = ""
    if tc_summary:
        tc_block = (
            "\n## 已执行过的工具（禁止重复调用同一工具+同一参数）\n"
            + tc_summary + "\n"
        )

    # Cairn 改进 #5: 最后一步时注入 conclude override 指令
    conclude_override = ""
    if step == max_rounds:
        conclude_override = (
            "\n## ⚠ 这是最后一步——立即停止探索并总结\n"
            "不要再发起新的工具调用、不要等待未完成的结果。\n"
            "基于已有的工具输出，总结本方向发现的所有客观事实。\n\n"
        )

    return (
        f"[探索方向 {intent.id} · 第 {step}/{max_rounds} 步]\n"
        f"目标(goal): {board.goal}\n"
        f"当前探索方向：{intent.description}{from_desc}\n"
        f"{conclude_override}"
        f"{tc_block}\n"
        "## 执行规则（必须遵守）\n"
        "1. 围绕当前方向用工具实际执行，每步必须有工具调用+响应分析。\n"
        "2. ⚠ 绝对禁止重复调用上面「已执行过的工具」列表中出现过的同一工具+同一参数。\n"
        "3. ⚠ 同一 URL 只 fetch 一次——如果已经 fetch 过，直接基于已有结果分析。\n"
        "4. 若该方向走不通，明确说明原因并停止。\n"
        "\n## 工具使用链路（按目标类型选择）\n"
        "Web 渗透标准链路：\n"
        "  ① js_recon(url=目标) — 抓 JS 提接口 + 自动未授权探测（**最先调用**）\n"
        "  ② dir_enum(url=目标) — 目录枚举\n"
        "  ③ space_search(domain=域名) — 空间测绘\n"
        "  ④ subdomain_enum(domain=域名) — 子域名枚举\n"
        "  ⑤ unauth_test(base_url, endpoints) — 对发现的接口做未授权验证\n"
        "  ⑥ fetch(url, method) — 单个请求探测（仅用于 js_recon/dir_enum 未覆盖的特定路径）\n"
        "Chrome MCP 链路：chrome_navigate → chrome_read_page/chrome_get_web_content → 分析（不要反复 navigate）\n"
    )


def _is_duplicate_intent(board: Blackboard, new_desc: str) -> bool:
    """检查新提案是否与已 abandoned 的 intent 高度重叠（仅检查 abandoned，不检查 concluded）。

    只阻止重复已失败的方向；已成功的方向可以在新事实基础上再次深入。
    """
    abandoned = [i for i in board.intents if i.status == IntentStatus.ABANDONED]
    if not abandoned:
        return False
    new_lower = new_desc.lower()
    new_words = set(re.findall(r"[a-zA-Z一-鿿]{2,}", new_lower))
    if len(new_words) < 3:
        return False
    for existing in abandoned:
        old_lower = existing.description.lower()
        old_words = set(re.findall(r"[a-zA-Z一-鿿]{2,}", old_lower))
        if len(old_words) < 3:
            continue
        overlap = len(new_words & old_words) / max(len(new_words | old_words), 1)
        if overlap > 0.65:
            return True
    return False


async def reason_step(agent: Any, board: Blackboard, max_intents: int) -> dict:
    raw = await _structured_call(agent, _reason_prompt(board, max_intents), max_tokens=1200)
    parsed = _extract_json(raw)
    return parsed or {}


async def explore_step(
    agent: Any,
    board: Blackboard,
    intent: BoardIntent,
    *,
    max_tool_rounds: int,
    evidence_buffer: list[str],
    stream_sink: Any = None,
    skip_context_write: bool = False,
) -> tuple[bool, str]:
    """围绕一个 Intent 实际探索，返回 (是否推进, 结论事实描述)。

    结论阶段只喂给模型「本次探索真实捕获的工具输出」作为唯一可信事实来源，降低幻觉。
    skip_context_write: 并行模式下跳过 agent.context.messages 写入（避免交叉写入）。
    """
    system_prompt = agent._build_system_prompt(
        agent.context.state.target, auto_mode=True, user_input=intent.description
    )
    evidence_start = len(evidence_buffer)
    tc_start = len(board.tool_calls)
    last_text = ""
    prev_tc_count = tc_start
    no_new_tc_streak = 0
    for step in range(1, max_tool_rounds + 1):
        ctx = _explore_context(board, intent, step, max_tool_rounds)
        text = await call_llm_auto(agent, system_prompt, ctx, stream_sink=stream_sink)
        last_text = text or ""
        if not skip_context_write:
            agent.context.add_assistant_message(f"[探索 {intent.id} 第{step}步] {last_text}")
        if hasattr(agent, "_finding_parser"):
            agent._finding_parser.parse(last_text)
        lowered = last_text.lower()
        if any(m.lower() in lowered for m in _ADVANCE_MARKERS):
            break
        if any(m in last_text for m in _DEAD_END_MARKERS) and step >= 2:
            break
        # 参考 Cairn checkpoint：比较本步前后 tool_calls 数量——没有新增说明模型空转
        cur_tc_count = len(board.tool_calls)
        if cur_tc_count == prev_tc_count:
            no_new_tc_streak += 1
            if no_new_tc_streak >= 2:
                last_text += "\n[!] 连续 2 步无新工具调用（空转），终止本方向。"
                break
        else:
            # 检查本步新增的调用是否全部是重复的（同 tool+key_args 已在之前出现）
            new_tcs = board.tool_calls[prev_tc_count:]
            all_repeated = all(
                any(old.tool == tc.tool and old.key_args == tc.key_args
                    for old in board.tool_calls[:prev_tc_count])
                for tc in new_tcs
            ) if new_tcs else True
            if all_repeated and step >= 2:
                last_text += "\n[!] 本步所有工具调用均为重复调用，终止本方向。"
                break
            no_new_tc_streak = 0
        prev_tc_count = cur_tc_count

    # ── Cairn 改进 #2: Conclude 阶段（参考 explore-conclude.md）──────
    # 无论 explore 如何结束（轮数耗尽/advance/dead-end/空转），都进入 conclude 阶段。
    # conclude 基于真实工具输出总结，偏向保留有价值的发现。
    intent_evidence = "\n".join(evidence_buffer[evidence_start:])[-6000:]
    raw = await _structured_call(
        agent, _conclude_prompt(board, intent, intent_evidence), max_tokens=600
    )
    parsed = _extract_json(raw) or {}
    advanced = bool(parsed.get("advanced"))
    fact = str(parsed.get("fact", "")).strip()
    if not fact:
        fact = strip_think_tags(last_text).strip()[:200]

    # ── Cairn 改进 #2b: 证据兜底 ─────────────────────────────────
    # 如果 conclude 说 advanced=false，但工具输出里明确有 200 响应或新发现，
    # 强制提升为 advanced=true（防止弱模型的 conclude 丢弃有价值的发现）。
    if not advanced and intent_evidence:
        evidence_lower = intent_evidence.lower()
        has_data = any(marker in evidence_lower for marker in [
            "status: 200", "200 ok", '"success"', "'success'",
            "未授权", "疑似未授权", "返回数据",
            "接口/路径", "命中",
        ])
        if has_data and fact:
            advanced = True

    return advanced, fact


async def solve(
    agent: Any,
    *,
    origin: str,
    goal: str,
    hints: Optional[list[str]] = None,
    max_steps: int = 40,
    max_intents: int = 3,
    max_tool_rounds: int = 4,
    max_parallel: int = 1,
    stream_sink: Any = None,
    on_event: Optional[Callable[[str, dict], None]] = None,
) -> SolveResult:
    """运行目标驱动的求解循环，直到目标达成 / 前沿耗尽 / 触达安全预算。"""
    board = agent.context.state.board
    board.origin = origin or board.origin
    board.goal = goal or board.goal
    guard = BoardGuard(board)

    def emit(kind: str, payload: dict) -> None:
        if on_event is not None:
            on_event(kind, payload)

    # 全局证据缓冲区——所有 flag/完成判定的唯一可信证据来源
    evidence_buffer: list[str] = []
    original_execute = agent._execute_mcp_tool

    async def _recording_execute(tool_name: str, tool_args: dict) -> str:
        import json as _json

        key_args = _json.dumps(tool_args, ensure_ascii=False, sort_keys=True)[:200]
        output = await original_execute(tool_name, tool_args)
        out_str = str(output)

        worker = _current_worker.get()
        if worker is not None:
            worker.evidence_buffer.append(out_str)
            if len(worker.evidence_buffer) > 400:
                del worker.evidence_buffer[:200]
            intent_id = worker.intent_id
        else:
            intent_id = ""

        evidence_buffer.append(out_str)
        if len(evidence_buffer) > 400:
            del evidence_buffer[:200]

        status = 0
        if "Status: 200" in out_str:
            status = 200
        elif "Status: 403" in out_str:
            status = 403
        elif "Status: 404" in out_str:
            status = 404
        note = out_str[:100].replace("\n", " ")
        await guard.record_tool_call(
            tool=tool_name, key_args=key_args,
            intent_id=intent_id, status=status, note=note,
        )
        return output

    agent._execute_mcp_tool = _recording_execute  # type: ignore[method-assign]

    try:
        # 播种初始事实
        if not board.facts:
            seed = f"目标 origin={origin}；目标 goal={goal}"
            if hints:
                seed += "；提示：" + " | ".join(hints)
            board.add_fact(seed, source="origin")

        empty_reason_streak = 0
        consecutive_errors = 0
        complete_reject_streak = 0
        steps = 0

        last_checkpoint = (-1, -1, -1)

        def _graph_checkpoint() -> tuple[int, int, int]:
            return (
                len(board.facts),
                sum(1 for i in board.intents if i.status == IntentStatus.CONCLUDED),
                sum(1 for i in board.intents if i.status == IntentStatus.ABANDONED),
            )

        while steps < max_steps and not board.completed:
            cur_checkpoint = _graph_checkpoint()
            open_intents = board.open_intents()
            skip_reason = (cur_checkpoint == last_checkpoint and open_intents)
            last_checkpoint = cur_checkpoint

            if skip_reason:
                pass
            else:
                try:
                    decision = await reason_step(agent, board, max_intents)
                except Exception as exc:
                    consecutive_errors += 1
                    emit("error", {"phase": "reason", "error": str(exc)})
                    if consecutive_errors >= 3:
                        break
                    continue
                emit("reason", {"decision": decision, "step": steps})

                complete_flag = decision.get("complete")
                if complete_flag is not None and complete_flag is not False:
                    full_evidence = "\n".join(evidence_buffer)
                    reason_text = str(
                        decision.get("reason")
                        or (complete_flag if isinstance(complete_flag, str) else "")
                    ).strip()
                    evidence_ids = [
                        fid for fid in (decision.get("evidence") or []) if board.get_fact(fid)
                    ]
                    grounded, why = _completion_is_grounded(board.goal, full_evidence)
                    fake = _unverified_flags(reason_text, full_evidence)

                    reject_reason: Optional[str] = None
                    if complete_flag is not True:
                        reject_reason = "完成判定未使用显式 complete=true，按未达成处理"
                    elif not reason_text:
                        reject_reason = "完成声明缺少 reason 说明"
                    elif _has_negation(reason_text):
                        reject_reason = f"完成理由含否定表述，实际未达成：{reason_text[:80]}"
                    elif not evidence_ids:
                        reject_reason = "完成声明未引用任何已确认 fact 作为证据"
                    elif not grounded:
                        reject_reason = why
                    elif fake:
                        reject_reason = f"完成声明引用的 flag {fake[0]} 未在真实工具输出中出现"

                    if reject_reason is None:
                        board.mark_complete(reason_text)
                        emit("completed", {"reason": reason_text})
                        break
                    board.add_fact(f"[拒绝完成] {reject_reason}；继续探索验证", source="verify")
                    emit("complete_rejected", {"reason": reject_reason})
                    complete_reject_streak += 1
                    if complete_reject_streak >= 3:
                        break
                    continue
                complete_reject_streak = 0

                for item in decision.get("intents") or []:
                    desc = (item or {}).get("description", "").strip() if isinstance(item, dict) else ""
                    if not desc:
                        continue
                    if _is_duplicate_intent(board, desc):
                        continue
                    board.add_intent(desc, (item or {}).get("from"))

                open_intents = board.open_intents()
                if not open_intents:
                    empty_reason_streak += 1
                    if empty_reason_streak >= 3:
                        break
                    continue
                empty_reason_streak = 0

            # ── 选取 intent batch 去探索 ──────────────────────────────
            open_intents = board.open_intents()
            if not open_intents:
                empty_reason_streak += 1
                if empty_reason_streak >= 3:
                    break
                continue
            empty_reason_streak = 0

            batch = open_intents[:max_parallel]
            is_parallel = len(batch) > 1 and max_parallel > 1

            for intent in batch:
                board.claim_intent(intent.id)
                emit("explore_start", {"intent_id": intent.id, "description": intent.description})

            if is_parallel:
                results = await _explore_batch(
                    agent, board, batch,
                    max_tool_rounds=max_tool_rounds,
                    evidence_buffer=evidence_buffer,
                    stream_sink=stream_sink,
                )
            else:
                intent = batch[0]
                worker = ExploreWorker(intent_id=intent.id, evidence_buffer=list(evidence_buffer), tc_start=len(board.tool_calls))
                _current_worker.set(worker)
                try:
                    advanced, fact = await explore_step(
                        agent, board, intent,
                        max_tool_rounds=max_tool_rounds,
                        evidence_buffer=worker.evidence_buffer,
                        stream_sink=stream_sink,
                    )
                except Exception as exc:
                    advanced, fact = False, ""
                    results = [(intent, False, f"探索异常: {exc}", True)]
                else:
                    results = [(intent, advanced, fact, False)]
                finally:
                    _current_worker.set(None)
                    evidence_buffer.extend(
                        e for e in worker.evidence_buffer if e not in evidence_buffer
                    )

            any_error = False
            for intent, advanced, fact, is_error in results:
                if is_error:
                    consecutive_errors += 1
                    board.abandon_intent(intent.id, note=fact[:120])
                    emit("error", {"phase": "explore", "intent_id": intent.id, "error": fact})
                    any_error = True
                    continue
                consecutive_errors = 0

                full_evidence = "\n".join(evidence_buffer)
                fake_flags = _unverified_flags(fact, full_evidence)
                if fake_flags:
                    note = f"声称获得 flag {fake_flags[0]} 但未在任何真实工具输出中出现，判定为幻觉，已拒绝"
                    board.abandon_intent(intent.id, note=note)
                    board.add_fact(f"[未验证] 探索 {intent.id}：{note}", source="verify")
                    emit("hallucination", {"intent_id": intent.id, "flags": fake_flags})
                elif advanced and fact:
                    new_fact = board.conclude_intent(intent.id, fact)
                    emit(
                        "conclude",
                        {"intent_id": intent.id, "fact": new_fact.id if new_fact else "", "desc": fact},
                    )
                    captured = _extract_flags(fact)
                    if captured and _goal_wants_flag(board.goal):
                        board.mark_complete(
                            f"已从 {new_fact.id if new_fact else 'fact'} 验证获取 flag: {captured[0]}"
                        )
                        emit("completed", {"reason": board.complete_reason})
                        break
                else:
                    board.abandon_intent(intent.id, note=(fact or "未推进")[:120])
                    emit("abandon", {"intent_id": intent.id, "note": fact})

            if board.completed:
                break

            if any_error and consecutive_errors >= 3:
                break

            steps += len(batch)
            agent.context.state.save()

            if is_parallel:
                summaries = []
                for intent, advanced, fact, is_error in results:
                    tag = "✓" if advanced else ("✗ ERR" if is_error else "—")
                    summaries.append(f"[{intent.id} {tag}] {fact[:120]}")
                agent.context.add_assistant_message(
                    "[并行探索摘要]\n" + "\n".join(summaries)
                )
    finally:
        agent._execute_mcp_tool = original_execute  # type: ignore[method-assign]

    reason = (
        board.complete_reason
        if board.completed
        else ("探索前沿耗尽" if steps < max_steps else "触达安全预算上限")
    )
    return SolveResult(
        completed=board.completed,
        reason=reason,
        steps=steps,
        facts=len(board.facts),
        board=board,
    )


async def _explore_batch(
    agent: Any,
    board: Blackboard,
    intents: list[BoardIntent],
    *,
    max_tool_rounds: int,
    evidence_buffer: list[str],
    stream_sink: Any = None,
) -> list[tuple[BoardIntent, bool, str, bool]]:
    """Run multiple intent explorations concurrently via asyncio.gather.

    Returns list of (intent, advanced, fact, is_error) tuples.
    """

    async def _run_one(intent: BoardIntent) -> tuple[BoardIntent, bool, str, bool]:
        worker = ExploreWorker(
            intent_id=intent.id,
            evidence_buffer=list(evidence_buffer),
            tc_start=len(board.tool_calls),
        )
        sink = IntentStreamSink(stream_sink, intent.id) if stream_sink else None
        ctx_token = _current_worker.set(worker)
        try:
            advanced, fact = await explore_step(
                agent, board, intent,
                max_tool_rounds=max_tool_rounds,
                evidence_buffer=worker.evidence_buffer,
                stream_sink=sink,
                skip_context_write=True,
            )
            return (intent, advanced, fact, False)
        except Exception as exc:
            return (intent, False, f"探索异常: {exc}", True)
        finally:
            _current_worker.reset(ctx_token)
            for e in worker.evidence_buffer:
                if e not in evidence_buffer:
                    evidence_buffer.append(e)

    raw = await asyncio.gather(*(_run_one(i) for i in intents), return_exceptions=True)
    results: list[tuple[BoardIntent, bool, str, bool]] = []
    for idx, r in enumerate(raw):
        if isinstance(r, BaseException):
            results.append((intents[idx], False, f"探索异常: {r}", True))
        else:
            results.append(r)
    return results
