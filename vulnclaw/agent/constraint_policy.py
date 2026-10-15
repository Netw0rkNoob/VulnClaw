"""Constraint policy helpers for task, phase, and tool enforcement."""

from __future__ import annotations

# 修改者: Nyaecho
# 修改时间: 2026-07-08
# 修改原因: 消除 V2/V3/V4 违规 — 叶子类型已移至 config/domain_models.py，
#          此处从 config 导入并重新导出共享策略函数。
from vulnclaw.config.domain_models import (
    PHASE_TO_ACTION,
    PentestPhase,
    TaskConstraints,
    normalize_action_name,
    phase_display_name,
    validate_action_constraints,
)

# Re-export for backward compatibility
__all__ = [
    "PHASE_TO_ACTION",
    "PentestPhase",
    "TaskConstraints",
    "normalize_action_name",
    "validate_action_constraints",
    "validate_phase_transition",
    "validate_tool_action",
    "infer_tool_action",
]


def validate_phase_transition(
    next_phase: PentestPhase,
    constraints: TaskConstraints,
) -> str | None:
    """Return a constraint violation message when a phase transition is out of scope."""
    action = PHASE_TO_ACTION.get(next_phase)
    if action is None:
        return None
    violation = validate_action_constraints(action, constraints)
    if violation is None:
        return None
    return f"{violation} (phase transition to {phase_display_name(next_phase)})"


# 纯本地/知识类工具：不与目标交互，不纳入「动作范围」约束
LOCAL_META_TOOLS = {
    "submit_finding",
    "evidence_list",
    "evidence_search",
    "evidence_view",
    "load_skill_reference",
    "crypto_decode",
    "source_extract",
    "runtime_diff_probe",
    "agent_run",
    "agent_job",
}

# 真正代表「利用」意图的攻击载荷特征——与传输方式（HTTP 方法/网络库）无关
EXPLOIT_PAYLOAD_MARKERS = [
    "union select",
    " or 1=1",
    "'or'",
    "../",
    "..\\",
    "<script",
    "cmd=",
    "php://",
    "data://",
    "extractvalue(",
    "updatexml(",
    "load_file(",
    "into outfile",
    "{{",  # SSTI
    "${",  # SSTI/EL
    "%00",
    "/etc/passwd",
    "/bin/sh",
    "bash -i",
    "nc -e",
    "powershell -e",
]

# python_execute 中代表本地命令执行/反弹 shell 的特征
PYTHON_EXPLOIT_MARKERS = [
    "os.system",
    "subprocess",
    "pty.spawn",
    "/bin/sh",
    "bash -i",
    "nc -e",
    "reverse_shell",
]


def infer_tool_action(tool_name: str, args: dict[str, object]) -> str:
    """Infer the effective action class of a tool invocation.

    关键原则：只有「实际攻击载荷」才推断为 exploit；HTTP 方法、是否用 requests/urllib
    等传输细节不构成利用意图（recon/scan 阶段本就需要发 POST/OPTIONS、用 requests 探测）。
    """
    normalized_tool = (tool_name or "").strip().lower()

    if normalized_tool in LOCAL_META_TOOLS:
        return "recon"  # 仅本地操作，配合 validate_tool_action 豁免

    # Intel tools: read-only lookups (no target egress) and active recon
    # (low-impact target/3rd-party contact) both classify as passive "recon".
    from vulnclaw.intel.tools import READ_ONLY_INTEL_TOOLS, RECON_INTEL_TOOLS

    if normalized_tool in READ_ONLY_INTEL_TOOLS or normalized_tool in RECON_INTEL_TOOLS:
        return "recon"

    if normalized_tool == "nmap_scan":
        return "recon"

    if normalized_tool == "fetch":
        url = str(args.get("url", "") or "").lower()
        method = str(args.get("method", "GET") or "GET").upper()
        payload_surface = " ".join(
            str(args.get(key, "") or "").lower()
            for key in ("body", "data", "form", "json", "params", "headers")
        )
        if any(marker in url or marker in payload_surface for marker in EXPLOIT_PAYLOAD_MARKERS):
            return "exploit"
        # 方法本身不代表利用：GET/HEAD/OPTIONS 属侦察，其它（POST 测表单等）属扫描
        if method in ("GET", "HEAD", "OPTIONS"):
            return "recon"
        return "scan"

    if normalized_tool == "http_probe_batch":
        requests = args.get("requests", [])
        if not isinstance(requests, list):
            requests = []
        joined_parts: list[str] = []
        methods: list[str] = []
        for item in requests:
            if not isinstance(item, dict):
                continue
            methods.append(str(item.get("method", "GET") or "GET").upper())
            for key in ("url", "raw_url", "params", "data", "body", "json"):
                joined_parts.append(str(item.get(key, "") or "").lower())
        joined = " ".join(joined_parts)
        if any(marker in joined for marker in EXPLOIT_PAYLOAD_MARKERS):
            return "exploit"
        if all(method in ("GET", "HEAD", "OPTIONS") for method in methods or ["GET"]):
            return "recon"
        return "scan"

    if normalized_tool == "python_execute":
        code = str(args.get("code", "") or "").lower()
        if any(marker in code for marker in EXPLOIT_PAYLOAD_MARKERS + PYTHON_EXPLOIT_MARKERS):
            return "exploit"
        # 用 requests/httpx/urllib/socket 做 HTTP 探测属扫描，而非利用
        if any(m in code for m in ("requests.", "httpx.", "urllib", "http.client", "socket")):
            return "scan"
        return "recon"

    if normalized_tool == "shell_command":
        command = str(args.get("command", "") or args.get("cmd", "") or "").lower()
        if any(marker in command for marker in EXPLOIT_PAYLOAD_MARKERS + PYTHON_EXPLOIT_MARKERS):
            return "exploit"
        if any(
            marker in command
            for marker in (
                "curl ",
                "wget ",
                "invoke-webrequest",
                "invoke-restmethod",
                "iwr ",
                "irm ",
                "http://",
                "https://",
            )
        ):
            return "scan"
        return "recon"

    if normalized_tool == "brute_force_login":
        return "scan"

    return "scan"


def validate_tool_action(
    tool_name: str, args: dict[str, object], constraints: TaskConstraints
) -> str | None:
    """Return a constraint violation when a tool invocation implies a blocked action."""
    # 纯本地/知识类工具不受动作范围约束（加载文档、编解码不触碰目标）
    if (tool_name or "").strip().lower() in LOCAL_META_TOOLS:
        return None
    inferred = infer_tool_action(tool_name, args)
    violation = validate_action_constraints(inferred, constraints)
    if violation is None:
        return None
    return f"{violation} (tool '{tool_name}' inferred action '{inferred}')"
