"""Agent built-in tools and OpenAI tool schema helpers."""

from __future__ import annotations

import ast
import asyncio
import base64
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from vulnclaw.agent.agent_context import AgentContext

from urllib.parse import quote, urljoin, urlparse

import httpx

from vulnclaw.agent.agent_state import clip_text, one_line
from vulnclaw.agent.constraint_policy import validate_tool_action
from vulnclaw.agent.network_scan import (
    attach_network_scan_to_session,
    build_nmap_command,
    build_nmap_plan,
    deescalate_nmap_argv,
    nmap_failure_needs_deescalation,
    nmap_has_raw_socket_access,
    parse_nmap_xml_structured,
    summarize_network_scan,
    target_is_private_literal,
    without_privileged_nmap_args,
)
from vulnclaw.agent.roles import role_tool_violation, tool_allowed_for_role
from vulnclaw.agent.tool_result_overrides import set_raw_tool_output_override
from vulnclaw.agent.tool_schemas import append_builtin_tool_schemas
from vulnclaw.config.source_render import (
    render_highlighted_source_block,
    strip_highlighted_source,
)

# 修改者: Nyaecho
# 修改时间: 2026-07-08
# 修改原因: 消除 V1 违规 — infer_port_from_url 已移至 config/url_utils.py，
#          此处重新导出以保持向后兼容。
from vulnclaw.config.url_utils import infer_port_from_url  # noqa: F401 — re-export
from vulnclaw.config.url_utils import is_cloud_metadata_address
from vulnclaw.intel.tools import (
    INTEL_TOOL_NAMES,
    dispatch_intel_tool,
    intel_tool_schemas,
)
from vulnclaw.traffic.tools import (
    TRAFFIC_TOOL_NAMES,
    dispatch_traffic_tool,
    traffic_tool_schemas,
)


def role_allows_tool(role: str | None, tool_name: str) -> bool:
    """Return whether the active team role may see or call a tool."""
    return tool_allowed_for_role(tool_name, role)

BLOCKED_PATTERNS: list[str] = [
    r"os\.\s*system\s*\(",
    r"subprocess\.\s*Popen\s*\(",
    r"shutil\.\s*rmtree\s*\(",
    r"__import__\s*\(\s*['\"]os['\"]",
    r"open\s*\(\s*['\"].*vulnclaw.*config",
    r"open\s*\(\s*['\"].*\.vulnclaw",
]

# ── AST-based sandbox bypass detection ──────────────────────────────
# Regex alone cannot catch dynamic import/loading patterns.
# This AST checker identifies:
#   1. importlib.import_module() / importlib.__import__()
#   2. exec() / eval() / compile() that could hide code
#   3. getattr() on builtins or modules to access blocked names
#   4. __builtins__ direct access
#   5. Dynamic attribute access on dangerous modules (os, subprocess, etc.)

_DANGEROUS_MODULES = frozenset({
    "os", "subprocess", "shutil", "sys", "socket",
    "http", "urllib", "requests", "ftplib", "smtplib",
    "pathlib", "importlib",
})

_DANGEROUS_BUILTIN_NAMES = frozenset({
    "open", "exec", "eval", "compile", "__import__",
    "getattr", "setattr", "delattr", "globals", "locals",
    "vars", "dir", "type",
})


def _ast_check_sandbox_bypass(code: str) -> str | None:
    """AST-based check for sandbox bypass patterns.

    Returns a description string if a bypass is detected, None if safe.
    Catches patterns that regex-based SAFE_MODE_PATTERNS miss:
    - importlib.import_module('os')
    - exec("import os; os.system('id')")
    - getattr(__builtins__, "open")
    - getattr(alias, "attr") where alias is a dangerous module
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return None  # Syntax errors are caught elsewhere

    # Pass 1: collect import aliases (import socket as s → s = socket)
    _alias_to_module: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local_name = alias.asname if alias.asname else alias.name
                _alias_to_module[local_name] = alias.name.split(".")[0]

    def _resolve_name(name: str) -> str | None:
        """Resolve a name to its real module, checking alias map."""
        if name in _DANGEROUS_MODULES:
            return name
        if name in _alias_to_module:
            real = _alias_to_module[name]
            if real in _DANGEROUS_MODULES:
                return real
        return None

    for node in ast.walk(tree):
        # 1. exec() / eval() / compile() — can hide arbitrary code
        if isinstance(node, ast.Call):
            func = node.func
            func_name = ""
            if isinstance(func, ast.Name):
                func_name = func.id
            elif isinstance(func, ast.Attribute):
                func_name = func.attr

            if func_name in ("exec", "eval", "compile"):
                return "exec/eval/compile detected (bypasses static analysis)"

            # 2. importlib.import_module() / importlib.__import__()
            if func_name == "import_module" and isinstance(func, ast.Attribute):
                if isinstance(func.value, ast.Name) and func.value.id == "importlib":
                    return "importlib.import_module() detected"
            if func_name == "__import__":
                return "__import__() detected"

            # 3. getattr() on builtins or modules
            if func_name == "getattr" and node.args:
                first_arg = node.args[0]
                if isinstance(first_arg, ast.Name):
                    if first_arg.id in ("__builtins__", "builtins"):
                        return "getattr on __builtins__ detected"
                    resolved = _resolve_name(first_arg.id)
                    if resolved:
                        return f"getattr on module '{resolved}' detected"
                if isinstance(first_arg, ast.Attribute):
                    root = first_arg
                    while isinstance(root, ast.Attribute):
                        root = root.value
                    if isinstance(root, ast.Name):
                        if root.id in ("__builtins__", "builtins"):
                            return "getattr on __builtins__ detected"
                        resolved = _resolve_name(root.id)
                        if resolved:
                            return f"getattr on module '{resolved}' detected"

        # 4. __builtins__ direct access
        if isinstance(node, ast.Attribute) and node.attr == "__builtins__":
            return "__builtins__ access detected"
        if isinstance(node, ast.Name) and node.id == "__builtins__":
            return "__builtins__ access detected"

    return None

RESERVED_IP_RANGES: list[tuple[str, str, str]] = [
    ("198.18.0.0", "198.19.255.255", "RFC 2544 基准测试地址"),
    ("10.0.0.0", "10.255.255.255", "RFC 1918 私有地址"),
    ("172.16.0.0", "172.31.255.255", "RFC 1918 私有地址"),
    ("192.168.0.0", "192.168.255.255", "RFC 1918 私有地址"),
    ("127.0.0.0", "127.255.255.255", "RFC 1122 环回地址"),
    ("169.254.0.0", "169.254.255.255", "RFC 3927 链路本地"),
    ("0.0.0.0", "0.255.255.255", "RFC 1122 当前网络"),
    ("224.0.0.0", "239.255.255.255", "RFC 5771 多播地址"),
    ("240.0.0.0", "255.255.255.255", "RFC 1112 保留地址"),
]

SAFE_MODE_PATTERNS: list[str] = [
    r"open\s*\(",
    r"with\s+open\s*\(",
    r"socket\.",
    r"urllib",
    r"http\.client",
    r"ftplib",
    r"smtplib",
    r"requests\.",
    r"import\s+os",
    r"from\s+os\s+import",
    r"import\s+subprocess",
    r"from\s+subprocess\s+import",
    r"import\s+shutil",
    r"from\s+shutil\s+import",
    r"import\s+pathlib",
    r"from\s+pathlib\s+import",
    r"__import__",
]

LAB_MODE_PATTERNS: list[str] = [
    r"import\s+subprocess",
    r"from\s+subprocess\s+import",
    r"os\.\s*system\s*\(",
    r"subprocess\.\s*Popen\s*\(",
    r"shutil\.\s*rmtree\s*\(",
]


def resolve_traffic_store(agent: AgentContext) -> Any:
    """Resolve the per-run traffic evidence store for this agent.

    Prefers a run/evidence directory carried on the session (once the run-dir
    PRD lands); otherwise falls back to the config-scoped evidence directory so
    headless/CI runs still get a durable store.
    """
    from vulnclaw.traffic.paths import resolve_traffic_store as _resolve

    session = getattr(agent, "session_state", None)
    base = getattr(session, "evidence_dir", None) or getattr(session, "run_dir", None)
    return _resolve(base)


def enforce_traffic_repeat_constraints(
    agent: AgentContext, store: Any, args: dict[str, Any]
) -> str | None:
    """Gate a ``traffic_repeat`` against task host/path/port constraints.

    The effective target is the ``url`` override if supplied, else the stored
    request's URL. Returns a violation message when the target is out of scope,
    or ``None`` when the replay is allowed.
    """
    target_url = str(args.get("url") or "").strip()
    if not target_url:
        entry = store.find(str(args.get("request_id", "")))
        target_url = str((entry or {}).get("url", "")).strip()
    if not target_url:
        return None

    parsed = urlparse(target_url)
    host = parsed.hostname or ""
    path = parsed.path or ""
    violation = enforce_host_path_constraints(agent, host=host, path=path, target=host)
    if violation is not None:
        return violation

    port = infer_port_from_url(target_url)
    if port is not None:
        violation = enforce_port_constraints(agent, [port], target=host or target_url)
        if violation is not None:
            return violation
    return None


def _agent_state_for_tool(agent: AgentContext) -> Any:
    state = getattr(getattr(agent, "context", None), "state", None)
    return getattr(state, "agent_state", None)


def execute_evidence_tool(agent: AgentContext, tool_name: str, args: dict[str, Any]) -> str:
    agent_state = _agent_state_for_tool(agent)
    if agent_state is None:
        return "[!] AgentState is not available"
    if tool_name == "evidence_list":
        return agent_state.format_evidence_list(limit=int(args.get("limit", 20) or 20))
    if tool_name == "evidence_view":
        return agent_state.format_evidence_view(
            str(args.get("evidence_id", "") or ""),
            offset=int(args.get("offset", 0) or 0),
            limit=int(args.get("limit", 12000) or 12000),
        )
    if tool_name == "evidence_search":
        return agent_state.format_evidence_search(
            str(args.get("query", "") or ""),
            evidence_id=str(args.get("evidence_id", "") or ""),
            regex=bool(args.get("regex", False)),
            context_chars=int(args.get("context_chars", 180) or 180),
            limit=int(args.get("limit", 12) or 12),
        )
    return f"[!] Unknown evidence tool: {tool_name}"


def _resolve_workdir(raw_workdir: Any) -> Path:
    workdir = Path(str(raw_workdir or os.getcwd())).expanduser()
    return workdir.resolve()


def _validate_command_url_scope(agent: AgentContext, command: str) -> str | None:
    for match in re.finditer(r"https?://[^\s'\"<>]+", command):
        parsed = urlparse(match.group(0))
        host = (parsed.hostname or "").lower()
        path = parsed.path.rstrip("/")
        violation = enforce_host_path_constraints(
            agent,
            host=host,
            path=path,
            target=host,
        )
        if violation:
            return violation
    return None


def _shell_argv(command: str, shell_name: str) -> list[str] | str:
    normalized = (shell_name or "").strip().lower()
    if os.name == "nt":
        if normalized in {"cmd", "cmd.exe"}:
            return ["cmd.exe", "/c", command]
        executable = "pwsh.exe" if normalized in {"pwsh", "pwsh.exe"} else "powershell.exe"
        return [executable, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command]
    return command


async def execute_shell_command(agent: AgentContext, args: dict[str, Any]) -> str:
    """Run a local shell command and return command output as model-visible evidence."""

    command = str(args.get("command") or args.get("cmd") or "").strip()
    if not command:
        return "[!] shell_command requires command"
    scope_violation = _validate_command_url_scope(agent, command)
    if scope_violation:
        return scope_violation

    try:
        workdir = _resolve_workdir(args.get("workdir"))
    except OSError as exc:
        return f"[!] shell_command invalid workdir: {exc}"
    if not workdir.exists() or not workdir.is_dir():
        return f"[!] shell_command workdir does not exist or is not a directory: {workdir}"

    timeout_ms = int(args.get("timeout_ms") or 10000)
    timeout_ms = max(1000, min(timeout_ms, 120000))
    max_output_chars = int(args.get("max_output_chars") or 0)
    shell_name = str(args.get("shell") or "")
    argv = _shell_argv(command, shell_name)
    use_shell = os.name != "nt"
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    started = time.perf_counter()

    try:
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None,
            lambda: subprocess.run(
                argv,
                cwd=str(workdir),
                shell=use_shell,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_ms / 1000,
                env=env,
            ),
        )
    except subprocess.TimeoutExpired as exc:
        output = "\n".join(part for part in (exc.stdout or "", exc.stderr or "") if part)
        return (
            f"[!] shell_command timed out after {timeout_ms}ms\n"
            f"Command: {command}\n"
            f"Workdir: {workdir}\n"
            f"Output:\n{output}"
        )
    except FileNotFoundError as exc:
        return f"[!] shell_command failed: shell executable not found ({exc})"
    except Exception as exc:
        return f"[!] shell_command failed: {exc.__class__.__name__}: {exc}"

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    parts = [
        f"Command: {command}",
        f"Workdir: {workdir}",
        f"Exit code: {result.returncode}",
        f"Wall time: {elapsed_ms}ms",
        "Output:",
    ]
    output = ""
    if result.stdout:
        output += result.stdout
    if result.stderr:
        output += ("\n" if output else "") + "[stderr]\n" + result.stderr
    if not output:
        output = "(no output)"
    raw_output = "\n".join(parts + [output])
    if max_output_chars > 0 and len(raw_output) > max_output_chars:
        clip = max_output_chars // 2
        return raw_output[:clip] + "\n...[truncated by max_output_chars]...\n" + raw_output[-clip:]
    return raw_output


def _strip_highlighted_source(raw: str) -> str:
    return strip_highlighted_source(raw)


def _source_signal_lines(source: str, *, context: int = 1) -> list[str]:
    markers = (
        "highlight_file", "show_source", "unserialize", "serialize", "__destruct",
        "__wakeup", "__tostring", "eval", "assert", "system", "exec(",
        "shell_exec", "passthru", "call_user_func", "preg_match", "$_cookie",
        "$_get", "$_post", "$_request", "class ", "function ", "->", "::",
    )
    lines = source.splitlines()
    selected: dict[int, str] = {}
    for index, line in enumerate(lines):
        lower = line.lower()
        if any(marker in lower for marker in markers):
            for neighbor in range(max(0, index - context), min(len(lines), index + context + 1)):
                selected[neighbor + 1] = lines[neighbor]
    return [f"L{line_no}: {line}" for line_no, line in sorted(selected.items())]


def _extract_html_surfaces(raw: str) -> list[str]:
    surfaces: list[str] = []
    for pattern, label in (
        (r"(?is)<form\b[^>]*>", "form"),
        (r"(?is)<input\b[^>]*>", "input"),
        (r"(?is)<textarea\b[^>]*>", "textarea"),
        (r"(?is)<select\b[^>]*>", "select"),
    ):
        for match in re.finditer(pattern, raw or ""):
            surfaces.append(f"{label}: {one_line(match.group(0), 260)}")
    return surfaces[:80]


def _extract_endpoints(raw: str) -> list[str]:
    endpoints: list[str] = []
    patterns = [
        r"""(?i)\b(?:href|src|action)\s*=\s*["']([^"']{1,300})["']""",
        r"""(?i)\b(?:fetch|open)\s*\(\s*["']([^"']{1,300})["']""",
        r"""(?i)\burl\s*:\s*["']([^"']{1,300})["']""",
    ]
    for pattern in patterns:
        for endpoint in re.findall(pattern, raw or ""):
            if endpoint and endpoint not in endpoints:
                endpoints.append(endpoint)
    return endpoints[:120]


async def execute_source_extract(agent: AgentContext, args: dict[str, Any]) -> str:
    """Normalize highlighted HTML/source evidence and extract vulnerability signals."""

    raw = str(args.get("text") or "")
    source_label = "inline text"
    evidence_id = str(args.get("evidence_id") or "").strip()
    if evidence_id:
        agent_state = _agent_state_for_tool(agent)
        if agent_state is None:
            return "[!] AgentState is not available"
        for evidence in agent_state.evidence:
            if evidence.id == evidence_id:
                raw = evidence.content
                source_label = f"evidence {evidence_id}"
                break
        else:
            return f"[!] evidence not found: {evidence_id}"
    if not raw.strip():
        return "[!] source_extract requires evidence_id or text"

    normalized = _strip_highlighted_source(raw)
    signal_lines = _source_signal_lines(normalized)
    surfaces = _extract_html_surfaces(raw)
    endpoints = _extract_endpoints(raw)
    parts = [f"# source_extract — {source_label}"]
    if signal_lines:
        parts.append("\n## High-signal source lines")
        parts.extend(signal_lines)
    if surfaces:
        parts.append("\n## HTML form/input surfaces")
        parts.extend(f"- {item}" for item in surfaces)
    if endpoints:
        parts.append("\n## Endpoints")
        parts.extend(f"- {endpoint}" for endpoint in endpoints)
    parts.append("\n## Normalized source/text")
    parts.append(normalized)
    return "\n".join(parts)


_PHP_SERIALIZE_LENGTH_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_])([OC]):([0-9]+):")
_PHP_SERIALIZE_STRING_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_])s:([0-9]+):")


def _runtime_diff_candidates(args: dict[str, Any]) -> list[tuple[str, str]]:
    """Build a compact candidate table for parser/filter differential probing."""

    payload = str(args.get("payload") or "")
    explicit = args.get("candidates") or []
    mutations = args.get("mutations") or ["signed_lengths", "leading_zero_lengths"]
    if isinstance(mutations, str):
        mutations = [mutations]
    mutation_set = {str(item).strip().lower() for item in mutations if str(item).strip()}

    candidates: list[tuple[str, str]] = []
    if payload:
        candidates.append(("original", payload))

    if "signed_lengths" in mutation_set and payload:
        signed = _PHP_SERIALIZE_LENGTH_TOKEN_RE.sub(r"\1:+\2:", payload)
        if signed != payload:
            candidates.append(("signed object/class lengths", signed))

    if "leading_zero_lengths" in mutation_set and payload:
        padded = _PHP_SERIALIZE_LENGTH_TOKEN_RE.sub(
            lambda match: f"{match.group(1)}:0{match.group(2)}:",
            payload,
        )
        if padded != payload:
            candidates.append(("zero-padded object/class lengths", padded))

    if "lowercase_type" in mutation_set and payload:
        lowered = _PHP_SERIALIZE_LENGTH_TOKEN_RE.sub(
            lambda match: f"{match.group(1).lower()}:{match.group(2)}:",
            payload,
        )
        if lowered != payload:
            candidates.append(("lowercase object/class token", lowered))

    if "uppercase_string_type" in mutation_set and payload:
        upper_s = _PHP_SERIALIZE_STRING_TOKEN_RE.sub(r"S:\1:", payload)
        if upper_s != payload:
            candidates.append(("uppercase string token", upper_s))

    if isinstance(explicit, list):
        for index, item in enumerate(explicit, start=1):
            if isinstance(item, dict):
                value = str(item.get("payload") or item.get("value") or "")
                label = str(item.get("label") or f"candidate {index}")
            else:
                value = str(item or "")
                label = f"candidate {index}"
            if value:
                candidates.append((label, value))

    deduped: list[tuple[str, str]] = []
    seen: set[str] = set()
    for label, value in candidates:
        if value in seen:
            continue
        seen.add(value)
        deduped.append((label, value))
    return deduped[:40]


def _parse_python_regex(pattern: str) -> tuple[str, int]:
    """Parse a PCRE-style /pattern/flags string for lightweight local checks."""

    raw = str(pattern or "")
    flags = 0
    if len(raw) >= 2 and raw.startswith("/"):
        escaped = False
        for index in range(len(raw) - 1, 0, -1):
            if raw[index] != "/" or escaped:
                escaped = raw[index] == "\\" and not escaped
                continue
            body = raw[1:index]
            suffix = raw[index + 1 :]
            if "i" in suffix:
                flags |= re.IGNORECASE
            if "s" in suffix:
                flags |= re.DOTALL
            if "m" in suffix:
                flags |= re.MULTILINE
            return body, flags
    return raw, flags


def _execute_regex_diff_probe(args: dict[str, Any]) -> str:
    filter_regex = str(args.get("filter_regex") or args.get("regex") or "")
    candidates = _runtime_diff_candidates(args)
    if not filter_regex:
        return "[!] runtime_diff_probe regex mode requires filter_regex"
    if not candidates:
        return "[!] runtime_diff_probe requires payload or candidates"

    pattern, flags = _parse_python_regex(filter_regex)
    lines = [
        "# runtime_diff_probe - regex",
        f"filter_regex={filter_regex}",
        f"candidate_count={len(candidates)}",
    ]
    try:
        compiled = re.compile(pattern, flags)
    except re.error as exc:
        return f"[!] runtime_diff_probe invalid regex for Python check: {exc}"

    for index, (label, value) in enumerate(candidates, start=1):
        hit = bool(compiled.search(value))
        lines.extend(
            [
                f"\n[{index}] {label}",
                f"filter_hit={str(hit).lower()}",
                f"length={len(value)}",
                f"urlencoded={quote(value, safe='')}",
                f"raw={value}",
            ]
        )
    return "\n".join(lines)


def _strip_php_open_close_tags(code: str) -> str:
    text = str(code or "").strip()
    text = re.sub(r"^\s*<\?php", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\?>\s*$", "", text)
    return text.strip()


def _b64_php_string(value: str) -> str:
    return base64.b64encode(str(value or "").encode("utf-8", errors="replace")).decode("ascii")


def _detect_target_runtime(agent: AgentContext, args: dict[str, Any]) -> str:
    explicit = str(args.get("target_runtime") or "").strip()
    if explicit:
        return one_line(explicit, 120)
    agent_state = _agent_state_for_tool(agent)
    if agent_state is None:
        return ""
    for evidence in reversed(getattr(agent_state, "evidence", [])[-24:]):
        text = "\n".join(
            part
            for part in (
                getattr(evidence, "summary", ""),
                getattr(evidence, "preview", ""),
                getattr(evidence, "content", "")[:4000],
            )
            if part
        )
        match = re.search(r"\bPHP/([0-9]+(?:\.[0-9]+){0,2})\b", text, re.IGNORECASE)
        if match:
            return f"PHP/{match.group(1)}"
        match = re.search(r"\bPHP\s+([0-9]+(?:\.[0-9]+){0,2})\b", text, re.IGNORECASE)
        if match:
            return f"PHP/{match.group(1)}"
    return ""


def _build_php_runtime_diff_script(
    *,
    filter_regex: str,
    candidates: list[tuple[str, str]],
    class_defs: str,
) -> str:
    entries = []
    for label, payload in candidates:
        entries.append(
            "array('label'=>base64_decode('%s'),'payload'=>base64_decode('%s'))"
            % (_b64_php_string(label), _b64_php_string(payload))
        )
    class_block = _strip_php_open_close_tags(class_defs)
    return "\n".join(
        [
            "<?php",
            "error_reporting(E_ALL);",
            class_block,
            "$filter = base64_decode('%s');" % _b64_php_string(filter_regex),
            "$candidates = array(%s);" % ",".join(entries),
            "echo \"# runtime_diff_probe - php_serialize\\n\";",
            "echo \"local_php_version=\" . PHP_VERSION . \"\\n\";",
            "echo \"filter_regex=\" . $filter . \"\\n\";",
            "echo \"candidate_count=\" . count($candidates) . \"\\n\";",
            "foreach ($candidates as $i => $item) {",
            "    $label = $item['label'];",
            "    $payload = $item['payload'];",
            "    echo \"\\n[\" . ($i + 1) . \"] \" . $label . \"\\n\";",
            "    echo \"length=\" . strlen($payload) . \"\\n\";",
            "    if ($filter !== '') {",
            "        $hit = @preg_match($filter, $payload);",
            "        echo \"filter_hit=\" . var_export($hit, true) . \"\\n\";",
            "    } else {",
            "        echo \"filter_hit=not_tested\\n\";",
            "    }",
            "    ob_start();",
            "    $result = @unserialize($payload);",
            "    $ok = !($result === false && $payload !== 'b:0;');",
            "    if (is_object($result)) {",
            "        $result_class = get_class($result);",
            "    } else {",
            "        $result_class = '';",
            "    }",
            "    $result_type = gettype($result);",
            "    unset($result);",
            "    $side = ob_get_clean();",
            "    echo \"unserialize_ok=\" . ($ok ? 'true' : 'false') . \"\\n\";",
            "    echo \"result_type=\" . $result_type . \"\\n\";",
            "    if ($result_class !== '') { echo \"result_class=\" . $result_class . \"\\n\"; }",
            "    if ($side !== '') { echo \"side_effect_output=\" . json_encode($side) . \"\\n\"; }",
            "    echo \"urlencoded=\" . rawurlencode($payload) . \"\\n\";",
            "    echo \"raw=\" . $payload . \"\\n\";",
            "}",
            "?>",
        ]
    )


async def _execute_php_serialize_diff_probe(
    args: dict[str, Any],
    *,
    target_runtime: str = "",
) -> str:
    filter_regex = str(args.get("filter_regex") or args.get("regex") or "")
    candidates = _runtime_diff_candidates(args)
    if not candidates:
        return "[!] runtime_diff_probe requires payload or candidates"

    php = shutil.which("php")
    if not php:
        return "[!] runtime_diff_probe php_serialize mode requires php in PATH"

    timeout_ms = max(1000, min(int(args.get("timeout_ms") or 10000), 120000))
    max_output_chars = int(args.get("max_output_chars") or 0)
    class_defs = str(args.get("class_defs") or "")
    script = _build_php_runtime_diff_script(
        filter_regex=filter_regex,
        candidates=candidates,
        class_defs=class_defs,
    )

    tmp_dir = Path(tempfile.mkdtemp(prefix="vulnclaw-runtime-diff-"))
    script_path = tmp_dir / "probe.php"
    script_path.write_text(script, encoding="utf-8")
    started = time.perf_counter()
    try:
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None,
            lambda: subprocess.run(
                [php, str(script_path)],
                cwd=str(tmp_dir),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_ms / 1000,
            ),
        )
    except subprocess.TimeoutExpired as exc:
        output = "\n".join(part for part in (exc.stdout or "", exc.stderr or "") if part)
        return (
            f"[!] runtime_diff_probe timed out after {timeout_ms}ms\n"
            f"Output:\n{output}"
        )
    finally:
        try:
            script_path.unlink(missing_ok=True)
            tmp_dir.rmdir()
        except Exception:
            pass

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    output = result.stdout or ""
    if result.stderr:
        output += ("\n" if output else "") + "[stderr]\n" + result.stderr
    if not output:
        output = "(no output)"
    raw = "\n".join(
        [
            f"Command: {php} {script_path.name}",
            f"Exit code: {result.returncode}",
            f"Wall time: {elapsed_ms}ms",
            "Output:",
            output,
        ]
    )
    local_match = re.search(r"local_php_version=([0-9]+(?:\.[0-9]+){0,2})", output)
    local_runtime = f"PHP/{local_match.group(1)}" if local_match else ""
    has_signed_candidate = any(label == "signed object/class lengths" for label, _ in candidates)
    target_is_php5 = bool(re.search(r"PHP/5(?:\.|$)", target_runtime, re.IGNORECASE))
    if target_runtime and local_runtime and target_runtime.lower() != local_runtime.lower():
        if target_is_php5 and has_signed_candidate:
            for label, payload in candidates:
                if label != "signed object/class lengths":
                    continue
                raw += (
                    "\n[remote_verification_required] signed object/class length candidate "
                    f"targets {target_runtime} and bypasses digit-only object filters. "
                    "REMOTE VERIFICATION OUTRANKS LOCAL unserialize_ok=false when the local "
                    "PHP runtime is newer/different. Replay this exact candidate against the "
                    "remote endpoint before declaring the bypass dead.\n"
                    f"remote_candidate_raw={payload}\n"
                    f"remote_candidate_urlencoded={quote(payload, safe='')}"
                )
        note = (
            f"[compatibility_note] target_runtime={target_runtime}; local_runtime={local_runtime}. "
            "Local parser behavior may differ from the target; do not discard filter-missed "
            "candidates solely because the local runtime rejected them."
        )
        if target_is_php5 and has_signed_candidate:
            note += (
                " PHP 5.x serialized parsers may accept signed object/class length tokens "
                "such as O:+n:/C:+n: while regex filters like /[oc]:\\d+:/i miss them; "
                "remote-verify the exact URL-encoded signed candidate."
            )
        raw += "\n" + note
    if max_output_chars > 0 and len(raw) > max_output_chars:
        clip = max_output_chars // 2
        return raw[:clip] + "\n...[truncated by max_output_chars]...\n" + raw[-clip:]
    return raw


async def execute_runtime_diff_probe(agent: AgentContext, args: dict[str, Any]) -> str:
    """Run compact local parser/filter differential checks.

    This tool is intentionally general-purpose: the model decides when a target
    has a regex/string filter in front of a runtime parser and needs a fast
    local table of "accepted by parser, missed by filter" candidates.
    """

    mode = str(args.get("mode") or args.get("parser") or "regex").strip().lower()
    if mode in {"regex", "generic", "filter"}:
        return _execute_regex_diff_probe(args)
    if mode in {"php_serialize", "php_unserialize", "php-serialize", "php"}:
        return await _execute_php_serialize_diff_probe(
            args,
            target_runtime=_detect_target_runtime(agent, args),
        )
    return "[!] runtime_diff_probe mode must be regex or php_serialize"


async def execute_mcp_tool(agent: AgentContext, tool_name: str, args: dict[str, Any]) -> str:
    """Execute a tool call via MCP manager or built-in tools."""
    violation = role_tool_violation(
        getattr(agent, "active_role", None),
        tool_name,
        args,
    )
    if violation is not None:
        return violation

    session = getattr(agent, "session_state", None)
    constraints = getattr(session, "task_constraints", None)
    if constraints is not None:
        tool_violation = validate_tool_action(tool_name, args, constraints)
        if tool_violation is not None:
            if session is not None and hasattr(session, "add_constraint_violation_event"):
                from vulnclaw.agent.constraint_policy import infer_tool_action

                session.add_constraint_violation_event(
                    source="tool",
                    action=infer_tool_action(tool_name, args),
                    tool_name=tool_name,
                    code="tool_action_blocked",
                    severity="high",
                    summary=tool_violation,
                    detail=json.dumps(args, ensure_ascii=False)[:500],
                )
            return f"[constraint_violation] {tool_violation}"

    if tool_name in {"agent_run", "agent_job"}:
        from vulnclaw.agent.subagent.integration import (
            execute_agent_job,
            execute_agent_run,
        )

        if tool_name == "agent_run":
            return await execute_agent_run(agent, args)
        return await execute_agent_job(agent, args)

    if tool_name in INTEL_TOOL_NAMES:
        return await dispatch_intel_tool(agent, tool_name, args)

    if tool_name in TRAFFIC_TOOL_NAMES:
        store = resolve_traffic_store(agent)
        if tool_name == "traffic_repeat":
            # A url override could aim the replay at a blocked/out-of-scope host,
            # so gate it with the same host/path/port guards other network tools
            # use — the generic action check above does not see the target URL.
            violation = enforce_traffic_repeat_constraints(agent, store, args)
            if violation is not None:
                return violation
        # traffic_repeat issues a real network request; keep the loop responsive.
        return await asyncio.to_thread(dispatch_traffic_tool, store, tool_name, args)

    if tool_name in {"evidence_list", "evidence_view", "evidence_search"}:
        return execute_evidence_tool(agent, tool_name, args)

    if tool_name == "memory_search":
        query = str(args.get("query") or "").strip()
        if not query:
            return "[!] memory_search requires a non-empty query"
        context = getattr(agent, "context", None)
        search = getattr(context, "search_cold_memory", None)
        if not callable(search):
            return "[-] No cold memory is configured"
        matches = search(query, limit=args.get("limit", 5))
        if not matches:
            return "[-] No matching archived conversation"
        rendered = json.dumps(matches, ensure_ascii=False, indent=2)
        max_chars = max(256, int(getattr(context, "search_max_chars", 6000)))
        if len(rendered) > max_chars:
            suffix = "\n...[cold-memory search output truncated]"
            rendered = rendered[: max_chars - len(suffix)] + suffix
        return rendered

    if tool_name == "source_extract":
        return await execute_source_extract(agent, args)

    if tool_name == "runtime_diff_probe":
        return await execute_runtime_diff_probe(agent, args)

    if tool_name == "shell_command":
        return await execute_shell_command(agent, args)

    if tool_name == "http_probe_batch":
        return await execute_http_probe_batch(agent, args)

    if tool_name == "python_execute":
        return await execute_python(agent, args)

    if tool_name == "load_skill_reference":
        try:
            from vulnclaw.skills.loader import load_skill_reference

            skill_name = args.get("skill_name", "")
            ref_name = args.get("reference_name", "")
            content = load_skill_reference(skill_name, ref_name)
            if content:
                state = getattr(agent, "session_state", None) or getattr(
                    getattr(agent, "context", None), "state", None
                )
                if state is not None and hasattr(state, "record_loaded_reference"):
                    state.record_loaded_reference(skill_name, ref_name)
                return content
            return f"[!] 参考文档未找到: {skill_name}/{ref_name}"
        except Exception as e:
            return f"[!] 加载参考文档错误: {e}"

    if tool_name == "nmap_scan":
        return await execute_nmap(agent, args)

    if tool_name == "crypto_decode":
        try:
            from vulnclaw.skills.crypto_tools import execute as crypto_execute

            operation = args.get("operation", "")
            input_str = args.get("input", "")
            kwargs: dict[str, Any] = {}
            for key in ("key", "iv", "shift", "secret", "header", "algorithm"):
                if key in args and args[key]:
                    kwargs[key] = args[key]
                    if key == "shift":
                        kwargs[key] = int(args[key])
            result = crypto_execute(operation=operation, input_str=input_str, **kwargs)
            if result.get("success"):
                return f"[✓] {operation} 结果:\n{result['result']}"
            return f"[!] {operation} 失败: {result.get('error', '未知错误')}"
        except Exception as e:
            return f"[!] 加密工具执行错误: {e}"

    if tool_name == "brute_force_login":
        return await execute_brute_force(agent, args)

    if tool_name in {"space_search", "subdomain_enum", "js_recon", "dir_enum", "unauth_test"}:
        from vulnclaw.agent import recon_tools

        dispatch = {
            "space_search": recon_tools.execute_space_search,
            "subdomain_enum": recon_tools.execute_subdomain_enum,
            "js_recon": recon_tools.execute_js_recon,
            "dir_enum": recon_tools.execute_dir_enum,
            "unauth_test": recon_tools.execute_unauth_test,
        }
        try:
            return await dispatch[tool_name](agent, args)
        except Exception as e:
            return f"[!] 工具执行错误 ({tool_name}): {e}"

    if not agent.mcp_manager:
        return f"[!] MCP 管理器未初始化，无法执行工具: {tool_name}"

    try:
        result = await agent.mcp_manager.call_tool(tool_name, args)
        if isinstance(result, dict):
            if result.get("ok", False):
                content = result.get("content")
                structured = result.get("structured_content")
                summary_parts: list[str] = []
                if content is not None:
                    summary_parts.append(str(content))
                if isinstance(structured, dict) and structured:
                    summary_parts.append(
                        f"[structured] {json.dumps(structured, ensure_ascii=False)}"
                    )
                if summary_parts:
                    return "\n".join(summary_parts)
                return f"[tool:{tool_name}] completed"

            message = str(result.get("message") or "")
            suggestion = str(result.get("suggestion") or "")
            error_type = str(result.get("error_type") or "error")
            if suggestion:
                return f"[{error_type}] {message}\n[suggestion] {suggestion}".strip()
            return f"[{error_type}] {message}".strip()

        text = str(result)
        if text.strip() in ("undefined", "null", "None"):
            return f"[!] 工具 {tool_name} 返回空结果 (undefined)，调用可能失败"
        return text
    except Exception as e:
        return f"[!] 工具执行错误 ({tool_name}): {e}"


def enforce_port_constraints(agent: AgentContext, ports: list[int], *, target: str = "") -> str | None:
    """Return a user-facing violation message when requested ports are out of scope."""
    session = getattr(agent, "session_state", None)
    constraints = getattr(session, "task_constraints", None)
    if constraints is None or constraints.is_empty():
        return None

    if constraints.allowed_ports:
        disallowed = [port for port in ports if port not in constraints.allowed_ports]
        if disallowed:
            allowed = ", ".join(str(p) for p in constraints.allowed_ports)
            denied = ", ".join(str(p) for p in disallowed)
            suffix = f" for target {target}" if target else ""
            return f"[constraint_violation] Port(s) {denied} are outside allowed scope [{allowed}]{suffix}."

    blocked = [port for port in ports if port in constraints.blocked_ports]
    if blocked:
        denied = ", ".join(str(p) for p in blocked)
        suffix = f" for target {target}" if target else ""
        return f"[constraint_violation] Port(s) {denied} are blocked by task constraints{suffix}."

    return None


def enforce_host_path_constraints(
    agent: AgentContext, *, host: str = "", path: str = "", target: str = ""
) -> str | None:
    """Return a user-facing violation when host/path are out of scope.

    Checks the cloud-metadata hard denylist unconditionally, before the
    optional scope allowlist below and regardless of whether any
    TaskConstraints scope is configured -- an empty/unset scope must not mean
    "anything goes" for these specific addresses. See url_utils.py for why
    this is a narrow, always-on floor rather than blocking all of RFC1918.
    """
    if host:
        is_metadata, reason = is_cloud_metadata_address(host)
        if is_metadata:
            return (
                f"[constraint_violation] Host {host} is blocked: {reason}. "
                "Cloud metadata endpoints are never a legitimate pentest target."
            )

    session = getattr(agent, "session_state", None)
    constraints = getattr(session, "task_constraints", None)
    if constraints is None or constraints.is_empty():
        return None

    if constraints.allowed_hosts and host and host not in constraints.allowed_hosts:
        allowed = ", ".join(constraints.allowed_hosts)
        return f"[constraint_violation] Host {host} is outside allowed scope [{allowed}] for target {target or host}."

    if host and host in constraints.blocked_hosts:
        return f"[constraint_violation] Host {host} is blocked by task constraints for target {target or host}."

    if constraints.allowed_paths and path and path not in constraints.allowed_paths:
        allowed = ", ".join(constraints.allowed_paths)
        return f"[constraint_violation] Path {path} is outside allowed scope [{allowed}] for target {target or host}."

    if path and path in constraints.blocked_paths:
        return f"[constraint_violation] Path {path} is blocked by task constraints for target {target or host}."

    return None


def infer_ports_from_nmap_args(args: dict[str, Any]) -> list[int]:
    """Infer concrete target ports from nmap arguments for constraint checks."""
    custom_ports = str(args.get("ports", "") or "").strip()
    scan_type = str(args.get("scan_type", "top_ports") or "top_ports")

    if custom_ports:
        ports: list[int] = []
        for chunk in custom_ports.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "-" in chunk:
                start_text, end_text = chunk.split("-", 1)
                try:
                    start = int(start_text)
                    end = int(end_text)
                except ValueError:
                    continue
                if 0 < start <= end <= 65535:
                    ports.extend(range(start, end + 1))
                continue
            try:
                port = int(chunk)
            except ValueError:
                continue
            if 0 < port <= 65535:
                ports.append(port)
        return sorted(set(ports))

    if scan_type == "top_ports":
        return []
    return []


def build_openai_tools(
    mcp_manager: Any,
    *,
    active_role: str | None = None,
    include_subagent_tool: bool = True,
) -> list[dict[str, Any]]:
    """Build OpenAI function calling schema from MCP tools + built-in tools."""
    tools: list[dict[str, Any]] = []

    def append_tool(tool: dict[str, Any]) -> None:
        name = str(tool.get("function", {}).get("name", ""))
        if role_allows_tool(active_role, name):
            tools.append(tool)

    append_builtin_tool_schemas(append_tool)

    if include_subagent_tool:
        from vulnclaw.agent.subagent.integration import tool_schemas

        for schema in tool_schemas():
            append_tool(schema)

    for tool in intel_tool_schemas():
        append_tool(tool)

    for tool in traffic_tool_schemas():
        append_tool(tool)

    if mcp_manager:
        for schema in mcp_manager.get_tool_schemas():
            append_tool(
                {
                    "type": "function",
                    "function": {
                        "name": schema.get("name", ""),
                        "description": schema.get("description", ""),
                        "parameters": schema.get(
                            "inputSchema", {"type": "object", "properties": {}}
                        ),
                    },
                }
            )

    return tools


async def execute_nmap(agent: AgentContext, args: dict[str, Any]) -> str:
    target = args.get("target", "").strip()
    if not target:
        return "[!] nmap_scan 需要 target 参数（目标 IP 或域名）"

    host_violation = enforce_host_path_constraints(agent, host=target.lower(), target=target)
    if host_violation:
        return host_violation

    violation = enforce_port_constraints(agent, infer_ports_from_nmap_args(args), target=target)
    if violation:
        return violation

    try:
        ips = socket.getaddrinfo(target, None, socket.AF_INET)
        if ips:
            ip = ips[0][4][0]
            is_reserved, reason = is_reserved_ip(ip)
            if is_reserved and not target_is_private_literal(target):
                return (
                    f"[SKIP] 目标 {target} 解析到保留/内网地址 ({reason}, IP: {ip})\n"
                    f"跳过 nmap 扫描。建议直接通过 Web 指纹、目录枚举等方法收集信息，"
                    f"不要在保留地址上浪费轮次。"
                )
    except Exception:
        pass

    scan_type = args.get("scan_type", "top_ports")
    custom_ports = args.get("ports", "")
    timing = int(args.get("timing", 4))
    profile = str(args.get("profile", "") or "").strip().lower()

    nmap_cmd = shutil.which("nmap")
    if not nmap_cmd:
        try:
            result = subprocess.run(
                ["where.exe", "nmap"], capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                nmap_cmd = result.stdout.strip().split("\n")[0]
        except Exception:
            pass
    if not nmap_cmd:
        return "[!] nmap 未安装或不在 PATH 中。请确认 nmap 已安装并加入系统 PATH。"

    if profile:
        plan = build_nmap_plan(
            profile=profile,
            scan_type=str(scan_type or ""),
            ports=str(custom_ports or ""),
            timing=timing,
            prior_recon=getattr(getattr(agent, "session_state", None), "recon_data", {}),
        )
        privileged = nmap_has_raw_socket_access()
        cmd = build_nmap_command(nmap_cmd, target, plan, privileged=privileged)
        deescalated_note = (
            ""
            if privileged or plan.args == without_privileged_nmap_args(plan.args)
            else "[i] 非管理员权限运行：已跳过操作系统指纹识别（-O），SYN 扫描降级为 connect 扫描（-sT）。\n"
        )
    else:
        plan = None
        privileged = nmap_has_raw_socket_access()
        deescalated_note = ""
        cmd = [nmap_cmd, "-v" if scan_type == "full" else "-q", f"-T{max(0, min(5, timing))}"]
        if scan_type == "top_ports":
            cmd.extend(["--top-ports", "100", "-oX", "-"])
        elif scan_type == "syn":
            cmd.extend(["-sS" if privileged else "-sT", "-oX", "-"])
            if not privileged:
                deescalated_note = "[i] 非管理员权限运行：使用 connect 扫描（-sT）代替 SYN 扫描（-sS）。\n"
        elif scan_type == "tcp":
            cmd.extend(["-sT", "-oX", "-"])
        elif scan_type == "service":
            cmd.extend(["-sV", "-oX", "-"])
        elif scan_type == "os":
            if privileged:
                cmd.extend(["-O", "-oX", "-"])
            else:
                cmd.extend(["-sV", "-oX", "-"])
                deescalated_note = (
                    "[i] 非管理员权限运行：操作系统指纹识别（-O）不可用，改用服务探测（-sV）。\n"
                )
        elif scan_type == "vuln":
            cmd.extend(["--script", "vuln", "-oX", "-"])
        elif scan_type == "full":
            if privileged:
                cmd.extend(["-sS", "-O", "-sV", "--script", "default,safe", "-oX", "-"])
            else:
                cmd.extend(["-sT", "-sV", "--script", "default,safe", "-oX", "-"])
                deescalated_note = (
                    "[i] 非管理员权限运行：已跳过操作系统指纹识别（-O），"
                    "SYN 扫描降级为 connect 扫描（-sT）。\n"
                )
        else:
            cmd.extend(["-sV", "-oX", "-"])

        if custom_ports:
            cmd.extend(["-p", custom_ports])
        cmd.append(target)

    try:
        kwargs: dict[str, Any] = {
            "capture_output": True,
            "text": True,
            "encoding": "utf-8",
            "errors": "replace",
            "timeout": 120,
        }
        if sys.platform == "win32":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            kwargs["startupinfo"] = startupinfo
        result = subprocess.run(cmd, **kwargs)
        if (
            result.returncode != 0
            and not result.stdout
            and nmap_failure_needs_deescalation(result.stderr or "")
        ):
            fallback_cmd = deescalate_nmap_argv(cmd)
            if fallback_cmd != cmd:
                fallback = subprocess.run(fallback_cmd, **kwargs)
                if fallback.returncode == 0 or fallback.stdout:
                    result = fallback
                    deescalated_note = "[i] 权限错误后已使用非特权 nmap 参数重试。\n"
    except subprocess.TimeoutExpired:
        return "[!] nmap 扫描超时（120秒），请减少扫描范围或使用更快的 timing"
    except PermissionError:
        return "[!] nmap 执行被拒绝（权限不足）。Windows 请以管理员身份运行终端。"
    except Exception as e:
        return f"[!] nmap 执行错误: {e}"

    if result.returncode != 0 and not result.stdout:
        return f"[!] nmap 扫描失败（{result.returncode}）: {result.stderr[:500]}"
    output = result.stdout or result.stderr
    human_summary = parse_nmap_xml(output, target)
    structured = parse_nmap_xml_structured(output, target)
    if getattr(agent, "session_state", None) is not None:
        attach_network_scan_to_session(
            agent.session_state,
            structured,
            profile=profile or str(scan_type or "top_ports"),
            safe_probes=profile != "vuln",
        )
    if profile:
        network_summary = summarize_network_scan(structured)
        return f"{deescalated_note}{human_summary}\n\n{network_summary}"
    return f"{deescalated_note}{human_summary}"


def is_reserved_ip(ip: str) -> tuple[bool, str]:
    try:
        import ipaddress

        addr = ipaddress.ip_address(ip)
        for start, end, desc in RESERVED_IP_RANGES:
            if ipaddress.ip_address(start) <= addr <= ipaddress.ip_address(end):
                return True, desc
        return False, ""
    except Exception:
        return False, ""


def validate_scan_target(target: str) -> str:
    try:
        ips = socket.getaddrinfo(target, None, socket.AF_INET)
        if not ips:
            return ""
        ip = ips[0][4][0]
        is_reserved, reason = is_reserved_ip(ip)
        if is_reserved:
            return (
                f"\n\n⚠️ **警告：目标 {target} 解析到保留/内网地址 ({reason})\n"
                f"   IP: {ip}\n"
                f"   扫描此地址得到的结果不代表真实系统的安全状态。\n"
                f"   nmap 扫描结果中的端口信息可能与真实目标无关。**"
            )
    except Exception:
        pass
    return ""


def parse_nmap_xml(xml_output: str, target: str) -> str:
    if not xml_output or "<nmaprun" not in xml_output:
        lines = xml_output.strip().splitlines()[:80]
        return "nmap 原始输出:\n" + "\n".join(lines)

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        lines = xml_output.strip().splitlines()[:80]
        return "nmap 原始输出:\n" + "\n".join(lines)

    lines = [f"nmap 扫描结果 — {target}", "=" * 60]
    for host in root.findall(".//host"):
        hostname = host.find(".//hostname[@type='user']")
        addrs = [a.get("addr", "") for a in host.findall("address")]
        status = host.find("status")
        status_val = status.get("state", "unknown") if status is not None else "unknown"
        host_ip = addrs[0] if addrs else target
        reserved, reason = is_reserved_ip(host_ip)
        if reserved:
            host_str = (
                f"\n[主机] {host_ip} ⚠️ **保留地址 ({reason})，测试网络结果不代表真实目标安全状态**"
            )
        else:
            host_str = f"\n[主机] {host_ip}"
        if hostname is not None:
            host_str += f" ({hostname.get('name', '')})"
        host_str += f" — {status_val}"
        lines.append(host_str)

        for port in host.findall(".//port"):
            port_id = port.get("portid", "")
            proto = port.get("protocol", "tcp")
            port_state = port.find("state")
            svc = port.find("service")
            state_val = port_state.get("state", "unknown") if port_state is not None else "unknown"
            svc_name = svc.get("name", "") if svc is not None else ""
            svc_product = svc.get("product", "") if svc is not None else ""
            svc_version = svc.get("version", "") if svc is not None else ""
            lines.append(
                f"  {proto.upper():5} {port_id}/{'s' if svc is not None and svc.get('tunnel') == 'ssl' else ''} "
                f"{state_val:8}{svc_name:15}{(svc_product + ' ' + svc_version).rstrip()}"
            )
            for script in port.findall("script"):
                lines.append(f"    | {script.get('id', '')}: {script.get('output', '')[:120]}")

    runstats = root.find(".//runstats")
    if runstats is not None:
        finished = runstats.find("finished")
        if finished is not None:
            elapsed = finished.get("elapsed", "")
            summary = finished.get("summary", "")
            lines.append(f"\n完成时间: {elapsed}s | {summary}")
    return "\n".join(lines) or f"nmap 扫描完成（无输出）: {target}"


_HTTP_PROBE_ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
_HTTP_PROBE_MAX_REQUESTS = 30
_HTTP_PROBE_DEFAULT_TIMEOUT = 10.0
_HTTP_PROBE_DEFAULT_BODY_CHARS_LIMIT = 0
_HTTP_PROBE_SENSITIVE_HEADER_NAMES = {
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-access-token",
}


async def execute_http_probe_batch(agent: AgentContext, args: dict[str, Any]) -> str:
    """Run HTTP probes for URL/param/header/body variants."""

    specs = args.get("requests", [])
    if not isinstance(specs, list) or not specs:
        return "[!] http_probe_batch requires a non-empty requests array"
    specs = specs[:_HTTP_PROBE_MAX_REQUESTS]

    base_url = str(args.get("base_url", "") or "").strip()
    timeout = _bounded_float(args.get("timeout", _HTTP_PROBE_DEFAULT_TIMEOUT), 1.0, 30.0)
    follow_redirects = bool(args.get("follow_redirects", True))
    verify_tls = bool(args.get("verify_tls", False))
    max_body_chars = _coerce_nonnegative_int(
        args.get("max_body_chars"),
        default=_HTTP_PROBE_DEFAULT_BODY_CHARS_LIMIT,
    )

    prepared: list[dict[str, Any]] = []
    for index, raw_spec in enumerate(specs, start=1):
        if not isinstance(raw_spec, dict):
            prepared.append({"index": index, "error": "request spec must be an object"})
            continue
        prepared.append(_prepare_http_probe_request(agent, base_url, index, raw_spec))

    def _run() -> str:
        results: list[dict[str, Any]] = []
        with httpx.Client(
            follow_redirects=follow_redirects,
            timeout=timeout,
            verify=verify_tls,
            headers={"User-Agent": "VulnClaw-http_probe_batch/1.0"},
        ) as client:
            for item in prepared:
                if item.get("error"):
                    results.append(item)
                    continue
                results.append(_execute_one_http_probe(client, item, max_body_chars))
        return _format_http_probe_batch(results)

    return await asyncio.to_thread(_run)


def _bounded_float(value: Any, lower: float, upper: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return lower
    return max(lower, min(parsed, upper))


def _coerce_nonnegative_int(value: Any, *, default: int = 0) -> int:
    if value is None:
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(0, parsed)


def _prepare_http_probe_request(
    agent: AgentContext,
    base_url: str,
    index: int,
    spec: dict[str, Any],
) -> dict[str, Any]:
    method = str(spec.get("method", "GET") or "GET").upper()
    label = str(spec.get("label", "") or "")
    if method not in _HTTP_PROBE_ALLOWED_METHODS:
        return {"index": index, "label": label, "error": f"method {method} is not allowed"}

    uses_raw_url = bool(spec.get("raw_url"))
    requested_url = str(spec.get("raw_url") or spec.get("url") or base_url or "").strip()
    if not requested_url:
        return {"index": index, "label": label, "error": "missing url/raw_url/base_url"}
    url = _resolve_probe_url(base_url, requested_url)
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return {"index": index, "label": label, "url": url, "error": "url must be http(s)"}

    host_violation = enforce_host_path_constraints(
        agent,
        host=parsed.hostname.lower(),
        path=(parsed.path or "/").rstrip("/") or "/",
        target=parsed.hostname,
    )
    if host_violation:
        return {"index": index, "label": label, "url": url, "error": host_violation}

    port = infer_port_from_url(url)
    if port is not None:
        port_violation = enforce_port_constraints(agent, [port], target=parsed.hostname)
        if port_violation:
            return {"index": index, "label": label, "url": url, "error": port_violation}

    return {
        "index": index,
        "label": label,
        "method": method,
        "url": url,
        "raw_url": uses_raw_url,
        "params": None if uses_raw_url else _object_or_none(spec.get("params")),
        "headers": _string_dict(spec.get("headers")),
        "cookies": _string_dict(spec.get("cookies")),
        "data": spec.get("data", spec.get("body")),
        "json": spec.get("json") if "json" in spec else None,
    }


def _resolve_probe_url(base_url: str, requested_url: str) -> str:
    parsed = urlparse(requested_url)
    if parsed.scheme:
        return requested_url
    if not base_url:
        return requested_url
    return urljoin(base_url.rstrip("/") + "/", requested_url)


def _object_or_none(value: Any) -> Any:
    return value if isinstance(value, (dict, list, tuple, str)) else None


def _string_dict(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(k): str(v) for k, v in value.items() if k is not None and v is not None}


def _jsonish_one_line(value: Any, limit: int = 700) -> str:
    if isinstance(value, (dict, list, tuple)):
        rendered = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    else:
        rendered = str(value)
    return one_line(rendered, limit)


def _masked_probe_headers(headers: dict[str, str]) -> dict[str, str]:
    masked: dict[str, str] = {}
    for key, value in (headers or {}).items():
        normalized = str(key).lower()
        if normalized in _HTTP_PROBE_SENSITIVE_HEADER_NAMES:
            masked[str(key)] = "[masked]"
        else:
            masked[str(key)] = str(value)
    return masked


def _cookies_need_exact_header(cookies: dict[str, str]) -> bool:
    for value in (cookies or {}).values():
        text = str(value)
        if any(marker in text for marker in (";", "{", "}", '"', "'", "\r", "\n")):
            return True
    return False


def _probe_request_surface_lines(item: dict[str, Any]) -> list[str]:
    lines = [f"request={item.get('method', 'GET')} {item.get('url', '')}"]
    if item.get("params") is not None:
        lines.append(f"params={_jsonish_one_line(item.get('params'))}")
    headers = item.get("headers") or {}
    if headers:
        lines.append(f"headers={_jsonish_one_line(_masked_probe_headers(headers))}")
    cookies = item.get("cookies") or {}
    if cookies:
        note = (
            " [exact-cookie-note: value contains raw delimiters; prefer headers.Cookie "
            "when byte-exact delivery matters]"
            if _cookies_need_exact_header(cookies)
            else ""
        )
        lines.append(f"cookies={_jsonish_one_line(cookies)}{note}")
    if item.get("data") is not None:
        lines.append(f"body={_jsonish_one_line(item.get('data'))}")
    if item.get("json") is not None:
        lines.append(f"json={_jsonish_one_line(item.get('json'))}")
    return lines


def _execute_one_http_probe(
    client: httpx.Client,
    item: dict[str, Any],
    max_body_chars: int,
) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        response = client.request(
            item["method"],
            item["url"],
            params=item.get("params"),
            headers=item.get("headers") or None,
            cookies=item.get("cookies") or None,
            data=item.get("data"),
            json=item.get("json"),
        )
        duration_ms = max(0, int((time.perf_counter() - started) * 1000))
        body = response.text or ""
        body_output, body_truncated = _body_with_optional_limit(body, max_body_chars)
        digest = hashlib.sha256(response.content or b"").hexdigest()[:12]
        return {
            **item,
            "status": response.status_code,
            "effective_url": str(response.url),
            "length": len(response.content or b""),
            "hash": digest,
            "response_headers": dict(response.headers),
            "title": _extract_html_title(body),
            "signals": _http_body_signals(body, 800),
            "decoded_source": render_highlighted_source_block(body, max_chars=max_body_chars),
            "body_chars": len(body),
            "body": body_output,
            "body_truncated": body_truncated,
            "duration_ms": duration_ms,
            "location": response.headers.get("location", ""),
            "content_type": response.headers.get("content-type", ""),
        }
    except httpx.HTTPError as exc:
        duration_ms = max(0, int((time.perf_counter() - started) * 1000))
        return {
            **item,
            "error": f"{exc.__class__.__name__}: {one_line(str(exc), 220)}",
            "duration_ms": duration_ms,
        }


def _extract_html_title(body: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return one_line(re.sub(r"<[^>]+>", "", match.group(1)), 120)


def _http_body_signals(body: str, limit: int) -> str:
    text = str(body or "")
    lines: list[str] = []
    markers = (
        "flag",
        "ctf{",
        "error",
        "exception",
        "sql",
        "warning",
        "<form",
        "<input",
        "href=",
        "token",
        "admin",
        "select",
        "union",
    )
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        lower = stripped.lower()
        if any(marker in lower for marker in markers):
            lines.append(one_line(stripped, 240))
        if len(lines) >= 5:
            break
    if lines:
        return clip_text("\n".join(lines), limit)
    visible = re.sub(r"<[^>]+>", " ", text)
    visible = re.sub(r"\s+", " ", visible).strip()
    return clip_text(visible, min(limit, 500))


def _body_with_optional_limit(body: str, max_body_chars: int) -> tuple[str, bool]:
    text = str(body or "")
    if max_body_chars > 0 and len(text) > max_body_chars:
        return text[:max_body_chars], True
    return text, False


def _format_http_probe_batch(results: list[dict[str, Any]]) -> str:
    lines = [f"# http_probe_batch results ({len(results)} request(s))"]
    hashes: dict[str, list[str]] = {}
    for item in results:
        label = f" {item['label']}" if item.get("label") else ""
        if item.get("error"):
            url = item.get("url", "")
            duration = f" {item.get('duration_ms')}ms" if item.get("duration_ms") is not None else ""
            request_surface = "\n".join(
                f"    {line}" for line in _probe_request_surface_lines(item)
            )
            surface = f"\n{request_surface}" if request_surface else ""
            lines.append(f"[{item['index']}] ERROR{label}{duration} {url} :: {item['error']}{surface}")
            continue
        hash_value = str(item.get("hash", ""))
        hashes.setdefault(hash_value, []).append(str(item["index"]))
        raw_note = " raw-url" if item.get("raw_url") else ""
        location = f" location={item['location']}" if item.get("location") else ""
        title = f" title={item['title']!r}" if item.get("title") else ""
        content_type = (
            f" type={one_line(item.get('content_type', ''), 80)}"
            if item.get("content_type")
            else ""
        )
        body_text = str(item.get("body", "") or "")
        body_note = (
            f" truncated_to={len(body_text)}" if item.get("body_truncated") else ""
        )
        lines.append(
            "\n".join(
                [
                    (
                        f"[{item['index']}] {item['method']}{raw_note}{label} "
                        f"{item['status']} len={item['length']} hash={item['hash']} "
                        f"{item['duration_ms']}ms{location}{content_type}{title}"
                    ),
                    f"    url={item['effective_url']}",
                    f"    response_headers={_jsonish_one_line(item.get('response_headers', {}), 1800)}",
                    *[f"    {line}" for line in _probe_request_surface_lines(item)],
                    *[
                        f"    {line}"
                        for line in str(item.get("decoded_source") or "").splitlines()
                    ],
                    f"    signals={item['signals'] or '(empty body)'}",
                    f"    body_length={item.get('body_chars', 0)}{body_note}",
                    f"    body:\n{body_text if body_text else '(empty body)'}",
                ]
            )
        )

    same_body_groups = [ids for ids in hashes.values() if len(ids) > 1]
    if same_body_groups:
        lines.append("Same-body groups: " + "; ".join(",".join(ids) for ids in same_body_groups))
    return "\n".join(lines)


def _resolve_python_execute_mode(agent: AgentContext) -> str:
    safety = getattr(agent.config, "safety", None)
    if safety is None:
        return "trusted-local"

    mode = str(getattr(safety, "python_execute_mode", "") or "").strip().lower()
    if not mode and getattr(safety, "python_execute_restricted", False):
        return "safe"
    if mode in {"safe", "lab", "trusted-local"}:
        return mode
    return "trusted-local"


def _validate_python_execute_mode(mode: str, code: str) -> str | None:
    patterns = SAFE_MODE_PATTERNS if mode == "safe" else LAB_MODE_PATTERNS if mode == "lab" else []
    for pattern in patterns:
        if re.search(pattern, code, re.IGNORECASE):
            return pattern
    # AST-based check for dynamic bypass patterns (importlib, exec, getattr, etc.)
    ast_result = _ast_check_sandbox_bypass(code)
    if ast_result:
        return f"ast:{ast_result}"
    return None


def _write_python_audit(
    agent: AgentContext,
    *,
    purpose: str,
    code: str,
    mode: str,
    outcome: str,
    blocked_reason: str = "",
) -> None:
    safety = getattr(agent.config, "safety", None)
    if safety is None or not getattr(safety, "python_execute_audit_enabled", True):
        return

    try:
        from datetime import datetime

        from vulnclaw.config.settings import PYTHON_EXECUTE_AUDIT_FILE, ensure_dirs

        ensure_dirs()
        record = {
            "timestamp": datetime.now().isoformat(),
            "target": getattr(getattr(agent, "session_state", None), "target", None),
            "mode": mode,
            "purpose": purpose,
            "outcome": outcome,
            "blocked_reason": blocked_reason,
            "code_preview": code[:300],
            "code_lines": code.count("\n") + 1,
        }
        with open(PYTHON_EXECUTE_AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        return


async def execute_python(agent: AgentContext, args: dict[str, Any]) -> str:
    code = args.get("code", "")
    purpose = args.get("purpose", "")
    if not code.strip():
        return "[!] Code is empty; nothing executed"

    url_matches = re.findall(r"https?://([a-zA-Z0-9._:-]+)(/[^\s'\"`]*)?", code)
    for raw_host, path in url_matches:
        # Strip the port before the scope check so an in-scope target referenced
        # with a port (e.g. localhost:3000) is not falsely flagged out of scope.
        # The fetch tool already compares against urlparse().hostname (no port);
        # this keeps python_execute consistent with that behavior.
        host = raw_host.split(":", 1)[0].lower()
        host_violation = enforce_host_path_constraints(
            agent,
            host=host,
            path=(path or "").rstrip("/"),
            target=host,
        )
        if host_violation:
            return host_violation

    safety = getattr(agent.config, "safety", None)
    if safety is None or not safety.enable_python_execute:
        return (
            "[!] python_execute is disabled. Set safety.enable_python_execute = true to enable it"
        )

    mode = _resolve_python_execute_mode(agent)
    max_lines = getattr(safety, "python_execute_max_lines", 50)
    if code.count("\n") + 1 > max_lines:
        _write_python_audit(
            agent,
            purpose=purpose,
            code=code,
            mode=mode,
            outcome="blocked",
            blocked_reason="max_lines",
        )
        return f"[!] Code exceeds the max line limit ({max_lines})"

    show_warning = getattr(safety, "python_execute_show_warning", True)
    warning_prefix = ""
    if show_warning:
        warning_prefix = (
            f"[!] Security warning: python_execute runs local Python code in {mode} mode.\n"
            "Review the code carefully before execution.\n"
            "---\n"
        )

    recon_keywords = ["recon", "crawl", "spider", "scan", "enum", "probe"]
    timeout_seconds = 60 if any(kw in purpose.lower() for kw in recon_keywords) else 30

    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, code):
            _write_python_audit(
                agent,
                purpose=purpose,
                code=code,
                mode=mode,
                outcome="blocked",
                blocked_reason=pattern,
            )
            return f"[!] Code contains a blocked operation pattern: {pattern}"

    blocked_pattern = _validate_python_execute_mode(mode, code)
    if blocked_pattern:
        _write_python_audit(
            agent,
            purpose=purpose,
            code=code,
            mode=mode,
            outcome="blocked",
            blocked_reason=blocked_pattern,
        )
        if mode == "safe":
            return f"[!] safe mode blocked operation: {blocked_pattern}"
        return f"[!] lab mode blocked operation: {blocked_pattern}"

    # AST-based check for dynamic bypass patterns (importlib, exec, getattr, etc.)
    ast_bypass = _ast_check_sandbox_bypass(code)
    if ast_bypass:
        _write_python_audit(
            agent,
            purpose=purpose,
            code=code,
            mode=mode,
            outcome="blocked",
            blocked_reason=f"ast:{ast_bypass}",
        )
        return f"[!] Sandbox bypass detected: {ast_bypass}"

    max_output_chars = getattr(safety, "python_execute_max_output_chars", 0)
    tmp_path = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            preamble = (
                "import sys, json, re, os, base64, hashlib, itertools, collections, datetime, struct, binascii, textwrap\n"
                "try:\n    import requests\nexcept ImportError:\n    pass\n"
                "try:\n    from bs4 import BeautifulSoup\nexcept ImportError:\n    pass\n"
                "try:\n    from Crypto.Cipher import AES\nexcept ImportError:\n    pass\n\n"
            )
            f.write(preamble)
            f.write(code)
            tmp_path = f.name

        base_env = {"PYTHONIOENCODING": "utf-8"}
        env = {**{k: v for k, v in os.environ.items() if not k.startswith("VULNCLAW_")}, **base_env} if mode == "trusted-local" else base_env

        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None,
            lambda: subprocess.run(
                [sys.executable, tmp_path],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
                cwd=tempfile.gettempdir(),
                env=env,
            ),
        )

        try:
            os.unlink(tmp_path)
        except OSError:
            pass

        output_parts: list[str] = []
        if result.stdout:
            output_parts.append(result.stdout)
        if result.stderr:
            stderr_lines = [
                line
                for line in result.stderr.splitlines()
                if "ImportError" not in line and "No module named" not in line
            ]
            if stderr_lines:
                output_parts.append("[stderr]\n" + "\n".join(stderr_lines))

        if not output_parts:
            _write_python_audit(agent, purpose=purpose, code=code, mode=mode, outcome="success")
            set_raw_tool_output_override(
                agent,
                tool="python_execute",
                arguments=args,
                output="[+] Python executed successfully with no output",
            )
            return f"{warning_prefix}[+] Python executed successfully with no output"

        output = "\n".join(output_parts)
        for sig in ["[DONE]", "[COMPLETE]"]:
            output = output.replace(sig, f"[BLOCKED_{sig[1:-1]}]")
        raw_return = f"[+] Python execution result ({mode}):\n{output}"
        display_output = output
        if max_output_chars > 0 and len(display_output) > max_output_chars:
            clip = max_output_chars // 2
            display_output = display_output[:clip] + "\n...[truncated]...\n" + display_output[-clip:]
        _write_python_audit(agent, purpose=purpose, code=code, mode=mode, outcome="success")
        set_raw_tool_output_override(
            agent,
            tool="python_execute",
            arguments=args,
            output=raw_return,
        )
        return f"{warning_prefix}[+] Python execution result ({mode}):\n{display_output}"
    except subprocess.TimeoutExpired:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        agent.runtime.python_timeout_rounds += 1
        _write_python_audit(agent, purpose=purpose, code=code, mode=mode, outcome="timeout")
        return f"[!] Python execution timed out after {timeout_seconds} seconds"
    except Exception as e:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        _write_python_audit(
            agent, purpose=purpose, code=code, mode=mode, outcome="error", blocked_reason=str(e)
        )
        return f"[!] Python execution error: {e}"


def _sync_cookies_to_shared_jar(
    agent: AgentContext, cookies: list[tuple[str, str, str, str]]
) -> None:
    """Copy session cookies into the agent's shared _fetch_cookies jar.

    This allows the ``fetch`` tool (which uses ``_fetch_cookies``) to
    immediately use the authenticated session obtained by
    ``brute_force_login`` without requiring a separate re-login.
    """
    if not agent or not cookies:
        return
    mcp = getattr(agent, "mcp_manager", None)
    if not mcp:
        return
    try:
        import httpx

        jar = getattr(mcp, "_fetch_cookies", None)
        if jar is None:
            jar = httpx.Cookies()
            mcp._fetch_cookies = jar
        for name, value, domain, path in cookies:
            if name and value:
                jar.set(name, value, domain=domain or "", path=path or "/")
    except Exception:
        pass


async def execute_brute_force(agent: AgentContext, args: dict[str, Any]) -> str:
    """Execute a login brute-force with automatic CSRF/session management.

    Handles the full flow in one call:
    GET login page → extract CSRF + session → POST passwords → detect result
    """
    import asyncio
    import re
    import time

    url = str(args.get("url", "") or "").strip()
    password_field = str(args.get("password_field", "") or "").strip()
    csrf_field = str(args.get("csrf_field", "") or "").strip()
    username_field = str(args.get("username_field", "") or "").strip()
    username = str(args.get("username", "") or "").strip()
    passwords = args.get("passwords", [])
    success_keyword = str(args.get("success_keyword", "") or "").strip()
    failure_keyword = str(args.get("failure_keyword", "") or "").strip()
    submit_action = str(args.get("submit_action", "") or "").strip()
    extra_data = args.get("extra_data", {}) or {}
    submit_url = submit_action or url

    if not url or not password_field or not passwords:
        return "[!] 缺少必需参数: url, password_field, passwords"

    if not isinstance(passwords, list) or not passwords:
        return "[!] passwords 必须是非空列表"

    passwords = passwords[:20]
    total = len(passwords)

    try:
        import httpx
    except ImportError:
        return "[!] httpx 未安装，无法执行爆破"

    def extract_csrf(html: str, field_name: str) -> str | None:
        """Extract CSRF token from HTML input field."""
        if not field_name:
            return None
        pattern = re.compile(
            rf'name=["\']{re.escape(field_name)}["\'][^>]*value=["\']([^"\']+)',
            re.IGNORECASE,
        )
        m = pattern.search(html)
        if m:
            return m.group(1)
        # Try alternative: value before name
        pattern2 = re.compile(
            rf'value=["\']([^"\']+)[^>]*name=["\']{re.escape(field_name)}',
            re.IGNORECASE,
        )
        m = pattern2.search(html)
        return m.group(1) if m else None

    results: list[str] = []
    start_time = time.time()
    attempts = 0
    found_password: str | None = None

    # Collect cookies from the internal client so we can sync them
    # back to the shared _fetch_cookies jar after a successful login.
    session_cookies: list[tuple[str, str, str, str]] = []  # name, value, domain, path

    async with httpx.AsyncClient(
        verify=False,
        timeout=30.0,
        follow_redirects=True,
    ) as client:
        # Step 1: Get login page for initial CSRF and session
        try:
            resp = await asyncio.wait_for(
                client.get(url),
                timeout=30.0,
            )
            html = resp.text
        except Exception as e:
            return f"[!] 获取登录页失败: {e}"

        csrf_token = extract_csrf(html, csrf_field)
        if csrf_token is None and csrf_field:
            results.append(f"[!] 警告: 未在登录页找到 CSRF 字段 '{csrf_field}'")

        # Auto-detect submit button values from login page HTML.
        # Many forms (DVWA, etc.) check isset($_POST['SubmitButtonName'])
        # before processing authentication. Without the button's name=value,
        # the server skips auth and just re-renders the page.
        auto_fields: dict[str, str] = {}
        for input_match in re.finditer(
            r'<(?:input|button)\s[^>]*type=["\']submit["\'][^>]*>',
            html,
            re.IGNORECASE,
        ):
            tag = input_match.group()
            name_m = re.search(r'name\s*=\s*["\']([^"\']+)["\']', tag, re.IGNORECASE)
            val_m = re.search(r'value\s*=\s*["\']([^"\']*)["\']', tag, re.IGNORECASE)
            if name_m:
                auto_fields[name_m.group(1)] = val_m.group(1) if val_m else name_m.group(1)

        # Step 2: Try each password
        for i, password in enumerate(passwords, 1):
            form_data: dict[str, str] = {}
            if username_field and username:
                form_data[username_field] = username
            form_data[password_field] = password
            if csrf_token and csrf_field:
                form_data[csrf_field] = csrf_token
            # Auto-detected submit buttons come first so they can be
            # overridden by explicit extra_data if needed.
            form_data.update(auto_fields)
            form_data.update({k: str(v) for k, v in extra_data.items()})

            try:
                resp = await asyncio.wait_for(
                    client.post(submit_url, data=form_data),
                    timeout=30.0,
                )
                attempts += 1
                response_html = resp.text
                status = resp.status_code

                # Determine success or failure
                is_success = False
                reason = ""
                csrf_markers = ["csrf token is incorrect", "csrf token mismatch",
                                "token mismatch", "invalid token"]

                if success_keyword and success_keyword.lower() in response_html.lower():
                    is_success = True
                    reason = f"'{success_keyword}'"
                elif failure_keyword and failure_keyword.lower() in response_html.lower():
                    is_success = False
                    reason = f"'{failure_keyword}'"
                elif any(m in response_html.lower() for m in csrf_markers):
                    is_success = False
                    reason = "CSRF token 错误（已自动同步新 token）"
                elif status == 302:
                    is_success = True
                    reason = "Status 302 (redirect)"
                elif "logout" in response_html.lower() or "welcome" in response_html.lower():
                    is_success = True
                    reason = "检测到已登录状态"
                else:
                    # Include a short snippet from the response so the model
                    # can diagnose what the server actually returned.
                    snippet = response_html.strip()[:200].replace("\n", " ")
                    is_success = False
                    reason = snippet

                prefix = "[✓]" if is_success else "[✗]"
                pw_preview = password[:40].replace("\n", "\\n")
                results.append(f"{prefix} {pw_preview} → {'成功' if is_success else '失败'} ({reason})")

                # Extract new CSRF from response for next attempt
                new_token = extract_csrf(response_html, csrf_field)
                if new_token:
                    csrf_token = new_token

                # Stop early on success if keyword matched
                if is_success and success_keyword:
                    found_password = password
                    break

            except Exception as e:
                pw_preview = password[:30].replace("\n", "\\n")
                results.append(f"[!] {pw_preview} → 请求失败: {e}")
                continue

        # Save cookies from the internal client for potential sharing with
        # the fetch tool's cookie jar.
        try:
            for cookie in client.cookies.jar:
                session_cookies.append(
                    (cookie.name, cookie.value, cookie.domain, cookie.path)
                )
        except Exception:
            pass

    elapsed = time.time() - start_time

    # Sync session cookies to the shared _fetch_cookies jar so that
    # subsequent `fetch` calls from the agent are already authenticated.
    if found_password and session_cookies:
        _sync_cookies_to_shared_jar(agent, session_cookies)

    summary = [
        f"[+] 爆破完成 — {url}",
        f"    用户: {username or '(未指定)'}",
        "",
        "    结果:",
    ]
    for r in results:
        summary.append(f"    {r}")
    summary.append("")
    summary.append(f"    耗时: {elapsed:.1f}s")
    summary.append(f"    尝试: {attempts}/{total}")

    return "\n".join(summary)
