"""Agent built-in tools and OpenAI tool schema helpers."""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import urlparse

from vulnclaw.agent.constraint_policy import validate_tool_action

BLOCKED_PATTERNS: list[str] = [
    r"os\.\s*system\s*\(",
    r"subprocess\.\s*Popen\s*\(",
    r"shutil\.\s*rmtree\s*\(",
    r"__import__\s*\(\s*['\"]os['\"]",
    r"open\s*\(\s*['\"].*vulnclaw.*config",
    r"open\s*\(\s*['\"].*\.vulnclaw",
]

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


async def execute_mcp_tool(agent: Any, tool_name: str, args: dict[str, Any]) -> str:
    """Execute a tool call via MCP manager or built-in tools."""
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

    if tool_name == "python_execute":
        return await execute_python(agent, args)

    if tool_name == "load_skill_reference":
        try:
            from vulnclaw.skills.loader import load_skill_reference

            skill_name = args.get("skill_name", "")
            ref_name = args.get("reference_name", "")
            content = load_skill_reference(skill_name, ref_name)
            if content:
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


def enforce_port_constraints(agent: Any, ports: list[int], *, target: str = "") -> str | None:
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
    agent: Any, *, host: str = "", path: str = "", target: str = ""
) -> str | None:
    """Return a user-facing violation when host/path are out of scope."""
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


def infer_port_from_url(url: str) -> int | None:
    """Infer request port from URL."""
    try:
        parsed = urlparse(url)
    except Exception:
        return None
    if parsed.port:
        return parsed.port
    if parsed.scheme == "https":
        return 443
    if parsed.scheme == "http":
        return 80
    return None


def build_openai_tools(mcp_manager: Any) -> list[dict[str, Any]]:
    """Build OpenAI function calling schema from MCP tools + built-in tools."""
    tools: list[dict[str, Any]] = []

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "load_skill_reference",
                "description": "加载指定 Skill 的参考文档，获取详细的渗透测试方法论、工作流或命令参考。当系统提示中提到'可用参考文档'时，使用此工具获取具体内容。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "skill_name": {
                            "type": "string",
                            "description": "Skill 名称，如 client-reverse, web-security-advanced, ai-mcp-security, intranet-pentest-advanced, pentest-tools, rapid-checklist, crypto-toolkit, ctf-web, ctf-crypto, ctf-misc, osint-recon, secknowledge-skill",
                        },
                        "reference_name": {
                            "type": "string",
                            "description": "参考文档文件名，如 02-client-api-reverse-and-burp.md, web-injection.md, encoding-cheatsheet.md",
                        },
                    },
                    "required": ["skill_name", "reference_name"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "python_execute",
                "description": (
                    "执行 Python 代码片段。用于：构造复杂 HTTP 请求并解析响应、"
                    "做编码转换和数据处理、批量测试不同 payload、比较响应差异、"
                    "执行数学计算等。代码在受限环境中执行，超时 30 秒。"
                    "预装库：requests, beautifulsoup4, pycryptodome, base64, json, re 等。"
                    "重要：构造 HTTP 请求时请使用此工具而非猜测响应内容。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {
                            "type": "string",
                            "description": "要执行的 Python 代码。支持多行，可 import 标准库和 requests/bs4 等。",
                        },
                        "purpose": {
                            "type": "string",
                            "description": "简要说明执行目的（用于审计日志），如'构造HTTP请求测试弱比较绕过'",
                        },
                    },
                    "required": ["code"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "crypto_decode",
                "description": (
                    "编码解码与加解密工具。遇到 base64/hex/URL/HTML/Unicode 编码字符串、"
                    "需要计算哈希、解密 AES/DES、解析 JWT 等场景时调用此工具。"
                    "重要：不要自行脑补解码结果，始终使用此工具确保准确性。"
                    "支持操作：base64_encode/decode, base32_encode/decode, base58_encode/decode, "
                    "hex_encode/decode, url_encode/decode, html_encode/decode, unicode_encode/decode, "
                    "rot13_encode/decode, caesar_encode/decode, morse_encode/decode, "
                    "md5_hash, sha1_hash, sha256_hash, sha512_hash, "
                    "aes_encrypt/decrypt, jwt_decode/encode, auto_decode"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "operation": {"type": "string", "description": "操作名称"},
                        "input": {
                            "type": "string",
                            "description": "待处理的输入字符串（待编码/解码/哈希/加密的文本）",
                        },
                        "key": {
                            "type": "string",
                            "description": "加密/解密密钥（AES/DES 需要，16/24/32字节）",
                        },
                        "iv": {"type": "string", "description": "AES 初始化向量（16字节，可选）"},
                        "shift": {
                            "type": "integer",
                            "description": "Caesar 密码位移量（默认3，解码时不提供则暴力所有位移）",
                        },
                        "secret": {"type": "string", "description": "JWT 签名密钥"},
                    },
                    "required": ["operation", "input"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "nmap_scan",
                "description": (
                    "nmap 网络端口扫描工具。信息收集时用于发现目标开放端口、服务版本和操作系统指纹。\n"
                    "用法示例：\n"
                    "  扫描常见端口: scan_type=top_ports, target=1.2.3.4\n"
                    "  SYN扫描: scan_type=syn, target=1.2.3.4（需要管理员权限）\n"
                    "  服务版本检测: scan_type=service, target=1.2.3.4\n"
                    "  漏洞扫描: scan_type=vuln, target=1.2.3.4\n"
                    "  全量扫描: scan_type=full, target=1.2.3.4\n"
                    "优先使用 nmap_scan 而非 python_execute 构造 socket 扫描，nmap 更专业更准确。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "目标 IP 地址或域名（必填），如 192.168.1.1 或 scanme.nmap.org",
                        },
                        "scan_type": {
                            "type": "string",
                            "description": "扫描类型：top_ports/syn/tcp/service/os/vuln/full",
                        },
                        "ports": {
                            "type": "string",
                            "description": "指定端口或范围（可选），如 80,443,8080 或 1-1000",
                        },
                        "timing": {
                            "type": "integer",
                            "description": "扫描速度模板 0-5（默认4），数字越大越快但越容易被检测",
                        },
                    },
                    "required": ["target"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "brute_force_login",
                "description": (
                    "对登录表单进行密码爆破。自动管理 Session Cookie、"
                    "自动提取和更新 CSRF Token、判断登录成功/失败。"
                    "单次调用内完成所有密码尝试，返回每个密码的结果。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "登录页面 URL",
                        },
                        "username_field": {
                            "type": "string",
                            "description": "用户名字段名，如 'username'",
                        },
                        "password_field": {
                            "type": "string",
                            "description": "密码字段名，如 'password'",
                        },
                        "csrf_field": {
                            "type": "string",
                            "description": "CSRF token 字段名，如 'user_token'",
                        },
                        "username": {
                            "type": "string",
                            "description": "要爆破的用户名",
                        },
                        "passwords": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "要尝试的密码列表（最多 20 个）",
                        },
                        "success_keyword": {
                            "type": "string",
                            "description": "登录成功后页面出现的特征词，如 'Welcome'、'Dashboard'",
                        },
                        "failure_keyword": {
                            "type": "string",
                            "description": "登录失败后页面出现的特征词，如 'Login failed'",
                        },
                        "submit_action": {
                            "type": "string",
                            "description": "表单提交的目标 URL（可选，不指定则从表单 action 属性提取）",
                        },
                        "extra_data": {
                            "type": "object",
                            "description": "额外表单字段，如 {\"Login\": \"Login\"}",
                        },
                    },
                    "required": ["url", "password_field", "passwords"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "space_search",
                "description": (
                    "空间测绘资产搜索（FOFA/Hunter/Quake/Shodan/ZoomEye/0.zone 零零信安）。"
                    "信息收集阶段用于被动发现目标资产、IP、端口、子域、标题、组件指纹，不直接接触目标。"
                    "给 domain 自动按各引擎语法构造 domain 查询；也可传完整 query 语法。"
                    "engine=all 时并发查询所有已配置 key 的引擎。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "engine": {
                            "type": "string",
                            "description": "fofa/hunter/quake/shodan/zoomeye/zerozone/all，默认 fofa",
                        },
                        "query": {
                            "type": "string",
                            "description": "引擎原生查询语法，如 'domain=\"x.com\"'、'app=\"Struts2\"'（可选）",
                        },
                        "domain": {
                            "type": "string",
                            "description": "目标主域名，自动构造各引擎 domain 查询（query 未给时使用）",
                        },
                        "size": {"type": "integer", "description": "返回条数，默认 100"},
                    },
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "subdomain_enum",
                "description": (
                    "子域名枚举。先用已配置的空间测绘引擎被动聚合，再用内置小字典做 DNS 解析爆破，"
                    "返回去重后的存活子域名列表。优先于 python_execute 自己写爆破。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "主域名，如 nju.edu.cn"},
                        "brute": {
                            "type": "boolean",
                            "description": "是否启用内置字典 DNS 爆破（默认 true）",
                        },
                    },
                    "required": ["domain"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "js_recon",
                "description": (
                    "JS 信息收集（参考 URLFinder）。抓取目标页面及其引用的全部 .js 文件，"
                    "提取 API 接口/路径、关联域名、绝对 URL，以及疑似硬编码密钥（AK/SK、token、JWT、私钥等）。"
                    "默认 auto_probe=true：自动对收集到的同源接口逐个做未授权访问探测（仅安全 GET，跳过破坏性接口）。"
                    "信息收集阶段优先调用，用真实提取的端点反哺后续测试，而非凭空猜接口。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "目标页面 URL"},
                        "max_js": {
                            "type": "integer",
                            "description": "最多抓取的 JS 文件数（默认 30）",
                        },
                        "auto_probe": {
                            "type": "boolean",
                            "description": "是否自动对收集到的接口做未授权探测（默认 true）",
                        },
                        "auth_header": {
                            "type": "string",
                            "description": "可选鉴权头做差分对比，如 'Authorization: Bearer xxx'，验证无 token 是否也能拿到数据",
                        },
                    },
                    "required": ["url"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "unauth_test",
                "description": (
                    "未授权访问探测。对一批接口（通常来自 js_recon 收集的端点）逐个无凭据请求，"
                    "按状态码/响应体/内容类型判定：⚠疑似未授权(返回数据) / ✓已鉴权拦截 / ↪跳转登录 / —不存在。"
                    "提供 auth_header 时做有/无 token 差分对比，无 token 也能拿到同样数据则判定 🔴未授权确认。"
                    "严守读写分离：仅发安全 GET，自动跳过 delete/update/sms 等破坏性接口，不批量遍历 ID。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "base_url": {"type": "string", "description": "目标基础 URL（确定同源范围）"},
                        "endpoints": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "待测接口路径/URL 列表（来自 js_recon 的接口/路径）",
                        },
                        "auth_header": {
                            "type": "string",
                            "description": "可选鉴权头做差分，如 'Authorization: Bearer xxx' 或 'Cookie: session=...'",
                        },
                        "max_endpoints": {
                            "type": "integer",
                            "description": "最多探测的接口数（默认 60）",
                        },
                    },
                    "required": ["base_url", "endpoints"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "dir_enum",
                "description": (
                    "目录/文件枚举（参考 dirsearch）。并发字典爆破，自带 404 基线与全局伪装响应识别"
                    "（随机路径返回 200 即判定伪装并停止）、状态码与响应长度过滤。"
                    "仅做安全的 GET 探测，不碰 delete/update 等破坏性路径。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "目标基础 URL，如 https://x.com/"},
                        "extensions": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "扩展名展开，如 ['php','jsp','bak','zip']（可选）",
                        },
                        "wordlist": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "追加的自定义路径（基于命名规律的启发式字典，可选）",
                        },
                    },
                    "required": ["url"],
                },
            },
        }
    )

    if mcp_manager:
        for schema in mcp_manager.get_tool_schemas():
            tools.append(
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


async def execute_nmap(agent: Any, args: dict[str, Any]) -> str:
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
            if is_reserved:
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

    cmd = [nmap_cmd, "-v" if scan_type == "full" else "-q", f"-T{max(0, min(5, timing))}"]
    if scan_type == "top_ports":
        cmd.extend(["--top-ports", "100", "-oX", "-"])
    elif scan_type == "syn":
        cmd.extend(["-sS", "-oX", "-"])
    elif scan_type == "tcp":
        cmd.extend(["-sT", "-oX", "-"])
    elif scan_type == "service":
        cmd.extend(["-sV", "-oX", "-"])
    elif scan_type == "os":
        cmd.extend(["-O", "-oX", "-"])
    elif scan_type == "vuln":
        cmd.extend(["--script", "vuln", "-oX", "-"])
    elif scan_type == "full":
        cmd.extend(["-sS", "-O", "-sV", "--script", "default,safe", "-oX", "-"])
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
    except subprocess.TimeoutExpired:
        return "[!] nmap 扫描超时（120秒），请减少扫描范围或使用更快的 timing"
    except PermissionError:
        return "[!] nmap 执行被拒绝（权限不足）。Windows 请以管理员身份运行终端。"
    except Exception as e:
        return f"[!] nmap 执行错误: {e}"

    if result.returncode != 0 and not result.stdout:
        return f"[!] nmap 扫描失败（{result.returncode}）: {result.stderr[:500]}"
    return parse_nmap_xml(result.stdout or result.stderr, target)


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


def _resolve_python_execute_mode(agent: Any) -> str:
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
    return None


def _write_python_audit(
    agent: Any,
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


async def execute_python(agent: Any, args: dict[str, Any]) -> str:
    code = args.get("code", "")
    purpose = args.get("purpose", "")
    if not code.strip():
        return "[!] Code is empty; nothing executed"

    url_matches = re.findall(r"https?://([a-zA-Z0-9._:-]+)(/[^\s'\"`]*)?", code)
    for host, path in url_matches:
        host_violation = enforce_host_path_constraints(
            agent,
            host=host.lower(),
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

    max_output_chars = getattr(safety, "python_execute_max_output_chars", 8000)
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
        env = {**os.environ, **base_env} if mode == "trusted-local" else base_env

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
            return f"{warning_prefix}[+] Python executed successfully with no output"

        output = "\n".join(output_parts)
        for sig in ["[DONE]", "[COMPLETE]"]:
            output = output.replace(sig, f"[BLOCKED_{sig[1:-1]}]")
        if len(output) > max_output_chars:
            clip = max_output_chars // 2
            output = output[:clip] + "\n...[truncated]...\n" + output[-clip:]
        _write_python_audit(agent, purpose=purpose, code=code, mode=mode, outcome="success")
        return f"{warning_prefix}[+] Python execution result ({mode}):\n{output}"
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
    agent: Any, cookies: list[tuple[str, str, str, str]]
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


async def execute_brute_force(agent: Any, args: dict[str, Any]) -> str:
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
