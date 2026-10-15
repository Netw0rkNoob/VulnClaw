"""VulnClaw Finding Similarity — lightweight semantic deduplication.

纯 Python 实现的漏洞发现语义去重，不引入任何外部 NLP 库。

修改者: Nyaecho
修改时间: 2026-07-08
修改原因: V2 修复 — 从 agent/finding_similarity.py 移至 config/ 基础设施层，
         消除 report/filter.py 对 agent/ 的依赖。
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Optional
from urllib.parse import parse_qs, urlsplit

if TYPE_CHECKING:
    from vulnclaw.config.domain_models import VulnerabilityFinding


# ── 漏洞类型归一化映射 ───────────────────────────────────────────────────

# 别名 -> 规范类型。键统一为小写、去空格的形式。
_VULN_TYPE_ALIASES: dict[str, str] = {
    # SQL 注入
    "sqli": "sql_injection",
    "sql注入": "sql_injection",
    "sql injection": "sql_injection",
    "blind sqli": "sql_injection",
    "盲注": "sql_injection",
    "注入漏洞": "sql_injection",
    "sql_injection": "sql_injection",
    # XSS
    "xss": "cross_site_scripting",
    "跨站脚本": "cross_site_scripting",
    "反射型xss": "cross_site_scripting",
    "存储型xss": "cross_site_scripting",
    "xss跨站脚本": "cross_site_scripting",
    "cross site scripting": "cross_site_scripting",
    "cross_site_scripting": "cross_site_scripting",
    # SSRF
    "ssrf": "server_side_request_forgery",
    "服务端请求伪造": "server_side_request_forgery",
    "server side request forgery": "server_side_request_forgery",
    "server_side_request_forgery": "server_side_request_forgery",
    # RCE
    "rce": "remote_code_execution",
    "命令执行": "remote_code_execution",
    "远程代码执行": "remote_code_execution",
    "命令注入": "remote_code_execution",
    "remote code execution": "remote_code_execution",
    "remote_code_execution": "remote_code_execution",
    # LFI / 文件包含
    "lfi": "local_file_inclusion",
    "文件包含": "local_file_inclusion",
    "rfi": "local_file_inclusion",
    "路径遍历": "local_file_inclusion",
    "文件包含/遍历": "local_file_inclusion",
    "local file inclusion": "local_file_inclusion",
    "local_file_inclusion": "local_file_inclusion",
    # IDOR / 越权
    "idor": "insecure_direct_object_reference",
    "越权": "insecure_direct_object_reference",
    "横向越权": "insecure_direct_object_reference",
    "纵向越权": "insecure_direct_object_reference",
    "insecure direct object reference": "insecure_direct_object_reference",
    "insecure_direct_object_reference": "insecure_direct_object_reference",
    # CSRF
    "csrf": "cross_site_request_forgery",
    "跨站请求伪造": "cross_site_request_forgery",
    "cross site request forgery": "cross_site_request_forgery",
    # 认证绕过
    "认证绕过": "auth_bypass",
    "未授权": "auth_bypass",
    "未授权访问": "auth_bypass",
    "未认证": "auth_bypass",
    "无需认证": "auth_bypass",
    # 信息泄露
    "信息泄露": "info_disclosure",
    "数据泄露": "info_disclosure",
    "敏感信息泄露": "info_disclosure",
    "info disclosure": "info_disclosure",
}


def normalize_vuln_type(vuln_type: str) -> str:
    """归一化漏洞类型，将常见别名映射到规范名称.

    Args:
        vuln_type: 原始漏洞类型字符串（任意大小写/中英文/含空格）。

    Returns:
        规范化后的类型；无匹配别名时返回去空格小写后的原值。
    """
    if not vuln_type:
        return ""
    key = re.sub(r"\s+", " ", vuln_type.strip().lower())
    if key in _VULN_TYPE_ALIASES:
        return _VULN_TYPE_ALIASES[key]
    # 尝试下划线/空格互换后再匹配
    underscore = key.replace(" ", "_")
    if underscore in _VULN_TYPE_ALIASES:
        return _VULN_TYPE_ALIASES[underscore]
    spaced = key.replace("_", " ")
    if spaced in _VULN_TYPE_ALIASES:
        return _VULN_TYPE_ALIASES[spaced]
    return underscore


# ── 文本归一化与相似度 ───────────────────────────────────────────────────

_URL_RE = re.compile(r'https?://[^\s<>"\')\]]+', re.IGNORECASE)
_TOKEN_RE = re.compile(r"[a-z0-9一-鿿]+", re.IGNORECASE)
# 标点边界标记（如 [自动]、[已确认]）应在分词前去掉，避免污染词集合
_NOISE_TAGS = ("[自动]", "[已确认]", "[未验证]")


def _normalize_url_path(url: str) -> str:
    """标准化 URL：去 scheme、去末尾斜杠、保留 host+path。"""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url.lower()
    host = (parts.hostname or "").lower()
    path = parts.path or ""
    if len(path) > 1:
        path = path.rstrip("/")
    return f"{host}{path}"


def normalize_text(text: str) -> str:
    """归一化文本：小写、合并空白、标准化内嵌 URL 路径.

    Args:
        text: 任意自由文本（描述/证据/标题）。

    Returns:
        归一化后的文本。
    """
    if not text:
        return ""
    result = text
    for tag in _NOISE_TAGS:
        result = result.replace(tag, " ")
    # 将内嵌 URL 替换为标准化后的 host+path 形式
    result = _URL_RE.sub(lambda m: _normalize_url_path(m.group(0)), result)
    result = result.lower()
    result = re.sub(r"\s+", " ", result).strip()
    return result


def _tokenize(text: str) -> set[str]:
    """将归一化文本切分为词集合。"""
    return set(_TOKEN_RE.findall(text))


def text_similarity(a: str, b: str) -> float:
    """基于词集合的 Jaccard 相似度.

    Args:
        a: 文本 A。
        b: 文本 B。

    Returns:
        [0.0, 1.0] 之间的相似度。两者皆空时返回 1.0；仅一方为空返回 0.0。
    """
    na, nb = normalize_text(a), normalize_text(b)
    if not na and not nb:
        return 1.0
    if not na or not nb:
        return 0.0
    ta, tb = _tokenize(na), _tokenize(nb)
    if not ta and not tb:
        return 1.0
    if not ta or not tb:
        return 0.0
    inter = len(ta & tb)
    union = len(ta | tb)
    return inter / union if union else 0.0


def url_similarity(a: str, b: str) -> float:
    """比较两个 URL 的 host / path / query 参数相似度.

    权重: host 0.3 + path 0.4 + query 参数名集合 0.3。
    非 URL 字符串回退为对原文做 Jaccard 文本相似度。

    Args:
        a: URL 或位置字符串 A。
        b: URL 或位置字符串 B。

    Returns:
        [0.0, 1.0] 之间的相似度。
    """
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0

    pa, pb = urlsplit(a.strip()), urlsplit(b.strip())
    # 若两者都不像 URL（无 scheme 也无 netloc 也无 path 分隔），按文本比
    if not (pa.scheme or pa.netloc) and not (pb.scheme or pb.netloc):
        return text_similarity(a, b)

    # host 比较
    ha, hb = (pa.hostname or "").lower(), (pb.hostname or "").lower()
    if not ha and not hb:
        host_sim = 1.0
    elif not ha or not hb:
        host_sim = 0.0
    else:
        host_sim = 1.0 if ha == hb else 0.0

    # path 比较：按 "/" 分段做 Jaccard
    seg_a = {s for s in pa.path.split("/") if s}
    seg_b = {s for s in pb.path.split("/") if s}
    if not seg_a and not seg_b:
        path_sim = 1.0
    elif not seg_a or not seg_b:
        path_sim = 0.0
    else:
        path_sim = len(seg_a & seg_b) / len(seg_a | seg_b)

    # query 参数名集合比较（忽略具体值，不同分页/ID 视为同一接口）
    qa = set(parse_qs(pa.query).keys())
    qb = set(parse_qs(pb.query).keys())
    if not qa and not qb:
        query_sim = 1.0
    elif not qa or not qb:
        query_sim = 0.0
    else:
        query_sim = len(qa & qb) / len(qa | qb)

    return host_sim * 0.3 + path_sim * 0.4 + query_sim * 0.3


# ── 综合 finding 相似度 ─────────────────────────────────────────────────

_LOCATION_RE = re.compile(r'(?:https?://[^\s<>"\')\]]+)|(?:/[\w%&=?\-./]+)')


def _extract_location(finding: "VulnerabilityFinding") -> str:
    """从 finding 的 evidence / description 中提取第一个 URL 或路径作为位置。"""
    for field in (finding.evidence or "", finding.description or ""):
        if not field:
            continue
        m = _LOCATION_RE.search(field)
        if m:
            return m.group(0)
    return ""


def _vuln_type_similarity(a: str, b: str) -> float:
    """漏洞类型相似度：完全匹配 1.0，归一化后匹配 0.8，否则 0.0。"""
    ra, rb = (a or "").strip().lower(), (b or "").strip().lower()
    if ra and rb and ra == rb:
        return 1.0
    na, nb = normalize_vuln_type(a), normalize_vuln_type(b)
    if na and nb and na == nb:
        return 0.8
    return 0.0


def finding_similarity(a: "VulnerabilityFinding", b: "VulnerabilityFinding") -> float:
    """综合比较两个漏洞发现的相似度.

    维度权重:
        - vuln_type:    0.3（完全匹配 1.0 / 归一化匹配 0.8）
        - location/URL: 0.4（从 evidence/description 提取后做 url_similarity）
        - description:  0.3（标题+描述的文本 Jaccard）

    Args:
        a: 漏洞发现 A。
        b: 漏洞发现 B。

    Returns:
        [0.0, 1.0] 之间的综合相似度。
    """
    if a.submission_id or b.submission_id:
        # Structured locations are authoritative; prose similarity cannot merge
        # separate endpoints, methods or owning targets.
        if (a.target, a.endpoint, a.method, a.code_location) != (
            b.target, b.endpoint, b.method, b.code_location,
        ):
            return 0.0
        if normalize_vuln_type(a.vuln_type) == normalize_vuln_type(b.vuln_type):
            return 1.0
        return 0.0
    type_sim = _vuln_type_similarity(a.vuln_type, b.vuln_type)

    loc_a, loc_b = _extract_location(a), _extract_location(b)
    if not loc_a and not loc_b:
        # 两者都无明确位置 — 该维度不可比，视为中性（不加分也不减分）
        loc_sim = 0.5
    else:
        loc_sim = url_similarity(loc_a, loc_b)

    desc_a = f"{a.title} {a.description}".strip()
    desc_b = f"{b.title} {b.description}".strip()
    desc_sim = text_similarity(desc_a, desc_b)

    return type_sim * 0.3 + loc_sim * 0.4 + desc_sim * 0.3


# ── 证据强度比较与去重 ───────────────────────────────────────────────────

_EVIDENCE_LEVEL_RANK = {"L1": 1, "L2": 2, "L3": 3, "L4": 4}
_LIFECYCLE_RANK = {
    "rejected": 0,
    "candidate": 1,
    "pending_verification": 2,
    "needs_manual_review": 3,
    "verified": 4,
}


def _evidence_strength(finding: "VulnerabilityFinding") -> tuple:
    """计算 finding 的证据强度，用于在重复时决定保留哪个.

    排序键（越大越强）:
        1. 已验证优先（verified=True）
        2. 生命周期等级
        3. 证据等级 L1-L4
        4. evidence 文本长度（更详细的证据）
    """
    return (
        1 if finding.verified else 0,
        _LIFECYCLE_RANK.get(finding.lifecycle_status, 1),
        _EVIDENCE_LEVEL_RANK.get(finding.evidence_level, 1),
        len(finding.evidence or ""),
    )


def deduplicate_findings(
    findings: list["VulnerabilityFinding"], threshold: float = 0.75
) -> list["VulnerabilityFinding"]:
    """对漏洞发现列表做语义去重，保留证据更充分的一方.

    遍历 findings，对每个新 finding 与已保留的 findings 逐一比较，
    相似度超过阈值即判定为重复；保留证据强度更高者。

    Args:
        findings: 原始漏洞发现列表。
        threshold: 相似度阈值，默认 0.75。

    Returns:
        去重后的列表，保持首次出现的相对顺序。
    """
    kept: list["VulnerabilityFinding"] = []
    for cand in findings:
        dup_index: Optional[int] = None
        for idx, existing in enumerate(kept):
            if finding_similarity(cand, existing) >= threshold:
                dup_index = idx
                break
        if dup_index is None:
            kept.append(cand)
            continue
        # 命中重复：保留证据更强者
        if _evidence_strength(cand) > _evidence_strength(kept[dup_index]):
            kept[dup_index] = cand
    return kept
