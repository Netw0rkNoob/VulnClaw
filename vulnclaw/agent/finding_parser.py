"""VulnClaw Finding Parser - three-layer vulnerability detection from LLM responses."""

from __future__ import annotations

import re

from vulnclaw.agent.context import ContextManager, VulnerabilityFinding
from vulnclaw.agent.runtime_state import RuntimeState
from vulnclaw.agent.think_filter import strip_think_tags
from vulnclaw.i18n import _

PROOF_PATTERNS: list[str] = [
    r"差异[：: ]*\d+",
    r"\d+\s*bytes|\d+\s*字节",
    r"(?:状态码|响应码)?[：: ]*5\d{2}",
    r"SQL.*错误|mysql.*error|sql.*error",
    r"SLEEP\(|BENCHMARK\(|EXTRACTVALUE\(|UPDATEXML\(",
    r"命令执行成功|whoami|id\s+",
    r"root[:\s]|administrator",
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    r"CVE-\d{4}-\d{4,}",
    r"成功提取|成功获取|获取到|successfully extracted|successfully obtained|retrieved ",
]

NATURAL_LANG_PATTERNS: list[tuple[str, str, str]] = [
    (r"SQL注入|SQLi|注入漏洞|sql injection|injection vulnerability", "High", "SQL注入"),
    (r"RCE|远程代码执行|命令注入|命令执行|remote code execution|command injection|command execution|arbitrary code execution", "Critical", "远程代码执行"),
    (r"未授权|未认证|无需认证|认证绕过|认证.*绕过|unauthorized|unauthenticated|authentication bypass|auth bypass|no authentication required", "High", "认证绕过"),
    (r"SSRF|服务端请求伪造|server-side request forgery", "High", "SSRF"),
    (r"XSS|跨站脚本|存储型XSS|反射型XSS|cross-site scripting|xss attack", "Medium", "XSS跨站脚本"),
    (r"CSRF|跨站请求伪造|cross-site request forgery", "Medium", "CSRF"),
    (r"文件包含|路径遍历|LFI|RFI|file inclusion|path traversal|directory traversal|local file inclusion|remote file inclusion", "Medium", "文件包含/遍历"),
    (r"弱口令|默认口令|默认密码|暴力破解|爆破|weak password|default password|default credentials|brute force|bruteforce", "Medium", "弱口令/暴力破解"),
    (r"配置错误|配置缺陷|泄露.*配置|misconfiguration|misconfigured|configuration flaw", "Medium", "配置错误"),
    (r"敏感目录|敏感文件.*发现|目录.*发现|sensitive directory|sensitive file|directory listing", "Info", "敏感目录/文件发现"),
    (r"版本.*过旧|中间件版本|指纹.*识别|outdated version|old version|middleware version|version disclosure|fingerprint", "Info", "版本信息"),
    (r"CVE-\d{4}-\d{4,}", "High", "已知CVE漏洞"),
]

ELEVATION_KEYWORDS: list[tuple[str, str, str]] = [
    (r"泄露|敏感信息|数据泄露|个人信息|\d+条数据|leak|leaked|sensitive information|data breach|personal data|records exposed", "High", "数据泄露"),
    (r"未授权|未认证|认证绕过|无需认证|unauthorized|unauthenticated|auth bypass|authentication bypass|no auth", "High", "未授权访问"),
    (r"RCE|命令执行|远程代码|remote code|arbitrary code|code execution", "Critical", "远程代码执行"),
    (r"SQL注入|SQLi|注入|sql injection|injection", "High", "注入漏洞"),
    (r"CVE-\d{4}-\d{4,}", "High", "已知CVE漏洞"),
    (r"弱口令|默认口令|暴力|weak password|default credentials|brute", "High", "弱口令/暴力破解"),
    (r"XSS|跨站脚本|cross-site scripting", "Medium", "XSS"),
    (r"文件包含|路径遍历|file inclusion|path traversal", "High", "文件包含/遍历"),
    (r"返回200.*不存在|200.*空内容|空响应.*位|200.*not found|empty response", "Medium", "潜在授权绕过"),
    (r"403.*接口|接口存在.*403|403.*endpoint|endpoint.*403", "Medium", "403认证拦截"),
]

VULN_TYPE_DISPLAY_KEYS: dict[str, str] = {
    "SQL注入": "agent.finding.type.sql_injection",
    "远程代码执行": "agent.finding.type.remote_code_execution",
    "认证绕过": "agent.finding.type.authentication_bypass",
    "SSRF": "agent.finding.type.ssrf",
    "XSS跨站脚本": "agent.finding.type.xss",
    "XSS": "agent.finding.type.xss",
    "CSRF": "agent.finding.type.csrf",
    "文件包含/遍历": "agent.finding.type.file_inclusion_traversal",
    "弱口令/暴力破解": "agent.finding.type.weak_credentials",
    "配置错误": "agent.finding.type.misconfiguration",
    "敏感目录/文件发现": "agent.finding.type.sensitive_path_disclosure",
    "版本信息": "agent.finding.type.version_disclosure",
    "已知CVE漏洞": "agent.finding.type.known_cve",
    "数据泄露": "agent.finding.type.data_exposure",
    "未授权访问": "agent.finding.type.unauthorized_access",
    "注入漏洞": "agent.finding.type.injection",
    "潜在授权绕过": "agent.finding.type.potential_authorization_bypass",
    "403认证拦截": "agent.finding.type.authentication_block",
}

URL_PATTERN = re.compile(r'https?://[^\s<>"\')\]]+')
PATH_PATTERN = re.compile(r"(?:/[\w%&=?\-]+)+")


def _display_vuln_type(vuln_type: str) -> str:
    key = VULN_TYPE_DISPLAY_KEYS.get(vuln_type)
    return _(key) if key else vuln_type


def _collect_location_summary(text: str, max_items: int = 4) -> str:
    seen: set[str] = set()
    items: list[str] = []

    for value in re.findall(URL_PATTERN, text):
        if value not in seen:
            seen.add(value)
            items.append(value)
        if len(items) >= max_items:
            return " | ".join(items)

    for value in re.findall(PATH_PATTERN, text):
        if value not in seen:
            seen.add(value)
            items.append(value)
        if len(items) >= max_items:
            break

    return " | ".join(items)


class FindingParser:
    """Parses LLM responses to extract vulnerability findings and discoveries."""

    def __init__(self, context: ContextManager, runtime: RuntimeState) -> None:
        self.context = context
        self.runtime = runtime

    def parse(self, response: str) -> None:
        """Three-layer detection:
        1. Explicit [Severity] tags
        2. Natural-language vulnerability descriptions
        3. confirmed_facts elevation
        """
        existing_titles = {f.title for f in self.context.state.findings}

        severity_patterns = [
            (r"\[Critical\]\s*(.+?)(?:\n|$)", "Critical"),
            (r"\[High\]\s*(.+?)(?:\n|$)", "High"),
            (r"\[Medium\]\s*(.+?)(?:\n|$)", "Medium"),
            (r"\[Low\]\s*(.+?)(?:\n|$)", "Low"),
        ]
        for pattern, severity in severity_patterns:
            for match in re.findall(pattern, response):
                title = match.strip()
                title = re.sub(r"\*+", "", title).strip(" -—–")
                if title and title not in existing_titles:
                    self.context.state.add_finding(
                        VulnerabilityFinding(
                            title=title,
                            severity=severity,
                            evidence_level="L1",
                            lifecycle_status="candidate",
                        )
                    )
                    existing_titles.add(title)

        clean_response = strip_think_tags(response)
        notes = self.context.state.notes
        if notes:
            clean_notes = [strip_think_tags(n) for n in notes[-5:]]
            evidence_pool = clean_response + " " + " ".join(clean_notes)
        else:
            evidence_pool = clean_response

        for pattern, severity, vuln_type in NATURAL_LANG_PATTERNS:
            # Use stable vuln_type for dedup, not the localized title
            # (same vuln_type from different languages must dedupe correctly)
            if vuln_type in {f.vuln_type for f in self.context.state.findings if f.vuln_type}:
                continue

            canonical_title = _(
                "agent.finding.auto_title", vuln_type=_display_vuln_type(vuln_type)
            )

            vuln_matches = re.findall(pattern, clean_response, re.IGNORECASE)
            if not vuln_matches:
                continue

            has_proof = any(
                re.search(p, clean_response + " " + " ".join(notes[-3:]), re.IGNORECASE)
                for p in PROOF_PATTERNS
            )
            has_confirmed_fact = any(
                re.search(
                    p, " ".join(getattr(self.context.state, "confirmed_facts", [])), re.IGNORECASE
                )
                for p in PROOF_PATTERNS
            )
            if not has_proof and not has_confirmed_fact:
                continue

            proof_snippets: list[str] = []
            for pattern_text in PROOF_PATTERNS:
                for match in re.finditer(pattern_text, evidence_pool, re.IGNORECASE):
                    snippet = match.group(0).strip()[:80]
                    if snippet and snippet not in proof_snippets:
                        proof_snippets.append(snippet)
                    if len(proof_snippets) >= 3:
                        break

            location = _collect_location_summary(evidence_pool)
            proof_text = " | ".join(proof_snippets) if proof_snippets else ""
            evidence = (
                f"{location} | {proof_text}" if location and proof_text else location or proof_text
            )

            self.context.state.add_finding(
                VulnerabilityFinding(
                    title=canonical_title,
                    severity=severity,
                    vuln_type=vuln_type,
                    description=_(
                        "agent.finding.auto_description",
                        match=vuln_matches[0].strip()[:100],
                    )
                    if vuln_matches
                    else _("agent.finding.auto_description_fallback"),
                    evidence=evidence[:300],
                    evidence_level="L2",
                    lifecycle_status="needs_manual_review"
                    if severity in ("Critical", "High")
                    else "pending_verification",
                )
            )
            existing_titles.add(canonical_title)

        confirmed_facts = getattr(self.context.state, "confirmed_facts", [])
        for fact in confirmed_facts:
            for pattern, severity, vuln_type in ELEVATION_KEYWORDS:
                if re.search(pattern, fact, re.IGNORECASE):
                    title = _("agent.finding.confirmed_title", fact=fact.strip()[:120])
                    if title not in existing_titles:
                        location = _collect_location_summary(evidence_pool)
                        evidence = (
                            _("agent.finding.confirmed_evidence", fact=fact, location=location)
                            if location
                            else _("agent.finding.confirmed_description", fact=fact)
                        )
                        finding = VulnerabilityFinding(
                            title=title,
                            severity=severity,
                            vuln_type=vuln_type,
                            description=_("agent.finding.confirmed_description", fact=fact),
                            evidence=evidence[:300],
                            evidence_level="L4",
                            lifecycle_status="verified",
                        )
                        finding.mark_verified(note=fact[:200], evidence_level="L4")
                        added = self.context.state.add_finding(finding)
                        if not added:
                            for existing in self.context.state.findings:
                                if existing.finding_id == finding.finding_id or (
                                    existing.vuln_type == finding.vuln_type
                                    and existing.verification_status != "verified"
                                ):
                                    existing.title = finding.title
                                    existing.severity = finding.severity
                                    existing.vuln_type = finding.vuln_type
                                    existing.description = finding.description
                                    existing.evidence = finding.evidence
                                    existing.verified = True
                                    existing.verification_status = "verified"
                                    existing.lifecycle_status = "verified"
                                    existing.evidence_level = "L4"
                                    existing.verified_at = finding.verified_at
                                    existing.verification_note = finding.verification_note
                                    break
                        existing_titles.add(title)
                    break

        clean_response = strip_think_tags(response)
        discovery_markers = [
            r"\[\+\]\s*(.+?)(?:\n|$)",
            r"发现[：: ]\s*(.+?)(?:\n|$)",
            r"(flag\{[^}]+\})",
            r"(NSSCTF\{[^}]+\})",
            r"(CTF\{[^}]+\})",
        ]
        for pattern in discovery_markers:
            for match in re.findall(pattern, clean_response, re.IGNORECASE):
                note = match.strip()[:200]
                if note and note not in self.context.state.notes:
                    self.context.state.add_note(note)

        confirmed_markers = [
            r"已确认[：: ]\s*(.+?)(?:\n|$)",
            r"确认[：: ]\s*(.+?)(?:\n|$)",
            r"验证成功[：: ]\s*(.+?)(?:\n|$)",
            r"\[✅\]\s*(.+?)(?:\n|$)",
            r"确认.*存在",
            r"漏洞.*已确认",
            r"已.*验证.*成功",
            r"payload.*差异[：: ]*\s*\d+",
            r"差异[：: ]*\s*\d+.*成功",
            r"SLEEP\([^)]+\).*耗时",
            r"成功提取[：: ]*\s*\S+",
            r"提取到[：: ]*\s*\S+",
            r"命令执行成功",
            r"可提取到[：: ]*\s*\S+",
            r"布尔.*成功|布尔.*有效",
            r"报错.*成功|报错.*有效",
            r"UNION.*成功|UNION.*有效",
            r"漏洞确认",
        ]
        for pattern in confirmed_markers:
            for match in re.findall(pattern, response, re.IGNORECASE):
                fact = match.strip()[:200]
                if fact and hasattr(self.context.state, "add_confirmed_fact"):
                    self.context.state.add_confirmed_fact(fact)

        assumption_markers = [
            r"假设[：: ]\s*(.+?)(?:\n|$)",
            r"推测[：: ]\s*(.+?)(?:\n|$)",
        ]
        for pattern in assumption_markers:
            for match in re.findall(pattern, response, re.IGNORECASE):
                assumption = match.strip()[:200]
                if assumption and assumption not in self.runtime.unverified_assumptions:
                    self.runtime.unverified_assumptions.append(assumption)
