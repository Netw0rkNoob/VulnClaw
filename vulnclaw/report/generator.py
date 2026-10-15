"""VulnClaw Report Generator — generate structured penetration test reports."""

from __future__ import annotations

import logging
import re
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Optional

from jinja2 import Template

from vulnclaw import __version__

# 修改者: Nyaecho
# 修改时间: 2026-07-08
# 修改原因: 消除 V2 违规 — 叶子类型已移至 config/domain_models.py。
from vulnclaw.agent.context import SessionState
from vulnclaw.config.domain_models import VulnerabilityFinding
from vulnclaw.config.settings import SESSIONS_DIR
from vulnclaw.i18n import _, current_lang
from vulnclaw.i18n.phases import localized_phase_name, localized_report_phase_heading
from vulnclaw.report.filter import ReportContentFilter, deduplicate_report_findings
from vulnclaw.report.findings_output import write_findings_artifacts


def _rl(zh: str, en: str) -> str:
    """Return the English or Chinese variant based on the active UI language."""
    return en if current_lang() == "en" else zh

logger = logging.getLogger(__name__)

REPORT_TEMPLATE = """# {{ report_title }}

## 1. {{ labels.overview }}

| {{ labels.item }} | {{ labels.value }} |
|---|---|
| {{ labels.target }} | {{ target }} |
| {{ labels.started }} | {{ started_at }} |
| {{ labels.generated }} | {{ generated_at }} |
| {{ labels.version }} | VulnClaw {{ version }} |
| {{ labels.scope }} | {{ task_constraints_summary }} |
{% if cycle_num %}| {{ labels.cycle }} | {{ cycle_num }} |{% endif %}

## 2. {{ labels.summary }}

{% for group in groups %}- **{{ group.label }}**: {{ group.findings|length }}
{% endfor %}
- {{ labels.surface }}: {{ attack_surface_summary }}
| Severity | {{ labels.value }} |
|---|---|
{% for severity, count in severity_counts.items() %}| {{ severity }} | {{ count }} |
{% endfor %}
### {{ labels.recommendations }}
{% for recommendation in recommendations %}- {{ recommendation }}{% endfor %}
{% if not findings %}
{{ labels.empty }}
{% endif %}

## 3. {{ labels.details }}

{% for group in groups %}
### {{ group.label }}
{% for finding in group.findings %}
#### {{ finding.title }} — [{{ finding.severity }}]

- {{ labels.type }}: {{ finding.vuln_type }}
- {{ labels.location }}: {{ finding.location_summary }}
- {{ labels.lifecycle }}: {{ finding.lifecycle_status }}
- {{ labels.evidence_level }}: {{ finding.evidence_level }}
- CVE: {{ finding.cve or 'N/A' }}
- {{ labels.impact }}: {{ finding.description }}
- {{ labels.remediation }}: {{ finding.remediation }}
- {{ labels.method }}: {{ finding.assessment.method }}
- {{ labels.basis }}: {{ finding.assessment.reason }}
{% if not finding.assessment.complete %}- **{{ labels.incomplete }}**{% endif %}
{% if finding.assessment.failure_reason %}- {{ labels.failure }}: {{ finding.assessment.failure_reason }}{% endif %}
{% if finding.assessment.missing_checks %}- {{ labels.missing }}: {{ finding.assessment.missing_checks|join('; ') }}{% endif %}
{% if finding.previous_verification.verification_status in ['verified', 'rejected'] %}- {{ labels.previous }}: {{ finding.previous_verification.verification_status }} — {{ finding.previous_verification.verification_note }}{% endif %}
{% if finding.evidence %}- {{ labels.evidence }}: {{ finding.evidence }}{% endif %}
{% for observation in finding.assessment.observations %}- {{ labels.observation }}: {{ observation }}{% endfor %}
{% for artifact in finding.assessment.artifacts %}- {{ labels.artifact }}: {{ artifact }}{% endfor %}
- {{ labels.reproduction }}: {{ finding.repro_summary }}

{% endfor %}
{% endfor %}

## 4. {{ labels.attack_path }}

{{ llm_attack_summary }}
{% for phase_name, phase_data in step_summary.phases.items() %}
### {{ phase_heading(phase_name, phase_data.count) }}
{% for action in phase_data.actions %}- {{ action }}{% endfor %}
{% endfor %}

## 5. {{ labels.constraints }}

{% for event in constraint_violation_events %}- {{ event.summary }}{% endfor %}
{% for violation in constraint_violations %}- {{ violation }}{% endfor %}

{{ labels.principle }}
"""


def _labels() -> dict[str, str]:
    pairs = {
        "overview": ("项目概述", "Project Overview"), "item": ("项目", "Item"),
        "value": ("详情", "Details"), "target": ("测试目标", "Target"),
        "started": ("测试时间", "Started"), "generated": ("报告生成", "Generated"),
        "version": ("测试工具版本", "Tool Version"), "scope": ("任务约束", "Task Constraints"),
        "cycle": ("周期", "Cycle"), "summary": ("执行摘要", "Executive Summary"),
        "surface": ("攻击面", "Attack Surface"), "details": ("详细发现", "Detailed Findings"),
        "type": ("漏洞类型", "Vulnerability Type"), "location": ("位置 / URL", "Location / URL"),
        "lifecycle": ("生命周期", "Lifecycle"), "evidence_level": ("证据等级", "Evidence Level"),
        "impact": ("影响范围", "Impact"), "remediation": ("修复建议", "Remediation"),
        "method": ("审计方式", "Assessment Method"), "basis": ("判定依据", "Assessment Basis"),
        "failure": ("PoC 未完成原因", "PoC Incomplete Reason"), "missing": ("缺失检查", "Missing Checks"),
        "previous": ("此前结论（不代替当前审计）", "Previous Result (not current assessment)"),
        "evidence": ("验证证据", "Evidence"), "observation": ("证据观察", "Observation"),
        "artifact": ("验证附件", "Verification Artifact"), "reproduction": ("复现 / PoC", "Reproduction / PoC"),
        "attack_path": ("攻击路径摘要", "Attack Path Summary"),
        "constraints": ("约束违规审计", "Constraint Violation Audit"),
        "recommendations": ("关键建议", "Key Recommendations"),
        "incomplete": ("校验未完成", "Assessment incomplete"),
        "empty": ("本次没有已上报的漏洞候选。", "No vulnerability candidates were submitted."),
        "principle": ("疑似结果保留供复核；只有对应当前漏洞输入、经 PoC 明确验证成立的结果计入已验证漏洞。",
                      "Suspected findings remain available for review; only conclusive PoC results count as verified."),
    }
    return {key: _rl(*value) for key, value in pairs.items()}


def _render_assessed_report(session, output: Path, *, summary="", cycle_num=None, target_state_context=None):
    from html import escape

    from vulnclaw.findings.types import require_assessed

    require_assessed(session)
    groups = []
    for outcome, zh, en in (
        ("verified", "已验证漏洞", "Verified Findings"),
        ("rejected", "确认排除", "Confirmed Exclusions"),
        ("suspected_high", "高置信疑似", "High-confidence Suspected Findings"),
        ("suspected_low", "低置信疑似", "Low-confidence Suspected Findings"),
    ):
        findings = [f for f in session.findings if f.assessment.outcome == outcome]
        groups.append({"label": _rl(zh, en), "findings": [_build_report_finding(f) for f in findings]})
    verified = deduplicate_report_findings(session.get_verified_findings())
    recommendations = []
    seen_types = set()
    for finding in verified:
        if finding.severity not in {"Critical", "High"}:
            continue
        kind = finding.vuln_type or _("report.rec.uncategorized")
        if kind in seen_types:
            continue
        seen_types.add(kind)
        recommendations.append(finding.remediation or (
            _("report.rec.fix_vuln", vt=kind, title=finding.title) if cycle_num
            else _("report.rec.fix_priority", vt=kind, title=finding.title)
        ))
    if not recommendations:
        recommendations.append(_("report.rec.none_high") if cycle_num else _("report.rec.review_surface"))
    context = {
        "report_title": _rl("渗透测试报告", "Penetration Test Report"), "labels": _labels(),
        "target": session.target or "unknown", "started_at": session.started_at,
        "generated_at": datetime.now().isoformat(), "version": __version__, "cycle_num": cycle_num,
        "task_constraints_summary": _format_task_constraints_summary(session),
        "attack_surface_summary": _summarize_attack_surface(session), "groups": groups,
        "findings": session.findings, "step_summary": session.get_step_summary(),
        "recommendations": recommendations,
        "severity_counts": {severity: sum(f.severity == severity for f in verified)
                            for severity in ("Critical", "High", "Medium", "Low", "Info")},
        "phase_heading": localized_report_phase_heading,
        "constraint_violations": session.constraint_violations,
        "constraint_violation_events": session.constraint_violation_events,
        "llm_attack_summary": ReportContentFilter.filter(summary) if summary else "",
    }
    content = Template(REPORT_TEMPLATE).render(**context)
    if verified:
        content += "\n\n" + _render_verified_finding_details_clean(
            verified, _rl("## 已验证漏洞定位与复现信息", "## Verified Findings — Location & Reproduction"),
            traffic_store=_resolve_traffic_store(output.parent),
        )
    if target_state_context:
        content += "\n\n" + _render_target_state_context(target_state_context)
    if output.suffix == ".html":
        content = '<!doctype html><html><head><meta charset="utf-8"><title>VulnClaw Report</title></head><body><pre>' + escape(content) + '</pre></body></html>'
    output.write_text(content, encoding="utf-8")
    write_findings_artifacts(session, output.parent / (output.stem + ".artifacts") / "findings")
    return output


async def generate_report(
    session: SessionState, output_path: Optional[str] = None, llm_attack_summary: str = "",
    report_format: str = "markdown", target_state_context: Optional[dict[str, Any]] = None,
) -> Path:
    from uuid import uuid4

    from vulnclaw.findings.types import require_assessed

    if output_path is None:
        safe_target = (session.target or "unknown").replace("/", "_").replace(":", "_")
        output_path = str(SESSIONS_DIR / f"report_{datetime.now():%Y%m%d_%H%M%S}_{safe_target}_{uuid4().hex[:8]}.md")
    output = Path(output_path)
    if report_format.lower() == "html":
        output = output.with_suffix(".html")
    if output.exists():
        raise FileExistsError("Report output already exists; choose a new output path")
    output.parent.mkdir(parents=True, exist_ok=True)
    require_assessed(session)
    assessed = session.model_copy(deep=True)
    assessed.findings = deduplicate_report_findings(assessed.findings)
    assessed._vulnerabilities.findings = assessed.findings
    if not llm_attack_summary:
        import asyncio
        llm_attack_summary = await asyncio.to_thread(_generate_attack_summary_from_session, assessed)
    return _render_assessed_report(assessed, output, summary=llm_attack_summary,
                                   target_state_context=target_state_context)


def _summarize_attack_surface(session: SessionState) -> str:
    """Summarize the attack surface from recon data, including subdomains."""
    parts = []
    recon = session.recon_data

    if "subdomains" in recon and recon["subdomains"]:
        joined = ", ".join(recon["subdomains"][:10])
        parts.append(_rl(f"子域名: {joined}", f"Subdomains: {joined}"))
    if "ports" in recon:
        parts.append(_rl(f"开放端口: {recon['ports']}", f"Open ports: {recon['ports']}"))
    if "services" in recon:
        parts.append(_rl(f"服务: {recon['services']}", f"Services: {recon['services']}"))
    if "technologies" in recon:
        parts.append(_rl(f"技术栈: {recon['technologies']}", f"Technologies: {recon['technologies']}"))
    if "waf" in recon:
        parts.append(_rl(f"WAF: {recon['waf']}", f"WAF: {recon['waf']}"))
    if "domains" in recon:
        joined = ", ".join(recon["domains"][:5])
        parts.append(_rl(f"关联域名: {joined}", f"Related domains: {joined}"))

    return "; ".join(parts) if parts else _rl("未收集", "Not collected")


# ── Persistent Pentest Cycle Report ──────────────────────────────────

def _generate_attack_summary_from_session(session: SessionState) -> str:
    """Generate a readable attack-path summary using VulnClaw's configured LLM."""
    try:
        from vulnclaw.config.settings import load_config, make_openai_client
        from vulnclaw.config.text_utils import strip_think_tags
        from vulnclaw.config.token_provider import (
            TokenResolutionError,
            has_llm_credentials,
            resolve_llm_token,
        )

        config = load_config()
        if not has_llm_credentials(config.llm):
            return ""

        try:
            token = resolve_llm_token(config.llm)
        except TokenResolutionError:
            return ""

        client = make_openai_client(
            api_key=token,
            base_url=config.llm.base_url,
        )

        steps = session.executed_steps[-40:] if session.executed_steps else []
        notes = session.notes[-25:] if session.notes else []
        findings = session.findings[-20:] if session.findings else []

        steps_text = (
            "\n".join(f"{idx + 1}. {step}" for idx, step in enumerate(steps))
            if steps
            else "No step records"
        )
        notes_text = "\n".join(f"- {note}" for note in notes) if notes else "No key observations"
        findings_text = (
            "\n".join(
                f"- [{finding.assessment.outcome}] [{finding.severity}] {finding.title} | Evidence: {(finding.evidence or '')[:200]}"
                for finding in findings
            )
            if findings
            else "No findings"
        )

        summary_language = "English" if current_lang() == "en" else "Chinese"
        prompt = (
            f"Target: {session.target or 'unknown'}\n"
            f"Phase: {localized_phase_name(session.phase)}\n\n"
            f"=== Executed Steps ===\n{steps_text}\n\n"
            f"=== Key Observations ===\n{notes_text}\n\n"
            f"=== Findings ===\n{findings_text}\n\n"
            f"Please write a readable {summary_language} attack-path summary. Requirements:\n"
            "1. Clearly explain how the testing progressed, not generic filler.\n"
            "2. Mention URLs, paths, parameters, stack, and verification actions when available.\n"
            "3. Explicitly call out false positives or findings that failed to reproduce.\n"
            "4. Output 2-5 short natural-language paragraphs only. No markdown headings. No thinking tags.\n"
            "5. Do not invent steps that were never executed or promote suspected findings.\n"
        )

        # Reports do not have an AgentCore instance, but their LLM request
        # still goes through the same budget/compaction policy as agent turns.
        from vulnclaw.agent.context_budget import prepare_context

        budget_agent = SimpleNamespace(
            config=config,
            context=SimpleNamespace(state=session),
        )
        messages = prepare_context(
            budget_agent,
            [{"role": "user", "content": prompt}],
            [],
            purpose="report_summary",
        ).messages

        response = client.chat.completions.create(
            **_build_report_summary_llm_kwargs(
                config,
                messages,
            )
        )
        if response and response.choices:
            raw = response.choices[0].message.content or ""
            return strip_think_tags(raw).strip()
    except Exception as exc:
        logger.warning("LLM attack summary generation failed: %s", exc)
        return ""
    return ""


def _build_report_summary_llm_kwargs(config: Any, messages: list[dict[str, Any]]) -> dict[str, Any]:
    """Build Chat Completions kwargs for report summary generation."""
    # 修改者: Nyaecho
    # 修改时间: 2026-07-08
    # 修改原因: V2 修复 — 直接使用 config/llm_utils，消除 AgentContext shim。
    from vulnclaw.config.llm_utils import build_chat_completion_kwargs

    return build_chat_completion_kwargs(
        config.llm,
        messages,
        max_tokens=min(config.llm.max_tokens, 1200),
        temperature=0.2,
    )


async def generate_persistent_cycle_report(
    session: SessionState, cycle_num: int, output_path: Optional[str] = None,
    llm_attack_summary: str = "",
) -> Path:
    import asyncio
    from uuid import uuid4

    from vulnclaw.findings.types import require_assessed

    if output_path is None:
        output_path = str(SESSIONS_DIR / f"persistent_cycle{cycle_num:03d}_{datetime.now():%Y%m%d_%H%M%S}_{uuid4().hex[:8]}.md")
    output = Path(output_path)
    if output.exists():
        raise FileExistsError("Report output already exists; choose a new output path")
    output.parent.mkdir(parents=True, exist_ok=True)
    require_assessed(session)
    assessed = session.model_copy(deep=True)
    assessed.findings = deduplicate_report_findings(assessed.findings)
    assessed._vulnerabilities.findings = assessed.findings
    if not llm_attack_summary:
        llm_attack_summary = await asyncio.to_thread(_generate_attack_summary_from_session, assessed)
    return _render_assessed_report(assessed, output, summary=llm_attack_summary, cycle_num=cycle_num)


def _render_target_state_context(target_state_context: dict[str, Any]) -> str:
    """Render extra governance context for target-state based reports."""
    resume_meta = target_state_context.get("resume_meta") or {}
    recon_meta = target_state_context.get("recon_meta") or {}
    runtime_meta = target_state_context.get("runtime_meta") or {}
    resume_summary = target_state_context.get("resume_summary") or ""

    lines = [_rl("## 6. 目标历史治理上下文", "## 6. Target Historical Governance Context")]

    if resume_meta:
        lines.extend(
            [
                "",
                _rl(
                    f"- 恢复策略: {resume_meta.get('resume_strategy', 'unknown')}",
                    f"- Resume strategy: {resume_meta.get('resume_strategy', 'unknown')}",
                ),
                _rl(
                    f"- 策略原因: {resume_meta.get('resume_strategy_reason', 'N/A')}",
                    f"- Strategy reason: {resume_meta.get('resume_strategy_reason', 'N/A')}",
                ),
            ]
        )
        if resume_meta.get("priority_targets"):
            joined = ", ".join(resume_meta["priority_targets"][:5])
            lines.append(_rl(f"- 恢复优先目标: {joined}", f"- Resume priority targets: {joined}"))
        if resume_meta.get("priority_recon_assets"):
            joined = ", ".join(resume_meta["priority_recon_assets"][:5])
            lines.append(
                _rl(
                    f"- 恢复优先侦察资产: {joined}",
                    f"- Resume priority recon assets: {joined}",
                )
            )
        if resume_meta.get("blocked_targets"):
            joined = ", ".join(resume_meta["blocked_targets"][:5])
            lines.append(_rl(f"- 已阻塞目标: {joined}", f"- Blocked targets: {joined}"))
        if resume_meta.get("failed_targets"):
            joined = ", ".join(resume_meta["failed_targets"][:5])
            lines.append(_rl(f"- 历史失败目标: {joined}", f"- Historically failed targets: {joined}"))
        if resume_meta.get("recent_failed_steps"):
            lines.append(_rl("- 最近失败路径/步骤:", "- Recent failed paths/steps:"))
            for item in resume_meta["recent_failed_steps"][:5]:
                lines.append(f"  - {item}")

    top_assets = _top_recon_assets_for_report(recon_meta)
    if top_assets:
        lines.extend(["", _rl("### 高价值侦察资产", "### High-Value Recon Assets")])
        for item in top_assets[:8]:
            lines.append(f"- {item}")

    if runtime_meta.get("current_attack_path"):
        lines.extend(
            [
                "",
                _rl(
                    f"- 最近攻击路径: {runtime_meta['current_attack_path']}",
                    f"- Most recent attack path: {runtime_meta['current_attack_path']}",
                ),
            ]
        )

    if resume_summary:
        lines.extend(
            ["", _rl("### 恢复摘要", "### Resume Summary"), "```text", resume_summary.strip(), "```"]
        )

    return "\n".join(lines)


def _top_recon_assets_for_report(recon_meta: dict[str, Any]) -> list[str]:
    ranked: list[tuple[float, str]] = []
    for category, items in recon_meta.items():
        if not isinstance(items, dict):
            continue
        for value, meta in items.items():
            confidence = float(meta.get("confidence", 0))
            ranked.append((confidence, f"{category}:{value} (conf={confidence:.2f})"))
    ranked.sort(key=lambda item: (-item[0], item[1]))
    return [label for _confidence, label in ranked]


def _extract_location_summary_clean(finding: VulnerabilityFinding) -> str:
    text = " ".join(part for part in [finding.evidence or "", finding.description or ""] if part)
    urls = re.findall(r'https?://[^\s<>"\')\]]+', text)
    paths = re.findall(r"(?:/[\w%&=?\-]+)+", text)

    items: list[str] = []
    seen: set[str] = set()
    for value in urls + paths:
        if value not in seen:
            seen.add(value)
            items.append(value)
        if len(items) >= 4:
            break
    return " | ".join(items)


def _build_repro_summary_clean(finding: VulnerabilityFinding) -> str:
    parts: list[str] = []
    if finding.poc_script:
        parts.append(_rl(f"运行 PoC 脚本: {finding.poc_script}", f"Run PoC script: {finding.poc_script}"))
    if finding.verification_note:
        parts.append(
            _rl(f"验证说明: {finding.verification_note}", f"Verification note: {finding.verification_note}")
        )
    elif finding.evidence:
        parts.append(
            _rl(
                f"根据已验证证据复现: {finding.evidence[:160]}",
                f"Reproduce from verified evidence: {finding.evidence[:160]}",
            )
        )
    if finding.verified_at:
        parts.append(_rl(f"验证时间: {finding.verified_at}", f"Verified at: {finding.verified_at}"))
    sep = _rl("；", "; ")
    return sep.join(parts) if parts else _rl("暂无可用复现说明", "No reproduction notes available.")


def _resolve_traffic_store(output_dir: Path) -> Any | None:
    """Return the run's TrafficStore (report dir preferred, config default as
    fallback so captures the agent wrote are found), or None if none exist."""
    try:
        from vulnclaw.traffic.paths import resolve_report_traffic_store
    except Exception:
        return None
    store = resolve_report_traffic_store(output_dir)
    return store if store.index_path.exists() else None


def _render_http_captures(finding: VulnerabilityFinding, traffic_store: Any) -> list[str]:
    """Inline the raw request/response for each http_capture evidence ref.

    Each verified finding's ``evidence_refs`` with ``kind="http_capture"``
    is resolved back to its JSONL record + blob files and rendered as fenced
    code blocks.
    """
    refs = getattr(finding, "evidence_refs", None) or []
    if not refs or traffic_store is None:
        return []

    lines: list[str] = []
    for ref in refs:
        if getattr(ref, "kind", "") != "http_capture":
            continue
        request_id = getattr(ref, "request_id", "")
        view = traffic_store.view(request_id) if request_id else None
        if not view:
            continue
        header = _rl(
            f"  - 抓包证据 `{request_id}` — {view.get('method')} {view.get('url')} → {view.get('status')}",
            f"  - Captured traffic `{request_id}` — {view.get('method')} {view.get('url')} → {view.get('status')}",
        )
        lines.append(header)
        request_text = (view.get("request_text") or "").strip()
        response_text = (view.get("response_text") or "").strip()
        if request_text:
            lines.append(_rl("    - 原始请求:", "    - Raw request:"))
            lines.append("")
            lines.append("```http")
            lines.append(request_text)
            lines.append("```")
        if response_text:
            lines.append(_rl("    - 原始响应:", "    - Raw response:"))
            lines.append("")
            lines.append("```http")
            lines.append(response_text)
            lines.append("```")
    return lines


def _render_verified_finding_details_clean(
    findings: list[VulnerabilityFinding], heading: str, traffic_store: Any | None = None
) -> str:
    lines = [heading, ""]
    for idx, finding in enumerate(findings, 1):
        location = _extract_location_summary_clean(finding) or _rl(
            "未定位 / 未提取到 URL", "No location / no URL extracted"
        )
        lines.append(f"### {idx}. {finding.title} [{finding.severity}]")
        lines.append(_rl("- 漏洞类型: ", "- Vulnerability type: ") + (finding.vuln_type or _rl("未分类", "Uncategorized")))
        lines.append(_rl("- 生命周期: ", "- Lifecycle: ") + (finding.lifecycle_status or "verified"))
        lines.append(_rl("- 证据等级: ", "- Evidence level: ") + (finding.evidence_level or "L4"))
        lines.append(_rl("- 位置 / URL: ", "- Location / URL: ") + location)
        if finding.evidence:
            lines.append(_rl("- 验证证据: ", "- Verification evidence: ") + finding.evidence)
        lines.append(_rl("- 复现 / PoC: ", "- Reproduction / PoC: ") + _build_repro_summary_clean(finding))
        capture_lines = _render_http_captures(finding, traffic_store)
        if capture_lines:
            lines.append(_rl("- 抓包复现证据:", "- Captured-traffic reproduction evidence:"))
            lines.extend(capture_lines)
        lines.append("")
    return "\n".join(lines).rstrip()


def _format_task_constraints_summary(session: SessionState) -> str:
    constraints = getattr(session, "task_constraints", None)
    if constraints is None or constraints.is_empty():
        return _rl("未指定", "Unspecified")

    parts: list[str] = []
    if constraints.allowed_ports:
        joined = ",".join(str(p) for p in constraints.allowed_ports)
        parts.append(_rl(f"仅端口 {joined}", f"Ports only: {joined}"))
    if constraints.blocked_ports:
        joined = ",".join(str(p) for p in constraints.blocked_ports)
        parts.append(_rl(f"禁端口 {joined}", f"Blocked ports: {joined}"))
    if constraints.allowed_hosts:
        joined = ",".join(constraints.allowed_hosts)
        parts.append(_rl(f"仅主机 {joined}", f"Hosts only: {joined}"))
    if constraints.allowed_paths:
        joined = ",".join(constraints.allowed_paths)
        parts.append(_rl(f"仅路径 {joined}", f"Paths only: {joined}"))
    if constraints.allowed_actions:
        joined = ",".join(constraints.allowed_actions)
        parts.append(_rl(f"仅动作 {joined}", f"Actions only: {joined}"))
    if constraints.blocked_actions:
        joined = ",".join(constraints.blocked_actions)
        parts.append(_rl(f"禁动作 {joined}", f"Blocked actions: {joined}"))
    sep = _rl("；", "; ")
    return sep.join(parts) if parts else _rl("已启用约束", "Constraints enabled")


def _lifecycle_label(status: str) -> str:
    labels = {
        "pending_verification": ("待验证", "Pending Verification"),
        "needs_manual_review": ("需人工复核", "Needs Manual Review"),
        "verified": ("已验证", "Verified"),
        "rejected": ("已排除", "Rejected"),
        "candidate": ("候选", "Candidate"),
    }
    return _rl(*labels.get(status, (status, status)))


def _build_report_finding(finding: VulnerabilityFinding) -> dict[str, Any]:
    return {
        "title": finding.title,
        "severity": finding.severity,
        "vuln_type": finding.vuln_type,
        "description": finding.description,
        "evidence": finding.evidence,
        "cve": finding.cve,
        "remediation": finding.remediation,
        "poc_script": finding.poc_script,
        "verified": finding.verified,
        "verified_at": finding.verified_at,
        "verification_status": finding.verification_status,
        "verification_note": finding.verification_note,
        "lifecycle_status": _lifecycle_label(finding.lifecycle_status),
        "evidence_level": finding.evidence_level,
        "subagent_provenance": finding.subagent_provenance,
        "assessment": finding.assessment,
        "previous_verification": finding.previous_verification,
        "location_summary": _extract_location_summary_clean(finding),
        "repro_summary": _build_repro_summary_clean(finding),
    }
