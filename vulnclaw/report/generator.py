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
from vulnclaw.report.poc_builder import generate_pocs


def _rl(zh: str, en: str) -> str:
    """Return the English or Chinese variant based on the active UI language."""
    return en if current_lang() == "en" else zh

logger = logging.getLogger(__name__)

# ── Report Template ─────────────────────────────────────────────────

REPORT_TEMPLATE = """\
# 渗透测试报告

## 1. 项目概述

| 项目 | 详情 |
|------|------|
| **测试目标** | {{ target }} |
| **测试时间** | {{ started_at }} |
| **报告生成** | {{ generated_at }} |
| **测试工具** | VulnClaw v{{ version }} |
| **任务约束** | {{ task_constraints_summary }} |

## 2. 执行摘要

{% if verified_count > 0 %}
- **已验证漏洞**: {{ verified_count }} 个（其中高危 {{ critical_count }} 个 Critical, {{ high_count }} 个 High）
{% else %}
- **已验证漏洞**: 0 个
{% endif %}
- **误报排除**: {{ rejected_count }} 个
- **待验证**: {{ pending_count }} 个（未在报告中显示）
- **候选项**: {{ candidate_count }} 个
- **待验证项**: {{ pending_verification_count }} 个
- **需人工复核**: {{ manual_review_count }} 个
- **攻击面**: {{ attack_surface_summary }}
{% if constraint_violation_events or constraint_violations %}
- **约束违规已阻断**: {{ constraint_violations|length }} 次
{% endif %}

{% if rejected_count > 0 %}
### 已排除的误报

以下漏洞假设经 PoC 验证失败，已排除，不计入报告：

{% for f in rejected_findings %}
- {{ f.title }} — {{ f.verification_note }}
{% endfor %}
{% endif %}

### 风险等级分布

| 等级 | 数量 |
|------|------|
| Critical | {{ critical_count }} |
| High | {{ high_count }} |
| Medium | {{ medium_count }} |
| Low/Info | {{ low_count }} |

{% if verified_findings %}
### 关键建议

{% for rec in key_recommendations %}
{{ loop.index }}. {{ rec }}
{% endfor %}
{% else %}
### 漏洞发现

**本次测试未发现有效漏洞。**

可能原因：
- 目标系统安全配置较好
- 渗透深度不够（信息收集轮数不足）
- 漏洞利用条件未满足

建议：
- 增加渗透测试轮数
- 尝试更多漏洞类型
- 检查是否需要特殊认证或访问权限
{% endif %}

## 3. 详细发现

{% for finding in findings %}
### 3.{{ loop.index }} {{ finding.title }} — [{{ finding.severity }}]
{% if finding.verification_status == "pending" %}
> ⚠️ **待验证** — 此漏洞由自动检测发现，尚未通过 PoC 验证。请手动审查。
{% elif finding.verification_status == "rejected" %}
> ❌ **已排除（误报）** — {{ finding.verification_note or "经验证为误报" }}
{% elif finding.lifecycle_status == "needs_manual_review" %}
> 🔎 **需人工复核** — 当前已有间接证据，但仍需人工复核后再升级为正式漏洞。
{% endif %}

- **漏洞类型**: {{ finding.vuln_type or "未分类" }}
- **生命周期**: {{ finding.lifecycle_status or "pending_verification" }}
- **证据等级**: {{ finding.evidence_level or "L1" }}
- **CVE**: {{ finding.cve or "N/A" }}
- **影响范围**: {{ finding.description or "无" }}
{% if finding.evidence %}
- **验证证据**: {{ finding.evidence }}
{% endif %}
{% if finding.poc_script %}
- **PoC 脚本**: 见附件 `{{ finding.poc_script }}`
{% endif %}
- **修复建议**: {{ finding.remediation or "请根据漏洞类型采取相应修复措施" }}
{% if finding.verified and finding.verified_at %}
- **验证时间**: {{ finding.verified_at }}
{% endif %}

{% endfor %}

{% if llm_attack_summary %}
## 4. 攻击路径摘要

{{ llm_attack_summary }}

{% elif step_summary and step_summary.total_steps > 0 %}
## 4. 攻击路径摘要

{% for phase_name, phase_data in step_summary.phases.items() %}
{{ phase_heading(phase_name, phase_data.count) }}

| 状态 | 数量 |
|------|------|
| ✅ 成功 | {{ phase_data.success_count }} |
| ❌ 失败 | {{ phase_data.failure_count }} |

**关键动作**: {{ phase_data.actions[:5]|join(', ') }}

{% if phase_data.key_results %}
**主要发现**:
{% for result in phase_data.key_results %}
- {{ result }}
{% endfor %}
{% endif %}

---
{% endfor %}

**总计**: {{ step_summary.total_steps }} 步

{% if step_summary.key_findings %}
### 关键发现时间线

{% for finding in step_summary.key_findings %}
- {{ finding }}
{% endfor %}
{% endif %}

{% elif findings %}
## 4. 攻击路径

{% for step in executed_steps %}
{{ loop.index }}. {{ step }}
{% endfor %}
{% endif %}

{% if constraint_violation_events or constraint_violations %}
## 5. 约束违规审计

{% if constraint_violation_events %}
{% for item in constraint_violation_events %}
- [{{ item.source or "unknown" }}] {{ item.summary }}
{% endfor %}
{% else %}
{% for item in constraint_violations %}
- {{ item }}
{% endfor %}
{% endif %}
{% endif %}

## 6. 附件

- PoC 脚本: 见 `pocs/` 目录
- 流量抓包: 见 `evidence/traffic/` 目录（requests.jsonl 索引 + 每请求原始请求/响应）
- 截图证据: 见 `screenshots/` 目录

---

> 🦞 报告由 VulnClaw 自动生成 | {{ generated_at }}
> **原则**: 未经验证的漏洞 = 误报 = 不写入报告
"""


REPORT_TEMPLATE_EN = """\
# Penetration Test Report

## 1. Project Overview

| Item | Details |
|------|------|
| **Target** | {{ target }} |
| **Test Time** | {{ started_at }} |
| **Report Generated** | {{ generated_at }} |
| **Testing Tool** | VulnClaw v{{ version }} |
| **Task Constraints** | {{ task_constraints_summary }} |

## 2. Executive Summary

{% if verified_count > 0 %}
- **Verified Findings**: {{ verified_count }} (including {{ critical_count }} Critical, {{ high_count }} High)
{% else %}
- **Verified Findings**: 0
{% endif %}
- **False Positives Excluded**: {{ rejected_count }}
- **Pending Verification**: {{ pending_count }} (not shown in this report)
- **Candidates**: {{ candidate_count }}
- **Pending Verification Items**: {{ pending_verification_count }}
- **Needs Manual Review**: {{ manual_review_count }}
- **Attack Surface**: {{ attack_surface_summary }}
{% if constraint_violation_events or constraint_violations %}
- **Constraint Violations Blocked**: {{ constraint_violations|length }}
{% endif %}

{% if rejected_count > 0 %}
### Excluded False Positives

The following vulnerability hypotheses failed PoC verification and were excluded from the report:

{% for f in rejected_findings %}
- {{ f.title }} — {{ f.verification_note }}
{% endfor %}
{% endif %}

### Risk Severity Distribution

| Severity | Count |
|------|------|
| Critical | {{ critical_count }} |
| High | {{ high_count }} |
| Medium | {{ medium_count }} |
| Low/Info | {{ low_count }} |

{% if verified_findings %}
### Key Recommendations

{% for rec in key_recommendations %}
{{ loop.index }}. {{ rec }}
{% endfor %}
{% else %}
### Findings

**No valid vulnerabilities were found during this test.**

Possible reasons:
- The target system's security posture is relatively solid
- Insufficient testing depth (not enough recon rounds)
- Exploitation preconditions were not met

Recommendations:
- Increase the number of pentest rounds
- Try more vulnerability classes
- Check whether special authentication or access is required
{% endif %}

## 3. Detailed Findings

{% for finding in findings %}
### 3.{{ loop.index }} {{ finding.title }} — [{{ finding.severity }}]
{% if finding.verification_status == "pending" %}
> ⚠️ **Pending verification** — auto-detected, not yet confirmed via PoC. Manual review required.
{% elif finding.verification_status == "rejected" %}
> ❌ **Excluded (false positive)** — {{ finding.verification_note or "Verified as a false positive" }}
{% elif finding.lifecycle_status == "needs_manual_review" %}
> 🔎 **Needs manual review** — indirect evidence exists but manual review is required before promoting to a confirmed finding.
{% endif %}

- **Vulnerability Type**: {{ finding.vuln_type or "Uncategorized" }}
- **Lifecycle**: {{ finding.lifecycle_status or "pending_verification" }}
- **Evidence Level**: {{ finding.evidence_level or "L1" }}
- **CVE**: {{ finding.cve or "N/A" }}
- **Impact**: {{ finding.description or "None" }}
{% if finding.evidence %}
- **Verification Evidence**: {{ finding.evidence }}
{% endif %}
{% if finding.poc_script %}
- **PoC Script**: see attachment `{{ finding.poc_script }}`
{% endif %}
- **Remediation**: {{ finding.remediation or "Apply remediation appropriate to the vulnerability type." }}
{% if finding.verified and finding.verified_at %}
- **Verified At**: {{ finding.verified_at }}
{% endif %}

{% endfor %}

{% if llm_attack_summary %}
## 4. Attack Path Summary

{{ llm_attack_summary }}

{% elif step_summary and step_summary.total_steps > 0 %}
## 4. Attack Path Summary

{% for phase_name, phase_data in step_summary.phases.items() %}
{{ phase_heading(phase_name, phase_data.count) }}

| Status | Count |
|------|------|
| ✅ Success | {{ phase_data.success_count }} |
| ❌ Failure | {{ phase_data.failure_count }} |

**Key Actions**: {{ phase_data.actions[:5]|join(', ') }}

{% if phase_data.key_results %}
**Key Findings**:
{% for result in phase_data.key_results %}
- {{ result }}
{% endfor %}
{% endif %}

---
{% endfor %}

**Total**: {{ step_summary.total_steps }} steps

{% if step_summary.key_findings %}
### Key Findings Timeline

{% for finding in step_summary.key_findings %}
- {{ finding }}
{% endfor %}
{% endif %}

{% elif findings %}
## 4. Attack Path

{% for step in executed_steps %}
{{ loop.index }}. {{ step }}
{% endfor %}
{% endif %}

{% if constraint_violation_events or constraint_violations %}
## 5. Constraint Violation Audit

{% if constraint_violation_events %}
{% for item in constraint_violation_events %}
- [{{ item.source or "unknown" }}] {{ item.summary }}
{% endfor %}
{% else %}
{% for item in constraint_violations %}
- {{ item }}
{% endfor %}
{% endif %}
{% endif %}

## 6. Attachments

- PoC scripts: see the `pocs/` directory
- Captured traffic: see the `evidence/traffic/` directory (requests.jsonl index + raw request/response per request)
- Screenshot evidence: see the `screenshots/` directory

---

> 🦞 Report auto-generated by VulnClaw | {{ generated_at }}
> **Principle**: Unverified vulnerability = false positive = not written to the report
"""


def _severity_count_context(verified_findings: list[VulnerabilityFinding]) -> dict[str, int]:
    """Tally verified findings by severity into report context keys.

    Unknown severities fall back to Medium; Info rolls up into the Low bucket.
    """
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for finding in verified_findings:
        sev = finding.severity
        if sev in counts:
            counts[sev] += 1
        else:
            counts["Medium"] += 1
    return {
        "critical_count": counts["Critical"],
        "high_count": counts["High"],
        "medium_count": counts["Medium"],
        "low_count": counts["Low"] + counts["Info"],
    }


def generate_report(
    session: SessionState,
    output_path: Optional[str] = None,
    llm_attack_summary: str = "",
    report_format: str = "markdown",
    target_state_context: Optional[dict[str, Any]] = None,
) -> Path:
    """Generate a penetration test report from session state.

    Only verified findings are rendered into the main detailed findings section.
    Pending, candidate, and rejected findings remain in summary/governance views.
    """

    all_findings = session.findings
    verified_findings = deduplicate_report_findings(session.get_verified_findings())
    pending_findings = session.get_pending_findings()
    rejected_findings = session.get_rejected_findings()
    candidate_findings = (
        session.get_candidate_findings() if hasattr(session, "get_candidate_findings") else []
    )
    pending_verification_findings = (
        session.get_pending_verification_findings()
        if hasattr(session, "get_pending_verification_findings")
        else []
    )
    manual_review_findings = (
        session.get_manual_review_findings()
        if hasattr(session, "get_manual_review_findings")
        else []
    )

    seen_vuln_types = set()
    recommendations = []
    for finding in verified_findings:
        if finding.severity in ("Critical", "High"):
            vt = finding.vuln_type or _("report.rec.uncategorized")
            if vt in seen_vuln_types:
                continue
            seen_vuln_types.add(vt)
            rec = finding.remediation or _("report.rec.fix_priority", vt=vt, title=finding.title)
            recommendations.append(rec)

    if not recommendations:
        recommendations.append(_("report.rec.review_surface"))

    if output_path is None:

        safe_target = (session.target or "unknown").replace("/", "_").replace(":", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = str(SESSIONS_DIR / f"report_{timestamp}_{safe_target}.md")

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)


    pocs_dir = output.parent / "pocs"
    generate_pocs(session, pocs_dir)


    if not llm_attack_summary:
        llm_attack_summary = _generate_attack_summary_from_session(session)
        if llm_attack_summary:
            logger.info("LLM attack summary generated for report section 4")
    filtered_summary = ReportContentFilter.filter(llm_attack_summary) if llm_attack_summary else ""

    context = {
        "target": session.target or "unknown",
        "started_at": session.started_at,
        "generated_at": datetime.now().isoformat(),
        "version": __version__,
        **_severity_count_context(verified_findings),
        "task_constraints_summary": _format_task_constraints_summary(session),
        "attack_surface_summary": _summarize_attack_surface(session),
        "constraint_violations": list(getattr(session, "constraint_violations", [])),
        "constraint_violation_events": [
            item.model_dump(mode="json") if hasattr(item, "model_dump") else item
            for item in getattr(session, "constraint_violation_events", [])
        ],
        "key_recommendations": recommendations,
        "verified_findings": [_build_report_finding(finding) for finding in verified_findings],
        "findings": [_build_report_finding(finding) for finding in verified_findings],
        "executed_steps": session.executed_steps,
        "total_findings_submitted": len(all_findings),
        "verified_count": len(verified_findings),
        "rejected_count": len(rejected_findings),
        "pending_count": len(pending_findings),
        "candidate_count": len(candidate_findings),
        "pending_verification_count": len(pending_verification_findings),
        "manual_review_count": len(manual_review_findings),
        "rejected_findings": rejected_findings,
        "step_summary": session.get_step_summary(),
        "phase_heading": localized_report_phase_heading,
        "llm_attack_summary": filtered_summary,
    }

    template = Template(REPORT_TEMPLATE_EN if current_lang() == "en" else REPORT_TEMPLATE)
    report_content = template.render(**context)
    if verified_findings:
        report_content += "\n\n" + _render_verified_finding_details_clean(
            verified_findings,
            heading=_rl(
                "## 6. 已验证漏洞定位与复现信息",
                "## 6. Verified Findings — Location & Reproduction",
            ),
            traffic_store=_resolve_traffic_store(output.parent),
        )
    if target_state_context:
        report_content += "\n\n" + _render_target_state_context(target_state_context)

    if report_format.lower() == "html":
        # 修改者: security-hardening pass (self-XSS in HTML report fix)
        # 修改原因: this template used to render with Jinja2's default
        # autoescape=False. report_content is built from finding evidence/PoC
        # text verbatim -- for an XSS finding, that text *is* something like
        # "<script>alert(1)</script>" by construction, since documenting the
        # payload is the whole point of the finding. Rendered unescaped, that
        # payload executes the moment the operator (or anyone they share the
        # report with) opens their own report in a browser -- <pre> only
        # affects whitespace display, it does not stop the browser from
        # parsing tags inside it. autoescape=True makes Jinja2 HTML-escape
        # `content` (and any other future variables in this template)
        # automatically; the escaped text is still fully readable, it just
        # can no longer execute as markup.
        html_content = Template(
            """<!doctype html><html><head><meta charset="utf-8"><title>VulnClaw Report</title></head><body><pre>{{ content }}</pre></body></html>""",
            autoescape=True,
        ).render(content=report_content)
        output = output.with_suffix(".html") if output.suffix.lower() != ".html" else output
        output.write_text(html_content, encoding="utf-8")
    else:
        output.write_text(report_content, encoding="utf-8")

    # ★ Emit machine-consumable findings artifacts next to the report: findings.json
    # (all findings + lifecycle) and findings.sarif (verified findings only). These
    # draw from the same verified feed as the report — no divergent finding lists.

    write_findings_artifacts(session, output.parent / "findings")

    return output


def generate_report_from_file(session_path: str) -> Path:
    """Generate a report from a saved session JSON file."""
    session = SessionState.load(Path(session_path))
    return generate_report(session)


def generate_report_from_target_state(
    target_state: dict[str, Any],
    report_format: str = "markdown",
    output_path: str | None = None,
) -> Path:
    """Generate a report from a target-state snapshot."""
    raw = dict(target_state)
    target_state_context = {
        "resume_meta": raw.pop("resume_meta", None),
        "resume_summary": raw.pop("resume_summary", None),
        "recon_meta": raw.pop("recon_meta", None),
        "runtime_meta": raw.pop("runtime_meta", None),
        "finding_meta": raw.pop("finding_meta", None),
    }
    session = SessionState(**raw)
    return generate_report(
        session,
        output_path=output_path,
        report_format=report_format,
        target_state_context=target_state_context,
    )


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

CYCLE_REPORT_TEMPLATE = """\
# 持续性渗透测试 — 周期报告

## 周期信息

| 项目 | 详情 |
|------|------|
| **测试目标** | {{ target }} |
| **当前周期** | 第 {{ cycle_num }} 周期 |
| **每周期轮数** | {{ rounds_per_cycle }} |
| **本周期新增已验证漏洞** | {{ new_findings }} 个 |
| **累计已验证漏洞** | {{ total_findings }} 个 |
| **累计执行步骤** | {{ total_steps }} 个 |
| **报告生成时间** | {{ generated_at }} |

{% if cycle_findings %}
## 本周期漏洞发现

{% for finding in cycle_findings %}
### {{ loop.index }}. {{ finding.title }} — [{{ finding.severity }}]
{% if finding.verification_status == "pending" %}
> ⚠️ **待验证** — 此漏洞由自动检测发现，尚未通过 PoC 验证。
{% elif finding.lifecycle_status == "needs_manual_review" %}
> 🔎 **需人工复核** — 当前已有间接证据，但仍需人工复核后再升级为正式漏洞。
{% endif %}
- **漏洞类型**: {{ finding.vuln_type or "未分类" }}
- **生命周期**: {{ finding.lifecycle_status or "pending_verification" }}
- **证据等级**: {{ finding.evidence_level or "L1" }}
- **CVE**: {{ finding.cve or "N/A" }}
- **影响范围**: {{ finding.description or "无" }}
{% if finding.evidence %}
- **验证证据**: {{ finding.evidence }}
{% endif %}
- **修复建议**: {{ finding.remediation or "请根据漏洞类型采取相应修复措施" }}
{% if finding.verified_at %}
- **验证时间**: {{ finding.verified_at }}
{% endif %}

{% endfor %}
{% else %}
## 本周期漏洞发现

本周期未发现新漏洞。
{% endif %}

## 累计漏洞汇总

| # | 漏洞标题 | 等级 | 类型 | 证据/URL | 状态 |
|---|---------|------|------|---------|------|
{% for finding in all_findings %}
{% set ev = (finding.evidence or finding.description or "")[:80] %}
| {{ loop.index }} | {{ finding.title }} | {{ finding.severity }} | {{ finding.vuln_type or "—" }} | {{ ev if ev else "—" }} | {% if finding.verification_status == "verified" %}✅ 已验证{% elif finding.lifecycle_status == "needs_manual_review" %}🔎 需人工复核{% elif finding.verification_status == "pending" %}⚠️ 待验证{% else %}❌ 已排除{% endif %} |
{% endfor %}

{% if not all_findings %}
暂未发现漏洞
{% endif %}

## 风险等级分布

| 等级 | 数量 |
|------|------|
| Critical | {{ critical_count }} |
| High | {{ high_count }} |
| Medium | {{ medium_count }} |
| Low/Info | {{ low_count }} |

{% if llm_attack_summary %}
## 攻击路径摘要

{{ llm_attack_summary }}

{% elif step_summary and step_summary.total_steps > 0 %}
## 攻击路径摘要

{% for phase_name, phase_data in step_summary.phases.items() %}
{{ phase_heading(phase_name, phase_data.count) }}

| 状态 | 数量 |
|------|------|
| ✅ 成功 | {{ phase_data.success_count }} |
| ❌ 失败 | {{ phase_data.failure_count }} |

**关键动作**: {{ phase_data.actions[:5]|join(', ') }}

{% if phase_data.key_results %}
**主要发现**:
{% for result in phase_data.key_results %}
- {{ result }}
{% endfor %}
{% endif %}

---
{% endfor %}

**总计**: {{ step_summary.total_steps }} 步

{% if step_summary.key_findings %}
### 关键发现时间线

{% for finding in step_summary.key_findings %}
- {{ finding }}
{% endfor %}
{% endif %}

{% elif recent_steps %}
## 攻击路径摘要

{% for step in recent_steps %}
{{ loop.index }}. {{ step }}
{% endfor %}
{% endif %}

## 关键建议

{% for rec in recommendations %}
{{ loop.index }}. {{ rec }}
{% endfor %}

---

> 🦞 持续性渗透测试周期报告 | VulnClaw | {{ generated_at }}
> **原则**: 未经验证的漏洞 = 误报 = 不写入报告
"""


CYCLE_REPORT_TEMPLATE_EN = """\
# Persistent Penetration Test — Cycle Report

## Cycle Information

| Item | Details |
|------|------|
| **Target** | {{ target }} |
| **Current Cycle** | Cycle {{ cycle_num }} |
| **Rounds per Cycle** | {{ rounds_per_cycle }} |
| **New Verified Findings This Cycle** | {{ new_findings }} |
| **Cumulative Verified Findings** | {{ total_findings }} |
| **Cumulative Executed Steps** | {{ total_steps }} |
| **Report Generated At** | {{ generated_at }} |

{% if cycle_findings %}
## Findings This Cycle

{% for finding in cycle_findings %}
### {{ loop.index }}. {{ finding.title }} — [{{ finding.severity }}]
{% if finding.verification_status == "pending" %}
> ⚠️ **Pending verification** — auto-detected, not yet confirmed via PoC.
{% elif finding.lifecycle_status == "needs_manual_review" %}
> 🔎 **Needs manual review** — indirect evidence exists but manual review is required before promoting to a confirmed finding.
{% endif %}
- **Vulnerability Type**: {{ finding.vuln_type or "Uncategorized" }}
- **Lifecycle**: {{ finding.lifecycle_status or "pending_verification" }}
- **Evidence Level**: {{ finding.evidence_level or "L1" }}
- **CVE**: {{ finding.cve or "N/A" }}
- **Impact**: {{ finding.description or "None" }}
{% if finding.evidence %}
- **Verification Evidence**: {{ finding.evidence }}
{% endif %}
- **Remediation**: {{ finding.remediation or "Apply remediation appropriate to the vulnerability type." }}
{% if finding.verified_at %}
- **Verified At**: {{ finding.verified_at }}
{% endif %}

{% endfor %}
{% else %}
## Findings This Cycle

No new findings this cycle.
{% endif %}

## Cumulative Findings Summary

| # | Title | Severity | Type | Evidence/URL | Status |
|---|---------|------|------|---------|------|
{% for finding in all_findings %}
{% set ev = (finding.evidence or finding.description or "")[:80] %}
| {{ loop.index }} | {{ finding.title }} | {{ finding.severity }} | {{ finding.vuln_type or "—" }} | {{ ev if ev else "—" }} | {% if finding.verification_status == "verified" %}✅ Verified{% elif finding.lifecycle_status == "needs_manual_review" %}🔎 Needs manual review{% elif finding.verification_status == "pending" %}⚠️ Pending{% else %}❌ Excluded{% endif %} |
{% endfor %}

{% if not all_findings %}
No findings yet.
{% endif %}

## Risk Severity Distribution

| Severity | Count |
|------|------|
| Critical | {{ critical_count }} |
| High | {{ high_count }} |
| Medium | {{ medium_count }} |
| Low/Info | {{ low_count }} |

{% if llm_attack_summary %}
## Attack Path Summary

{{ llm_attack_summary }}

{% elif step_summary and step_summary.total_steps > 0 %}
## Attack Path Summary

{% for phase_name, phase_data in step_summary.phases.items() %}
{{ phase_heading(phase_name, phase_data.count) }}

| Status | Count |
|------|------|
| ✅ Success | {{ phase_data.success_count }} |
| ❌ Failure | {{ phase_data.failure_count }} |

**Key Actions**: {{ phase_data.actions[:5]|join(', ') }}

{% if phase_data.key_results %}
**Key Findings**:
{% for result in phase_data.key_results %}
- {{ result }}
{% endfor %}
{% endif %}

---
{% endfor %}

**Total**: {{ step_summary.total_steps }} steps

{% if step_summary.key_findings %}
### Key Findings Timeline

{% for finding in step_summary.key_findings %}
- {{ finding }}
{% endfor %}
{% endif %}

{% elif recent_steps %}
## Attack Path Summary

{% for step in recent_steps %}
{{ loop.index }}. {{ step }}
{% endfor %}
{% endif %}

## Key Recommendations

{% for rec in recommendations %}
{{ loop.index }}. {{ rec }}
{% endfor %}

---

> 🦞 Persistent Penetration Test Cycle Report | VulnClaw | {{ generated_at }}
> **Principle**: Unverified vulnerability = false positive = not written to the report
"""


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
                f"- [{finding.severity}] {finding.title} | Evidence: {(finding.evidence or '')[:200]}"
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
            "5. Do not invent steps that were never executed.\n"
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


def generate_persistent_cycle_report(
    session: SessionState,
    cycle_num: int,
    total_findings: int,
    new_findings: int,
    total_steps: int,
    rounds_per_cycle: int,
    output_path: Optional[str] = None,
    llm_attack_summary: str = "",  # ★ LLM 生成的攻击路径摘要
    prev_verified_ids: Optional[set] = None,
) -> Path:
    """Generate a cycle report for persistent pentest.

    只包含已验证 (verified=True) 的漏洞。

    Args:
        session: Current session state with findings.
        cycle_num: Current cycle number (1-based).
        total_findings: Total findings so far (cumulative).
        new_findings: New findings in this cycle (all findings delta; used only
            as a fallback when prev_verified_ids is not supplied).
        total_steps: Total executed steps so far (cumulative).
        rounds_per_cycle: Rounds per cycle.
        output_path: Output file path. If None, auto-generate.
        prev_verified_ids: finding_id set of findings already verified before this
            cycle. When provided, "new this cycle" is computed by identity against
            this set instead of slicing by an all-findings count — the count-based
            slice mislabels prior verified findings as new when a cycle adds
            unverified findings.

    Returns:
        Path to the generated report file.
    """

    # ★ 包含所有 findings（包括 pending 和 confirmed，不只是 verified）
    all_findings = session.findings
    verified_findings = deduplicate_report_findings(session.get_verified_findings())
    manual_review_findings = (
        session.get_manual_review_findings()
        if hasattr(session, "get_manual_review_findings")
        else []
    )

    # ★ 本周期新增已验证 findings（只统计 verified）
    if prev_verified_ids is not None:
        # 按 finding_id 身份判定本周期新验证的漏洞，避免用"全部 findings 增量"
        # 去切片"已验证子集"导致把往期漏洞误标为本周期新增。
        cycle_findings = [
            f for f in verified_findings if f.finding_id not in prev_verified_ids
        ]
    else:
        cycle_findings = verified_findings[-new_findings:] if new_findings > 0 else []

    # Generate recommendations from verified high/critical findings only
    # Deduplicate by vuln_type: only one recommendation per vulnerability type
    seen_vuln_types = set()
    recommendations = []
    for finding in verified_findings:
        if finding.severity in ("Critical", "High"):
            vt = finding.vuln_type or _("report.rec.uncategorized")
            if vt in seen_vuln_types:
                continue
            seen_vuln_types.add(vt)
            rec = finding.remediation or _("report.rec.fix_vuln", vt=vt, title=finding.title)
            recommendations.append(rec)
    if not recommendations:
        recommendations.append(_("report.rec.none_high"))

    if output_path is None:

        safe_target = (session.target or "unknown").replace("/", "_").replace(":", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = str(
            SESSIONS_DIR / f"persistent_cycle{cycle_num:03d}_{timestamp}_{safe_target}.md"
        )

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)


    pocs_dir = output.parent / "pocs"
    generate_pocs(session, pocs_dir)

    # Recent steps (last 20 to avoid bloat)
    recent_steps = session.executed_steps[-20:]

    # ★ 攻击路径摘要（过滤 LLM 原始输出中的 think 标签 / 调试标记）
    step_summary = session.get_step_summary()

    if not llm_attack_summary:
        llm_attack_summary = _generate_attack_summary_from_session(session)
    filtered_summary = ReportContentFilter.filter(llm_attack_summary) if llm_attack_summary else ""

    context = {
        "target": session.target or _rl("未指定", "Unspecified"),
        "cycle_num": cycle_num,
        "rounds_per_cycle": rounds_per_cycle,
        "new_findings": len(cycle_findings),
        "total_findings": len(all_findings),
        "total_steps": total_steps,
        "generated_at": datetime.now().isoformat(),
        "version": __version__,
        "cycle_findings": cycle_findings,
        "all_findings": all_findings,  # ★ 包含所有 findings（包括 pending）
        **_severity_count_context(verified_findings),
        "recent_steps": recent_steps,
        "recommendations": recommendations,
        "manual_review_count": len(manual_review_findings),
        "step_summary": step_summary,
        "phase_heading": localized_report_phase_heading,
        "llm_attack_summary": filtered_summary,
    }

    # Render report
    template = Template(
        CYCLE_REPORT_TEMPLATE_EN if current_lang() == "en" else CYCLE_REPORT_TEMPLATE
    )
    report_content = template.render(**context)
    if verified_findings:
        report_content += "\n\n" + _render_verified_finding_details_clean(
            verified_findings,
            heading=_rl(
                "## 已验证漏洞定位与复现信息",
                "## Verified Findings — Location & Reproduction",
            ),
            traffic_store=_resolve_traffic_store(output.parent),
        )
    output.write_text(report_content, encoding="utf-8")

    # ★ Emit the same machine-consumable findings artifacts as generate_report, so a
    # persistent run's per-cycle reports also produce findings/findings.json and
    # findings/findings.sarif.

    write_findings_artifacts(session, output.parent / "findings")

    return output


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
    return [label for _, label in ranked]


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

    Mirrors the way poc_builder inlines PoC scripts: each verified finding's
    ``evidence_refs`` with ``kind="http_capture"`` is resolved back to its
    JSONL record + blob files and rendered as fenced code blocks.
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


def _extract_location_summary(finding: VulnerabilityFinding) -> str:
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


def _build_repro_summary(finding: VulnerabilityFinding) -> str:
    parts: list[str] = []
    if finding.poc_script:
        parts.append(f"运行 PoC 脚本: {finding.poc_script}")
    if finding.verification_note:
        parts.append(f"验证说明: {finding.verification_note}")
    elif finding.evidence:
        parts.append(f"根据已验证证据复现: {finding.evidence[:160]}")
    if finding.verified_at:
        parts.append(f"验证时间: {finding.verified_at}")
    return "；".join(parts) if parts else "暂无可用复现说明"


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
        "lifecycle_status": finding.lifecycle_status,
        "evidence_level": finding.evidence_level,
        "subagent_provenance": finding.subagent_provenance,
        "location_summary": _extract_location_summary(finding),
        "repro_summary": _build_repro_summary(finding),
    }


def _render_verified_finding_details(findings: list[VulnerabilityFinding], heading: str) -> str:
    lines = [heading, ""]
    for idx, finding in enumerate(findings, 1):
        location = _extract_location_summary(finding) or "未定位 / 未提取到 URL"
        lines.append(f"### {idx}. {finding.title} [{finding.severity}]")
        lines.append(f"- 漏洞类型: {finding.vuln_type or '未分类'}")
        lines.append(f"- 位置 / URL: {location}")
        if finding.evidence:
            lines.append(f"- 验证证据: {finding.evidence}")
        lines.append(f"- 复现 / PoC: {_build_repro_summary(finding)}")
        lines.append("")
    return "\n".join(lines).rstrip()
