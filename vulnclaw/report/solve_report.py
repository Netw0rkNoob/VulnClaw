"""Markdown report generation for model-led solve runs.

The general penetration-test report generator is finding-oriented.  A completed
``solve`` run often needs a different artifact: a compact, reproducible trail
from target evidence to the final flag / exploit proof.  This module renders
that artifact directly from ``AgentState`` without asking the LLM to summarize,
so the report stays grounded in recorded tool output.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from vulnclaw.agent.agent_state import AgentState, clip_text, extract_flags, one_line
from vulnclaw.i18n import _

_HTTP_PROBE_SECTION_RE = re.compile(
    r"^\[(?P<index>\d+)\]\s+(?P<method>[A-Z]+)\s+(?P<label>.*?)\s+"
    r"(?P<status>\d{3})\b",
)
_FETCH_REQUEST_RE = re.compile(r"^Request:\s+(?P<method>[A-Z]+)\s+(?P<url>\S+)", re.MULTILINE)
_FETCH_STATUS_RE = re.compile(r"^Status:\s+(?P<status>\d{3})", re.MULTILINE)
_FETCH_BODY_RE = re.compile(r"^Body \([^)]*\):\s*(?P<body>.*)", re.MULTILINE | re.DOTALL)
_SOURCE_SQL_PREFIX = "Source SQL:"


@dataclass
class ReproductionRequest:
    """One request/response pair useful for replaying a solve result."""

    method: str
    url: str
    status: int = 0
    label: str = ""
    body: str = ""
    evidence_id: str = ""
    tool: str = ""

    @property
    def flags(self) -> list[str]:
        return extract_flags(self.body)

    def request_packet(self) -> str:
        """Render a replayable raw HTTP request packet."""

        parsed = urlparse(self.url)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        host = parsed.netloc or "(host)"
        return "\n".join(
            [
                f"{self.method or 'GET'} {path} HTTP/1.1",
                f"Host: {host}",
                "User-Agent: VulnClaw-replay/1.0",
                "Accept: */*",
                "Connection: close",
            ]
        )

    def curl_command(self) -> str:
        method = (self.method or "GET").upper()
        parts = ["curl", "-k", "-i"]
        if method != "GET":
            parts.extend(["-X", method])
        parts.append(_shell_quote(self.url))
        return " ".join(parts)


def generate_solve_report(
    state: AgentState,
    output_path: str | Path | None = None,
    *,
    report_format: str = "markdown",
) -> Path:
    """Write a completed solve report and return its path."""

    if report_format.lower() not in {"markdown", "md"}:
        raise ValueError("solve reports currently support markdown only")

    if output_path is None:
        from vulnclaw.config.settings import SESSIONS_DIR, ensure_dirs

        ensure_dirs()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = _safe_filename(_target_label(state))
        output_path = SESSIONS_DIR / f"solve_report_{timestamp}_{safe_target}.md"

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_solve_report(state), encoding="utf-8")
    return output


def render_solve_report(state: AgentState) -> str:
    """Render a Markdown solve report from AgentState."""

    flags = extract_flags((state.final_answer or "") + "\n" + state.evidence_text())
    requests = extract_reproduction_requests(state)
    key_requests = _rank_reproduction_requests(requests, flags)
    pinned = [item.text for item in state.pinned_facts]
    sql_facts = [item for item in pinned if item.startswith(_SOURCE_SQL_PREFIX)]

    lines: list[str] = [
        "# VulnClaw Solve Report",
        "",
        f"- Target: `{state.origin or 'unknown'}`",
        f"- Goal: {state.goal or '(unset)'}",
        f"- Status: {'completed' if state.completed else 'not completed'}",
        f"- Result: {state.complete_reason or '(none)'}",
        f"- Generated at: {datetime.now().isoformat(timespec='seconds')}",
    ]
    if flags:
        lines.append(f"- Flag / proof: `{flags[0]}`")

    lines.extend(["", _("report.solve.step1")])
    lines.extend(_render_solution_chain(state, sql_facts, key_requests, flags))

    lines.extend(["", _("report.solve.step2")])
    if pinned:
        for fact in pinned[:24]:
            lines.append(f"- {fact}")
    else:
        lines.append("- No pinned facts were recorded.")

    lines.extend(["", _("report.solve.step3")])
    if key_requests:
        for index, request in enumerate(key_requests, start=1):
            title = request.label or f"{request.method} {request.url}"
            lines.extend(
                [
                    "",
                    f"### 3.{index} {title}",
                    "",
                    f"- Evidence: `{request.evidence_id}` ({request.tool})",
                    f"- URL: `{request.url}`",
                    f"- Status: `{request.status or 'unknown'}`",
                    "",
                    "Raw HTTP request:",
                    "",
                    "```http",
                    request.request_packet(),
                    "```",
                    "",
                    "curl:",
                    "",
                    "```bash",
                    request.curl_command(),
                    "```",
                    "",
                    "Response excerpt:",
                    "",
                    "```text",
                    _response_excerpt(request.body, flags),
                    "```",
                ]
            )
    else:
        lines.append("- No replayable HTTP request was extracted from evidence.")

    lines.extend(["", _("report.solve.step4")])
    if state.steps:
        for step in state.steps:
            tools = ", ".join(step.tool_calls) or "none"
            lines.append(
                f"- Turn {step.index}: {step.reason or '(no reason)'} "
                f"| tools={tools} | finding={step.observation or '(none)'}"
            )
    else:
        lines.append("- No model steps were recorded.")

    lines.extend(["", _("report.solve.step5")])
    if state.evidence:
        for item in state.evidence:
            lines.append(
                f"- `{item.id}` tool={item.tool} status={item.status} "
                f"size={item.size} chars summary={item.summary}"
            )
    else:
        lines.append("- No evidence records were saved.")

    lines.append("")
    return "\n".join(lines)


def extract_reproduction_requests(state: AgentState) -> list[ReproductionRequest]:
    """Extract replayable HTTP requests from saved solve evidence."""

    requests: list[ReproductionRequest] = []
    for evidence in state.evidence:
        content = evidence.content or ""
        if evidence.tool == "http_probe_batch" or "# http_probe_batch results" in content:
            requests.extend(_parse_http_probe_batch(content, evidence.id, evidence.tool))
            continue
        if evidence.tool == "fetch" or "Request:" in content:
            request = _parse_fetch_response(content, evidence.id, evidence.tool)
            if request is not None:
                requests.append(request)
    return requests


def _parse_http_probe_batch(
    content: str,
    evidence_id: str,
    tool: str,
) -> list[ReproductionRequest]:
    requests: list[ReproductionRequest] = []
    current: dict[str, Any] | None = None
    body_lines: list[str] = []
    in_body = False

    def finish() -> None:
        nonlocal current, body_lines, in_body
        if not current or not current.get("url"):
            current = None
            body_lines = []
            in_body = False
            return
        requests.append(
            ReproductionRequest(
                method=str(current.get("method") or "GET"),
                url=str(current["url"]),
                status=int(current.get("status") or 0),
                label=str(current.get("label") or ""),
                body="\n".join(body_lines).strip(),
                evidence_id=evidence_id,
                tool=tool,
            )
        )
        current = None
        body_lines = []
        in_body = False

    for raw_line in str(content or "").splitlines():
        section = _HTTP_PROBE_SECTION_RE.match(raw_line.strip())
        if section:
            finish()
            current = {
                "method": section.group("method"),
                "label": one_line(section.group("label"), 120),
                "status": int(section.group("status")),
            }
            continue
        if current is None:
            continue
        stripped = raw_line.strip()
        if stripped.startswith("url="):
            current["url"] = stripped[len("url=") :].strip()
            continue
        if stripped.startswith("body:"):
            in_body = True
            tail = stripped[len("body:") :].strip()
            if tail:
                body_lines.append(tail)
            continue
        if in_body:
            if (
                stripped.startswith("[correction]")
                or stripped.startswith("[diagnostic]")
                or stripped.startswith("# Same-body")
            ):
                in_body = False
                continue
            body_lines.append(raw_line.rstrip())

    finish()
    return requests


def _parse_fetch_response(content: str, evidence_id: str, tool: str) -> ReproductionRequest | None:
    request_match = _FETCH_REQUEST_RE.search(content or "")
    if not request_match:
        return None
    status_match = _FETCH_STATUS_RE.search(content or "")
    body_match = _FETCH_BODY_RE.search(content or "")
    return ReproductionRequest(
        method=request_match.group("method"),
        url=request_match.group("url"),
        status=int(status_match.group("status")) if status_match else 0,
        label="fetch",
        body=(body_match.group("body").strip() if body_match else ""),
        evidence_id=evidence_id,
        tool=tool,
    )


def _rank_reproduction_requests(
    requests: list[ReproductionRequest],
    flags: list[str],
) -> list[ReproductionRequest]:
    if not requests:
        return []

    def score(request: ReproductionRequest) -> tuple[int, int]:
        body = request.body or ""
        url = request.url or ""
        value = 0
        if any(flag in body for flag in flags):
            value += 100
        if "username" in body.lower() and "flag" in body.lower():
            value += 30
        if "api/" in url.lower() or "/api" in url.lower():
            value += 10
        if request.status == 200:
            value += 5
        return value, len(body)

    ranked = sorted(requests, key=score, reverse=True)
    positive = [item for item in ranked if score(item)[0] >= 30]
    return (positive or ranked)[:5]


def _render_solution_chain(
    state: AgentState,
    sql_facts: list[str],
    requests: list[ReproductionRequest],
    flags: list[str],
) -> list[str]:
    lines: list[str] = []
    linked = [item.text for item in state.pinned_facts if "endpoint:" in item.text.lower()]
    forms = [item.text for item in state.pinned_facts if item.text.startswith("HTML ")]

    if linked:
        lines.append(_("report.solve.chain.entry", items="; ".join(linked[:4])))
    elif forms:
        lines.append(_("report.solve.chain.forms", items="; ".join(forms[:4])))
    else:
        lines.append(_("report.solve.chain.baseline"))

    if sql_facts:
        expr = sql_facts[0][len(_SOURCE_SQL_PREFIX):].strip()
        lines.append(_("report.solve.chain.sql_expr", expr=expr))
        lines.append(_("report.solve.chain.sql_hint"))
    else:
        lines.append(_("report.solve.chain.confirm_params"))

    if requests:
        payload_url = requests[0].url
        lines.append(_("report.solve.chain.reproduced", url=payload_url))
    if flags:
        lines.append(_("report.solve.chain.flag", flag=flags[0]))
    return lines


def _response_excerpt(body: str, flags: list[str]) -> str:
    text = str(body or "")
    if not text:
        return "(empty response body)"
    for flag in flags:
        index = text.find(flag)
        if index >= 0:
            start = max(0, index - 220)
            end = min(len(text), index + len(flag) + 220)
            return text[start:end].strip()
    return clip_text(text.strip(), 1200)


def _target_label(state: AgentState) -> str:
    parsed = urlparse(state.origin or "")
    if parsed.netloc:
        return parsed.netloc
    return state.origin or "unknown"


def _safe_filename(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "unknown")).strip("._")
    return safe[:120] or "unknown"


def _shell_quote(value: str) -> str:
    return "'" + str(value).replace("'", "'\"'\"'") + "'"
