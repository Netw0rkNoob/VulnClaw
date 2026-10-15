"""Approved, data-driven HTTP checks with explicit controls and structured results."""

from __future__ import annotations

import asyncio
import json
import re
import sys
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import uuid4

import httpx
from pydantic import BaseModel, ConfigDict, Field

from vulnclaw.agent.constraint_policy import validate_tool_action
from vulnclaw.agent.exec_gate import GateRequest, get_execution_gate
from vulnclaw.config.url_utils import infer_port_from_url
from vulnclaw.findings.evidence import endpoint_identity
from vulnclaw.findings.types import FindingAssessment, Snapshot
from vulnclaw.mcp.fetch_request import prepare_fetch_request_kwargs


class PocRequest(BaseModel):
    method: str
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None


class PocPlan(BaseModel):
    kind: str
    requests: list[PocRequest]
    evidence_ids: list[str]
    markers: list[str] = Field(default_factory=list)
    baseline: dict | list | None = None


class PocResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    outcome: str
    reason: str
    observations: list[dict[str, str]] = Field(default_factory=list)


PROGRAM = r'''
import json, re, sys
import httpx

plan = json.loads(sys.stdin.read())
responses = []
try:
    with httpx.Client(timeout=15, follow_redirects=False, trust_env=False) as client:
        for item in plan["requests"]:
            response = client.request(item["method"], item["url"],
                                      headers=item["headers"], content=item["body"])
            if response.status_code != 200:
                print(json.dumps({"outcome":"inconclusive", "reason":"A control or test request did not return HTTP 200", "observations":[]}))
                sys.exit(0)
            responses.append(response.text)
    outcome, reason = "inconclusive", "The type-specific controlled check was not conclusive"
    kind = plan["kind"]
    if kind == "command_execution":
        markers = plan["markers"]
        if all(markers[i % 2] in body and markers[1-i % 2] not in body
               for i, body in enumerate(responses)):
            outcome, reason = "verified", "Two repeated command controls produced distinct server-side constructed nonces"
    elif kind == "file_traversal":
        def passwd(body):
            return bool(re.search(r"^root:[^:\n]*:0:\d+:[^:\n]*:/[^:\n]*:/[^:\n]+$", body, re.M))
        if all(passwd(responses[i]) and not passwd(responses[i+1]) for i in (0,2)):
            outcome, reason = "verified", "Repeated requested-file checks returned structured passwd records absent from missing-file controls"
    elif kind == "sql_boolean":
        values = [json.loads(body) for body in responses]
        if all(isinstance(value, (dict,list)) for value in values):
            def rows(value):
                if isinstance(value, list):
                    return value
                for key in ("rows", "records", "data", "items", "results"):
                    if isinstance(value.get(key), list):
                        return value[key]
                return None
            a, b = rows(values[0]), rows(values[1])
            reflected = any(value in body for item,body in zip(plan["requests"], responses)
                            for value in httpx.URL(item["url"]).params.values()
                            if "AND 1=" in value.upper())
            if not reflected and a and b == [] and values[0] == values[2] and values[1] == values[3]:
                outcome, reason = "verified", "Repeated recorded true/false SQL controls yielded stable distinct structured responses"
            elif not reflected and plan["baseline"] and values[0] == values[1] == values[2] == values[3] == plan["baseline"]:
                outcome, reason = "rejected", "Recorded successful JSON response was reproduced identically for both logical controls, contradicting the submitted differential claim"
    print(json.dumps({"outcome":outcome, "reason":reason, "observations":[
        {"request":item["url"], "response_excerpt":body[:2000]}
        for item,body in zip(plan["requests"], responses)
    ]}))
except Exception as exc:
    print(json.dumps({"outcome":"inconclusive", "reason":"Verification execution failed: " + type(exc).__name__, "observations":[]}))
'''


def _request(snapshot: Snapshot) -> PocRequest | None:
    if snapshot.tool != "fetch" or not snapshot.arguments.get("url"):
        return None
    kwargs, body_mode = prepare_fetch_request_kwargs(snapshot.arguments)
    request = httpx.Request(**kwargs)
    if request.method != "GET" or body_mode is not None:
        return None
    return PocRequest(method=request.method, url=str(request.url), headers=dict(request.headers))


def _replace(request: PocRequest, key: str, value: str) -> PocRequest:
    parsed = urlsplit(request.url)
    pairs = [(name, value if name == key else original) for name, original in parse_qsl(parsed.query)]
    return request.model_copy(update={"url": urlunsplit(parsed._replace(query=urlencode(pairs)))})


def build_plan(finding, snapshots: dict[str, Snapshot]) -> PocPlan | None:
    for evidence_id, snapshot in snapshots.items():
        request = _request(snapshot)
        if request is None:
            continue
        if finding.method and finding.method.upper() != request.method:
            # A replay must exercise the claimed method: a GET result can never
            # confirm a POST candidate, so unsupported methods fall back to
            # evidence review instead of borrowing a same-path GET.
            continue
        if finding.endpoint and endpoint_identity(finding.endpoint) != endpoint_identity(request.url):
            continue
        pairs = parse_qsl(urlsplit(request.url).query)
        if finding.vuln_type == "remote_code_execution":
            for key, value in pairs:
                match = re.search(r"\bid\s*$", value)
                if not match:
                    continue
                tokens = [uuid4().hex for _ in range(2)]
                markers = ["VC_" + token for token in tokens]
                variants = [
                    _replace(request, key, value[:match.start()] +
                             "printf 'VC_%s%s' '" + token[:16] + "' '" + token[16:] + "'")
                    for token in tokens
                ]
                return PocPlan(kind="command_execution", requests=variants * 2,
                               markers=markers, evidence_ids=[evidence_id])
        if finding.vuln_type == "local_file_inclusion":
            for key, value in pairs:
                if value.endswith("/etc/passwd") and ("../" in value or value.startswith("/")):
                    control = _replace(request, key, value + ".missing-" + uuid4().hex)
                    return PocPlan(kind="file_traversal", requests=[request, control] * 2,
                                   evidence_ids=[evidence_id])
        if finding.vuln_type == "sql_injection":
            for key, value in pairs:
                if not re.search(r"\bAND\s+1\s*=\s*1\b", value, re.I):
                    continue
                false_value = re.sub(r"\bAND\s+1\s*=\s*1\b", "AND 1=2", value, flags=re.I)
                control = _replace(request, key, false_value)
                # A rejection requires a recorded successful structured baseline,
                # not an error page or an arbitrary lack of a signature.
                body = snapshot.content.partition("Body (")[2].partition("):")[2].strip()
                try:
                    baseline = json.loads(body)
                except (ValueError, TypeError):
                    baseline = None
                return PocPlan(kind="sql_boolean", requests=[request, control] * 2,
                               evidence_ids=[evidence_id], baseline=baseline)
    return None


def scope_violation(session, plan: PocPlan) -> str | None:
    from vulnclaw.agent.builtin_tools import enforce_host_path_constraints, enforce_port_constraints
    from vulnclaw.config.domain_models import validate_action_constraints
    from vulnclaw.findings.evidence import scope_identity

    violation = validate_action_constraints("exploit", session.task_constraints)
    if violation:
        return violation

    agent = SimpleNamespace(session_state=session)
    for request in plan.requests:
        parsed = urlsplit(request.url)
        if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
            return "PoC request must use an HTTP(S) URL without URL credentials"
        if scope_identity(request.url)[0] != scope_identity(session.target or "")[0]:
            return "PoC request belongs to another target"
        violation = enforce_host_path_constraints(
            agent, host=parsed.hostname or "", path=parsed.path, target=request.url,
        ) or enforce_port_constraints(agent, [infer_port_from_url(request.url)], target=request.url)
        if violation:
            return violation
        violation = validate_tool_action("fetch", {"url": request.url}, session.task_constraints)
        if violation:
            return violation
    return None


async def execute_plan(plan: PocPlan, session, config, artifact_dir: Path) -> FindingAssessment:
    violation = scope_violation(session, plan)
    if violation:
        raise ValueError(violation)
    payload = plan.model_dump(mode="json")
    gate = get_execution_gate(config)
    decision = await gate.authorize(GateRequest(
        kind="poc", display=PROGRAM + "\n# Request plan:\n" + json.dumps(payload, ensure_ascii=False),
        detail="Independent finding verification; HTTP redirects are disabled", model_risk="review",
    ), run_id=session.run_id)
    if not decision.approved:
        raise ValueError(decision.refusal_text("poc"))
    violation = scope_violation(session, plan)
    if violation:
        raise ValueError(violation)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    script = artifact_dir / "verify.py"
    script.write_text(PROGRAM, encoding="utf-8")
    (artifact_dir / "plan.json").write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    process = await asyncio.create_subprocess_exec(
        sys.executable, "-c", PROGRAM, stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(json.dumps(payload).encode()), 70)
    except (asyncio.CancelledError, TimeoutError):
        if process.returncode is None:
            process.kill()
        await process.wait()
        raise
    output = artifact_dir / "output.json"
    output.write_bytes(stdout)
    (artifact_dir / "stderr.txt").write_bytes(stderr)
    if process.returncode != 0:
        raise ValueError("PoC process did not complete successfully")
    result = PocResult.model_validate_json(stdout)
    if result.outcome not in {"verified", "rejected"}:
        raise ValueError(result.reason)
    return FindingAssessment(
        outcome=result.outcome, method="poc", reason=result.reason,
        evidence_ids=plan.evidence_ids, observations=result.observations,
        artifacts=[str(script), str(artifact_dir / "plan.json"), str(output)],
    )
