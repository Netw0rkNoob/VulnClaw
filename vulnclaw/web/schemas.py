"""Pydantic models for the Web UI backend."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal, Optional
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, field_validator

from vulnclaw.config.schema import LLM_MODEL_ID_MAX_LENGTH, normalize_llm_model_id

TaskCommand = Literal["run", "recon", "scan", "exploit", "persistent"]
TaskStatus = Literal["pending", "restoring", "running", "completed", "failed", "stopped"]
PythonExecuteMode = Literal["safe", "lab", "trusted-local"]
ProviderModelsStatus = Literal[
    "ok",
    "missing_key",
    "untrusted_url",
    "authentication_failed",
    "timeout",
    "malformed_response",
    "response_too_large",
    "empty_catalog",
    "redirect_blocked",
    "upstream_error",
]

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _reject_control_chars(value: str | None) -> str | None:
    """Reject strings containing control characters (prompt injection guard)."""
    if value is None:
        return None
    if value != value.replace("\n", "").replace("\r", "").replace("\t", "") or _CONTROL_CHARS_RE.search(value):
        raise ValueError(
            "input must not contain control characters (newlines, tabs, or other non-printable chars)"
        )
    return value


def _validate_http_base_url(value: str | None) -> str | None:
    """Validate an OpenAI-compatible HTTP(S) base URL from the Web UI."""
    if value is None:
        return None
    normalized = value.strip().rstrip("/")
    if not normalized:
        return ""
    parsed = urlsplit(normalized)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("base_url must use http or https")
    if not parsed.netloc or not parsed.hostname:
        raise ValueError("base_url must include a host")
    if parsed.username or parsed.password:
        raise ValueError("base_url must not include credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("base_url must not include query strings or fragments")
    return normalized


class TaskOptions(BaseModel):
    max_rounds: Optional[int] = Field(
        default=None, ge=1, le=100, description="Override for autonomous rounds"
    )
    rounds_per_cycle: Optional[int] = Field(
        default=None, ge=1, le=1000, description="Persistent mode rounds per cycle"
    )
    max_cycles: Optional[int] = Field(
        default=None, ge=0, le=1000, description="Persistent mode max cycles"
    )
    cve: Optional[str] = Field(default=None, max_length=64, description="Exploit command CVE hint")
    cmd: Optional[str] = Field(
        default=None, max_length=512, description="Exploit command execution hint"
    )
    only_port: Optional[int] = Field(
        default=None,
        ge=1,
        le=65535,
        description="Restrict task scope to a single port",
    )
    only_host: Optional[str] = Field(
        default=None, max_length=253, description="Restrict task scope to a single host"
    )
    only_path: Optional[str] = Field(
        default=None, max_length=2048, description="Restrict task scope to a single path"
    )
    blocked_host: Optional[str] = Field(
        default=None, max_length=253, description="Explicitly blocked host"
    )
    blocked_path: Optional[str] = Field(
        default=None, max_length=2048, description="Explicitly blocked path"
    )
    allow_actions: Optional[list[str]] = Field(
        default=None, max_length=20, description="Explicit allow-list for task actions"
    )
    block_actions: Optional[list[str]] = Field(
        default=None, max_length=20, description="Explicit block-list for task actions"
    )

    @field_validator("cve", "cmd")
    @classmethod
    def validate_injection_fields(cls, value: str | None) -> str | None:
        return _reject_control_chars(value)


class TaskCreateRequest(BaseModel):
    command: TaskCommand
    target: str = Field(min_length=1, max_length=2048)
    resume: bool = True
    snapshot_id: Optional[str] = Field(default=None, max_length=160)
    run_name: Optional[str] = Field(default=None, max_length=120)
    resume_run_name: Optional[str] = Field(default=None, max_length=120)
    runs_dir: Optional[str] = Field(default=None, max_length=4096)
    additional_targets: list[str] = Field(default_factory=list, max_length=20)
    target_type: Optional[str] = Field(default=None, max_length=32)
    mount: bool = False
    repair: bool = False
    force_fresh: bool = False
    no_import: bool = False
    options: TaskOptions = Field(default_factory=TaskOptions)

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        return _reject_control_chars(value)  # type: ignore[return-value]

    @field_validator("additional_targets")
    @classmethod
    def validate_additional_targets(cls, value: list[str]) -> list[str]:
        for i, t in enumerate(value):
            if isinstance(t, str):
                _reject_control_chars(t)  # type: ignore[return-value]
        return value


class TaskEvent(BaseModel):
    event: str
    task_id: str
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    payload: dict[str, Any] = Field(default_factory=dict)


class TaskSummary(BaseModel):
    target: str
    command: TaskCommand
    restored: bool = False
    snapshot_id: str = ""
    schema_version: int = 1
    status: str = "completed"
    exit_code: int = 0
    exit_meaning: str = "completed"
    run_name: str = ""
    run_dir: str = ""
    resume_command: str = ""
    artifact_locations: dict[str, str] = Field(default_factory=dict)
    phase: Optional[str] = None
    findings_count: int = 0
    verified_count: int = 0
    pending_count: int = 0
    candidate_count: int = 0
    quarantined_count: int = 0
    executed_steps: int = 0
    resume_strategy: str = ""
    resume_reason: str = ""
    constraints: dict[str, Any] = Field(default_factory=dict)
    constraint_violations: list[str] = Field(default_factory=list)
    constraint_violation_events: list[dict[str, Any]] = Field(default_factory=list)


class TaskRecord(BaseModel):
    task_id: str
    command: TaskCommand
    target: str
    status: TaskStatus
    created_at: str = Field(default_factory=lambda: datetime.now().isoformat())
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error: Optional[str] = None
    resume: bool = True
    snapshot_id: Optional[str] = None
    options: TaskOptions = Field(default_factory=TaskOptions)
    latest_phase: Optional[str] = None
    latest_message: Optional[str] = None
    summary: Optional[TaskSummary] = None


class TargetSnapshotView(BaseModel):
    snapshot_id: str
    schema_version: int = 1
    last_saved_at: str = ""
    last_command: str = ""
    verified_findings: int = 0
    pending_findings: int = 0
    executed_steps: int = 0
    resume_strategy: str = ""


class TargetView(BaseModel):
    target: str
    schema_version: int = 1
    phase: Optional[str] = None
    findings_count: int = 0
    verified_count: int = 0
    pending_count: int = 0
    candidate_count: int = 0
    pending_verification_count: int = 0
    manual_review_count: int = 0
    resume_strategy: str = ""
    resume_reason: str = ""
    constraints: dict[str, Any] = Field(default_factory=dict)
    constraint_violations: list[str] = Field(default_factory=list)
    constraint_violation_events: list[dict[str, Any]] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


class TargetPreviewView(BaseModel):
    target: str
    schema_version: int = 1
    phase: Optional[str] = None
    snapshot_id: str = ""
    last_command: str = ""
    resume_strategy: str = ""
    resume_reason: str = ""
    findings_count: int = 0
    verified_count: int = 0
    pending_count: int = 0
    candidate_count: int = 0
    pending_verification_count: int = 0
    manual_review_count: int = 0
    priority_targets: list[str] = Field(default_factory=list)
    priority_recon_assets: list[str] = Field(default_factory=list)
    blocked_targets: list[str] = Field(default_factory=list)
    failed_targets: list[str] = Field(default_factory=list)
    recent_failed_steps: list[str] = Field(default_factory=list)
    next_actions: list[str] = Field(default_factory=list)
    low_value_rounds: int = 0
    constraints: dict[str, Any] = Field(default_factory=dict)
    constraint_violations: list[str] = Field(default_factory=list)
    constraint_violation_events: list[dict[str, Any]] = Field(default_factory=list)


class TargetStateDiffView(BaseModel):
    target: str
    schema_version_from: int = 1
    schema_version_to: int = 1
    from_snapshot_id: str
    to_snapshot_id: str
    resume_strategy_from: str = ""
    resume_strategy_to: str = ""
    added_findings: list[str] = Field(default_factory=list)
    removed_findings: list[str] = Field(default_factory=list)
    updated_findings: list[str] = Field(default_factory=list)
    added_steps: list[str] = Field(default_factory=list)
    removed_steps: list[str] = Field(default_factory=list)
    added_notes: list[str] = Field(default_factory=list)
    removed_notes: list[str] = Field(default_factory=list)
    added_recon_assets: list[str] = Field(default_factory=list)
    removed_recon_assets: list[str] = Field(default_factory=list)


class ReportGenerateRequest(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    output_path: Optional[str] = Field(default=None, max_length=1024)
    report_format: Literal["markdown", "html"] = "markdown"


class ConfigView(BaseModel):
    provider: str
    model: str
    base_url: str
    api_key_configured: bool
    output_dir: str
    max_rounds: int
    persistent_rounds_per_cycle: int
    persistent_max_cycles: int
    show_thinking: bool
    python_execute_enabled: bool
    python_execute_mode: str
    python_execute_max_lines: int
    python_execute_audit_enabled: bool


class ConfigUpdateRequest(BaseModel):
    provider: Optional[str] = Field(default=None, min_length=1, max_length=64)
    model: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=LLM_MODEL_ID_MAX_LENGTH,
    )
    base_url: Optional[str] = Field(default=None, max_length=512)
    output_dir: Optional[str] = Field(default=None, min_length=1, max_length=1024)
    max_rounds: Optional[int] = Field(default=None, ge=1, le=100)
    persistent_rounds_per_cycle: Optional[int] = Field(default=None, ge=1, le=1000)
    persistent_max_cycles: Optional[int] = Field(default=None, ge=0, le=1000)
    show_thinking: Optional[bool] = None
    python_execute_enabled: Optional[bool] = None
    python_execute_mode: Optional[PythonExecuteMode] = None
    python_execute_max_lines: Optional[int] = Field(default=None, ge=1, le=500)
    python_execute_audit_enabled: Optional[bool] = None

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str | None) -> str | None:
        return _validate_http_base_url(value)

    @field_validator("model", mode="before")
    @classmethod
    def validate_model(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("model must be a string")
        return normalize_llm_model_id(value)


class ProviderPresetView(BaseModel):
    id: str
    label: str
    base_url: str
    default_model: str


class ProvidersView(BaseModel):
    providers: list[ProviderPresetView] = Field(default_factory=list)


class ProviderModelsRequest(BaseModel):
    provider: Optional[str] = Field(default=None, min_length=1, max_length=64)
    base_url: Optional[str] = Field(default=None, max_length=512)

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str | None) -> str | None:
        return _validate_http_base_url(value)


class ProviderModelsResponse(BaseModel):
    base_url: str
    models: list[str] = Field(default_factory=list)
    has_api_key: bool = False
    status: ProviderModelsStatus = "ok"
    detail: str = ""


class ReportContentView(BaseModel):
    path: str
    kind: str
    content: str


# 修改者: Nyaecho
# 修改时间: 2026-07-08
# 修改原因: V6 修复 — MCP 视图模型已移至 mcp/schemas.py，此处重新导出以保持兼容。
from vulnclaw.mcp.schemas import MCPDiagnosticsView, MCPServiceView  # noqa: F401, E402


class ConstraintAuditEventView(BaseModel):
    target: str
    timestamp: str = ""
    code: str = ""
    severity: str = ""
    source: str = ""
    action: str = ""
    tool_name: str = ""
    phase: str = ""
    summary: str = ""
    detail: str = ""


class ConstraintAuditView(BaseModel):
    total_events: int = 0
    high_severity_events: int = 0
    by_source: dict[str, int] = Field(default_factory=dict)
    by_code: dict[str, int] = Field(default_factory=dict)
    recent_events: list[ConstraintAuditEventView] = Field(default_factory=list)
