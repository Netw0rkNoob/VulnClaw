export type TaskCommand = "run" | "recon" | "scan" | "exploit" | "persistent";

export type TaskStatus = "pending" | "restoring" | "running" | "completed" | "failed" | "stopped";

export interface ConfigView {
  provider: string;
  model: string;
  base_url: string;
  api_key_configured: boolean;
  output_dir: string;
  max_rounds: number;
  persistent_rounds_per_cycle: number;
  persistent_max_cycles: number;
  show_thinking: boolean;
  python_execute_enabled: boolean;
  python_execute_mode: string;
  python_execute_max_lines: number;
  python_execute_audit_enabled: boolean;
}

export interface ConfigUpdateRequest {
  provider?: string;
  model?: string;
  base_url?: string;
  output_dir?: string;
  max_rounds?: number;
  persistent_rounds_per_cycle?: number;
  persistent_max_cycles?: number;
  show_thinking?: boolean;
  python_execute_enabled?: boolean;
  python_execute_mode?: string;
  python_execute_max_lines?: number;
  python_execute_audit_enabled?: boolean;
}

export interface ProviderPresetView {
  id: string;
  label: string;
  base_url: string;
  default_model: string;
}

export interface ProvidersView {
  providers: ProviderPresetView[];
}

export interface ProviderModelsRequest {
  provider?: string;
  base_url?: string;
}

export type ProviderModelsStatus =
  | "ok"
  | "missing_key"
  | "untrusted_url"
  | "authentication_failed"
  | "timeout"
  | "malformed_response"
  | "response_too_large"
  | "empty_catalog"
  | "redirect_blocked"
  | "upstream_error";

export interface ProviderModelsResponse {
  base_url: string;
  models: string[];
  has_api_key: boolean;
  status: ProviderModelsStatus;
  detail: string;
}

export interface TargetView {
  target: string;
  schema_version: number;
  phase?: string;
  findings_count: number;
  verified_count: number;
  pending_count: number;
  candidate_count: number;
  pending_verification_count: number;
  manual_review_count: number;
  resume_strategy: string;
  resume_reason: string;
  constraints: Record<string, unknown>;
  constraint_violations: string[];
  constraint_violation_events: Record<string, unknown>[];
  raw: Record<string, unknown>;
}

export interface TargetSnapshotView {
  snapshot_id: string;
  schema_version: number;
  last_saved_at: string;
  last_command: string;
  verified_findings: number;
  pending_findings: number;
  executed_steps: number;
  resume_strategy: string;
}

export interface TargetPreviewView {
  target: string;
  schema_version: number;
  phase?: string;
  snapshot_id: string;
  last_command: string;
  resume_strategy: string;
  resume_reason: string;
  findings_count: number;
  verified_count: number;
  pending_count: number;
  candidate_count: number;
  pending_verification_count: number;
  manual_review_count: number;
  priority_targets: string[];
  priority_recon_assets: string[];
  blocked_targets: string[];
  failed_targets: string[];
  recent_failed_steps: string[];
  next_actions: string[];
  low_value_rounds: number;
  constraints: Record<string, unknown>;
  constraint_violations: string[];
  constraint_violation_events: Record<string, unknown>[];
}

export interface TargetStateDiffView {
  target: string;
  schema_version_from: number;
  schema_version_to: number;
  from_snapshot_id: string;
  to_snapshot_id: string;
  resume_strategy_from: string;
  resume_strategy_to: string;
  added_findings: string[];
  removed_findings: string[];
  updated_findings: string[];
  added_steps: string[];
  removed_steps: string[];
  added_notes: string[];
  removed_notes: string[];
  added_recon_assets: string[];
  removed_recon_assets: string[];
}

export interface ReportListItem {
  name: string;
  path: string;
  kind: string;
  modified_at?: string;
  size_bytes?: number;
}

export interface ReportContentView {
  path: string;
  kind: string;
  content: string;
}

export interface TaskOptions {
  max_rounds?: number;
  rounds_per_cycle?: number;
  max_cycles?: number;
  cve?: string;
  cmd?: string;
  only_port?: number;
  only_host?: string;
  only_path?: string;
  blocked_host?: string;
  blocked_path?: string;
  allow_actions?: string[];
  block_actions?: string[];
}

export interface TaskSummary {
  target: string;
  command: TaskCommand;
  restored: boolean;
  snapshot_id: string;
  schema_version: number;
  status: string;
  exit_code: number;
  exit_meaning: string;
  run_name: string;
  run_dir: string;
  resume_command: string;
  artifact_locations: Record<string, string>;
  phase?: string;
  findings_count: number;
  verified_count: number;
  pending_count: number;
  candidate_count: number;
  quarantined_count: number;
  executed_steps: number;
  resume_strategy: string;
  resume_reason: string;
  constraints: Record<string, unknown>;
  constraint_violations: string[];
  constraint_violation_events: Record<string, unknown>[];
}

export interface TaskRecord {
  task_id: string;
  command: TaskCommand;
  target: string;
  status: TaskStatus;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  error?: string;
  resume: boolean;
  snapshot_id?: string | null;
  options: TaskOptions;
  latest_phase?: string | null;
  latest_message?: string | null;
  summary?: TaskSummary | null;
}

export interface TaskEvent {
  event: string;
  task_id: string;
  timestamp: string;
  payload: Record<string, unknown>;
}

export interface MCPServiceView {
  name: string;
  enabled: boolean;
  priority: number;
  transport_type: string;
  execution_mode: string;
  health_status: string;
  attach_attempted: boolean;
  attach_succeeded: boolean;
  running: boolean;
  can_execute: boolean;
  tool_count: number;
  tools: string[];
  error?: string | null;
  last_error_type?: string | null;
  started_at?: string | null;
  description: string;
  call_count: number;
  success_count: number;
  failure_count: number;
}

export interface MCPDiagnosticsView {
  total_services: number;
  running_services: number;
  local_services: number;
  placeholder_services: number;
  tool_count: number;
  services: MCPServiceView[];
}

export interface ConstraintAuditEventView {
  target: string;
  timestamp: string;
  code: string;
  severity: string;
  source: string;
  action: string;
  tool_name: string;
  phase: string;
  summary: string;
  detail: string;
}

export interface ConstraintAuditView {
  total_events: number;
  high_severity_events: number;
  by_source: Record<string, number>;
  by_code: Record<string, number>;
  recent_events: ConstraintAuditEventView[];
}
