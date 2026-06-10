import type { TaskCommand } from "../types/api";
import { t } from "../i18n";

export function formatTaskCommand(command: string | null | undefined): string {
  if (!command) return t("command.default");
  const key = `command.${command}`;
  const label = t(key);
  return label !== key ? label : t("command.custom");
}

export function formatTaskTitle(command: string | null | undefined, target: string): string {
  return `${formatTaskCommand(command)} - ${target}`;
}

export function formatActionLabel(action: string): string {
  const key = `action.${action}`;
  const label = t(key);
  return label !== key ? label : action;
}

export function formatActionList(actions: string[] | undefined, fallback?: string): string {
  if (!actions?.length) return fallback ?? t("boundary.default_scope");
  return actions.map(formatActionLabel).join(", ");
}

export function formatPhaseLabel(phase: string | null | undefined): string {
  if (!phase) return t("phase.none");
  const normalized = phase.toLowerCase();
  const key = `phase.${normalized}`;
  const label = t(key);
  if (label !== key) return label;
  // Try partial match
  for (const k of ["scope", "recon", "scan", "verify", "exploit", "report"]) {
    if (normalized.includes(k)) return t(`phase.${k}`);
  }
  return phase;
}

export function formatTaskStatus(status: string | null | undefined): string {
  if (!status) return t("status.idle");
  const key = `status.${status}`;
  const label = t(key);
  return label !== key ? label : status;
}

export function formatFindingStatus(status: string | null | undefined): string {
  if (!status) return t("finding_status.pending");
  const normalized = status.toLowerCase();
  const key = `finding_status.${normalized}`;
  const label = t(key);
  if (label !== key) return label;
  for (const k of ["verified", "pending", "candidate", "manual_review", "dismissed", "false_positive"]) {
    if (normalized.includes(k)) return t(`finding_status.${k}`);
  }
  return status;
}

export function formatEventLabel(event: string | null | undefined): string {
  if (!event) return t("event.default");
  const key = `event.${event}`;
  const label = t(key);
  return label !== key ? label : event;
}

export function formatSeverityLabel(severity: string | null | undefined): string {
  if (!severity) return t("severity.info");
  const normalized = severity.toLowerCase();
  const key = `severity.${normalized}`;
  const label = t(key);
  if (label !== key) return label;
  for (const k of ["critical", "high", "medium", "warn", "warning", "low", "info"]) {
    if (normalized.includes(k)) return t(`severity.${k}`);
  }
  return severity;
}

export function formatMcpHealth(status: string | null | undefined): string {
  if (!status) return t("mcp_health.unknown");
  const key = `mcp_health.${status}`;
  const label = t(key);
  return label !== key ? label : status;
}

export function formatMcpExecutionMode(mode: string | null | undefined): string {
  if (!mode) return t("mcp_mode.local");
  const key = `mcp_mode.${mode}`;
  const label = t(key);
  return label !== key ? label : mode;
}

export function formatResumeStrategy(strategy: string | null | undefined): string {
  if (!strategy) return t("resume.none");
  const normalized = strategy.toLowerCase();
  if (normalized.includes("stop") || normalized.includes("complete")) return t("resume.stop");
  if (normalized.includes("verify")) return t("resume.verify");
  if (normalized.includes("exploit")) return t("resume.exploit");
  if (normalized.includes("scan")) return t("resume.scan");
  if (normalized.includes("recon")) return t("resume.recon");
  if (normalized.includes("continue") || normalized.includes("resume")) return t("resume.continue");
  return strategy;
}

export function formatConstraintSummary(constraints: Record<string, unknown> | undefined): string {
  if (!constraints || !Object.keys(constraints).length) return t("boundary.no_extra");
  const labels: string[] = [];
  const onlyHost = constraints.allowed_hosts ?? constraints.only_host;
  const onlyPath = constraints.allowed_paths ?? constraints.only_path;
  const onlyPort = constraints.allowed_ports ?? constraints.only_port;
  const blockedHost = constraints.blocked_hosts ?? constraints.blocked_host;
  const blockedPath = constraints.blocked_paths ?? constraints.blocked_path;
  const allowActions = constraints.allowed_actions ?? constraints.allow_actions;
  const blockActions = constraints.blocked_actions ?? constraints.block_actions;
  if (onlyHost) labels.push(`host ${formatConstraintValue(onlyHost)}`);
  if (onlyPath) labels.push(`path ${formatConstraintValue(onlyPath)}`);
  if (onlyPort) labels.push(`port ${formatConstraintValue(onlyPort)}`);
  if (blockedHost) labels.push(`block host ${formatConstraintValue(blockedHost)}`);
  if (blockedPath) labels.push(`block path ${formatConstraintValue(blockedPath)}`);
  if (Array.isArray(allowActions)) labels.push(`allow ${formatActionList(allowActions.map(String))}`);
  if (Array.isArray(blockActions)) labels.push(`block ${formatActionList(blockActions.map(String))}`);
  return labels.length ? labels.join(", ") : t("boundary.custom");
}

export function countConstraintViolations(
  events: unknown[] | undefined,
  violations: unknown[] | undefined,
  fallback = 0,
): number {
  if (events?.length) return events.length;
  if (violations?.length) return violations.length;
  return fallback;
}

function formatConstraintValue(value: unknown): string {
  if (Array.isArray(value)) return value.map(String).filter(Boolean).join(", ");
  return String(value);
}
