import { useEffect, useMemo, useState } from "react";
import { SectionCard } from "../components/SectionCard";
import { useConstraintAuditQuery, useTargetQuery, useTargetsQuery } from "../hooks/queries";
import { useT, type TFunction } from "../i18n";
import type { ConstraintAuditEventView, TaskOptions, TaskRecord } from "../types/api";
import { loadUiPreferences, subscribeUiPreferences, type BoundaryDefaults } from "../utils/preferences";
import { countConstraintViolations, formatActionList, formatPhaseLabel, formatSeverityLabel } from "../utils/taskLabels";

interface SafetyBoundaryPageProps {
  selectedTarget: string | null;
  activeTask: TaskRecord | null;
  onOpenHome: () => void;
  onOpenSettings: () => void;
  onSelectTarget: (target: string | null) => void;
}

interface BoundaryChip {
  label: string;
  value: string;
  tone: "allow" | "block" | "neutral";
}

interface BoundaryReadiness {
  tone: "ok" | "warn";
  title: string;
  copy: string;
}

function stringifyValue(key: string, value: unknown): string {
  if (Array.isArray(value)) {
    const values = value.map(String).filter(Boolean);
    return key.includes("actions") ? formatActionList(values) : values.join(", ");
  }
  if (typeof value === "string") return key.includes("actions") ? formatActionList([value]) : value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (value && typeof value === "object") return JSON.stringify(value);
  return "";
}

function boundaryLabel(key: string, t: TFunction): string {
  const labels: Record<string, string> = {
    only_host: t("boundary.host_only"),
    only_path: t("boundary.path_only"),
    only_port: t("boundary.port_only"),
    allowed_hosts: t("boundary.host_only"),
    allowed_paths: t("boundary.path_only"),
    allowed_ports: t("boundary.port_only"),
    blocked_host: t("boundary.block_host"),
    blocked_path: t("boundary.block_path"),
    blocked_hosts: t("boundary.block_host"),
    blocked_paths: t("boundary.block_path"),
    allow_actions: t("boundary.allow_actions"),
    allowed_actions: t("boundary.allow_actions"),
    block_actions: t("boundary.block_actions"),
    blocked_actions: t("boundary.block_actions"),
  };
  return labels[key] ?? key;
}

function boundaryTone(key: string): BoundaryChip["tone"] {
  if (key.startsWith("blocked") || key.startsWith("block_")) return "block";
  if (key.startsWith("only") || key.startsWith("allow") || key.startsWith("allowed")) return "allow";
  return "neutral";
}

function normalizeConstraints(constraints: Record<string, unknown> | undefined): Record<string, unknown> {
  if (!constraints) return {};
  return {
    allowed_hosts: constraints.allowed_hosts ?? constraints.only_host,
    allowed_ports: constraints.allowed_ports ?? constraints.only_port,
    allowed_paths: constraints.allowed_paths ?? constraints.only_path,
    blocked_hosts: constraints.blocked_hosts ?? constraints.blocked_host,
    blocked_paths: constraints.blocked_paths ?? constraints.blocked_path,
    allowed_actions: constraints.allowed_actions ?? constraints.allow_actions,
    blocked_actions: constraints.blocked_actions ?? constraints.block_actions,
  };
}

function buildBoundaryChips(constraints: Record<string, unknown> | undefined, t: TFunction): BoundaryChip[] {
  if (!constraints) return [];
  return Object.entries(normalizeConstraints(constraints))
    .map(([key, value]) => ({
      label: boundaryLabel(key, t),
      value: stringifyValue(key, value),
      tone: boundaryTone(key),
    }))
    .filter((item) => item.value && item.value !== "[]" && item.value !== "{}");
}

function boundaryDefaultsToConstraints(defaults: BoundaryDefaults): Record<string, unknown> {
  return {
    only_port: defaults.onlyPort,
    only_host: defaults.onlyHost,
    only_path: defaults.onlyPath,
    blocked_host: defaults.blockedHost,
    blocked_path: defaults.blockedPath,
    allow_actions: defaults.allowActions,
    block_actions: defaults.blockActions,
  };
}

function taskOptionsToConstraints(options: TaskOptions | undefined): Record<string, unknown> {
  if (!options) return {};
  return {
    only_port: options.only_port,
    only_host: options.only_host,
    only_path: options.only_path,
    blocked_host: options.blocked_host,
    blocked_path: options.blocked_path,
    allow_actions: options.allow_actions,
    block_actions: options.block_actions,
  };
}

function hasConstraintValue(value: unknown): boolean {
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === "string") return value.trim().length > 0;
  return value !== undefined && value !== null && value !== false;
}

function boundaryReadiness(constraints: Record<string, unknown> | undefined, t: TFunction): BoundaryReadiness {
  const normalized = normalizeConstraints(constraints);
  if (!Object.values(normalized).some(hasConstraintValue)) {
    return {
      tone: "warn",
      title: t("boundary.readiness_add_scope"),
      copy: t("boundary.readiness_add_scope_desc"),
    };
  }

  const hasPreciseScope = ["allowed_hosts", "allowed_ports", "allowed_paths"].some((key) => hasConstraintValue(normalized[key]));
  const hasActionBoundary = ["allowed_actions", "blocked_actions"].some((key) => hasConstraintValue(normalized[key]));

  if (hasPreciseScope && hasActionBoundary) {
    return {
      tone: "ok",
      title: t("boundary.readiness_clear"),
      copy: t("boundary.readiness_clear_desc"),
    };
  }

  return {
    tone: "warn",
    title: t("boundary.readiness_active"),
    copy: hasPreciseScope ? t("boundary.readiness_active_need_actions") : t("boundary.readiness_active_need_scope"),
  };
}

function formatTime(value: string, t: TFunction): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value || t("boundary.unknown");
  return date.toLocaleString();
}

function eventTone(event: ConstraintAuditEventView): "danger" | "warn" | "info" {
  const severity = event.severity.toLowerCase();
  if (severity.includes("high") || severity.includes("critical")) return "danger";
  if (severity.includes("medium") || severity.includes("warn")) return "warn";
  return "info";
}

export function SafetyBoundaryPage({ selectedTarget, activeTask, onOpenHome, onOpenSettings, onSelectTarget }: SafetyBoundaryPageProps) {
  const { t } = useT();
  const targetsQuery = useTargetsQuery();
  const auditQuery = useConstraintAuditQuery();
  const [localTarget, setLocalTarget] = useState("");
  const [showTechnical, setShowTechnical] = useState(false);
  const [defaultBoundary, setDefaultBoundary] = useState<BoundaryDefaults>(() => loadUiPreferences().defaultBoundary);

  useEffect(() => subscribeUiPreferences((preferences) => setDefaultBoundary(preferences.defaultBoundary)), []);

  useEffect(() => {
    if (selectedTarget) {
      setLocalTarget(selectedTarget);
      return;
    }
    const first = targetsQuery.data?.[0]?.target;
    if (first) {
      setLocalTarget(first);
      onSelectTarget(first);
    }
  }, [selectedTarget, targetsQuery.data, onSelectTarget]);

  const targetValue = selectedTarget ?? localTarget ?? null;
  const targetQuery = useTargetQuery(targetValue);
  const target = targetQuery.data;
  const audit = auditQuery.data;
  const defaultConstraints = useMemo(() => boundaryDefaultsToConstraints(defaultBoundary), [defaultBoundary]);
  const activeTaskConstraints = useMemo(() => taskOptionsToConstraints(activeTask?.options), [activeTask?.options]);
  const activeTaskMatchesTarget = Boolean(activeTask?.target && activeTask.target === targetValue);
  const displayedConstraints = activeTaskMatchesTarget && Object.values(activeTaskConstraints).some(hasConstraintValue)
    ? activeTaskConstraints
    : target?.constraints;
  const displayedConstraintsSource = activeTaskMatchesTarget && Object.values(activeTaskConstraints).some(hasConstraintValue)
    ? t("boundary.active_task_source")
    : t("boundary.saved_target_source");
  const chips = useMemo(() => buildBoundaryChips(displayedConstraints, t), [displayedConstraints, t]);
  const defaultChips = useMemo(() => buildBoundaryChips(defaultConstraints, t), [defaultConstraints, t]);
  const targetEvents = useMemo(() => {
    const selected = targetValue;
    const events = audit?.recent_events ?? [];
    return selected ? events.filter((event) => event.target === selected) : events;
  }, [audit?.recent_events, targetValue]);
  const blockedCount = countConstraintViolations(target?.constraint_violation_events, target?.constraint_violations, targetEvents.length);
  const highSeverityCount = targetEvents.filter((event) => eventTone(event) === "danger").length;
  const readiness = useMemo(() => boundaryReadiness(displayedConstraints, t), [displayedConstraints, t]);
  const defaultReadiness = useMemo(() => boundaryReadiness(defaultConstraints, t), [defaultConstraints, t]);

  return (
    <section className="boundary-page">
      <SectionCard
        title={t("boundary.title")}
        aside={<span className="status-badge">{t("boundary.blocked", { count: String(blockedCount) })}</span>}
      >
        <label className="field">
          <span>{t("boundary.target")}</span>
          <select
            value={targetValue ?? ""}
            onChange={(event) => {
              const value = event.target.value || null;
              setLocalTarget(value ?? "");
              onSelectTarget(value);
            }}
          >
            <option value="">{t("boundary.all_targets")}</option>
            {targetsQuery.data?.map((item) => (
              <option key={item.target} value={item.target}>
                {item.target}
              </option>
            ))}
          </select>
        </label>

        <div className="boundary-hero">
          <div>
            <span className="pill">{t("boundary.watch")}</span>
            <h3>{blockedCount > 0 ? t("boundary.blocked_attempts") : t("boundary.no_blocked")}</h3>
          </div>
          <div className="boundary-shield">
            <strong>{blockedCount}</strong>
            <span>{t("boundary.blocked_label")}</span>
          </div>
        </div>

        <div className="stats-grid">
          <article className="stat">
            <span className="stat-label">{t("boundary.audit_hits")}</span>
            <strong>{audit?.total_events ?? 0}</strong>
          </article>
          <article className="stat">
            <span className="stat-label">{t("boundary.high_severity")}</span>
            <strong>{audit?.high_severity_events ?? 0}</strong>
          </article>
          <article className="stat">
            <span className="stat-label">{t("boundary.current_high")}</span>
            <strong>{highSeverityCount}</strong>
          </article>
          <article className="stat">
            <span className="stat-label">{t("boundary.rules")}</span>
            <strong>{chips.length}</strong>
          </article>
        </div>
      </SectionCard>

      <div className="split-grid">
        <SectionCard title={t("boundary.current_scope")} aside={<span className="status-badge">{displayedConstraintsSource}</span>}>
          <div className={`boundary-readiness boundary-readiness-${readiness.tone}`}>
            <strong>{readiness.title}</strong>
            <span>{readiness.copy}</span>
          </div>
          <div className="boundary-chip-grid">
            {chips.length ? chips.map((chip) => (
              <div key={`${chip.label}-${chip.value}`} className={`boundary-chip boundary-chip-${chip.tone}`}>
                <span>{chip.label}</span>
                <strong>{chip.value}</strong>
              </div>
            )) : (
              <div className="empty-state boundary-empty-state">
                <span>{targetQuery.isLoading ? t("boundary.loading_target") : t("boundary.no_scope_set")}</span>
                {!targetQuery.isLoading && (
                  <button className="secondary-btn" type="button" onClick={onOpenHome}>
                    {t("boundary.set_scope_home")}
                  </button>
                )}
              </div>
            )}
          </div>
        </SectionCard>

        <SectionCard title={t("boundary.defaults")}>
          <div className={`boundary-readiness boundary-readiness-${defaultReadiness.tone}`}>
            <strong>{defaultReadiness.title}</strong>
            <span>{defaultReadiness.copy}</span>
          </div>
          <div className="boundary-chip-grid">
            {defaultChips.length ? defaultChips.map((chip) => (
              <div key={`default-${chip.label}-${chip.value}`} className={`boundary-chip boundary-chip-${chip.tone}`}>
                <span>{chip.label}</span>
                <strong>{chip.value}</strong>
              </div>
            )) : (
              <div className="empty-state boundary-empty-state">
                <span>{t("boundary.no_defaults")}</span>
                <button className="secondary-btn" type="button" onClick={onOpenSettings}>
                  {t("boundary.open_settings")}
                </button>
              </div>
            )}
          </div>
        </SectionCard>

        <SectionCard title={t("boundary.notes")}>
          <div className="boundary-explain-list">
            <div className="boundary-explain-item">
              <strong>{t("boundary.note_checked")}</strong>
              <span>{t("boundary.note_checked_desc")}</span>
            </div>
            <div className="boundary-explain-item">
              <strong>{t("boundary.note_saved")}</strong>
              <span>{t("boundary.note_saved_desc")}</span>
            </div>
            <div className="boundary-explain-item">
              <strong>{t("boundary.note_deeper")}</strong>
              <span>{t("boundary.note_deeper_desc")}</span>
            </div>
          </div>
        </SectionCard>
      </div>

      <SectionCard title={t("boundary.blocked_attempts_title")}>
        <div className="boundary-timeline">
          {targetEvents.length ? (
            targetEvents.map((event, index) => (
              <article key={`${event.timestamp}-${event.code}-${index}`} className={`boundary-event boundary-event-${eventTone(event)}`}>
                <div className="boundary-event-time">
                  <span>{formatTime(event.timestamp, t)}</span>
                </div>
                <div className="boundary-event-body">
                  <div className="boundary-event-head">
                    <strong>{event.summary || t("boundary.blocked_attempt")}</strong>
                    <span className={`severity-badge severity-${eventTone(event)}`}>{formatSeverityLabel(event.severity)}</span>
                  </div>
                  <p>{event.detail || t("boundary.blocked_attempt_default")}</p>
                  <div className="boundary-event-meta">
                    <span>{t("home.target")}: {event.target || t("boundary.unknown")}</span>
                    <span>{t("boundary.allow_actions")}: {formatActionList(event.action ? [event.action] : undefined, t("boundary.unrecorded"))}</span>
                    <span>Tool: {event.tool_name || t("boundary.unrecorded")}</span>
                    <span>{t("phase.none")}: {formatPhaseLabel(event.phase)}</span>
                  </div>
                </div>
              </article>
            ))
          ) : (
            <div className="empty-state">{t("boundary.no_blocked_recorded")}</div>
          )}
        </div>
      </SectionCard>

      <SectionCard
        title={t("boundary.technical_audit")}
        aside={
          <button type="button" className="text-btn inline-text-btn" onClick={() => setShowTechnical((value) => !value)}>
            {showTechnical ? t("boundary.hide") : t("boundary.show")}
          </button>
        }
      >
        {showTechnical ? (
          <div className="split-grid no-top-gap">
            <article className="inset-card compact-card">
              <h4>{t("boundary.by_source")}</h4>
              <div className="list">
                {audit && Object.entries(audit.by_source).length ? Object.entries(audit.by_source).map(([key, value]) => (
                  <div key={key} className="list-item">
                    <strong>{key}</strong>
                    <span>{value}</span>
                  </div>
                )) : <div className="empty-state">{t("boundary.no_source")}</div>}
              </div>
            </article>
            <article className="inset-card compact-card">
              <h4>{t("boundary.by_rule")}</h4>
              <div className="list">
                {audit && Object.entries(audit.by_code).length ? Object.entries(audit.by_code).map(([key, value]) => (
                  <div key={key} className="list-item">
                    <strong>{key}</strong>
                    <span>{value}</span>
                  </div>
                )) : <div className="empty-state">{t("boundary.no_rule")}</div>}
              </div>
            </article>
          </div>
        ) : (
          <div className="empty-state">{t("boundary.technical_hidden")}</div>
        )}
      </SectionCard>
    </section>
  );
}
