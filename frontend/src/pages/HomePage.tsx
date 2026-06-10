import { useEffect, useMemo, useState } from "react";
import type { TaskCommand, TaskEvent, TaskOptions, TaskRecord, TaskSummary } from "../types/api";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { SectionCard } from "../components/SectionCard";
import { useT, type TFunction } from "../i18n";
import { loadUiPreferences, subscribeUiPreferences } from "../utils/preferences";
import {
  countConstraintViolations,
  formatActionLabel,
  formatActionList,
  formatEventLabel,
  formatPhaseLabel,
  formatTaskCommand,
  formatTaskStatus,
} from "../utils/taskLabels";
import { parseOptionalPort } from "../utils/validation";

type CheckMode = "quick" | "standard" | "deep" | "continuous";

interface HomePageProps {
  selectedTarget: string | null;
  activeTask: TaskRecord | null;
  latestEvent: TaskEvent | null;
  taskEvents: TaskEvent[];
  onCreateTask: (command: TaskCommand, target: string, resume: boolean, options: TaskOptions) => Promise<TaskRecord>;
  onOpenRisk: () => void;
  onOpenReports: () => void;
  onOpenBoundary: () => void;
}

interface ModeDef {
  key: CheckMode;
  title: string;
  copy: string;
  command: TaskCommand;
  allowActions?: string[];
  blockActions?: string[];
}

function buildModes(t: TFunction): ModeDef[] {
  return [
    { key: "quick", title: t("home.mode_quick"), copy: t("home.mode_quick_copy"), command: "recon", allowActions: ["recon"], blockActions: ["exploit", "persistent"] },
    { key: "standard", title: t("home.mode_standard"), copy: t("home.mode_standard_copy"), command: "run", allowActions: ["recon", "scan"], blockActions: ["post_exploitation"] },
    { key: "deep", title: t("home.mode_deep"), copy: t("home.mode_deep_copy"), command: "scan", allowActions: ["recon", "scan", "exploit"] },
    { key: "continuous", title: t("home.mode_loop"), copy: t("home.mode_loop_copy"), command: "persistent", allowActions: ["recon", "scan", "persistent"], blockActions: ["post_exploitation"] },
  ];
}

function buildActionOptions(t: TFunction) {
  return [
    { value: "recon", copy: t("home.action_recon_copy") },
    { value: "scan", copy: t("home.action_scan_copy") },
    { value: "exploit", copy: t("home.action_exploit_copy") },
    { value: "persistent", copy: t("home.action_persistent_copy") },
    { value: "post_exploitation", copy: t("home.action_post_exploit_copy") },
  ];
}

function latestEventText(event: TaskEvent | null, t: TFunction): string {
  if (!event) return t("home.waiting_events");
  const message = event.payload.message ?? event.payload.text;
  if (typeof message === "string" && message.trim()) return message;
  if (typeof event.payload.phase === "string" && event.payload.phase.trim()) {
    return formatPhaseLabel(event.payload.phase);
  }
  return formatEventLabel(event.event);
}

function currentPhaseKey(task: TaskRecord | null, event: TaskEvent | null): string {
  if (!task) return "scope";
  if (task.status === "completed" || task.status === "failed" || task.status === "stopped") return "report";
  const text = `${event?.payload.phase ?? ""} ${event?.event ?? ""} ${task.latest_phase ?? ""}`.toLowerCase();
  if (text.includes("report")) return "report";
  if (text.includes("exploit") || text.includes("verify")) return "verify";
  if (text.includes("scan")) return "scan";
  if (text.includes("recon")) return "recon";
  return task.status === "running" ? "recon" : "scope";
}

function taskResultTitle(task: TaskRecord, t: TFunction): string {
  if (task.status === "completed") return t("home.scan_complete");
  if (task.status === "failed") return t("home.scan_error");
  if (task.status === "stopped") return t("home.scan_stopped");
  return t("home.scanning", { target: task.target });
}

function eventSummary(event: TaskEvent | null): TaskSummary | null {
  const summary = event?.payload.summary;
  return summary && typeof summary === "object" ? (summary as TaskSummary) : null;
}

function taskSummary(task: TaskRecord, event: TaskEvent | null): TaskSummary | null {
  return task.summary ?? eventSummary(event);
}

function formatEventPayload(event: TaskEvent): string {
  return JSON.stringify(event.payload, null, 2);
}

function joinScopeItems(items: string[], t: TFunction): string {
  return items.length ? items.join(" - ") : t("home.auto_scope");
}

function inferScopeFromTarget(value: string): { host: string; port: string; path: string } {
  const target = value.trim();
  if (!target) return { host: "", port: "", path: "" };
  try {
    const parsed = new URL(target.includes("://") ? target : `https://${target}`);
    const inferredPath = parsed.pathname && parsed.pathname !== "/" ? parsed.pathname : "";
    return { host: parsed.hostname, port: parsed.port, path: inferredPath };
  } catch {
    const withoutScheme = target.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
    const match = withoutScheme.match(/^([^/:?#]+)(?::([^/?#]+))?(\/[^?#]*)?/);
    const inferredPath = match?.[3] && match[3] !== "/" ? match[3] : "";
    return { host: match?.[1] ?? "", port: match?.[2] ?? "", path: inferredPath };
  }
}

function uniqueActions(actions: Array<string | undefined>): string[] {
  return Array.from(new Set(actions.filter((action): action is string => Boolean(action))));
}

export function HomePage({ selectedTarget, activeTask, latestEvent, taskEvents, onCreateTask, onOpenRisk, onOpenReports, onOpenBoundary }: HomePageProps) {
  const { t } = useT();
  const preferences = loadUiPreferences();
  const MODES = useMemo(() => buildModes(t), [t]);
  const ACTION_OPTIONS = useMemo(() => buildActionOptions(t), [t]);
  const [target, setTarget] = useState(selectedTarget ?? "");
  const [mode, setMode] = useState<CheckMode>(() => preferences.defaultCheckMode);
  const [onlyPort, setOnlyPort] = useState(preferences.defaultBoundary.onlyPort);
  const [onlyHost, setOnlyHost] = useState(preferences.defaultBoundary.onlyHost);
  const [onlyPath, setOnlyPath] = useState(preferences.defaultBoundary.onlyPath);
  const [blockedHost, setBlockedHost] = useState(preferences.defaultBoundary.blockedHost);
  const [blockedPath, setBlockedPath] = useState(preferences.defaultBoundary.blockedPath);
  const [allowActions, setAllowActions] = useState<string[]>(preferences.defaultBoundary.allowActions);
  const [blockActions, setBlockActions] = useState<string[]>(preferences.defaultBoundary.blockActions);
  const [resume, setResume] = useState(true);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [technicalLogsOpen, setTechnicalLogsOpen] = useState(() => preferences.showTechnicalLogs);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => subscribeUiPreferences((nextPreferences) => {
    setMode(nextPreferences.defaultCheckMode);
    setTechnicalLogsOpen(nextPreferences.showTechnicalLogs);
    setOnlyPort(nextPreferences.defaultBoundary.onlyPort);
    setOnlyHost(nextPreferences.defaultBoundary.onlyHost);
    setOnlyPath(nextPreferences.defaultBoundary.onlyPath);
    setBlockedHost(nextPreferences.defaultBoundary.blockedHost);
    setBlockedPath(nextPreferences.defaultBoundary.blockedPath);
    setAllowActions(nextPreferences.defaultBoundary.allowActions);
    setBlockActions(nextPreferences.defaultBoundary.blockActions);
  }), []);

  useEffect(() => {
    if (selectedTarget) setTarget(selectedTarget);
  }, [selectedTarget]);

  const selectedMode = useMemo(() => MODES.find((item) => item.key === mode) ?? MODES[1], [mode]);
  const inferredScope = inferScopeFromTarget(target);
  const effectiveOnlyHost = onlyHost.trim() || inferredScope.host;
  const effectiveOnlyPort = onlyPort.trim() || inferredScope.port;
  const effectiveOnlyPath = onlyPath.trim() || inferredScope.path;
  const scopeCount = [effectiveOnlyPort, effectiveOnlyHost, effectiveOnlyPath, blockedHost, blockedPath].filter((item) => item.trim()).length;
  const activeSummary = activeTask ? taskSummary(activeTask, latestEvent) : null;
  const boundaryBlockCount = countConstraintViolations(activeSummary?.constraint_violation_events, activeSummary?.constraint_violations);
  const scopePreview = joinScopeItems([
    effectiveOnlyHost ? (onlyHost.trim() ? t("home.host_scope", { host: effectiveOnlyHost }) : t("home.host_scope_inferred", { host: effectiveOnlyHost })) : "",
    effectiveOnlyPort ? (onlyPort.trim() ? t("home.port_scope", { port: effectiveOnlyPort }) : t("home.port_scope_inferred", { port: effectiveOnlyPort })) : "",
    effectiveOnlyPath ? (onlyPath.trim() ? t("home.path_scope", { path: effectiveOnlyPath }) : t("home.path_scope_inferred", { path: effectiveOnlyPath })) : "",
    blockedHost.trim() ? t("home.block_host_scope", { host: blockedHost.trim() }) : "",
    blockedPath.trim() ? t("home.block_path_scope", { path: blockedPath.trim() }) : "",
  ].filter(Boolean), t);
  const effectiveAllowActions = uniqueActions([...(allowActions.length ? allowActions : selectedMode.allowActions ?? []), selectedMode.command]);
  const effectiveBlockActions = uniqueActions(blockActions.length ? blockActions : selectedMode.blockActions ?? [])
    .filter((action) => action !== selectedMode.command);
  const allowPreview = formatActionList(effectiveAllowActions);
  const blockPreview = formatActionList(effectiveBlockActions);
  const requiresExtraCare = mode === "deep" || mode === "continuous";
  const confirmCopy = [
    `${t("home.target")}: ${target.trim() || t("home.confirm_not_set")}`,
    `${t("home.mode_label")}: ${selectedMode.title}`,
    `${t("home.scope")}: ${scopePreview}`,
    requiresExtraCare ? t("home.confirm_extra_care") : "",
  ].join("\n");

  function buildOptions(): TaskOptions {
    return {
      only_port: parseOptionalPort(effectiveOnlyPort),
      only_host: effectiveOnlyHost || undefined,
      only_path: effectiveOnlyPath || undefined,
      blocked_host: blockedHost.trim() || undefined,
      blocked_path: blockedPath.trim() || undefined,
      allow_actions: effectiveAllowActions,
      block_actions: effectiveBlockActions,
    };
  }

  function toggleAction(
    value: string,
    selected: string[],
    setSelected: (next: string[]) => void,
    oppositeSelected?: string[],
    setOppositeSelected?: (next: string[]) => void,
  ) {
    const isSelected = selected.includes(value);
    setSelected(isSelected ? selected.filter((item) => item !== value) : [...selected, value]);
    if (!isSelected && oppositeSelected && setOppositeSelected) {
      setOppositeSelected(oppositeSelected.filter((item) => item !== value));
    }
  }

  async function submit() {
    try {
      setSubmitting(true);
      setError(null);
      await onCreateTask(selectedMode.command, target.trim(), resume, buildOptions());
    } catch (err) {
      setError(err instanceof Error ? err.message : t("error.failed_to_start"));
    } finally {
      setSubmitting(false);
      setConfirmOpen(false);
    }
  }

  function handleStart() {
    try {
      parseOptionalPort(effectiveOnlyPort);
      if (mode === "continuous" && effectiveOnlyPath) {
        setError(t("home.continuous_no_path"));
        return;
      }
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("error.invalid_port"));
      return;
    }
    if (requiresExtraCare) {
      setConfirmOpen(true);
      return;
    }
    void submit();
  }

  const phaseKey = currentPhaseKey(activeTask, latestEvent);
  const phaseSteps = [
    ["scope", t("phase.scope")],
    ["recon", t("phase.recon")],
    ["scan", t("phase.scan")],
    ["verify", t("phase.verify")],
    ["report", t("phase.report")],
  ] as const;

  return (
    <section className="home-page">
      <div className="goby-home-board">
        <div className="goby-welcome-panel" aria-hidden="true">
          <div className="goby-map-illustration">
            <span className="map-node map-node-a">IP</span>
            <span className="map-node map-node-b">WEB</span>
            <span className="map-node map-node-c">APP</span>
            <span className="map-node map-node-d">CVE</span>
            <div className="map-ring">
              <div className="map-shield">VC</div>
            </div>
          </div>
          <div className="goby-welcome-copy">
            <h2>{t("home.welcome")}</h2>
            <p>{t("home.tagline")}</p>
          </div>
          <button
            type="button"
            className={`goby-scan-orb ${submitting ? "hero-orb-busy" : ""}`}
            disabled={submitting || !target.trim()}
            onClick={handleStart}
          >
            {submitting ? t("home.starting") : t("home.scan")}
          </button>
        </div>

        <div className="scan-launch goby-task-panel">
          <div className="goby-task-title">
            <span className="goby-task-icon">▣</span>
            <strong>{t("home.new_scan_task")}</strong>
            <button type="button" className="text-btn inline-text-btn" onClick={() => setTarget("")} aria-label={t("home.clear_target")}>
              ×
            </button>
          </div>
          <div className="goby-task-form">
            <label className="field scan-target-field field-wide">
              <span>{t("home.ip_domain")}</span>
              <textarea
                value={target}
                onChange={(event) => setTarget(event.target.value)}
                placeholder={"172.16.20.36\nexample.com\n192.0.2.0/24"}
              />
            </label>
            <label className="field field-wide">
              <span>{t("home.black_ip")}</span>
              <textarea value={blockedHost} onChange={(event) => setBlockedHost(event.target.value)} placeholder="192.0.2.10" />
            </label>
            <label className="field">
              <span>{t("home.port")}</span>
              <select value={mode} onChange={(event) => setMode(event.target.value as CheckMode)}>
                {MODES.map((item) => (
                  <option key={item.key} value={item.key}>
                    {item.title}
                  </option>
                ))}
              </select>
            </label>
            <label className="field">
              <span>{t("home.custom_ports")}</span>
              <input value={onlyPort} onChange={(event) => setOnlyPort(event.target.value)} inputMode="numeric" placeholder="21,22,80,443" />
            </label>
          </div>

          <div className="scan-mode-row" aria-label="Scan mode">
            {MODES.map((item) => (
              <button
                key={item.key}
                type="button"
                className={`scan-mode-pill ${mode === item.key ? "selected-item" : ""}`}
                onClick={() => setMode(item.key)}
              >
                <strong>{item.title}</strong>
                <span>{item.copy}</span>
              </button>
            ))}
          </div>

          <div className="scan-summary-row">
            <label className="check-row goby-printer-row">
              <input checked={resume} onChange={(event) => setResume(event.target.checked)} type="checkbox" />
              <span>{t("home.resume_previous")}</span>
            </label>
            <span>{scopeCount ? t("home.bounds", { count: String(scopeCount) }) : t("home.auto_scope")}</span>
            <button type="button" className="text-btn inline-text-btn" onClick={() => setAdvancedOpen((value) => !value)}>
              {advancedOpen ? t("home.hide_advanced") : t("home.advanced")}
            </button>
          </div>

          <button
            type="button"
            className={`primary-btn scan-start-btn ${submitting ? "hero-orb-busy" : ""}`}
            disabled={submitting || !target.trim()}
            onClick={handleStart}
          >
            {submitting ? t("home.starting_btn") : t("home.start")}
          </button>
        </div>
      </div>

      {advancedOpen && (
        <SectionCard title={t("home.advanced")}>
          <div className="form-grid compact-form">
            <label className="check-row">
              <input checked={resume} onChange={(event) => setResume(event.target.checked)} type="checkbox" />
              <span>{t("home.resume_previous")}</span>
            </label>
            <label className="field">
              <span>{t("home.port")}</span>
              <input value={onlyPort} onChange={(event) => setOnlyPort(event.target.value)} inputMode="numeric" placeholder="443" />
            </label>
            <label className="field">
              <span>{t("home.host")}</span>
              <input value={onlyHost} onChange={(event) => setOnlyHost(event.target.value)} placeholder="example.com" />
            </label>
            <label className="field">
              <span>{t("home.path")}</span>
              <input value={onlyPath} onChange={(event) => setOnlyPath(event.target.value)} placeholder="/admin" />
            </label>
            <label className="field">
              <span>{t("home.block_host_field")}</span>
              <input value={blockedHost} onChange={(event) => setBlockedHost(event.target.value)} placeholder="staging.example.com" />
            </label>
            <label className="field">
              <span>{t("home.block_path_field")}</span>
              <input value={blockedPath} onChange={(event) => setBlockedPath(event.target.value)} placeholder="/internal" />
            </label>
          </div>
          <div className="scope-summary">
            <strong>{t("home.scope")}</strong>
            <span>{scopePreview}</span>
            <strong>{t("home.allow")}</strong>
            <span>{allowPreview}</span>
            <strong>{t("home.block")}</strong>
            <span>{blockPreview}</span>
          </div>
          <details className="advanced-details">
            <summary>{t("home.action_rules")}</summary>
            <div className="action-boundary-panel">
              <div className="action-choice-grid">
                {ACTION_OPTIONS.map((action) => (
                  <button
                    key={`allow-${action.value}`}
                    type="button"
                    className={`action-choice ${allowActions.includes(action.value) ? "selected-item" : ""}`}
                    onClick={() => toggleAction(action.value, allowActions, setAllowActions, blockActions, setBlockActions)}
                  >
                    <strong>{formatActionLabel(action.value)}</strong>
                  </button>
                ))}
              </div>
              <div className="action-choice-grid">
                {ACTION_OPTIONS.map((action) => (
                  <button
                    key={`block-${action.value}`}
                    type="button"
                    className={`action-choice action-choice-block ${blockActions.includes(action.value) ? "selected-item" : ""}`}
                    onClick={() => toggleAction(action.value, blockActions, setBlockActions, allowActions, setAllowActions)}
                  >
                    <strong>Block {formatActionLabel(action.value)}</strong>
                  </button>
                ))}
              </div>
            </div>
          </details>
          {error && <div className="error-box">{error}</div>}
        </SectionCard>
      )}

      {activeTask && (
        <SectionCard title={t("home.running")} aside={<span className="status-badge">{formatTaskStatus(activeTask.status)}</span>}>
          <div className="check-progress-card">
            <div className="check-progress-head">
              <div>
                <span className="pill">{t("home.current_task")}</span>
                <h3>{taskResultTitle(activeTask, t)}</h3>
                <p>{latestEventText(latestEvent, t)}</p>
              </div>
              <div className="check-progress-target">
                <span>{t("home.target")}</span>
                <strong>{activeTask.target}</strong>
              </div>
            </div>
            <div className="check-stepper">
              {phaseSteps.map(([key, label]) => {
                const done = phaseSteps.findIndex(([stepKey]) => stepKey === key) <= phaseSteps.findIndex(([stepKey]) => stepKey === phaseKey);
                return (
                  <div key={key} className={`check-step ${done ? "check-step-done" : ""}`}>
                    <span />
                    <strong>{label}</strong>
                  </div>
                );
              })}
            </div>
            <div className="next-actions">
              <button type="button" className="primary-btn" onClick={onOpenRisk}>{t("home.view_results")}</button>
              <button type="button" className="secondary-btn" onClick={onOpenReports}>{t("home.view_reports")}</button>
              <button type="button" className="secondary-btn" onClick={onOpenBoundary}>{t("home.view_boundary")}</button>
            </div>
            {activeSummary && (
              <div className="stats-grid check-result-stats">
                <article className="stat">
                  <span className="stat-label">{t("home.verified")}</span>
                  <strong>{activeSummary.verified_count}</strong>
                </article>
                <article className="stat">
                  <span className="stat-label">{t("home.pending")}</span>
                  <strong>{activeSummary.pending_count}</strong>
                </article>
                <article className="stat">
                  <span className="stat-label">{t("home.boundary_hits")}</span>
                  <strong>{boundaryBlockCount}</strong>
                </article>
                <article className="stat">
                  <span className="stat-label">{t("home.snapshot")}</span>
                  <strong>{activeSummary.snapshot_id || t("home.saved")}</strong>
                </article>
              </div>
            )}
            <div className="technical-log-panel">
              <button type="button" className="text-btn technical-log-toggle" onClick={() => setTechnicalLogsOpen((value) => !value)}>
                {technicalLogsOpen ? t("home.hide_raw_events") : t("home.show_raw_events")}
              </button>
              {technicalLogsOpen && (
                <div className="technical-log-stream" aria-live="polite">
                  {taskEvents.length ? (
                    taskEvents.slice(-24).map((event) => (
                      <article key={`${event.task_id}-${event.timestamp}-${event.event}`} className="technical-log-entry">
                        <header>
                          <strong>{formatEventLabel(event.event)}</strong>
                          <span>{new Date(event.timestamp).toLocaleTimeString()}</span>
                        </header>
                        <pre>{formatEventPayload(event)}</pre>
                      </article>
                    ))
                  ) : (
                    <div className="empty-state">{t("home.no_raw_events")}</div>
                  )}
                </div>
              )}
            </div>
          </div>
        </SectionCard>
      )}

      <ConfirmDialog
        open={confirmOpen}
        title={t("home.confirm_deep_title")}
        copy={confirmCopy}
        confirmLabel={t("home.confirm_scan_label")}
        onCancel={() => setConfirmOpen(false)}
        onConfirm={() => {
          setConfirmOpen(false);
          void submit();
        }}
      />
    </section>
  );
}
