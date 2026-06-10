import { useMemo, useState } from "react";
import { createTask, stopTask } from "../api/web";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { useTasksQuery } from "../hooks/queries";
import { useT, type TFunction } from "../i18n";
import type { TaskCommand, TaskEvent, TaskOptions, TaskRecord } from "../types/api";
import {
  formatActionLabel,
  formatActionList,
  formatConstraintSummary,
  formatEventLabel,
  formatPhaseLabel,
  formatTaskCommand,
  formatTaskStatus,
  formatTaskTitle,
} from "../utils/taskLabels";
import { parseOptionalPort } from "../utils/validation";

function buildActionOptions(t: TFunction) {
  return [
    { value: "recon", copy: t("home.action_recon_copy") },
    { value: "scan", copy: t("home.action_scan_copy") },
    { value: "exploit", copy: t("home.action_exploit_copy") },
    { value: "persistent", copy: t("home.action_persistent_copy") },
    { value: "post_exploitation", copy: t("home.action_post_exploit_copy") },
  ];
}

interface TaskConsolePageProps {
  activeTask: TaskRecord | null;
  events: TaskEvent[];
  onTaskCreated: (task: TaskRecord) => void;
  onEvent: (event: TaskEvent) => void;
  onFocusTarget: (target: string) => void;
}

export function TaskConsolePage({
  activeTask,
  events,
  onTaskCreated,
  onFocusTarget,
}: TaskConsolePageProps) {
  const { t } = useT();
  const ACTION_OPTIONS = useMemo(() => buildActionOptions(t), [t]);
  const tasksQuery = useTasksQuery();
  const [command, setCommand] = useState<TaskCommand>("persistent");
  const [target, setTarget] = useState("");
  const [resume, setResume] = useState(true);
  const [maxRounds, setMaxRounds] = useState<number | "">("");
  const [roundsPerCycle, setRoundsPerCycle] = useState<number | "">("");
  const [maxCycles, setMaxCycles] = useState<number | "">("");
  const [cve, setCve] = useState("");
  const [cmd, setCmd] = useState("");
  const [onlyPort, setOnlyPort] = useState("");
  const [onlyHost, setOnlyHost] = useState("");
  const [onlyPath, setOnlyPath] = useState("");
  const [blockedHost, setBlockedHost] = useState("");
  const [blockedPath, setBlockedPath] = useState("");
  const [allowActions, setAllowActions] = useState<string[]>([]);
  const [blockActions, setBlockActions] = useState<string[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmRunOpen, setConfirmRunOpen] = useState(false);
  const [confirmStopOpen, setConfirmStopOpen] = useState(false);

  const latestEvents = useMemo(() => events.slice(-24).reverse(), [events]);
  const requiresRunConfirmation = command === "exploit" || command === "persistent";
  const scopePreview = formatConstraintSummary({
    only_port: onlyPort.trim() || undefined,
    only_host: onlyHost.trim() || undefined,
    only_path: onlyPath.trim() || undefined,
    blocked_host: blockedHost.trim() || undefined,
    blocked_path: blockedPath.trim() || undefined,
    allow_actions: allowActions.length ? allowActions : undefined,
    block_actions: blockActions.length ? blockActions : undefined,
  });
  const runConfirmCopy = t("console.confirm_raw_copy", {
    target: target.trim() || t("home.confirm_not_set"),
    command: `${formatTaskCommand(command)} (${command})`,
    scope: scopePreview,
  });

  function renderEventText(item: TaskEvent): string {
    const payload = item.payload;
    const parts: string[] = [];
    if (typeof payload.cycle === "number") parts.push(`cycle ${payload.cycle}`);
    if (typeof payload.round === "number") parts.push(`round ${payload.round}`);
    if (typeof payload.phase === "string") parts.push(formatPhaseLabel(payload.phase));
    const text = typeof payload.text === "string" ? payload.text : "";
    const message = typeof payload.message === "string" ? payload.message : "";
    parts.push(text || message || formatEventLabel(item.event));
    return parts.join(" - ");
  }

  function eventTone(eventName: string): "ok" | "warn" | "danger" | "info" {
    if (eventName.includes("completed")) return "ok";
    if (eventName.includes("failed")) return "danger";
    if (eventName.includes("stopped")) return "warn";
    if (eventName.includes("state") || eventName.includes("started")) return "info";
    return "info";
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

  function buildTaskOptions(): TaskOptions {
    return {
      max_rounds: maxRounds === "" ? undefined : maxRounds,
      rounds_per_cycle: roundsPerCycle === "" ? undefined : roundsPerCycle,
      max_cycles: maxCycles === "" ? undefined : maxCycles,
      cve: cve.trim() || undefined,
      cmd: cmd.trim() || undefined,
      only_port: parseOptionalPort(onlyPort),
      only_host: onlyHost.trim() || undefined,
      only_path: onlyPath.trim() || undefined,
      blocked_host: blockedHost.trim() || undefined,
      blocked_path: blockedPath.trim() || undefined,
      allow_actions: allowActions.length ? allowActions : undefined,
      block_actions: blockActions.length ? blockActions : undefined,
    };
  }

  function handleRunRequest() {
    try {
      setError(null);
      buildTaskOptions();
      if (requiresRunConfirmation) {
        setConfirmRunOpen(true);
        return;
      }
      void handleRun();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("error.invalid_task_params"));
    }
  }

  async function handleRun() {
    try {
      setSubmitting(true);
      setError(null);
      const task = await createTask(command, target, resume, buildTaskOptions());
      onTaskCreated(task);
      onFocusTarget(task.target);
      await tasksQuery.refetch();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("error.failed_to_start"));
    } finally {
      setSubmitting(false);
    }
  }

  async function handleStop() {
    if (!activeTask) return;
    try {
      await stopTask(activeTask.task_id);
      await tasksQuery.refetch();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("error.stop_failed"));
    }
  }

  return (
    <section className="card">
      <header className="card-header">
        <div>
          <h3>{t("console.title")}</h3>
          <p>{t("console.description")}</p>
        </div>
        <span className="status-badge">{formatTaskStatus(activeTask?.status)}</span>
      </header>

      <div className="form-grid">
        <label className="field">
          <span>{t("console.command")}</span>
          <select value={command} onChange={(event) => setCommand(event.target.value as TaskCommand)}>
            <option value="run">{t("command.run")}</option>
            <option value="recon">{t("command.recon")}</option>
            <option value="scan">{t("command.scan")}</option>
            <option value="exploit">{t("command.exploit")}</option>
            <option value="persistent">{t("command.persistent")}</option>
          </select>
          <small>{t("console.api_command", { command })}</small>
        </label>

        <label className="field field-wide">
          <span>{t("console.target")}</span>
          <input value={target} onChange={(event) => setTarget(event.target.value)} placeholder="https://target.example" />
        </label>

        <label className="check-row">
          <input checked={resume} onChange={(event) => setResume(event.target.checked)} type="checkbox" />
          <span>{t("console.resume_state")}</span>
        </label>
        <label className="field">
          <span>{t("console.max_rounds")}</span>
          <input type="number" value={maxRounds} onChange={(event) => setMaxRounds(event.target.value ? Number(event.target.value) : "")} placeholder={t("console.backend_default")} />
        </label>
        <label className="field">
          <span>{t("console.rounds_per_cycle")}</span>
          <input type="number" value={roundsPerCycle} onChange={(event) => setRoundsPerCycle(event.target.value ? Number(event.target.value) : "")} placeholder={t("console.continuous_only")} />
        </label>
        <label className="field">
          <span>{t("console.max_cycles")}</span>
          <input type="number" value={maxCycles} onChange={(event) => setMaxCycles(event.target.value ? Number(event.target.value) : "")} placeholder={t("console.continuous_only")} />
        </label>
        <label className="field">
          <span>{t("console.cve_hint")}</span>
          <input value={cve} onChange={(event) => setCve(event.target.value)} placeholder="CVE-2024-xxxx" />
        </label>
        <label className="field">
          <span>{t("console.port_only")}</span>
          <input inputMode="numeric" value={onlyPort} onChange={(event) => setOnlyPort(event.target.value)} placeholder="443" />
        </label>
        <label className="field">
          <span>{t("console.host_only")}</span>
          <input value={onlyHost} onChange={(event) => setOnlyHost(event.target.value)} placeholder="example.com" />
        </label>
        <label className="field field-wide">
          <span>{t("console.path_only")}</span>
          <input value={onlyPath} onChange={(event) => setOnlyPath(event.target.value)} placeholder="/admin" />
        </label>
        <label className="field">
          <span>{t("console.block_host")}</span>
          <input value={blockedHost} onChange={(event) => setBlockedHost(event.target.value)} placeholder="staging.example.com" />
        </label>
        <label className="field">
          <span>{t("console.block_path")}</span>
          <input value={blockedPath} onChange={(event) => setBlockedPath(event.target.value)} placeholder="/internal" />
        </label>
        <div className="field field-wide">
          <span>{t("console.allow_actions")}</span>
          <div className="action-choice-grid">
            {ACTION_OPTIONS.map((action) => (
              <button
                key={`advanced-allow-${action.value}`}
                type="button"
                className={`action-choice ${allowActions.includes(action.value) ? "selected-item" : ""}`}
                onClick={() => toggleAction(action.value, allowActions, setAllowActions, blockActions, setBlockActions)}
              >
                <strong>{formatActionLabel(action.value)}</strong>
                <span>{action.copy}</span>
              </button>
            ))}
          </div>
          <small>{formatActionList(allowActions, t("console.no_allow_list"))}</small>
        </div>
        <div className="field field-wide">
          <span>{t("console.block_actions")}</span>
          <div className="action-choice-grid">
            {ACTION_OPTIONS.map((action) => (
              <button
                key={`advanced-block-${action.value}`}
                type="button"
                className={`action-choice action-choice-block ${blockActions.includes(action.value) ? "selected-item" : ""}`}
                onClick={() => toggleAction(action.value, blockActions, setBlockActions, allowActions, setAllowActions)}
              >
                <strong>{formatActionLabel(action.value)}</strong>
                <span>{action.copy}</span>
              </button>
            ))}
          </div>
          <small>{formatActionList(blockActions, t("console.no_block_list"))}</small>
        </div>
        <label className="field field-wide">
          <span>{t("console.command_hint")}</span>
          <input value={cmd} onChange={(event) => setCmd(event.target.value)} placeholder="verification command, for example id" />
        </label>
      </div>

      <div className="button-row">
        <button className="primary-btn" disabled={submitting || !target.trim()} onClick={handleRunRequest} type="button">
          {submitting ? t("console.launching") : t("console.launch_raw")}
        </button>
        <button className="secondary-btn" disabled={!activeTask || activeTask.status !== "running"} onClick={() => setConfirmStopOpen(true)} type="button">
          {t("console.stop_task")}
        </button>
      </div>

      {error && <div className="error-box">{error}</div>}

      <ConfirmDialog
        open={confirmRunOpen}
        title={t("console.confirm_raw_title")}
        copy={runConfirmCopy}
        tone="danger"
        confirmLabel={t("console.launch")}
        onCancel={() => setConfirmRunOpen(false)}
        onConfirm={() => {
          setConfirmRunOpen(false);
          void handleRun();
        }}
      />

      <ConfirmDialog
        open={confirmStopOpen}
        title={t("console.confirm_stop_title")}
        copy={t("console.confirm_stop_copy", {
          target: activeTask?.target ?? t("boundary.unknown"),
          task: activeTask ? formatTaskTitle(activeTask.command, activeTask.target) : "None",
        })}
        tone="danger"
        confirmLabel={t("console.stop")}
        onCancel={() => setConfirmStopOpen(false)}
        onConfirm={() => {
          setConfirmStopOpen(false);
          void handleStop();
        }}
      />

      <div className="split-grid inner-grid">
        <article className="card inset-card">
          <h4>{t("console.task_log")}</h4>
          <div className="list list-scroll">
            {tasksQuery.data?.slice(0, 8).map((task) => (
              <button
                key={task.task_id}
                type="button"
                className={`list-item list-button ${activeTask?.task_id === task.task_id ? "selected-item" : ""}`}
                onClick={() => {
                  onTaskCreated(task);
                  onFocusTarget(task.target);
                }}
              >
                <strong>{formatTaskTitle(task.command, task.target)}</strong>
                <span>{formatTaskStatus(task.status)}</span>
                <span className="muted-inline">{task.latest_phase ? formatPhaseLabel(task.latest_phase) : task.created_at}</span>
                {task.summary?.constraints && Object.keys(task.summary.constraints).length > 0 && (
                  <span className="muted-inline">{formatConstraintSummary(task.summary.constraints)}</span>
                )}
              </button>
            ))}
            {!tasksQuery.data?.length && <div className="empty-state">{t("console.no_tasks")}</div>}
          </div>
        </article>

        <article className="card inset-card">
          <h4>{t("console.live_events")}</h4>
          <div className="terminal terminal-scroll">
            {activeTask ? (
              <>
                <div className="terminal-line">{t("console.task_id", { id: activeTask.task_id })}</div>
                <div className="terminal-line">{t("console.command_line", { command: formatTaskCommand(activeTask.command), raw: activeTask.command })}</div>
                <div className="terminal-line">{t("console.target_line", { target: activeTask.target })}</div>
                <div className="terminal-line dim">{t("console.phase_line", { phase: formatPhaseLabel(activeTask.latest_phase) })}</div>
                {activeTask.summary?.constraints && Object.keys(activeTask.summary.constraints).length > 0 && (
                  <div className="terminal-line dim">{t("console.boundary_line", { boundary: formatConstraintSummary(activeTask.summary.constraints) })}</div>
                )}
              </>
            ) : (
              <div className="terminal-line dim">{t("console.no_running")}</div>
            )}

            {latestEvents.map((item) => (
              <div key={`${item.timestamp}-${item.event}`} className="terminal-line terminal-row">
                <span className={`terminal-event tone-${eventTone(item.event)}`}>{formatEventLabel(item.event)}</span>
                <span className="terminal-time">{new Date(item.timestamp).toLocaleTimeString()}</span>
                <span>{renderEventText(item)}</span>
              </div>
            ))}
          </div>
        </article>
      </div>
    </section>
  );
}
