import { useEffect, useMemo, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { rollbackTarget } from "../api/web";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { SectionCard } from "../components/SectionCard";
import { useT, type TFunction } from "../i18n";
import { useTargetDiffQuery, useTargetSnapshotsQuery, useTargetsQuery, useTasksQuery } from "../hooks/queries";
import { formatPhaseLabel, formatResumeStrategy, formatTaskCommand, formatTaskStatus, formatTaskTitle } from "../utils/taskLabels";

interface HistoryPageProps {
  selectedTarget: string | null;
  onSelectTarget: (target: string | null) => void;
  onOpenHome: () => void;
  onOpenReports: (target: string) => void;
  onOpenTarget: (target: string) => void;
}

function formatTime(value: string | undefined, t: TFunction): string {
  if (!value) return t("reports.unknown_date");
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function diffConclusion(diff: {
  added_findings: string[];
  updated_findings: string[];
  added_steps: string[];
  added_recon_assets: string[];
}, t: TFunction): string {
  const total = diff.added_findings.length + diff.updated_findings.length + diff.added_steps.length + diff.added_recon_assets.length;
  if (diff.added_findings.length || diff.updated_findings.length) return t("history.diff_risk_changed");
  if (total > 0) return t("history.diff_new_context");
  return t("history.diff_no_delta");
}

export function HistoryPage({ selectedTarget, onSelectTarget, onOpenHome, onOpenReports, onOpenTarget }: HistoryPageProps) {
  const { t } = useT();
  const queryClient = useQueryClient();
  const targetsQuery = useTargetsQuery();
  const tasksQuery = useTasksQuery();
  const [localTarget, setLocalTarget] = useState("");
  const [fromSnapshotId, setFromSnapshotId] = useState<string | null>(null);
  const [toSnapshotId, setToSnapshotId] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busySnapshot, setBusySnapshot] = useState<string | null>(null);
  const [pendingRollbackId, setPendingRollbackId] = useState<string | null>(null);

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
  const snapshotsQuery = useTargetSnapshotsQuery(targetValue);
  const diffQuery = useTargetDiffQuery(targetValue, fromSnapshotId, toSnapshotId);

  useEffect(() => {
    const snapshots = snapshotsQuery.data ?? [];
    if (snapshots.length >= 2) {
      setToSnapshotId((current) => current ?? snapshots[0].snapshot_id);
      setFromSnapshotId((current) => current ?? snapshots[1].snapshot_id);
    } else if (snapshots.length === 1) {
      setToSnapshotId(snapshots[0].snapshot_id);
      setFromSnapshotId(snapshots[0].snapshot_id);
    } else {
      setFromSnapshotId(null);
      setToSnapshotId(null);
    }
  }, [snapshotsQuery.data]);

  const targetTasks = useMemo(() => {
    const tasks = tasksQuery.data ?? [];
    return targetValue ? tasks.filter((task) => task.target === targetValue) : tasks;
  }, [tasksQuery.data, targetValue]);

  async function handleRollback(snapshotId: string) {
    if (!targetValue) return;
    try {
      setBusySnapshot(snapshotId);
      setError(null);
      setMessage(null);
      await rollbackTarget(targetValue, snapshotId);
      setMessage(t("history.restored", { target: targetValue, snapshot: snapshotId }));
      await Promise.all([
        snapshotsQuery.refetch(),
        targetsQuery.refetch(),
        queryClient.invalidateQueries({ queryKey: ["target", targetValue] }),
        queryClient.invalidateQueries({ queryKey: ["target-preview", targetValue] }),
        queryClient.invalidateQueries({ queryKey: ["target-diff", targetValue] }),
      ]);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("error.snapshot_restore_failed"));
    } finally {
      setBusySnapshot(null);
    }
  }

  return (
    <section className="history-page">
      <SectionCard
        title={t("history.title")}
        aside={<span className="status-badge">{t("history.tasks_count", { count: String(targetTasks.length) })}</span>}
      >
        <label className="field">
          <span>{t("risk.target")}</span>
          <select
            value={targetValue ?? ""}
            onChange={(event) => {
              const value = event.target.value || null;
              setLocalTarget(value ?? "");
              onSelectTarget(value);
              setMessage(null);
              setError(null);
            }}
          >
            <option value="">{t("boundary.all_targets")}</option>
            {targetsQuery.data?.map((target) => (
              <option key={target.target} value={target.target}>
                {target.target}
              </option>
            ))}
          </select>
        </label>

        <div className="history-summary-grid">
          <article className="stat">
            <span className="stat-label">{t("history.tasks")}</span>
            <strong>{targetTasks.length}</strong>
          </article>
          <article className="stat">
            <span className="stat-label">{t("history.targets")}</span>
            <strong>{targetsQuery.data?.length ?? 0}</strong>
          </article>
          <article className="stat">
            <span className="stat-label">{t("history.snapshots")}</span>
            <strong>{snapshotsQuery.data?.length ?? 0}</strong>
          </article>
        </div>

        {message && <div className="success-box">{message}</div>}
        {error && <div className="error-box">{error}</div>}
      </SectionCard>

      <div className="history-grid">
        <SectionCard title={t("history.tasks")}>
          <div className="list list-scroll history-list">
            {targetTasks.slice(0, 18).map((task) => (
              <article key={task.task_id} className="list-item history-task-item">
                <strong>{formatTaskTitle(task.command, task.target)}</strong>
                <span>{formatTaskStatus(task.status)}</span>
                <span className="muted-inline">{formatPhaseLabel(task.latest_phase)}</span>
                <span className="muted-inline">{formatTime(task.created_at, t)}</span>
                <div className="button-row compact-row">
                  <button className="secondary-btn" type="button" onClick={() => onOpenTarget(task.target)}>
                    {t("history.open_results")}
                  </button>
                  <button className="secondary-btn" type="button" onClick={() => onOpenReports(task.target)}>
                    {t("history.open_reports")}
                  </button>
                </div>
              </article>
            ))}
            {!targetTasks.length && (
              <div className="empty-state history-empty-state">
                <strong>{t("history.no_task_history")}</strong>
                <button className="secondary-btn" onClick={onOpenHome} type="button">
                  {t("history.new_scan")}
                </button>
              </div>
            )}
          </div>
        </SectionCard>

        <SectionCard title={t("history.targets")}>
          <div className="list list-scroll history-list">
            {targetsQuery.data?.slice(0, 18).map((target) => (
              <article key={target.target} className={`list-item ${targetValue === target.target ? "selected-item" : ""}`}>
                <strong>{target.target}</strong>
                <span>{t("history.verified_pending", { verified: String(target.verified_count), pending: String(target.pending_count) })}</span>
                <span className="muted-inline">{formatResumeStrategy(target.resume_strategy)}</span>
                <div className="button-row compact-row">
                  <button className="secondary-btn" type="button" onClick={() => { onSelectTarget(target.target); onOpenTarget(target.target); }}>
                    {t("history.open_results")}
                  </button>
                  <button className="secondary-btn" type="button" onClick={() => onOpenReports(target.target)}>
                    {t("history.open_reports")}
                  </button>
                </div>
              </article>
            ))}
            {!targetsQuery.data?.length && (
              <div className="empty-state history-empty-state">
                <strong>{t("history.no_target_state")}</strong>
                <button className="secondary-btn" onClick={onOpenHome} type="button">
                  {t("history.new_scan")}
                </button>
              </div>
            )}
          </div>
        </SectionCard>
      </div>

      <div className="history-grid">
        <SectionCard title={t("history.snapshots")}>
          <div className="list list-scroll history-list">
            {snapshotsQuery.data?.map((snapshot) => (
              <div key={snapshot.snapshot_id} className="list-item">
                <strong>{snapshot.snapshot_id}</strong>
                <span>{formatTaskCommand(snapshot.last_command)}</span>
                <span className="muted-inline">{formatTime(snapshot.last_saved_at, t)}</span>
                <span className="muted-inline">{t("history.snapshot_detail", { verified: String(snapshot.verified_findings), pending: String(snapshot.pending_findings) })}</span>
                <div className="button-row compact-row">
                  <button
                    className="secondary-btn"
                    disabled={busySnapshot === snapshot.snapshot_id}
                    onClick={() => setPendingRollbackId(snapshot.snapshot_id)}
                    type="button"
                  >
                    {busySnapshot === snapshot.snapshot_id ? t("history.restoring") : t("history.restore")}
                  </button>
                </div>
              </div>
            ))}
            {!snapshotsQuery.data?.length && (
              <div className="empty-state">{targetValue ? t("history.no_snapshots") : t("history.choose_target_snapshots")}</div>
            )}
          </div>
        </SectionCard>

        <SectionCard title={t("history.diff")}>
          <div className="form-grid compact-form">
            <label className="field">
              <span>{t("history.from")}</span>
              <select value={fromSnapshotId ?? ""} onChange={(event) => setFromSnapshotId(event.target.value || null)}>
                <option value="">{t("history.select")}</option>
                {snapshotsQuery.data?.map((snapshot) => (
                  <option key={`from-${snapshot.snapshot_id}`} value={snapshot.snapshot_id}>
                    {snapshot.snapshot_id}
                  </option>
                ))}
              </select>
            </label>
            <label className="field">
              <span>{t("history.to")}</span>
              <select value={toSnapshotId ?? ""} onChange={(event) => setToSnapshotId(event.target.value || null)}>
                <option value="">{t("history.current")}</option>
                {snapshotsQuery.data?.map((snapshot) => (
                  <option key={`to-${snapshot.snapshot_id}`} value={snapshot.snapshot_id}>
                    {snapshot.snapshot_id}
                  </option>
                ))}
              </select>
            </label>
          </div>

          {diffQuery.data ? (
            <div className="list dense-list">
              <div className="history-diff-summary">
                <strong>{diffConclusion(diffQuery.data, t)}</strong>
                <div>
                  <span>{t("risk.findings")} {diffQuery.data.added_findings.length}</span>
                  <span>{t("history.updated_findings")} {diffQuery.data.updated_findings.length}</span>
                  <span>{t("history.added_steps")} {diffQuery.data.added_steps.length}</span>
                  <span>{t("history.added_assets")} {diffQuery.data.added_recon_assets.length}</span>
                </div>
              </div>
              <div className="list-item">
                <strong>{t("history.added_findings")}</strong>
                {diffQuery.data.added_findings.length ? diffQuery.data.added_findings.map((item) => <span key={item}>{item}</span>) : <span className="muted-inline">{t("history.none")}</span>}
              </div>
              <div className="list-item">
                <strong>{t("history.updated_findings")}</strong>
                {diffQuery.data.updated_findings.length ? diffQuery.data.updated_findings.map((item) => <span key={item}>{item}</span>) : <span className="muted-inline">{t("history.none")}</span>}
              </div>
              <div className="list-item">
                <strong>{t("history.added_steps")}</strong>
                {diffQuery.data.added_steps.length ? diffQuery.data.added_steps.map((item) => <span key={item}>{item}</span>) : <span className="muted-inline">{t("history.none")}</span>}
              </div>
              <div className="list-item">
                <strong>{t("history.added_assets")}</strong>
                {diffQuery.data.added_recon_assets.length ? diffQuery.data.added_recon_assets.map((item) => <span key={item}>{item}</span>) : <span className="muted-inline">{t("history.none")}</span>}
              </div>
            </div>
          ) : (
            <div className="empty-state">{diffQuery.isLoading ? t("history.loading_diff") : t("history.pick_snapshots")}</div>
          )}
        </SectionCard>
      </div>

      <ConfirmDialog
        open={Boolean(pendingRollbackId)}
        title={t("history.confirm_restore_title")}
        copy={t("history.confirm_restore_copy")}
        tone="danger"
        confirmLabel={t("history.restore")}
        onCancel={() => setPendingRollbackId(null)}
        onConfirm={() => {
          const snapshotId = pendingRollbackId;
          setPendingRollbackId(null);
          if (snapshotId) void handleRollback(snapshotId);
        }}
      />
    </section>
  );
}
