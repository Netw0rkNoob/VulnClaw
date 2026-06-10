import { useEffect, useMemo, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { generateTargetReport } from "../api/web";
import { SectionCard } from "../components/SectionCard";
import { useTargetPreviewQuery, useTargetQuery, useTargetsQuery } from "../hooks/queries";
import { useT, type TFunction } from "../i18n";
import { loadUiPreferences, subscribeUiPreferences, type UiPreferences } from "../utils/preferences";
import {
  countConstraintViolations,
  formatConstraintSummary,
  formatFindingStatus,
  formatPhaseLabel,
  formatResumeStrategy,
  formatSeverityLabel,
} from "../utils/taskLabels";

interface RiskResultsPageProps {
  selectedTarget: string | null;
  onSelectTarget: (target: string | null) => void;
  onOpenHome: () => void;
  onOpenReports: (path?: string) => void;
  onOpenBoundary: () => void;
}

interface FindingCard {
  id: string;
  title: string;
  severity: string;
  status: string;
  evidence: string;
  impact: string;
  recommendation: string;
  type: string;
}

interface ActionCard {
  title: string;
  copy: string;
  tone: "primary" | "warn" | "safe";
}

interface GeneratedReportState {
  format: UiPreferences["reportFormat"];
  path: string;
}

function asText(value: unknown, fallback = ""): string {
  return typeof value === "string" && value.trim() ? value : fallback;
}

function normalizeSeverity(value: unknown): string {
  const text = asText(value, "Info");
  const lower = text.toLowerCase();
  if (lower.includes("critical")) return "Critical";
  if (lower.includes("high")) return "High";
  if (lower.includes("medium")) return "Medium";
  if (lower.includes("low")) return "Low";
  return text;
}

function severityTone(severity: string): "danger" | "warn" | "ok" | "info" {
  const normalized = severity.toLowerCase();
  if (normalized.includes("critical") || normalized.includes("high")) return "danger";
  if (normalized.includes("medium") || normalized.includes("warn")) return "warn";
  if (normalized.includes("low")) return "ok";
  return "info";
}

function extractEvidence(raw: Record<string, unknown>, t: TFunction): string {
  const evidence = raw.evidence;
  if (typeof evidence === "string" && evidence.trim()) return evidence;
  if (Array.isArray(evidence) && evidence.length) return evidence.map(String).slice(0, 3).join(" / ");
  return asText(raw.description, t("risk.not_summarized"));
}

function extractFindingCards(rawFindings: unknown, t: TFunction): FindingCard[] {
  if (!Array.isArray(rawFindings)) return [];
  return rawFindings.slice(0, 24).map((item, index) => {
    const raw = item && typeof item === "object" ? item as Record<string, unknown> : {};
    const title = asText(raw.title, t("risk.default_finding", { index: String(index + 1) }));
    return {
      id: asText(raw.finding_id, `${title}-${index}`),
      title,
      severity: normalizeSeverity(raw.severity),
      status: asText(raw.verification_status, asText(raw.lifecycle_status, raw.verified ? "verified" : "pending")),
      evidence: extractEvidence(raw, t),
      impact: asText(raw.impact, asText(raw.risk, t("risk.impact_needs_review"))),
      recommendation: asText(raw.recommendation, asText(raw.remediation, t("risk.validate_patch"))),
      type: asText(raw.vuln_type, asText(raw.category, t("risk.uncategorized"))),
    };
  });
}

function resultConclusion(verified: number, pending: number, manualReview: number, t: TFunction): string {
  if (verified > 0) return t("risk.conclusion_verified", { count: String(verified) });
  if (manualReview > 0) return t("risk.conclusion_manual", { count: String(manualReview) });
  if (pending > 0) return t("risk.conclusion_pending", { count: String(pending) });
  return t("risk.conclusion_none");
}

function actionCardFromSignal(signal: string, t: TFunction): ActionCard {
  const normalized = signal.toLowerCase();
  if (normalized.includes("report")) {
    return { title: t("risk.action_generate_report"), copy: t("risk.action_generate_report_copy"), tone: "primary" };
  }
  if (normalized.includes("boundary") || normalized.includes("constraint")) {
    return { title: t("risk.action_review_scope"), copy: t("risk.action_review_scope_copy"), tone: "safe" };
  }
  if (normalized.includes("verify") || normalized.includes("manual")) {
    return { title: t("risk.action_manual_review"), copy: t("risk.action_manual_review_copy"), tone: "warn" };
  }
  if (normalized.includes("scan") || normalized.includes("recon")) {
    return { title: t("risk.action_continue_scan"), copy: t("risk.action_continue_scan_copy"), tone: "primary" };
  }
  return { title: signal, copy: t("risk.action_default_copy"), tone: "primary" };
}

function buildActionCards(actions: string[], pending: number, manualReview: number, t: TFunction): ActionCard[] {
  const cards = actions.slice(0, 6).map((s) => actionCardFromSignal(s, t));
  if (!cards.length && (pending > 0 || manualReview > 0)) {
    cards.push({ title: t("risk.action_review_pending"), copy: t("risk.action_review_pending_copy"), tone: "warn" });
  }
  if (!cards.length) {
    cards.push({ title: t("risk.action_generate_default"), copy: t("risk.action_generate_default_copy"), tone: "safe" });
  }
  return cards;
}

export function RiskResultsPage({ selectedTarget, onSelectTarget, onOpenHome, onOpenReports, onOpenBoundary }: RiskResultsPageProps) {
  const { t } = useT();
  const queryClient = useQueryClient();
  const targetsQuery = useTargetsQuery();
  const [localTarget, setLocalTarget] = useState("");
  const [generatedReport, setGeneratedReport] = useState<GeneratedReportState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [generating, setGenerating] = useState(false);
  const [reportFormat, setReportFormat] = useState<UiPreferences["reportFormat"]>(() => loadUiPreferences().reportFormat);
  const [showRaw, setShowRaw] = useState(false);

  useEffect(() => subscribeUiPreferences((preferences) => {
    setReportFormat(preferences.reportFormat);
  }), []);

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
  const previewQuery = useTargetPreviewQuery(targetValue);
  const target = targetQuery.data;
  const preview = previewQuery.data;

  const findings = useMemo(() => extractFindingCards(target?.raw?.findings, t), [target, t]);
  const criticalOrHigh = findings.filter((item) => severityTone(item.severity) === "danger").length;
  const uniqueTypes = Array.from(new Set(findings.map((item) => item.type).filter(Boolean))).slice(0, 4);
  const portSignals = Array.from(new Set(findings.map((item) => {
    const match = item.evidence.match(/\b(?:port|:)\s*(\d{2,5})\b/i);
    return match?.[1];
  }).filter((item): item is string => Boolean(item)))).slice(0, 5);
  const boundaryBlocks = countConstraintViolations(
    target?.constraint_violation_events,
    target?.constraint_violations,
  );
  const nextActions = preview?.next_actions ?? [];
  const actionCards = useMemo(
    () => buildActionCards(nextActions, target?.pending_count ?? 0, target?.manual_review_count ?? 0, t),
    [nextActions, target?.pending_count, target?.manual_review_count, t],
  );

  async function handleGenerateReport() {
    if (!targetValue) return;
    try {
      setGenerating(true);
      setError(null);
      const result = await generateTargetReport(targetValue, reportFormat);
      setGeneratedReport({ format: reportFormat, path: result.path });
      await queryClient.invalidateQueries({ queryKey: ["reports"] });
    } catch (err) {
      setError(err instanceof Error ? err.message : t("error.report_failed"));
    } finally {
      setGenerating(false);
    }
  }

  return (
    <section className="risk-page">
      <SectionCard
        title={t("risk.findings")}
        aside={<span className="status-badge">{target ? formatPhaseLabel(target.phase) : t("risk.waiting")}</span>}
      >
        <label className="field">
          <span>{t("risk.target")}</span>
          <select
            value={targetValue ?? ""}
            onChange={(event) => {
              const value = event.target.value || null;
              setLocalTarget(value ?? "");
              onSelectTarget(value);
              setGeneratedReport(null);
              setError(null);
            }}
          >
            <option value="">{t("risk.select_target")}</option>
            {targetsQuery.data?.map((item) => (
              <option key={item.target} value={item.target}>
                {item.target}
              </option>
            ))}
          </select>
        </label>

        {target ? (
          <>
            <div className="goby-scan-summary">
              <button type="button" className="text-btn inline-text-btn" onClick={onOpenHome}>{t("risk.back")}</button>
              <strong>{t("risk.scan")}</strong>
            </div>

            <div className="stats-grid goby-metric-grid">
              <article className="stat goby-metric-card">
                <span className="stat-label">{t("risk.asset")}</span>
                <strong>{Math.max(1, targetsQuery.data?.length ?? 0)}</strong>
              </article>
              <article className="stat goby-metric-card">
                <span className="stat-label">{t("risk.active_ip")}</span>
                <strong>{targetValue ? 1 : 0}</strong>
              </article>
              <article className="stat goby-metric-card">
                <span className="stat-label">{t("risk.port")}</span>
                <strong>{portSignals.length || target.pending_count}</strong>
              </article>
              <article className="stat goby-metric-card">
                <span className="stat-label">{t("risk.vulnerability")}</span>
                <strong>{target.verified_count + target.pending_count}</strong>
              </article>
            </div>

            <div className="goby-intel-grid">
              <article className="goby-intel-card">
                <header><strong>{t("risk.hardware")}</strong><span>✓</span></header>
                <div className="goby-donut"><span>{Math.max(1, targetsQuery.data?.length ?? 0)}</span></div>
                <p>{targetValue ?? t("risk.no_target_selected")} 100%</p>
              </article>
              <article className="goby-intel-card">
                <header><strong>{t("risk.software")}</strong><span>✓</span></header>
                <div className="goby-donut goby-donut-soft"><span>{uniqueTypes.length || findings.length}</span></div>
                {(uniqueTypes.length ? uniqueTypes : [t("phase.recon"), t("phase.scan"), t("phase.verify")]).slice(0, 3).map((item) => <p key={item}>{item}</p>)}
              </article>
              <article className="goby-intel-card">
                <header><strong>{t("risk.port")}</strong><span>✓</span></header>
                {(portSignals.length ? portSignals : ["443", "80", "22"]).slice(0, 5).map((port) => (
                  <div key={port} className="goby-bar-row"><span>{port}</span><i /></div>
                ))}
              </article>
              <article className="goby-intel-card goby-intel-danger">
                <header><strong>{t("risk.vulnerability")}</strong><span>✓</span></header>
                {findings.length ? findings.slice(0, 4).map((finding) => (
                  <p key={finding.id}>{finding.title}</p>
                )) : <p>{resultConclusion(target.verified_count, target.pending_count, target.manual_review_count, t)}</p>}
              </article>
            </div>

            <div className="button-row">
              <button type="button" className="primary-btn" disabled={generating} onClick={handleGenerateReport}>
                {generating ? t("risk.generating") : t("risk.generate_report")}
              </button>
              <button type="button" className="secondary-btn" onClick={() => onOpenReports()}>
                {t("risk.open_reports")}
              </button>
              <button type="button" className="secondary-btn" onClick={onOpenBoundary}>
                {t("risk.open_scope")}
              </button>
            </div>

            {generatedReport && (
              <div className="report-delivery-card risk-delivery-card">
                <div>
                  <span>{t("risk.status")}</span>
                  <strong>{t("risk.report_generated")}</strong>
                </div>
                <div>
                  <span>{t("risk.format")}</span>
                  <strong>{generatedReport.format === "html" ? "HTML" : "Markdown"}</strong>
                </div>
                <div>
                  <span>{t("risk.path")}</span>
                  <strong>{generatedReport.path}</strong>
                </div>
                <div className="risk-delivery-action">
                  <button className="primary-btn" onClick={() => onOpenReports(generatedReport.path)} type="button">
                    {t("risk.open_report")}
                  </button>
                </div>
              </div>
            )}
            {error && <div className="error-box">{error}</div>}
          </>
        ) : (
          <div className="goby-empty-results">
            <div className="goby-scan-summary">
              <button type="button" className="text-btn inline-text-btn" onClick={onOpenHome}>{t("risk.back")}</button>
              <strong>{t("risk.scan")}</strong>
            </div>
            <div className="stats-grid goby-metric-grid">
              {[t("risk.asset"), t("risk.active_ip"), t("risk.port"), t("risk.vulnerability")].map((label) => (
                <article key={label} className="stat goby-metric-card">
                  <span className="stat-label">{label}</span>
                  <strong>0</strong>
                </article>
              ))}
            </div>
            <div className="goby-intel-grid">
              {[t("risk.hardware"), t("risk.hardware_vendor"), t("risk.software"), t("risk.software_vendor")].map((label) => (
                <article key={label} className="goby-intel-card">
                  <header><strong>{label}</strong><span>○</span></header>
                  <div className="goby-placeholder-lines">
                    <i />
                    <i />
                    <i />
                  </div>
                </article>
              ))}
            </div>
            <div className="empty-state risk-empty-state">
              <strong>{targetQuery.isLoading ? t("risk.loading_target") : t("risk.no_target_selected")}</strong>
              {!targetQuery.isLoading && (
                <button className="secondary-btn" type="button" onClick={onOpenHome}>
                  {t("risk.new_scan")}
                </button>
              )}
            </div>
          </div>
        )}
      </SectionCard>

      {target && (
        <div className="split-grid">
          <SectionCard title={t("risk.findings")}>
            <div className="risk-list">
              {findings.length ? (
                findings.map((finding) => (
                  <article key={finding.id} className="risk-item">
                    <div className="risk-item-head">
                      <div>
                        <span className={`severity-badge severity-${severityTone(finding.severity)}`}>{formatSeverityLabel(finding.severity)}</span>
                        <h4>{finding.title}</h4>
                      </div>
                      <span className="status-badge">{formatFindingStatus(finding.status)}</span>
                    </div>
                    <div className="risk-detail-grid">
                      <div>
                        <strong>{t("risk.type")}</strong>
                        <span>{finding.type}</span>
                      </div>
                      <div>
                        <strong>{t("risk.evidence")}</strong>
                        <span>{finding.evidence}</span>
                      </div>
                      <div>
                        <strong>{t("risk.impact")}</strong>
                        <span>{finding.impact}</span>
                      </div>
                      <div>
                        <strong>{t("risk.fix")}</strong>
                        <span>{finding.recommendation}</span>
                      </div>
                    </div>
                  </article>
                ))
              ) : (
                <div className="empty-state">{t("risk.no_findings")}</div>
              )}
            </div>
          </SectionCard>

          <SectionCard title={t("risk.next")}>
            <div className="list dense-list">
              <div className="list-item">
                <strong>{t("risk.resume_plan")}</strong>
                <span>{formatResumeStrategy(target.resume_strategy || preview?.resume_strategy)}</span>
                <span className="muted-inline">{target.resume_reason || preview?.resume_reason || t("risk.no_reason")}</span>
              </div>
              <div className="list-item">
                <strong>{t("risk.recommended_actions")}</strong>
                <div className="risk-action-grid">
                  {actionCards.map((item) => (
                    <article key={`${item.title}-${item.copy}`} className={`risk-action-card risk-action-card-${item.tone}`}>
                      <strong>{item.title}</strong>
                      <span>{item.copy}</span>
                    </article>
                  ))}
                </div>
              </div>
              <div className="list-item">
                <strong>{t("risk.priority_targets")}</strong>
                {preview?.priority_targets.length ? (
                  preview.priority_targets.slice(0, 6).map((item) => <span key={item}>{item}</span>)
                ) : (
                  <span className="muted-inline">{t("risk.no_priority")}</span>
                )}
              </div>
              <div className="list-item">
                <strong>{t("risk.scope")}</strong>
                <span className="muted-inline">{formatConstraintSummary(target.constraints)}</span>
              </div>
            </div>
          </SectionCard>
        </div>
      )}

      {target && (
        <SectionCard
          title={t("risk.raw_data")}
          aside={
            <button type="button" className="text-btn inline-text-btn" onClick={() => setShowRaw((value) => !value)}>
              {showRaw ? t("risk.collapse") : t("risk.expand")}
            </button>
          }
        >
          {showRaw ? (
            <div className="report-preview">
              <pre>{JSON.stringify(target.raw, null, 2)}</pre>
            </div>
          ) : (
            <div className="empty-state">{t("risk.raw_collapsed")}</div>
          )}
        </SectionCard>
      )}
    </section>
  );
}
