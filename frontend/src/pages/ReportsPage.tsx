import { useEffect, useState } from "react";
import { generateTargetReport, getReportDownloadUrl } from "../api/web";
import { ReportPreview, ReportPreviewDialog } from "../components/ReportPreviewDialog";
import { SectionCard } from "../components/SectionCard";
import { useReportContentQuery, useReportsQuery, useTargetsQuery } from "../hooks/queries";
import { useT, type TFunction } from "../i18n";
import type { ReportListItem } from "../types/api";
import { loadUiPreferences, subscribeUiPreferences } from "../utils/preferences";

interface ReportsPageProps {
  selectedTarget: string | null;
  focus?: {
    target: string | null;
    path?: string;
    openPreview?: boolean;
  } | null;
}

export function ReportsPage({ selectedTarget, focus }: ReportsPageProps) {
  const { t } = useT();
  const reportsQuery = useReportsQuery();
  const targetsQuery = useTargetsQuery();
  const [selectedPath, setSelectedPath] = useState<string | null>(null);
  const [previewOpen, setPreviewOpen] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [generating, setGenerating] = useState(false);
  const [copyStatus, setCopyStatus] = useState<string | null>(null);
  const [search, setSearch] = useState(selectedTarget ?? "");
  const [reportTarget, setReportTarget] = useState(selectedTarget ?? "");
  const [generateFormat, setGenerateFormat] = useState<"markdown" | "html">(() => loadUiPreferences().reportFormat);
  const [kindFilter, setKindFilter] = useState<"all" | "markdown" | "html">("all");
  const [dateFilter, setDateFilter] = useState<"all" | "today" | "week">("all");

  useEffect(() => {
    if (!selectedPath && reportsQuery.data?.[0]?.path) setSelectedPath(reportsQuery.data[0].path);
  }, [selectedPath, reportsQuery.data]);

  useEffect(() => subscribeUiPreferences((preferences) => setGenerateFormat(preferences.reportFormat)), []);

  useEffect(() => {
    if (selectedTarget) {
      setSearch(selectedTarget);
      setReportTarget(selectedTarget);
    }
  }, [selectedTarget]);

  useEffect(() => {
    if (!focus) return;
    if (focus.target) {
      setSearch(focus.target);
      setReportTarget(focus.target);
    }
    if (focus.path) setSelectedPath(focus.path);
    if (focus.openPreview) setPreviewOpen(true);
  }, [focus]);

  useEffect(() => {
    if (!reportTarget && targetsQuery.data?.[0]?.target) {
      setReportTarget(targetsQuery.data[0].target);
    }
  }, [reportTarget, targetsQuery.data]);

  const reports = reportsQuery.data ?? [];
  const filteredReports = reports.filter((report) => reportMatchesFilters(report, search, kindFilter, dateFilter));
  const selectedReport = filteredReports.find((report) => report.path === selectedPath) ?? filteredReports[0] ?? null;
  const previewPath = selectedReport?.path ?? null;
  const contentQuery = useReportContentQuery(previewPath);
  const markdownCount = reports.filter((report) => report.kind === "markdown").length;
  const htmlCount = reports.filter((report) => report.kind === "html").length;
  const totalSize = reports.reduce((sum, report) => sum + (report.size_bytes ?? 0), 0);
  const canGenerate = Boolean(reportTarget.trim()) && !generating;
  const previewContent = selectedReport ? contentQuery.data?.content : undefined;
  const previewKind = selectedReport ? contentQuery.data?.kind : undefined;
  const previewLoading = Boolean(selectedReport) && contentQuery.isLoading;

  async function handleGenerate() {
    const target = reportTarget.trim();
    if (!target) {
      setError(t("error.select_target_first"));
      return;
    }
    try {
      setGenerating(true);
      setError(null);
      const result = await generateTargetReport(target, generateFormat);
      setStatus(result.path);
      setSearch(target);
      await reportsQuery.refetch();
      setSelectedPath(result.path);
      setPreviewOpen(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("error.report_failed"));
    } finally {
      setGenerating(false);
    }
  }

  async function handleCopyPath() {
    if (!selectedReport?.path) return;
    try {
      await navigator.clipboard.writeText(selectedReport.path);
      setCopyStatus(t("reports.path_copied"));
    } catch {
      setCopyStatus(t("reports.clipboard_unavailable"));
    }
  }

  function handleDownload() {
    const content = previewContent;
    if (!content || !selectedReport) return;
    const mime = previewKind === "html" ? "text/html;charset=utf-8" : "text/markdown;charset=utf-8";
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = selectedReport.name || `vulnclaw-report.${previewKind === "html" ? "html" : "md"}`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
    setCopyStatus(t("reports.download_started"));
  }

  function handleOpenReportFile() {
    if (!selectedReport?.path) return;
    window.open(getReportDownloadUrl(selectedReport.path), "_blank", "noopener,noreferrer");
  }

  function resetReportFilters() {
    setSearch("");
    setKindFilter("all");
    setDateFilter("all");
    setSelectedPath(reports[0]?.path ?? null);
  }

  return (
    <section className="reports-page">
      <SectionCard
        title={t("reports.title")}
        aside={<span className="status-badge">{t("reports.files", { count: String(reports.length) })}</span>}
      >
        <div className="report-hero">
          <div>
            <span className="pill">{t("reports.selected")}</span>
            <h3>{selectedReport?.name ?? t("reports.no_report_selected")}</h3>
            <p>{reportStatusCopy(selectedReport, t)}</p>
          </div>
          <div className="report-actions">
            <label className="field report-target-field">
              <span>{t("reports.target")}</span>
              <input
                list="report-targets"
                value={reportTarget}
                onChange={(event) => setReportTarget(event.target.value)}
                placeholder={t("reports.select_or_enter_target")}
              />
              <datalist id="report-targets">
                {targetsQuery.data?.map((target) => (
                  <option key={target.target} value={target.target} />
                ))}
              </datalist>
            </label>
            <label className="field report-format-field">
              <span>{t("reports.format")}</span>
              <select value={generateFormat} onChange={(event) => setGenerateFormat(event.target.value as "markdown" | "html")}>
                <option value="markdown">{t("reports.markdown")}</option>
                <option value="html">{t("reports.html")}</option>
              </select>
            </label>
            <button className="primary-btn" disabled={!canGenerate} onClick={handleGenerate} type="button">
              {generating ? t("reports.generating") : t("reports.generate")}
            </button>
            <button className="secondary-btn" disabled={!selectedReport} onClick={() => setPreviewOpen(true)} type="button">
              {t("reports.preview")}
            </button>
            <button className="secondary-btn" disabled={!selectedReport?.path} onClick={handleOpenReportFile} type="button">
              {t("reports.open_file")}
            </button>
          </div>
        </div>

        {status && <div className="success-box">{t("reports.generated", { path: status })}</div>}
        {copyStatus && <div className="success-box">{copyStatus}</div>}
        {error && <div className="error-box">{error}</div>}
      </SectionCard>

      <div className="report-center-grid">
        <SectionCard
          title={t("reports.file_list")}
          aside={<span className="status-badge">{filteredReports.length} / {reports.length}</span>}
        >
          <div className="report-filter-grid">
            <label className="field">
              <span>{t("reports.search")}</span>
              <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder={t("reports.search_placeholder")} />
            </label>
            <label className="field">
              <span>{t("reports.format_filter")}</span>
              <select value={kindFilter} onChange={(event) => setKindFilter(event.target.value as "all" | "markdown" | "html")}>
                <option value="all">{t("reports.all")}</option>
                <option value="markdown">{t("reports.markdown")}</option>
                <option value="html">{t("reports.html")}</option>
              </select>
            </label>
            <label className="field">
              <span>{t("reports.time_filter")}</span>
              <select value={dateFilter} onChange={(event) => setDateFilter(event.target.value as "all" | "today" | "week")}>
                <option value="all">{t("reports.all_time")}</option>
                <option value="today">{t("reports.today")}</option>
                <option value="week">{t("reports.last_7_days")}</option>
              </select>
            </label>
          </div>
          <div className="list list-scroll report-file-list">
            {filteredReports.slice(0, 24).map((report) => (
              <button
                key={report.path}
                type="button"
                className={`list-item list-button report-file-item ${selectedReport?.path === report.path ? "selected-item" : ""}`}
                onClick={() => setSelectedPath(report.path)}
              >
                <strong>{report.name}</strong>
                <span>{report.kind} - {formatSize(report.size_bytes ?? 0, t)}</span>
                <span className="muted-inline">{formatDate(report.modified_at, t)}</span>
                <span className="muted-inline">{report.path}</span>
              </button>
            ))}
            {!reports.length && (
              <div className="empty-state report-empty-state">
                <strong>{t("reports.no_reports")}</strong>
                <button className="secondary-btn" disabled={!canGenerate} onClick={handleGenerate} type="button">
                  {generating ? t("reports.generating") : t("reports.generate")}
                </button>
              </div>
            )}
            {Boolean(reports.length) && !filteredReports.length && (
              <div className="empty-state report-filter-empty-state">
                <strong>{t("reports.no_matches")}</strong>
                <button className="secondary-btn" onClick={resetReportFilters} type="button">
                  {t("reports.clear_filters")}
                </button>
              </div>
            )}
          </div>
        </SectionCard>

        <SectionCard
          title={t("reports.preview")}
          aside={
            <div className="report-preview-actions">
              <button className="text-btn inline-text-btn" disabled={!previewContent} onClick={handleDownload} type="button">
                {t("reports.export_copy")}
              </button>
              <button className="text-btn inline-text-btn" disabled={!selectedReport?.path} onClick={handleOpenReportFile} type="button">
                {t("reports.open_file")}
              </button>
              <button className="text-btn inline-text-btn" disabled={!selectedReport?.path} onClick={() => void handleCopyPath()} type="button">
                {t("reports.copy_path")}
              </button>
              <button className="text-btn inline-text-btn" disabled={!selectedReport} onClick={() => setPreviewOpen(true)} type="button">
                {t("reports.expand")}
              </button>
            </div>
          }
        >
          <ReportPreview content={previewContent} kind={previewKind} loading={previewLoading} />
        </SectionCard>
      </div>

      <ReportPreviewDialog
        open={previewOpen && Boolean(selectedReport)}
        title={selectedReport?.name ?? "Report preview"}
        path={selectedReport?.path}
        content={previewContent}
        kind={previewKind}
        loading={previewLoading}
        onDownload={handleDownload}
        onClose={() => setPreviewOpen(false)}
      />
    </section>
  );
}

function reportMatchesFilters(
  report: ReportListItem,
  search: string,
  kindFilter: "all" | "markdown" | "html",
  dateFilter: "all" | "today" | "week",
): boolean {
  const keyword = search.trim().toLowerCase();
  const haystack = `${report.name} ${report.path}`.toLowerCase();
  if (keyword && !haystack.includes(keyword)) return false;
  if (kindFilter !== "all" && report.kind !== kindFilter) return false;
  return matchesDateFilter(report.modified_at, dateFilter);
}

function matchesDateFilter(value: string | undefined, filter: "all" | "today" | "week"): boolean {
  if (filter === "all") return true;
  if (!value) return false;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return false;
  const now = new Date();
  if (filter === "today") {
    return date.toDateString() === now.toDateString();
  }
  const weekAgo = now.getTime() - 7 * 24 * 60 * 60 * 1000;
  return date.getTime() >= weekAgo;
}

function formatDate(value: string | undefined, t: TFunction): string {
  if (!value) return t("reports.unknown_date");
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function formatSize(value: number, t: TFunction): string {
  if (!value) return `0 B`;
  if (value < 1024) return t("reports.size_b", { size: String(value) });
  if (value < 1024 * 1024) return t("reports.size_kb", { size: (value / 1024).toFixed(1) });
  return t("reports.size_mb", { size: (value / 1024 / 1024).toFixed(1) });
}

function reportStatusCopy(report: ReportListItem | null, t: TFunction): string {
  if (!report) return t("reports.no_report_selected");
  const kind = report.kind === "html" ? t("reports.html_report") : t("reports.markdown_report");
  return t("reports.report_status", { kind, size: formatSize(report.size_bytes ?? 0, t), date: formatDate(report.modified_at, t) });
}
