import { useEffect, useRef } from "react";
import { useT } from "../i18n";

interface ReportPreviewDialogProps {
  open: boolean;
  title: string;
  path?: string;
  content?: string;
  kind?: string;
  loading: boolean;
  onDownload?: () => void;
  onClose: () => void;
}

interface ReportPreviewProps {
  content?: string;
  kind?: string;
  loading: boolean;
  expanded?: boolean;
}

export function ReportPreviewDialog({ open, title, path, content, kind, loading, onDownload, onClose }: ReportPreviewDialogProps) {
  const closeButtonRef = useRef<HTMLButtonElement | null>(null);
  const { t } = useT();

  useEffect(() => {
    if (!open) return undefined;
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [open, onClose]);

  useEffect(() => {
    if (open) closeButtonRef.current?.focus();
  }, [open]);

  if (!open) return null;

  return (
    <div className="dialog-backdrop" role="presentation" onMouseDown={onClose}>
      <section className="report-dialog" role="dialog" aria-modal="true" aria-labelledby="report-preview-title" onMouseDown={(event) => event.stopPropagation()}>
        <header className="report-dialog-header">
          <div>
            <span className="dialog-kicker">{t("dialog.report_preview")}</span>
            <h3 id="report-preview-title">{title}</h3>
            {path && <p>{path}</p>}
          </div>
          <div className="report-dialog-actions">
            <button className="secondary-btn" disabled={!content || !onDownload} type="button" onClick={onDownload}>
              {t("dialog.download")}
            </button>
            <button ref={closeButtonRef} className="secondary-btn" type="button" onClick={onClose}>
              {t("dialog.close")}
            </button>
          </div>
        </header>
        <ReportPreview content={content} kind={kind} loading={loading} expanded />
      </section>
    </div>
  );
}

export function ReportPreview({ content, kind, loading, expanded = false }: ReportPreviewProps) {
  const { t } = useT();
  return (
    <div className={`report-preview ${expanded ? "report-preview-expanded" : ""}`}>
      {content ? (
        kind === "html" ? (
          <iframe className="report-frame" sandbox="" srcDoc={content} title="HTML report preview" />
        ) : (
          <pre>{content}</pre>
        )
      ) : loading ? (
        <div className="empty-state">{t("dialog.loading_preview")}</div>
      ) : (
        <div className="empty-state">{t("dialog.select_report_preview")}</div>
      )}
    </div>
  );
}
