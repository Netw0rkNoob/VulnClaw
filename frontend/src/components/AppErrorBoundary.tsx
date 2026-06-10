import { Component, type ErrorInfo, type ReactNode } from "react";
import { t } from "../i18n";

interface AppErrorBoundaryProps {
  children: ReactNode;
}

interface AppErrorBoundaryState {
  error: Error | null;
}

export class AppErrorBoundary extends Component<AppErrorBoundaryProps, AppErrorBoundaryState> {
  state: AppErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): AppErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("VulnClaw Web UI crashed", error, errorInfo);
  }

  render() {
    if (!this.state.error) return this.props.children;

    return (
      <main className="app-fallback-page">
        <section className="app-fallback-card">
          <span className="pill">{t("error_boundary.kicker")}</span>
          <h1>{t("error_boundary.title")}</h1>
          <p>{t("error_boundary.copy")}</p>
          <div className="app-fallback-actions">
            <button className="primary-btn" type="button" onClick={() => window.location.reload()}>
              {t("error_boundary.reload")}
            </button>
          </div>
          <details>
            <summary>{t("error_boundary.technical")}</summary>
            <pre>{this.state.error.message}</pre>
          </details>
        </section>
      </main>
    );
  }
}
