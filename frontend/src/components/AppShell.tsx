import type { ReactNode } from "react";
import type { TaskEvent, TaskRecord } from "../types/api";
import { useT } from "../i18n";
import { ActiveTaskBanner } from "./ActiveTaskBanner";
import { Sidebar, type NavItem } from "./Sidebar";
import { Topbar } from "./Topbar";

interface ViewMeta {
  eyebrow: string;
  title: string;
  copy: string;
}

export interface ShellAction {
  label: string;
  glyph: string;
  onClick: () => void;
  active?: boolean;
  disabled?: boolean;
}

interface AppShellProps<T extends string> {
  activeView: T;
  activeNavView?: T;
  nav: NavItem<T>[];
  meta: ViewMeta;
  quickActions: ShellAction[];
  sidebarActions: ShellAction[];
  backendUnavailable?: boolean;
  backendError?: string;
  onRetryBackend?: () => void;
  selectedTarget: string | null;
  activeTask: TaskRecord | null;
  latestEvent: TaskEvent | null;
  onSelectView: (view: T) => void;
  onOpenAdvanced: () => void;
  onOpenBoundary: () => void;
  onOpenReports: () => void;
  onOpenTarget: (target: string) => void;
  onStopTask: () => void;
  children: ReactNode;
}

export function AppShell<T extends string>({
  activeView,
  activeNavView,
  nav,
  meta,
  quickActions,
  sidebarActions,
  backendUnavailable = false,
  backendError,
  onRetryBackend,
  selectedTarget,
  activeTask,
  latestEvent,
  onSelectView,
  onOpenAdvanced,
  onOpenBoundary,
  onOpenReports,
  onOpenTarget,
  onStopTask,
  children,
}: AppShellProps<T>) {
  const { t } = useT();

  return (
    <div className="app-shell">
      <Sidebar
        activeView={activeView}
        activeNavView={activeNavView}
        nav={nav}
        footerActions={sidebarActions}
        onSelectView={onSelectView}
      />
      <main className="workspace">
        <Topbar
          eyebrow={meta.eyebrow}
          title={meta.title}
          copy={meta.copy}
          selectedTarget={selectedTarget}
          activeTaskStatus={activeTask?.status}
        />
        {backendUnavailable && (
          <section className="connection-banner" role="status">
            <div>
              <strong>{t("shell.backend_unavailable")}</strong>
              <span>
                {t("shell.backend_hint")}
              </span>
              {backendError && <small>{backendError}</small>}
            </div>
            {onRetryBackend && (
              <button className="secondary-btn" onClick={onRetryBackend} type="button">
                {t("shell.retry")}
              </button>
            )}
          </section>
        )}
        <ActiveTaskBanner
          task={activeTask}
          latestEvent={latestEvent}
          onOpenAdvanced={onOpenAdvanced}
          onOpenBoundary={onOpenBoundary}
          onOpenReports={onOpenReports}
          onOpenTarget={onOpenTarget}
          onStop={onStopTask}
        />
        <div className="view-mount">{children}</div>
      </main>
      <aside className="quick-rail" aria-label="quick actions">
        <div className="quick-rail-main">
          {quickActions.map((item) => (
            <button
              key={item.label}
              type="button"
              className={item.active ? "active" : ""}
              title={item.label}
              aria-label={item.label}
              disabled={item.disabled}
              onClick={item.onClick}
            >
              <span>{item.glyph}</span>
            </button>
          ))}
        </div>
      </aside>
    </div>
  );
}
