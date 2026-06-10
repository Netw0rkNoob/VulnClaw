import { useEffect, useMemo, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import type { ShellAction } from "./components/AppShell";
import { AppShell } from "./components/AppShell";
import { ConfirmDialog } from "./components/ConfirmDialog";
import { ToastHost, type ToastItem, type ToastTone } from "./components/ToastHost";
import { HistoryPage } from "./pages/HistoryPage";
import { HomePage } from "./pages/HomePage";
import { ReportsPage } from "./pages/ReportsPage";
import { RiskResultsPage } from "./pages/RiskResultsPage";
import { SafetyBoundaryPage } from "./pages/SafetyBoundaryPage";
import { SettingsPage } from "./pages/SettingsPage";
import { TaskConsolePage } from "./pages/TaskConsolePage";
import { createTask, openTaskStream, stopTask } from "./api/web";
import { useConfigQuery } from "./hooks/queries";
import { useT, type TFunction } from "./i18n";
import type { TaskCommand, TaskEvent, TaskOptions, TaskRecord, TaskSummary } from "./types/api";
import { formatTaskTitle } from "./utils/taskLabels";

type AppView = "home" | "risk" | "reports" | "boundary" | "history" | "settings" | "advanced";
type SettingsSection = "basic" | "ai" | "checks" | "boundary" | "data" | "python" | "diagnostics";

interface ReportFocus {
  target: string | null;
  path?: string;
  openPreview?: boolean;
}

function buildViewMeta(t: TFunction): Record<AppView, { eyebrow: string; title: string; copy: string }> {
  return {
    home: {
      eyebrow: t("view.scan.eyebrow"),
      title: t("view.scan.title"),
      copy: t("view.scan.copy"),
    },
    risk: {
      eyebrow: t("view.findings.eyebrow"),
      title: t("view.findings.title"),
      copy: t("view.findings.copy"),
    },
    reports: {
      eyebrow: t("view.reports.eyebrow"),
      title: t("view.reports.title"),
      copy: t("view.reports.copy"),
    },
    boundary: {
      eyebrow: t("view.scope.eyebrow"),
      title: t("view.scope.title"),
      copy: t("view.scope.copy"),
    },
    history: {
      eyebrow: t("view.history.eyebrow"),
      title: t("view.history.title"),
      copy: t("view.history.copy"),
    },
    settings: {
      eyebrow: t("view.settings.eyebrow"),
      title: t("view.settings.title"),
      copy: t("view.settings.copy"),
    },
    advanced: {
      eyebrow: t("view.console.eyebrow"),
      title: t("view.console.title"),
      copy: t("view.console.copy"),
    },
  };
}

const HASH_TO_VIEW: Record<string, AppView> = {
  home: "home",
  risk: "risk",
  reports: "reports",
  boundary: "boundary",
  history: "history",
  settings: "settings",
  advanced: "advanced",
};

function viewFromHash(): AppView {
  const key = window.location.hash.replace(/^#/, "");
  return HASH_TO_VIEW[key] ?? "home";
}

function viewHash(view: AppView): string {
  return view;
}

export function App() {
  const configQuery = useConfigQuery();
  const queryClient = useQueryClient();
  const { t } = useT();
  const [activeView, setActiveView] = useState<AppView>(() => viewFromHash());
  const [selectedTarget, setSelectedTarget] = useState<string | null>(null);
  const [activeTask, setActiveTask] = useState<TaskRecord | null>(null);
  const [reportFocus, setReportFocus] = useState<ReportFocus | null>(null);
  const [settingsSection, setSettingsSection] = useState<SettingsSection>("basic");
  const [taskEvents, setTaskEvents] = useState<TaskEvent[]>([]);
  const [stopConfirmOpen, setStopConfirmOpen] = useState(false);
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const VIEW_META = useMemo(() => buildViewMeta(t), [t]);

  const nav = useMemo(
    () => [
      { key: "home" as const, label: t("nav.scan"), description: "", icon: "/icons/sidebar/scan.svg" },
      { key: "risk" as const, label: t("nav.findings"), description: "", icon: "/icons/sidebar/findings.svg" },
      { key: "reports" as const, label: t("nav.reports"), description: "", icon: "/icons/sidebar/reports.svg" },
      { key: "boundary" as const, label: t("nav.scope"), description: "", icon: "/icons/sidebar/scope.svg" },
      { key: "history" as const, label: t("nav.history"), description: "", icon: "/icons/sidebar/history.svg" },
      { key: "settings" as const, label: t("nav.settings"), description: "", icon: "/icons/sidebar/settings.svg" },
    ],
    [t],
  );

  const latestEvent = taskEvents.length > 0 ? taskEvents[taskEvents.length - 1] : null;
  const hasStoppableTask = activeTask?.status === "running" || activeTask?.status === "pending";

  useEffect(() => {
    const handleHashChange = () => setActiveView(viewFromHash());
    handleHashChange();
    window.addEventListener("hashchange", handleHashChange);
    return () => window.removeEventListener("hashchange", handleHashChange);
  }, []);

  function navigateToView(view: AppView) {
    const nextHash = viewHash(view);
    if (window.location.hash !== `#${nextHash}`) {
      window.location.hash = nextHash;
    }
    setActiveView(view);
  }

  function eventSummary(event: TaskEvent): TaskSummary | null {
    const summary = event.payload.summary;
    return summary && typeof summary === "object" ? (summary as TaskSummary) : null;
  }

  function pushToast(
    tone: ToastTone,
    title: string,
    copy?: string,
    action?: Pick<ToastItem, "actionLabel" | "onAction">,
  ) {
    const id = Date.now() + Math.round(Math.random() * 1000);
    setToasts((prev) => [...prev.slice(-3), { id, tone, title, copy, ...action }]);
    window.setTimeout(() => {
      setToasts((prev) => prev.filter((toast) => toast.id !== id));
    }, 4800);
  }

  function refreshTaskData(target: string | null | undefined) {
    void queryClient.invalidateQueries({ queryKey: ["tasks"] });
    void queryClient.invalidateQueries({ queryKey: ["targets"] });
    void queryClient.invalidateQueries({ queryKey: ["constraint-audit"] });
    void queryClient.invalidateQueries({ queryKey: ["reports"] });
    if (target) {
      void queryClient.invalidateQueries({ queryKey: ["target", target] });
      void queryClient.invalidateQueries({ queryKey: ["target-preview", target] });
      void queryClient.invalidateQueries({ queryKey: ["target-snapshots", target] });
    }
  }

  useEffect(() => {
    if (!activeTask) return;
    const source = openTaskStream(activeTask.task_id, (event) => {
      setTaskEvents((prev) => [...prev.slice(-79), event]);
      if (event.event === "task_completed") {
        const summary = eventSummary(event);
        setActiveTask((prev) =>
          prev && prev.task_id === event.task_id
            ? { ...prev, status: "completed", summary: summary ?? prev.summary }
            : prev,
        );
        refreshTaskData(summary?.target ?? activeTask.target);
        pushToast(
          "success",
          t("toast.task_finished"),
          t("toast.task_finished_copy"),
          {
            actionLabel: t("toast.open_results"),
            onAction: () => {
              setSelectedTarget(summary?.target ?? activeTask.target);
              navigateToView("risk");
            },
          },
        );
      }
      if (event.event === "task_failed") {
        setActiveTask((prev) => (prev && prev.task_id === event.task_id ? { ...prev, status: "failed" } : prev));
        refreshTaskData(activeTask.target);
        pushToast("error", t("toast.task_failed"), String(event.payload.message ?? event.payload.error ?? t("toast.task_failed_copy")), {
          actionLabel: t("toast.open_console"),
          onAction: () => navigateToView("advanced"),
        });
      }
      if (event.event === "task_stopped") {
        setActiveTask((prev) => (prev && prev.task_id === event.task_id ? { ...prev, status: "stopped" } : prev));
        refreshTaskData(activeTask.target);
        pushToast("info", t("toast.task_stopped"), t("toast.task_stopped_copy"));
      }
    });
    return () => source.close();
  }, [activeTask?.task_id]);

  async function handleCreateTask(command: TaskCommand, target: string, resume: boolean, options: TaskOptions): Promise<TaskRecord> {
    const task = await createTask(command, target, resume, options);
    setActiveTask(task);
    setSelectedTarget(task.target);
    setTaskEvents([]);
    pushToast("success", t("toast.task_started"), formatTaskTitle(task.command, task.target));
    return task;
  }

  async function handleStopTask() {
    if (!activeTask) return;
    await stopTask(activeTask.task_id);
    setActiveTask((prev) => (prev ? { ...prev, status: "stopped" } : prev));
    refreshTaskData(activeTask.target);
    pushToast("info", t("toast.stop_sent"), t("toast.stop_sent_copy"));
  }

  function openBoundaryForActiveTask() {
    if (activeTask?.target) {
      setSelectedTarget(activeTask.target);
    }
    navigateToView("boundary");
  }

  function openReports(target: string | null = selectedTarget, path?: string, openPreview = false) {
    if (target) {
      setSelectedTarget(target);
    }
    setReportFocus({ target, path, openPreview });
    navigateToView("reports");
  }

  function openSettings(section: SettingsSection = "basic") {
    setSettingsSection(section);
    navigateToView("settings");
  }

  function handleSelectView(view: AppView) {
    if (view === "settings") {
      setSettingsSection("basic");
    }
    navigateToView(view);
  }

  const quickActions: ShellAction[] = useMemo(() => [
    { label: t("quick.new_scan"), glyph: "+", active: activeView === "home", onClick: () => navigateToView("home") },
    { label: t("quick.history"), glyph: "T", active: activeView === "history", onClick: () => navigateToView("history") },
    { label: t("quick.reports"), glyph: "R", active: activeView === "reports", onClick: () => openReports(activeTask?.target ?? selectedTarget) },
    {
      label: t("quick.assets"),
      glyph: "A",
      active: activeView === "risk",
      onClick: () => {
        if (activeTask?.target) setSelectedTarget(activeTask.target);
        navigateToView("risk");
      },
    },
    {
      label: t("quick.scope"),
      glyph: "IP",
      active: activeView === "boundary",
      onClick: openBoundaryForActiveTask,
    },
    {
      label: t("quick.findings"),
      glyph: "!",
      active: activeView === "risk",
      onClick: () => navigateToView("risk"),
    },
    { label: t("nav.console"), glyph: "C", active: activeView === "advanced", onClick: () => navigateToView("advanced") },
    {
      label: t("quick.refresh"),
      glyph: "F",
      onClick: () => refreshTaskData(activeTask?.target ?? selectedTarget),
    },
  ], [t, activeView, activeTask?.target, selectedTarget]);

  const sidebarActions: ShellAction[] = useMemo(() => [
    hasStoppableTask
      ? { label: t("quick.stop_task"), glyph: "ST", onClick: () => setStopConfirmOpen(true) }
      : { label: t("quick.home"), glyph: "H", active: activeView === "home", onClick: () => navigateToView("home") },
    { label: t("nav.settings"), glyph: "S", active: activeView === "settings", onClick: () => openSettings("basic") },
    { label: t("nav.console"), glyph: "C", active: activeView === "advanced", onClick: () => navigateToView("advanced") },
  ], [t, hasStoppableTask, activeView]);

  return (
    <AppShell
      activeView={activeView}
      activeNavView={activeView === "advanced" ? "settings" : activeView}
      nav={nav}
      meta={VIEW_META[activeView]}
      quickActions={quickActions}
      sidebarActions={sidebarActions}
      backendUnavailable={configQuery.isError}
      backendError={configQuery.error instanceof Error ? configQuery.error.message : undefined}
      onRetryBackend={() => void configQuery.refetch()}
      selectedTarget={selectedTarget}
      activeTask={activeTask}
      latestEvent={latestEvent}
      onSelectView={handleSelectView}
      onOpenAdvanced={() => navigateToView("advanced")}
      onOpenBoundary={openBoundaryForActiveTask}
      onOpenReports={() => openReports()}
      onOpenTarget={(target) => {
        setSelectedTarget(target);
        navigateToView("risk");
      }}
      onStopTask={() => setStopConfirmOpen(true)}
    >
      {activeView === "home" && (
        <HomePage
          selectedTarget={selectedTarget}
          activeTask={activeTask}
          latestEvent={latestEvent}
          taskEvents={taskEvents}
          onCreateTask={handleCreateTask}
          onOpenRisk={() => navigateToView("risk")}
          onOpenReports={() => openReports(activeTask?.target ?? selectedTarget)}
          onOpenBoundary={openBoundaryForActiveTask}
        />
      )}

      {activeView === "risk" && (
        <RiskResultsPage
          selectedTarget={selectedTarget}
          onSelectTarget={setSelectedTarget}
          onOpenHome={() => navigateToView("home")}
          onOpenReports={(path) => openReports(selectedTarget, path, Boolean(path))}
          onOpenBoundary={openBoundaryForActiveTask}
        />
      )}

      {activeView === "reports" && <ReportsPage selectedTarget={selectedTarget} focus={reportFocus} />}

      {activeView === "boundary" && (
        <SafetyBoundaryPage
          selectedTarget={selectedTarget}
          activeTask={activeTask}
          onOpenHome={() => navigateToView("home")}
          onOpenSettings={() => openSettings("boundary")}
          onSelectTarget={setSelectedTarget}
        />
      )}

      {activeView === "history" && (
        <HistoryPage
          selectedTarget={selectedTarget}
          onSelectTarget={setSelectedTarget}
          onOpenHome={() => navigateToView("home")}
          onOpenReports={(target) => openReports(target)}
          onOpenTarget={(target) => {
            setSelectedTarget(target);
            navigateToView("risk");
          }}
        />
      )}

      {activeView === "settings" && <SettingsPage initialSection={settingsSection} onOpenAdvanced={() => navigateToView("advanced")} />}

      {activeView === "advanced" && (
        <TaskConsolePage
          activeTask={activeTask}
          events={taskEvents}
          onTaskCreated={(task) => {
            setActiveTask(task);
            setSelectedTarget(task.target);
            setTaskEvents([]);
            navigateToView("advanced");
          }}
          onEvent={(event) => {
            setTaskEvents((prev) => [...prev.slice(-79), event]);
          }}
          onFocusTarget={(target) => {
            setSelectedTarget(target);
            navigateToView("risk");
          }}
        />
      )}

      <ConfirmDialog
        open={stopConfirmOpen}
        title={t("confirm.stop_scan_title")}
        copy={t("confirm.stop_scan_copy")}
        tone="danger"
        confirmLabel={t("confirm.stop_task_label")}
        onCancel={() => setStopConfirmOpen(false)}
        onConfirm={() => {
          setStopConfirmOpen(false);
          void handleStopTask();
        }}
      />
      <ToastHost toasts={toasts} onDismiss={(id) => setToasts((prev) => prev.filter((toast) => toast.id !== id))} />
    </AppShell>
  );
}
