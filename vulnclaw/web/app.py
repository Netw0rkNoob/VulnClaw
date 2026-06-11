"""FastAPI app entry for the VulnClaw Web UI backend."""

from __future__ import annotations

from pathlib import Path

from vulnclaw.web.schemas import ConfigUpdateRequest, ReportGenerateRequest, TaskCreateRequest
from vulnclaw.web.services.config_service import get_public_config, update_public_config
from vulnclaw.web.services.constraint_audit_service import get_constraint_audit
from vulnclaw.web.services.mcp_service import get_mcp_diagnostics
from vulnclaw.web.services.report_service import (
    generate_target_report,
    list_reports,
    read_report_content,
    resolve_report_path,
)
from vulnclaw.web.services.target_service import (
    clear_target,
    get_diff,
    get_preview,
    get_snapshots,
    get_target,
    get_target_raw,
    list_targets,
    rollback_target,
)
from vulnclaw.web.services.task_service import start_task
from vulnclaw.web.stream import encode_sse
from vulnclaw.web.task_manager import WebTaskManager

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

    FASTAPI_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised in CLI dry-run and tests
    FastAPI = None  # type: ignore[assignment]
    HTTPException = RuntimeError  # type: ignore[assignment]
    FileResponse = None  # type: ignore[assignment]
    JSONResponse = None  # type: ignore[assignment]
    StreamingResponse = None  # type: ignore[assignment]
    FASTAPI_AVAILABLE = False


PROJECT_ROOT = Path(__file__).resolve().parents[2]
STATIC_DIR = Path(__file__).with_name("static")
FRONTEND_DIST_DIR = PROJECT_ROOT / "frontend" / "dist"
task_manager = WebTaskManager()


def resolve_web_index() -> Path:
    """Return the preferred index file for the Web UI."""
    dist_index = FRONTEND_DIST_DIR / "index.html"
    if dist_index.exists():
        return dist_index
    return STATIC_DIR / "index.html"


def resolve_web_asset(path: str) -> Path:
    """Resolve a frontend asset path from dist or fallback static dir."""
    normalized = path.lstrip("/").strip()
    if not normalized:
        return resolve_web_index()

    dist_path = FRONTEND_DIST_DIR / normalized
    if dist_path.exists() and dist_path.is_file():
        return dist_path

    static_path = STATIC_DIR / normalized
    if static_path.exists() and static_path.is_file():
        return static_path

    return resolve_web_index()


def create_app():
    """Create the Web UI backend app."""
    if not FASTAPI_AVAILABLE:
        raise RuntimeError(
            "FastAPI is not installed. Install the web extra first: pip install vulnclaw[web]"
        )

    app = FastAPI(title="VulnClaw Web UI", version="0.3.0")

    @app.get("/api/health")
    async def health():
        return {"status": "ok", "service": "vulnclaw-web"}

    @app.get("/api/config")
    async def config_view():
        return get_public_config().model_dump(mode="json")

    @app.get("/api/mcp")
    async def mcp_view():
        return get_mcp_diagnostics().model_dump(mode="json")

    @app.get("/api/constraint-audit")
    async def constraint_audit_view():
        return get_constraint_audit().model_dump(mode="json")

    @app.post("/api/config")
    async def config_update(request: ConfigUpdateRequest):
        return update_public_config(request).model_dump(mode="json")

    @app.get("/api/tasks")
    async def tasks():
        return [item.model_dump(mode="json") for item in task_manager.list_tasks()]

    @app.post("/api/tasks/run")
    async def create_task(request: TaskCreateRequest):
        task_id = start_task(task_manager, request)
        record = task_manager.get_task(task_id)
        return record.model_dump(mode="json") if record else {"task_id": task_id}

    @app.get("/api/tasks/{task_id}")
    async def task_detail(task_id: str):
        record = task_manager.get_task(task_id)
        if not record:
            raise HTTPException(status_code=404, detail="Task not found")
        return record.model_dump(mode="json")

    @app.post("/api/tasks/{task_id}/stop")
    async def stop_task(task_id: str):
        ok = await task_manager.stop_task(task_id)
        if not ok:
            raise HTTPException(status_code=404, detail="Task not running")
        return {"status": "stopped", "task_id": task_id}

    @app.get("/api/tasks/{task_id}/stream")
    async def stream_task(task_id: str):
        if not task_manager.get_task(task_id):
            raise HTTPException(status_code=404, detail="Task not found")

        async def event_iter():
            async for item in task_manager.stream_events(task_id):
                yield encode_sse(item)

        return StreamingResponse(event_iter(), media_type="text/event-stream")

    @app.get("/api/targets")
    async def targets():
        return [item.model_dump(mode="json") for item in list_targets()]

    @app.get("/api/targets/{target:path}")
    async def target_detail(target: str):
        item = get_target(target)
        if not item:
            raise HTTPException(status_code=404, detail="Target not found")
        return item.model_dump(mode="json")

    @app.get("/api/targets/{target:path}/raw")
    async def target_raw(target: str):
        raw = get_target_raw(target)
        if not raw:
            raise HTTPException(status_code=404, detail="Target not found")
        return JSONResponse(raw)

    @app.get("/api/target-preview/{target:path}")
    async def target_preview(target: str, snapshot_id: str | None = None):
        item = get_preview(target, snapshot_id=snapshot_id)
        if not item:
            raise HTTPException(status_code=404, detail="Target or snapshot not found")
        return item.model_dump(mode="json")

    @app.get("/api/targets/{target:path}/snapshots")
    async def target_snapshots(target: str):
        return [item.model_dump(mode="json") for item in get_snapshots(target)]

    @app.get("/api/target-diff/{target:path}")
    async def target_diff(target: str, from_snapshot_id: str, to_snapshot_id: str | None = None):
        item = get_diff(target, from_snapshot_id=from_snapshot_id, to_snapshot_id=to_snapshot_id)
        if not item:
            raise HTTPException(status_code=404, detail="Snapshot or target state not found")
        return item.model_dump(mode="json")

    @app.post("/api/targets/{target:path}/rollback")
    async def target_rollback(target: str, payload: dict):
        snapshot_id = str(payload.get("snapshot_id", "")).strip()
        if not snapshot_id:
            raise HTTPException(status_code=400, detail="snapshot_id is required")
        if not rollback_target(target, snapshot_id):
            raise HTTPException(status_code=404, detail="Snapshot not found")
        return {"status": "ok", "target": target, "snapshot_id": snapshot_id}

    @app.delete("/api/targets/{target:path}")
    async def target_clear(target: str):
        if not clear_target(target):
            raise HTTPException(status_code=404, detail="Target not found")
        return {"status": "ok", "target": target}

    @app.get("/api/reports")
    async def reports():
        return list_reports()

    @app.get("/api/reports/content")
    async def report_content(path: str):
        try:
            content = read_report_content(path)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        return content.model_dump(mode="json")

    @app.get("/api/reports/download")
    async def report_download(path: str):
        try:
            report_path = resolve_report_path(path)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        media_type = "text/html" if report_path.suffix.lower() == ".html" else "text/markdown"
        return FileResponse(report_path, media_type=media_type, filename=report_path.name)

    @app.post("/api/reports/target")
    async def report_target(request: ReportGenerateRequest):
        try:
            path = generate_target_report(
                request.target,
                request.output_path,
                request.report_format,
            )
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {"status": "ok", "path": path}

    @app.get("/")
    async def index():
        return FileResponse(resolve_web_index())

    @app.get("/{full_path:path}")
    async def frontend_routes(full_path: str):
        if full_path.startswith("api/"):
            raise HTTPException(status_code=404, detail="Not found")
        return FileResponse(resolve_web_asset(full_path))

    return app
