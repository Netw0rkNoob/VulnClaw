"""FastAPI app entry for the VulnClaw Web UI backend."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

from vulnclaw.finding_service import FindingStateChangedError
from vulnclaw.web.auth import AuthMiddleware, attach_session_cookie, verify_token
from vulnclaw.web.schemas import (
    ConfigUpdateRequest,
    FindingVerifyRequest,
    ProviderModelsRequest,
    ReportGenerateRequest,
    TaskCreateRequest,
)
from vulnclaw.web.services.config_service import get_public_config, update_public_config
from vulnclaw.web.services.constraint_audit_service import get_constraint_audit
from vulnclaw.web.services.mcp_service import get_mcp_diagnostics
from vulnclaw.web.services.provider_service import fetch_models, get_provider_presets
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
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.responses import (
        FileResponse,
        JSONResponse,
        RedirectResponse,
        StreamingResponse,
    )
    from starlette.middleware.base import BaseHTTPMiddleware

    FASTAPI_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised in CLI dry-run and tests
    FastAPI = None  # type: ignore[assignment]
    HTTPException = RuntimeError  # type: ignore[assignment]
    Request = None  # type: ignore[assignment]
    FileResponse = None  # type: ignore[assignment]
    JSONResponse = None  # type: ignore[assignment]
    RedirectResponse = None  # type: ignore[assignment]
    StreamingResponse = None  # type: ignore[assignment]
    BaseHTTPMiddleware = object  # type: ignore[assignment,misc]
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
    normalized = path.replace("\\", "/").lstrip("/").strip()
    if not normalized:
        return resolve_web_index()

    for base_dir in (FRONTEND_DIST_DIR, STATIC_DIR):
        candidate = (base_dir / normalized).resolve()
        base_resolved = base_dir.resolve()
        if base_resolved in candidate.parents and candidate.is_file():
            return candidate

    return resolve_web_index()


def _serve_spa(request, file_path: Path):  # type: ignore[no-untyped-def]
    """Serve a frontend file, trading a ``?token=`` query for a session cookie.

    The browser UI cannot send a bearer header (see :mod:`vulnclaw.web.auth`),
    so opening the printed ``/?token=<token>`` URL once is what authenticates
    the session. The token is redirected straight back out of the address bar
    so it does not linger in history or leak through ``Referer``.
    """
    token = request.query_params.get("token", "")
    if token and verify_token(token):
        response = RedirectResponse(
            str(request.url.remove_query_params("token")), status_code=303
        )
        attach_session_cookie(response, token)
        return response
    return FileResponse(file_path)


@contextmanager
def _report_fs_errors():
    """Map report filesystem errors onto HTTP responses (missing -> 404, denied -> 403)."""
    try:
        yield
    except FileExistsError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except FindingStateChangedError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


def create_app():
    """Create the Web UI backend app."""
    if not FASTAPI_AVAILABLE:
        raise RuntimeError(
            "FastAPI is not installed. Install the web extra first: pip install vulnclaw[web]"
        )

    app = FastAPI(title="VulnClaw Web UI", version="0.4.0")
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(AuthMiddleware)

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

    @app.get("/api/providers")
    async def providers_view():
        return get_provider_presets().model_dump(mode="json")

    @app.post("/api/provider-models")
    async def provider_models_view(request: ProviderModelsRequest):
        return fetch_models(request).model_dump(mode="json")

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
        with _report_fs_errors():
            content = read_report_content(path)
        return content.model_dump(mode="json")

    @app.get("/api/reports/download")
    async def report_download(path: str):
        with _report_fs_errors():
            report_path = resolve_report_path(path)
        media_type = "text/html" if report_path.suffix.lower() == ".html" else "text/markdown"
        return FileResponse(report_path, media_type=media_type, filename=report_path.name)

    @app.post("/api/reports/target")
    async def report_target(request: ReportGenerateRequest):
        with _report_fs_errors():
            path = await generate_target_report(
                request.target,
                request.output_path,
                request.report_format,
            )
        return {"status": "ok", "path": path}

    @app.post("/api/findings/verify")
    async def findings_verify(request: FindingVerifyRequest):
        from vulnclaw.config.settings import load_config
        from vulnclaw.finding_service import assessment_summary, verify_target
        from vulnclaw.i18n import init_i18n

        config = load_config()
        init_i18n(config=config)
        with _report_fs_errors():
            session, path, _raw = await verify_target(
                request.target, config=config, poc_verify=request.poc_verify,
            )
        return {"status": "ok", "target": request.target,
                "path": str(path), "summary": assessment_summary(session)}

    @app.get("/")
    async def index(request: Request):
        return _serve_spa(request, resolve_web_index())

    @app.get("/{full_path:path}")
    async def frontend_routes(full_path: str, request: Request):
        if full_path.startswith("api/"):
            raise HTTPException(status_code=404, detail="Not found")
        return _serve_spa(request, resolve_web_asset(full_path))

    return app


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add conservative browser security headers for the local Web UI."""

    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; "
            "connect-src 'self'; "
            "frame-src 'self' about: data: blob:; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'",
        )
        return response
