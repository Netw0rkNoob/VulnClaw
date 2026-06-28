"""Report service for the Web UI backend."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from vulnclaw.config.settings import SESSIONS_DIR, ensure_dirs
from vulnclaw.report.generator import generate_report_from_target_state
from vulnclaw.target_state.store import load_target_state
from vulnclaw.web.schemas import ReportContentView


def _report_item(path: Path, kind: str) -> dict[str, str | int]:
    stat = path.stat()
    return {
        "name": path.name,
        "path": str(path.resolve()),
        "kind": kind,
        "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        "size_bytes": stat.st_size,
    }


def _default_report_path(target: str, report_format: str) -> Path:
    safe_target = (target or "unknown").replace("/", "_").replace(":", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    suffix = ".html" if report_format == "html" else ".md"
    return SESSIONS_DIR / f"report_{timestamp}_{safe_target}{suffix}"


def list_reports(limit: int = 50) -> list[dict[str, str | int]]:
    """List recent reports from the sessions directory."""
    ensure_dirs()
    items: list[dict[str, str | int]] = []
    for path in SESSIONS_DIR.glob("*.md"):
        items.append(_report_item(path, "markdown"))
    for path in SESSIONS_DIR.glob("*.html"):
        items.append(_report_item(path, "html"))
    items.sort(key=lambda item: str(item["modified_at"]), reverse=True)
    return items[:limit]


def generate_target_report(
    target: str,
    output_path: str | None = None,
    report_format: str = "markdown",
) -> str:
    """Generate a report from target state and return the saved path."""
    raw = load_target_state(target)
    if not raw:
        raise FileNotFoundError(f"Target state not found: {target}")
    normalized_format = "html" if report_format.lower() == "html" else "markdown"
    path = generate_report_from_target_state(
        raw,
        report_format=normalized_format,
        output_path=str(_default_report_path(target, normalized_format)),
    )
    if output_path:
        destination = Path(output_path).resolve()
        sessions_root = SESSIONS_DIR.resolve()
        if sessions_root not in destination.parents and destination != sessions_root:
            raise PermissionError(f"Output path is outside sessions dir: {destination}")
        destination.write_text(Path(path).read_text(encoding="utf-8"), encoding="utf-8")
        return str(destination)
    return str(Path(path).resolve())


def read_report_content(path: str) -> ReportContentView:
    """Read a report file for preview, limited to the sessions directory."""
    candidate = resolve_report_path(path)
    suffix = candidate.suffix.lower()
    kind = "html" if suffix == ".html" else "markdown"
    return ReportContentView(
        path=str(candidate),
        kind=kind,
        content=candidate.read_text(encoding="utf-8"),
    )


def resolve_report_path(path: str) -> Path:
    """Resolve a report path while preventing access outside sessions dir."""
    ensure_dirs()
    candidate = Path(path).resolve()
    sessions_root = SESSIONS_DIR.resolve()

    if sessions_root not in candidate.parents and candidate != sessions_root:
        raise PermissionError(f"Report path is outside sessions dir: {candidate}")
    if not candidate.exists():
        raise FileNotFoundError(f"Report not found: {candidate}")
    if not candidate.is_file():
        raise FileNotFoundError(f"Report is not a file: {candidate}")

    return candidate
