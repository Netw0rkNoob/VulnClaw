"""Report service for the Web UI backend."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from vulnclaw.config.settings import SESSIONS_DIR, ensure_dirs, load_config
from vulnclaw.i18n import init_i18n
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
    safe_target = re.sub(r"[^A-Za-z0-9_.-]+", "_", target or "unknown").strip("._")
    safe_target = safe_target[:80] or "unknown"
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
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    # The report generator picks Chinese vs English from current_lang(). Unlike
    # the scan task path, this standalone endpoint has no ambient i18n state, so
    # initialize it from the saved config.session.language before generating —
    # otherwise the report always falls back to auto-detection (defaults to en).
    init_i18n(config=load_config())
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
        destination = resolve_report_output_path(output_path, normalized_format)
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
    if candidate.suffix.lower() not in {".md", ".html"}:
        raise PermissionError(f"Unsupported report file type: {candidate.suffix}")

    return candidate


def resolve_report_output_path(path: str, report_format: str) -> Path:
    """Resolve a web report output path under sessions dir."""
    ensure_dirs()
    normalized_format = "html" if report_format.lower() == "html" else "markdown"
    expected_suffix = ".html" if normalized_format == "html" else ".md"
    destination = Path(path)
    if not destination.name:
        raise PermissionError("Report output path must include a file name")
    if destination.suffix.lower() != expected_suffix:
        raise PermissionError(f"Report output path must end with {expected_suffix}")

    candidate = destination.resolve()
    sessions_root = SESSIONS_DIR.resolve()
    if sessions_root not in candidate.parents and candidate != sessions_root:
        raise PermissionError(f"Report output path is outside sessions dir: {candidate}")
    candidate.parent.mkdir(parents=True, exist_ok=True)
    return candidate
