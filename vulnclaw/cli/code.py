"""VulnClaw CLI — code sub-command group (local source-code scanning).

Usage:
    vulnclaw code scan <path> [--layer L1|L2|L3|all] [--format text|json|sarif|markdown]
                              [--output FILE] [--stream] [--no-progress]

The scanner is pure-Python (no LLM required for L1/L2). L3 uses the
configured LLM provider for semantic review and is opt-in.
"""

from __future__ import annotations

import sys
from typing import Optional

import typer
from rich.panel import Panel

from vulnclaw.cli._helpers import console, err_console

code_app = typer.Typer(
    name="code",
    help="Local source-code security scanning (no network target needed)",
    no_args_is_help=False,
)


@code_app.callback(invoke_without_command=True)
def code_root(ctx: typer.Context) -> None:
    """Print the code-group help when invoked bare."""
    if ctx.resilient_parsing or ctx.invoked_subcommand is not None:
        return
    console.print(Panel.fit("vulnclaw code — local source-code audit\n\n  vulnclaw code scan <path>", title="CodeScan"))


@code_app.command("scan")
def code_scan(
    path: str = typer.Argument(..., help="Source file or directory to scan"),
    layer: str = typer.Option(
        "all",
        "--layer",
        help="Detection layers: L1 (instant regex/entropy), L2 (structural), L3 (LLM, opt-in), all",
    ),
    output_format: str = typer.Option(
        "text",
        "--format",
        "-f",
        help="Output format: text, json, sarif, markdown",
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Write the report to a file instead of stdout",
    ),
    stream: bool = typer.Option(
        False,
        "--stream",
        help="Emit newline-delimited JSON events for the Rust TUI",
    ),
    no_progress: bool = typer.Option(
        False,
        "--no-progress",
        help="Do not print per-file progress lines",
    ),
) -> None:
    """Scan local source code for vulnerabilities (like DeepSec shield scan)."""
    import os

    if not os.path.exists(path):
        err_console.print(f"[!] Path not found: {path}")
        raise typer.Exit(2)

    layer_set = _parse_layers(layer)
    if layer_set is None:
        err_console.print("[!] --layer must be one of: L1, L2, L3, all")
        raise typer.Exit(2)

    from vulnclaw.codescan.scanner import scan_code

    progress_cb = None if no_progress or stream else _make_progress()

    # L3 needs an LLM client; resolve lazily only when requested.
    llm_client = None
    if "L3" in layer_set:
        llm_client = _resolve_llm_client()

    result = scan_code(path, layers=layer_set, progress=progress_cb)

    if "L3" in layer_set and llm_client is not None:
        from vulnclaw.codescan.scanner import scan_code_llm

        result.findings = scan_code_llm(path, findings=result.findings, llm_client=llm_client)

    if stream:
        from vulnclaw.codescan.stream import emit_code_scan_stream

        emit_code_scan_stream(result, sys.stdout)
    else:
        from vulnclaw.codescan.report import format_result

        rendered = format_result(result, output_format)
        structured = output_format in ("json", "sarif", "markdown", "md")
        if output:
            _write_output(output, rendered)
            console.print(f"[+] Wrote {output_format} report to {output}")
            console.print(result.summary())
        elif structured:
            # Write structured formats directly to stdout to avoid CRLF
            # corruption from rich console on Windows.
            sys.stdout.write(rendered)
            sys.stdout.write("\n")
        else:
            console.print(rendered)

    # Non-zero exit when critical/high findings exist (CI-friendly).
    counts = result.severity_counts
    if counts.get("Critical", 0) or counts.get("High", 0):
        raise typer.Exit(1)


def _parse_layers(layer: str) -> Optional[set[str]]:
    raw = (layer or "all").upper()
    if raw == "ALL":
        return {"L1", "L2"}
    valid = {"L1", "L2", "L3"}
    parts = {p.strip().upper() for p in raw.replace(",", " ").split() if p.strip()}
    if not parts or not parts <= valid:
        return None
    return parts


def _make_progress():
    """Return a progress callback printing one line per file scanned."""
    import time

    start = time.perf_counter()

    def _cb(file_path: str, findings_so_far: int) -> None:
        elapsed = (time.perf_counter() - start) * 1000
        console.print(f"  [dim]{elapsed:7.1f} ms[/dim]  {file_path}  ({findings_so_far} findings)")

    return _cb


def _resolve_llm_client():
    """Build a thin LLM client from the current config (best effort).

    Returns an object with ``.complete(prompt) -> str`` or ``None`` when
    the provider is not configured. Uses the already-declared ``openai``
    dependency so no new packages are required.
    """
    try:
        from vulnclaw.config.settings import load_config

        config = load_config()
        llm = getattr(config, "llm", None)
        if llm is None:
            raise RuntimeError("no llm config")
        provider = getattr(llm, "provider", None) or "openai"
        api_key = getattr(llm, "api_key", None) or ""
        base_url = getattr(llm, "base_url", None) or None
        model = getattr(llm, "model", None) or "gpt-4o"
        if not api_key or api_key in ("", "${LLM_API_KEY}"):
            raise RuntimeError("no api_key configured")

        from openai import OpenAI

        client = OpenAI(api_key=api_key, base_url=base_url)

        class _SyncLLM:
            def complete(self, prompt: str, *, temperature: float = 0.2) -> str:
                resp = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=temperature,
                )
                return resp.choices[0].message.content or ""

        console.print(f"[+] L3 enabled: using provider '{provider}' (model {model})")
        return _SyncLLM()
    except Exception as exc:  # noqa: BLE001
        err_console.print(f"[!] L3 requested but LLM client unavailable ({exc}). Skipping L3.")
        return None


def _write_output(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)
