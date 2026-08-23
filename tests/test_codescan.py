"""Tests for the VulnClaw codescan package (local source-code scanner).

Covers the rule engine, scanner layering, JSON/SARIF reporting, and the
JSONL stream protocol used by the Rust TUI.
"""

from __future__ import annotations

import json

from vulnclaw.codescan.report import format_json, format_markdown, format_sarif
from vulnclaw.codescan.rules import L1_RULES, L2_RULES, L1Rule
from vulnclaw.codescan.scanner import scan_code
from vulnclaw.codescan.stream import emit_code_scan_stream

SAMPLE_TS = """\
import { OpenAI } from "openai";

const openai = new OpenAI({
  apiKey: "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcd", // L1: hardcoded secret
});

export function renderUserProfile(userInput: string): string {
  const container = document.getElementById("profile")!;
  container.innerHTML = userInput; // L2: DOM XSS
  return container.innerHTML;
}

export async function queryDatabase(userId: string) {
  const query = "SELECT * FROM users WHERE id = '" + userId + "'"; // L2: SQL injection
  return db.run(query);
}

export function runCommand(userCmd: string) {
  const { exec } = require("child_process");
  exec(userCmd); // L2: command injection
}

export async function fetchFromUrl(targetUrl: string) {
  const resp = await fetch(targetUrl); // L2: SSRF
  return resp.json();
}
"""


def _write_sample(tmp_path) -> str:
    p = tmp_path / "unsafe-ai-sample.ts"
    p.write_text(SAMPLE_TS, encoding="utf-8")
    return str(p)


# ---------------------------------------------------------------------------
# Rule engine
# ---------------------------------------------------------------------------

def test_rule_compile_and_match():
    rule = L1Rule(
        "test_rule",
        r"sk-[A-Za-z0-9_\-]{20,}",
        "Critical",
        "t",
        "d",
        "r",
    )
    assert rule.match("key = sk-abcdefghijklmnopqrstuvwxyz123456") is not None
    assert rule.match("no secret here") is None


def test_l2_rules_tagged_l2():
    """L2 rules must carry detection_layer='L2' so layer filtering works."""
    for rule in L2_RULES:
        assert rule.detection_layer == "L2", rule.rule_id


def test_l1_rules_tagged_l1():
    for rule in L1_RULES:
        assert rule.detection_layer == "L1", rule.rule_id


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def test_scan_finds_expected_vulns(tmp_path):
    path = _write_sample(tmp_path)
    result = scan_code(path, layers=("L1", "L2"))
    by_id = {f.rule_id for f in result.findings}
    assert "hardcoded_openai_key" in by_id
    assert "xss_inner_html" in by_id
    assert "sql_string_concat" in by_id
    assert "command_injection" in by_id
    assert "ssrf_url_fetch" in by_id
    assert result.files_scanned == 1


def test_scan_layer_filtering(tmp_path):
    path = _write_sample(tmp_path)
    l1_only = scan_code(path, layers=("L1",))
    l2_only = scan_code(path, layers=("L2",))
    assert all(f.detection_layer == "L1" for f in l1_only.findings)
    assert all(f.detection_layer == "L2" for f in l2_only.findings)
    assert l1_only.findings  # hardcoded key
    assert l2_only.findings  # xss/sqli/cmd/ssrf


def test_scan_clean_file(tmp_path):
    p = tmp_path / "clean.ts"
    p.write_text("const x = 1;\nexport default x;\n", encoding="utf-8")
    result = scan_code(str(p), layers=("L1", "L2"))
    assert result.findings == []


def test_scan_skips_git_and_node_modules(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "node_modules").mkdir()
    (tmp_path / ".git" / "secret.ts").write_text(
        'const k = "sk-abcdefghijklmnopqrstuvwxyz123456";\n', encoding="utf-8"
    )
    (tmp_path / "node_modules" / "bad.ts").write_text(
        'const k = "sk-abcdefghijklmnopqrstuvwxyz123456";\n', encoding="utf-8"
    )
    result = scan_code(str(tmp_path), layers=("L1", "L2"))
    assert result.findings == []


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def test_format_json_parses(tmp_path):
    path = _write_sample(tmp_path)
    result = scan_code(path, layers=("L1", "L2"))
    doc = json.loads(format_json(result))
    assert doc["tool"] == "vulnclaw"
    assert doc["files_scanned"] == 1
    assert len(doc["findings"]) == len(result.findings)
    first = doc["findings"][0]
    assert "finding_id" in first
    assert "code_location" in first
    assert "detection_layer" in first
    # No raw control chars may leak into string values.
    for f in doc["findings"]:
        for key, val in f.items():
            if isinstance(val, str):
                assert "\n" not in val and "\r" not in val, (key, val)


def test_format_sarif_parses(tmp_path):
    path = _write_sample(tmp_path)
    result = scan_code(path, layers=("L1", "L2"))
    doc = json.loads(format_sarif(result))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "VulnClaw"
    assert run["results"]
    for res in run["results"]:
        assert res["ruleId"] in {f.rule_id for f in result.findings}


def test_format_markdown(tmp_path):
    path = _write_sample(tmp_path)
    result = scan_code(path, layers=("L1", "L2"))
    md = format_markdown(result)
    assert "# VulnClaw Code Scan Report" in md
    assert "hardcoded_openai_key" in md


# ---------------------------------------------------------------------------
# Stream protocol (TUI)
# ---------------------------------------------------------------------------

def test_stream_events(tmp_path, capsys):
    path = _write_sample(tmp_path)
    result = scan_code(path, layers=("L1", "L2"))
    emit_code_scan_stream(result, sys_out := _Capture())
    events = [json.loads(line) for line in sys_out.lines if line.strip()]
    types = [e["type"] for e in events]
    assert types[0] == "status"
    assert "finding" in types
    assert types[-1] == "complete"
    complete = events[-1]
    assert complete["result"]["findings"]
    assert complete["summary"].startswith("Scanned")


class _Capture:
    """Tiny StringIO-like object for the stream emitter."""

    def __init__(self):
        self.lines: list[str] = []

    def write(self, s: str) -> int:
        self.lines.append(s)
        return len(s)

    def flush(self) -> None:
        pass
