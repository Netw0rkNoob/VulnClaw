"""VulnClaw CodeScan detection rules.

Pure-Python, zero-dependency rule set for local source-code auditing.
Mirrors the DeepSec shield layering:

- L1: instant regex + entropy checks (hardcoded secrets, unsafe config,
      AI-generated code smells, dangerous imports)
- L2: structural / taint-ish checks via regex over source lines
      (SQL injection, XSS, command injection, path traversal, SSRF)
- L3: LLM-assisted semantic review (optional, opt-in)

Every rule yields a `CodeFinding` with severity, CWE and a fix hint so
results are actionable out of the box.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------
@dataclass
class CodeFinding:
    """A single local code-scan finding (schema-compatible with VulnerabilityFinding)."""

    rule_id: str
    title: str
    severity: str  # Critical / High / Medium / Low / Info
    file: str
    line: int
    column: int = 0
    evidence: str = ""
    description: str = ""
    remediation: str = ""
    cwe: str = ""
    detection_layer: str = "L1"  # L1 / L2 / L3
    confidence: float = 0.9

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "evidence": self.evidence,
            "description": self.description,
            "remediation": self.remediation,
            "cwe": self.cwe,
            "detection_layer": self.detection_layer,
            "confidence": self.confidence,
        }


# ---------------------------------------------------------------------------
# Rule primitives
# ---------------------------------------------------------------------------
@dataclass
class L1Rule:
    """L1 rule: anchored regex over a single line + optional entropy check."""

    rule_id: str
    pattern: str  # compiled lazily
    severity: str
    title: str
    description: str
    remediation: str
    cwe: str = ""
    entropy_min: float = 0.0  # >0 => require line-level shannon entropy
    language_hint: Optional[str] = None  # e.g. "python" / "js" / None=any
    detection_layer: str = "L1"  # layer tag stamped on findings

    _rx: Optional[re.Pattern[str]] = field(default=None, repr=False)

    def compile(self) -> "L1Rule":
        if self._rx is None:
            self._rx = re.compile(self.pattern, re.IGNORECASE)
        return self

    def match(self, line: str) -> Optional[re.Match[str]]:
        self.compile()
        assert self._rx is not None
        m = self._rx.search(line)
        if not m:
            return None
        if self.entropy_min > 0:
            entropy = _shannon_entropy(line.strip())
            if entropy < self.entropy_min:
                return None
        return m


def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string (approximates key randomness)."""
    if not s:
        return 0.0
    import math
    from collections import Counter

    counts = Counter(s)
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


# ---------------------------------------------------------------------------
# L1 rule set — instant, regex + entropy
# ---------------------------------------------------------------------------
L1_RULES: list[L1Rule] = [
    # --- Hardcoded secrets (entropy boosted) ---
    L1Rule(
        "hardcoded_openai_key",
        r"\b(sk-[A-Za-z0-9_\-]{20,})\b",
        "Critical",
        "Hardcoded OpenAI API key",
        "An OpenAI-style API key literal was found in source. Keys committed to "
        "a repository can be harvested by scanners and abused to run up billing.",
        "Move the key to an environment variable or secret manager, rotate the exposed key.",
        cwe="CWE-798",
        entropy_min=3.0,
    ),
    L1Rule(
        "hardcoded_aws_key",
        r"\b(AKIA[0-9A-Z]{16})\b",
        "Critical",
        "Hardcoded AWS access key ID",
        "An AWS access key ID literal was found in source.",
        "Move to IAM roles / env vars, rotate the leaked key.",
        cwe="CWE-798",
    ),
    L1Rule(
        "hardcoded_private_key",
        r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "Critical",
        "Embedded private key material",
        "Private key material is embedded in the repository.",
        "Remove the key, use a secrets manager, rotate immediately.",
        cwe="CWE-798",
    ),
    L1Rule(
        "hardcoded_password",
        r"(password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*['\"][^'\"\s]{6,}['\"]",
        "High",
        "Hardcoded credential",
        "A credential-like assignment (password/token/API key) was found in source.",
        "Use environment variables or a secret store; rotate the credential.",
        cwe="CWE-798",
        entropy_min=2.5,
    ),
    # --- Dangerous dynamic execution ---
    L1Rule(
        "dangerous_eval",
        r"\beval\s*\(|new\s+Function\s*\(|child_process\.exec\s*\(|os\.system\s*\(|subprocess\.(call|run|Popen)\s*\(",
        "High",
        "Dangerous dynamic execution",
        "Source invokes an eval/exec-style API. If any part of the argument is "
        "user-controlled, this is a command-injection / RCE primitive.",
        "Avoid eval/exec; validate and allow-list inputs; use parameterized APIs.",
        cwe="CWE-95",
    ),
    # --- AI-generated code smells ---
    L1Rule(
        "ai_placeholder_secret",
        r"(sk-xxxx|your[_-]?api[_-]?key|api_key\s*=\s*['\"]?['\"]|CHANGE_ME|REPLACE_ME|TODO.*(?:key|secret|token))",
        "Medium",
        "AI placeholder secret / TODO secret",
        "A placeholder key or a TODO that mentions secrets — a classic AI-code "
        "leftover that often slips into production.",
        "Fill in real configuration via env vars; never commit placeholder secrets.",
        cwe="CWE-798",
    ),
    L1Rule(
        "ai_hallucinated_dependency",
        r"(import|from|require)\s+['\"]?[A-Za-z0-9_\-\.]+\.[A-Za-z]{2,}['\"]?",
        "Low",
        "Possibly hallucinated dependency (review)",
        "AI models sometimes emit imports for packages that do not exist. "
        "This rule flags imports that may warrant a registry check.",
        "Verify the dependency exists in the registry before adding it.",
        cwe="CWE-1104",
    ),
    # --- Unsafe configuration ---
    L1Rule(
        "unsafe_debug_true",
        r"(debug|DEBUG|verification_mode|sandbox)\s*[:=]\s*true",
        "Medium",
        "Debug / unsafe config enabled",
        "Debug or permissive verification settings enabled in code/config.",
        "Disable debug mode for production.",
        cwe="CWE-489",
    ),
]


# ---------------------------------------------------------------------------
# L2 rule set — structural taint-ish checks (per-line, language aware)
# ---------------------------------------------------------------------------
L2_RULES: list[L1Rule] = [
    L1Rule(
        "sql_string_concat",
        r"(\"SELECT .*\"\s*\+|f['\"].*SELECT .*\{|'SELECT .*'\s*%|query\s*=\s*['\"].*SELECT)",
        "High",
        "SQL string concatenation",
        "A SQL statement appears to be built by string concatenation — the "
        "classic SQL-injection primitive.",
        "Use parameterized queries / prepared statements.",
        cwe="CWE-89",
        detection_layer="L2",
    ),
    L1Rule(
        "xss_inner_html",
        r"\.innerHTML\s*=|dangerouslySetInnerHTML|document\.write\s*\(|v-html\s*=",
        "High",
        "DOM XSS sink (innerHTML)",
        "User-controlled data flows into an HTML sink, enabling DOM XSS.",
        "Use textContent / escape output, or sanitize with a trusted library.",
        cwe="CWE-79",
        detection_layer="L2",
    ),
    L1Rule(
        "xss_template_unsafe",
        r"\{\{\s*[^}]*\|\s*safe\s*\}\}|\{%\s*(?:autoescape\s+off|mark_safe)|mark_safe\s*\(",
        "Medium",
        "Unsafe template rendering",
        "Template autoescaping is disabled or mark_safe is used on dynamic data.",
        "Keep autoescape on; avoid mark_safe on user input.",
        cwe="CWE-79",
        detection_layer="L2",
    ),
    L1Rule(
        "command_injection",
        r"(exec|system|popen|spawn|shell\s*=\s*True|child_process)\s*\(?[^)]*?(?:user|input|data|query|param|req|request|body|arg|name|cmd)\w*",
        "High",
        "Command injection sink",
        "Dynamic input reaches a command-execution sink.",
        "Use allow-lists / argument arrays without a shell; validate input strictly.",
        cwe="CWE-78",
        detection_layer="L2",
    ),
    L1Rule(
        "path_traversal",
        r"(open|openFile|readFile|writeFile|sendFile|Path\.join|join\s*\(|os\.path\.join|unlink|rmdir|mkdir)\s*\([^)]*?(?:user|input|filename|path|name|file)\w*",
        "High",
        "Path traversal sink",
        "User-controlled input is used to build a filesystem path.",
        "Validate/normalize paths; reject absolute paths and '..' segments.",
        cwe="CWE-22",
        detection_layer="L2",
    ),
    L1Rule(
        "ssrf_url_fetch",
        r"(requests\.(?:get|post)|urllib\.request|httpx\.(?:get|post|request)|fetch|axios\.(?:get|post))\s*\([^)]*?(?:target|url|host|user|input|param)\w*(?=\W|$)",
        "High",
        "SSRF sink (user-controlled fetch)",
        "User input is used to build an outbound request URL.",
        "Validate against an allow-list of hosts; block private/loopback ranges.",
        cwe="CWE-918",
        detection_layer="L2",
    ),
    L1Rule(
        "insecure_deserialization",
        r"(pickle\.loads?|yaml\.load\s*\(|load\s*\([^)]*Loader\s*=\s*SafeLoader|eval\s*\(|node-serialize|unserialize\s*\()",
        "High",
        "Insecure deserialization",
        "Untrusted data is deserialized without safety constraints.",
        "Use safe deserializers (yaml.safe_load, json) and validate schemas.",
        cwe="CWE-502",
        detection_layer="L2",
    ),
    L1Rule(
        "weak_crypto",
        r"(md5\s*\(|sha1\s*\(|DES\.new|ARC4|MDB5|weak_hash|Crypto\.Cipher\.DES)",
        "Medium",
        "Weak cryptographic primitive",
        "A deprecated / weak crypto primitive is used.",
        "Use SHA-256+ / AES-GCM / argon2 for password hashing.",
        cwe="CWE-327",
        detection_layer="L2",
    ),
    L1Rule(
        "insecure_http",
        r"http://[A-Za-z0-9\.\-]+\.[A-Za-z]{2,}",
        "Low",
        "Insecure HTTP URL",
        "Plain HTTP endpoint in code — traffic is unencrypted.",
        "Use HTTPS; for internal traffic consider TLS everywhere.",
        cwe="CWE-319",
        detection_layer="L2",
    ),
]


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------
EXT_LANGUAGE: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
    ".php": "php",
    ".rb": "ruby",
    ".c": "c",
    ".cpp": "cpp",
    ".h": "c",
    ".cs": "csharp",
    ".sh": "shell",
    ".bash": "shell",
    ".ps1": "powershell",
    ".html": "html",
    ".htm": "html",
    ".vue": "vue",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".json": "json",
    ".toml": "toml",
    ".ini": "ini",
    ".env": "env",
    ".sql": "sql",
}

SKIP_DIRS: set[str] = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    "node_modules",
    "venv",
    ".venv",
    "env",
    "dist",
    "build",
    ".next",
    ".nuxt",
    ".cache",
    "target",
    ".tox",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "coverage",
    ".idea",
    ".vscode",
    "vendor",
    "bower_components",
    ".terraform",
}

SKIP_EXTS: set[str] = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".webp",
    ".bmp",
    ".pdf",
    ".zip",
    ".gz",
    ".tar",
    ".7z",
    ".rar",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".whl",
    ".vsix",
    ".class",
    ".pyc",
    ".lock",  # lockfiles (npm/yarn/pip) — noise
}

# Files we always scan even without a code extension.
ALWAYS_SCAN_FILES: set[str] = {".env", ".env.example", "Dockerfile", "Makefile", "package.json", "requirements.txt"}


def detect_language(path: str) -> Optional[str]:
    """Return the language hint for a file path, or None to skip."""
    import os

    name = os.path.basename(path)
    if name in ALWAYS_SCAN_FILES:
        return "config"
    ext = os.path.splitext(name)[1].lower()
    return EXT_LANGUAGE.get(ext)


def should_scan_file(path: str) -> bool:
    """Decide whether a file should be scanned (extension + size gate)."""
    import os

    name = os.path.basename(path)
    if name in ALWAYS_SCAN_FILES:
        return True
    ext = os.path.splitext(name)[1].lower()
    if ext in SKIP_EXTS:
        return False
    if ext not in EXT_LANGUAGE:
        return False
    try:
        if os.path.getsize(path) > 2_000_000:  # 2 MB cap
            return False
    except OSError:
        return False
    return True
