"""VulnClaw CodeScan — local source-code security auditing.

Zero-dependency static analysis layered like DeepSec shield:

- L1: instant regex + entropy (hardcoded secrets, unsafe config, AI smells)
- L2: structural taint-ish checks (SQLi, XSS, command injection, path traversal)
- L3: LLM-assisted semantic review (opt-in)

Entry points: ``vulnclaw code scan <path>`` (CLI), ``/codescan <path>`` (TUI),
plus the Python API::

    from vulnclaw.codescan.scanner import scan_code
    result = scan_code("./src", layers=("L1", "L2"))
"""

from vulnclaw.codescan.rules import CodeFinding
from vulnclaw.codescan.scanner import ScanResult, scan_code, scan_code_llm

__all__ = ["CodeFinding", "ScanResult", "scan_code", "scan_code_llm"]
