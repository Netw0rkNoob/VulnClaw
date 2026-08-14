"""VulnClaw Vulnerability Verifier — validate findings before they enter the report.

核心原则: 未经验证的漏洞 = 误报 = 不写入报告

工作流程:
    1. 接收漏洞假设（pending finding）
    2. 生成 PoC 代码
    3. 通过 python_execute 执行 PoC
    4. 判定结果: verified / rejected
    5. 只有 verified 的漏洞才能进入报告
"""

from __future__ import annotations

import logging
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional

# 修改者: Nyaecho
# 修改时间: 2026-07-08
# 修改原因: 消除 V2 违规 — 叶子类型已移至 config/domain_models.py。
from vulnclaw.config.domain_models import VulnerabilityFinding

logger = logging.getLogger(__name__)


class VerificationStatus(str, Enum):
    """漏洞验证状态."""

    PENDING = "pending"  # 待验证
    VERIFIED = "verified"  # 验证通过
    REJECTED = "rejected"  # 验证失败/误报
    SKIPPED = "skipped"  # 跳过验证（如已确认的事实）


class VerificationResult(str, Enum):
    """验证结果详情."""

    # Verified outcomes
    VULN_CONFIRMED = "vuln_confirmed"  # 漏洞确认
    SENSITIVE_DATA_EXPOSED = "sensitive_data"  # 敏感数据泄露
    SECURITY_BYPASS = "security_bypass"  # 安全限制绕过

    # Rejected outcomes
    FALSE_POSITIVE = "false_positive"  # 误报
    NO_RESPONSE_DIFF = "no_response_diff"  # 响应无差异
    PARAM_INVALID = "param_invalid"  # 参数无效
    NORMAL_RESPONSE = "normal_response"  # 正常响应
    TIMEOUT = "timeout"  # 超时
    ERROR_403_404 = "error_403_404"  # 403/404 正常拒绝
    EXECUTION_ERROR = "execution_error"  # PoC 执行环境错误（如解释器缺失）


@dataclass
class VerifiedFinding:
    """经过验证的漏洞发现."""

    # 来自原始 finding 的信息
    original_finding: VulnerabilityFinding

    # 验证状态
    status: VerificationStatus = VerificationStatus.PENDING
    result: Optional[VerificationResult] = None

    # PoC 信息
    poc_code: Optional[str] = None
    poc_output: Optional[str] = None
    poc_executed_at: Optional[str] = None

    # 验证结论
    verified_description: str = ""
    verified_evidence: str = ""
    verified_severity: str = ""  # 可能根据验证结果调整严重度

    # 排除原因（如果验证失败）
    rejection_reason: str = ""

    # 验证者（元信息）
    verified_by: str = "verifier_module"
    verified_at: str = field(default_factory=lambda: datetime.now().isoformat())


# ── PoC 生成器 ────────────────────────────────────────────────────────────────


class PoCGenerator:
    """根据漏洞假设生成 PoC 代码."""

    # 漏洞类型 → PoC 模板映射
    #
    # ⚠️ 模板使用 *单花括号* 作为 Python 语法（dict 字面量、f-string 插值）。
    # 唯一的模板占位符是 ``{target}`` / ``{payload}`` / ``{baseline_len}`` /
    # ``{path}``，它们由 :meth:`generate_poc` 通过 ``str.replace`` 精确替换。
    # 不要使用 ``{{`` / ``}}`` 转义——渲染器不是 ``str.format``，双花括号会原样
    # 残留到生成的 PoC 中，导致 ``dict`` 字面量变成 ``set``（``TypeError``）或
    # f-string 打印字面量 ``{var}`` 文本而非插值结果。
    POC_TEMPLATES: dict[str, str] = {
        "sql_injection": """
import requests

target = "{target}"
params = {
    "id": "{payload}",
}

try:
    r = requests.get(target, params=params, timeout=10, verify=False)
    text = r.text.lower()

    # SQL error signatures
    sql_errors = [
        "sql syntax", "mysql", "sqlite", "postgres", "oracle",
        "sqlstate", "microsoft sql", "odbc", "syntax error",
        "you have an error in your sql", "warning: mysql",
    ]

    for err in sql_errors:
        if err in text:
            print(f"[CONFIRMED] SQL injection: detected SQL error signature '{err}'")
            print(f"[INFO] Response status: {r.status_code}")
            exit(0)

    # Check response difference (if a normal baseline is provided)
    baseline_len = {baseline_len}
    if len(r.content) != baseline_len and baseline_len > 0:
        print(f"[POSSIBLE] Abnormal response length: {len(r.content)} vs baseline {baseline_len}")

    print("[REJECTED] No SQL injection signature detected")
except requests.Timeout:
    print("[REJECTED] Request timed out")
except Exception as e:
    print(f"[ERROR] {e}")
""",
        "xss": """
import requests

target = "{target}"
payload = "{payload}"

try:
    r = requests.get(target, params={"q": payload}, timeout=10, verify=False)

    if payload in r.text:
        print("[CONFIRMED] XSS: payload reflected in the response")
        print("[INFO] XSS payload sent; verbatim reflection detected")
        exit(0)

    print("[REJECTED] XSS payload not found in the response")
except Exception as e:
    print(f"[ERROR] {e}")
""",
        "command_injection": """
import requests

target = "{target}"
params = {
    "cmd": "{payload}",
}

try:
    r = requests.get(target, params=params, timeout=10, verify=False)
    text = r.text

    # Command-injection signatures
    cmd_indicators = ["uid=", "gid=", "root:", "/bin/bash", "whoami", "linux"]

    for indicator in cmd_indicators:
        if indicator in text:
            print(f"[CONFIRMED] Command injection: detected '{indicator}'")
            exit(0)

    print("[REJECTED] No command-injection signature detected")
except Exception as e:
    print(f"[ERROR] {e}")
""",
        "debug_mode": """
import requests

target = "{target}"

try:
    # Normal request
    r_normal = requests.get(target, timeout=10, verify=False)
    len_normal = len(r_normal.content)

    # Debug-mode request
    r_debug = requests.get(target + "/?debug=1", timeout=10, verify=False)
    len_debug = len(r_debug.content)

    print(f"[INFO] Normal response length: {len_normal}")
    print(f"[INFO] debug=1 response length: {len_debug}")

    # Check for debug info disclosure
    if len_debug != len_normal:
        diff = len_debug - len_normal
        print(f"[POSSIBLE] Debug-mode response differs from normal, delta: {diff} bytes")

        # Check whether sensitive info is actually leaked
        debug_content = r_debug.text.replace(r_normal.text, "")
        if debug_content:
            sensitive_keywords = ["password", "secret", "api_key", "token", "db_", "connection"]
            for kw in sensitive_keywords:
                if kw.lower() in debug_content.lower():
                    print(f"[CONFIRMED] Debug mode leaks sensitive info: detected '{kw}'")
                    exit(0)

        # If only the length differs but no sensitive info, downgrade to Info
        print("[INFO] Debug-mode response differs but no sensitive info leak found; downgraded to Info")

    # Check debug-related keywords
    if "debug" in r_debug.text.lower() and r_debug.text.lower().count("debug") > r_normal.text.lower().count("debug"):
        print("[POSSIBLE] debug mode contains extra debug info")

    print("[REJECTED] No obvious sensitive info leak found in debug mode")

except Exception as e:
    print(f"[ERROR] {e}")
""",
        "lfi": """
import requests

target = "{target}"
payload = "{payload}"

try:
    r = requests.get(target, params={"file": payload}, timeout=10, verify=False)
    text = r.text.lower()

    # LFI signatures
    lfi_indicators = ["root:", "/bin/bash", "/bin/sh", "[boot loader]", "windows"]

    for indicator in lfi_indicators:
        if indicator in text:
            print(f"[CONFIRMED] LFI: detected '{indicator}'")
            exit(0)

    print("[REJECTED] No LFI signature detected")
except Exception as e:
    print(f"[ERROR] {e}")
""",
        "sensitive_file": """
import requests

target = "{target}"
path = "{path}"

try:
    r = requests.get(target + path, timeout=10, verify=False)

    if r.status_code == 200 and len(r.content) > 10:
        print(f"[CONFIRMED] Exposed file accessible: {path}")
        print(f"[INFO] Status: {r.status_code}, length: {len(r.content)}")

        # Check content type
        ct = r.headers.get("content-type", "")
        print(f"[INFO] Content-Type: {ct}")

        exit(0)

    print(f"[REJECTED] File not accessible or empty: {r.status_code}")
except Exception as e:
    print(f"[ERROR] {e}")
""",
        "info_disclosure": """
import requests

target = "{target}"

try:
    r = requests.get(target, timeout=10, verify=False)
    headers = {k.lower(): v.lower() for k, v in r.headers.items()}

    # Check response headers
    sensitive_headers = {
        "x-powered-by": "tech-stack info",
        "server": "server info",
        "x-aspnet-version": "ASP.NET version",
        "x-generator": "generator info",
    }

    found = []
    for header, desc in sensitive_headers.items():
        if header in headers:
            found.append(f"{header}: {headers[header][:50]}")

    if found:
        print(f"[CONFIRMED] Info disclosure: {len(found)} disclosing header(s)")
        for item in found:
            print(f"  - {item}")
        exit(0)

    print("[INFO] No obvious info disclosure; this is a normal security-config concern")
    print("[REJECTED] Response-header info disclosure - a config issue, not a vulnerability")
except Exception as e:
    print(f"[ERROR] {e}")
""",
    }

    @classmethod
    def generate_poc(
        cls,
        finding: VulnerabilityFinding,
        target: str,
        baseline_len: int = 0,
    ) -> str:
        """根据漏洞类型生成 PoC 代码.

        Args:
            finding: 漏洞发现
            target: 目标 URL
            baseline_len: 正常响应长度（用于对比）

        Returns:
            PoC Python 代码字符串
        """
        vuln_type = (finding.vuln_type or "").lower().replace(" ", "_")
        template = cls.POC_TEMPLATES.get(vuln_type)

        if not template:
            # 通用 PoC 模板
            template = cls._generic_template()

        payload = cls._guess_payload(finding)
        replacements = {
            "{target}": target,
            "{payload}": payload,
            "{baseline_len}": str(baseline_len),
            "{path}": payload,
        }
        for placeholder, value in replacements.items():
            template = template.replace(placeholder, value)
        return template

    @classmethod
    def _generic_template(cls) -> str:
        """生成通用 PoC 模板.

        当漏洞类型没有专用模板时使用。通过对比基准响应与注入 payload 后的响应，
        在常见注入参数上做启发式验证：反射检测、错误/敏感特征扫描、以及状态码/
        响应长度差异，并输出与 :meth:`VerifierExecutor.parse_result` 一致的
        ``[CONFIRMED]`` / ``[POSSIBLE]`` / ``[REJECTED]`` 标记。
        """
        return """
import requests

target = "{target}"
payload = "{payload}"

# Common injectable parameter names; try each with the payload and compare to the baseline
CANDIDATE_PARAMS = ["id", "q", "search", "name", "file", "page", "cmd", "url"]

# Generic error / anomaly signatures
SIGNATURES = [
    "sql syntax", "sqlstate", "mysql", "odbc", "you have an error in your sql",
    "traceback (most recent call last)", "stack trace", "fatal error",
    "warning:", "exception", "root:", "/bin/bash", "uid=", "gid=",
]


def fetch(params=None):
    return requests.get(target, params=params, timeout=10, verify=False)


try:
    baseline = fetch()
    base_status = baseline.status_code
    base_len = len(baseline.content)
    print(f"[*] Baseline response: status={base_status}, len={base_len}")

    confirmed = False
    for name in CANDIDATE_PARAMS:
        try:
            r = fetch(params={name: payload})
        except Exception:
            continue

        # 1) Reflection check: payload appears verbatim in the response (potential XSS / template injection)
        if payload and payload in r.text:
            print(f"[CONFIRMED] payload reflected verbatim via parameter '{name}'")
            confirmed = True
            break

        # 2) Error / anomaly signature scan
        low = r.text.lower()
        hit = next((s for s in SIGNATURES if s in low), None)
        if hit:
            print(f"[CONFIRMED] parameter '{name}' triggered an error/anomaly signature: '{hit}'")
            confirmed = True
            break

        # 3) Response difference: status-code change or significant length change
        if r.status_code != base_status:
            print(f"[POSSIBLE] parameter '{name}' changed the response status code: {base_status} -> {r.status_code}")
        elif base_len and abs(len(r.content) - base_len) > max(50, int(base_len * 0.2)):
            print(f"[POSSIBLE] parameter '{name}' significantly changed the response length: {base_len} -> {len(r.content)}")

    if not confirmed:
        print("[REJECTED] Generic verification detected no clear vulnerability signature")

except requests.Timeout:
    print("[REJECTED] Request timed out")
except Exception as e:
    print(f"[ERROR] {e}")
"""

    @classmethod
    def _guess_payload(cls, finding: VulnerabilityFinding) -> str:
        """根据漏洞类型猜测 payload."""
        vuln_type = (finding.vuln_type or "").lower()

        payloads = {
            "sql": "1' OR '1'='1",
            "xss": "<script>alert(1)</script>",
            "command": ";id",
            "lfi": "../../../etc/passwd",
        }

        for key, payload in payloads.items():
            if key in vuln_type:
                return payload

        return "test"


# ── 验证执行器 ───────────────────────────────────────────────────────────────


class VerifierExecutor:
    """执行 PoC 验证并判定结果."""

    # Python 解释器路径：使用当前运行的解释器，避免 "python" 在仅有
    # "python3" 的环境中缺失而被误判为漏洞验证失败。
    PYTHON_CMD = sys.executable or "python"

    @classmethod
    def execute_poc(cls, poc_code: str, timeout: int = 30) -> tuple[int, str]:
        """执行 PoC 代码.

        Args:
            poc_code: PoC Python 代码
            timeout: 超时秒数

        Returns:
            (返回码, 输出内容)
        """
        # 写入临时文件
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            delete=False,
            encoding="utf-8",
        ) as f:
            f.write(poc_code)
            temp_path = f.name

        try:
            # 执行 PoC
            result = subprocess.run(
                [cls.PYTHON_CMD, temp_path],
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            output = result.stdout + result.stderr
            return result.returncode, output

        except subprocess.TimeoutExpired:
            return -1, "[TIMEOUT] PoC 执行超时"
        except FileNotFoundError:
            return -2, f"[ERROR] Python 解释器未找到: {cls.PYTHON_CMD}"
        except Exception as e:
            return -3, f"[ERROR] 执行失败: {e}"
        finally:
            # 清理临时文件
            try:
                Path(temp_path).unlink()
            except Exception:
                pass

    @classmethod
    def parse_result(cls, output: str, returncode: int) -> VerificationResult:
        """解析 PoC 输出，判定验证结果.

        Args:
            output: PoC 输出内容
            returncode: 返回码

        Returns:
            验证结果
        """
        output_lower = output.lower()

        # 执行失败
        if returncode == -1:
            return VerificationResult.TIMEOUT
        if returncode in (-2, -3):
            # -2: Python 解释器缺失；-3: PoC 执行本身抛出异常。
            # 均为执行环境问题，而非目标返回 403/404。
            return VerificationResult.EXECUTION_ERROR
        if returncode != 0:
            return VerificationResult.FALSE_POSITIVE

        # 检查确认标记
        if "[CONFIRMED]" in output or "[VERIFIED]" in output:
            if "敏感信息" in output or "sensitive" in output_lower:
                return VerificationResult.SENSITIVE_DATA_EXPOSED
            if "绕过" in output or "bypass" in output_lower:
                return VerificationResult.SECURITY_BYPASS
            return VerificationResult.VULN_CONFIRMED

        # 检查拒绝标记
        if "[REJECTED]" in output or "[FALSE]" in output:
            return VerificationResult.FALSE_POSITIVE

        # 检查响应差异
        if "[POSSIBLE]" in output:
            return VerificationResult.NO_RESPONSE_DIFF

        # 检查正常响应
        if returncode == 0 and "[CONFIRMED]" not in output:
            return VerificationResult.NORMAL_RESPONSE

        return VerificationResult.FALSE_POSITIVE


# ── 主验证器 ────────────────────────────────────────────────────────────────


class VulnerabilityVerifier:
    """漏洞验证器 — 核心验证流程."""

    def __init__(self, target: str, baseline_len: int = 0) -> None:
        """初始化验证器.

        Args:
            target: 目标 URL
            baseline_len: 正常响应长度
        """
        self.target = target
        self.baseline_len = baseline_len
        self.verified_findings: list[VerifiedFinding] = []
        self.rejected_findings: list[VerifiedFinding] = []

    def verify(self, finding: VulnerabilityFinding) -> VerifiedFinding:
        """验证一个漏洞发现.

        Args:
            finding: 漏洞发现

        Returns:
            验证后的发现（含状态和证据）
        """
        vf = VerifiedFinding(original_finding=finding)

        # 生成 PoC
        poc_code = PoCGenerator.generate_poc(
            finding=finding,
            target=self.target,
            baseline_len=self.baseline_len,
        )
        vf.poc_code = poc_code

        # 执行 PoC
        returncode, output = VerifierExecutor.execute_poc(poc_code)
        vf.poc_output = output
        vf.poc_executed_at = datetime.now().isoformat()

        # 解析结果
        result = VerifierExecutor.parse_result(output, returncode)
        vf.result = result

        # 根据结果判定状态
        if result in (
            VerificationResult.VULN_CONFIRMED,
            VerificationResult.SENSITIVE_DATA_EXPOSED,
            VerificationResult.SECURITY_BYPASS,
        ):
            vf.status = VerificationStatus.VERIFIED
            vf._build_verified_finding(output)
        else:
            vf.status = VerificationStatus.REJECTED
            vf._build_rejected_finding(result, output)

        # 分类存储
        if vf.status == VerificationStatus.VERIFIED:
            self.verified_findings.append(vf)
        else:
            self.rejected_findings.append(vf)

        return vf

    def verify_batch(self, findings: list[VulnerabilityFinding]) -> list[VerifiedFinding]:
        """批量验证漏洞发现.

        Args:
            findings: 漏洞发现列表

        Returns:
            验证后的发现列表（只包含 verified）
        """
        verified = []

        for finding in findings:
            vf = self.verify(finding)
            if vf.status == VerificationStatus.VERIFIED:
                verified.append(vf)

        return verified

    def _build_verified_finding(self, output: str) -> None:
        """构建验证通过的发现详情."""
        vf = self.verified_findings[-1] if self.verified_findings else None
        if not vf:
            return

        original = vf.original_finding

        # 从输出中提取确认信息
        confirmed_lines = [
            line.strip()
            for line in output.split("\n")
            if "[CONFIRMED]" in line or "[VERIFIED]" in line
        ]

        vf.verified_description = (
            f"PoC verification passed. Original description: {original.description}"
            if original.description
            else "PoC verification confirmed the vulnerability exists"
        )
        vf.verified_evidence = "\n".join(confirmed_lines) if confirmed_lines else output[:500]
        vf.verified_severity = original.severity  # 保持原严重度，可根据结果调整

    def _build_rejected_finding(
        self,
        result: VerificationResult,
        output: str,
    ) -> None:
        """构建验证失败的发现详情."""
        vf = self.rejected_findings[-1] if self.rejected_findings else None
        if not vf:
            return

        original = vf.original_finding

        # 排除原因映射
        rejection_reasons = {
            VerificationResult.FALSE_POSITIVE: "No vulnerability signature detected after running the PoC; judged a false positive",
            VerificationResult.NO_RESPONSE_DIFF: "No response difference; parameter invalid or vulnerability not triggered",
            VerificationResult.PARAM_INVALID: "Invalid parameter; unable to verify the vulnerability hypothesis",
            VerificationResult.NORMAL_RESPONSE: "Normal response returned; the vulnerability does not exist",
            VerificationResult.TIMEOUT: "PoC execution timed out",
            VerificationResult.ERROR_403_404: "Request rejected (403/404); the target is not exploitable",
            VerificationResult.EXECUTION_ERROR: "PoC execution-environment error (e.g. missing interpreter); could not verify the vulnerability",
        }

        vf.rejection_reason = rejection_reasons.get(
            result,
            f"Verification failed, reason: {result.value}",
        )

        # 记录排除原因，但不加入报告
        logger.info("排除漏洞: %s | 原因: %s", original.title, vf.rejection_reason)

    def get_verified_report_findings(self) -> list[VulnerabilityFinding]:
        """获取可写入报告的漏洞列表.

        只返回验证通过的漏洞，验证失败的不返回。
        """
        result = []

        for vf in self.verified_findings:
            if vf.status == VerificationStatus.VERIFIED:
                # 克隆 finding 并更新验证信息
                finding = vf.original_finding.model_copy()
                finding.evidence = vf.verified_evidence
                finding.description = vf.verified_description
                finding.severity = vf.verified_severity
                # Stamp verification state so the produced finding passes the
                # report/SARIF/findings.json inclusion gate (verification_status
                # == "verified"), recording the actual PoC execution time.
                finding.mark_verified(
                    note=vf.verified_evidence[:200], evidence_level="L4"
                )
                if vf.poc_executed_at:
                    finding.verified_at = vf.poc_executed_at
                result.append(finding)

        return result

    def get_summary(self) -> dict[str, Any]:
        """获取验证摘要."""
        return {
            "total": len(self.verified_findings) + len(self.rejected_findings),
            "verified": len(self.verified_findings),
            "rejected": len(self.rejected_findings),
            "target": self.target,
            "verified_findings": [
                {
                    "title": vf.original_finding.title,
                    "severity": vf.verified_severity,
                    "result": vf.result.value if vf.result else None,
                }
                for vf in self.verified_findings
            ],
            "rejected_findings": [
                {
                    "title": vf.original_finding.title,
                    "reason": vf.rejection_reason,
                }
                for vf in self.rejected_findings
            ],
        }
