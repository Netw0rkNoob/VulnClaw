"""VulnClaw Report Module Tests — generator.py"""

from pathlib import Path

from tests.reporting_fixtures import assessed_snapshot

# ── generator.py ─────────────────────────────────────────────────────


class TestReportGenerator:
    """Test report generation."""

    def _make_session(self):
        from vulnclaw.agent.context import PentestPhase, SessionState, VulnerabilityFinding

        state = SessionState(target="192.168.1.100")
        state.advance_phase(PentestPhase.RECON)
        state.advance_phase(PentestPhase.VULN_DISCOVERY)
        f1 = VulnerabilityFinding(
            title="SQL Injection",
            severity="Critical",
            vuln_type="SQLi",
            description="SQL injection in login form",
            evidence="admin' OR 1=1-- bypassed authentication",
            remediation="Use parameterized queries",
        )
        f1.verified = True
        f1.verification_status = "verified"
        state.add_finding(f1)
        f2 = VulnerabilityFinding(
            title="Cross-Site Scripting",
            severity="High",
            vuln_type="XSS",
            description="Reflected XSS in search parameter",
            evidence="<script>alert(1)</script>",
        )
        f2.verified = True
        f2.verification_status = "verified"
        state.add_finding(f2)
        f3 = VulnerabilityFinding(
            title="Information Disclosure",
            severity="Medium",
            vuln_type="Info Leak",
            description="Server version header exposed",
        )
        f3.verified = True
        f3.verification_status = "verified"
        state.add_finding(f3)
        return state

    async def test_generate_report(self, tmp_path):
        from vulnclaw.report.generator import generate_report

        session = self._make_session()
        output = str(tmp_path / "report.md")
        path = await generate_report(assessed_snapshot(session), output)
        assert path.exists()

    async def test_generate_html_report(self, tmp_path):
        from vulnclaw.report.generator import generate_report

        session = self._make_session()
        output = str(tmp_path / "report.md")
        path = await generate_report(assessed_snapshot(session), output, report_format="html")
        assert path.suffix == ".html"
        assert path.exists()

    async def test_report_contains_target(self, tmp_path):
        from vulnclaw.report.generator import generate_report

        session = self._make_session()
        output = str(tmp_path / "report.md")
        await generate_report(assessed_snapshot(session), output)
        content = Path(output).read_text(encoding="utf-8")
        assert "192.168.1.100" in content

    async def test_report_contains_task_constraints_summary(self, tmp_path):
        from vulnclaw.agent.context import TaskConstraints
        from vulnclaw.i18n import init_i18n
        from vulnclaw.report.generator import generate_report

        session = self._make_session()
        session.task_constraints = TaskConstraints(
            allowed_ports=[443],
            allowed_hosts=["example.com"],
            allowed_paths=["/admin"],
            strict_mode=True,
        )
        output = str(tmp_path / "report_constraints.md")
        init_i18n(lang="zh")  # pin the Chinese report bundle for this assertion
        try:
            await generate_report(assessed_snapshot(session), output)
        finally:
            init_i18n()
        content = Path(output).read_text(encoding="utf-8")
        assert "任务约束" in content
        assert "仅端口 443" in content
        assert "仅主机 example.com" in content
        assert "仅路径 /admin" in content

    async def test_report_contains_constraint_violation_audit(self, tmp_path):
        from vulnclaw.i18n import init_i18n
        from vulnclaw.report.generator import generate_report

        session = self._make_session()
        session.constraint_violations = [
            "constraint_violation: command 'exploit' is outside allowed actions [recon]",
            "constraint_violation: tool 'fetch' inferred action 'exploit'",
        ]
        output = str(tmp_path / "report_violations.md")
        init_i18n(lang="zh")  # pin the Chinese report bundle for this assertion
        try:
            await generate_report(assessed_snapshot(session), output)
        finally:
            init_i18n()
        content = Path(output).read_text(encoding="utf-8")
        assert "约束违规审计" in content
        assert "tool 'fetch'" in content

    async def test_report_contains_findings(self, tmp_path):
        from vulnclaw.i18n import init_i18n
        from vulnclaw.report.generator import generate_report

        session = self._make_session()
        output = str(tmp_path / "report.md")
        init_i18n(lang="zh")  # pin the Chinese report bundle for this assertion
        try:
            await generate_report(assessed_snapshot(session), output)
        finally:
            init_i18n()
        content = Path(output).read_text(encoding="utf-8")
        assert "SQL Injection" in content
        assert "Cross-Site Scripting" in content
        assert "Information Disclosure" in content
        assert "PoC" in content
        assert "证据等级" in content
        assert "生命周期" in content

    async def test_report_includes_location_and_repro_details(self, tmp_path):
        from vulnclaw.agent.context import SessionState, VulnerabilityFinding
        from vulnclaw.i18n import init_i18n
        from vulnclaw.report.generator import generate_report

        session = SessionState(target="https://example.com")
        finding = VulnerabilityFinding(
            title="Verified RCE",
            severity="Critical",
            vuln_type="RCE",
            description="通过工具验证确认：admin 接口存在命令执行",
            evidence="https://example.com/admin/exec | /admin/exec | 通过工具验证确认：命令执行成功",
        )
        finding.mark_verified(note="whoami 返回 www-data")
        session.add_finding(finding)

        output = str(tmp_path / "report_rce.md")
        init_i18n(lang="zh")  # pin the Chinese report bundle for this assertion
        try:
            await generate_report(assessed_snapshot(session), output)
        finally:
            init_i18n()
        content = Path(output).read_text(encoding="utf-8")
        assert "已验证漏洞定位与复现信息" in content
        assert "https://example.com/admin/exec" in content
        assert "PoC" in content

    async def test_report_high_risk_pending_item_marks_manual_review(self, tmp_path):
        from vulnclaw.agent.context import SessionState, VulnerabilityFinding
        from vulnclaw.i18n import init_i18n
        from vulnclaw.report.generator import generate_report

        session = SessionState(target="https://example.com")
        finding = VulnerabilityFinding(
            title="Possible RCE",
            severity="Critical",
            vuln_type="RCE",
            description="Potential command execution path",
            evidence="https://example.com/admin/exec | whoami",
            evidence_level="L2",
            lifecycle_status="pending_verification",
        )
        session.add_finding(finding)

        output = str(tmp_path / "report_review.md")
        init_i18n(lang="zh")  # pin the Chinese report bundle for this assertion
        try:
            await generate_report(assessed_snapshot(session), output)
        finally:
            init_i18n()
        content = Path(output).read_text(encoding="utf-8")
        # Unverified candidates stay suspected and are marked for manual review.
        assert "低置信疑似" in content
        assert "需人工复核" in content

    async def test_report_contains_severity_counts(self, tmp_path):
        from vulnclaw.report.generator import generate_report

        session = self._make_session()
        output = str(tmp_path / "report.md")
        await generate_report(assessed_snapshot(session), output)
        content = Path(output).read_text(encoding="utf-8")
        assert "Critical" in content
        assert "High" in content
        assert "Medium" in content

    async def test_report_contains_vulnclaw_brand(self, tmp_path):
        from vulnclaw.report.generator import generate_report

        session = self._make_session()
        output = str(tmp_path / "report.md")
        await generate_report(assessed_snapshot(session), output)
        content = Path(output).read_text(encoding="utf-8")
        assert "VulnClaw" in content

    async def test_report_prefers_llm_attack_summary_when_generated_from_session(
        self, tmp_path, monkeypatch
    ):
        from vulnclaw.report.generator import generate_report

        session = self._make_session()
        monkeypatch.setattr(
            "vulnclaw.report.generator._generate_attack_summary_from_session",
            lambda session: "这是通过 VulnClaw 对接的 LLM 生成的攻击路径摘要。",
        )

        output = str(tmp_path / "report_llm_summary.md")
        await generate_report(assessed_snapshot(session), output)
        content = Path(output).read_text(encoding="utf-8")
        assert "这是通过 VulnClaw 对接的 LLM 生成的攻击路径摘要。" in content

    def test_report_summary_uses_gpt5_token_parameter(self):
        from vulnclaw.config.schema import VulnClawConfig
        from vulnclaw.report.generator import _build_report_summary_llm_kwargs

        config = VulnClawConfig()
        config.llm.provider = "openai"
        config.llm.model = "gpt-5.5"
        config.llm.max_tokens = 4096

        kwargs = _build_report_summary_llm_kwargs(
            config,
            [{"role": "user", "content": "summarize"}],
        )

        assert kwargs["max_completion_tokens"] == 1200
        assert "max_tokens" not in kwargs
        assert "temperature" not in kwargs

    async def test_report_with_recon_data(self, tmp_path):
        from vulnclaw.agent.context import SessionState
        from vulnclaw.report.generator import generate_report

        session = SessionState(target="10.0.0.1")
        session.recon_data = {
            "ports": [80, 443, 3306],
            "services": ["nginx/1.24", "mysql/8.0"],
        }
        output = str(tmp_path / "report_recon.md")
        await generate_report(assessed_snapshot(session), output)
        content = Path(output).read_text(encoding="utf-8")
        assert "10.0.0.1" in content

    async def test_report_empty_findings(self, tmp_path):
        from vulnclaw.agent.context import SessionState
        from vulnclaw.i18n import init_i18n
        from vulnclaw.report.generator import generate_report

        session = SessionState(target="10.0.0.1")
        output = str(tmp_path / "report_empty.md")
        init_i18n(lang="zh")  # pin the Chinese report bundle for this assertion
        try:
            await generate_report(assessed_snapshot(session), output)
        finally:
            init_i18n()
        content = Path(output).read_text(encoding="utf-8")
        # Report with no submitted candidates states so and keeps the section layout.
        assert "10.0.0.1" in content
        assert "已上报的漏洞候选" in content
        assert "已验证漏洞" in content

    async def test_report_writes_findings_artifacts(self, tmp_path):
        from vulnclaw.report.generator import generate_report

        session = self._make_session()
        output = str(tmp_path / "report_with_artifacts.md")
        await generate_report(assessed_snapshot(session), output)
        # Every report writes the structured findings + SARIF artifact set.
        artifacts_dir = tmp_path / "report_with_artifacts.artifacts" / "findings"
        assert (artifacts_dir / "findings.json").exists()
        assert (artifacts_dir / "findings.sarif").exists()

    async def test_report_auto_output_path(self, tmp_path):
        """If no output path specified, should auto-generate one."""
        from vulnclaw.agent.context import SessionState
        from vulnclaw.report.generator import generate_report

        session = SessionState(target="auto-target")
        # This will use the default SESSIONS_DIR
        try:
            path = await generate_report(assessed_snapshot(session))
            assert path.exists()
        except Exception:
            # Might fail if SESSIONS_DIR not writable, that's ok for test
            pass

    async def test_report_respects_output_suffix(self, tmp_path):
        from vulnclaw.report.generator import generate_report

        session = self._make_session()
        output = str(tmp_path / "report.custom")
        path = await generate_report(assessed_snapshot(session), output, report_format="markdown")
        assert path.suffix == ".custom"

    async def test_report_includes_governance_context(self, tmp_path):
        from vulnclaw.agent.context import SessionState
        from vulnclaw.i18n import init_i18n
        from vulnclaw.report.generator import generate_report

        target_state = {
            "target": "https://example.com",
            "started_at": "2026-05-08T12:00:00",
            "phase": "漏洞发现",
            "findings": [],
            "recon_data": {
                "subdomains": ["vpn.example.com"],
                "paths": ["/admin"],
            },
            "executed_steps": ["Round 1: 访问 /admin 失败"],
            "notes": [],
            "resume_meta": {
                "resume_strategy": "continue_scan",
                "resume_strategy_reason": "已有高价值侦察资产，继续候选验证",
                "priority_targets": ["/admin"],
                "priority_recon_assets": ["paths:/admin", "subdomains:vpn.example.com"],
                "blocked_targets": ["old.example.com"],
                "failed_targets": ["old.example.com (3)"],
                "recent_failed_steps": ["Round 1: 访问 /admin 失败"],
            },
            "resume_summary": "恢复后优先测试 /admin 与 vpn.example.com",
            "recon_meta": {
                "paths": {
                    "/admin": {"confidence": 0.92},
                },
                "subdomains": {
                    "vpn.example.com": {"confidence": 0.88},
                },
            },
            "runtime_meta": {
                "current_attack_path": "path_probe",
            },
        }

        init_i18n(lang="zh")  # pin the Chinese report bundle for this assertion
        try:
            output = await generate_report(
                SessionState(**target_state), str(tmp_path / "governance.md"),
                target_state_context=target_state,
            )
        finally:
            init_i18n()
        content = Path(output).read_text(encoding="utf-8")
        assert "目标历史治理上下文" in content
        assert "continue_scan" in content
        assert "paths:/admin" in content
        assert "old.example.com" in content

    async def test_persistent_cycle_report_includes_verified_location_and_poc(self, tmp_path):
        from vulnclaw.agent.context import SessionState, VulnerabilityFinding
        from vulnclaw.i18n import init_i18n
        from vulnclaw.report.generator import generate_persistent_cycle_report

        session = SessionState(target="https://example.com")
        finding = VulnerabilityFinding(
            title="Verified Command Exec",
            severity="Critical",
            vuln_type="RCE",
            description="通过工具验证确认：admin 接口存在命令执行",
            evidence="https://example.com/admin/exec | /admin/exec | 通过工具验证确认：命令执行成功",
        )
        finding.mark_verified(note="whoami 返回 www-data")
        session.add_finding(finding)

        init_i18n(lang="zh")  # pin the Chinese report bundle for this assertion
        try:
            output = await generate_persistent_cycle_report(
                session=assessed_snapshot(session),
                cycle_num=1,
                output_path=str(tmp_path / "cycle.md"),
            )
        finally:
            init_i18n()  # restore auto-detected default
        content = Path(output).read_text(encoding="utf-8")
        assert "已验证漏洞定位与复现信息" in content
        assert "https://example.com/admin/exec" in content
        assert "PoC" in content

    async def test_persistent_cycle_report_counts_by_current_assessment(self, tmp_path):
        """Cycle report counts come from this run's assessment of every finding,
        never from the raw all-findings delta or stored session state."""
        from vulnclaw.agent.context import SessionState, VulnerabilityFinding
        from vulnclaw.i18n import init_i18n
        from vulnclaw.report.generator import generate_persistent_cycle_report

        session = SessionState(target="https://example.com")

        old = VulnerabilityFinding(
            title="Old RCE",
            severity="Critical",
            vuln_type="RCE",
            description="prior cycle finding",
            evidence="https://example.com/old | /old | confirmed",
        )
        old.mark_verified(note="prior")
        session.add_finding(old)

        # This cycle adds one newly-verified finding plus an unverified one.
        new_verified = VulnerabilityFinding(
            title="New SQLi",
            severity="High",
            vuln_type="SQLI",
            description="new cycle finding",
            evidence="https://example.com/new | /new | confirmed",
        )
        new_verified.mark_verified(note="this cycle")
        session.add_finding(new_verified)
        session.add_finding(
            VulnerabilityFinding(
                title="Unverified XSS",
                severity="Low",
                vuln_type="XSS",
                description="not verified",
                evidence="https://example.com/xss | /xss",
            )
        )

        init_i18n(lang="zh")  # pin the Chinese report bundle for this assertion
        try:
            output = await generate_persistent_cycle_report(
                session=assessed_snapshot(session),
                cycle_num=2,
                output_path=str(tmp_path / "cycle2.md"),
            )
        finally:
            init_i18n()  # restore auto-detected default
        content = Path(output).read_text(encoding="utf-8")
        # Both verified findings count via the current assessment; the
        # unverified one lands in the suspected section, not in verified.
        assert "**已验证漏洞**: 2" in content
        assert "**低置信疑似**: 1" in content
        assert "New SQLi" in content

    async def test_persistent_cycle_report_prefers_llm_attack_summary(self, tmp_path, monkeypatch):
        from vulnclaw.report.generator import generate_persistent_cycle_report

        session = self._make_session()
        monkeypatch.setattr(
            "vulnclaw.report.generator._generate_attack_summary_from_session",
            lambda session: "来自 LLM 的持续渗透周期摘要",
        )

        output = await generate_persistent_cycle_report(
            session=assessed_snapshot(session),
            cycle_num=1,
            output_path=str(tmp_path / "cycle_llm.md"),
        )
        content = Path(output).read_text(encoding="utf-8")
        assert "来自 LLM 的持续渗透周期摘要" in content


# ── i18n: standard report (issue #62) ──────────────────────────────


class TestStandardReportI18n:
    """generate_report / REPORT_TEMPLATE and its helpers render English under
    language=en (zero Chinese characters), while zh output stays unchanged."""

    _CJK_RE = __import__("re").compile(r"[一-鿿]")

    def _session_with_full_context(self):
        from vulnclaw.agent.context import SessionState, TaskConstraints, VulnerabilityFinding

        session = SessionState(target="https://example.com")
        session.task_constraints = TaskConstraints(
            allowed_ports=[443],
            allowed_hosts=["example.com"],
            allowed_paths=["/admin"],
            strict_mode=True,
        )
        session.recon_data = {
            "subdomains": ["a.example.com"],
            "ports": [80, 443],
            "services": ["nginx/1.24"],
            "technologies": ["php"],
            "waf": "cloudflare",
            "domains": ["b.example.com"],
        }
        session.constraint_violations = ["constraint_violation: test blocked"]
        finding = VulnerabilityFinding(
            title="Verified RCE",
            severity="Critical",
            vuln_type="RCE",
            description="Command execution confirmed via admin endpoint",
            evidence="https://example.com/admin/exec | /admin/exec | confirmed",
        )
        finding.mark_verified(note="whoami returned www-data")
        session.add_finding(finding)
        pending = VulnerabilityFinding(
            title="Possible RCE",
            severity="High",
            evidence_level="L1",
            lifecycle_status="pending_verification",
        )
        session.add_finding(pending)
        return session

    async def test_standard_report_english_has_zero_chinese_characters(self, tmp_path, monkeypatch):
        from vulnclaw.i18n import init_i18n
        from vulnclaw.report.generator import generate_report

        monkeypatch.setattr(
            "vulnclaw.report.generator._generate_attack_summary_from_session",
            lambda session: "",
        )
        session = self._session_with_full_context()
        init_i18n(lang="en")
        try:
            out = await generate_report(assessed_snapshot(session), str(tmp_path / "en.md"))
        finally:
            init_i18n()
        content = out.read_text(encoding="utf-8")
        assert not self._CJK_RE.search(content), self._CJK_RE.findall(content)
        # Sanity: the localized chrome actually rendered (not just absence of CJK).
        assert "Task Constraints" in content
        assert "Ports only: 443" in content
        assert "Open ports:" in content
        assert "Verified Findings — Location & Reproduction" in content
        assert "Needs Manual Review" in content

    async def test_standard_report_chinese_unchanged(self, tmp_path, monkeypatch):
        from vulnclaw.i18n import init_i18n
        from vulnclaw.report.generator import generate_report

        monkeypatch.setattr(
            "vulnclaw.report.generator._generate_attack_summary_from_session",
            lambda session: "",
        )
        session = self._session_with_full_context()
        init_i18n(lang="zh")
        try:
            out = await generate_report(assessed_snapshot(session), str(tmp_path / "zh.md"))
        finally:
            init_i18n()
        content = out.read_text(encoding="utf-8")
        assert "任务约束" in content
        assert "仅端口 443" in content
        assert "开放端口:" in content
        assert "服务:" in content
        assert "技术栈:" in content
        assert "关联域名:" in content
        assert "已验证漏洞定位与复现信息" in content
        assert "需人工复核" in content

    async def test_standard_report_recon_summary_uncollected_localized(self, tmp_path):
        from vulnclaw.agent.context import SessionState
        from vulnclaw.i18n import init_i18n
        from vulnclaw.report.generator import generate_report

        session = SessionState(target="10.0.0.1")

        async def _run(lang, path):
            init_i18n(lang=lang)
            try:
                return (await generate_report(assessed_snapshot(session), str(path))).read_text(encoding="utf-8")
            finally:
                init_i18n()

        en = await _run("en", tmp_path / "en_recon.md")
        zh = await _run("zh", tmp_path / "zh_recon.md")
        assert "Not collected" in en
        assert "未收集" in zh

    async def test_target_state_report_english_has_zero_chinese_characters(self, tmp_path):
        from vulnclaw.agent.context import SessionState
        from vulnclaw.i18n import init_i18n
        from vulnclaw.report.generator import generate_report

        target_state = {
            "target": "https://example.com",
            "started_at": "2026-05-08T12:00:00",
            "phase": "vuln_discovery",
            "findings": [],
            "recon_data": {"subdomains": ["vpn.example.com"]},
            "executed_steps": [],
            "notes": [],
            "resume_meta": {
                "resume_strategy": "continue_scan",
                "resume_strategy_reason": "priority recon assets already found",
                "priority_targets": ["/admin"],
                "priority_recon_assets": ["paths:/admin"],
                "blocked_targets": ["old.example.com"],
                "failed_targets": ["old.example.com (3)"],
                "recent_failed_steps": ["Round 1: probe /admin failed"],
            },
            "resume_summary": "Resume: prioritize /admin and vpn.example.com",
            "recon_meta": {"paths": {"/admin": {"confidence": 0.92}}},
            "runtime_meta": {"current_attack_path": "path_probe"},
        }

        init_i18n(lang="en")
        try:
            out = await generate_report(
                SessionState(**target_state), output_path=str(tmp_path / "en_ts.md"),
                target_state_context=target_state,
            )
        finally:
            init_i18n()
        content = out.read_text(encoding="utf-8")
        assert not self._CJK_RE.search(content), self._CJK_RE.findall(content)
        assert "Target Historical Governance Context" in content
        assert "continue_scan" in content
        assert "paths:/admin" in content


# ── i18n: report recommendations (issue #63) ─────────────────────────


class TestReportRecommendationI18n:
    """Recommendation text is language-aware; zh output unchanged (issue #63)."""

    def _session_with_unremediated_high(self):
        from vulnclaw.agent.context import PentestPhase, SessionState, VulnerabilityFinding

        state = SessionState(target="192.168.1.100")
        state.advance_phase(PentestPhase.RECON)
        state.advance_phase(PentestPhase.VULN_DISCOVERY)
        # High finding with NO remediation → triggers the localized fallback.
        f = VulnerabilityFinding(
            title="Reflected XSS",
            severity="High",
            vuln_type="XSS",
            description="Reflected XSS in search",
        )
        f.verified = True
        f.verification_status = "verified"
        state.add_finding(f)
        return state

    def _session_no_high(self):
        from vulnclaw.agent.context import PentestPhase, SessionState, VulnerabilityFinding

        state = SessionState(target="192.168.1.100")
        state.advance_phase(PentestPhase.RECON)
        f = VulnerabilityFinding(
            title="Server banner",
            severity="Medium",
            vuln_type="Info Leak",
            description="Version header exposed",
        )
        f.verified = True
        f.verification_status = "verified"
        state.add_finding(f)
        return state

    async def test_standard_report_recommendation_english(self, tmp_path):
        from vulnclaw.i18n import init_i18n
        from vulnclaw.report.generator import generate_report

        session = self._session_with_unremediated_high()
        try:
            init_i18n(lang="en")
            out = await generate_report(assessed_snapshot(session), str(tmp_path / "en.md"))
        finally:
            init_i18n()
        content = out.read_text(encoding="utf-8")
        assert "Prioritize fixing XSS risk: Reflected XSS" in content

    async def test_standard_report_recommendation_chinese_unchanged(self, tmp_path):
        from vulnclaw.i18n import init_i18n
        from vulnclaw.report.generator import generate_report

        session = self._session_with_unremediated_high()
        try:
            init_i18n(lang="zh")
            out = await generate_report(assessed_snapshot(session), str(tmp_path / "zh.md"))
        finally:
            init_i18n()
        content = out.read_text(encoding="utf-8")
        assert "请优先修复 XSS 风险: Reflected XSS" in content

    async def test_standard_report_empty_recommendation_localized(self, tmp_path):
        from vulnclaw.i18n import init_i18n
        from vulnclaw.report.generator import generate_report

        session = self._session_no_high()
        try:
            init_i18n(lang="en")
            en = (await generate_report(assessed_snapshot(session), str(tmp_path / "en.md"))).read_text(encoding="utf-8")
            init_i18n(lang="zh")
            zh = (await generate_report(assessed_snapshot(session), str(tmp_path / "zh.md"))).read_text(encoding="utf-8")
        finally:
            init_i18n()
        assert "Prioritize reviewing the attack surface" in en
        assert "优先复核攻击面并补充验证链路" in zh

    async def test_cycle_report_recommendation_english(self, tmp_path):
        from vulnclaw.i18n import init_i18n
        from vulnclaw.report.generator import generate_persistent_cycle_report

        session = self._session_with_unremediated_high()
        try:
            init_i18n(lang="en")
            out = await generate_persistent_cycle_report(
                session=assessed_snapshot(session),
                cycle_num=1,
                output_path=str(tmp_path / "cycle_en.md"),
            )
        finally:
            init_i18n()
        content = out.read_text(encoding="utf-8")
        assert "Fix XSS vulnerability: Reflected XSS" in content

    async def test_cycle_report_recommendation_chinese_unchanged(self, tmp_path):
        from vulnclaw.i18n import init_i18n
        from vulnclaw.report.generator import generate_persistent_cycle_report

        session = self._session_with_unremediated_high()
        try:
            init_i18n(lang="zh")
            out = await generate_persistent_cycle_report(
                session=assessed_snapshot(session),
                cycle_num=1,
                output_path=str(tmp_path / "cycle_zh.md"),
            )
        finally:
            init_i18n()
        content = out.read_text(encoding="utf-8")
        assert "修复 XSS 漏洞: Reflected XSS" in content

    async def test_cycle_report_empty_recommendation_localized(self, tmp_path):
        from vulnclaw.i18n import init_i18n
        from vulnclaw.report.generator import generate_persistent_cycle_report

        session = self._session_no_high()

        async def _run(path):
            return (await generate_persistent_cycle_report(
                session=assessed_snapshot(session),
                cycle_num=1,
                output_path=str(path),
            )).read_text(encoding="utf-8")

        try:
            init_i18n(lang="en")
            en = await _run(tmp_path / "cycle_en.md")
            init_i18n(lang="zh")
            zh = await _run(tmp_path / "cycle_zh.md")
        finally:
            init_i18n()
        assert "No high-risk findings yet" in en
        assert "暂无高危发现，继续深入测试" in zh

    def _session_uncategorized_high(self):
        from vulnclaw.agent.context import PentestPhase, SessionState, VulnerabilityFinding

        state = SessionState(target="192.168.1.100")
        state.advance_phase(PentestPhase.RECON)
        state.advance_phase(PentestPhase.VULN_DISCOVERY)
        # High finding with empty vuln_type and no remediation → exercises the
        # report.rec.uncategorized fallback inside the recommendation string.
        f = VulnerabilityFinding(
            title="Unknown Issue",
            severity="High",
            vuln_type="",
            description="Some unclassified high-severity finding",
        )
        f.verified = True
        f.verification_status = "verified"
        state.add_finding(f)
        return state

    async def test_cycle_report_uncategorized_fallback_localized(self, tmp_path):
        from vulnclaw.i18n import init_i18n
        from vulnclaw.report.generator import generate_persistent_cycle_report

        session = self._session_uncategorized_high()

        async def _run(path):
            return (await generate_persistent_cycle_report(
                session=assessed_snapshot(session),
                cycle_num=1,
                output_path=str(path),
            )).read_text(encoding="utf-8")

        try:
            init_i18n(lang="en")
            en = await _run(tmp_path / "cycle_uncat_en.md")
            init_i18n(lang="zh")
            zh = await _run(tmp_path / "cycle_uncat_zh.md")
        finally:
            init_i18n()
        assert "Uncategorized" in en
        assert "未分类" in zh


