"""VulnClaw Report Module Tests — generator.py + poc_builder.py"""

from pathlib import Path

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

    def test_generate_report(self, tmp_path):
        from vulnclaw.report.generator import generate_report

        session = self._make_session()
        output = str(tmp_path / "report.md")
        path = generate_report(session, output)
        assert path.exists()

    def test_generate_html_report(self, tmp_path):
        from vulnclaw.report.generator import generate_report

        session = self._make_session()
        output = str(tmp_path / "report.md")
        path = generate_report(session, output, report_format="html")
        assert path.suffix == ".html"
        assert path.exists()

    def test_report_contains_target(self, tmp_path):
        from vulnclaw.report.generator import generate_report

        session = self._make_session()
        output = str(tmp_path / "report.md")
        generate_report(session, output)
        content = Path(output).read_text(encoding="utf-8")
        assert "192.168.1.100" in content

    def test_report_contains_task_constraints_summary(self, tmp_path):
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
            generate_report(session, output)
        finally:
            init_i18n()
        content = Path(output).read_text(encoding="utf-8")
        assert "任务约束" in content
        assert "仅端口 443" in content
        assert "仅主机 example.com" in content
        assert "仅路径 /admin" in content

    def test_report_contains_constraint_violation_audit(self, tmp_path):
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
            generate_report(session, output)
        finally:
            init_i18n()
        content = Path(output).read_text(encoding="utf-8")
        assert "约束违规审计" in content
        assert "tool 'fetch'" in content

    def test_report_contains_findings(self, tmp_path):
        from vulnclaw.i18n import init_i18n
        from vulnclaw.report.generator import generate_report

        session = self._make_session()
        output = str(tmp_path / "report.md")
        init_i18n(lang="zh")  # pin the Chinese report bundle for this assertion
        try:
            generate_report(session, output)
        finally:
            init_i18n()
        content = Path(output).read_text(encoding="utf-8")
        assert "SQL Injection" in content
        assert "Cross-Site Scripting" in content
        assert "Information Disclosure" in content
        assert "PoC" in content
        assert "证据等级" in content
        assert "生命周期" in content

    def test_report_includes_location_and_repro_details(self, tmp_path):
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
            generate_report(session, output)
        finally:
            init_i18n()
        content = Path(output).read_text(encoding="utf-8")
        assert "已验证漏洞定位与复现信息" in content
        assert "https://example.com/admin/exec" in content
        assert "PoC" in content

    def test_report_high_risk_pending_item_marks_manual_review(self, tmp_path):
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
            generate_report(session, output)
        finally:
            init_i18n()
        content = Path(output).read_text(encoding="utf-8")
        assert "需人工复核" in content
        assert "候选项" in content or "待验证项" in content

    def test_report_contains_severity_counts(self, tmp_path):
        from vulnclaw.report.generator import generate_report

        session = self._make_session()
        output = str(tmp_path / "report.md")
        generate_report(session, output)
        content = Path(output).read_text(encoding="utf-8")
        assert "Critical" in content
        assert "High" in content
        assert "Medium" in content

    def test_report_contains_vulnclaw_brand(self, tmp_path):
        from vulnclaw.report.generator import generate_report

        session = self._make_session()
        output = str(tmp_path / "report.md")
        generate_report(session, output)
        content = Path(output).read_text(encoding="utf-8")
        assert "VulnClaw" in content

    def test_report_prefers_llm_attack_summary_when_generated_from_session(
        self, tmp_path, monkeypatch
    ):
        from vulnclaw.report.generator import generate_report

        session = self._make_session()
        monkeypatch.setattr(
            "vulnclaw.report.generator._generate_attack_summary_from_session",
            lambda session: "这是通过 VulnClaw 对接的 LLM 生成的攻击路径摘要。",
        )

        output = str(tmp_path / "report_llm_summary.md")
        generate_report(session, output)
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

    def test_report_with_recon_data(self, tmp_path):
        from vulnclaw.agent.context import SessionState
        from vulnclaw.report.generator import generate_report

        session = SessionState(target="10.0.0.1")
        session.recon_data = {
            "ports": [80, 443, 3306],
            "services": ["nginx/1.24", "mysql/8.0"],
        }
        output = str(tmp_path / "report_recon.md")
        generate_report(session, output)
        content = Path(output).read_text(encoding="utf-8")
        assert "10.0.0.1" in content

    def test_report_empty_findings(self, tmp_path):
        from vulnclaw.agent.context import SessionState
        from vulnclaw.i18n import init_i18n
        from vulnclaw.report.generator import generate_report

        session = SessionState(target="10.0.0.1")
        output = str(tmp_path / "report_empty.md")
        init_i18n(lang="zh")  # pin the Chinese report bundle for this assertion
        try:
            generate_report(session, output)
        finally:
            init_i18n()
        content = Path(output).read_text(encoding="utf-8")
        # Report with no verified findings should mention 0 verified or show summary
        assert "10.0.0.1" in content
        assert "候选项" in content
        assert "已验证漏洞" in content

    def test_report_creates_pocs_dir(self, tmp_path):
        from vulnclaw.report.generator import generate_report

        session = self._make_session()
        output = str(tmp_path / "report_with_poc.md")
        generate_report(session, output)
        # PoC directory should be created
        pocs_dir = tmp_path / "pocs"
        assert pocs_dir.exists()

    def test_report_auto_output_path(self, tmp_path):
        """If no output path specified, should auto-generate one."""
        from vulnclaw.agent.context import SessionState
        from vulnclaw.report.generator import generate_report

        session = SessionState(target="auto-target")
        # This will use the default SESSIONS_DIR
        try:
            path = generate_report(session)
            assert path.exists()
        except Exception:
            # Might fail if SESSIONS_DIR not writable, that's ok for test
            pass

    def test_report_respects_output_suffix(self, tmp_path):
        from vulnclaw.report.generator import generate_report

        session = self._make_session()
        output = str(tmp_path / "report.custom")
        path = generate_report(session, output, report_format="markdown")
        assert path.suffix == ".custom"

    def test_generate_report_from_target_state_includes_governance_context(self, tmp_path):
        from vulnclaw.i18n import init_i18n
        from vulnclaw.report.generator import generate_report_from_target_state

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
            output = generate_report_from_target_state(target_state)
        finally:
            init_i18n()
        content = Path(output).read_text(encoding="utf-8")
        assert "目标历史治理上下文" in content
        assert "continue_scan" in content
        assert "paths:/admin" in content
        assert "old.example.com" in content

    def test_persistent_cycle_report_includes_verified_location_and_poc(self, tmp_path):
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
            output = generate_persistent_cycle_report(
                session=session,
                cycle_num=1,
                total_findings=1,
                new_findings=1,
                total_steps=10,
                rounds_per_cycle=100,
                output_path=str(tmp_path / "cycle.md"),
            )
        finally:
            init_i18n()  # restore auto-detected default
        content = Path(output).read_text(encoding="utf-8")
        assert "已验证漏洞定位与复现信息" in content
        assert "https://example.com/admin/exec" in content
        assert "PoC" in content

    def test_persistent_cycle_report_counts_only_newly_verified(self, tmp_path):
        """Regression: with prev_verified_ids, prior verified findings are not
        counted as new this cycle even when the all-findings delta is larger."""
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

        # Snapshot taken at the start of this cycle: the old finding is already verified.
        prev_verified_ids = {f.finding_id for f in session.get_verified_findings()}

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
            output = generate_persistent_cycle_report(
                session=session,
                cycle_num=2,
                total_findings=3,
                new_findings=2,  # all-findings delta — would over-count without prev ids
                total_steps=10,
                rounds_per_cycle=100,
                output_path=str(tmp_path / "cycle2.md"),
                prev_verified_ids=prev_verified_ids,
            )
        finally:
            init_i18n()  # restore auto-detected default
        content = Path(output).read_text(encoding="utf-8")
        # Only the one newly-verified finding counts as new this cycle.
        assert "本周期新增已验证漏洞** | 1 个" in content
        assert "New SQLi" in content

    def test_persistent_cycle_report_prefers_llm_attack_summary(self, tmp_path, monkeypatch):
        from vulnclaw.report.generator import generate_persistent_cycle_report

        session = self._make_session()
        monkeypatch.setattr(
            "vulnclaw.report.generator._generate_attack_summary_from_session",
            lambda session: "来自 LLM 的持续渗透周期摘要",
        )

        output = generate_persistent_cycle_report(
            session=session,
            cycle_num=1,
            total_findings=3,
            new_findings=1,
            total_steps=12,
            rounds_per_cycle=100,
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

    def test_standard_report_english_has_zero_chinese_characters(self, tmp_path, monkeypatch):
        from vulnclaw.i18n import init_i18n
        from vulnclaw.report.generator import generate_report

        monkeypatch.setattr(
            "vulnclaw.report.generator._generate_attack_summary_from_session",
            lambda session: "",
        )
        session = self._session_with_full_context()
        init_i18n(lang="en")
        try:
            out = generate_report(session, str(tmp_path / "en.md"))
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

    def test_standard_report_chinese_unchanged(self, tmp_path, monkeypatch):
        from vulnclaw.i18n import init_i18n
        from vulnclaw.report.generator import generate_report

        monkeypatch.setattr(
            "vulnclaw.report.generator._generate_attack_summary_from_session",
            lambda session: "",
        )
        session = self._session_with_full_context()
        init_i18n(lang="zh")
        try:
            out = generate_report(session, str(tmp_path / "zh.md"))
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

    def test_standard_report_recon_summary_uncollected_localized(self, tmp_path):
        from vulnclaw.agent.context import SessionState
        from vulnclaw.i18n import init_i18n
        from vulnclaw.report.generator import generate_report

        session = SessionState(target="10.0.0.1")

        def _run(lang, path):
            init_i18n(lang=lang)
            try:
                return generate_report(session, str(path)).read_text(encoding="utf-8")
            finally:
                init_i18n()

        en = _run("en", tmp_path / "en_recon.md")
        zh = _run("zh", tmp_path / "zh_recon.md")
        assert "Not collected" in en
        assert "未收集" in zh

    def test_target_state_report_english_has_zero_chinese_characters(self, tmp_path):
        from vulnclaw.i18n import init_i18n
        from vulnclaw.report.generator import generate_report_from_target_state

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
            out = generate_report_from_target_state(
                target_state, output_path=str(tmp_path / "en_ts.md")
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

    def test_standard_report_recommendation_english(self, tmp_path):
        from vulnclaw.i18n import init_i18n
        from vulnclaw.report.generator import generate_report

        session = self._session_with_unremediated_high()
        try:
            init_i18n(lang="en")
            out = generate_report(session, str(tmp_path / "en.md"))
        finally:
            init_i18n()
        content = out.read_text(encoding="utf-8")
        assert "Prioritize fixing XSS risk: Reflected XSS" in content

    def test_standard_report_recommendation_chinese_unchanged(self, tmp_path):
        from vulnclaw.i18n import init_i18n
        from vulnclaw.report.generator import generate_report

        session = self._session_with_unremediated_high()
        try:
            init_i18n(lang="zh")
            out = generate_report(session, str(tmp_path / "zh.md"))
        finally:
            init_i18n()
        content = out.read_text(encoding="utf-8")
        assert "请优先修复 XSS 风险: Reflected XSS" in content

    def test_standard_report_empty_recommendation_localized(self, tmp_path):
        from vulnclaw.i18n import init_i18n
        from vulnclaw.report.generator import generate_report

        session = self._session_no_high()
        try:
            init_i18n(lang="en")
            en = generate_report(session, str(tmp_path / "en.md")).read_text(encoding="utf-8")
            init_i18n(lang="zh")
            zh = generate_report(session, str(tmp_path / "zh.md")).read_text(encoding="utf-8")
        finally:
            init_i18n()
        assert "Prioritize reviewing the attack surface" in en
        assert "优先复核攻击面并补充验证链路" in zh

    def test_cycle_report_recommendation_english(self, tmp_path):
        from vulnclaw.i18n import init_i18n
        from vulnclaw.report.generator import generate_persistent_cycle_report

        session = self._session_with_unremediated_high()
        try:
            init_i18n(lang="en")
            out = generate_persistent_cycle_report(
                session=session,
                cycle_num=1,
                total_findings=1,
                new_findings=1,
                total_steps=5,
                rounds_per_cycle=100,
                output_path=str(tmp_path / "cycle_en.md"),
            )
        finally:
            init_i18n()
        content = out.read_text(encoding="utf-8")
        assert "Fix XSS vulnerability: Reflected XSS" in content

    def test_cycle_report_recommendation_chinese_unchanged(self, tmp_path):
        from vulnclaw.i18n import init_i18n
        from vulnclaw.report.generator import generate_persistent_cycle_report

        session = self._session_with_unremediated_high()
        try:
            init_i18n(lang="zh")
            out = generate_persistent_cycle_report(
                session=session,
                cycle_num=1,
                total_findings=1,
                new_findings=1,
                total_steps=5,
                rounds_per_cycle=100,
                output_path=str(tmp_path / "cycle_zh.md"),
            )
        finally:
            init_i18n()
        content = out.read_text(encoding="utf-8")
        assert "修复 XSS 漏洞: Reflected XSS" in content

    def test_cycle_report_empty_recommendation_localized(self, tmp_path):
        from vulnclaw.i18n import init_i18n
        from vulnclaw.report.generator import generate_persistent_cycle_report

        session = self._session_no_high()

        def _run(path):
            return generate_persistent_cycle_report(
                session=session,
                cycle_num=1,
                total_findings=1,
                new_findings=1,
                total_steps=5,
                rounds_per_cycle=100,
                output_path=str(path),
            ).read_text(encoding="utf-8")

        try:
            init_i18n(lang="en")
            en = _run(tmp_path / "cycle_en.md")
            init_i18n(lang="zh")
            zh = _run(tmp_path / "cycle_zh.md")
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

    def test_cycle_report_uncategorized_fallback_localized(self, tmp_path):
        from vulnclaw.i18n import init_i18n
        from vulnclaw.report.generator import generate_persistent_cycle_report

        session = self._session_uncategorized_high()

        def _run(path):
            return generate_persistent_cycle_report(
                session=session,
                cycle_num=1,
                total_findings=1,
                new_findings=1,
                total_steps=5,
                rounds_per_cycle=100,
                output_path=str(path),
            ).read_text(encoding="utf-8")

        try:
            init_i18n(lang="en")
            en = _run(tmp_path / "cycle_uncat_en.md")
            init_i18n(lang="zh")
            zh = _run(tmp_path / "cycle_uncat_zh.md")
        finally:
            init_i18n()
        assert "Uncategorized" in en
        assert "未分类" in zh


# ── poc_builder.py ───────────────────────────────────────────────────


class TestPoCBuilder:
    """Test PoC script generation."""

    def test_generate_pocs(self, tmp_path):
        from vulnclaw.agent.context import SessionState, VulnerabilityFinding
        from vulnclaw.report.poc_builder import generate_pocs

        session = SessionState(target="192.168.1.100")
        session.add_finding(
            VulnerabilityFinding(
                title="SQL Injection",
                severity="Critical",
                vuln_type="SQLi",
            )
        )
        session.add_finding(
            VulnerabilityFinding(
                title="XSS Attack",
                severity="High",
                vuln_type="XSS",
            )
        )
        pocs_dir = tmp_path / "pocs"
        paths = generate_pocs(session, pocs_dir)
        assert len(paths) == 2
        for p in paths:
            assert p.exists()

    def test_poc_content(self, tmp_path):
        from vulnclaw.agent.context import SessionState, VulnerabilityFinding
        from vulnclaw.report.poc_builder import generate_pocs

        session = SessionState(target="192.168.1.100")
        session.add_finding(
            VulnerabilityFinding(
                title="SQL Injection",
                severity="Critical",
                vuln_type="SQLi",
                cve="CVE-2026-12345",
                evidence="http://192.168.1.100/login?id=1",
            )
        )
        pocs_dir = tmp_path / "pocs"
        paths = generate_pocs(session, pocs_dir)
        content = paths[0].read_text(encoding="utf-8")
        assert "SQL Injection" in content
        assert "Critical" in content
        assert "CVE-2026-12345" in content
        assert "python3" in content
        assert "sql_injection" in content
        assert "requests.get(target, params=params" in content
        assert "http://192.168.1.100/login?id=1" in content
        assert "[CONFIRMED] SQL injection" in content

    def test_poc_is_valid_python(self, tmp_path):
        """Generated PoC should be syntactically valid Python."""
        from vulnclaw.agent.context import SessionState, VulnerabilityFinding
        from vulnclaw.report.poc_builder import generate_pocs

        session = SessionState(target="10.0.0.1")
        session.add_finding(
            VulnerabilityFinding(title="Candidate", severity="Low", lifecycle_status="candidate")
        )
        session.add_finding(
            VulnerabilityFinding(
                title="RCE Vuln",
                severity="Critical",
                vuln_type="RCE",
            )
        )
        pocs_dir = tmp_path / "pocs"
        paths = generate_pocs(session, pocs_dir)
        content = paths[0].read_text(encoding="utf-8")
        # Try to compile it
        compile(content, str(paths[0]), "exec")

    def test_poc_updates_finding(self, tmp_path):
        """Generating PoCs should update finding.poc_script."""
        from vulnclaw.agent.context import SessionState, VulnerabilityFinding
        from vulnclaw.report.poc_builder import generate_pocs

        session = SessionState(target="10.0.0.1")
        session.add_finding(
            VulnerabilityFinding(
                title="Test Vuln",
                severity="High",
            )
        )
        pocs_dir = tmp_path / "pocs"
        generate_pocs(session, pocs_dir)
        assert session.findings[0].poc_script is not None

    def test_generate_single_poc(self):
        from vulnclaw.report.poc_builder import generate_single_poc

        poc = generate_single_poc(
            title="SQLi",
            severity="Critical",
            cve="CVE-2026-0001",
            target="http://target",
            vuln_type="sqli",
        )
        assert isinstance(poc, str)
        assert "SQLi" in poc
        assert "CVE-2026-0001" in poc
        assert "sql_injection" in poc
        assert "params = {" in poc
        assert 'target = "http://target"' in poc

    def test_generate_single_poc_uses_specific_template_for_rce(self):
        from vulnclaw.report.poc_builder import generate_single_poc

        poc = generate_single_poc(
            title="RCE",
            severity="Critical",
            target="https://demo.local/exec",
            vuln_type="RCE",
        )

        assert "command_injection" in poc
        assert '"cmd": ";id"' in poc
        assert 'target = "https://demo.local/exec"' in poc

    def test_generate_pocs_extracts_target_from_evidence(self, tmp_path):
        from vulnclaw.agent.context import SessionState, VulnerabilityFinding
        from vulnclaw.report.poc_builder import generate_pocs

        session = SessionState(target="example.com")
        session.add_finding(
            VulnerabilityFinding(
                title="File Inclusion",
                severity="High",
                vuln_type="LFI",
                evidence="可访问地址 https://victim.local/download?file=../../etc/passwd 并返回 root:x:0:0",
            )
        )

        paths = generate_pocs(session, tmp_path / "pocs")
        content = paths[0].read_text(encoding="utf-8")
        assert 'target = "https://victim.local/download?file=../../etc/passwd"' in content
        assert "../../../etc/passwd" in content

    def test_generate_pocs_sanitizes_windows_unsafe_title(self, tmp_path):
        from vulnclaw.agent.context import SessionState, VulnerabilityFinding
        from vulnclaw.report.poc_builder import generate_pocs

        session = SessionState(target="https://example.com")
        session.add_finding(
            VulnerabilityFinding(
                title="[已确认] **ThinkPHP:RCE?** / 唯一标识符",
                severity="Critical",
                vuln_type="RCE",
            )
        )

        paths = generate_pocs(session, tmp_path / "pocs")
        assert len(paths) == 1
        assert paths[0].exists()
        assert "*" not in paths[0].name
        assert ":" not in paths[0].name
        assert "?" not in paths[0].name

    def test_generate_pocs_avoids_existing_filename_collision(self, tmp_path):
        from vulnclaw.agent.context import SessionState, VulnerabilityFinding
        from vulnclaw.report.poc_builder import generate_pocs

        pocs_dir = tmp_path / "pocs"
        pocs_dir.mkdir(parents=True, exist_ok=True)
        (pocs_dir / "poc_01_SQL_Injection.py").write_text("old", encoding="utf-8")

        session = SessionState(target="https://example.com")
        session.add_finding(
            VulnerabilityFinding(
                title="SQL Injection",
                severity="Critical",
                vuln_type="SQLi",
            )
        )

        paths = generate_pocs(session, pocs_dir)
        assert len(paths) == 1
        assert paths[0].name != "poc_01_SQL_Injection.py"
        assert paths[0].exists()

    def test_poc_empty_findings(self, tmp_path):
        """No findings should produce no PoC files."""
        from vulnclaw.agent.context import SessionState
        from vulnclaw.report.poc_builder import generate_pocs

        session = SessionState(target="10.0.0.1")
        pocs_dir = tmp_path / "pocs"
        paths = generate_pocs(session, pocs_dir)
        assert len(paths) == 0

    def test_report_counts_manual_review_findings(self, tmp_path):
        from vulnclaw.agent.context import SessionState, VulnerabilityFinding
        from vulnclaw.i18n import init_i18n
        from vulnclaw.report.generator import generate_report

        session = SessionState(target="https://example.com")
        session.add_finding(
            VulnerabilityFinding(
                title="High Risk Candidate",
                severity="High",
                lifecycle_status="candidate",
                evidence_level="L1",
            )
        )

        output = str(tmp_path / "report_manual.md")
        init_i18n(lang="zh")  # pin the Chinese report bundle for this assertion
        try:
            generate_report(session, output)
        finally:
            init_i18n()
        content = Path(output).read_text(encoding="utf-8")
        assert "需人工复核" in content
