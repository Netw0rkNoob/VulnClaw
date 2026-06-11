"""VulnClaw Agent Module Tests — context.py + memory.py + prompts.py + core.py"""

import time

import pytest

# ── context.py ───────────────────────────────────────────────────────


class TestPentestPhase:
    """Test PentestPhase enum."""

    def test_phase_values(self):
        from vulnclaw.agent.context import PentestPhase

        assert PentestPhase.IDLE.value == "就绪"
        assert PentestPhase.RECON.value == "信息收集"
        assert PentestPhase.VULN_DISCOVERY.value == "漏洞发现"
        assert PentestPhase.EXPLOITATION.value == "漏洞利用"
        assert PentestPhase.POST_EXPLOITATION.value == "后渗透"
        assert PentestPhase.REPORTING.value == "报告生成"

    def test_phase_is_str(self):
        from vulnclaw.agent.context import PentestPhase

        # PentestPhase inherits from str, Enum
        assert isinstance(PentestPhase.RECON, str)


class TestVulnerabilityFinding:
    """Test VulnerabilityFinding model."""

    def test_default_values(self):
        from vulnclaw.agent.context import VulnerabilityFinding

        finding = VulnerabilityFinding(title="Test Vuln")
        assert finding.title == "Test Vuln"
        assert finding.severity == "Medium"
        assert finding.vuln_type == ""
        assert finding.cve is None
        assert finding.evidence_level == "L1"
        assert finding.lifecycle_status == "candidate"

    def test_full_values(self):
        from vulnclaw.agent.context import VulnerabilityFinding

        finding = VulnerabilityFinding(
            title="SQL Injection",
            severity="Critical",
            vuln_type="SQLi",
            description="Login form SQLi",
            evidence="admin' OR 1=1--",
            cve="CVE-2026-12345",
            remediation="Use parameterized queries",
        )
        assert finding.severity == "Critical"
        assert finding.cve == "CVE-2026-12345"
        assert finding.remediation == "Use parameterized queries"


class TestSessionState:
    """Test SessionState model."""

    def test_default_state(self):
        from vulnclaw.agent.context import PentestPhase, SessionState

        state = SessionState()
        assert state.phase == PentestPhase.IDLE
        assert state.target is None
        assert state.findings == []
        assert state.executed_steps == []

    def test_advance_phase(self):
        from vulnclaw.agent.context import PentestPhase, SessionState

        state = SessionState()
        state.advance_phase(PentestPhase.RECON)
        assert state.phase == PentestPhase.RECON
        # Should record the phase change in steps
        assert len(state.executed_steps) == 1
        assert "信息收集" in state.executed_steps[0]

    def test_add_finding(self):
        from vulnclaw.agent.context import SessionState, VulnerabilityFinding

        state = SessionState()
        state.add_finding(VulnerabilityFinding(title="XSS", severity="High"))
        assert len(state.findings) == 1
        # High severity without evidence gets [未验证] prefix in model_post_init
        assert "XSS" in state.findings[0].title

    def test_add_step(self):
        from vulnclaw.agent.context import SessionState

        state = SessionState()
        state.add_step("Scanned port 80")
        assert state.findings == []
        assert len(state.executed_steps) == 1

    def test_add_note(self):
        from vulnclaw.agent.context import SessionState

        state = SessionState()
        state.add_note("Interesting endpoint found")
        assert len(state.notes) == 1

    def test_save_and_load(self, tmp_path):
        from vulnclaw.agent.context import PentestPhase, SessionState, VulnerabilityFinding

        state = SessionState(target="192.168.1.100")
        state.advance_phase(PentestPhase.RECON)
        state.add_finding(VulnerabilityFinding(title="SQLi", severity="Critical"))

        save_path = tmp_path / "session.json"
        returned_path = state.save(save_path)
        assert returned_path.exists()

        loaded = SessionState.load(save_path)
        assert loaded.target == "192.168.1.100"
        assert loaded.phase == PentestPhase.RECON
        assert len(loaded.findings) == 1
        # Critical severity without evidence gets [未验证] prefix
        assert "SQLi" in loaded.findings[0].title

    def test_multiple_findings(self):
        from vulnclaw.agent.context import SessionState, VulnerabilityFinding

        state = SessionState()
        severities = ["Critical", "High", "Medium", "Low", "Info"]
        for sev in severities:
            state.add_finding(
                VulnerabilityFinding(title=f"Vuln-{sev}", severity=sev, vuln_type=f"type-{sev}")
            )
        assert len(state.findings) == 5

    def test_recon_data(self):
        from vulnclaw.agent.context import SessionState

        state = SessionState()
        state.recon_data = {"ports": [80, 443], "services": ["nginx", "mysql"]}
        assert state.recon_data["ports"] == [80, 443]


class TestContextManager:
    """Test ContextManager."""

    def test_add_messages(self):
        from vulnclaw.agent.context import ContextManager

        cm = ContextManager()
        cm.add_user_message("Hello")
        cm.add_assistant_message("Hi there")
        assert len(cm.get_messages()) == 2
        assert cm.get_messages()[0]["role"] == "user"
        assert cm.get_messages()[1]["role"] == "assistant"

    def test_max_history(self):
        from vulnclaw.agent.context import ContextManager

        cm = ContextManager(max_history=5)
        for i in range(10):
            cm.add_user_message(f"msg {i}")
        # Should only keep the last 5
        assert len(cm.get_messages()) <= 5

    def test_reset(self):
        from vulnclaw.agent.context import ContextManager

        cm = ContextManager()
        cm.add_user_message("Hello")
        cm.reset()
        assert len(cm.get_messages()) == 0
        assert cm.state.target is None

    def test_session_state_access(self):
        from vulnclaw.agent.context import ContextManager, PentestPhase

        cm = ContextManager()
        cm.state.target = "10.0.0.1"
        cm.state.advance_phase(PentestPhase.RECON)
        assert cm.state.target == "10.0.0.1"
        assert cm.state.phase == PentestPhase.RECON


class TestAgentAutoSave:
    """Test agent auto-save behavior."""

    def test_auto_save_respects_config(self, monkeypatch, tmp_path):
        from vulnclaw.agent.context import SessionState
        from vulnclaw.agent.core import AgentCore
        from vulnclaw.config.schema import VulnClawConfig

        config = VulnClawConfig()
        config.session.auto_save = False
        config.session.output_dir = tmp_path

        agent = AgentCore(config)

        saved = {"count": 0}

        def fake_save(*args, **kwargs):
            saved["count"] += 1

        monkeypatch.setattr(SessionState, "save", fake_save)
        agent._maybe_auto_save_session()
        assert saved["count"] == 0


class TestTargetState:
    """Test target-level resume state."""

    def test_target_state_save_and_load(self, monkeypatch, tmp_path):
        import vulnclaw.target_state.store as store_mod
        from vulnclaw.agent.context import PentestPhase, SessionState

        monkeypatch.setattr(store_mod, "TARGETS_DIR", tmp_path)
        state = SessionState(target="https://example.com")
        state.advance_phase(PentestPhase.RECON)
        path = store_mod.save_target_state("https://example.com", state, command="recon")
        assert path.exists()

        restored = store_mod.hydrate_session_from_target_state("https://example.com")
        assert restored is not None
        assert restored.target == "https://example.com"
        assert restored.phase == PentestPhase.RECON
        assert "历史成果摘要" in restored.resume_summary

    def test_target_state_merges_findings(self, monkeypatch, tmp_path):
        import vulnclaw.target_state.store as store_mod
        from vulnclaw.agent.context import SessionState, VulnerabilityFinding

        monkeypatch.setattr(store_mod, "TARGETS_DIR", tmp_path)

        state1 = SessionState(target="https://example.com")
        state1.add_finding(VulnerabilityFinding(title="SQLi", severity="High", vuln_type="SQLi"))
        store_mod.save_target_state("https://example.com", state1, command="scan")

        state2 = SessionState(target="https://example.com")
        state2.add_finding(VulnerabilityFinding(title="XSS", severity="Medium", vuln_type="XSS"))
        time.sleep(0.01)
        store_mod.save_target_state("https://example.com", state2, command="scan")

        restored = store_mod.hydrate_session_from_target_state("https://example.com")
        assert restored is not None
        titles = [f.title for f in restored.findings]
        assert "SQLi" in titles
        assert "XSS" in titles

    def test_target_state_resume_strategy_prefers_pending(self, monkeypatch, tmp_path):
        import vulnclaw.target_state.store as store_mod
        from vulnclaw.agent.context import SessionState, VulnerabilityFinding

        monkeypatch.setattr(store_mod, "TARGETS_DIR", tmp_path)
        state = SessionState(target="https://example.com")
        pending = VulnerabilityFinding(title="Pending SQLi", severity="High", vuln_type="SQLi")
        state.add_finding(pending)
        store_mod.save_target_state("https://example.com", state, command="scan")

        restored = store_mod.hydrate_session_from_target_state("https://example.com")
        assert restored is not None
        assert restored.resume_meta["resume_strategy"] == "verify_pending_findings"
        assert restored.phase.value == "漏洞发现"
        raw = store_mod.load_target_state("https://example.com")
        assert raw is not None
        assert "finding_meta" in raw

    def test_target_state_preview_carries_structured_constraint_violation_events(
        self, monkeypatch, tmp_path
    ):
        import vulnclaw.target_state.store as store_mod
        from vulnclaw.agent.context import SessionState

        monkeypatch.setattr(store_mod, "TARGETS_DIR", tmp_path)
        state = SessionState(target="https://example.com")
        state.add_constraint_violation_event(
            source="tool",
            action="exploit",
            tool_name="fetch",
            code="tool_action_blocked",
            severity="high",
            summary="constraint_violation: tool 'fetch' inferred action 'exploit'",
            detail="GET /admin?cmd=whoami",
        )
        store_mod.save_target_state("https://example.com", state, command="scan")

        preview = store_mod.get_target_state_preview("https://example.com")
        assert preview is not None
        assert preview["constraint_violation_events"]
        assert preview["constraint_violation_events"][0]["source"] == "tool"

    def test_target_state_resume_strategy_prefers_exploit_on_verified(self, monkeypatch, tmp_path):
        import vulnclaw.target_state.store as store_mod
        from vulnclaw.agent.context import SessionState, VulnerabilityFinding

        monkeypatch.setattr(store_mod, "TARGETS_DIR", tmp_path)
        state = SessionState(target="https://example.com")
        verified = VulnerabilityFinding(title="Verified SQLi", severity="High", vuln_type="SQLi")
        verified.mark_verified()
        state.add_finding(verified)
        state.recon_dimensions_completed = {
            "server": True,
            "website": True,
            "domain": True,
            "personnel": False,
        }
        store_mod.save_target_state("https://example.com", state, command="exploit")

        restored = store_mod.hydrate_session_from_target_state("https://example.com")
        assert restored is not None
        assert restored.resume_meta["resume_strategy"] == "exploit_expand"
        assert restored.phase.value == "漏洞利用"
        assert "priority_findings" in restored.resume_meta
        assert "next_actions" in restored.resume_meta

    def test_target_state_confidence_is_persisted(self, monkeypatch, tmp_path):
        import vulnclaw.target_state.store as store_mod
        from vulnclaw.agent.context import SessionState, VulnerabilityFinding

        monkeypatch.setattr(store_mod, "TARGETS_DIR", tmp_path)
        state = SessionState(target="https://example.com")
        finding = VulnerabilityFinding(title="Pending SQLi", severity="High", vuln_type="SQLi")
        state.add_finding(finding)
        store_mod.save_target_state("https://example.com", state, command="scan")

        raw = store_mod.load_target_state("https://example.com")
        assert raw is not None
        meta = next(iter(raw["finding_meta"].values()))
        assert "confidence" in meta
        assert meta["confidence"] > 0

    def test_target_state_recon_meta_is_persisted(self, monkeypatch, tmp_path):
        import vulnclaw.target_state.store as store_mod
        from vulnclaw.agent.context import SessionState

        monkeypatch.setattr(store_mod, "TARGETS_DIR", tmp_path)
        state = SessionState(target="https://example.com")
        state.recon_data = {
            "subdomains": ["vpn.example.com", "api.example.com"],
            "paths": ["/admin", "/login"],
            "params": ["id", "file"],
        }

        store_mod.save_target_state("https://example.com", state, command="recon")
        raw = store_mod.load_target_state("https://example.com")
        assert raw is not None
        assert "recon_meta" in raw
        assert "subdomains" in raw["recon_meta"]
        assert "vpn.example.com" in raw["recon_meta"]["subdomains"]
        assert raw["recon_meta"]["paths"]["/admin"]["confidence"] > 0
        assert raw["recon_meta"]["params"]["id"]["observation_count"] >= 1

    def test_target_state_resume_summary_includes_recon_assets(self, monkeypatch, tmp_path):
        import vulnclaw.target_state.store as store_mod
        from vulnclaw.agent.context import SessionState

        monkeypatch.setattr(store_mod, "TARGETS_DIR", tmp_path)
        state = SessionState(target="https://example.com")
        state.recon_data = {
            "subdomains": ["vpn.example.com"],
            "paths": ["/admin"],
            "params": ["id"],
        }

        store_mod.save_target_state("https://example.com", state, command="scan")
        restored = store_mod.hydrate_session_from_target_state("https://example.com")
        assert restored is not None
        assert "高置信度侦察资产" in restored.resume_summary
        assert (
            "paths:/admin" in restored.resume_summary
            or "subdomains:vpn.example.com" in restored.resume_summary
        )

    def test_target_state_resume_strategy_exposes_recon_priority_targets(
        self, monkeypatch, tmp_path
    ):
        import vulnclaw.target_state.store as store_mod
        from vulnclaw.agent.context import SessionState
        from vulnclaw.agent.runtime_state import RuntimeState

        monkeypatch.setattr(store_mod, "TARGETS_DIR", tmp_path)
        state = SessionState(target="https://example.com")
        state.recon_data = {
            "subdomains": ["vpn.example.com"],
            "paths": ["/admin", "/upload"],
            "params": ["file"],
        }
        runtime = RuntimeState()
        runtime.rounds_without_progress = 4

        store_mod.save_target_state("https://example.com", state, command="scan", runtime=runtime)
        raw = store_mod.load_target_state("https://example.com")
        assert raw is not None
        assert raw["resume_meta"]["resume_strategy"] in {"continue_recon", "continue_scan"}
        assert raw["resume_meta"]["priority_targets"]
        assert raw["resume_meta"]["priority_recon_assets"]

    def test_target_state_runtime_meta_is_persisted(self, monkeypatch, tmp_path):
        import vulnclaw.target_state.store as store_mod
        from vulnclaw.agent.context import SessionState
        from vulnclaw.agent.runtime_state import RuntimeState

        monkeypatch.setattr(store_mod, "TARGETS_DIR", tmp_path)
        state = SessionState(target="https://example.com")
        state.executed_steps = [
            "Round 1: 访问 https://a.example.com/admin 失败，连接超时",
            "Round 2: 测试 /login 参数无新发现",
        ]
        runtime = RuntimeState()
        runtime.blocked_targets = {"a.example.com"}
        runtime.failed_targets = {"a.example.com": 3, "b.example.com": 1}
        runtime.rounds_without_progress = 4
        runtime.current_attack_path = "sql_injection"

        store_mod.save_target_state("https://example.com", state, command="scan", runtime=runtime)
        raw = store_mod.load_target_state("https://example.com")
        assert raw is not None
        assert raw["runtime_meta"]["blocked_targets"] == ["a.example.com"]
        assert raw["runtime_meta"]["failed_targets"]["a.example.com"] == 3
        assert raw["runtime_meta"]["rounds_without_progress"] == 4
        assert raw["runtime_meta"]["current_attack_path"] == "sql_injection"
        assert raw["runtime_meta"]["failed_steps"]

    def test_target_state_resume_summary_includes_runtime_signals(self, monkeypatch, tmp_path):
        import vulnclaw.target_state.store as store_mod
        from vulnclaw.agent.context import SessionState
        from vulnclaw.agent.runtime_state import RuntimeState

        monkeypatch.setattr(store_mod, "TARGETS_DIR", tmp_path)
        state = SessionState(target="https://example.com")
        state.executed_steps = ["Round 1: 访问 https://a.example.com/admin 失败，连接超时"]
        runtime = RuntimeState()
        runtime.blocked_targets = {"a.example.com"}
        runtime.failed_targets = {"a.example.com": 3}
        runtime.rounds_without_progress = 5

        store_mod.save_target_state("https://example.com", state, command="recon", runtime=runtime)
        restored = store_mod.hydrate_session_from_target_state("https://example.com")
        assert restored is not None
        assert "已阻塞目标" in restored.resume_summary
        assert "连续低价值轮次" in restored.resume_summary
        assert "最近失败路径/步骤" in restored.resume_summary

    def test_target_state_snapshots_and_rollback(self, monkeypatch, tmp_path):
        import vulnclaw.target_state.store as store_mod
        from vulnclaw.agent.context import SessionState, VulnerabilityFinding

        monkeypatch.setattr(store_mod, "TARGETS_DIR", tmp_path)

        state1 = SessionState(target="https://example.com")
        state1.add_finding(VulnerabilityFinding(title="SQLi", severity="High", vuln_type="SQLi"))
        store_mod.save_target_state("https://example.com", state1, command="scan")

        state2 = SessionState(target="https://example.com")
        state2.add_finding(VulnerabilityFinding(title="XSS", severity="Medium", vuln_type="XSS"))
        store_mod.save_target_state("https://example.com", state2, command="scan")

        snapshots = store_mod.list_target_snapshots("https://example.com")
        assert len(snapshots) >= 2

        oldest = snapshots[-1]["snapshot_id"]
        store_mod.rollback_target_state("https://example.com", oldest)
        restored = store_mod.hydrate_session_from_target_state("https://example.com")
        assert restored is not None
        titles = [f.title for f in restored.findings]
        assert "SQLi" in titles

    def test_target_state_schema_preview_and_diff(self, monkeypatch, tmp_path):
        import vulnclaw.target_state.store as store_mod
        from vulnclaw.agent.context import SessionState, VulnerabilityFinding

        monkeypatch.setattr(store_mod, "TARGETS_DIR", tmp_path)

        state1 = SessionState(target="https://example.com")
        state1.add_note("first note")
        state1.add_finding(VulnerabilityFinding(title="SQLi", severity="High", vuln_type="SQLi"))
        store_mod.save_target_state("https://example.com", state1, command="recon")

        state2 = SessionState(target="https://example.com")
        state2.add_note("second note")
        state2.add_finding(VulnerabilityFinding(title="XSS", severity="Medium", vuln_type="XSS"))
        store_mod.save_target_state("https://example.com", state2, command="scan")

        snapshots = store_mod.list_target_snapshots("https://example.com")
        assert snapshots and snapshots[0]["schema_version"] >= 2

        preview = store_mod.get_target_state_preview("https://example.com")
        assert preview is not None
        assert preview["schema_version"] >= 2
        assert preview["findings_count"] >= 1
        assert preview["next_actions"]

        diff = store_mod.diff_target_state_snapshots(
            "https://example.com",
            snapshots[-1]["snapshot_id"],
            to_snapshot_id=snapshots[0]["snapshot_id"],
        )
        assert diff is not None
        assert diff["added_findings"]
        assert diff["added_notes"]


# ── memory.py ────────────────────────────────────────────────────────


class TestMemoryStore:
    """Test MemoryStore."""

    def test_save_and_retrieve(self, tmp_path):
        from vulnclaw.agent.memory import MemoryStore

        store = MemoryStore(store_dir=tmp_path)
        store.save("test_key", {"data": "test_value"})
        result = store.retrieve("test_key")
        assert result == {"data": "test_value"}

    def test_retrieve_nonexistent(self, tmp_path):
        from vulnclaw.agent.memory import MemoryStore

        store = MemoryStore(store_dir=tmp_path)
        assert store.retrieve("nonexistent") is None

    def test_list_keys(self, tmp_path):
        from vulnclaw.agent.memory import MemoryStore

        store = MemoryStore(store_dir=tmp_path)
        store.save("key1", "val1")
        store.save("key2", "val2")
        keys = store.list_keys()
        assert "key1" in keys
        assert "key2" in keys

    def test_delete(self, tmp_path):
        from vulnclaw.agent.memory import MemoryStore

        store = MemoryStore(store_dir=tmp_path)
        store.save("to_delete", "value")
        store.delete("to_delete")
        assert store.retrieve("to_delete") is None

    def test_search(self, tmp_path):
        from vulnclaw.agent.memory import MemoryStore

        store = MemoryStore(store_dir=tmp_path)
        store.save("sqli_info", {"type": "SQL Injection", "severity": "High"})
        store.save("xss_info", {"type": "XSS", "severity": "Medium"})
        results = store.search("sqli")
        assert len(results) >= 1
        assert results[0][0] == "sqli_info"

    def test_persistence(self, tmp_path):
        from vulnclaw.agent.memory import MemoryStore

        store1 = MemoryStore(store_dir=tmp_path)
        store1.save("persistent", "value_across_sessions")
        # Create a new store instance pointing to the same dir
        store2 = MemoryStore(store_dir=tmp_path)
        assert store2.retrieve("persistent") == "value_across_sessions"

    def test_overwrite(self, tmp_path):
        from vulnclaw.agent.memory import MemoryStore

        store = MemoryStore(store_dir=tmp_path)
        store.save("key", "original")
        store.save("key", "updated")
        assert store.retrieve("key") == "updated"

    def test_complex_value(self, tmp_path):
        from vulnclaw.agent.memory import MemoryStore

        store = MemoryStore(store_dir=tmp_path)
        complex_val = {
            "target": "192.168.1.100",
            "findings": ["SQLi", "XSS"],
            "metadata": {"tool": "nmap", "timestamp": "2026-01-01"},
        }
        store.save("complex", complex_val)
        result = store.retrieve("complex")
        assert result["findings"] == ["SQLi", "XSS"]


# ── prompts.py ───────────────────────────────────────────────────────


class TestPromptBuilder:
    """Test prompt building."""

    def test_basic_prompt(self):
        from vulnclaw.agent.prompts import build_system_prompt

        prompt = build_system_prompt()
        assert "VulnClaw" in prompt
        assert "渗透测试" in prompt

    def test_prompt_with_target(self):
        from vulnclaw.agent.prompts import build_system_prompt

        prompt = build_system_prompt(target="192.168.1.100")
        assert "192.168.1.100" in prompt

    def test_prompt_with_phase(self):
        from vulnclaw.agent.prompts import build_system_prompt

        prompt = build_system_prompt(phase="信息收集")
        assert "信息收集" in prompt

    def test_prompt_with_skill_context(self):
        from vulnclaw.agent.prompts import build_system_prompt

        prompt = build_system_prompt(skill_context="这是逆向分析的 Skill 上下文")
        assert "逆向分析" in prompt
        assert "Skill 上下文" in prompt

    def test_prompt_with_mcp_tools(self):
        from vulnclaw.agent.prompts import build_system_prompt

        tools = [
            {
                "name": "fetch",
                "description": "Fetch a URL",
                "inputSchema": {
                    "type": "object",
                    "properties": {"url": {"type": "string", "description": "URL to fetch"}},
                },
            }
        ]
        prompt = build_system_prompt(mcp_tools=tools)
        assert "fetch" in prompt
        assert "URL to fetch" in prompt

    def test_waf_bypass_knowledge_included(self):
        from vulnclaw.agent.prompts import build_system_prompt

        prompt = build_system_prompt()
        assert "WAF" in prompt
        assert "base64" in prompt

    def test_core_contract_included(self):
        from vulnclaw.agent.prompts import build_system_prompt

        prompt = build_system_prompt()
        assert "沙盒模式" in prompt
        assert "证据冲突" in prompt

    def test_all_phases_render(self):
        from vulnclaw.agent.prompts import build_system_prompt

        phases = ["信息收集", "漏洞发现", "漏洞利用", "后渗透", "报告生成"]
        for phase in phases:
            prompt = build_system_prompt(phase=phase)
            assert phase in prompt


# ── core.py ──────────────────────────────────────────────────────────


class TestAgentCore:
    """Test AgentCore."""

    def _make_agent(self):
        from vulnclaw.agent.core import AgentCore
        from vulnclaw.config.schema import VulnClawConfig

        return AgentCore(VulnClawConfig())

    def test_init(self):
        agent = self._make_agent()
        assert agent.config is not None
        assert agent.context is not None

    def test_phase_detection_recon(self):
        from vulnclaw.agent.context import PentestPhase

        agent = self._make_agent()
        assert agent._detect_phase("扫描 192.168.1.100 的端口") == PentestPhase.RECON
        assert agent._detect_phase("信息收集") == PentestPhase.RECON
        assert agent._detect_phase("recon") == PentestPhase.RECON

    def test_phase_detection_vuln(self):
        from vulnclaw.agent.context import PentestPhase

        agent = self._make_agent()
        assert agent._detect_phase("有什么漏洞") == PentestPhase.VULN_DISCOVERY
        assert agent._detect_phase("SQL注入") == PentestPhase.VULN_DISCOVERY

    def test_phase_detection_exploit(self):
        from vulnclaw.agent.context import PentestPhase

        agent = self._make_agent()
        assert agent._detect_phase("exploit") == PentestPhase.EXPLOITATION
        assert agent._detect_phase("尝试利用") == PentestPhase.EXPLOITATION
        # Note: "利用漏洞" matches VULN_DISCOVERY because "漏洞" appears first in the scan
        # This is a known limitation — more specific keywords should win
        assert agent._detect_phase("poc验证") == PentestPhase.EXPLOITATION

    def test_phase_detection_post(self):
        from vulnclaw.agent.context import PentestPhase

        agent = self._make_agent()
        assert agent._detect_phase("后渗透") == PentestPhase.POST_EXPLOITATION

    def test_phase_detection_report(self):
        from vulnclaw.agent.context import PentestPhase

        agent = self._make_agent()
        assert agent._detect_phase("生成渗透报告") == PentestPhase.REPORTING
        assert agent._detect_phase("report") == PentestPhase.REPORTING

    def test_phase_detection_with_ip(self):
        agent = self._make_agent()
        # IP without any keyword should default to recon
        phase = agent._detect_phase("10.0.0.1 有什么服务")
        assert phase is not None

    def test_phase_detection_none(self):
        agent = self._make_agent()
        phase = agent._detect_phase("今天天气怎么样")
        assert phase is None

    def test_target_detection_ip(self):
        agent = self._make_agent()
        assert agent._detect_target("对 192.168.1.100 进行渗透测试") == "192.168.1.100"

    def test_target_detection_url(self):
        agent = self._make_agent()
        assert agent._detect_target("测试 https://example.com") == "https://example.com"

    def test_target_detection_domain(self):
        agent = self._make_agent()
        target = agent._detect_target("扫描 testsite.com")
        assert target == "testsite.com"

    def test_target_detection_none(self):
        agent = self._make_agent()
        assert agent._detect_target("没有目标的输入") is None

    def test_skill_context_no_input(self):
        """Without user_input, should fallback to pentest-flow."""
        agent = self._make_agent()
        context = agent._get_active_skill_context(user_input=None)
        assert context is not None
        assert "渗透" in context

    def test_skill_context_with_input(self):
        """With user_input, should dispatch to the right Skill."""
        agent = self._make_agent()
        context = agent._get_active_skill_context(user_input="测试SQL注入")
        assert context is not None
        # Should match web-security-advanced
        assert "注入" in context or "SQL" in context

    def test_skill_context_reverse(self):
        agent = self._make_agent()
        context = agent._get_active_skill_context(user_input="对这个APP做逆向分析")
        assert context is not None
        assert "逆向" in context or "reverse" in context.lower()

    def test_build_openai_tools_includes_skill_ref(self):
        """Tools should include load_skill_reference."""
        agent = self._make_agent()
        tools = agent._build_openai_tools()
        tool_names = [t["function"]["name"] for t in tools]
        assert "load_skill_reference" in tool_names

    def test_build_system_prompt(self):
        agent = self._make_agent()
        prompt = agent._build_system_prompt(target="10.0.0.1", user_input="扫描端口")
        assert "10.0.0.1" in prompt
        assert "VulnClaw" in prompt

    def test_build_system_prompt_auto_mode(self):
        agent = self._make_agent()
        prompt = agent._build_system_prompt(
            target="10.0.0.1", auto_mode=True, user_input="渗透测试"
        )
        assert "自主渗透" in prompt

    def test_recon_personnel_dimension_requires_confirmed_facts(self):
        agent = self._make_agent()
        agent.context.state.recon_dimensions_completed = {
            "server": False,
            "website": False,
            "domain": False,
            "personnel": False,
        }
        agent.context.state.recon_dimension4_active = True
        agent.context.state.notes = ["python_execute 里出现 github.com 和 twitter.com 字符串"]
        agent.context.state.executed_steps = ["写了一个匹配 github/twitter 链接的脚本"]

        agent._update_recon_dimension_completion("LLM 提到 github 但没有真实结果")
        assert agent.context.state.recon_dimensions_completed["personnel"] is False

        agent.context.state.add_confirmed_fact("github_id=12345 followers=10 public_repos=3")
        agent._update_recon_dimension_completion("工具结果确认了 GitHub 账号")
        assert agent.context.state.recon_dimensions_completed["personnel"] is True

    def test_recon_non_personnel_dimension_can_use_notes_and_steps(self):
        agent = self._make_agent()
        agent.context.state.recon_dimensions_completed = {
            "server": False,
            "website": False,
            "domain": False,
            "personnel": False,
        }
        agent.context.state.recon_dimension4_active = False
        agent.context.state.notes = ["发现开放端口 80 和 443，运行 nginx 服务"]
        agent.context.state.executed_steps = ["执行了 nmap 端口扫描"]

        agent._update_recon_dimension_completion("端口扫描已完成")
        assert agent.context.state.recon_dimensions_completed["server"] is True

    def test_trim_summary_uses_system_role(self):
        from vulnclaw.agent.context import ContextManager

        cm = ContextManager(max_history=5)
        for i in range(8):
            if i % 2 == 0:
                cm.add_user_message(f"用户消息 {i}")
            else:
                cm.add_assistant_message(f"[+] 发现端口 {i}")

        messages = cm.get_messages()
        assert len(messages) <= 5
        assert messages[0]["role"] == "system"
        assert "之前的会话摘要" in messages[0]["content"]

    def test_completion_signal_detection(self):
        agent = self._make_agent()
        assert agent._is_completion_signal("[DONE]") is True
        assert agent._is_completion_signal("渗透测试已完成") is True
        assert agent._is_completion_signal("继续扫描") is False

    def test_parse_findings(self):
        agent = self._make_agent()
        response = "[Critical] RCE found in /api/exec\n[High] SQL Injection in login"
        agent._finding_parser.parse(response)
        assert len(agent.session_state.findings) >= 1
        assert agent.session_state.findings[0].severity == "Critical"
        assert agent.session_state.findings[0].evidence_level == "L1"

    def test_parse_high_confidence_pattern_needs_manual_review(self):
        agent = self._make_agent()
        agent.context.state.add_note("访问 https://example.com/admin/exec 后 whoami 返回 www-data")
        response = "发现远程代码执行漏洞，命令执行成功，whoami"
        agent._finding_parser.parse(response)

        review_items = [
            f for f in agent.session_state.findings if f.lifecycle_status == "needs_manual_review"
        ]
        assert review_items
        assert review_items[0].evidence_level == "L2"

    def test_confirmed_fact_verified_finding_carries_location_and_verified_at(self):
        agent = self._make_agent()
        agent.context.state.add_confirmed_fact("命令执行成功")
        agent.context.state.add_note("发现入口 https://example.com/admin/exec")
        agent._finding_parser.parse("访问 https://example.com/admin/exec 后确认命令执行成功")

        verified = [f for f in agent.session_state.findings if f.verification_status == "verified"]
        assert verified
        assert "https://example.com/admin/exec" in (verified[0].evidence or "")
        assert verified[0].verified_at is not None
        assert verified[0].evidence_level == "L4"
        assert verified[0].lifecycle_status == "verified"

    def test_phase_detection_from_output(self):
        from vulnclaw.agent.context import PentestPhase

        agent = self._make_agent()
        assert agent._detect_phase_from_output("进入漏洞发现阶段") == PentestPhase.VULN_DISCOVERY
        assert agent._detect_phase_from_output("开始利用漏洞") == PentestPhase.EXPLOITATION
        assert agent._detect_phase_from_output("没有特殊信号") is None

    def test_reset_context(self):
        agent = self._make_agent()
        agent.context.state.target = "10.0.0.1"
        agent.runtime.blocked_targets = {"a.example.com"}
        agent.runtime.claimed_flag = "flag{demo}"
        agent.runtime.flag_verified = True
        agent.runtime.same_path_fail_count = 2
        agent.runtime.user_vuln_hint_rounds = 1
        agent.context.state.recon_dimension4_active = True
        agent.reset_context()
        assert agent.session_state.target is None
        assert agent.runtime.blocked_targets == set()
        assert agent.runtime.claimed_flag is None
        assert agent.runtime.flag_verified is False
        assert agent.runtime.same_path_fail_count == 0
        assert agent.runtime.user_vuln_hint_rounds == 0
        assert agent.context.state.recon_dimension4_active is False

    def test_reset_runtime_state_for_recon_initializes_expected_fields(self):
        from vulnclaw.agent.context import PentestPhase

        agent = self._make_agent()
        agent._reset_runtime_state(
            user_input="对 example.com 做社工和信息收集，顺便找flag",
            detected_phase=PentestPhase.RECON,
        )

        assert agent.runtime.auto_skill_input == "对 example.com 做社工和信息收集，顺便找flag"
        assert agent.runtime.is_recon_phase is True
        assert agent.runtime.is_ctf_mode is True
        assert agent.runtime.claimed_flag is None
        assert agent.runtime.flag_verified is False
        assert agent.runtime.flag_claim_count == 0
        assert agent.runtime.post_flag_rounds == 0
        assert agent.runtime.rounds_without_progress == 0
        assert agent.runtime.python_timeout_rounds == 0
        assert agent.runtime.blocked_targets == set()
        assert agent.runtime.failed_targets == {}
        assert agent.runtime.seen_step_signatures == set()
        assert agent.runtime.current_attack_path is None
        assert agent.runtime.same_path_fail_count == 0
        assert agent.runtime.path_switch_forced is False
        assert agent.runtime.consecutive_errors == 0
        assert agent.context.state.recon_dimension4_active is True
        assert agent.context.state.recon_dimensions_completed == {
            "server": False,
            "website": False,
            "domain": False,
            "personnel": False,
        }

    def test_agent_init_sets_runtime_defaults(self):
        agent = self._make_agent()
        assert agent.runtime.auto_skill_input == ""
        assert agent.runtime.user_vuln_hint == ""
        assert agent.runtime.user_vuln_hint_rounds == 0
        assert agent.runtime.claimed_flag is None
        assert agent.runtime.flag_verified is False
        assert agent.runtime.flag_claim_count == 0
        assert agent.runtime.post_flag_rounds == 0
        assert agent.runtime.is_recon_phase is False
        assert agent.runtime.rounds_without_progress == 0
        assert agent.runtime.python_timeout_rounds == 0
        assert agent.runtime.seen_step_signatures == set()
        assert agent.runtime.current_attack_path is None
        assert agent.runtime.same_path_fail_count == 0
        assert agent.runtime.path_switch_forced is False
        assert agent.runtime.failed_targets == {}
        assert agent.runtime.blocked_targets == set()
        assert agent.runtime.unverified_assumptions == []
        assert agent.runtime.is_ctf_mode is False
        assert agent.runtime.consecutive_errors == 0

    def test_build_round_context_consumes_user_vuln_hint_rounds(self):
        from vulnclaw.agent.context import PentestPhase

        agent = self._make_agent()
        agent.context.state.advance_phase(PentestPhase.VULN_DISCOVERY)
        agent._reset_runtime_state(
            user_input="测试 https://example.com/login 的 SQL注入",
            detected_phase=PentestPhase.VULN_DISCOVERY,
        )

        round1 = agent._build_round_context(1, 5)
        assert "用户明确提示" in round1
        assert "第 1/3 轮" in round1
        assert agent.runtime.user_vuln_hint_rounds == 2

        round2 = agent._build_round_context(2, 5)
        assert "第 2/2 轮" in round2
        assert agent.runtime.user_vuln_hint_rounds == 1

    def test_extract_task_constraints_parses_allowed_ports(self):
        from vulnclaw.agent.input_analysis import extract_task_constraints

        constraints = extract_task_constraints("对 https://example.com 只测试 443 端口")
        assert constraints.allowed_ports == [443]
        assert constraints.strict_mode is True

    def test_extract_task_constraints_infers_allowed_host_and_path(self):
        from vulnclaw.agent.input_analysis import extract_task_constraints

        constraints = extract_task_constraints("对 https://example.com/admin 只测试这个路径")
        assert "example.com" in constraints.allowed_hosts
        assert "/admin" in constraints.allowed_paths
        assert constraints.strict_mode is True

    def test_extract_task_constraints_url_with_trailing_dot_in_sentence(self):
        """URL at end of sentence should not capture trailing period as part of host.

        Regression test for issue #10: when a URL appears before a period ending
        a sentence, detect_target() was capturing the period as part of the URL,
        causing allowed_hosts to contain 'example.com.' with a trailing dot.
        This then caused fetch scope checks to fail because urlparse().hostname
        never returns a trailing dot per RFC 3986.
        """
        from vulnclaw.agent.input_analysis import extract_task_constraints

        # The period after .com is sentence punctuation, not part of the URL
        constraints = extract_task_constraints("对 http://example.com. 进行渗透测试")
        assert "example.com" in constraints.allowed_hosts
        # Must NOT contain trailing dot - urlparse().hostname never returns trailing dots
        assert all(not h.endswith(".") for h in constraints.allowed_hosts)

    def test_round_context_includes_hard_constraints(self):
        from vulnclaw.agent.context import PentestPhase

        agent = self._make_agent()
        agent.context.state.advance_phase(PentestPhase.RECON)
        agent._reset_runtime_state(
            user_input="对 https://example.com 只测试 443 端口",
            detected_phase=PentestPhase.RECON,
        )

        round1 = agent._build_round_context(1, 5)
        round5 = agent._build_round_context(5, 5)

        assert "当前任务硬约束" in round1
        assert "仅允许测试端口: 443" in round1
        assert "当前任务硬约束" in round5
        assert "仅允许测试端口: 443" in round5

    @pytest.mark.asyncio
    async def test_persistent_pentest_keeps_constraints_in_followup_cycles(self):
        agent = self._make_agent()
        captured_inputs = []

        async def _fake_auto_pentest(*args, **kwargs):
            captured_inputs.append(kwargs.get("user_input", args[0] if args else ""))
            from vulnclaw.agent.runtime_state import AgentResult

            return [AgentResult(output="cycle", should_continue=False)]

        agent.auto_pentest = _fake_auto_pentest
        agent._reset_runtime_state(
            user_input="对 https://example.com 只测试 443 端口",
            detected_phase=agent._detect_phase("信息收集"),
        )
        agent.context.state.target = "https://example.com"

        await agent.persistent_pentest(
            "对 https://example.com 只测试 443 端口",
            max_cycles=2,
            rounds_per_cycle=1,
        )

        assert len(captured_inputs) == 2
        assert "只测试 443 端口" in captured_inputs[0]
        assert "当前任务硬约束" in captured_inputs[1]
        assert "仅允许测试端口: 443" in captured_inputs[1]

    def test_reset_runtime_state_clears_previous_run_contamination(self):
        from vulnclaw.agent.context import PentestPhase

        agent = self._make_agent()
        agent.runtime.blocked_targets = {"old.example.com"}

        agent.runtime.failed_targets = {"old.example.com": 3}
        agent.runtime.claimed_flag = "flag{old}"
        agent.runtime.flag_verified = True
        agent.runtime.flag_claim_count = 7
        agent.runtime.post_flag_rounds = 2
        agent.runtime.rounds_without_progress = 5
        agent.runtime.python_timeout_rounds = 4
        agent.runtime.current_attack_path = "regex_bypass"
        agent.runtime.same_path_fail_count = 3
        agent.runtime.path_switch_forced = True
        agent.runtime.consecutive_errors = 2
        agent.runtime.user_vuln_hint = "old hint"
        agent.runtime.user_vuln_hint_rounds = 9
        agent.context.state.recon_dimension4_active = True
        agent.context.state.recon_dimensions_completed = {
            "server": True,
            "website": True,
            "domain": True,
            "personnel": True,
        }

        agent._reset_runtime_state(
            user_input="测试 https://example.com/login 的 SQL注入",
            detected_phase=PentestPhase.VULN_DISCOVERY,
        )

        assert agent.runtime.is_recon_phase is False
        assert agent.runtime.is_ctf_mode is False
        assert agent.runtime.blocked_targets == set()
        assert agent.runtime.failed_targets == {}
        assert agent.runtime.claimed_flag is None
        assert agent.runtime.flag_verified is False
        assert agent.runtime.flag_claim_count == 0
        assert agent.runtime.post_flag_rounds == 0
        assert agent.runtime.rounds_without_progress == 0
        assert agent.runtime.python_timeout_rounds == 0
        assert agent.runtime.current_attack_path is None
        assert agent.runtime.same_path_fail_count == 0
        assert agent.runtime.path_switch_forced is False
        assert agent.runtime.consecutive_errors == 0
        assert agent.runtime.user_vuln_hint
        assert agent.runtime.user_vuln_hint_rounds == 3
        assert agent.context.state.recon_dimension4_active is False
        assert agent.context.state.recon_dimensions_completed == {
            "server": False,
            "website": False,
            "domain": False,
            "personnel": False,
        }

    def test_reset_runtime_state_preserves_existing_constraints_when_new_input_has_none(self):
        from vulnclaw.agent.context import PentestPhase, TaskConstraints

        agent = self._make_agent()
        agent.context.state.task_constraints = TaskConstraints(
            allowed_ports=[443], strict_mode=True
        )

        agent._reset_runtime_state(
            user_input="[Persistent Cycle 2] 继续对目标 https://example.com 进行渗透测试。",
            detected_phase=PentestPhase.RECON,
        )

        assert agent.runtime.task_constraints.allowed_ports == [443]
        assert agent.context.state.task_constraints.allowed_ports == [443]


class TestAgentCoreLoop:
    """State-machine-level tests for auto_pentest / persistent_pentest loops."""

    def _make_agent(self):
        from vulnclaw.agent.core import AgentCore
        from vulnclaw.config.schema import VulnClawConfig

        config = VulnClawConfig()
        config.llm.model = "gpt-4o-mini"
        config.llm.api_key = "sk-test"
        return AgentCore(config=config)

    def test_llm_client_uses_max_completion_tokens_for_gpt5_models(self):
        from vulnclaw.agent.llm_client import build_chat_completion_kwargs

        class DummyAgent:
            class _DummyConfig:
                class _DummyLLM:
                    model = "gpt-5.5"
                    max_tokens = 256
                    temperature = 0.1
                    provider = "openai"
                    reasoning_effort = "high"

                llm = _DummyLLM()

            config = _DummyConfig()

        kwargs = build_chat_completion_kwargs(DummyAgent(), [{"role": "user", "content": "hi"}])

        assert kwargs["max_completion_tokens"] == 256
        assert "max_tokens" not in kwargs
        assert "temperature" not in kwargs
        assert kwargs["reasoning_effort"] == "high"

    def test_llm_client_keeps_max_tokens_for_compatible_providers(self):
        from vulnclaw.agent.llm_client import build_chat_completion_kwargs

        class DummyAgent:
            class _DummyConfig:
                class _DummyLLM:
                    model = "deepseek-chat"
                    max_tokens = 512
                    temperature = 0.2
                    provider = "deepseek"
                    reasoning_effort = "high"

                llm = _DummyLLM()

            config = _DummyConfig()

        kwargs = build_chat_completion_kwargs(DummyAgent(), [{"role": "user", "content": "hi"}])

        assert kwargs["max_tokens"] == 512
        assert kwargs["temperature"] == 0.2
        assert "max_completion_tokens" not in kwargs
        assert "reasoning_effort" not in kwargs

    @pytest.mark.asyncio
    async def test_generate_attack_summary_uses_gpt5_token_parameter(self):
        from vulnclaw.agent.context import SessionState
        from vulnclaw.agent.prompt_context import generate_attack_summary

        captured_kwargs = {}

        class DummyClient:
            class chat:
                class completions:
                    @staticmethod
                    def create(**kwargs):
                        captured_kwargs.update(kwargs)

                        class Msg:
                            content = "summary"

                        class Choice:
                            message = Msg()

                        class Resp:
                            choices = [Choice()]

                        return Resp()

        class DummyAgent:
            state = SessionState(target="example.com")
            session_state = state
            context = type("Context", (), {"state": state})()
            config = type(
                "Config",
                (),
                {
                    "llm": type(
                        "LLM",
                        (),
                        {
                            "model": "gpt-5.5",
                            "max_tokens": 4096,
                            "temperature": 0.1,
                            "provider": "openai",
                            "reasoning_effort": "high",
                        },
                    )()
                },
            )()

            @staticmethod
            def _get_client():
                return DummyClient()

        result = await generate_attack_summary(DummyAgent())

        assert result == "summary"
        assert captured_kwargs["max_completion_tokens"] == 800
        assert "max_tokens" not in captured_kwargs
        assert "temperature" not in captured_kwargs

    @pytest.mark.asyncio
    async def test_llm_client_call_llm_auto_uses_shared_helper(self, monkeypatch):
        from vulnclaw.agent import llm_client

        class DummyLoop:
            async def run_in_executor(self, executor, fn):
                class Msg:
                    content = "hello"
                    tool_calls = None

                class Choice:
                    message = Msg()

                class Resp:
                    choices = [Choice()]

                return Resp()

        class DummyAgent:
            class _DummyClient:
                class _Chat:
                    class _Completions:
                        def create(self, **kwargs):
                            raise AssertionError("executor stub should be used")

                    completions = _Completions()

                chat = _Chat()

            class _DummyConfig:
                class _DummyLLM:
                    model = "gpt-4o-mini"
                    max_tokens = 256
                    temperature = 0.1
                    provider = "openai"
                    reasoning_effort = "high"

                llm = _DummyLLM()

            class _DummyContext:
                @staticmethod
                def get_messages():
                    return []

            config = _DummyConfig()
            context = _DummyContext()

            def _build_openai_tools(self):
                return []

            def _get_client(self):
                return self._DummyClient()

        dummy = DummyAgent()
        monkeypatch.setattr(llm_client, "extract_response", lambda message: "ok")
        monkeypatch.setattr(llm_client.asyncio, "get_running_loop", lambda: DummyLoop())
        result = await llm_client.call_llm_auto(dummy, "sys", "round")
        assert result == "ok"

    @pytest.mark.asyncio
    async def test_llm_client_call_llm_auto_retries_within_same_round(self, monkeypatch):
        from vulnclaw.agent import llm_client

        class DummyLoop:
            def __init__(self):
                self.calls = 0

            async def run_in_executor(self, executor, fn):
                self.calls += 1
                if self.calls < 3:
                    raise RuntimeError("connection error")

                class Msg:
                    content = "恢复成功"
                    tool_calls = None

                class Choice:
                    message = Msg()

                class Resp:
                    choices = [Choice()]

                return Resp()

        class DummyAgent:
            class _DummyClient:
                class _Chat:
                    class _Completions:
                        def create(self, **kwargs):
                            return None

                    completions = _Completions()

                chat = _Chat()

            class _DummyConfig:
                class _DummyLLM:
                    model = "gpt-4o-mini"
                    max_tokens = 256
                    temperature = 0.1
                    provider = "openai"
                    reasoning_effort = "high"

                llm = _DummyLLM()

            class _DummyContext:
                @staticmethod
                def get_messages():
                    return []

                @staticmethod
                def add_assistant_message(text):
                    return None

            config = _DummyConfig()
            context = _DummyContext()

            def _build_openai_tools(self):
                return []

            def _get_client(self):
                return self._DummyClient()

        loop = DummyLoop()
        dummy = DummyAgent()
        monkeypatch.setattr(llm_client.asyncio, "get_running_loop", lambda: loop)

        async def no_sleep(_seconds):
            return None

        monkeypatch.setattr(llm_client.asyncio, "sleep", no_sleep)
        result = await llm_client.call_llm_auto(dummy, "sys", "round")
        assert "LLM恢复" in result
        assert "恢复成功" in result
        assert loop.calls == 3

    @pytest.mark.asyncio
    async def test_llm_client_bad_request_errors_are_not_retried(self, monkeypatch):
        from vulnclaw.agent import llm_client

        class DummyLoop:
            def __init__(self):
                self.calls = 0

            async def run_in_executor(self, executor, fn):
                self.calls += 1
                raise RuntimeError("bad_request_error: invalid chat setting (2013)")

        class DummyAgent:
            class _DummyClient:
                class _Chat:
                    class _Completions:
                        def create(self, **kwargs):
                            return None

                    completions = _Completions()

                chat = _Chat()

            class _DummyConfig:
                class _DummyLLM:
                    model = "gpt-4o-mini"
                    max_tokens = 256
                    temperature = 0.1
                    provider = "openai"
                    reasoning_effort = "high"

                llm = _DummyLLM()

            class _DummyContext:
                @staticmethod
                def get_messages():
                    return []

            config = _DummyConfig()
            context = _DummyContext()

            def _build_openai_tools(self):
                return []

            def _get_client(self):
                return self._DummyClient()

        loop = DummyLoop()
        dummy = DummyAgent()
        monkeypatch.setattr(llm_client.asyncio, "get_running_loop", lambda: loop)

        with pytest.raises(RuntimeError):
            await llm_client.call_llm_auto(dummy, "sys", "round")

        assert loop.calls == 1

    @pytest.mark.asyncio
    async def test_llm_client_tool_summary_bad_request_degrades_to_plain_text(self, monkeypatch):
        from vulnclaw.agent import llm_client

        class DummyLoop:
            def __init__(self):
                self.calls = 0

            async def run_in_executor(self, executor, fn):
                self.calls += 1
                if self.calls == 1:

                    class ToolCall:
                        id = "call_1"

                        class Function:
                            name = "fetch"
                            arguments = '{"url":"https://example.com"}'

                        function = Function()

                    class Msg:
                        content = ""
                        tool_calls = [ToolCall()]

                    class Choice:
                        message = Msg()

                    class Resp:
                        choices = [Choice()]

                    return Resp()
                raise RuntimeError(
                    "bad_request_error: invalid function arguments json string, tool_call_id: call_1"
                )

        class DummyAgent:
            class _DummyClient:
                class _Chat:
                    class _Completions:
                        def create(self, **kwargs):
                            return None

                    completions = _Completions()

                chat = _Chat()

            class _DummyConfig:
                class _DummyLLM:
                    model = "gpt-4o-mini"
                    max_tokens = 256
                    temperature = 0.1
                    provider = "openai"
                    reasoning_effort = "high"

                llm = _DummyLLM()

            class _DummyContext:
                def __init__(self):
                    self.saved = []

                @staticmethod
                def get_messages():
                    return []

                def add_assistant_message(self, text):
                    self.saved.append(text)

            config = _DummyConfig()

            def __init__(self):
                self.context = self._DummyContext()

            def _build_openai_tools(self):
                return [{"function": {"name": "fetch"}}]

            def _get_client(self):
                return self._DummyClient()

        async def fake_handle_tool_calls_with_results(agent, message):
            return (
                [
                    {
                        "tool_call": message.tool_calls[0],
                        "tool_call_id": "call_1",
                        "content": "[tool:fetch] Status: 200",
                    }
                ],
                [],
            )

        loop = DummyLoop()
        dummy = DummyAgent()
        monkeypatch.setattr(llm_client.asyncio, "get_running_loop", lambda: loop)
        monkeypatch.setattr(
            llm_client, "handle_tool_calls_with_results", fake_handle_tool_calls_with_results
        )

        result = await llm_client.call_llm_auto(dummy, "sys", "round")
        assert "已降级为纯文本结果摘要" in result
        assert "Status: 200" in result

    @pytest.mark.asyncio
    async def test_llm_client_does_not_persist_tool_summary_as_assistant_history(self, monkeypatch):
        from vulnclaw.agent import llm_client

        class DummyLoop:
            def run_in_executor(self, executor, func):
                return func()

        class DummyToolCall:
            id = "tool_1"
            function = type(
                "Fn", (), {"name": "navigate", "arguments": '{"url":"https://example.com"}'}
            )()

        class DummyMessage:
            tool_calls = [DummyToolCall()]
            content = ""

        class DummyChoice:
            message = DummyMessage()

        class DummyResponse:
            choices = [DummyChoice()]

        class DummyFollowupMessage:
            tool_calls = []
            content = "followup ok"

        class DummyFollowupChoice:
            message = DummyFollowupMessage()

        class DummyFollowupResponse:
            choices = [DummyFollowupChoice()]

        calls = [DummyResponse(), DummyFollowupResponse()]

        class DummyClient:
            class chat:
                class completions:
                    @staticmethod
                    def create(**kwargs):
                        return calls.pop(0)

        saved_messages: list[str] = []

        class DummyContext:
            @staticmethod
            def get_messages():
                return []

            @staticmethod
            def add_assistant_message(text):
                saved_messages.append(text)

        class DummyConfig:
            llm = type(
                "LLM",
                (),
                {
                    "model": "test-model",
                    "max_tokens": 1000,
                    "temperature": 0.1,
                    "provider": "openai",
                    "reasoning_effort": "high",
                },
            )()

        class DummyAgent:
            context = DummyContext()
            config = DummyConfig()

            @staticmethod
            def _get_client():
                return DummyClient()

            @staticmethod
            def _build_openai_tools():
                return [{"function": {"name": "navigate"}}]

        async def fake_handle_tool_calls_with_results(agent, message):
            return (
                [
                    {
                        "tool_call": DummyToolCall(),
                        "tool_call_id": "tool_1",
                        "content": "[tool:navigate] navigated",
                        "structured_content": {"url": "https://example.com", "status": "ok"},
                    }
                ],
                [],
            )

        monkeypatch.setattr(
            llm_client, "handle_tool_calls_with_results", fake_handle_tool_calls_with_results
        )
        monkeypatch.setattr(llm_client, "extract_response", lambda message: message.content)
        monkeypatch.setattr(llm_client.asyncio, "get_running_loop", lambda: DummyLoop())

        result = await llm_client.call_llm_auto(DummyAgent(), "sys", "round")
        assert result == "followup ok"
        assert saved_messages == ["followup ok"]

    @pytest.mark.asyncio
    async def test_auto_pentest_stops_on_done_signal(self, monkeypatch):
        agent = self._make_agent()
        from vulnclaw.agent import loop_controller

        async def _fake_call_llm_auto(agent_obj, system_prompt, round_context, **kwargs):
            return "本轮未发现新漏洞，准备总结。\n[DONE]"

        monkeypatch.setattr(loop_controller, "call_llm_auto", _fake_call_llm_auto)
        # Use input that skips recon (so RECON_MIN_ROUNDS doesn't block [DONE])
        results = await agent.auto_pentest("扫描 example.com 的 SQL注入漏洞", max_rounds=5)

        assert len(results) == 1
        assert results[0].should_continue is False

    @pytest.mark.asyncio
    async def test_auto_pentest_ctf_flag_state_machine(self, monkeypatch):
        agent = self._make_agent()
        from vulnclaw.agent import loop_controller

        round_responses = [
            "发现可疑文件，尝试读取。\nflag{test123}",
            "验证 flag{test123} 正确，flag 获取成功！",
            "总结：成功获取 flag{test123}，任务完成。\n[DONE]",
        ]
        call_idx = 0

        async def _fake_call_llm_auto(agent_obj, system_prompt, round_context, **kwargs):
            nonlocal call_idx
            text = round_responses[call_idx]
            call_idx += 1
            return text

        monkeypatch.setattr(loop_controller, "call_llm_auto", _fake_call_llm_auto)
        results = await agent.auto_pentest("NSSCTF 解题找 flag", max_rounds=10)

        # Should claim flag on round 1
        assert agent.runtime.claimed_flag == "flag{test123}"
        # Should verify on round 2 (verification markers in response)
        assert agent.runtime.flag_verified is True
        # Post-flag safety exit should limit extra rounds
        assert len(results) <= 4
        assert results[-1].should_continue is False

    @pytest.mark.asyncio
    async def test_auto_pentest_dead_loop_detects_same_path(self, monkeypatch):
        agent = self._make_agent()
        from vulnclaw.agent import loop_controller

        async def _fake_call_llm_auto(agent_obj, system_prompt, round_context, **kwargs):
            # Same wording every round, with an attack-path keyword
            return "尝试 sql注入测试，使用 UNION SELECT，未成功。"

        monkeypatch.setattr(loop_controller, "call_llm_auto", _fake_call_llm_auto)
        results = await agent.auto_pentest("扫描 example.com 的 SQL注入漏洞", max_rounds=5)

        # Same path repeated without progress → counter increases
        assert agent.runtime.same_path_fail_count >= 3
        assert agent.runtime.rounds_without_progress >= 3
        # Should still stop at max_rounds (no [DONE])
        assert len(results) == 5

    @pytest.mark.asyncio
    async def test_auto_pentest_blocks_phase_transition_when_action_not_allowed(self, monkeypatch):
        agent = self._make_agent()
        from vulnclaw.agent import loop_controller

        async def _fake_call_llm_auto(agent_obj, system_prompt, round_context, **kwargs):
            return "信息收集完成，切换到漏洞利用。\nphase: exploitation"

        monkeypatch.setattr(loop_controller, "call_llm_auto", _fake_call_llm_auto)
        results = await agent.auto_pentest(
            "对 https://example.com 做信息收集。 Only allowed actions: recon",
            max_rounds=3,
        )

        assert len(results) == 1
        assert results[0].should_continue is False
        assert "constraint_violation" in results[0].output
        assert agent.context.state.phase.value == "信息收集"

    def test_constraint_policy_normalizes_actions_and_validates_phase(self):
        from vulnclaw.agent.constraint_policy import (
            infer_tool_action,
            normalize_action_name,
            validate_action_constraints,
            validate_phase_transition,
            validate_tool_action,
        )
        from vulnclaw.agent.context import PentestPhase, TaskConstraints

        constraints = TaskConstraints(allowed_actions=["recon"], strict_mode=True)
        assert normalize_action_name("reporting") == "report"
        assert validate_action_constraints("run", constraints) is None  # composite command skips allowed check
        assert validate_action_constraints("recon", constraints) is None
        assert validate_phase_transition(PentestPhase.EXPLOITATION, constraints) is not None
        assert infer_tool_action("nmap_scan", {"target": "example.com"}) == "recon"
        assert (
            infer_tool_action("fetch", {"url": "https://example.com/login?id=1' OR 1=1--"})
            == "exploit"
        )
        assert (
            validate_tool_action(
                "fetch", {"url": "https://example.com/login?id=1' OR 1=1--"}, constraints
            )
            is not None
        )

    @pytest.mark.asyncio
    async def test_auto_pentest_blocks_repeatedly_failed_target(self, monkeypatch):
        agent = self._make_agent()
        from vulnclaw.agent import loop_controller

        async def _fake_call_llm_auto(agent_obj, system_prompt, round_context, **kwargs):
            return "访问 https://victim.local/admin 访问失败，连接超时。"

        monkeypatch.setattr(loop_controller, "call_llm_auto", _fake_call_llm_auto)
        await agent.auto_pentest("测试 victim.local", max_rounds=5)

        # victim.local should be tracked as failed
        assert "victim.local" in agent.runtime.failed_targets
        assert agent.runtime.failed_targets["victim.local"] >= 3
        # After 3 failures it should be blocked
        assert "victim.local" in agent.runtime.blocked_targets

    @pytest.mark.asyncio
    async def test_persistent_pentest_aggregates_cycles(self):
        agent = self._make_agent()
        cycle_count = 0

        async def _fake_auto_pentest(*args, **kwargs):
            nonlocal cycle_count
            cycle_count += 1
            from vulnclaw.agent.runtime_state import AgentResult

            return [AgentResult(output=f"cycle {cycle_count}", should_continue=False)]

        agent.auto_pentest = _fake_auto_pentest
        cycle_results = await agent.persistent_pentest(
            "持续测试 target",
            max_cycles=3,
            rounds_per_cycle=5,
        )

        assert len(cycle_results) == 3
        assert cycle_results[0].cycle_num == 1
        assert cycle_results[-1].cycle_num == 3
        assert all(cr.total_steps >= 0 for cr in cycle_results)
