"""VulnClaw Skill Module Tests — loader.py + dispatcher.py"""


# ── loader.py ────────────────────────────────────────────────────────


class TestSkillLoader:
    """Test Skill loading and management."""

    def test_list_core_skills(self):
        from vulnclaw.skills.loader import list_core_skills

        core = list_core_skills()
        assert isinstance(core, list)
        assert len(core) == 7
        expected = [
            "pentest-flow",
            "recon",
            "vuln-discovery",
            "exploitation",
            "post-exploitation",
            "reporting",
            "waf-bypass",
        ]
        for skill in expected:
            assert skill in core, f"Missing core skill: {skill}"

    def test_list_specialized_skills(self):
        from vulnclaw.skills.loader import list_specialized_skills

        spec = list_specialized_skills()
        assert isinstance(spec, list)
        assert (
            len(spec) >= 9
        )  # Grew from 9 with CTF/OSINT/SecKnowledge specialized skills.
        expected = [
            "web-pentest",
            "android-pentest",
            "client-reverse",
            "web-security-advanced",
            "ai-mcp-security",
            "intranet-pentest-advanced",
            "pentest-tools",
            "rapid-checklist",
            "crypto-toolkit",
            "secknowledge-skill",
        ]
        for skill in expected:
            assert skill in spec, f"Missing specialized skill: {skill}"

    def test_load_core_skill(self):
        from vulnclaw.skills.loader import load_core_skill

        skill = load_core_skill("pentest-flow")
        assert skill is not None
        assert "content" in skill
        assert "渗透" in skill["content"]

    def test_load_skill_by_name_core(self):
        from vulnclaw.skills.loader import load_skill_by_name

        skill = load_skill_by_name("pentest-flow")
        assert skill is not None
        assert skill["name"] == "pentest-flow"

    def test_load_skill_by_name_specialized(self):
        from vulnclaw.skills.loader import load_skill_by_name

        skill = load_skill_by_name("client-reverse")
        assert skill is not None
        assert skill["name"] == "client-reverse"

    def test_load_nonexistent_skill(self):
        from vulnclaw.skills.loader import load_skill_by_name

        skill = load_skill_by_name("nonexistent-skill")
        assert skill is None

    def test_skill_has_description(self):
        from vulnclaw.skills.loader import load_skill_by_name

        for name in ["pentest-flow", "recon", "client-reverse", "web-security-advanced"]:
            skill = load_skill_by_name(name)
            assert skill is not None
            assert "description" in skill
            assert len(skill["description"]) > 0, f"Skill {name} has empty description"

    def test_skill_requires_target_defaults_true(self):
        """Skills without a requires_target frontmatter key default to True."""
        from vulnclaw.skills.loader import load_skill_by_name

        skill = load_skill_by_name("pentest-flow")
        assert skill["requires_target"] is True

    def test_skill_requires_target_frontmatter_override(self, tmp_path):
        """frontmatter ``requires_target: false`` is surfaced on the skill dict."""
        from vulnclaw.skills.loader import _parse_skill_file

        skill_file = tmp_path / "self-discovering.md"
        skill_file.write_text(
            "---\nname: self-discovering\ndescription: reads its own target\n"
            "requires_target: false\n---\nbody\n",
            encoding="utf-8",
        )
        skill = _parse_skill_file(skill_file)
        assert skill["requires_target"] is False

    def test_skill_requires_target_ignores_non_boolean(self, tmp_path):
        """Only an explicit boolean false opts out; falsy non-bools stay True."""
        from vulnclaw.skills.loader import _parse_skill_file

        for raw in ["requires_target:", "requires_target: 0", 'requires_target: "false"']:
            skill_file = tmp_path / "s.md"
            skill_file.write_text(f"---\nname: s\n{raw}\n---\nbody\n", encoding="utf-8")
            skill = _parse_skill_file(skill_file)
            assert skill["requires_target"] is True, raw

    def test_skill_format_field(self):
        """Directory-format skills should have format='directory'."""
        from vulnclaw.skills.loader import load_skill_by_name

        # Core skills are flat format
        pentest = load_skill_by_name("pentest-flow")
        assert pentest["format"] == "flat"
        # Specialized skills are directory format
        client_rev = load_skill_by_name("client-reverse")
        assert client_rev["format"] == "directory"

    def test_directory_skill_has_references(self):
        """Directory-format skills should list their reference files."""
        from vulnclaw.skills.loader import load_skill_by_name

        skill = load_skill_by_name("client-reverse")
        assert "references" in skill
        assert len(skill["references"]) > 0
        # Should be a list of filenames
        for ref in skill["references"]:
            assert isinstance(ref, str)
            assert ref.endswith(".md") or ref.endswith(".yaml")

    def test_flat_skill_no_references(self):
        """Flat-format core skills should have empty references."""
        from vulnclaw.skills.loader import load_skill_by_name

        skill = load_skill_by_name("pentest-flow")
        assert skill.get("references", []) == []

    def test_hackerone_skill_and_reference_are_english(self):
        """The HackerOne workflow should honor the English UI language."""
        from vulnclaw.skills.loader import load_skill_by_name, load_skill_reference

        skill = load_skill_by_name("hackerone")
        reference = load_skill_reference("hackerone", "hackerone-report-and-scope.md")

        assert skill is not None
        assert reference is not None
        assert not any("\u4e00" <= char <= "\u9fff" for char in skill["content"])
        assert not any("\u4e00" <= char <= "\u9fff" for char in reference)
        assert "Scope defined:" in skill["content"]
        assert "Automatically begin recon" in skill["content"]
        assert "Do not load or print the reference document during startup" in skill["content"]
        assert "hackerone_scope" in skill["content"]
        assert "Never treat `hackerone.com` as the recon/pentest target" in skill["content"]

    def test_load_skill_reference(self):
        """Test loading a specific reference file from a skill."""
        from vulnclaw.skills.loader import load_skill_reference

        content = load_skill_reference("client-reverse", "02-client-api-reverse-and-burp.md")
        assert content is not None
        assert len(content) > 100
        assert (
            "client" in content.lower() or "burp" in content.lower() or "reverse" in content.lower()
        )

    def test_load_secknowledge_reference(self):
        """SecKnowledge references should be loadable through VulnClaw."""
        from vulnclaw.skills.loader import load_skill_reference

        content = load_skill_reference("secknowledge-skill", "vulnclaw-ctf-src-routing.md")
        assert content is not None
        assert "SRC" in content
        assert "GAARM" in content
        assert "web-sqli.md" in content
        assert "web-sqli-fushuling-one-pass.md" in content

    def test_load_fushuling_sqli_reference(self):
        """The fushuling SQLi one-pass reference should be loadable."""
        from vulnclaw.skills.loader import load_skill_reference

        content = load_skill_reference(
            "secknowledge-skill", "web-sqli-fushuling-one-pass.md"
        )
        assert content is not None
        assert "SQL 注入一命通关" in content
        assert "fushuling.com" in content
        assert "sqlmap" in content

    def test_load_skill_reference_nonexistent(self):
        from vulnclaw.skills.loader import load_skill_reference

        content = load_skill_reference("client-reverse", "nonexistent.md")
        assert content is None

    def test_load_skill_reference_wrong_skill(self):
        from vulnclaw.skills.loader import load_skill_reference

        content = load_skill_reference("nonexistent-skill", "some.md")
        assert content is None

    def test_all_specialized_skills_loadable(self):
        """Every specialized skill should load successfully."""
        from vulnclaw.skills.loader import list_specialized_skills, load_skill_by_name

        for name in list_specialized_skills():
            skill = load_skill_by_name(name)
            assert skill is not None, f"Failed to load skill: {name}"
            assert "content" in skill, f"Skill {name} has no content"
            assert len(skill["content"]) > 50, f"Skill {name} has suspiciously short content"

    def test_all_core_skills_loadable(self):
        """Every core skill should load successfully."""
        from vulnclaw.skills.loader import list_core_skills, load_skill_by_name

        for name in list_core_skills():
            skill = load_skill_by_name(name)
            assert skill is not None, f"Failed to load skill: {name}"

    def test_reference_count_per_specialized_skill(self):
        """Each specialized skill should have at least 1 reference file."""
        from vulnclaw.skills.loader import list_specialized_skills, load_skill_by_name

        for name in list_specialized_skills():
            skill = load_skill_by_name(name)
            refs = skill.get("references", [])
            assert len(refs) >= 1, f"Skill {name} has no reference files"

    def test_specific_reference_files_exist(self):
        """Check key reference files exist for each specialized skill."""
        from vulnclaw.skills.loader import load_skill_by_name

        test_cases = [
            ("client-reverse", "02-client-api-reverse-and-burp.md"),
            ("web-security-advanced", "web-injection.md"),
            ("ai-mcp-security", "ai-app-security.md"),
            ("intranet-pentest-advanced", "06-intranet-and-host-operations-integrated.md"),
            ("pentest-tools", "tools-reference-index.md"),
            ("rapid-checklist", "08-rapid-checklists-and-payloads.md"),
            ("web-pentest", "web-injection.md"),
            ("android-pentest", "android-authorized-app-pentest-sop.md"),
            ("crypto-toolkit", "encoding-cheatsheet.md"),
            ("secknowledge-skill", "vulnclaw-ctf-src-routing.md"),
        ]
        for skill_name, ref_name in test_cases:
            skill = load_skill_by_name(skill_name)
            assert ref_name in skill.get("references", []), (
                f"Skill {skill_name} missing reference: {ref_name}"
            )


# ── dispatcher.py ────────────────────────────────────────────────────


class TestSkillDispatcher:
    """Test Skill dispatching based on user input."""

    def _make_dispatcher(self):
        from vulnclaw.skills.dispatcher import SkillDispatcher

        return SkillDispatcher()

    def test_dispatch_pentest_flow(self):
        d = self._make_dispatcher()
        skill = d.dispatch("对目标进行渗透测试")
        assert skill["name"] == "pentest-flow"

    def test_dispatch_recon(self):
        d = self._make_dispatcher()
        skill = d.dispatch("信息收集 侦察目标")
        assert skill["name"] == "recon"

    def test_dispatch_vuln_discovery(self):
        d = self._make_dispatcher()
        skill = d.dispatch("漏洞扫描发现漏洞")
        assert skill["name"] == "vuln-discovery"

    def test_dispatch_exploitation(self):
        d = self._make_dispatcher()
        skill = d.dispatch("exploit利用漏洞")
        assert skill["name"] == "exploitation"

    def test_dispatch_post_exploitation(self):
        d = self._make_dispatcher()
        skill = d.dispatch("后渗透post-exploitation")
        assert skill["name"] == "post-exploitation"

    def test_dispatch_reporting(self):
        d = self._make_dispatcher()
        skill = d.dispatch("生成报告report")
        assert skill["name"] == "reporting"

    def test_dispatch_waf_bypass(self):
        d = self._make_dispatcher()
        skill = d.dispatch("绕过waf")
        assert skill["name"] == "waf-bypass"

    def test_dispatch_web_pentest(self):
        d = self._make_dispatcher()
        skill = d.dispatch("web渗透测试网站")
        assert skill["name"] == "web-pentest"

    def test_dispatch_android_pentest(self):
        d = self._make_dispatcher()
        skill = d.dispatch("安卓android apk测试")
        assert skill["name"] == "android-pentest"

    def test_dispatch_client_reverse(self):
        d = self._make_dispatcher()
        skill = d.dispatch("逆向分析签名恢复")
        assert skill["name"] == "client-reverse"

    def test_dispatch_web_security_advanced(self):
        d = self._make_dispatcher()
        skill = d.dispatch("sql注入xss测试")
        assert skill["name"] == "web-security-advanced"

    def test_dispatch_ai_mcp_security(self):
        d = self._make_dispatcher()
        skill = d.dispatch("AI安全MCP安全评估")
        assert skill["name"] == "ai-mcp-security"

    def test_dispatch_intranet(self):
        d = self._make_dispatcher()
        skill = d.dispatch("内网横向移动域渗透")
        assert skill["name"] == "intranet-pentest-advanced"

    def test_dispatch_pentest_tools(self):
        d = self._make_dispatcher()
        skill = d.dispatch("nmap命令速查工具")
        assert skill["name"] == "pentest-tools"

    def test_dispatch_rapid_checklist(self):
        d = self._make_dispatcher()
        skill = d.dispatch("快速XSS payload速查")
        assert skill["name"] == "rapid-checklist"

    def test_dispatch_secknowledge_src(self):
        d = self._make_dispatcher()
        skill = d.dispatch("SRC 漏洞挖掘 目标 https://example.com SQL注入 XSS 测试")
        assert skill["name"] == "secknowledge-skill"

    def test_dispatch_secknowledge_ai_gaarm(self):
        d = self._make_dispatcher()
        skill = d.dispatch("GAARM AI应用安全测试 Prompt注入 MCP Agent 风险映射")
        assert skill["name"] == "secknowledge-skill"

    def test_dispatch_non_security_injects_nothing(self):
        """Unrelated, non-security text no longer auto-injects pentest-flow."""
        d = self._make_dispatcher()
        skill = d.dispatch("你好今天天气怎么样")
        assert skill is None

    def test_dispatch_generic_pentest_falls_back(self):
        """Generic pentest-like input without specificity falls back to pentest-flow."""
        d = self._make_dispatcher()
        skill = d.dispatch("帮我对这个目标做一次渗透测试")
        assert skill is not None
        assert skill["name"] == "pentest-flow"

    def test_dispatch_returns_dict(self):
        d = self._make_dispatcher()
        skill = d.dispatch("渗透测试")
        assert isinstance(skill, dict)
        assert "name" in skill
        assert "content" in skill
        assert "description" in skill

    def test_dispatch_specialized_over_core(self):
        """Specialized skills should win over core skills for specific inputs."""
        d = self._make_dispatcher()
        # "内网" could match post-exploitation (core) or intranet-pentest-advanced (specialized)
        # With the 1.5x boost, specialized should win for specific intranet keywords
        skill = d.dispatch("内网渗透横向移动")
        assert skill["name"] == "intranet-pentest-advanced"

    def test_dispatch_case_insensitive(self):
        """Dispatch should be case-insensitive."""
        d = self._make_dispatcher()
        skill1 = d.dispatch("SQL注入")
        skill2 = d.dispatch("sql注入")
        assert skill1["name"] == skill2["name"]

    def test_dispatch_crypto_toolkit(self):
        """Crypto-related inputs should dispatch to crypto-toolkit."""
        d = self._make_dispatcher()
        skill = d.dispatch("帮我base64解码")
        assert skill["name"] == "crypto-toolkit"

    def test_dispatch_crypto_hash(self):
        d = self._make_dispatcher()
        skill = d.dispatch("MD5哈希加密")
        assert skill["name"] == "crypto-toolkit"


# ── flag_skills.py ────────────────────────────────────────────────


class TestFlagSkills:
    """Test slash-dot flag skill registry and TUI application helpers."""

    def test_flag_skill_registry_includes_common_and_command_flags(self):
        from vulnclaw.skills.flag_skills import find_flag_skill

        assert find_flag_skill("/.only-port").canonical == "--only-port"
        assert find_flag_skill("/.--allow-actions").canonical == "--allow-actions"
        assert find_flag_skill("parallel-agents").canonical == "--parallel-agents"
        assert find_flag_skill("allow-remote").canonical == "--allow-remote"
        assert find_flag_skill("format").canonical == "--format"

    def test_flag_skill_aliases_normalize_slash_dot_forms(self):
        from vulnclaw.skills.flag_skills import find_flag_skill

        expected = find_flag_skill("--only-port")
        assert find_flag_skill("/.only-port") == expected
        assert find_flag_skill("/.--only-port") == expected
        assert find_flag_skill("only_port") == expected

    def test_complete_flag_skills_filters_by_prefix(self):
        from vulnclaw.skills.flag_skills import complete_flag_skills

        names = [skill.name for skill in complete_flag_skills("only-")]
        assert "only-port" in names
        assert "only-host" in names
        assert "blocked-host" not in names

    def test_apply_flag_skill_to_tui_state(self):
        from vulnclaw.cli.tui import TuiState
        from vulnclaw.skills.flag_skills import apply_flag_skill_to_tui_state, find_flag_skill

        state = TuiState()
        result = apply_flag_skill_to_tui_state(find_flag_skill("only-port"), "443", state)

        assert result.applied is True
        assert state.only_port == "443"

    def test_apply_flag_skill_rejects_invalid_port(self):
        from vulnclaw.cli.tui import TuiState
        from vulnclaw.skills.flag_skills import apply_flag_skill_to_tui_state, find_flag_skill

        state = TuiState()
        result = apply_flag_skill_to_tui_state(find_flag_skill("only-port"), "99999", state)

        assert result.applied is False
        assert result.error is True
        assert state.only_port == ""

    def test_no_resume_flag_applies_without_value(self):
        from vulnclaw.cli.tui import TuiState
        from vulnclaw.skills.flag_skills import apply_flag_skill_to_tui_state, find_flag_skill

        state = TuiState(resume=True)
        result = apply_flag_skill_to_tui_state(find_flag_skill("no-resume"), "", state)

        assert result.applied is True
        assert state.resume is False


# ── crypto_tools.py ────────────────────────────────────────────────


class TestCryptoTools:
    """Test the crypto toolkit module."""

    def test_base64_decode(self):
        from vulnclaw.skills.crypto_tools import execute

        result = execute("base64_decode", "TnNTY1RmLnBocA==")
        assert result["success"] is True
        assert result["result"] == "NsScTf.php"

    def test_base64_decode_urlsafe(self):
        from vulnclaw.skills.crypto_tools import execute

        result = execute("base64_decode", "SGVsbG8_d29ybGQ")
        assert result["success"] is True
        assert result["result"] == "Hello?world"

    def test_base64_decode_rejects_invalid_input(self):
        from vulnclaw.skills.crypto_tools import execute

        result = execute("base64_decode", "!!!!")
        assert result["success"] is False
        assert "Base64 解码失败" in result["error"]

    def test_base64_encode(self):
        from vulnclaw.skills.crypto_tools import execute

        result = execute("base64_encode", "NsScTf.php")
        assert result["success"] is True
        assert result["result"] == "TnNTY1RmLnBocA=="

    def test_hex_decode(self):
        from vulnclaw.skills.crypto_tools import execute

        result = execute("hex_decode", "4e73536354662e706870")
        assert result["success"] is True
        assert result["result"] == "NsScTf.php"

    def test_url_decode(self):
        from vulnclaw.skills.crypto_tools import execute

        result = execute("url_decode", "%2Fadmin")
        assert result["success"] is True
        assert result["result"] == "/admin"

    def test_rot13(self):
        from vulnclaw.skills.crypto_tools import execute

        result = execute("rot13_encode", "Hello")
        assert result["success"] is True
        assert result["result"] == "Uryyb"

    def test_md5_hash(self):
        from vulnclaw.skills.crypto_tools import execute

        result = execute("md5_hash", "admin")
        assert result["success"] is True
        assert result["result"] == "21232f297a57a5a743894a0e4a801fc3"

    def test_auto_decode_base64(self):
        from vulnclaw.skills.crypto_tools import execute

        result = execute("auto_decode", "TnNTY1RmLnBocA==")
        assert result["success"] is True
        assert "NsScTf.php" in result["result"]

    def test_caesar_decode_brute(self):
        from vulnclaw.skills.crypto_tools import execute

        result = execute("caesar_decode", "Khoor")
        assert result["success"] is True
        assert "Hello" in result["result"]

    def test_morse_decode(self):
        from vulnclaw.skills.crypto_tools import execute

        result = execute("morse_decode", ".... . .-.. .-.. ---")
        assert result["success"] is True
        assert "HELLO" in result["result"]

    def test_jwt_decode(self):
        from vulnclaw.skills.crypto_tools import execute

        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = execute("jwt_decode", token)
        assert result["success"] is True
        assert "HS256" in result["result"]

    def test_unknown_operation(self):
        from vulnclaw.skills.crypto_tools import execute

        result = execute("unknown_op", "test")
        assert result["success"] is False
        assert "未知操作" in result["error"]

    def test_unicode_decode(self):
        from vulnclaw.skills.crypto_tools import execute

        result = execute("unicode_decode", r"\u0048\u0065\u006c\u006c\u006f")
        assert result["success"] is True
        assert "Hello" in result["result"]

    def test_html_decode(self):
        from vulnclaw.skills.crypto_tools import execute

        result = execute("html_decode", "&#x3C;script&#x3E;")
        assert result["success"] is True
        assert "<script>" in result["result"]

    def test_list_operations(self):
        from vulnclaw.skills.crypto_tools import list_operations

        ops = list_operations()
        assert len(ops) >= 25
        assert "base64_decode" in ops
        assert "auto_decode" in ops
        assert "md5_hash" in ops
