import json
from types import SimpleNamespace


class DummyRuntime:
    def __init__(self):
        self.python_timeout_rounds = 0


class DummySession:
    def __init__(self, target="https://example.com"):
        self.target = target
        from vulnclaw.agent.context import TaskConstraints

        self.task_constraints = TaskConstraints()


class DummySafety:
    def __init__(self):
        self.enable_python_execute = True
        self.python_execute_restricted = False
        self.python_execute_mode = "trusted-local"
        self.python_execute_max_lines = 50
        self.python_execute_show_warning = False
        self.python_execute_max_output_chars = 0
        self.python_execute_audit_enabled = True


class DummyConfig:
    def __init__(self):
        self.safety = DummySafety()


class DummyAgent:
    def __init__(self):
        from vulnclaw.agent.context import ContextManager

        self.config = DummyConfig()
        self.context = ContextManager()
        self.runtime = DummyRuntime()
        self.session_state = DummySession()
        self.mcp_manager = None


class TestColdMemoryTool:
    async def test_memory_search_retrieves_archived_turn_on_demand(self, tmp_path):
        from vulnclaw.agent.builtin_tools import execute_mcp_tool
        from vulnclaw.agent.context import ContextManager
        from vulnclaw.agent.memory import MemoryStore

        agent = DummyAgent()
        store = MemoryStore(store_dir=tmp_path)
        store.archive_messages(
            [{"role": "tool", "tool_call_id": "old-call", "content": "legacy-marker"}]
        )
        agent.context = ContextManager(memory_store=store)

        result = await execute_mcp_tool(agent, "memory_search", {"query": "legacy-marker"})

        assert "legacy-marker" in result

    def test_memory_search_is_exposed_to_the_model(self):
        from vulnclaw.agent.builtin_tools import build_openai_tools

        names = {tool["function"]["name"] for tool in build_openai_tools(None)}
        assert "memory_search" in names

    async def test_memory_search_final_output_is_bounded(self, tmp_path):
        from vulnclaw.agent.builtin_tools import execute_mcp_tool
        from vulnclaw.agent.context import ContextManager
        from vulnclaw.agent.memory import MemoryStore

        agent = DummyAgent()
        store = MemoryStore(store_dir=tmp_path)
        store.archive_messages(
            [{"role": "tool", "content": "needle " + "x" * 10000}],
            scope=store.session_id,
        )
        agent.context = ContextManager(
            memory_store=store,
            search_max_chars=512,
        )

        result = await execute_mcp_tool(agent, "memory_search", {"query": "needle"})

        assert len(result) <= 512


class TestBuiltinPythonExecute:
    async def test_safe_mode_blocks_network_access(self, monkeypatch, tmp_path):
        import vulnclaw.agent.builtin_tools as builtin_tools

        agent = DummyAgent()
        agent.config.safety.python_execute_mode = "safe"
        monkeypatch.setattr(builtin_tools, "_write_python_audit", lambda *args, **kwargs: None)

        result = await builtin_tools.execute_python(
            agent,
            {
                "code": "import requests\nprint(requests.get('https://example.com').status_code)",
                "purpose": "recon",
            },
        )
        assert "safe mode blocked operation" in result

    async def test_lab_mode_blocks_subprocess(self, monkeypatch):
        import vulnclaw.agent.builtin_tools as builtin_tools

        agent = DummyAgent()
        agent.config.safety.python_execute_mode = "lab"
        monkeypatch.setattr(builtin_tools, "_write_python_audit", lambda *args, **kwargs: None)

        result = await builtin_tools.execute_python(
            agent,
            {"code": "import subprocess\nprint('x')", "purpose": "local helper"},
        )
        assert "lab mode blocked operation" in result

    async def test_trusted_local_allows_basic_code(self, monkeypatch):
        import vulnclaw.agent.builtin_tools as builtin_tools

        agent = DummyAgent()
        agent.config.safety.python_execute_mode = "trusted-local"
        monkeypatch.setattr(builtin_tools, "_write_python_audit", lambda *args, **kwargs: None)

        result = await builtin_tools.execute_python(
            agent,
            {"code": "print('ok')", "purpose": "demo"},
        )
        assert "ok" in result

    async def test_python_execute_keeps_raw_and_returns_small_output_to_model(self, monkeypatch):
        import vulnclaw.agent.builtin_tools as builtin_tools
        from vulnclaw.agent.tool_call_manager import handle_tool_calls_with_results

        class ToolAgent(DummyAgent):
            async def _execute_mcp_tool(self, func_name, func_args):
                return await builtin_tools.execute_mcp_tool(self, func_name, func_args)

        agent = ToolAgent()
        agent.config.safety.python_execute_mode = "trusted-local"
        agent.config.safety.python_execute_max_output_chars = 20
        monkeypatch.setattr(builtin_tools, "_write_python_audit", lambda *args, **kwargs: None)

        code = "print('A' * 5000 + 'RAW_END')"
        message = SimpleNamespace(
            tool_calls=[
                SimpleNamespace(
                    id="c1",
                    function=SimpleNamespace(
                        name="python_execute",
                        arguments=json.dumps({"code": code, "purpose": "raw output test"}),
                    ),
                )
            ]
        )

        results, _ = await handle_tool_calls_with_results(agent, message)

        assert "RAW_END" in results[0]["content"]
        assert "raw output stored" not in results[0]["content"]
        raw = agent.context.state.agent_state.evidence[0].content
        assert "RAW_END" in raw
        assert "...[truncated]..." not in raw

    async def test_audit_writer_emits_jsonl(self, monkeypatch, tmp_path):
        import vulnclaw.agent.builtin_tools as builtin_tools

        agent = DummyAgent()

        monkeypatch.setattr(
            "vulnclaw.config.settings.PYTHON_EXECUTE_AUDIT_FILE",
            tmp_path / "python_execute_audit.jsonl",
        )
        monkeypatch.setattr("vulnclaw.config.settings.ensure_dirs", lambda: None)

        builtin_tools._write_python_audit(
            agent,
            purpose="demo",
            code="print('x')",
            mode="safe",
            outcome="blocked",
            blocked_reason="requests",
        )

        content = (tmp_path / "python_execute_audit.jsonl").read_text(encoding="utf-8").strip()
        record = json.loads(content)
        assert record["mode"] == "safe"
        assert record["outcome"] == "blocked"
        assert record["blocked_reason"] == "requests"

    async def test_http_probe_batch_compares_variants_without_network(self, monkeypatch):
        import vulnclaw.agent.builtin_tools as builtin_tools

        class DummyResponse:
            def __init__(self, url, text):
                self.status_code = 200
                self.url = url
                self.text = text
                self.content = text.encode()
                self.headers = {"content-type": "text/html"}

        class DummyClient:
            def __init__(self, *args, **kwargs):
                self.calls = []

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def request(self, method, url, **kwargs):
                self.calls.append((method, url, kwargs))
                text = "<title>T</title><form><input name='id'>flag{batch}</form>"
                return DummyResponse(url, text)

        monkeypatch.setattr(builtin_tools.httpx, "Client", DummyClient)
        agent = DummyAgent()

        result = await builtin_tools.execute_http_probe_batch(
            agent,
            {
                "base_url": "https://example.com/app/",
                "requests": [
                    {"url": "select.php", "params": {"id": "1"}},
                    {"raw_url": "select.php?id=1%27", "label": "quote"},
                ],
            },
        )

        assert "http_probe_batch results" in result
        assert "raw-url quote" in result
        assert "request=GET https://example.com/app/select.php" in result
        assert 'params={"id":"1"}' in result
        assert "flag{batch}" in result
        assert "body_length=" in result
        assert "body:" in result
        assert "Same-body groups" in result

    async def test_http_probe_batch_exposes_response_headers_and_defaults_tls_off(
        self, monkeypatch
    ):
        import vulnclaw.agent.builtin_tools as builtin_tools

        seen_client_kwargs = []

        class DummyResponse:
            def __init__(self, url, text):
                self.status_code = 200
                self.url = url
                self.text = text
                self.content = text.encode()
                self.headers = {
                    "content-type": "text/html",
                    "x-powered-by": "PHP/5.6.40",
                }

        class DummyClient:
            def __init__(self, *args, **kwargs):
                seen_client_kwargs.append(dict(kwargs))

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def request(self, method, url, **kwargs):
                return DummyResponse(url, "<title>T</title>ok")

        monkeypatch.setattr(builtin_tools.httpx, "Client", DummyClient)
        agent = DummyAgent()

        result = await builtin_tools.execute_http_probe_batch(
            agent,
            {"base_url": "https://example.com/", "requests": [{"url": "/"}]},
        )

        assert seen_client_kwargs[0]["verify"] is False
        assert "response_headers=" in result
        assert "PHP/5.6.40" in result

    async def test_http_probe_batch_returns_full_body_by_default(self, monkeypatch):
        import vulnclaw.agent.builtin_tools as builtin_tools

        class DummyResponse:
            def __init__(self, url, text):
                self.status_code = 200
                self.url = url
                self.text = text
                self.content = text.encode()
                self.headers = {"content-type": "text/html"}

        class DummyClient:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def request(self, method, url, **kwargs):
                text = "A" * 3000 + "select-waf.php"
                return DummyResponse(url, text)

        monkeypatch.setattr(builtin_tools.httpx, "Client", DummyClient)
        agent = DummyAgent()

        result = await builtin_tools.execute_http_probe_batch(
            agent,
            {"base_url": "https://example.com/", "requests": [{"url": "/"}]},
        )

        assert "select-waf.php" in result
        assert "truncated_to=" not in result

    async def test_http_probe_batch_auto_renders_highlighted_source(self, monkeypatch):
        import vulnclaw.agent.builtin_tools as builtin_tools

        highlighted = (
            '<code><span style="color:#0000BB">&lt;?php<br /></span>'
            '<span style="color:#007700">highlight_file(</span>'
            '<span style="color:#0000BB">__FILE__</span>'
            '<span style="color:#007700">);<br />'
            "if(!preg_match('/[oc]:\\d+:/i', $_COOKIE['user'])){<br />"
            "$user = unserialize($_COOKIE['user']);<br />"
            "}<br /></span></code>"
        )

        class DummyResponse:
            def __init__(self, url, text):
                self.status_code = 200
                self.url = url
                self.text = text
                self.content = text.encode()
                self.headers = {"content-type": "text/html"}

        class DummyClient:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def request(self, method, url, **kwargs):
                return DummyResponse(url, highlighted)

        monkeypatch.setattr(builtin_tools.httpx, "Client", DummyClient)
        agent = DummyAgent()

        result = await builtin_tools.execute_http_probe_batch(
            agent,
            {"base_url": "https://example.com/", "requests": [{"url": "/source.php"}]},
        )

        assert "# Decoded highlighted source (auto)" in result
        assert "highlight_file(__FILE__);" in result
        assert "if(!preg_match('/[oc]:\\d+:/i', $_COOKIE['user'])){" in result
        assert "$user = unserialize($_COOKIE['user']);" in result
        assert result.index("# Decoded highlighted source (auto)") < result.index("signals=")

    async def test_http_probe_batch_prints_audited_request_surface(self, monkeypatch):
        import vulnclaw.agent.builtin_tools as builtin_tools

        class DummyResponse:
            def __init__(self, url, text):
                self.status_code = 200
                self.url = url
                self.text = text
                self.content = text.encode()
                self.headers = {"content-type": "text/plain"}

        class DummyClient:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def request(self, method, url, **kwargs):
                return DummyResponse(url, f"{method} ok")

        monkeypatch.setattr(builtin_tools.httpx, "Client", DummyClient)
        agent = DummyAgent()

        result = await builtin_tools.execute_http_probe_batch(
            agent,
            {
                "base_url": "https://example.com/",
                "requests": [
                    {
                        "method": "POST",
                        "url": "/api",
                        "headers": {
                            "Authorization": "Bearer secret",
                            "Cookie": "user=O%3A%2B4%3A%22Test%22%3A0%3A%7B%7D",
                        },
                        "cookies": {"debug": 'x;y"z'},
                        "data": {"id": "1"},
                        "label": "exact-request",
                    }
                ],
            },
        )

        assert "POST exact-request" in result
        assert "request=POST https://example.com/api" in result
        assert '"Authorization":"[masked]"' in result
        assert "Bearer secret" not in result
        assert "Cookie" in result
        assert "O%3A%2B4" in result
        assert 'cookies={"debug":"x;y\\"z"}' in result
        assert "exact-cookie-note" in result
        assert 'body={"id":"1"}' in result

    async def test_source_extract_normalizes_highlighted_php_evidence(self):
        import vulnclaw.agent.builtin_tools as builtin_tools

        agent = DummyAgent()
        raw = """
        <html><body>
        <code><span>&lt;?php</span><br />
        <span>highlight_file(__FILE__);</span><br />
        <span>class User { function __destruct(){ eval($_GET['cmd']); } }</span><br />
        <span>unserialize($_COOKIE['payload']);</span><br />
        </code>
        <form action="api.php" method="get"><input name="id"></form>
        </body></html>
        """
        record = agent.context.state.agent_state.remember_tool_result(
            tool="fetch",
            arguments={"url": "https://example.com/source.php"},
            output=raw,
        )

        result = await builtin_tools.execute_mcp_tool(
            agent,
            "source_extract",
            {"evidence_id": record.id},
        )

        assert "High-signal source lines" in result
        assert "<?php" in result
        assert "highlight_file(__FILE__);" in result
        assert any(
            line.endswith("highlight_file(__FILE__);")
            for line in result.splitlines()
            if line.startswith("L")
        )
        assert "__destruct" in result
        assert "class User { function __destruct(){ eval($_GET['cmd']); } }" in result
        assert "unserialize($_COOKIE" in result
        assert "form:" in result
        assert 'action="api.php"' in result

    async def test_shell_command_runs_local_verification_and_returns_full_output(self):
        import sys

        import vulnclaw.agent.builtin_tools as builtin_tools

        agent = DummyAgent()
        # Use the running interpreter instead of a bare ``python``, which is not
        # on PATH where the interpreter is installed only as ``python3`` (macOS
        # default, minimal Linux/Docker). The path is left unquoted so the shell
        # token is a bare executable, exactly like the previous ``python`` — this
        # keeps the Windows ``cmd`` command line unchanged in shape (POSIX single
        # quotes from ``shlex.quote`` break ``cmd``; hosted CI paths have no spaces).
        command = f"{sys.executable} -c \"print('SHELL_OK')\""

        result = await builtin_tools.execute_mcp_tool(
            agent,
            "shell_command",
            {"command": command, "timeout_ms": 10000, "shell": "cmd"},
        )

        assert "Exit code: 0" in result
        assert "SHELL_OK" in result

    async def test_runtime_diff_probe_generates_signed_length_regex_bypass_candidate(self):
        import vulnclaw.agent.builtin_tools as builtin_tools

        agent = DummyAgent()
        payload = (
            'O:11:"ctfShowUser":1:{s:5:"class";'
            'O:8:"backDoor":1:{s:4:"code";s:11:"echo 12345;";}}'
        )

        result = await builtin_tools.execute_mcp_tool(
            agent,
            "runtime_diff_probe",
            {
                "mode": "regex",
                "filter_regex": r"/[oc]:\d+:/i",
                "payload": payload,
                "mutations": ["signed_lengths"],
            },
        )

        assert "# runtime_diff_probe - regex" in result
        assert "[1] original" in result
        assert "filter_hit=true" in result
        assert "[2] signed object/class lengths" in result
        assert 'O:+11:"ctfShowUser"' in result
        assert 'O:+8:"backDoor"' in result
        assert "filter_hit=false" in result

    async def test_runtime_diff_probe_warns_on_target_php_version_mismatch(self, monkeypatch):
        import vulnclaw.agent.builtin_tools as builtin_tools

        agent = DummyAgent()
        agent.context.state.agent_state.remember_tool_result(
            tool="fetch",
            arguments={"url": "https://target/"},
            output="Headers: {'x-powered-by': 'PHP/5.6.40'}",
            status=200,
        )
        monkeypatch.setattr(builtin_tools.shutil, "which", lambda name: "php" if name == "php" else None)

        def fake_run(*args, **kwargs):
            return SimpleNamespace(
                returncode=0,
                stdout=(
                    "# runtime_diff_probe - php_serialize\n"
                    "local_php_version=7.3.4\n"
                    "filter_regex=/[oc]:\\d+:/i\n"
                    "candidate_count=2\n"
                    "[2] signed object/class lengths\n"
                    "filter_hit=0\n"
                    "unserialize_ok=false\n"
                ),
                stderr="",
            )

        monkeypatch.setattr(builtin_tools.subprocess, "run", fake_run)

        result = await builtin_tools.execute_mcp_tool(
            agent,
            "runtime_diff_probe",
            {
                "mode": "php_serialize",
                "filter_regex": r"/[oc]:\d+:/i",
                "payload": 'O:11:"ctfShowUser":1:{}',
                "mutations": ["signed_lengths"],
            },
        )

        assert "target_runtime=PHP/5.6.40" in result
        assert "local_runtime=PHP/7.3.4" in result
        assert "remote-verify the exact URL-encoded signed candidate" in result

    async def test_runtime_diff_probe_emits_php5_remote_candidate_from_probe_headers(
        self, monkeypatch
    ):
        import vulnclaw.agent.builtin_tools as builtin_tools

        agent = DummyAgent()
        agent.context.state.agent_state.remember_tool_result(
            tool="http_probe_batch",
            arguments={"requests": [{"url": "https://target/"}]},
            output='response_headers={"x-powered-by":"PHP/5.6.40"}',
            status=200,
        )
        monkeypatch.setattr(builtin_tools.shutil, "which", lambda name: "php" if name == "php" else None)

        def fake_run(*args, **kwargs):
            return SimpleNamespace(
                returncode=0,
                stdout=(
                    "# runtime_diff_probe - php_serialize\n"
                    "local_php_version=7.3.4\n"
                    "filter_regex=/[oc]:\\d+:/i\n"
                    "candidate_count=2\n"
                    "[2] signed object/class lengths\n"
                    "filter_hit=0\n"
                    "unserialize_ok=false\n"
                ),
                stderr="",
            )

        monkeypatch.setattr(builtin_tools.subprocess, "run", fake_run)
        payload = (
            'O:11:"ctfShowUser":1:{s:5:"class";'
            'O:8:"backDoor":1:{s:4:"code";s:13:"echo "VCLAW";";}}'
        )

        result = await builtin_tools.execute_mcp_tool(
            agent,
            "runtime_diff_probe",
            {
                "mode": "php_serialize",
                "filter_regex": r"/[oc]:\d+:/i",
                "payload": payload,
                "mutations": ["signed_lengths"],
            },
        )

        assert "[remote_verification_required]" in result
        assert "REMOTE VERIFICATION OUTRANKS LOCAL unserialize_ok=false" in result
        assert 'remote_candidate_raw=O:+11:"ctfShowUser"' in result
        assert "O%3A%2B11%3A%22ctfShowUser" in result


class TestBuiltinMcpExecution:
    def test_build_openai_tools_filters_schema_by_active_role(self):
        import vulnclaw.agent.builtin_tools as builtin_tools

        class DummyMcpManager:
            def get_tool_schemas(self):
                return [
                    {
                        "name": "fetch",
                        "description": "Fetch a URL",
                        "inputSchema": {"type": "object", "properties": {}},
                    }
                ]

        tool_names = {
            tool["function"]["name"]
            for tool in builtin_tools.build_openai_tools(
                DummyMcpManager(), active_role="developer"
            )
        }

        assert "python_execute" in tool_names
        assert "source_extract" in tool_names
        assert "runtime_diff_probe" in tool_names
        assert "shell_command" in tool_names
        assert "crypto_decode" in tool_names
        assert "fetch" not in tool_names
        assert "nmap_scan" not in tool_names

    async def test_execute_mcp_tool_rejects_out_of_role_tool(self):
        import vulnclaw.agent.builtin_tools as builtin_tools

        class DummyMcpManager:
            async def call_tool(self, tool_name, args):
                return {"ok": True, "content": "should not run"}

        agent = DummyAgent()
        agent.active_role = "adviser"
        agent.mcp_manager = DummyMcpManager()

        result = await builtin_tools.execute_mcp_tool(
            agent, "python_execute", {"code": "print('should not run')"}
        )

        assert "role_tool_violation" in result
        assert "adviser" in result
        assert "python_execute" in result

    async def test_execute_loads_secknowledge_reference(self):
        import vulnclaw.agent.builtin_tools as builtin_tools

        agent = DummyAgent()
        result = await builtin_tools.execute_mcp_tool(
            agent,
            "load_skill_reference",
            {
                "skill_name": "secknowledge-skill",
                "reference_name": "web-sqli.md",
            },
        )

        assert "SQL" in result or "sql" in result
        assert "注入" in result or "injection" in result.lower()

    async def test_execute_mcp_tool_includes_structured_content_summary(self):
        import vulnclaw.agent.builtin_tools as builtin_tools

        class DummyMcpManager:
            async def call_tool(self, tool_name, args):
                return {
                    "ok": True,
                    "content": "navigated to page",
                    "structured_content": {"url": "https://example.com", "status": "ok"},
                }

        agent = DummyAgent()
        agent.mcp_manager = DummyMcpManager()

        result = await builtin_tools.execute_mcp_tool(
            agent, "navigate", {"url": "https://example.com"}
        )
        assert "navigated to page" in result
        assert "[structured]" in result
        assert '"status": "ok"' in result

    async def test_execute_fetch_blocks_tool_level_exploit_when_only_recon_allowed(self):
        import vulnclaw.agent.builtin_tools as builtin_tools

        class DummyMcpManager:
            async def call_tool(self, tool_name, args):
                return {"ok": True, "content": "should not run", "structured_content": {}}

        agent = DummyAgent()
        agent.mcp_manager = DummyMcpManager()
        agent.session_state.task_constraints.allowed_actions = ["recon"]
        agent.session_state.task_constraints.strict_mode = True

        result = await builtin_tools.execute_mcp_tool(
            agent,
            "fetch",
            {"url": "https://example.com/login?id=1' OR 1=1--", "method": "GET"},
        )
        assert "constraint_violation" in result
        assert "tool 'fetch'" in result

    async def test_execute_python_blocks_tool_level_exploit_when_only_recon_allowed(self):
        import vulnclaw.agent.builtin_tools as builtin_tools

        agent = DummyAgent()
        agent.session_state.task_constraints.allowed_actions = ["recon"]
        agent.session_state.task_constraints.strict_mode = True

        result = await builtin_tools.execute_mcp_tool(
            agent,
            "python_execute",
            {"code": "import requests\nrequests.get('https://example.com/admin?cmd=whoami')"},
        )
        assert "constraint_violation" in result
        assert "tool 'python_execute'" in result

    async def test_execute_python_blocks_blocked_host(self):
        import vulnclaw.agent.builtin_tools as builtin_tools

        agent = DummyAgent()
        agent.session_state.task_constraints.blocked_hosts = ["example.com"]
        agent.session_state.task_constraints.strict_mode = True

        result = await builtin_tools.execute_python(
            agent,
            {"code": "import requests\nrequests.get('https://example.com/admin')"},
        )
        assert "constraint_violation" in result
        assert "Host example.com" in result

    async def test_execute_python_allows_in_scope_host_with_port(self):
        import vulnclaw.agent.builtin_tools as builtin_tools

        agent = DummyAgent()
        agent.session_state.task_constraints.allowed_hosts = ["localhost"]
        agent.session_state.task_constraints.strict_mode = True

        result = await builtin_tools.execute_python(
            agent,
            {"code": "import requests\nrequests.get('http://localhost:3000/home')"},
        )
        assert "constraint_violation" not in result

    async def test_execute_python_blocks_out_of_scope_host_with_port(self):
        import vulnclaw.agent.builtin_tools as builtin_tools

        agent = DummyAgent()
        agent.session_state.task_constraints.allowed_hosts = ["localhost"]
        agent.session_state.task_constraints.strict_mode = True

        result = await builtin_tools.execute_python(
            agent,
            {"code": "import requests\nrequests.get('http://evil.example:8080/x')"},
        )
        assert "constraint_violation" in result
        assert "Host evil.example" in result

    async def test_execute_nmap_blocks_out_of_scope_port(self):
        import vulnclaw.agent.builtin_tools as builtin_tools

        agent = DummyAgent()
        agent.session_state.task_constraints.allowed_ports = [443]
        agent.session_state.task_constraints.strict_mode = True

        result = await builtin_tools.execute_nmap(
            agent,
            {"target": "example.com", "ports": "80", "scan_type": "tcp"},
        )
        assert "constraint_violation" in result
        assert "80" in result
        assert "443" in result
