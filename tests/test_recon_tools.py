from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from vulnclaw.agent import recon_tools
from vulnclaw.config.schema import ReconConfig, VulnClawConfig


def _agent(recon: ReconConfig | None = None):
    cfg = VulnClawConfig()
    if recon is not None:
        cfg.recon = recon
    return SimpleNamespace(config=cfg, session_state=SimpleNamespace(task_constraints=None))


class _Resp:
    def __init__(self, *, json_data=None, text="", content=b"", status=200, headers=None):
        self._json = json_data
        self.text = text
        self.content = content or text.encode()
        self.status_code = status
        self.headers = headers or {}

    def json(self):
        return self._json


class _FakeClient:
    """Minimal httpx.AsyncClient stand-in driven by a routing callable."""

    def __init__(self, router):
        self._router = router

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url, params=None, headers=None):
        return self._router("GET", url, params, None)

    async def post(self, url, headers=None, content=None):
        return self._router("POST", url, None, content)


# ── JS 提取（纯函数）────────────────────────────────────────────────


def test_extract_from_js_pulls_paths_domains_secrets():
    content = """
        var api = "/api/v1/user/list";
        fetch("https://cdn.example.com/static/app.js");
        const k = {api_key: "AKIAABCDEFGHIJKLMNOP"};
        let t = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36";
        url: "/admin/login.action"
    """
    out = recon_tools.extract_from_js(content, base_host="example.com")
    assert "/api/v1/user/list" in out["paths"]
    assert "/admin/login.action" in out["paths"]
    assert "cdn.example.com" in out["domains"]
    assert any("aws_ak" in s for s in out["secrets"])
    assert any("jwt" in s for s in out["secrets"])


def test_extract_from_js_infers_rest_crud_from_base_and_entity():
    """base path + entity name → CRUD 动词推断（修复 User/list、Org/list 漏判）。"""
    content = """
        var baseUrl = "/jalis/rest";
        var smBase = "/smweb/rest";
        var entity = "User";
        var org = "Org";
    """
    out = recon_tools.extract_from_js(content)
    paths = out["paths"]
    assert "/jalis/rest/User/list" in paths
    assert "/jalis/rest/Org/list" in paths
    assert "/smweb/rest/User/list" in paths
    assert "/smweb/rest/Org/list" in paths


def test_extract_from_js_discovers_dynamic_entities():
    """PascalCase 实体名动态提取——不依赖硬编码实体列表。"""
    content = """
        var base = "/smweb/rest";
        url: "AppRoleService";
        var c = "Count";
        var art = "Article";
    """
    out = recon_tools.extract_from_js(content)
    paths = out["paths"]
    assert "/smweb/rest/AppRoleService/list" in paths
    assert "/smweb/rest/Count/list" in paths
    assert "/smweb/rest/Article/list" in paths


def test_extract_from_js_captures_short_fragments():
    """不以 / 开头的 REST 片段（如 "User/list"）也要提取。"""
    content = """$.post(baseUrl + "User/list", data);"""
    out = recon_tools.extract_from_js(content)
    assert any("User/list" in p for p in out["paths"])


def test_extract_from_js_captures_framework_verb_variants():
    """listForLayUI / getAllByType 等框架变体也匹配。"""
    content = """$.post(base + "Article/listForLayUI", data);"""
    out = recon_tools.extract_from_js(content)
    assert any("Article/listForLayUI" in p for p in out["paths"])


# ── 空间测绘：查询构造 + 解析 ───────────────────────────────────────


async def test_space_search_fofa_builds_b64_query_and_parses(monkeypatch):
    captured = {}

    def router(method, url, params, content):
        captured["url"] = url
        captured["params"] = params
        # FOFA results: [host, ip, port, title, domain, server, protocol]
        return _Resp(json_data={
            "error": False, "size": 1,
            "results": [["http://t.example.com", "1.2.3.4", "80", "Home", "example.com", "nginx", "http"]],
        })

    monkeypatch.setattr(recon_tools, "_make_client", lambda cfg: _FakeClient(router))
    agent = _agent(ReconConfig(fofa_email="a@b.com", fofa_key="k"))
    res = await recon_tools.execute_space_search(agent, {"engine": "fofa", "domain": "example.com"})

    assert "fofa.info" in captured["url"]
    # qbase64 should decode to domain="example.com"
    import base64
    assert base64.b64decode(captured["params"]["qbase64"]).decode() == 'domain="example.com"'
    assert "1.2.3.4" in res and "example.com" in res


async def test_space_search_missing_key_reports_gracefully(monkeypatch):
    monkeypatch.setattr(recon_tools, "_make_client", lambda cfg: _FakeClient(lambda *a: _Resp()))
    agent = _agent(ReconConfig())  # no keys
    res = await recon_tools.execute_space_search(agent, {"engine": "fofa", "domain": "x.com"})
    assert "未配置" in res


async def test_space_search_quake_uses_token_header_and_post(monkeypatch):
    seen = {}

    def router(method, url, params, content):
        seen["method"] = method
        seen["body"] = json.loads(content) if content else None
        return _Resp(json_data={
            "code": 0, "meta": {"pagination": {"total": 1}},
            "data": [{"ip": "9.9.9.9", "port": 443, "domain": "x.com",
                      "service": {"name": "http", "http": {"title": "T", "host": "x.com"}}}],
        })

    monkeypatch.setattr(recon_tools, "_make_client", lambda cfg: _FakeClient(router))
    agent = _agent(ReconConfig(quake_key="tok"))
    res = await recon_tools.execute_space_search(agent, {"engine": "quake", "query": 'domain:"x.com"'})
    assert seen["method"] == "POST"
    assert seen["body"]["query"] == 'domain:"x.com"'
    assert "9.9.9.9" in res


# ── 目录枚举：全局伪装 200 识别 ─────────────────────────────────────


async def test_dir_enum_aborts_on_global_200(monkeypatch):
    def router(method, url, params, content):
        # 任何路径都返回 200 → 伪装
        return _Resp(text="ok", status=200)

    monkeypatch.setattr(recon_tools, "_make_client", lambda cfg: _FakeClient(router))
    agent = _agent(ReconConfig())
    res = await recon_tools.execute_dir_enum(agent, {"url": "http://t.example.com"})
    assert "终止" in res and "200" in res


async def test_dir_enum_filters_and_reports_hits(monkeypatch):
    def router(method, url, params, content):
        if "vulnclaw_nope" in url:
            return _Resp(text="not found", status=404)
        if url.rstrip("/").endswith("/admin"):
            return _Resp(text="ADMIN PANEL " * 20, status=200)
        return _Resp(text="nope", status=404)

    monkeypatch.setattr(recon_tools, "_make_client", lambda cfg: _FakeClient(router))
    agent = _agent(ReconConfig())
    res = await recon_tools.execute_dir_enum(agent, {"url": "http://t.example.com"})
    assert "/admin" in res
    assert "[200]" in res


async def test_dir_enum_respects_host_constraint(monkeypatch):
    monkeypatch.setattr(recon_tools, "_make_client", lambda cfg: _FakeClient(lambda *a: _Resp()))
    agent = _agent(ReconConfig())
    # constrain scope to a different host
    agent.session_state.task_constraints = SimpleNamespace(
        is_empty=lambda: False,
        allowed_hosts=["only-this.com"], blocked_hosts=[],
        allowed_paths=[], blocked_paths=[],
    )
    res = await recon_tools.execute_dir_enum(agent, {"url": "http://t.example.com"})
    assert "constraint_violation" in res


# ── 子域名枚举：被动聚合 + 字典爆破关闭时不解析 ─────────────────────


async def test_unauth_classify():
    assert recon_tools._classify_unauth(401, "x", "")[1] is False
    assert recon_tools._classify_unauth(403, "x", "")[1] is False
    assert recon_tools._classify_unauth(404, "x", "")[1] is False
    # 200 returning JSON data → lead
    v, lead = recon_tools._classify_unauth(200, '{"users":[1,2,3]}', "application/json")
    assert lead is True and "未授权" in v
    # 200 but login page → not a lead
    v2, lead2 = recon_tools._classify_unauth(200, "请登录后访问", "text/html")
    assert lead2 is False


async def test_unauth_test_skips_destructive_and_flags_data(monkeypatch):
    def router(method, url, params, content):
        if url.endswith("/api/user/list"):
            return _Resp(json_data=None, text='{"data":[{"uid":1}]}', status=200)
        if url.endswith("/api/user/profile"):
            return _Resp(text="<html>请登录</html>", status=200)
        return _Resp(text="nope", status=404)

    monkeypatch.setattr(recon_tools, "_make_client", lambda cfg: _FakeClient(router))
    # patch content-type via header — _FakeClient returns _Resp; add headers attr
    agent = _agent(ReconConfig())
    res = await recon_tools.execute_unauth_test(agent, {
        "base_url": "http://t.example.com",
        "endpoints": ["/api/user/list", "/api/user/profile", "/api/user/delete?id=1"],
    })
    assert "跳过(破坏性接口)" in res  # delete endpoint skipped
    assert "/api/user/list" in res


async def test_js_recon_auto_probes_endpoints(monkeypatch):
    calls = {"n": 0}

    def router(method, url, params, content):
        calls["n"] += 1
        if url.endswith("/index.html") or url.endswith("t.example.com/"):
            return _Resp(text='<script src="/app.js"></script>', status=200)
        if url.endswith("/app.js"):
            return _Resp(text='fetch("/api/v1/admin/users")', status=200)
        if "/api/v1/admin/users" in url:
            return _Resp(text='{"ok":true}', status=200)
        return _Resp(text="x", status=404)

    monkeypatch.setattr(recon_tools, "_make_client", lambda cfg: _FakeClient(router))
    agent = _agent(ReconConfig())
    res = await recon_tools.execute_js_recon(agent, {"url": "http://t.example.com/index.html"})
    # discovered endpoint should appear in the auto unauth-probe section
    assert "未授权访问探测" in res
    assert "/api/v1/admin/users" in res


async def test_subdomain_enum_passive_only(monkeypatch):
    def router(method, url, params, content):
        return _Resp(json_data={
            "error": False, "size": 2,
            "results": [
                ["http://api.example.com", "1.1.1.1", "80", "", "api.example.com", "", ""],
                ["http://mail.example.com", "2.2.2.2", "443", "", "mail.example.com", "", ""],
            ],
        })

    monkeypatch.setattr(recon_tools, "_make_client", lambda cfg: _FakeClient(router))
    agent = _agent(ReconConfig(fofa_email="a@b.com", fofa_key="k"))
    res = await recon_tools.execute_subdomain_enum(agent, {"domain": "example.com", "brute": False})
    assert "api.example.com" in res
    assert "mail.example.com" in res
