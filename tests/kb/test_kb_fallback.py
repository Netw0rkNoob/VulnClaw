"""Tests for KB retrieval graceful degradation (keyword fallback)."""

import vulnclaw.kb.retriever as retriever_mod
from vulnclaw.i18n import current_lang, init_i18n
from vulnclaw.kb.retriever import (
    KeywordRetriever,
    KnowledgeRetriever,
    RetrieverStatus,
)
from vulnclaw.kb.store import KnowledgeStore


def _seed_store(tmp_path):
    store = KnowledgeStore(store_dir=tmp_path)
    store.add_entry(
        "techniques",
        "sqli-bypass",
        {
            "title": "SQL 注入绕过技巧",
            "description": "绕过 WAF 的 SQL injection payload 构造方法",
            "tags": ["sqli", "waf-bypass", "web"],
            "bypass_methods": ["大小写混合 SeLeCt", "内联注释"],
        },
    )
    store.add_entry(
        "techniques",
        "xss-bypass",
        {
            "title": "XSS 绕过技巧",
            "description": "绕过 WAF 的 cross site scripting payload",
            "tags": ["xss", "waf-bypass", "web"],
        },
    )
    store.add_entry(
        "cve",
        "CVE-2026-0001",
        {
            "title": "Nginx Buffer Overflow",
            "description": "A remote nginx overflow vulnerability",
            "tags": ["nginx", "rce"],
        },
    )
    return store


# ── Automatic degradation when ChromaDB unavailable ──────────────────


class TestAutoDegradation:
    def test_falls_back_to_keyword_when_chromadb_missing(self, tmp_path, monkeypatch):
        monkeypatch.setattr(retriever_mod, "CHROMADB_AVAILABLE", False)
        monkeypatch.setattr(retriever_mod, "CHROMADB_IMPORT_ERROR", "No module named 'chromadb'")
        store = _seed_store(tmp_path)

        retriever = KnowledgeRetriever(store=store)
        assert retriever.get_status() == RetrieverStatus.KEYWORD_FALLBACK
        assert "chromadb" in retriever.get_status_detail().lower()
        assert isinstance(retriever._backend, KeywordRetriever)

    def test_status_disabled_when_no_data(self, tmp_path, monkeypatch):
        monkeypatch.setattr(retriever_mod, "CHROMADB_AVAILABLE", False)
        store = KnowledgeStore(store_dir=tmp_path)  # empty

        retriever = KnowledgeRetriever(store=store)
        assert retriever.get_status() == RetrieverStatus.DISABLED
        # Generic retrieve degrades to empty list rather than raising.
        assert retriever.retrieve("anything") == []


# ── Keyword retrieval functionality ──────────────────────────────────


class TestKeywordRetriever:
    def test_retrieve_ranks_relevant_first(self, tmp_path, monkeypatch):
        monkeypatch.setattr(retriever_mod, "CHROMADB_AVAILABLE", False)
        store = _seed_store(tmp_path)
        kw = KeywordRetriever(store)

        assert kw.has_data()
        results = kw.retrieve("sql injection waf bypass", top_k=3)
        assert results, "expected at least one keyword match"
        assert results[0]["id"] == "sqli-bypass"

    def test_retrieve_chinese_query_finds_chinese_entry(self, tmp_path):
        store = _seed_store(tmp_path)
        kw = KeywordRetriever(store)

        # The old [a-z0-9]+ tokenizer dropped CJK entirely, so this returned [].
        results = kw.retrieve("注入绕过", top_k=3)
        assert results, "expected Chinese query to match Chinese KB entries"
        assert results[0]["id"] == "sqli-bypass"

    def test_retrieve_matches_cve_by_service(self, tmp_path):
        store = _seed_store(tmp_path)
        kw = KeywordRetriever(store)
        results = kw.retrieve("nginx overflow", top_k=3)
        assert any(r["id"] == "CVE-2026-0001" for r in results)

    def test_retrieve_empty_query_returns_empty(self, tmp_path):
        store = _seed_store(tmp_path)
        kw = KeywordRetriever(store)
        assert kw.retrieve("", top_k=3) == []

    def test_retrieve_no_match_returns_empty(self, tmp_path):
        store = _seed_store(tmp_path)
        kw = KeywordRetriever(store)
        assert kw.retrieve("zzzzz_nonexistent_token", top_k=3) == []

    def test_has_data_false_on_empty_store(self, tmp_path):
        store = KnowledgeStore(store_dir=tmp_path)
        kw = KeywordRetriever(store)
        assert kw.has_data() is False


# ── Status reporting ─────────────────────────────────────────────────


class TestStatusReporting:
    def test_get_status_returns_enum(self, tmp_path, monkeypatch):
        monkeypatch.setattr(retriever_mod, "CHROMADB_AVAILABLE", False)
        store = _seed_store(tmp_path)
        retriever = KnowledgeRetriever(store=store)
        assert isinstance(retriever.get_status(), RetrieverStatus)

    def test_status_detail_is_string(self, tmp_path, monkeypatch):
        monkeypatch.setattr(retriever_mod, "CHROMADB_AVAILABLE", False)
        store = _seed_store(tmp_path)
        retriever = KnowledgeRetriever(store=store)
        assert isinstance(retriever.get_status_detail(), str)
        assert retriever.get_status_detail()


# ── Retrieval result caching (via kb_context) ────────────────────────


class _FakeState:
    def __init__(self):
        self.recon_data = {}
        self.findings = []


class _FakeContext:
    def __init__(self):
        self.state = _FakeState()


class _FakeAgent:
    """Minimal agent surface required by build_kb_context."""

    def __init__(self):
        self.context = _FakeContext()
        self._kb_retriever = None
        self._kb_context_cache = {}


class TestContextCaching:
    def test_same_query_uses_cache(self, tmp_path, monkeypatch):
        monkeypatch.setattr(retriever_mod, "CHROMADB_AVAILABLE", False)
        from vulnclaw.agent import kb_context as kbc

        store = _seed_store(tmp_path)
        agent = _FakeAgent()
        agent._kb_retriever = KnowledgeRetriever(store=store)

        calls = {"n": 0}
        original = kbc._collect_kb_context

        def counting(*args, **kwargs):
            calls["n"] += 1
            return original(*args, **kwargs)

        monkeypatch.setattr(kbc, "_collect_kb_context", counting)

        # KB injection is gated by language (ticket #65); pin zh explicitly
        # so this test is deterministic regardless of the host's ambient
        # LANG/VULNCLAW_LANG env vars.
        previous_lang = current_lang()
        init_i18n(lang="zh")
        try:
            first = kbc.build_kb_context(agent, "test sqli on target")
            second = kbc.build_kb_context(agent, "test sqli on target")
        finally:
            init_i18n(lang=previous_lang)

        assert first == second
        assert calls["n"] == 1, "second identical query should hit the cache"

    def test_disabled_retriever_returns_empty_context(self, tmp_path, monkeypatch):
        monkeypatch.setattr(retriever_mod, "CHROMADB_AVAILABLE", False)
        from vulnclaw.agent import kb_context as kbc

        store = KnowledgeStore(store_dir=tmp_path)  # empty → disabled
        agent = _FakeAgent()
        agent._kb_retriever = KnowledgeRetriever(store=store)

        assert kbc.build_kb_context(agent, "anything") == ""


# ── Language gate (ticket #65) ────────────────────────────────────────


class TestKbContextLanguageGate:
    """English runs must never see the (predominantly Chinese) KB corpus.

    See the scoping-decision docstring in ``vulnclaw.agent.kb_context`` —
    the chosen approach is to gate injection by language rather than
    translate or maintain a dual corpus.
    """

    def test_en_gate_suppresses_kb_context(self, tmp_path, monkeypatch):
        monkeypatch.setattr(retriever_mod, "CHROMADB_AVAILABLE", False)
        from vulnclaw.agent import kb_context as kbc

        store = _seed_store(tmp_path)
        agent = _FakeAgent()
        agent._kb_retriever = KnowledgeRetriever(store=store)

        previous_lang = current_lang()
        init_i18n(lang="en")
        try:
            result = kbc.build_kb_context(agent, "sql injection waf bypass")
            assert result == ""
        finally:
            init_i18n(lang=previous_lang)

    def test_zh_keeps_full_kb_behavior(self, tmp_path, monkeypatch):
        monkeypatch.setattr(retriever_mod, "CHROMADB_AVAILABLE", False)
        from vulnclaw.agent import kb_context as kbc

        store = _seed_store(tmp_path)
        agent = _FakeAgent()
        agent._kb_retriever = KnowledgeRetriever(store=store)

        previous_lang = current_lang()
        init_i18n(lang="zh")
        try:
            result = kbc.build_kb_context(agent, "sql injection waf bypass")
            assert result != ""
            assert "SQL 注入绕过技巧" in result
        finally:
            init_i18n(lang=previous_lang)

    def test_assembled_system_prompt_has_no_chinese_kb_text_under_en(
        self, tmp_path, monkeypatch
    ):
        """End-to-end: build_dynamic_system_prompt must not leak Chinese KB
        text into an English-language assembled prompt."""
        monkeypatch.setattr(retriever_mod, "CHROMADB_AVAILABLE", False)
        from vulnclaw.agent import kb_context as kbc
        from vulnclaw.agent.system_prompt import build_dynamic_system_prompt

        store = _seed_store(tmp_path)
        agent = _FakeAgent()
        agent._kb_retriever = KnowledgeRetriever(store=store)

        previous_lang = current_lang()
        init_i18n(lang="en")
        try:
            kb_ctx = kbc.build_kb_context(agent, "sql injection waf bypass")
            prompt = build_dynamic_system_prompt(
                target=None,
                phase=None,
                skill_context=None,
                mcp_tools=[],
                enable_personnel_dim=True,
                auto_mode=False,
                user_input="sql injection waf bypass",
                kb_context=kb_ctx,
            )
            assert "SQL 注入绕过技巧" not in prompt
            assert "知识库参考" not in prompt
        finally:
            init_i18n(lang=previous_lang)

    def test_assembled_system_prompt_keeps_full_kb_under_zh(self, tmp_path, monkeypatch):
        monkeypatch.setattr(retriever_mod, "CHROMADB_AVAILABLE", False)
        from vulnclaw.agent import kb_context as kbc
        from vulnclaw.agent.system_prompt import build_dynamic_system_prompt

        store = _seed_store(tmp_path)
        agent = _FakeAgent()
        agent._kb_retriever = KnowledgeRetriever(store=store)

        previous_lang = current_lang()
        init_i18n(lang="zh")
        try:
            kb_ctx = kbc.build_kb_context(agent, "sql injection waf bypass")
            prompt = build_dynamic_system_prompt(
                target=None,
                phase=None,
                skill_context=None,
                mcp_tools=[],
                enable_personnel_dim=True,
                auto_mode=False,
                user_input="sql injection waf bypass",
                kb_context=kb_ctx,
            )
            assert "SQL 注入绕过技巧" in prompt
            assert "知识库参考" in prompt
        finally:
            init_i18n(lang=previous_lang)


# ── Full-corpus loading from store ───────────────────────────────────


class TestStoreIteration:
    def test_iter_all_entries_returns_all(self, tmp_path):
        store = _seed_store(tmp_path)
        entries = store.iter_all_entries()
        ids = {e["id"] for e in entries}
        assert {"sqli-bypass", "xss-bypass", "CVE-2026-0001"} <= ids
        assert all("_category" in e for e in entries)

    def test_iter_all_entries_empty_store(self, tmp_path):
        store = KnowledgeStore(store_dir=tmp_path)
        assert store.iter_all_entries() == []
