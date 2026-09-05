"""Tests for the Chinese-aware KB ranking primitives (ranking.py + glue)."""


# ── bigram_tokenize ──────────────────────────────────────────────────


class TestBigramTokenize:
    def test_chinese_produces_bigrams(self):
        from vulnclaw.kb.ranking import bigram_tokenize

        # The old [a-z0-9]+ tokenizer returned only ["sql"], dropping all CJK.
        assert bigram_tokenize("SQL 注入绕过") == ["sql", "注入", "入绕", "绕过"]

    def test_latin_runs_stay_whole(self):
        from vulnclaw.kb.ranking import bigram_tokenize

        assert bigram_tokenize("sql injection waf bypass") == [
            "sql",
            "injection",
            "waf",
            "bypass",
        ]

    def test_cjk_run_overlaps(self):
        from vulnclaw.kb.ranking import bigram_tokenize

        assert bigram_tokenize("注入绕过") == ["注入", "入绕", "绕过"]

    def test_single_cjk_char_emitted_alone(self):
        from vulnclaw.kb.ranking import bigram_tokenize

        assert bigram_tokenize("中") == ["中"]

    def test_empty_string(self):
        from vulnclaw.kb.ranking import bigram_tokenize

        assert bigram_tokenize("") == []

    def test_punctuation_acts_as_separator(self):
        from vulnclaw.kb.ranking import bigram_tokenize

        assert bigram_tokenize("WAF;注入,绕过") == ["waf", "注入", "绕过"]


# ── BM25 ─────────────────────────────────────────────────────────────


class TestBM25:
    DOCS = [
        "SQL 注入绕过 WAF 技巧",
        "PHP 命令执行绕过技巧",
        "Nmap 端口扫描速查",
    ]

    def test_chinese_query_ranks_relevant_first(self):
        from vulnclaw.kb.ranking import BM25

        ranked = BM25(self.DOCS).search("注入绕过", top_k=3)
        assert ranked and ranked[0][0] == 0  # "SQL 注入绕过 WAF 技巧"

    def test_english_query_matches_latin_tokens(self):
        from vulnclaw.kb.ranking import BM25

        ranked = BM25(self.DOCS).search("nmap port scan", top_k=3)
        assert ranked and ranked[0][0] == 2  # "Nmap 端口扫描速查"

    def test_empty_query_returns_empty(self):
        from vulnclaw.kb.ranking import BM25

        assert BM25(self.DOCS).search("", top_k=3) == []

    def test_no_match_returns_empty(self):
        from vulnclaw.kb.ranking import BM25

        assert BM25(self.DOCS).search("zzzzz_nonexistent", top_k=3) == []

    def test_top_k_truncation(self):
        from vulnclaw.kb.ranking import BM25

        ranked = BM25(self.DOCS).search("绕过", top_k=1)
        assert len(ranked) == 1


# ── RerankedRetriever (two-stage glue) ───────────────────────────────


class _FakeBase:
    def __init__(self, entries):
        self._entries = entries

    def has_data(self):
        return bool(self._entries)

    def retrieve(self, query, top_k=5):
        return self._entries[:top_k]


class _FakeReranker:
    def __init__(self, available=True, order=None):
        self.available = available
        self._order = order or []

    def rerank(self, query, texts, top_k):
        return self._order[:top_k]


class TestRerankedRetriever:
    def test_unavailable_reranker_returns_base_ranking(self):
        from vulnclaw.kb.retriever import RerankedRetriever

        entries = [{"id": "a"}, {"id": "b"}, {"id": "c"}]
        rr = RerankedRetriever(_FakeBase(entries), _FakeReranker(available=False))
        assert [e["id"] for e in rr.retrieve("query", top_k=2)] == ["a", "b"]

    def test_available_reranker_reorders(self):
        from vulnclaw.kb.retriever import RerankedRetriever

        entries = [{"id": "a"}, {"id": "b"}, {"id": "c"}]
        rr = RerankedRetriever(_FakeBase(entries), _FakeReranker(available=True, order=[2, 0, 1]))
        assert [e["id"] for e in rr.retrieve("query", top_k=2)] == ["c", "a"]

    def test_has_data_delegates(self):
        from vulnclaw.kb.retriever import RerankedRetriever

        assert RerankedRetriever(_FakeBase([]), _FakeReranker()).has_data() is False
        assert RerankedRetriever(_FakeBase([{"id": "a"}]), _FakeReranker()).has_data() is True


# ── KnowledgeRetriever rerank opt-in ─────────────────────────────────


class _UnavailableRerankerClass:
    def __init__(self, *args, **kwargs):
        self.available = False


class TestKnowledgeRetrieverRerank:
    def test_rerank_opt_in_degrades_when_unavailable(self, tmp_path, monkeypatch):
        import vulnclaw.kb.retriever as retriever_mod
        from vulnclaw.kb.retriever import KeywordRetriever, KnowledgeRetriever
        from vulnclaw.kb.store import KnowledgeStore

        monkeypatch.setattr(retriever_mod, "CHROMADB_AVAILABLE", False)
        monkeypatch.setattr(retriever_mod, "CrossEncoderReranker", _UnavailableRerankerClass)

        store = KnowledgeStore(store_dir=tmp_path)
        store.add_entry(
            "techniques",
            "sqli-bypass",
            {"title": "SQL 注入绕过技巧", "tags": ["sqli"]},
        )

        retriever = KnowledgeRetriever(store=store, rerank=True)
        # Reranking was requested but is unavailable, so the backend degrades
        # to the plain keyword retriever rather than a wrapped retriever.
        assert isinstance(retriever._backend, KeywordRetriever)
