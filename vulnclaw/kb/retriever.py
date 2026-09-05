"""VulnClaw Knowledge Retriever — retrieve relevant knowledge for the agent.

Retrieval degrades gracefully across three backends:

- ``chromadb_active``   : semantic vector search (requires the optional
                          ``chromadb`` dependency, installed via
                          ``pip install vulnclaw[kb]``).
- ``keyword_fallback``  : pure-Python Chinese-aware BM25 scoring over the KB
                          JSON corpus, optionally reranked by a cross-encoder.
                          No external dependency required.
- ``disabled``          : no KB data is available at all.

The public method surface (``get_cve``, ``search_by_service``,
``search_technique`` ...) is identical regardless of which backend is
active, so callers never need to branch on the backend.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any, Optional

from vulnclaw.kb.ranking import BM25, CrossEncoderReranker
from vulnclaw.kb.store import KnowledgeStore

logger = logging.getLogger(__name__)


# ── ChromaDB availability probe ─────────────────────────────────────

CHROMADB_AVAILABLE = False
CHROMADB_IMPORT_ERROR = ""
try:  # pragma: no cover - depends on optional dependency being installed
    import chromadb  # noqa: F401

    CHROMADB_AVAILABLE = True
except Exception as exc:  # pragma: no cover - exercised when chromadb missing
    CHROMADB_IMPORT_ERROR = str(exc) or exc.__class__.__name__


class RetrieverStatus(str, Enum):
    """Operational status of the knowledge retriever."""

    CHROMADB_ACTIVE = "chromadb_active"
    KEYWORD_FALLBACK = "keyword_fallback"
    DISABLED = "disabled"


def _entry_text(entry: dict[str, Any]) -> str:
    """Flatten the searchable text of a KB entry into a single string."""
    parts: list[str] = []
    for key in ("id", "title", "description", "severity", "affected", "remediation"):
        val = entry.get(key)
        if isinstance(val, str):
            parts.append(val)
    for key in ("tags",):
        val = entry.get(key)
        if isinstance(val, list):
            parts.extend(str(v) for v in val)
    # List-of-steps style fields contribute to the document text.
    for key in ("exploitation_steps", "bypass_methods", "commands", "workflow"):
        val = entry.get(key)
        if isinstance(val, list):
            parts.extend(str(v) for v in val)
    return " ".join(parts)


class KeywordRetriever:
    """Pure-Python keyword retriever used when ChromaDB is unavailable.

    Loads every KB entry into memory once and ranks documents against a query
    with Okapi BM25 over Chinese-aware character-bigram tokens, so the
    predominantly-Chinese KB corpus is searchable without a segmentation
    dictionary or any external dependency.
    """

    def __init__(self, store: KnowledgeStore) -> None:
        self.store = store
        self._docs: list[dict[str, Any]] = self.store.iter_all_entries()
        self._bm25: BM25 = BM25([_entry_text(entry) for entry in self._docs])

    def has_data(self) -> bool:
        """Return True when at least one document is indexed."""
        return bool(self._docs)

    def retrieve(self, query: str, top_k: int = 5) -> list[dict[str, Any]]:
        """Return the top-k entries most relevant to the query."""
        return [self._docs[index] for index, _score in self._bm25.search(query, top_k)]


class RerankedRetriever:
    """Two-stage retriever: broad recall, then precise cross-encoder reranking.

    Wraps a base retriever (e.g. :class:`KeywordRetriever`) that recalls more
    candidates than needed, then reorders the top candidates with a
    cross-encoder for finer ranking. When the reranker is unavailable or there
    are too few candidates to reorder, the base ranking is returned unchanged.
    """

    def __init__(self, base: Any, reranker: CrossEncoderReranker, *, recall_k: int = 20) -> None:
        self._base = base
        self._reranker = reranker
        self._recall_k = recall_k

    def has_data(self) -> bool:
        return self._base.has_data()

    def retrieve(self, query: str, top_k: int = 5) -> list[dict[str, Any]]:
        """Recall broadly, rerank, and return the top-k entries."""
        candidates = self._base.retrieve(query, top_k=max(self._recall_k, top_k))
        if len(candidates) <= top_k or not self._reranker.available:
            return candidates[:top_k]
        texts = [_entry_text(entry) for entry in candidates]
        order = self._reranker.rerank(query, texts, top_k)
        return [candidates[index] for index in order]


class _ChromaRetriever:
    """Thin semantic-search wrapper over a ChromaDB collection.

    Built lazily from the KB corpus. If anything goes wrong during setup the
    caller is expected to fall back to :class:`KeywordRetriever`.
    """

    def __init__(self, store: KnowledgeStore) -> None:
        self.store = store
        self._collection = None
        self._docs_by_id: dict[str, dict[str, Any]] = {}
        self._build()

    def _build(self) -> None:  # pragma: no cover - requires chromadb installed
        import chromadb

        client = chromadb.EphemeralClient()
        self._collection = client.get_or_create_collection("vulnclaw_kb")

        ids: list[str] = []
        documents: list[str] = []
        for entry in self.store.iter_all_entries():
            eid = str(entry.get("id") or entry.get("title") or "")
            if not eid or eid in self._docs_by_id:
                continue
            self._docs_by_id[eid] = entry
            ids.append(eid)
            documents.append(_entry_text(entry))

        if ids:
            self._collection.add(ids=ids, documents=documents)

    def has_data(self) -> bool:
        return bool(self._docs_by_id)

    def retrieve(self, query: str, top_k: int = 5) -> list[dict[str, Any]]:  # pragma: no cover
        if not self._collection or not self._docs_by_id or not query.strip():
            return []
        result = self._collection.query(query_texts=[query], n_results=top_k)
        ids = (result.get("ids") or [[]])[0]
        return [self._docs_by_id[i] for i in ids if i in self._docs_by_id]


class KnowledgeRetriever:
    """Retrieves relevant knowledge from the KB for the agent.

    Supports:
    - CVE-based retrieval
    - Service version-based CVE matching
    - Vulnerability type-based retrieval
    - WAF bypass technique retrieval
    - Generic semantic/keyword retrieval (``retrieve``)

    The retriever transparently selects the best available backend
    (ChromaDB semantic search, keyword fallback, or disabled) and reports
    its choice via :meth:`get_status`.
    """

    def __init__(self, store: Optional[KnowledgeStore] = None, *, rerank: bool = False) -> None:
        self.store = store or KnowledgeStore()
        self._rerank_enabled = rerank
        self._status: RetrieverStatus = RetrieverStatus.DISABLED
        self._status_detail: str = ""
        self._backend: Any = None
        self._init_backend()

    def _init_backend(self) -> None:
        """Pick the retrieval backend and record the resulting status."""
        from vulnclaw.i18n import _

        if CHROMADB_AVAILABLE:
            try:
                backend = _ChromaRetriever(self.store)
                if backend.has_data():
                    self._backend = backend
                    self._status = RetrieverStatus.CHROMADB_ACTIVE
                    self._status_detail = _("kb.status.chroma_enabled")
                    return
                # ChromaDB present but no data → nothing to disable yet,
                # keep probing the keyword backend below.
                logger.info("ChromaDB available but KB corpus is empty")
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("ChromaDB backend init failed, falling back: %s", exc)
                self._status_detail = _("kb.status.chroma_init_failed", exc=exc)

        try:
            keyword = KeywordRetriever(self.store)
        except Exception as exc:
            logger.warning("Keyword retriever init failed: %s", exc)
            self._backend = None
            self._status = RetrieverStatus.DISABLED
            self._status_detail = _("kb.status.keyword_init_failed", exc=exc)
            return

        self._backend = keyword
        if self._rerank_enabled:
            self._backend = self._wrap_reranker(keyword)
        if keyword.has_data():
            self._status = RetrieverStatus.KEYWORD_FALLBACK
            if not CHROMADB_AVAILABLE:
                self._status_detail = _(
                    "kb.status.chroma_missing",
                    reason=CHROMADB_IMPORT_ERROR or "not installed",
                )
            elif not self._status_detail:
                self._status_detail = _("kb.status.keyword_fallback")
        else:
            self._status = RetrieverStatus.DISABLED
            self._status_detail = _("kb.status.empty")

    def _wrap_reranker(self, base: Any) -> Any:
        """Wrap ``base`` with a cross-encoder reranking stage when possible.

        The cross-encoder is loaded lazily and only when reranking was
        explicitly enabled; if the dependency or model is missing, ``base`` is
        returned unchanged so the retriever degrades to base ranking instead of
        failing.
        """
        reranker = CrossEncoderReranker()
        if not reranker.available:
            logger.info("Cross-encoder reranker unavailable; keeping base ranking")
            return base
        return RerankedRetriever(base, reranker)

    # ── Status reporting ─────────────────────────────────────────────

    def get_status(self) -> RetrieverStatus:
        """Return the current retriever backend status."""
        return self._status

    def get_status_detail(self) -> str:
        """Return a human-readable explanation of the current status."""
        return self._status_detail

    # ── Generic retrieval ────────────────────────────────────────────

    def retrieve(self, query: str, top_k: int = 5) -> list[dict[str, Any]]:
        """Generic relevance retrieval across the whole KB.

        Works regardless of backend. Returns an empty list when disabled or
        when retrieval fails (degrades silently).
        """
        if self._backend is None or self._status is RetrieverStatus.DISABLED:
            return []
        try:
            return self._backend.retrieve(query, top_k=top_k)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("KB retrieve failed for query %r: %s", query, exc)
            return []

    def get_cve(self, cve_id: str) -> Optional[dict[str, Any]]:
        """Get a specific CVE entry."""
        # Normalize CVE ID
        cve_id = cve_id.upper()
        if not cve_id.startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"

        return self.store.get_entry("cve", cve_id)

    def search_by_service(self, service: str, version: str = "") -> list[dict[str, Any]]:
        """Search CVEs by service name and version.

        Args:
            service: Service name, e.g. "nginx", "apache", "tomcat"
            version: Version string, e.g. "1.24.0"

        Returns:
            List of matching CVE entries.
        """
        query = service.lower()
        if version:
            query += f" {version}"

        return self.store.search(query, category="cve", tags=[service.lower()])

    def search_technique(self, vuln_type: str) -> list[dict[str, Any]]:
        """Search exploitation techniques by vulnerability type.

        Args:
            vuln_type: Vulnerability type, e.g. "sqli", "xss", "rce"

        Returns:
            List of matching technique entries.
        """
        return self.store.search(vuln_type.lower(), category="techniques")

    def get_waf_bypass(self, waf_name: str = "") -> list[dict[str, Any]]:
        """Get WAF bypass techniques.

        Args:
            waf_name: Specific WAF name, e.g. "safeline", "cloudflare"

        Returns:
            List of bypass technique entries.
        """
        if waf_name:
            return self.store.search(waf_name.lower(), category="techniques", tags=["waf-bypass"])
        return self.store.search("waf", category="techniques", tags=["waf-bypass"])

    def get_tool_guide(self, tool_name: str) -> Optional[dict[str, Any]]:
        """Get a tool usage guide."""
        return self.store.get_entry("tools", tool_name.lower())

    def get_payload(self, payload_type: str) -> list[dict[str, Any]]:
        """Get payloads by type.

        Args:
            payload_type: Type, e.g. "webshell", "reverse-shell", "encoding"

        Returns:
            List of payload entries.
        """
        return self.store.search(payload_type.lower(), category="payloads")

    def format_for_prompt(self, entries: list[dict[str, Any]], max_entries: int = 5) -> str:
        """Format knowledge entries for injection into LLM prompt.

        Args:
            entries: Knowledge entries to format.
            max_entries: Maximum number of entries to include.

        Returns:
            Formatted string for prompt injection.
        """
        if not entries:
            return ""

        lines = []
        for entry in entries[:max_entries]:
            title = entry.get("title", entry.get("id", "Unknown"))
            lines.append(f"- **{title}**")

            # Add description if available
            desc = entry.get("description", "")
            if desc:
                lines.append(f"  {desc[:200]}")

            # Add exploitation steps if available
            steps = entry.get("exploitation_steps", [])
            if steps:
                for i, step in enumerate(steps[:5], 1):
                    lines.append(f"  {i}. {step}")

        return "\n".join(lines)
