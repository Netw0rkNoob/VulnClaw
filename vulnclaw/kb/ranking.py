"""Chinese-aware sparse ranking + optional cross-encoder reranking for the KB.

This module holds the retrieval primitives used by ``KeywordRetriever``:

- :func:`bigram_tokenize` — a tokenizer that keeps Latin alphanumeric runs as
  whole tokens while splitting CJK into overlapping character bigrams, so the
  predominantly-Chinese KB corpus is searchable without a segmentation
  dictionary or any new required dependency.
- :class:`BM25` — a small dependency-free Okapi BM25 scorer replacing the weak
  TF-IDF overlap that previously failed to rank Chinese entries.
- :class:`CrossEncoderReranker` — an optional cross-encoder precision stage,
  imported lazily so the core path stays free of heavy dependencies.

The public surface is deliberately minimal and independent of the KB store, so
it can later be reused by the cold-memory and evidence search paths.
"""

from __future__ import annotations

import math
import re
from collections import Counter

# A maximal run of either Latin letters/digits or CJK Unified Ideographs.
# Latin runs are kept whole; CJK runs are split into overlapping bigrams.
_RUN_RE = re.compile(r"[a-z0-9]+|[一-鿿]+")


def bigram_tokenize(text: str) -> list[str]:
    """Split ``text`` into Latin word tokens and CJK character bigrams.

    Latin alphanumeric runs are lowercased and emitted as single tokens
    (e.g. ``"SQL"`` -> ``"sql"``). CJK runs are emitted as overlapping
    character bigrams (e.g. ``"注入绕过"`` -> ``"注入"``, ``"入绕"``, ``"绕过"``),
    and a single isolated CJK character is emitted on its own. All other
    characters act as token separators.

    This keeps existing English-keyword behavior intact while making Chinese
    content retrievable.
    """
    tokens: list[str] = []
    for match in _RUN_RE.finditer(text.lower()):
        run = match.group()
        if run.isascii() or len(run) == 1:
            tokens.append(run)
        else:
            tokens.extend(run[i : i + 2] for i in range(len(run) - 1))
    return tokens


class BM25:
    """Dependency-free Okapi BM25 over a small in-memory document set.

    Parameters ``k1`` and ``b`` control term-frequency saturation and
    document-length normalization respectively. Documents are tokenized with
    :func:`bigram_tokenize`, so both Latin and CJK content are scored.
    """

    def __init__(self, docs: list[str], *, k1: float = 1.5, b: float = 0.75) -> None:
        self.k1 = float(k1)
        self.b = float(b)
        tokenized = [bigram_tokenize(doc) for doc in docs]
        self._doc_counts = [Counter(tokens) for tokens in tokenized]
        self._doc_len = [len(tokens) for tokens in tokenized]
        count = len(tokenized)
        self._avg_len = (sum(self._doc_len) / count) if count else 0.0

        document_frequency: Counter[str] = Counter()
        for doc_counts in self._doc_counts:
            document_frequency.update(doc_counts.keys())
        self._idf: dict[str, float] = {
            token: math.log((count - freq + 0.5) / (freq + 0.5) + 1.0)
            for token, freq in document_frequency.items()
        }
        self._norm = [
            (1.0 - self.b + self.b * (length / self._avg_len)) if self._avg_len > 0 else 1.0
            for length in self._doc_len
        ]

    def search(self, query: str, top_k: int) -> list[tuple[int, float]]:
        """Return ``(doc_index, score)`` pairs ranked descending by BM25.

        Only documents with a positive score are returned, at most ``top_k``
        items. An empty query yields an empty list.
        """
        if not query or not self._doc_counts:
            return []
        query_counts = Counter(bigram_tokenize(query))
        if not query_counts:
            return []

        scored: list[tuple[int, float]] = []
        for index, doc_counts in enumerate(self._doc_counts):
            score = 0.0
            norm = self._norm[index]
            for token, query_tf in query_counts.items():
                doc_tf = doc_counts.get(token, 0)
                if doc_tf <= 0:
                    continue
                idf = self._idf.get(token, 0.0)
                if idf <= 0.0:
                    continue
                tf = doc_tf * (self.k1 + 1.0) / (doc_tf + self.k1 * norm)
                score += idf * tf * float(query_tf)
            if score > 0.0:
                scored.append((index, score))

        scored.sort(key=lambda pair: pair[1], reverse=True)
        return scored[: max(0, int(top_k))]


class CrossEncoderReranker:
    """Optional cross-encoder precision stage over candidate documents.

    A bi-encoder/BM25 pass recalls a broad candidate set; this reranks it with
    a cross-encoder for finer ordering. The model is imported and loaded lazily
    so importing this module never pulls in ``sentence-transformers`` unless a
    reranker is actually constructed. When the dependency or model is missing,
    :attr:`available` is ``False`` and callers should fall back to the base
    retriever unchanged.
    """

    def __init__(self, model_name: str = "BAAI/bge-reranker-base") -> None:
        self.model_name = model_name
        self._model = None
        try:
            from sentence_transformers import CrossEncoder

            self._model = CrossEncoder(model_name)
        except Exception:
            # Missing dependency or model download/load failure: leave the
            # reranker unavailable so the caller degrades to the base retriever.
            self._model = None

    @property
    def available(self) -> bool:
        """Whether a usable cross-encoder was loaded successfully."""
        return self._model is not None

    def rerank(self, query: str, texts: list[str], top_k: int) -> list[int]:
        """Return the indices of ``texts`` ordered by relevance to ``query``.

        Returns at most ``top_k`` indices. ``texts`` must be non-empty.
        """
        if not self._model or not texts:
            return []
        pairs = [(query, text) for text in texts]
        raw_scores = self._model.predict(pairs)
        if isinstance(raw_scores, (int, float)):
            scores = [float(raw_scores)]
        else:
            scores = [float(score) for score in raw_scores]
        order = sorted(range(len(texts)), key=lambda index: scores[index], reverse=True)
        return order[: max(0, int(top_k))]
