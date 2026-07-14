"""Lightweight local Retrieval-Augmented Generation (RAG) retriever.

Instead of a heavyweight vector database (FAISS/Chroma), this MVP uses a local
JSON knowledge base and scikit-learn's TF-IDF vectorizer with cosine
similarity. Given a query built from URL features, page text and evidence
messages, it returns the top-k most relevant knowledge snippets.

No external APIs are called.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from .config import KNOWLEDGE_BASE_PATH, settings
from .schemas import RetrievedEvidence


def entry_to_evidence(entry: dict, index: int, score: float) -> RetrievedEvidence:
    """Build a ``RetrievedEvidence`` from a knowledge-base entry and a score.

    Shared by the TF-IDF and embedding retrievers so both produce identical
    ``RetrievedEvidence`` objects (only the ``similarity_score`` scale differs).
    """
    return RetrievedEvidence(
        id=str(entry.get("id", index)),
        title=entry.get("title", ""),
        category=entry.get("category", ""),
        source_type=entry.get("source_type", ""),
        trust_level=entry.get("trust_level", ""),
        content=entry.get("content", ""),
        indicators=entry.get("indicators", []) or [],
        recommended_action=entry.get("recommended_action", ""),
        similarity_score=round(float(score), 4),
    )


class RAGRetriever:
    """TF-IDF based retriever over a local JSON knowledge base."""

    def __init__(self, knowledge_base_path: Optional[Path] = None) -> None:
        self.knowledge_base_path = Path(knowledge_base_path or KNOWLEDGE_BASE_PATH)
        self.entries: List[dict] = []
        self._vectorizer: Optional[TfidfVectorizer] = None
        self._matrix = None
        self._load()
        self._build_index()

    # ------------------------------------------------------------------
    # Index construction
    # ------------------------------------------------------------------
    def _load(self) -> None:
        """Load knowledge-base entries from JSON (empty list on failure)."""
        try:
            raw = self.knowledge_base_path.read_text(encoding="utf-8")
            data = json.loads(raw)
            self.entries = data.get("entries", data) if isinstance(data, dict) else data
        except (OSError, json.JSONDecodeError):
            self.entries = []

    def _corpus_text(self, entry: dict) -> str:
        """Build the searchable text for an entry (title + content + indicators)."""
        indicators = " ".join(entry.get("indicators", []) or [])
        return " ".join(
            [
                entry.get("title", ""),
                entry.get("category", ""),
                entry.get("content", ""),
                indicators,
            ]
        ).strip()

    def _build_index(self) -> None:
        """Fit the TF-IDF vectorizer over the corpus."""
        if not self.entries:
            return
        corpus = [self._corpus_text(e) for e in self.entries]
        self._vectorizer = TfidfVectorizer(stop_words="english", ngram_range=(1, 2))
        self._matrix = self._vectorizer.fit_transform(corpus)

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------
    def retrieve(self, query: str, top_k: Optional[int] = None) -> List[RetrievedEvidence]:
        """Return the top-k knowledge entries most relevant to ``query``.

        Args:
            query: Free-text query (URL features + page text + evidence).
            top_k: Number of entries to return (defaults to settings.rag_top_k).

        Returns:
            A list of ``RetrievedEvidence`` sorted by descending similarity.
            Entries with zero similarity are skipped.
        """
        top_k = top_k or settings.rag_top_k
        if not self.entries or self._vectorizer is None or not query.strip():
            return []

        query_vec = self._vectorizer.transform([query])
        scores = cosine_similarity(query_vec, self._matrix)[0]

        # Rank indices by descending similarity.
        ranked = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)

        results: List[RetrievedEvidence] = []
        for idx in ranked[:top_k]:
            score = float(scores[idx])
            if score <= 0.0:
                continue
            results.append(entry_to_evidence(self.entries[idx], idx, score))
        return results


def build_query(
    url_evidence: List[str],
    page_evidence: List[str],
    injection_evidence: List[str],
    extra_terms: Optional[List[str]] = None,
) -> str:
    """Combine evidence messages and key terms into a single retrieval query."""
    parts: List[str] = []
    parts.extend(url_evidence or [])
    parts.extend(page_evidence or [])
    parts.extend(injection_evidence or [])
    if extra_terms:
        parts.extend(extra_terms)
    return " ".join(parts)
