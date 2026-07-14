"""Tests for the optional embedding retriever and the backend factory.

The embedding backend needs heavy optional deps (sentence-transformers, chromadb)
and a local model; tests that require them ``skip`` cleanly when unavailable so
the suite still passes in a zero-heavy-dependency environment. The fallback,
interface, and factory tests always run.
"""

import inspect

import pytest

import src.embedding_retriever as er
from src.embedding_retriever import EmbeddingRetriever, build_retriever
from src.rag_retriever import RAGRetriever


def _make_embedding_retriever():
    """Build a real EmbeddingRetriever, or skip if deps/model are unavailable."""
    pytest.importorskip("chromadb")
    pytest.importorskip("sentence_transformers")
    try:
        return EmbeddingRetriever()
    except Exception as exc:  # model download blocked, etc.
        pytest.skip(f"embedding backend unavailable: {exc}")


# ---------------------------------------------------------------------------
# Interface parity (no heavy deps needed — importing the module is cheap)
# ---------------------------------------------------------------------------
def test_embedding_retriever_matches_tfidf_interface():
    assert issubclass(EmbeddingRetriever, RAGRetriever)
    assert inspect.signature(EmbeddingRetriever.__init__) == inspect.signature(RAGRetriever.__init__)
    assert inspect.signature(EmbeddingRetriever.retrieve) == inspect.signature(RAGRetriever.retrieve)


# ---------------------------------------------------------------------------
# (b) Fallback-to-TF-IDF triggers cleanly when the backend is unavailable
# ---------------------------------------------------------------------------
def test_factory_falls_back_to_tfidf_on_backend_failure(monkeypatch):
    monkeypatch.setattr(er.settings, "retriever_backend", "embedding")

    class _Boom:
        def __init__(self, *a, **k):
            raise RuntimeError("vector DB unavailable")

    monkeypatch.setattr(er, "EmbeddingRetriever", _Boom)

    retriever = build_retriever()
    # Exactly the TF-IDF retriever, and it actually works.
    assert type(retriever) is RAGRetriever
    assert isinstance(retriever.retrieve("password login form on the page"), list)


def test_factory_defaults_to_tfidf(monkeypatch):
    monkeypatch.setattr(er.settings, "retriever_backend", "tfidf")
    assert type(build_retriever()) is RAGRetriever


def test_factory_unknown_backend_uses_tfidf(monkeypatch):
    monkeypatch.setattr(er.settings, "retriever_backend", "bogus-backend")
    assert type(build_retriever()) is RAGRetriever


def test_factory_selects_embedding_when_available(monkeypatch):
    _make_embedding_retriever()  # skips if unavailable
    monkeypatch.setattr(er.settings, "retriever_backend", "embedding")
    retriever = build_retriever()
    assert isinstance(retriever, EmbeddingRetriever)


# ---------------------------------------------------------------------------
# (a) Index builds and returns relevant entries for a known query
# ---------------------------------------------------------------------------
def test_embedding_index_builds_and_returns_relevant_entries():
    retriever = _make_embedding_retriever()
    results = retriever.retrieve(
        "the web page shows a password login form asking for account credentials"
    )
    assert results, "embedding retriever returned no results for a clearly relevant query"
    # Results are RetrievedEvidence sorted by descending similarity.
    scores = [e.similarity_score for e in results]
    assert scores == sorted(scores, reverse=True)
    # At least one top result is topically relevant (login / password / phishing).
    haystack = " ".join(f"{e.category} {e.title}".lower() for e in results)
    assert any(term in haystack for term in ("login", "password", "credential", "phish"))


def test_embedding_cache_meta_written():
    _make_embedding_retriever()
    import hashlib
    import json

    from src.config import KNOWLEDGE_BASE_PATH, VECTOR_CACHE_DIR

    meta = json.loads((VECTOR_CACHE_DIR / "meta.json").read_text(encoding="utf-8"))
    assert meta["hash"] == hashlib.sha256(KNOWLEDGE_BASE_PATH.read_bytes()).hexdigest()
    assert meta["count"] > 0


# ---------------------------------------------------------------------------
# (c) Pipeline classification band is stable across backends
# ---------------------------------------------------------------------------
def test_classification_band_stable_across_backends():
    from src.pipeline import analyze_url

    embedding = _make_embedding_retriever()  # skips if unavailable
    tfidf = RAGRetriever()

    # Sample modes: offline (bundled HTML), no live crawl. Threat intel disabled
    # so the only thing varying between runs is the retriever backend.
    for mode in ("benign", "phishing", "prompt_injection"):
        a = analyze_url("https://demo.example.org/", mode, retriever=tfidf,
                        trusted_domains=[], enable_threat_intel=False)
        b = analyze_url("https://demo.example.org/", mode, retriever=embedding,
                        trusted_domains=[], enable_threat_intel=False)
        assert a.classification == b.classification, (
            f"backend changed the band for {mode}: tfidf={a.classification} "
            f"(score {a.risk_score}) vs embedding={b.classification} (score {b.risk_score})"
        )
