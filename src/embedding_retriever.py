"""Optional embedding-based RAG retriever (local sentence-transformer + Chroma).

This is a drop-in alternative to the TF-IDF :class:`RAGRetriever`. It subclasses
it so the public interface is guaranteed identical — same ``__init__`` signature,
same ``retrieve(query, top_k=None) -> List[RetrievedEvidence]`` — and callers do
not change. Only the index build and the retrieval math differ.

Design notes:
  * **Heavy deps are lazy.** ``sentence-transformers`` and ``chromadb`` are
    imported inside ``_build_index`` so merely importing this module is cheap and
    never fails. If either is missing (or the model can't load), ``_build_index``
    raises and :func:`build_retriever` transparently falls back to TF-IDF.
  * **Offline at query time.** The model is loaded once at construction; the
    Chroma client runs with telemetry disabled. No network call happens during
    ``retrieve``. (The very first build may download the model to the HF cache;
    after that everything is local.)
  * **Incremental cache.** The Chroma index is persisted under
    ``data/vector_cache/`` and is only re-embedded when ``knowledge_base.json``
    changes (checked via a SHA-256 hash recorded in a sidecar ``meta.json``).
  * The retriever change does NOT touch the risk engine's evidence-conditioned
    scoring — it still returns the same ``RetrievedEvidence`` objects (with
    ``category`` etc.), so conditioning behaves identically.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import List, Optional

from .config import VECTOR_CACHE_DIR, settings
from .rag_retriever import RAGRetriever, entry_to_evidence
from .schemas import RetrievedEvidence

logger = logging.getLogger(__name__)

_COLLECTION_NAME = "knowledge_base"
# Cosine-similarity floor below which an embedding match is treated as noise and
# skipped (mirrors the TF-IDF path skipping zero-similarity entries).
_SIMILARITY_FLOOR = 0.15


class EmbeddingRetriever(RAGRetriever):
    """Embedding retriever over the local knowledge base, backed by Chroma.

    Raises on construction if the embedding model or vector DB is unavailable, so
    :func:`build_retriever` can catch it and fall back to TF-IDF.
    """

    def __init__(self, knowledge_base_path: Optional[Path] = None) -> None:
        self._model = None
        self._collection = None
        self._model_name = settings.embedding_model_name
        # RAGRetriever.__init__ runs _load() then _build_index() (overridden below).
        super().__init__(knowledge_base_path)

    # ------------------------------------------------------------------
    def _file_hash(self) -> str:
        try:
            return hashlib.sha256(self.knowledge_base_path.read_bytes()).hexdigest()
        except OSError:
            return ""

    def _build_index(self) -> None:
        """Build or load the persistent embedding index. Raises on missing deps."""
        if not self.entries:
            self._collection = None
            return

        # Lazy heavy imports — a missing dependency raises here and the factory
        # falls back to TF-IDF.
        import chromadb
        from sentence_transformers import SentenceTransformer

        self._model = SentenceTransformer(self._model_name)

        cache_dir = VECTOR_CACHE_DIR / "chroma"
        cache_dir.mkdir(parents=True, exist_ok=True)
        client = chromadb.PersistentClient(
            path=str(cache_dir),
            settings=chromadb.Settings(anonymized_telemetry=False),  # no network
        )
        collection = client.get_or_create_collection(
            name=_COLLECTION_NAME, metadata={"hnsw:space": "cosine"}
        )

        current_hash = self._file_hash()
        meta_path = VECTOR_CACHE_DIR / "meta.json"
        meta = {}
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            meta = {}

        fresh = (
            meta.get("hash") == current_hash
            and meta.get("model") == self._model_name
            and collection.count() == len(self.entries)
        )

        if not fresh:
            # Re-embed from scratch — the KB (or model) changed.
            if collection.count() > 0:
                client.delete_collection(_COLLECTION_NAME)
                collection = client.get_or_create_collection(
                    name=_COLLECTION_NAME, metadata={"hnsw:space": "cosine"}
                )
            corpus = [self._corpus_text(e) for e in self.entries]
            embeddings = self._model.encode(
                corpus, normalize_embeddings=True, show_progress_bar=False
            )
            collection.add(
                ids=[str(i) for i in range(len(self.entries))],
                embeddings=[e.tolist() for e in embeddings],
                documents=corpus,
            )
            meta_path.parent.mkdir(parents=True, exist_ok=True)
            meta_path.write_text(
                json.dumps(
                    {"hash": current_hash, "model": self._model_name, "count": len(self.entries)}
                ),
                encoding="utf-8",
            )
            logger.info("Built embedding index (%d entries, model=%s).", len(self.entries), self._model_name)
        else:
            logger.info("Loaded cached embedding index (%d entries).", collection.count())

        self._collection = collection

    # ------------------------------------------------------------------
    def retrieve(self, query: str, top_k: Optional[int] = None) -> List[RetrievedEvidence]:
        """Return the top-k knowledge entries most similar to ``query`` (cosine).

        Same contract as ``RAGRetriever.retrieve``: descending similarity, weak
        matches skipped, results are ``RetrievedEvidence``.
        """
        top_k = top_k or settings.rag_top_k
        if not self.entries or self._collection is None or self._model is None or not query.strip():
            return []

        query_embedding = self._model.encode(
            [query], normalize_embeddings=True, show_progress_bar=False
        )[0].tolist()
        n = min(top_k, self._collection.count())
        if n <= 0:
            return []
        result = self._collection.query(query_embeddings=[query_embedding], n_results=n)

        ids = result.get("ids", [[]])[0]
        distances = result.get("distances", [[]])[0]

        evidence: List[RetrievedEvidence] = []
        for entry_id, distance in zip(ids, distances):
            similarity = 1.0 - float(distance)  # chroma cosine distance -> similarity
            if similarity < _SIMILARITY_FLOOR:
                continue
            idx = int(entry_id)
            if 0 <= idx < len(self.entries):
                evidence.append(entry_to_evidence(self.entries[idx], idx, similarity))
        return evidence


def build_retriever(knowledge_base_path: Optional[Path] = None) -> RAGRetriever:
    """Return the configured retriever, falling back to TF-IDF on any problem.

    Selected by ``settings.retriever_backend`` ("tfidf" | "embedding"). The
    embedding backend is attempted only when explicitly requested; if its heavy
    dependencies or model are unavailable, a clear warning is logged and the
    proven TF-IDF retriever is returned instead. The demo never hard-crashes.
    """
    backend = (settings.retriever_backend or "tfidf").lower()
    if backend == "embedding":
        try:
            retriever = EmbeddingRetriever(knowledge_base_path)
            logger.info("Using embedding retriever backend.")
            return retriever
        except Exception as exc:  # noqa: BLE001 - any failure -> safe fallback
            logger.warning(
                "Embedding retriever unavailable (%s); falling back to the TF-IDF retriever.",
                exc,
            )
    elif backend != "tfidf":
        logger.warning("Unknown RETRIEVER_BACKEND %r; using TF-IDF.", backend)

    return RAGRetriever(knowledge_base_path)
