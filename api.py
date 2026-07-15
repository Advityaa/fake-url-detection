from typing import Dict, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
from fastapi.middleware.cors import CORSMiddleware

from src.capabilities import capabilities
from src.config import load_trusted_domains, settings
from src.embedding_retriever import build_retriever
from src.pipeline import analyze_url
from src.rag_retriever import RAGRetriever

app = FastAPI(title="Fake URL Detection API")

# Allow React app to communicate with FastAPI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_retriever_cache: Dict[str, RAGRetriever] = {}
_trusted_domains_instance = None


def get_retriever(backend: Optional[str] = None) -> RAGRetriever:
    """Return a cached retriever for ``backend`` (or the configured default).

    Cached per backend so a reviewer can switch TF-IDF <-> embedding at analysis
    time without rebuilding an already-built index. ``build_retriever`` itself
    falls back to TF-IDF if the embedding deps are missing, so this never crashes.
    """
    key = (backend or settings.retriever_backend or "tfidf").lower()
    if key not in _retriever_cache:
        _retriever_cache[key] = build_retriever(backend=key)
    return _retriever_cache[key]


def get_trusted_domains() -> set[str]:
    global _trusted_domains_instance
    if _trusted_domains_instance is None:
        _trusted_domains_instance = set(load_trusted_domains())
    return _trusted_domains_instance


class AnalyzeRequest(BaseModel):
    url: str
    mode: str = "live"
    # Optional per-request stage toggles (interactive ablation). Omitted / null
    # means "use the configured default" — these map 1:1 to analyze_url overrides.
    enable_threat_intel: Optional[bool] = None
    enable_domain_intel: Optional[bool] = None
    enable_multimodal: Optional[bool] = None
    enable_dynamic: Optional[bool] = None
    enable_llm: Optional[bool] = None
    render_backend: Optional[str] = None  # "requests" | "playwright"
    retriever_backend: Optional[str] = None  # "tfidf" | "embedding"


@app.get("/api/capabilities")
def capabilities_endpoint():
    """Which optional stages can be toggled (deps present) + their defaults."""
    return capabilities()


@app.post("/api/analyze")
def analyze_endpoint(req: AnalyzeRequest):
    result = analyze_url(
        req.url,
        req.mode,
        retriever=get_retriever(req.retriever_backend),
        trusted_domains=get_trusted_domains(),
        enable_threat_intel=True if req.enable_threat_intel is None else req.enable_threat_intel,
        enable_domain_intel=req.enable_domain_intel,
        enable_multimodal=req.enable_multimodal,
        enable_dynamic=req.enable_dynamic,
        enable_llm=req.enable_llm,
        render_backend=req.render_backend,
    )
    if result is None:
        raise HTTPException(status_code=400, detail="Invalid URL")
    return result.to_dict()


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
