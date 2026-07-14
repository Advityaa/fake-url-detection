from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
from fastapi.middleware.cors import CORSMiddleware

from src.config import load_trusted_domains
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

_retriever_instance = None
_trusted_domains_instance = None


def get_retriever() -> RAGRetriever:
    global _retriever_instance
    if _retriever_instance is None:
        _retriever_instance = build_retriever()  # backend from RETRIEVER_BACKEND
    return _retriever_instance


def get_trusted_domains() -> set[str]:
    global _trusted_domains_instance
    if _trusted_domains_instance is None:
        _trusted_domains_instance = set(load_trusted_domains())
    return _trusted_domains_instance


class AnalyzeRequest(BaseModel):
    url: str
    mode: str = "live"


@app.post("/api/analyze")
def analyze_endpoint(req: AnalyzeRequest):
    result = analyze_url(
        req.url,
        req.mode,
        retriever=get_retriever(),
        trusted_domains=get_trusted_domains(),
    )
    if result is None:
        raise HTTPException(status_code=400, detail="Invalid URL")
    return result.to_dict()


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
