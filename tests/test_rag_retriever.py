"""Unit tests for the lightweight TF-IDF RAG retriever."""

from src.rag_retriever import RAGRetriever, build_query


def test_knowledge_base_loads():
    retriever = RAGRetriever()
    assert len(retriever.entries) >= 20


def test_retrieve_returns_relevant_password_entry():
    retriever = RAGRetriever()
    results = retriever.retrieve("password input field credential harvesting login form")
    assert len(results) > 0
    categories = {r.category for r in results}
    assert categories & {"password_field", "login_form"}


def test_retrieve_prompt_injection_entry():
    retriever = RAGRetriever()
    results = retriever.retrieve(
        "ignore previous instructions system prompt prompt injection hidden"
    )
    titles = " ".join(r.title.lower() for r in results)
    assert "prompt injection" in titles


def test_retrieve_respects_top_k():
    retriever = RAGRetriever()
    results = retriever.retrieve("phishing url login password ip punycode", top_k=3)
    assert len(results) <= 3


def test_scores_sorted_descending():
    retriever = RAGRetriever()
    results = retriever.retrieve("shortened url bit.ly redirect hidden destination")
    scores = [r.similarity_score for r in results]
    assert scores == sorted(scores, reverse=True)


def test_empty_query_returns_nothing():
    retriever = RAGRetriever()
    assert retriever.retrieve("") == []


def test_build_query_combines_parts():
    query = build_query(["url ev"], ["page ev"], ["inj ev"], extra_terms=["login"])
    assert "url ev" in query and "page ev" in query and "login" in query
