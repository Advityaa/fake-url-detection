"""phishing-rag-mvp source package.

Evidence-Grounded Fake URL / Phishing Website Detection (50% MVP prototype).

This package contains the core, lightweight modules used by the Streamlit app:
URL feature extraction, a safe crawler, HTML analysis, prompt-injection
detection, a local TF-IDF RAG retriever, a transparent rule-based risk engine,
an optional LLM explainer (with deterministic fallback) and report generation.
"""

__version__ = "0.1.0"
