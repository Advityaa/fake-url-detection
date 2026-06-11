"""Shared analysis pipeline for the Fake URL / phishing detector.

Both front-ends (the Streamlit app in ``app.py`` and the FastAPI service in
``api.py``) call :func:`analyze_url` so the analysis logic lives in exactly one
place and the two interfaces can never drift apart. Each caller supplies its own
(cached) ``RAGRetriever`` and trusted-domain set so resource caching stays the
responsibility of the front-end.
"""

from __future__ import annotations

from typing import List, Optional, Sequence

from .crawler import crawl_sample, crawl_url
from .html_analyzer import analyze_html, check_brand_domain
from .llm_explainer import LLMExplainer
from .prompt_injection_detector import detect_prompt_injection
from .rag_retriever import RAGRetriever, build_query
from .risk_engine import assess_risk
from .schemas import FinalAnalysisResult
from .url_features import extract_url_features, normalize_url
from .utils import utc_timestamp


def analyze_url(
    url: str,
    mode: str,
    retriever: RAGRetriever,
    trusted_domains: Sequence[str],
    limitations: Optional[List[str]] = None,
) -> Optional[FinalAnalysisResult]:
    """Run the full analysis pipeline for a URL.

    Args:
        url: Raw URL string (used for feature extraction; also live-crawled).
        mode: One of ``"live"``, ``"benign"``, ``"phishing"``, ``"prompt_injection"``.
        retriever: A (preferably cached) RAG retriever instance.
        trusted_domains: Iterable of lowercased trusted registered domains.
        limitations: Optional list of caveats to attach to the result.

    Returns:
        A populated :class:`FinalAnalysisResult`, or ``None`` if live mode was
        requested with an invalid/empty URL.
    """
    trusted = set(trusted_domains)

    normalized = normalize_url(url) if url else ""
    if mode == "live" and not normalized:
        return None

    # 1. Crawl (live, HTTPS-first) or load sample HTML.
    if mode == "live":
        crawl = crawl_url(normalized)
    else:
        crawl = crawl_sample(mode)

    # 2. URL features. For a successful live crawl, recompute from the FINAL URL
    #    so the scheme used for scoring reflects redirects (HTTPS-first).
    feature_url = url or normalized or "https://local.sample"
    if mode == "live" and crawl.success and crawl.final_url:
        feature_url = crawl.final_url
    url_features = extract_url_features(feature_url)

    # 3. HTML analysis.
    html_analysis = analyze_html(crawl.html, crawl.visible_text, base_url=crawl.final_url)

    # 4. Brand-domain check (page text vs registered domain).
    registered_domain = url_features.registered_domain or ".".join(
        p for p in [url_features.domain, url_features.suffix] if p
    )
    brand_check = check_brand_domain(html_analysis.brand_like_words, registered_domain)

    # 5. Prompt-injection (hidden instruction) detection.
    prompt_injection = detect_prompt_injection(crawl.html, crawl.visible_text)

    # 6. Trusted-domain allowlist (MVP demo signal only).
    is_trusted = bool(registered_domain) and registered_domain.lower() in trusted

    # 7. RAG retrieval.
    query = build_query(
        url_features.evidence_messages,
        html_analysis.evidence_messages,
        prompt_injection.evidence_messages,
        extra_terms=url_features.suspicious_keywords_found
        + html_analysis.credential_patterns_found,
    )
    retrieved = retriever.retrieve(query)

    # 8. Risk assessment (evidence-conditioned).
    risk = assess_risk(
        url_features,
        html_analysis,
        prompt_injection,
        retrieved,
        brand_check=brand_check,
        is_trusted_domain=is_trusted,
        redirect_count=len(crawl.redirect_chain),
    )

    # 9. Explanation (LLM if configured, else deterministic fallback).
    explainer = LLMExplainer()
    explanation, source = explainer.generate_explanation(
        url_features, html_analysis, prompt_injection, retrieved, risk
    )

    requested_url = url if mode == "live" else f"[sample:{mode}] {url}".strip()

    return FinalAnalysisResult(
        requested_url=requested_url,
        timestamp=utc_timestamp(),
        classification=risk.classification,
        risk_score=risk.score,
        confidence_label=risk.confidence_label,
        url_features=url_features,
        crawl=crawl,
        html_analysis=html_analysis,
        prompt_injection=prompt_injection,
        brand_check=brand_check,
        is_trusted_domain=is_trusted,
        retrieved_evidence=retrieved,
        risk_assessment=risk,
        explanation=explanation,
        explanation_source=source,
        limitations=limitations or [],
    )
