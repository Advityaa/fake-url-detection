"""Shared analysis pipeline for the Fake URL / phishing detector.

Both front-ends (the Streamlit app in ``app.py`` and the FastAPI service in
``api.py``) call :func:`analyze_url` so the analysis logic lives in exactly one
place and the two interfaces can never drift apart. Each caller supplies its own
(cached) ``RAGRetriever`` and trusted-domain set so resource caching stays the
responsibility of the front-end.
"""

from __future__ import annotations

from typing import List, Optional, Sequence

from .capabilities import llm_key_present
from .config import settings
from .crawler import crawl_sample, fetch_live
from .domain_intel import DomainIntelClient
from .domain_intel import get_default_client as get_default_domain_client
from .dynamic_analysis import run_dynamic_analysis
from .html_analyzer import analyze_html, check_brand_domain
from .llm_explainer import LLMExplainer
from .prompt_injection_detector import detect_prompt_injection
from .rag_retriever import RAGRetriever, build_query
from .risk_engine import assess_risk
from .schemas import (
    DomainIntelResult,
    DynamicAnalysisResult,
    FinalAnalysisResult,
    MultimodalResult,
    ThreatIntelResult,
)
from .screenshot_ocr import run_multimodal
from .threat_intel import ThreatIntelClient, get_default_client
from .url_features import extract_url_features, normalize_url
from .utils import utc_timestamp


def analyze_url(
    url: str,
    mode: str,
    retriever: RAGRetriever,
    trusted_domains: Sequence[str],
    limitations: Optional[List[str]] = None,
    threat_client: Optional[ThreatIntelClient] = None,
    domain_client: Optional[DomainIntelClient] = None,
    enable_threat_intel: bool = True,
    multimodal: Optional[MultimodalResult] = None,
    dynamic: Optional[DynamicAnalysisResult] = None,
    enable_domain_intel: Optional[bool] = None,
    enable_multimodal: Optional[bool] = None,
    enable_dynamic: Optional[bool] = None,
    enable_llm: Optional[bool] = None,
    render_backend: Optional[str] = None,
) -> Optional[FinalAnalysisResult]:
    """Run the full analysis pipeline for a URL.

    Args:
        url: Raw URL string (used for feature extraction; also live-crawled).
        mode: One of ``"live"``, ``"benign"``, ``"phishing"``, ``"prompt_injection"``.
        retriever: A (preferably cached) RAG retriever instance.
        trusted_domains: Iterable of lowercased trusted registered domains.
        limitations: Optional list of caveats to attach to the result.

    Per-request stage overrides (all default ``None`` = use the configured
    ``settings`` default). These are the wiring behind the UI stage toggles so a
    reviewer can run an interactive ablation without editing config; they only
    turn existing stages on/off and never change detection logic:
        enable_domain_intel: Force WHOIS/DNS/TLS reputation on/off.
        enable_multimodal: Force screenshot+OCR on/off (live mode only).
        enable_dynamic: Force post-interaction cloaking analysis on/off.
        enable_llm: Force the LLM explanation on/off (on only if a key is set).
        render_backend: Override the crawl backend ("requests" | "playwright").

    Returns:
        A populated :class:`FinalAnalysisResult`, or ``None`` if live mode was
        requested with an invalid/empty URL.
    """
    trusted = set(trusted_domains)

    normalized = normalize_url(url) if url else ""
    if mode == "live" and not normalized:
        return None

    # 1. Crawl (live, HTTPS-first) or load sample HTML. fetch_live selects the
    #    render backend (requests | playwright) from config, with safe fallback.
    if mode == "live":
        crawl = fetch_live(normalized, render_backend=render_backend)
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

    # 7. Threat-intelligence lookup (OpenPhish cache + optional PhishTank).
    #    Uses the FINAL URL so redirects to a known-phishing landing page count.
    #    ``enable_threat_intel=False`` skips the lookup entirely — used by the
    #    evaluation harness so feed-derived labels cannot leak into the score.
    threat_url = crawl.final_url if (mode == "live" and crawl.final_url) else (normalized or url)
    if enable_threat_intel:
        threat_intel = (threat_client or get_default_client()).check(threat_url, registered_domain)
    else:
        threat_intel = ThreatIntelResult(
            confidence_note="Threat-intelligence lookups disabled for this run."
        )

    # 8. Domain reputation (WHOIS age / DNS / TLS). Live lookups only make sense
    #    for real domains, so sample modes skip them unless a client is injected
    #    (tests inject mocked clients and may use sample mode). A per-request
    #    ``enable_domain_intel`` override (UI toggle) wins over the default gate.
    if enable_domain_intel is None:
        want_domain_intel = domain_client is not None or mode == "live"
    else:
        want_domain_intel = enable_domain_intel
    if want_domain_intel:
        domain_intel = (domain_client or get_default_domain_client()).gather(
            threat_url, registered_domain, page_brands=html_analysis.brand_like_words
        )
    else:
        domain_intel = DomainIntelResult(domain=registered_domain.lower())

    # 9. Multimodal (screenshot + OCR) — OPTIONAL, off by default. Only renders a
    #    real URL (live mode), and only when enabled + not caller-injected. All
    #    OCR text is treated as untrusted (scanned for injection, never obeyed).
    #    A caller-supplied ``multimodal`` (e.g. tests) is used as-is.
    if multimodal is None:
        want_multimodal = settings.use_multimodal if enable_multimodal is None else enable_multimodal
        if want_multimodal and mode == "live":
            multimodal = run_multimodal(
                threat_url, crawl.visible_text, registered_domain,
                is_trusted_domain=is_trusted,
            )
        else:
            multimodal = MultimodalResult(
                note="Multimodal analysis not run (disabled or non-live mode)."
            )

    # 9b. Dynamic analysis (post-interaction cloaking) — needs the Playwright
    #     render backend and a live URL. Skips gracefully if the browser is
    #     unavailable. A caller-supplied ``dynamic`` (tests) is used as-is.
    if dynamic is None:
        effective_render = render_backend or settings.render_backend
        if enable_dynamic is None:
            want_dynamic = effective_render == "playwright"
        else:
            want_dynamic = enable_dynamic
        if want_dynamic and mode == "live":
            dynamic = run_dynamic_analysis(
                threat_url, registered_domain, is_trusted_domain=is_trusted
            )
        else:
            dynamic = DynamicAnalysisResult(
                note="Dynamic analysis not run (needs the playwright backend + live mode)."
            )

    # 10. RAG retrieval.
    query = build_query(
        url_features.evidence_messages,
        html_analysis.evidence_messages,
        prompt_injection.evidence_messages,
        extra_terms=url_features.suspicious_keywords_found
        + html_analysis.credential_patterns_found
        + threat_intel.evidence_messages
        + domain_intel.evidence_messages
        + multimodal.evidence_messages
        + dynamic.evidence_messages,
    )
    retrieved = retriever.retrieve(query)

    # 11. Risk assessment (evidence-conditioned).
    risk = assess_risk(
        url_features,
        html_analysis,
        prompt_injection,
        retrieved,
        brand_check=brand_check,
        is_trusted_domain=is_trusted,
        redirect_count=len(crawl.redirect_chain),
        threat_intel=threat_intel,
        domain_intel=domain_intel,
        multimodal=multimodal,
        dynamic=dynamic,
    )

    # 12. Explanation (LLM if configured, else deterministic fallback).
    #     WORDING ONLY: the LLM (when enabled) rephrases the explanation; the
    #     classification and risk_score above come solely from the risk engine
    #     and are never overridden by the LLM. Raw page text is passed so the
    #     explainer can include it as clearly-delimited untrusted evidence — it
    #     is withheld automatically when prompt injection is detected.
    explainer = LLMExplainer()
    # Per-request LLM override (UI toggle): force the LLM path on only when a
    # provider key is actually configured; force off unconditionally. Wording is
    # still the only thing the LLM affects — the score/classification are fixed.
    if enable_llm is not None:
        explainer.available = bool(enable_llm) and llm_key_present()
    explanation, source = explainer.generate_explanation(
        url_features, html_analysis, prompt_injection, retrieved, risk,
        page_text=crawl.visible_text,
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
        threat_intel=threat_intel,
        domain_intel=domain_intel,
        multimodal=multimodal,
        dynamic_analysis=dynamic,
        retrieved_evidence=retrieved,
        risk_assessment=risk,
        explanation=explanation,
        explanation_source=source,
        limitations=limitations or [],
    )
