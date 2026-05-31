"""Streamlit UI for the Evidence-Grounded Fake URL / Phishing Detection MVP.

Run with:  streamlit run app.py

This 50% MVP lets a user analyse a URL either by live (safe) crawling or by
loading one of the bundled sample HTML pages. It displays a classification,
risk score, evidence, retrieved RAG context, prompt-injection warnings and an
explanation, and can export JSON / Markdown reports.
"""

from __future__ import annotations

from typing import List, Optional

import streamlit as st

from src.config import OUTPUTS_DIR, settings
from src.crawler import crawl_sample, crawl_url
from src.html_analyzer import analyze_html
from src.llm_explainer import LLMExplainer
from src.prompt_injection_detector import detect_prompt_injection
from src.rag_retriever import RAGRetriever, build_query
from src.report_generator import build_markdown_report, save_json_report, save_markdown_report
from src.risk_engine import assess_risk
from src.schemas import FinalAnalysisResult
from src.url_features import extract_url_features, normalize_url
from src.utils import safe_filename_stamp, utc_timestamp

MVP_LIMITATIONS = [
    "Research prototype only - not a production security control.",
    "Rule-based scoring uses weak lexical/structural signals; false positives and negatives are expected.",
    "No WHOIS/DNS/TLS, no live threat-intelligence feeds, and no screenshot/OCR analysis yet.",
    "LLM explanation is optional and disabled by default; a deterministic fallback is used.",
    "Webpage content is treated as untrusted evidence and is never executed or obeyed.",
]

COMPLETED_MODULES = [
    "URL validation & normalization",
    "URL feature extraction",
    "Safe webpage crawler (GET-only)",
    "HTML / text analysis",
    "Form & password-field detection",
    "Prompt-injection detection",
    "Local TF-IDF RAG retriever",
    "Rule-based risk engine",
    "Fallback + optional LLM explainer",
    "JSON / Markdown reports",
    "Unit tests",
]

PENDING_MODULES = [
    "Multimodal screenshot + OCR analysis",
    "Live threat-intelligence APIs (PhishTank/OpenPhish)",
    "WHOIS / DNS / TLS certificate intelligence",
    "Stronger prompt-injection defenses",
    "Larger labelled evaluation & metrics",
    "Browser extension / full deployment",
]


# ---------------------------------------------------------------------------
# Cached resources
# ---------------------------------------------------------------------------
@st.cache_resource(show_spinner=False)
def get_retriever() -> RAGRetriever:
    """Build (and cache) the RAG retriever once per session."""
    return RAGRetriever()


# ---------------------------------------------------------------------------
# Core analysis pipeline
# ---------------------------------------------------------------------------
def analyze(url: str, mode: str) -> Optional[FinalAnalysisResult]:
    """Run the full analysis pipeline for a URL.

    Args:
        url: Raw URL string (used for feature extraction; also live-crawled).
        mode: One of "live", "benign", "phishing", "prompt_injection".

    Returns:
        A populated ``FinalAnalysisResult`` or ``None`` if input is invalid.
    """
    normalized = normalize_url(url) if url else ""
    if mode == "live" and not normalized:
        return None

    # 1. URL features (always computed from the typed URL).
    url_features = extract_url_features(url or normalized or "sample://local")

    # 2. Crawl (live) or load sample HTML.
    if mode == "live":
        crawl = crawl_url(normalized)
    else:
        crawl = crawl_sample(mode)

    # 3. HTML analysis.
    html_analysis = analyze_html(
        crawl.html, crawl.visible_text, base_url=crawl.final_url
    )

    # 4. Prompt-injection detection.
    prompt_injection = detect_prompt_injection(crawl.html, crawl.visible_text)

    # 5. RAG retrieval.
    retriever = get_retriever()
    query = build_query(
        url_features.evidence_messages,
        html_analysis.evidence_messages,
        prompt_injection.evidence_messages,
        extra_terms=url_features.suspicious_keywords_found
        + html_analysis.credential_patterns_found,
    )
    retrieved = retriever.retrieve(query)

    # 6. Risk assessment.
    risk = assess_risk(url_features, html_analysis, prompt_injection, retrieved)

    # 7. Explanation (LLM if configured, else deterministic fallback).
    explainer = LLMExplainer()
    explanation, source = explainer.generate_explanation(
        url_features, html_analysis, prompt_injection, retrieved, risk
    )

    return FinalAnalysisResult(
        requested_url=url if mode == "live" else f"[sample:{mode}] {url}".strip(),
        timestamp=utc_timestamp(),
        classification=risk.classification,
        risk_score=risk.score,
        confidence_label=risk.confidence_label,
        url_features=url_features,
        crawl=crawl,
        html_analysis=html_analysis,
        prompt_injection=prompt_injection,
        retrieved_evidence=retrieved,
        risk_assessment=risk,
        explanation=explanation,
        explanation_source=source,
        limitations=MVP_LIMITATIONS,
    )


# ---------------------------------------------------------------------------
# UI helpers
# ---------------------------------------------------------------------------
def render_sidebar() -> None:
    with st.sidebar:
        st.header("Project Status")
        st.progress(0.5, text="Current MVP Progress: 50%")
        st.metric("MVP Progress", "50%")

        st.subheader("Completed modules")
        for module in COMPLETED_MODULES:
            st.markdown(f"- {module}")

        st.subheader("Pending (next phase)")
        for module in PENDING_MODULES:
            st.markdown(f"- {module}")

        st.divider()
        llm_state = "enabled" if settings.llm_is_available() else "fallback (deterministic)"
        st.caption(f"Explanation mode: **{llm_state}**")
        st.caption(
            "Defensive research prototype. Do not use as your only security control."
        )


def render_classification(result: FinalAnalysisResult) -> None:
    cls = result.classification
    msg = (
        f"**{cls}** - risk score {result.risk_score}/100 "
        f"(confidence: {result.confidence_label})"
    )
    if cls == "Likely Phishing":
        st.error(msg)
    elif cls == "Suspicious":
        st.warning(msg)
    else:
        st.success(msg)


def render_results(result: FinalAnalysisResult) -> None:
    render_classification(result)

    col1, col2, col3 = st.columns(3)
    col1.metric("Risk score", f"{result.risk_score}/100")
    col2.metric("Classification", result.classification)
    col3.metric("Confidence", result.confidence_label)

    # Crawl status note.
    if not result.crawl.success and result.crawl.source == "live":
        st.warning(f"Live crawl did not succeed: {result.crawl.error}")

    # Prompt-injection warning.
    pi = result.prompt_injection
    if pi.injection_detected:
        st.error(
            f"Prompt-injection content detected (severity: {pi.severity}). "
            "Matched: " + ", ".join(pi.matched_patterns)
            + ". This text is treated as untrusted evidence and is never obeyed."
        )
    else:
        st.info("No prompt-injection patterns detected in page content.")

    # Risk factors.
    with st.expander("Key risk factors", expanded=True):
        rf = result.risk_assessment.risk_factors if result.risk_assessment else []
        if rf:
            for factor in rf:
                st.markdown(f"- {factor}")
        else:
            st.markdown("- No risk factors triggered.")
        sf = result.risk_assessment.safe_factors if result.risk_assessment else []
        if sf:
            st.markdown("**Mitigating factors:**")
            for factor in sf:
                st.markdown(f"- {factor}")

    # URL + page evidence.
    with st.expander("URL feature evidence"):
        for msg in result.url_features.evidence_messages:
            st.markdown(f"- {msg}")
        st.json(result.url_features.to_dict())

    with st.expander("Webpage analysis evidence"):
        st.markdown(f"**Page title:** {result.html_analysis.page_title or '(none)'}")
        for msg in result.html_analysis.evidence_messages:
            st.markdown(f"- {msg}")
        st.json(result.html_analysis.to_dict())

    # RAG evidence.
    with st.expander("Retrieved RAG evidence", expanded=True):
        if result.retrieved_evidence:
            for ev in result.retrieved_evidence:
                st.markdown(
                    f"**{ev.title}** "
                    f"_(category: {ev.category}, similarity: {ev.similarity_score}, "
                    f"trust: {ev.trust_level})_"
                )
                st.markdown(f"> {ev.content}")
                if ev.recommended_action:
                    st.caption(f"Recommended action: {ev.recommended_action}")
        else:
            st.markdown("No knowledge-base entries were retrieved.")

    # Explanation.
    st.subheader("Explanation")
    st.caption(f"Source: {result.explanation_source}")
    st.write(result.explanation)

    # Reports.
    render_download_buttons(result)


def render_download_buttons(result: FinalAnalysisResult) -> None:
    st.subheader("Reports")
    import json as _json

    json_bytes = _json.dumps(result.to_dict(), indent=2, ensure_ascii=False).encode("utf-8")
    md_text = build_markdown_report(result)
    stamp = safe_filename_stamp()

    col1, col2, col3 = st.columns(3)
    col1.download_button(
        "Download JSON",
        data=json_bytes,
        file_name=f"analysis_{stamp}.json",
        mime="application/json",
    )
    col2.download_button(
        "Download Markdown",
        data=md_text.encode("utf-8"),
        file_name=f"analysis_{stamp}.md",
        mime="text/markdown",
    )
    if col3.button("Save both to outputs/"):
        json_path = save_json_report(result, OUTPUTS_DIR / f"analysis_{stamp}.json")
        md_path = save_markdown_report(result, OUTPUTS_DIR / f"analysis_{stamp}.md")
        st.success(f"Saved:\n- {json_path}\n- {md_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    st.set_page_config(
        page_title="Evidence-Grounded Phishing URL Detection (MVP)",
        page_icon="🛡️",
        layout="wide",
    )

    render_sidebar()

    st.title("🛡️ Evidence-Grounded Fake URL / Phishing Detection")
    st.markdown(
        "A **50% MVP** research prototype that analyses a URL using lexical "
        "features, a safe crawler, HTML analysis, prompt-injection detection, a "
        "lightweight local RAG retriever and a transparent rule-based risk engine. "
        "It produces an evidence-grounded classification and explanation."
    )
    st.caption(
        "Defensive research tool. Sample data uses fictional brands/domains only. "
        "Treat results as decision support, not a definitive verdict."
    )

    mode_label = st.radio(
        "Analysis source",
        options=[
            "Live crawl",
            "Use sample benign page",
            "Use sample phishing page",
            "Use sample prompt-injection page",
        ],
        horizontal=True,
    )
    mode_map = {
        "Live crawl": "live",
        "Use sample benign page": "benign",
        "Use sample phishing page": "phishing",
        "Use sample prompt-injection page": "prompt_injection",
    }
    mode = mode_map[mode_label]

    default_url = "" if mode == "live" else "https://example.com/login"
    url = st.text_input(
        "URL to analyze",
        value=default_url,
        placeholder="https://example.com/login",
        help="For sample modes the URL is still used for feature extraction; the page content comes from the bundled sample.",
    )

    if mode != "live":
        st.info(
            "Sample mode: page content is loaded from a bundled local HTML file. "
            "The URL field is only used for URL feature extraction."
        )

    analyze_clicked = st.button("Analyze URL", type="primary")

    if analyze_clicked:
        if mode == "live" and not (url and url.strip()):
            st.error("Please enter a URL to analyze in live-crawl mode.")
            return
        with st.spinner("Analyzing..."):
            result = analyze(url, mode)
        if result is None:
            st.error("Could not analyze the provided input. Check the URL and try again.")
            return
        st.session_state["last_result"] = result

    if "last_result" in st.session_state:
        st.divider()
        render_results(st.session_state["last_result"])


if __name__ == "__main__":
    main()
