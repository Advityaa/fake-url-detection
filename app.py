"""Streamlit UI for the Fake Website Safety Checker (50% MVP).

Run with:  streamlit run app.py

This 50% MVP lets a user check a website by live (safe) crawling or by loading
one of the bundled sample pages. It shows a plain-English safety result, a risk
score, the reasons behind the result, retrieved security knowledge, a hidden
instruction (prompt-injection) check, and an explanation, and can export
JSON / Markdown reports.
"""

from __future__ import annotations

from typing import Optional

import streamlit as st

from src.config import OUTPUTS_DIR, load_trusted_domains, settings
from src.crawler import crawl_sample, crawl_url
from src.html_analyzer import analyze_html, check_brand_domain
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
    "Rule-based scoring uses weak lexical/structural signals; false positives and negatives are still possible.",
    "The trusted-domain allowlist is a small local demo signal, not a security guarantee.",
    "No WHOIS/DNS/TLS, no live threat-intelligence feeds, and no screenshot/OCR analysis yet.",
    "LLM explanation is optional and disabled by default; a deterministic fallback is used.",
    "Webpage content is treated as untrusted evidence and is never executed or obeyed.",
]

COMPLETED_MODULES = [
    "URL analysis",
    "Safe crawler",
    "HTML analysis",
    "Local RAG retrieval",
    "Risk scoring",
    "Basic hidden instruction detection",
    "Report generation",
]

PENDING_MODULES = [
    "OCR screenshot analysis",
    "Live threat-intelligence APIs",
    "WHOIS / DNS / TLS checks",
    "Larger dataset evaluation",
    "Full final report metrics",
]

_STATUS_STYLE = {
    "Likely Safe": ("success", "🟢"),
    "Needs Caution": ("warning", "🟠"),
    "High Risk": ("error", "🔴"),
}


# ---------------------------------------------------------------------------
# Cached resources
# ---------------------------------------------------------------------------
@st.cache_resource(show_spinner=False)
def get_retriever() -> RAGRetriever:
    """Build (and cache) the RAG retriever once per session."""
    return RAGRetriever()


@st.cache_resource(show_spinner=False)
def get_trusted_domains() -> set[str]:
    """Load (and cache) the local trusted-domain allowlist."""
    return set(load_trusted_domains())


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

    # 4. Brand-domain check.
    registered_domain = ".".join(p for p in [url_features.domain, url_features.suffix] if p)
    brand_check = check_brand_domain(html_analysis.brand_like_words, registered_domain)

    # 5. Prompt-injection (hidden instruction) detection.
    prompt_injection = detect_prompt_injection(crawl.html, crawl.visible_text)

    # 6. Trusted-domain allowlist (MVP demo signal only).
    is_trusted = bool(registered_domain) and registered_domain.lower() in get_trusted_domains()

    # 7. RAG retrieval.
    retriever = get_retriever()
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
        brand_check=brand_check,
        is_trusted_domain=is_trusted,
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
        st.header("Prototype status")
        st.progress(0.5, text="Current prototype completion: 50%")

        st.subheader("Completed")
        for module in COMPLETED_MODULES:
            st.markdown(f"- {module}")

        st.subheader("Pending")
        for module in PENDING_MODULES:
            st.markdown(f"- {module}")

        st.divider()
        llm_state = "enabled" if settings.llm_is_available() else "fallback (deterministic)"
        st.caption(f"Explanation mode: **{llm_state}**")
        st.caption(
            "This tool is for research and decision support only. It does not "
            "guarantee that a website is safe."
        )


def render_summary_card(result: FinalAnalysisResult) -> None:
    risk = result.risk_assessment
    label = risk.ui_label if risk else result.classification
    style, emoji = _STATUS_STYLE.get(label, ("info", "ℹ️"))
    headline = f"{emoji} **{label}** — risk score {result.risk_score}/100 (confidence: {result.confidence_label})"

    getattr(st, style)(headline)

    col1, col2, col3 = st.columns(3)
    col1.metric("Safety result", label)
    col2.metric("Risk score", f"{result.risk_score}/100")
    col3.metric("Confidence", result.confidence_label)

    if risk and risk.recommended_action:
        st.markdown(f"**Recommended action:** {risk.recommended_action}")

    if not result.crawl.success and result.crawl.source == "live":
        st.warning(
            f"Live website check could not fully load the page ({result.crawl.error}). "
            "The result is based on the URL and any available content."
        )


def render_reasons(result: FinalAnalysisResult) -> None:
    st.subheader("Why did we give this result?")
    risk = result.risk_assessment
    risk_factors = risk.risk_factors if risk else []
    safe_factors = risk.safe_factors if risk else []

    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown("**Risk signals found**")
        if risk_factors:
            for factor in risk_factors:
                st.markdown(f"- {_friendly(factor)}")
        else:
            st.markdown("- None.")
    with col_b:
        st.markdown("**Safety / mitigating signals found**")
        if safe_factors:
            for factor in safe_factors:
                st.markdown(f"- {_friendly(factor)}")
        else:
            st.markdown("- None.")


def render_hidden_instruction_check(result: FinalAnalysisResult) -> None:
    st.subheader("Hidden instruction check")
    st.caption(
        "Some malicious webpages may hide text that tries to manipulate AI tools. "
        "This system checks for such patterns and never follows them."
    )
    pi = result.prompt_injection
    if pi.injection_detected:
        st.error(
            f"Hidden AI-manipulation instructions were detected (severity: {pi.severity}). "
            "This text was treated as untrusted evidence and was not followed."
        )
        with st.expander("Show detected patterns (advanced)"):
            st.markdown("Matched patterns: " + ", ".join(pi.matched_patterns))
            for snippet in pi.suspicious_snippets:
                st.markdown(f"- {snippet}")
    else:
        st.success("No hidden AI-manipulation instructions found.")


def render_knowledge(result: FinalAnalysisResult) -> None:
    st.subheader("Retrieved security knowledge")
    st.caption(
        "Relevant background knowledge retrieved from a local knowledge base to "
        "help explain the result."
    )
    if not result.retrieved_evidence:
        st.markdown("No related knowledge was retrieved.")
        return

    for ev in result.retrieved_evidence:
        with st.container(border=True):
            st.markdown(f"**{ev.title}**")
            st.markdown(f"Why it matters: {ev.content}")
            if ev.recommended_action:
                st.markdown(f"Recommended action: {ev.recommended_action}")
            with st.expander("Advanced details"):
                st.markdown(
                    f"- Category: {ev.category}\n"
                    f"- Trust level: {ev.trust_level}\n"
                    f"- Source type: {ev.source_type}\n"
                    f"- Similarity score: {ev.similarity_score}"
                )


def render_explanation(result: FinalAnalysisResult) -> None:
    st.subheader("Explanation")
    st.caption(f"Source: {result.explanation_source}")
    st.write(result.explanation)


def render_advanced(result: FinalAnalysisResult) -> None:
    with st.expander("Advanced technical details"):
        st.markdown("**URL features**")
        st.json(result.url_features.to_dict())
        st.markdown("**Webpage analysis**")
        st.json(result.html_analysis.to_dict())
        if result.brand_check:
            st.markdown("**Brand-domain check**")
            st.json(result.brand_check.to_dict())
        st.markdown("**Crawl / fetch**")
        st.json(result.crawl.to_dict())
        st.markdown("**Full result**")
        st.json(result.to_dict())


def render_downloads(result: FinalAnalysisResult) -> None:
    st.subheader("Download reports")
    import json as _json

    json_bytes = _json.dumps(result.to_dict(), indent=2, ensure_ascii=False).encode("utf-8")
    md_text = build_markdown_report(result)
    stamp = safe_filename_stamp()

    col1, col2, col3 = st.columns(3)
    col1.download_button(
        "Download detailed JSON report",
        data=json_bytes,
        file_name=f"analysis_{stamp}.json",
        mime="application/json",
    )
    col2.download_button(
        "Download Markdown report",
        data=md_text.encode("utf-8"),
        file_name=f"analysis_{stamp}.md",
        mime="text/markdown",
    )
    if col3.button("Save both to outputs/"):
        json_path = save_json_report(result, OUTPUTS_DIR / f"analysis_{stamp}.json")
        md_path = save_markdown_report(result, OUTPUTS_DIR / f"analysis_{stamp}.md")
        st.success(f"Saved:\n- {json_path}\n- {md_path}")


def render_results(result: FinalAnalysisResult) -> None:
    render_summary_card(result)
    st.divider()
    render_reasons(result)
    st.divider()
    render_hidden_instruction_check(result)
    st.divider()
    render_knowledge(result)
    st.divider()
    render_explanation(result)
    st.divider()
    render_downloads(result)
    render_advanced(result)


def _friendly(factor: str) -> str:
    """Strip the trailing "[+N]." scoring annotation for readability in the UI."""
    idx = factor.rfind("[")
    if idx != -1:
        return factor[:idx].strip().rstrip(".")
    return factor


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    st.set_page_config(
        page_title="Fake Website Safety Checker",
        page_icon="🛡️",
        layout="wide",
    )

    render_sidebar()

    st.title("🛡️ Fake Website Safety Checker")
    st.markdown(
        "Research prototype using URL analysis, webpage evidence, local RAG, and "
        "explainable risk scoring."
    )
    st.info(
        "This tool is for research and decision support only. It does not "
        "guarantee that a website is safe."
    )

    mode_label = st.radio(
        "Analysis mode",
        options=[
            "Live website check",
            "Sample safe page",
            "Sample phishing page",
            "Sample prompt-injection page",
        ],
        horizontal=True,
    )
    mode_map = {
        "Live website check": "live",
        "Sample safe page": "benign",
        "Sample phishing page": "phishing",
        "Sample prompt-injection page": "prompt_injection",
    }
    mode = mode_map[mode_label]

    # Per-mode default URLs. Sample modes use fictional, non-trusted,
    # suspicious-looking domains so the demo is realistic (the page content
    # still comes from the bundled local HTML file).
    sample_defaults = {
        "live": "",
        "benign": "https://maple-town-library.example.org/",
        "phishing": "http://globapay-account-verify.secure-login.example.net/account/update",
        "prompt_injection": "http://cloudvault-login.secure-files.example.net/login",
    }
    url = st.text_input(
        "Enter a website URL",
        value=sample_defaults.get(mode, ""),
        placeholder="example: amazon.com or https://example.com/login",
        help="You can type a bare domain (e.g. amazon.com); it is checked over HTTPS first.",
    )

    if mode != "live":
        st.caption(
            "Sample mode: page content is loaded from a bundled local HTML file. "
            "The URL field is only used for URL feature extraction."
        )

    if st.button("Check Website", type="primary"):
        if mode == "live" and not (url and url.strip()):
            st.error("Please enter a website URL to check in live mode.")
            return
        with st.spinner("Checking..."):
            result = analyze(url, mode)
        if result is None:
            st.error("Could not check the provided input. Check the URL and try again.")
            return
        st.session_state["last_result"] = result

    if "last_result" in st.session_state:
        st.divider()
        render_results(st.session_state["last_result"])


if __name__ == "__main__":
    main()
