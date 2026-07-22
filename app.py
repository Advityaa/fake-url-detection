
from __future__ import annotations

from typing import Optional

import streamlit as st

from src.capabilities import capabilities
from src.config import OUTPUTS_DIR, load_trusted_domains, settings
from src.embedding_retriever import build_retriever
from src.pipeline import analyze_url
from src.rag_retriever import RAGRetriever
from src.report_generator import build_markdown_report, save_json_report, save_markdown_report
from src.schemas import FinalAnalysisResult
from src.utils import safe_filename_stamp

MVP_LIMITATIONS = [
    "Research prototype only - not a production security control.",
    "Rule-based scoring uses weak lexical/structural signals; false positives and negatives are still possible.",
    "The trusted-domain allowlist is a small local demo signal, not a security guarantee.",
    "WHOIS/DNS/TLS and threat-feed lookups depend on network availability and may report 'data not available'.",
    "Screenshot/OCR, browser rendering and dynamic analysis are optional stages that must be enabled (and require Playwright / Tesseract).",
    "LLM explanation is optional and disabled by default; a deterministic fallback is used.",
    "Webpage content is treated as untrusted evidence and is never executed or obeyed.",
]

COMPLETED_MODULES = [
    "URL analysis",
    "Safe crawler",
    "HTML analysis",
    "Local RAG retrieval (TF-IDF; optional embedding backend)",
    "Risk scoring",
    "Hidden instruction / prompt-injection detection",
    "Threat-intelligence feeds (OpenPhish / PhishTank)",
    "WHOIS / DNS / TLS domain reputation + conflict layer",
    "Multimodal screenshot + OCR (optional)",
    "Dynamic post-interaction cloaking analysis (optional)",
    "Report generation",
]

PENDING_MODULES = [
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
def get_retriever(backend: Optional[str] = None) -> RAGRetriever:
    """Build (and cache) a RAG retriever per backend.

    ``st.cache_resource`` keys on the ``backend`` argument, so TF-IDF and the
    embedding retriever are each built at most once even if a reviewer switches
    between them via the stage toggles. ``build_retriever`` falls back to TF-IDF
    if the embedding deps are missing.
    """
    return build_retriever(backend=backend)


@st.cache_resource(show_spinner=False)
def get_trusted_domains() -> set[str]:
    """Load (and cache) the local trusted-domain allowlist."""
    return set(load_trusted_domains())


# ---------------------------------------------------------------------------
# Core analysis pipeline
# ---------------------------------------------------------------------------
def analyze(
    url: str, mode: str, overrides: Optional[dict] = None
) -> Optional[FinalAnalysisResult]:
    """Run the full analysis pipeline for a URL (delegates to ``src.pipeline``).

    Args:
        url: Raw URL string (used for feature extraction; also live-crawled).
        mode: One of "live", "benign", "phishing", "prompt_injection".
        overrides: Optional per-request stage toggles from the sidebar controls
            (see :func:`render_stage_toggles`). ``None`` = use configured defaults.

    Returns:
        A populated ``FinalAnalysisResult`` or ``None`` if input is invalid.
    """
    overrides = overrides or {}
    return analyze_url(
        url,
        mode,
        retriever=get_retriever(overrides.get("retriever_backend")),
        trusted_domains=get_trusted_domains(),
        limitations=MVP_LIMITATIONS,
        enable_threat_intel=overrides.get("enable_threat_intel", True),
        enable_domain_intel=overrides.get("enable_domain_intel"),
        enable_multimodal=overrides.get("enable_multimodal"),
        enable_dynamic=overrides.get("enable_dynamic"),
        enable_llm=overrides.get("enable_llm"),
        render_backend=overrides.get("render_backend"),
    )


# ---------------------------------------------------------------------------
# UI helpers
# ---------------------------------------------------------------------------
def render_sidebar() -> None:
    with st.sidebar:
        st.header("Prototype status")
        st.progress(0.8, text="Current prototype completion: 80%")

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


# Sidebar stage toggles. `key` matches the capabilities() keys.
_STAGE_DEFS = [
    ("threat_intel", "Threat-intel feeds", "OpenPhish / PhishTank lookup"),
    ("domain_intel", "Domain reputation", "WHOIS age · DNS · TLS · conflicts"),
    ("render_playwright", "Playwright render", "Headless Chromium (vs plain GET)"),
    ("dynamic", "Dynamic analysis", "Post-interaction cloaking (needs render)"),
    ("multimodal", "Multimodal OCR", "Screenshot + OCR (needs render + EasyOCR)"),
    ("embedding", "Embedding RAG", "Vector retrieval (vs TF-IDF)"),
    ("llm", "LLM explanation", "Rephrases wording only (needs API key)"),
]


def render_stage_toggles() -> dict:
    """Render sidebar controls for the optional stages; return analyze() overrides.

    Availability comes from the single :func:`capabilities` source of truth: a
    stage whose dependency is missing renders disabled with a short reason, and
    is forced off in the returned overrides (never a silent no-op).
    """
    caps = capabilities()
    with st.sidebar:
        st.divider()
        st.subheader("Analysis stages")
        st.caption("Toggle optional stages to run an interactive ablation.")
        state: dict = {}
        for key, label, desc in _STAGE_DEFS:
            cap = caps.get(key, {})
            available = bool(cap.get("available"))
            default = bool(cap.get("default"))
            help_text = desc if available else f"Unavailable — {cap.get('reason', 'dependency missing')}"
            state[key] = st.checkbox(
                label,
                value=available and default,
                disabled=not available,
                help=help_text,
                key=f"stage_{key}",
            )

    def on(k: str) -> bool:
        return bool(caps.get(k, {}).get("available")) and bool(state.get(k))

    return {
        "enable_threat_intel": on("threat_intel"),
        "enable_domain_intel": on("domain_intel"),
        "enable_multimodal": on("multimodal"),
        "enable_dynamic": on("dynamic"),
        "enable_llm": on("llm"),
        "render_backend": "playwright" if on("render_playwright") else "requests",
        "retriever_backend": "embedding" if on("embedding") else "tfidf",
    }


def render_summary_card(result: FinalAnalysisResult) -> None:
    risk = result.risk_assessment
    label = risk.ui_label if risk else result.classification
    style, emoji = _STATUS_STYLE.get(label, ("info", "ℹ️"))
    
    card_class = "result-card-warning"
    if style == "success":
        card_class = "result-card-success"
    elif style == "error":
        card_class = "result-card-error"

    headline = f"<div class='{card_class}' style='margin-bottom: 2rem;'><h3>{emoji} {label}</h3><p style='margin: 0; font-size: 1.1rem;'>Risk Score: <strong>{result.risk_score}/100</strong> (Confidence: {result.confidence_label})</p></div>"
    st.markdown(headline, unsafe_allow_html=True)

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


def render_score_breakdown(result: FinalAnalysisResult) -> None:
    risk = result.risk_assessment
    if not risk or not risk.score_breakdown:
        return
    st.subheader("Score breakdown")
    st.caption(
        "Points each category contributed to the risk score "
        "(positive = riskier, negative = safer)."
    )
    entries = [(k, v) for k, v in risk.score_breakdown.items() if v != 0]
    if not entries:
        st.markdown("No category contributed to the score.")
        return
    max_abs = max(25, max(abs(v) for _, v in entries))
    for key, value in entries:
        label = key.replace("_", " ")
        sign = f"+{value}" if value > 0 else str(value)
        col_a, col_b = st.columns([4, 1])
        with col_a:
            st.markdown(f"**{label}**")
            st.progress(min(1.0, abs(value) / max_abs))
        col_b.markdown(f"`{sign}`")


def render_threat_intel(result: FinalAnalysisResult) -> None:
    ti = result.threat_intel
    st.markdown("#### Threat-intel feeds")
    if not ti or not ti.checked:
        note = ti.confidence_note if ti and ti.confidence_note else \
            "Threat-intel lookup was disabled for this run."
        st.caption(note)
        return
    if ti.listed:
        detail = f": {ti.matched_value}" if ti.matched_value else ""
        st.error(f"Listed on {ti.source or 'a feed'}{detail}")
    else:
        st.success("Not found in any consulted feed.")
    st.markdown(f"- Sources checked: {', '.join(ti.sources_checked) or '—'}")
    if ti.confidence_note:
        st.caption(ti.confidence_note)


def render_domain_intel(result: FinalAnalysisResult) -> None:
    di = result.domain_intel
    st.markdown("#### Domain reputation")
    if not di or not di.checked:
        st.caption("WHOIS / DNS / TLS lookups were not run for this analysis.")
        return
    if di.conflict_count > 0:
        st.error(f"{di.conflict_count} cross-signal conflict(s) detected.")
    else:
        st.success("No cross-signal conflicts detected.")
    col_w, col_d, col_t = st.columns(3)
    with col_w:
        st.markdown("**WHOIS**")
        if di.whois_available:
            st.markdown(f"- Registrar: {di.registrar or '—'}")
            st.markdown(f"- Created: {di.domain_created or '—'}")
            age = di.domain_age_days if di.domain_age_days is not None else "—"
            new_flag = " ⚠️ newly registered" if di.is_newly_registered else ""
            st.markdown(f"- Age (days): {age}{new_flag}")
            st.markdown(f"- Registrant country: {di.registrant_country or '—'}")
        else:
            st.markdown("- unavailable")
    with col_d:
        st.markdown("**DNS**")
        if di.dns_available:
            st.markdown(f"- Resolves (A): {_yesno(di.resolves)}")
            st.markdown(f"- Mail (MX): {_yesno(di.has_mx)}")
        else:
            st.markdown("- unavailable")
    with col_t:
        st.markdown("**TLS**")
        if di.tls_available:
            st.markdown(f"- Issuer: {di.cert_issuer or '—'}")
            st.markdown(f"- Cert org: {di.cert_org or '—'}")
            st.markdown(f"- Valid until: {di.cert_valid_until or '—'}")
            st.markdown(f"- Currently valid: {_yesno(di.cert_currently_valid)}")
            st.markdown(f"- Self-signed: {_yesno(di.cert_self_signed)}")
        else:
            st.markdown("- not checked (HTTP or unavailable)")
    if di.conflicts:
        st.markdown("**Conflicts**")
        for conflict in di.conflicts:
            st.markdown(f"- {_friendly(conflict)}")


def render_multimodal(result: FinalAnalysisResult) -> None:
    mm = result.multimodal
    st.markdown("#### Multimodal (screenshot + OCR)")
    if not mm or not mm.checked or not mm.available:
        st.caption(mm.note if mm and mm.note else "Multimodal analysis was not run.")
        return
    col_a, col_b = st.columns(2)
    col_a.markdown(f"- Brand seen in image: {mm.brand_in_image or 'none'}")
    col_a.markdown(f"- Text divergence: {_yesno(mm.text_divergence)} (ratio {mm.divergence_ratio:.2f})")
    inj = f" (severity {mm.injection_severity})" if mm.injection_in_ocr else ""
    col_b.markdown(f"- Injection in OCR: {_yesno(mm.injection_in_ocr)}{inj}")
    col_b.markdown(f"- OCR characters: {mm.ocr_char_count}")
    if mm.divergent_terms:
        st.markdown("Divergent terms: " + ", ".join(mm.divergent_terms))
    if mm.ocr_text_excerpt:
        with st.expander("OCR text excerpt (untrusted — never obeyed)"):
            st.code(mm.ocr_text_excerpt)


def render_dynamic(result: FinalAnalysisResult) -> None:
    dy = result.dynamic_analysis
    st.markdown("#### Dynamic analysis (post-interaction)")
    if not dy or not dy.checked or not dy.available:
        st.caption(dy.note if dy and dy.note else "Dynamic analysis was not run.")
        return
    if dy.cloaking_detected:
        st.error("Post-interaction cloaking detected.")
    else:
        st.success("No post-interaction cloaking detected.")
    fields = [
        ("Forms", "forms", "delta_forms"),
        ("Inputs", "inputs", "delta_inputs"),
        ("Password fields", "password_fields", "delta_password_fields"),
        ("Visible password fields", "visible_password_fields", "delta_visible_password_fields"),
    ]
    lines = ["| DOM element | Before | After | Δ |", "|---|---:|---:|---:|"]
    for label, field, delta_field in fields:
        before = getattr(dy.pre, field, 0)
        after = getattr(dy.post, field, 0)
        delta = getattr(dy, delta_field, 0)
        lines.append(f"| {label} | {before} | {after} | {delta:+d} |")
    st.markdown("\n".join(lines))
    st.caption(f"Clicked login control: {_yesno(dy.clicked_login)}")
    if dy.reasons:
        for reason in dy.reasons:
            st.markdown(f"- {_friendly(reason)}")


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
    render_score_breakdown(result)
    st.divider()
    st.subheader("Backend analysis stages")
    render_threat_intel(result)
    render_domain_intel(result)
    render_multimodal(result)
    render_dynamic(result)
    st.divider()
    render_hidden_instruction_check(result)
    st.divider()
    render_knowledge(result)
    st.divider()
    render_explanation(result)
    st.divider()
    render_downloads(result)
    render_advanced(result)


def _yesno(value) -> str:
    """Render an Optional[bool] as yes / no / — (unknown)."""
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "—"


def _friendly(factor: str) -> str:
    """Strip the trailing "[+N]." scoring annotation for readability in the UI."""
    idx = factor.rfind("[")
    if idx != -1:
        return factor[:idx].strip().rstrip(".")
    return factor


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def load_css(file_name: str) -> None:
    from pathlib import Path
    css_path = Path(__file__).parent / file_name
    if css_path.exists():
        with open(css_path) as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)


def main() -> None:
    st.set_page_config(
        page_title="Fake Website Safety Checker",
        page_icon="🛡️",
        layout="wide",
    )

    load_css("src/style.css")

    render_sidebar()
    overrides = render_stage_toggles()

    st.markdown('<div class="gradient-text">🛡️ Fake Website Safety Checker</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sub-header">Research prototype using URL analysis, webpage evidence, local RAG, and '
        'explainable risk scoring.</div>',
        unsafe_allow_html=True
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
            result = analyze(url, mode, overrides)
        if result is None:
            st.error("Could not check the provided input. Check the URL and try again.")
            return
        st.session_state["last_result"] = result

    if "last_result" in st.session_state:
        st.divider()
        render_results(st.session_state["last_result"])


if __name__ == "__main__":
    main()
