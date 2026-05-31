"""Report generation: serialise a ``FinalAnalysisResult`` to JSON / Markdown."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Union

from .schemas import FinalAnalysisResult


def save_json_report(final_result: FinalAnalysisResult, output_path: Union[str, Path]) -> Path:
    """Write the full analysis result as a pretty-printed JSON file."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(final_result.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return output_path


def build_markdown_report(final_result: FinalAnalysisResult) -> str:
    """Build a human-readable Markdown report string from the result."""
    f = final_result
    uf = f.url_features
    ha = f.html_analysis
    pi = f.prompt_injection

    lines: list[str] = []
    ui_label = f.risk_assessment.ui_label if f.risk_assessment else f.classification
    recommended = f.risk_assessment.recommended_action if f.risk_assessment else ""

    lines.append("# Website Safety Analysis Report")
    lines.append("")
    lines.append(f"- **URL analyzed:** `{f.requested_url}`")
    lines.append(f"- **Timestamp (UTC):** {f.timestamp}")
    lines.append(f"- **Safety result (UI):** {ui_label}")
    lines.append(f"- **Internal classification:** {f.classification}")
    lines.append(f"- **Risk score:** {f.risk_score}/100")
    lines.append(f"- **Confidence:** {f.confidence_label}")
    lines.append(f"- **Trusted-domain allowlist match:** {f.is_trusted_domain}")
    if recommended:
        lines.append(f"- **Recommended action:** {recommended}")
    lines.append(f"- **Explanation source:** {f.explanation_source}")
    lines.append("")

    # URL features.
    lines.append("## URL Features Summary")
    lines.append("")
    lines.append(f"- Normalized URL: `{uf.normalized_url}`")
    lines.append(f"- Scheme: {uf.scheme} | HTTPS: {uf.uses_https}")
    lines.append(f"- Hostname: `{uf.hostname}` (domain: `{uf.domain}`, suffix: `{uf.suffix}`)")
    lines.append(f"- URL length: {uf.url_length}, subdomains: {uf.number_of_subdomains}")
    lines.append(
        f"- IP address: {uf.contains_ip_address} | '@' symbol: {uf.contains_at_symbol} | "
        f"punycode: {uf.contains_punycode} | shortener: {uf.is_shortened_url}"
    )
    if uf.suspicious_keywords_found:
        lines.append(f"- Suspicious keywords: {', '.join(uf.suspicious_keywords_found)}")
    lines.append(f"- Hostname entropy: {uf.entropy_score}")
    for msg in uf.evidence_messages:
        lines.append(f"  - {msg}")
    lines.append("")

    # Crawl.
    lines.append("## Crawl / Fetch Status")
    lines.append("")
    lines.append(f"- Source: {f.crawl.source}")
    lines.append(f"- Success: {f.crawl.success}")
    lines.append(f"- Status code: {f.crawl.status_code}")
    lines.append(f"- Final URL: `{f.crawl.final_url}`")
    if f.crawl.redirect_chain:
        lines.append(f"- Redirect chain: {' -> '.join(f.crawl.redirect_chain)}")
    if f.crawl.error:
        lines.append(f"- Error: {f.crawl.error}")
    lines.append("")

    # HTML analysis.
    lines.append("## Webpage Analysis Summary")
    lines.append("")
    lines.append(f"- Page title: {ha.page_title or '(none)'}")
    lines.append(f"- Forms: {ha.number_of_forms} | Password fields: {ha.number_of_password_fields}")
    lines.append(
        f"- Input fields: {ha.number_of_input_fields} | External links: "
        f"{ha.number_of_external_links} | Scripts: {ha.number_of_script_tags}"
    )
    lines.append(f"- Credential request detected: {ha.credential_request_detected}")
    if ha.credential_patterns_found:
        lines.append(f"- Credential patterns: {', '.join(ha.credential_patterns_found)}")
    if ha.brand_like_words:
        lines.append(f"- Brand-like words: {', '.join(ha.brand_like_words)}")
    for msg in ha.evidence_messages:
        lines.append(f"  - {msg}")
    lines.append("")

    # Brand-domain check.
    if f.brand_check is not None:
        bc = f.brand_check
        lines.append("## Brand-Domain Check")
        lines.append("")
        lines.append(f"- Registered domain: `{bc.registered_domain}`")
        lines.append(f"- Detected brands: {', '.join(bc.detected_brands) or '(none)'}")
        lines.append(f"- Brand-domain match: {bc.brand_domain_match}")
        lines.append(f"- Possible brand mismatch: {bc.possible_brand_mismatch}")
        for msg in bc.evidence_messages:
            lines.append(f"  - {msg}")
        lines.append("")

    # Prompt injection.
    lines.append("## Hidden-Instruction (Prompt-Injection) Findings")
    lines.append("")
    lines.append(f"- Detected: {pi.injection_detected} (severity: {pi.severity})")
    if pi.matched_patterns:
        lines.append(f"- Matched patterns: {', '.join(pi.matched_patterns)}")
    for snippet in pi.suspicious_snippets:
        lines.append(f"  - Snippet: {snippet}")
    for msg in pi.evidence_messages:
        lines.append(f"  - {msg}")
    lines.append("")

    # RAG evidence.
    lines.append("## Retrieved RAG Evidence")
    lines.append("")
    if f.retrieved_evidence:
        for ev in f.retrieved_evidence:
            lines.append(
                f"- **{ev.title}** (category: {ev.category}, "
                f"similarity: {ev.similarity_score}, trust: {ev.trust_level})"
            )
            lines.append(f"  - {ev.content}")
            if ev.recommended_action:
                lines.append(f"  - Recommended action: {ev.recommended_action}")
    else:
        lines.append("- No knowledge-base entries were retrieved.")
    lines.append("")

    # Explanation.
    lines.append("## Final Explanation")
    lines.append("")
    lines.append(f.explanation or "(no explanation generated)")
    lines.append("")

    # Limitations.
    lines.append("## Limitations")
    lines.append("")
    for limitation in f.limitations:
        lines.append(f"- {limitation}")
    lines.append("")

    return "\n".join(lines)


def save_markdown_report(final_result: FinalAnalysisResult, output_path: Union[str, Path]) -> Path:
    """Write a Markdown report to ``output_path`` and return the path."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(build_markdown_report(final_result), encoding="utf-8")
    return output_path
