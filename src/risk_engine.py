"""Transparent, rule-based risk scoring engine.

The engine combines weak signals from URL features, HTML analysis, prompt
injection detection and retrieved RAG evidence into a single 0-100 risk score.
Every point added is recorded as a human-readable risk factor, so the result is
fully explainable (no black-box model in the MVP).
"""

from __future__ import annotations

from typing import List

from .config import (
    CLASS_BENIGN,
    CLASS_PHISHING,
    CLASS_SUSPICIOUS,
    PHISHING_THRESHOLD,
    SUSPICIOUS_THRESHOLD,
)
from .schemas import (
    HTMLAnalysisResult,
    PromptInjectionResult,
    RetrievedEvidence,
    RiskAssessmentResult,
    URLFeatureResult,
)

# Phishing-related RAG categories used to (mildly) boost the score when the
# retriever surfaces strongly relevant knowledge.
_PHISHING_RAG_CATEGORIES = {
    "url_structure",
    "brand_impersonation",
    "login_form",
    "password_field",
    "shortened_url",
    "ip_url",
    "punycode",
    "http_only",
    "social_engineering",
    "account_verification",
    "payment_harvesting",
    "prompt_injection",
    "hidden_text",
    "brand_mismatch",
    "redirects",
}


def assess_risk(
    url_features: URLFeatureResult,
    html_analysis: HTMLAnalysisResult,
    prompt_injection: PromptInjectionResult,
    retrieved_evidence: List[RetrievedEvidence],
) -> RiskAssessmentResult:
    """Compute a transparent 0-100 risk score and classification.

    Returns:
        A ``RiskAssessmentResult`` with score, classification, confidence,
        and the lists of risk / safe / explanation factors.
    """
    score = 0
    risk_factors: List[str] = []
    safe_factors: List[str] = []

    score += _score_url(url_features, risk_factors, safe_factors)
    score += _score_html(html_analysis, risk_factors, safe_factors)
    score += _score_injection(prompt_injection, risk_factors)
    score += _score_rag(retrieved_evidence, risk_factors)

    score = max(0, min(100, score))
    classification = _classify(score)
    confidence = _confidence_label(score, risk_factors)

    explanation_points = _build_explanation_points(
        classification, score, risk_factors, safe_factors
    )

    return RiskAssessmentResult(
        score=score,
        classification=classification,
        confidence_label=confidence,
        risk_factors=risk_factors,
        safe_factors=safe_factors,
        explanation_points=explanation_points,
    )


# ---------------------------------------------------------------------------
# Individual scoring components
# ---------------------------------------------------------------------------
def _score_url(f: URLFeatureResult, risk: List[str], safe: List[str]) -> int:
    points = 0

    if f.url_length > 120:
        points += 10
        risk.append(f"Very long URL ({f.url_length} chars) [+10].")
    elif f.url_length > 75:
        points += 5
        risk.append(f"Long URL ({f.url_length} chars) [+5].")

    if f.contains_ip_address:
        points += 20
        risk.append("URL uses a raw IP address [+20].")

    if f.contains_at_symbol:
        points += 15
        risk.append("URL contains an '@' symbol [+15].")

    if f.contains_punycode:
        points += 15
        risk.append("Hostname uses punycode (possible homoglyph spoofing) [+15].")

    if f.number_of_subdomains > 3:
        points += 10
        risk.append(f"Excessive subdomains ({f.number_of_subdomains}) [+10].")

    if f.suspicious_keywords_found:
        n = len(f.suspicious_keywords_found)
        kw_points = min(15, 5 * n)
        points += kw_points
        risk.append(
            f"Suspicious keyword(s) in URL ({', '.join(f.suspicious_keywords_found)}) [+{kw_points}]."
        )

    if f.is_shortened_url:
        points += 15
        risk.append("URL uses a link shortener (destination hidden) [+15].")

    if not f.uses_https:
        points += 5
        risk.append("URL does not use HTTPS [+5].")
    else:
        safe.append("URL uses HTTPS.")

    if not f.contains_ip_address and not f.contains_at_symbol and not f.contains_punycode:
        safe.append("URL uses a normal domain name (no IP/@/punycode tricks).")

    return points


def _score_html(r: HTMLAnalysisResult, risk: List[str], safe: List[str]) -> int:
    points = 0

    if r.number_of_password_fields > 0:
        points += 25
        risk.append(
            f"Page contains password field(s) ({r.number_of_password_fields}) [+25]."
        )
    else:
        safe.append("No password input fields detected.")

    if r.number_of_forms > 1:
        points += 10
        risk.append(f"Page contains multiple forms ({r.number_of_forms}) [+10].")

    if r.credential_request_detected and r.credential_patterns_found:
        points += 15
        risk.append(
            "Page text requests credentials/sensitive data ("
            + ", ".join(r.credential_patterns_found)
            + ") [+15]."
        )

    # Account verification / payment harvesting language.
    verification_terms = {
        "account verification",
        "verify your account",
        "payment information",
        "card number",
        "credit card",
        "cvv",
    }
    if verification_terms & set(r.credential_patterns_found):
        points += 15
        risk.append("Page uses account-verification / payment language [+15].")

    if r.number_of_external_links >= 20 or r.number_of_script_tags >= 20:
        points += 10
        risk.append("Page has a large number of external links/scripts [+10].")
    elif r.number_of_external_links >= 10 or r.number_of_script_tags >= 10:
        points += 5
        risk.append("Page has many external links/scripts [+5].")

    return points


def _score_injection(r: PromptInjectionResult, risk: List[str]) -> int:
    if not r.injection_detected:
        return 0
    if r.severity == "high":
        risk.append("High-severity prompt-injection content detected [+30].")
        return 30
    risk.append(
        f"Prompt-injection content detected (severity: {r.severity}) [+20]."
    )
    return 20


def _score_rag(evidence: List[RetrievedEvidence], risk: List[str]) -> int:
    if not evidence:
        return 0
    # Count strongly relevant phishing-related evidence (decent similarity).
    strong = [
        e
        for e in evidence
        if e.category in _PHISHING_RAG_CATEGORIES and e.similarity_score >= 0.10
    ]
    if not strong:
        return 0
    points = min(20, 10 + 5 * (len(strong) - 1))
    titles = ", ".join(e.title for e in strong[:3])
    risk.append(
        f"Retrieved knowledge strongly matches phishing indicators ({titles}) [+{points}]."
    )
    return points


# ---------------------------------------------------------------------------
# Classification helpers
# ---------------------------------------------------------------------------
def _classify(score: int) -> str:
    if score >= PHISHING_THRESHOLD:
        return CLASS_PHISHING
    if score >= SUSPICIOUS_THRESHOLD:
        return CLASS_SUSPICIOUS
    return CLASS_BENIGN


def _confidence_label(score: int, risk_factors: List[str]) -> str:
    """A rough confidence proxy based on score extremity and evidence volume."""
    distance = min(score, 100 - score)  # distance from the 50 midpoint mirror
    if len(risk_factors) >= 4 or score >= 80 or score <= 10:
        return "High"
    if len(risk_factors) >= 2 or distance <= 15:
        return "Medium"
    return "Low"


def _build_explanation_points(
    classification: str, score: int, risk_factors: List[str], safe_factors: List[str]
) -> List[str]:
    """Build concise explanation bullet points for the explainer."""
    points = [f"Overall classification: {classification} (risk score {score}/100)."]
    if risk_factors:
        points.append("Key risk factors:")
        points.extend(f"  - {factor}" for factor in risk_factors)
    if safe_factors:
        points.append("Mitigating / safe factors:")
        points.extend(f"  - {factor}" for factor in safe_factors)
    return points
