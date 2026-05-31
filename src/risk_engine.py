"""Transparent, rule-based risk scoring engine (calibrated to reduce false positives).

Key calibration principles (added after the ``amazon.com`` false positive):

  * The score relies on the **final** URL scheme (HTTPS-first normalization), so a
    legitimate HTTPS site is never penalised for "no HTTPS".
  * **Evidence-conditioned RAG**: retrieved knowledge only adds risk when a
    matching indicator was actually observed on this URL/page.
  * **Common e-commerce terms** (sign in, payment, account, ...) only add
    meaningful risk when combined with other suspicious signals, and are
    suppressed for trusted domains / brand-domain matches.
  * **Many links/scripts** is only a weak signal and never pushes a site into
    "Needs Caution" on its own.
  * **Brand-domain match** reduces risk; **brand mismatch** strongly increases it.
  * A small local **trusted-domain allowlist** mitigates risk (MVP demo signal
    only) but never hides severe risks such as prompt injection or brand mismatch.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from .config import (
    CLASS_BENIGN,
    CLASS_PHISHING,
    CLASS_SUSPICIOUS,
    PHISHING_THRESHOLD,
    SUSPICIOUS_THRESHOLD,
    action_recommendation,
    ui_label,
)
from .schemas import (
    BrandCheckResult,
    HTMLAnalysisResult,
    PromptInjectionResult,
    RetrievedEvidence,
    RiskAssessmentResult,
    URLFeatureResult,
)

# Maps a knowledge-base category to the observed-indicator key that must be
# present for that retrieved knowledge to contribute any risk.
_RAG_CATEGORY_TO_INDICATOR = {
    "url_structure": "suspicious_url_structure",
    "brand_impersonation": "brand_mismatch",
    "brand_mismatch": "brand_mismatch",
    "login_form": "password_field",
    "password_field": "password_field",
    "shortened_url": "shortener",
    "ip_url": "ip_address",
    "punycode": "punycode",
    "http_only": "no_https",
    "social_engineering": "social_engineering",
    "account_verification": "account_verification",
    "payment_harvesting": "payment_harvesting",
    "prompt_injection": "prompt_injection",
    "hidden_text": "hidden_text",
    "redirects": "many_redirects",
}

# Account-verification / payment language used to detect e-commerce-term risk.
_VERIFICATION_TERMS = {
    "account verification",
    "verify your account",
    "confirm your identity",
}
_PAYMENT_TERMS = {
    "payment information",
    "card number",
    "credit card",
    "cvv",
}


def build_observed_indicators(
    url_features: URLFeatureResult,
    html_analysis: HTMLAnalysisResult,
    prompt_injection: PromptInjectionResult,
    brand_check: Optional[BrandCheckResult],
    is_trusted_domain: bool,
    redirect_count: int = 0,
) -> Dict[str, bool]:
    """Derive the set of indicators actually observed for this URL/page.

    These boolean facts are what conditional RAG scoring and e-commerce-term
    scoring are gated on, so the engine never adds risk for something it did not
    actually see.
    """
    brand_match = bool(brand_check and brand_check.brand_domain_match)
    brand_mismatch = bool(brand_check and brand_check.possible_brand_mismatch)
    trust = is_trusted_domain or brand_match

    payment_terms_present = bool(set(html_analysis.credential_patterns_found) & _PAYMENT_TERMS)
    verification_terms_present = bool(
        set(html_analysis.credential_patterns_found) & _VERIFICATION_TERMS
    )

    suspicious_url_structure = (
        url_features.number_of_subdomains > 3
        or url_features.url_length > 120
        or bool(url_features.suspicious_keywords_found)
    )

    indicators = {
        "password_field": html_analysis.number_of_password_fields > 0,
        "shortener": url_features.is_shortened_url,
        "ip_address": url_features.contains_ip_address,
        "punycode": url_features.contains_punycode,
        "at_symbol": url_features.contains_at_symbol,
        "no_https": not url_features.uses_https,
        "suspicious_url_keywords": bool(url_features.suspicious_keywords_found),
        "suspicious_url_structure": suspicious_url_structure,
        "many_subdomains": url_features.number_of_subdomains > 3,
        "brand_match": brand_match,
        "brand_mismatch": brand_mismatch,
        "prompt_injection": prompt_injection.injection_detected,
        "hidden_text": prompt_injection.found_in_hidden,
        "many_redirects": redirect_count > 2,
        # Account-verification / payment language only counts as a phishing
        # indicator when the domain is NOT trusted and brand matches the domain.
        "account_verification": verification_terms_present and not trust,
        "payment_harvesting": payment_terms_present and not trust,
    }

    # "Other suspicious" = any strong/structural signal beyond plain page words.
    other_suspicious = any(
        indicators[k]
        for k in (
            "ip_address",
            "punycode",
            "at_symbol",
            "shortener",
            "no_https",
            "suspicious_url_keywords",
            "many_subdomains",
            "brand_mismatch",
            "prompt_injection",
            "password_field",
        )
    )
    indicators["other_suspicious"] = other_suspicious

    # Social-engineering language only matters alongside another suspicious signal.
    indicators["social_engineering"] = (
        html_analysis.credential_request_detected and other_suspicious and not trust
    )
    indicators["trusted"] = trust
    return indicators


def score_rag_evidence_conditionally(
    retrieved_evidence: List[RetrievedEvidence],
    observed_indicators: Dict[str, bool],
) -> tuple[int, List[str]]:
    """Score retrieved RAG evidence only when it matches an observed indicator.

    Semantic similarity alone never adds risk. A retrieved entry contributes
    points only if its category maps to an indicator that is True for this page.

    Returns:
        ``(points, risk_factor_messages)`` with points capped at +15.
    """
    points = 0
    factors: List[str] = []
    seen_indicators: set[str] = set()

    for ev in retrieved_evidence:
        indicator_key = _RAG_CATEGORY_TO_INDICATOR.get(ev.category)
        if not indicator_key:
            continue
        if not observed_indicators.get(indicator_key, False):
            continue
        if indicator_key in seen_indicators:
            continue  # one contribution per distinct indicator
        seen_indicators.add(indicator_key)
        points += 5
        factors.append(
            f"Retrieved knowledge '{ev.title}' matches an observed indicator "
            f"({indicator_key}) [+5]."
        )

    points = min(points, 15)
    return points, factors


def assess_risk(
    url_features: URLFeatureResult,
    html_analysis: HTMLAnalysisResult,
    prompt_injection: PromptInjectionResult,
    retrieved_evidence: List[RetrievedEvidence],
    brand_check: Optional[BrandCheckResult] = None,
    is_trusted_domain: bool = False,
    redirect_count: int = 0,
) -> RiskAssessmentResult:
    """Compute a transparent 0-100 risk score and classification.

    Returns:
        A ``RiskAssessmentResult`` with score, classification, UI label,
        recommended action, confidence and the lists of factors.
    """
    indicators = build_observed_indicators(
        url_features,
        html_analysis,
        prompt_injection,
        brand_check,
        is_trusted_domain,
        redirect_count,
    )

    score = 0
    risk_factors: List[str] = []
    safe_factors: List[str] = []

    score += _score_url(url_features, risk_factors, safe_factors)
    score += _score_html(html_analysis, indicators, risk_factors, safe_factors)
    score += _score_brand(brand_check, risk_factors, safe_factors)
    score += _score_injection(prompt_injection, risk_factors)

    rag_points, rag_factors = score_rag_evidence_conditionally(retrieved_evidence, indicators)
    score += rag_points
    risk_factors.extend(rag_factors)
    if retrieved_evidence and not rag_factors:
        safe_factors.append(
            "Retrieved security knowledge did not match any observed indicator, "
            "so it did not increase the risk score."
        )

    # Trusted-domain mitigation (applied last, never hides severe risks above).
    if is_trusted_domain:
        score -= 20
        safe_factors.append(
            "Domain appears in the local trusted-domain list used for this MVP demo "
            "(prototype signal only, not a security guarantee)."
        )

    score = max(0, min(100, score))
    classification = _classify(score)
    confidence = _confidence_label(score, risk_factors)

    explanation_points = _build_explanation_points(
        classification, score, risk_factors, safe_factors
    )

    return RiskAssessmentResult(
        score=score,
        classification=classification,
        ui_label=ui_label(classification),
        recommended_action=action_recommendation(classification),
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

    # HTTPS is judged on the final URL scheme (HTTPS-first normalization upstream).
    if not f.uses_https:
        points += 5
        risk.append("Final URL does not use HTTPS [+5].")
    else:
        safe.append("Final URL uses HTTPS.")

    if not f.contains_ip_address and not f.contains_at_symbol and not f.contains_punycode:
        safe.append("URL uses a normal domain name (no IP/@/punycode tricks).")

    return points


def _score_html(
    r: HTMLAnalysisResult, ind: Dict[str, bool], risk: List[str], safe: List[str]
) -> int:
    points = 0
    trusted = ind.get("trusted", False)
    other_suspicious = ind.get("other_suspicious", False)

    # Password field is a strong, direct credential-collection signal.
    if r.number_of_password_fields > 0:
        points += 25
        risk.append(
            f"Page contains password field(s) ({r.number_of_password_fields}) [+25]."
        )
    else:
        safe.append("No password input fields detected.")

    # Multiple forms: minor, and ignored for trusted domains.
    if r.number_of_forms > 1 and not trusted:
        points += 5
        risk.append(f"Page contains multiple forms ({r.number_of_forms}) [+5].")

    # Common e-commerce terms (sign in / account / payment words) WITHOUT a
    # password field: only meaningful when combined with other suspicious signals.
    if r.credential_request_detected and r.number_of_password_fields == 0:
        if trusted:
            safe.append(
                "Login/payment words on the page are common on legitimate sites and "
                "were not treated as phishing on their own (trusted/brand match)."
            )
        elif other_suspicious:
            points += 15
            risk.append(
                "Credential/payment text combined with other suspicious signals [+15]."
            )
        else:
            points += 3
            risk.append(
                "Page mentions login/payment words (weak signal on its own) [+3]."
            )

    # Account-verification / payment-harvesting language (already gated to exclude
    # trusted domains and brand matches inside the indicator builder).
    if (ind.get("account_verification") or ind.get("payment_harvesting")) and other_suspicious:
        points += 15
        risk.append("Account-verification / payment-harvesting language [+15].")

    # Many external links/scripts: weak signal only, suppressed for trusted sites.
    if not trusted and (r.number_of_external_links >= 10 or r.number_of_script_tags >= 10):
        points += 3
        risk.append("Page has many external links/scripts (weak signal) [+3].")

    return points


def _score_brand(
    brand_check: Optional[BrandCheckResult], risk: List[str], safe: List[str]
) -> int:
    if brand_check is None:
        return 0
    if brand_check.brand_domain_match:
        safe.append("Displayed brand appears to match the registered domain.")
        return -20
    if brand_check.possible_brand_mismatch:
        risk.append(
            "Displayed brand does not match the registered domain (possible impersonation) [+25]."
        )
        return 25
    return 0


def _score_injection(r: PromptInjectionResult, risk: List[str]) -> int:
    if not r.injection_detected:
        return 0
    if r.severity == "high":
        risk.append("High-severity hidden-instruction (prompt-injection) content detected [+30].")
        return 30
    risk.append(
        f"Hidden-instruction (prompt-injection) content detected (severity: {r.severity}) [+20]."
    )
    return 20


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
    if len(risk_factors) >= 4 or score >= 75 or score <= 10:
        return "High"
    if len(risk_factors) >= 2 or score >= 45:
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
