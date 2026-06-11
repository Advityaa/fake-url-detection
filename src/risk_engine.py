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

# ---------------------------------------------------------------------------
# Centralized, documented scoring weights (single source of truth).
# Grouped by category so the score is transparent and tunable, and so the UI can
# show a per-category breakdown of where the score came from.
# ---------------------------------------------------------------------------
WEIGHTS: Dict[str, int] = {
    # --- URL structure ---
    "ip_address": 25,            # raw IP host instead of a domain
    "at_symbol": 18,            # "@" can hide the real destination
    "punycode": 22,            # homoglyph / IDN spoofing
    "shortener": 15,           # destination hidden behind a shortener
    "no_https": 8,             # final URL not encrypted
    "many_subdomains": 12,     # padding to look legitimate
    "suspicious_tld": 8,       # TLD frequently abused for phishing
    "host_keyword_each": 9,    # phishy keyword IN the hostname (login/verify/...)
    "host_keyword_cap": 27,    # cap on hostname-keyword points
    "path_keyword_combo": 4,   # path-only keyword, only with other signals
    "url_long": 4,             # > 75 chars
    "url_very_long": 8,        # > 120 chars
    # --- Brand impersonation (very strong phishing signals) ---
    "brand_impersonation_url": 55,  # known brand in host of a non-brand domain
    "lookalike_domain": 55,         # typosquat / leetspeak of a known brand
    "brand_mismatch_page": 25,      # page brand text != registered domain
    "brand_match": -20,             # page brand text matches the domain
    # --- Page content ---
    "password_field": 25,
    "multiple_forms": 5,
    "credential_combo": 15,    # credential text + other suspicious signal
    "credential_weak": 3,      # credential text alone (weak)
    "verification_language": 15,
    "many_links_scripts": 3,
    # --- Hidden instructions (prompt injection) ---
    "injection_high": 35,
    "injection_other": 20,
    # --- Retrieved knowledge (conditional) ---
    "rag_per_indicator": 5,
    "rag_cap": 15,
    # --- Mitigation ---
    "trusted_domain": -25,
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
    # Brand mismatch comes from EITHER page text (brand_check) OR the URL itself
    # (a known brand in the host of a non-brand domain), so impersonation is
    # caught even when the page does not load.
    url_impersonation = bool(url_features.impersonated_brand)
    lookalike = bool(url_features.lookalike_brand)
    page_mismatch = bool(brand_check and brand_check.possible_brand_mismatch)
    brand_mismatch = page_mismatch or url_impersonation or lookalike
    trust = is_trusted_domain or brand_match

    payment_terms_present = bool(set(html_analysis.credential_patterns_found) & _PAYMENT_TERMS)
    verification_terms_present = bool(
        set(html_analysis.credential_patterns_found) & _VERIFICATION_TERMS
    )

    suspicious_url_structure = (
        url_features.number_of_subdomains > 3
        or url_features.url_length > 120
        or bool(url_features.suspicious_keywords_in_host)
        or url_impersonation
        or lookalike
    )

    indicators = {
        "password_field": html_analysis.number_of_password_fields > 0,
        "shortener": url_features.is_shortened_url,
        "ip_address": url_features.contains_ip_address,
        "punycode": url_features.contains_punycode,
        "at_symbol": url_features.contains_at_symbol,
        "no_https": not url_features.uses_https,
        "suspicious_tld": url_features.suspicious_tld,
        "suspicious_url_keywords": bool(url_features.suspicious_keywords_in_host),
        "suspicious_url_structure": suspicious_url_structure,
        "many_subdomains": url_features.number_of_subdomains > 3,
        "brand_match": brand_match,
        "brand_mismatch": brand_mismatch,
        "brand_impersonation_url": url_impersonation,
        "lookalike_domain": lookalike,
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
        points += WEIGHTS["rag_per_indicator"]
        factors.append(
            f"Retrieved knowledge '{ev.title}' matches an observed indicator "
            f"({indicator_key}) [+{WEIGHTS['rag_per_indicator']}]."
        )

    points = min(points, WEIGHTS["rag_cap"])
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

    risk_factors: List[str] = []
    safe_factors: List[str] = []

    url_pts = _score_url(url_features, indicators, risk_factors, safe_factors)
    brand_pts = _score_brand(url_features, brand_check, risk_factors, safe_factors)
    html_pts = _score_html(html_analysis, indicators, risk_factors, safe_factors)
    injection_pts = _score_injection(prompt_injection, risk_factors)

    rag_points, rag_factors = score_rag_evidence_conditionally(retrieved_evidence, indicators)
    risk_factors.extend(rag_factors)
    if retrieved_evidence and not rag_factors:
        safe_factors.append(
            "Retrieved security knowledge did not match any observed indicator, "
            "so it did not increase the risk score."
        )

    # Trusted-domain mitigation (applied last). It is SUPPRESSED when a severe
    # risk is present (brand impersonation/mismatch, lookalike, or prompt
    # injection) so the allowlist can never hide a serious threat.
    severe_risk = any(
        indicators.get(k)
        for k in ("brand_mismatch", "brand_impersonation_url", "lookalike_domain", "prompt_injection")
    )
    trusted_pts = 0
    if is_trusted_domain and not severe_risk:
        trusted_pts = WEIGHTS["trusted_domain"]
        safe_factors.append(
            "Domain appears in the local trusted-domain list used for this MVP demo "
            "(prototype signal only, not a security guarantee)."
        )
    elif is_trusted_domain and severe_risk:
        safe_factors.append(
            "Domain is on the local trusted list, but trusted-domain mitigation was "
            "suppressed because a severe risk (impersonation or hidden instructions) was found."
        )

    breakdown = {
        "URL structure": url_pts,
        "Brand / impersonation": brand_pts,
        "Page content": html_pts,
        "Hidden instructions": injection_pts,
        "Knowledge match": rag_points,
        "Trusted-domain mitigation": trusted_pts,
    }

    raw_score = url_pts + brand_pts + html_pts + injection_pts + rag_points + trusted_pts
    score = max(0, min(100, raw_score))
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
        score_breakdown=breakdown,
    )


# ---------------------------------------------------------------------------
# Individual scoring components
# ---------------------------------------------------------------------------
def _score_url(
    f: URLFeatureResult, ind: Dict[str, bool], risk: List[str], safe: List[str]
) -> int:
    points = 0

    if f.url_length > 120:
        points += WEIGHTS["url_very_long"]
        risk.append(f"Very long URL ({f.url_length} chars) [+{WEIGHTS['url_very_long']}].")
    elif f.url_length > 75:
        points += WEIGHTS["url_long"]
        risk.append(f"Long URL ({f.url_length} chars) [+{WEIGHTS['url_long']}].")

    if f.contains_ip_address:
        points += WEIGHTS["ip_address"]
        risk.append(f"URL uses a raw IP address [+{WEIGHTS['ip_address']}].")

    if f.contains_at_symbol:
        points += WEIGHTS["at_symbol"]
        risk.append(f"URL contains an '@' symbol [+{WEIGHTS['at_symbol']}].")

    if f.contains_punycode:
        points += WEIGHTS["punycode"]
        risk.append(f"Hostname uses punycode (possible homoglyph spoofing) [+{WEIGHTS['punycode']}].")

    if f.number_of_subdomains > 3:
        points += WEIGHTS["many_subdomains"]
        risk.append(f"Excessive subdomains ({f.number_of_subdomains}) [+{WEIGHTS['many_subdomains']}].")

    if f.suspicious_tld:
        points += WEIGHTS["suspicious_tld"]
        risk.append(f"Domain uses a TLD ('.{f.suffix}') often abused for phishing [+{WEIGHTS['suspicious_tld']}].")

    # Phishy keywords in the HOSTNAME are a meaningful signal; keywords only in
    # the PATH are common on legitimate sites and count weakly (and only when
    # other suspicious signals are present).
    if f.suspicious_keywords_in_host:
        n = len(f.suspicious_keywords_in_host)
        kw_points = min(WEIGHTS["host_keyword_cap"], WEIGHTS["host_keyword_each"] * n)
        points += kw_points
        risk.append(
            f"Suspicious keyword(s) in the domain name ({', '.join(f.suspicious_keywords_in_host)}) [+{kw_points}]."
        )
    else:
        path_only = [k for k in f.suspicious_keywords_found if k not in f.suspicious_keywords_in_host]
        if path_only and ind.get("other_suspicious"):
            points += WEIGHTS["path_keyword_combo"]
            risk.append(
                "Login/security keyword in the URL path alongside other suspicious "
                f"signals ({', '.join(path_only)}) [+{WEIGHTS['path_keyword_combo']}]."
            )

    if f.is_shortened_url:
        points += WEIGHTS["shortener"]
        risk.append(f"URL uses a link shortener (destination hidden) [+{WEIGHTS['shortener']}].")

    # HTTPS is judged on the final URL scheme (HTTPS-first normalization upstream).
    if not f.uses_https:
        points += WEIGHTS["no_https"]
        risk.append(f"Final URL does not use HTTPS [+{WEIGHTS['no_https']}].")
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
        points += WEIGHTS["password_field"]
        risk.append(
            f"Page contains password field(s) ({r.number_of_password_fields}) [+{WEIGHTS['password_field']}]."
        )
    else:
        safe.append("No password input fields detected.")

    # Multiple forms: minor, and ignored for trusted domains.
    if r.number_of_forms > 1 and not trusted:
        points += WEIGHTS["multiple_forms"]
        risk.append(f"Page contains multiple forms ({r.number_of_forms}) [+{WEIGHTS['multiple_forms']}].")

    # Common e-commerce terms (sign in / account / payment words) WITHOUT a
    # password field: only meaningful when combined with other suspicious signals.
    if r.credential_request_detected and r.number_of_password_fields == 0:
        if trusted:
            safe.append(
                "Login/payment words on the page are common on legitimate sites and "
                "were not treated as phishing on their own (trusted/brand match)."
            )
        elif other_suspicious:
            points += WEIGHTS["credential_combo"]
            risk.append(
                f"Credential/payment text combined with other suspicious signals [+{WEIGHTS['credential_combo']}]."
            )
        else:
            points += WEIGHTS["credential_weak"]
            risk.append(
                f"Page mentions login/payment words (weak signal on its own) [+{WEIGHTS['credential_weak']}]."
            )

    # Account-verification / payment-harvesting language (already gated to exclude
    # trusted domains and brand matches inside the indicator builder).
    if (ind.get("account_verification") or ind.get("payment_harvesting")) and other_suspicious:
        points += WEIGHTS["verification_language"]
        risk.append(f"Account-verification / payment-harvesting language [+{WEIGHTS['verification_language']}].")

    # Many external links/scripts: weak signal only, suppressed for trusted sites.
    if not trusted and (r.number_of_external_links >= 10 or r.number_of_script_tags >= 10):
        points += WEIGHTS["many_links_scripts"]
        risk.append(f"Page has many external links/scripts (weak signal) [+{WEIGHTS['many_links_scripts']}].")

    return points


def _score_brand(
    f: URLFeatureResult,
    brand_check: Optional[BrandCheckResult],
    risk: List[str],
    safe: List[str],
) -> int:
    """Score brand impersonation from the URL (strong) and page text.

    URL-based impersonation/lookalike are decisive and take precedence: if the
    registered domain is not the brand's, a page "brand match" cannot apply.
    """
    if f.impersonated_brand:
        risk.append(
            f"URL references the brand '{f.impersonated_brand}' but is not hosted on its "
            f"official domain (registered: '{f.registered_domain}') [+{WEIGHTS['brand_impersonation_url']}]."
        )
        return WEIGHTS["brand_impersonation_url"]

    if f.lookalike_brand:
        risk.append(
            f"Domain is a lookalike/typosquat of '{f.lookalike_brand}' [+{WEIGHTS['lookalike_domain']}]."
        )
        return WEIGHTS["lookalike_domain"]

    if brand_check is None:
        return 0
    if brand_check.brand_domain_match:
        safe.append("Displayed brand appears to match the registered domain.")
        return WEIGHTS["brand_match"]
    if brand_check.possible_brand_mismatch:
        risk.append(
            f"Displayed brand does not match the registered domain (possible impersonation) [+{WEIGHTS['brand_mismatch_page']}]."
        )
        return WEIGHTS["brand_mismatch_page"]
    return 0


def _score_injection(r: PromptInjectionResult, risk: List[str]) -> int:
    if not r.injection_detected:
        return 0
    if r.severity == "high":
        risk.append(f"High-severity hidden-instruction (prompt-injection) content detected [+{WEIGHTS['injection_high']}].")
        return WEIGHTS["injection_high"]
    risk.append(
        f"Hidden-instruction (prompt-injection) content detected (severity: {r.severity}) [+{WEIGHTS['injection_other']}]."
    )
    return WEIGHTS["injection_other"]


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
