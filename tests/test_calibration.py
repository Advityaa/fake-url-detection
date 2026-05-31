"""Calibration tests for the false-positive fixes (Issues 2, 3, 4, 7)."""

from src.html_analyzer import HTMLAnalysisResult, check_brand_domain
from src.prompt_injection_detector import PromptInjectionResult
from src.risk_engine import (
    assess_risk,
    build_observed_indicators,
    score_rag_evidence_conditionally,
)
from src.schemas import RetrievedEvidence
from src.url_features import extract_url_features


def _rag(category: str, title: str = "kb") -> RetrievedEvidence:
    return RetrievedEvidence(
        id="x",
        title=title,
        category=category,
        source_type="t",
        trust_level="high",
        content="c",
        similarity_score=0.5,
    )


def test_rag_prompt_injection_not_added_when_none_observed():
    indicators = {"prompt_injection": False}
    points, factors = score_rag_evidence_conditionally(
        [_rag("prompt_injection", "Prompt injection")], indicators
    )
    assert points == 0
    assert factors == []


def test_rag_http_not_added_when_final_https():
    indicators = {"no_https": False}
    points, _ = score_rag_evidence_conditionally([_rag("http_only", "HTTP risk")], indicators)
    assert points == 0


def test_rag_added_only_when_indicator_observed():
    indicators = {"password_field": True}
    points, factors = score_rag_evidence_conditionally(
        [_rag("password_field", "Password field risk")], indicators
    )
    assert points == 5
    assert factors


def test_no_https_penalty_when_final_url_is_https():
    f = extract_url_features("https://shop.example.org/account")
    result = assess_risk(f, HTMLAnalysisResult(), PromptInjectionResult(), [])
    assert not any("HTTPS" in rf for rf in result.risk_factors)
    assert any("HTTPS" in sf for sf in result.safe_factors)


def test_ecommerce_terms_alone_do_not_make_trusted_site_suspicious():
    f = extract_url_features("amazon.com")
    html = HTMLAnalysisResult(
        number_of_external_links=50,
        number_of_script_tags=50,
        credential_request_detected=True,
        credential_patterns_found=["sign in", "payment information", "account"],
        brand_like_words=["amazon"],
    )
    brand = check_brand_domain(["amazon"], "amazon.com")
    result = assess_risk(f, html, PromptInjectionResult(), [], brand_check=brand, is_trusted_domain=True)
    assert result.classification == "Likely Benign"
    assert result.score < 30


def test_many_links_scripts_is_only_weak_signal():
    f = extract_url_features("https://blog.example.org/post")
    html = HTMLAnalysisResult(number_of_external_links=50, number_of_script_tags=50)
    result = assess_risk(f, html, PromptInjectionResult(), [])
    # Many links/scripts alone must never reach the "Needs Caution" threshold.
    assert result.score < 30
    assert result.classification == "Likely Benign"


def test_brand_mismatch_increases_risk():
    f = extract_url_features("http://paypal-login.example.com/verify")
    html = HTMLAnalysisResult(
        number_of_password_fields=1,
        credential_request_detected=True,
        credential_patterns_found=["password", "sign in"],
        brand_like_words=["paypal"],
    )
    brand = check_brand_domain(["paypal"], "example.com")
    result = assess_risk(f, html, PromptInjectionResult(), [], brand_check=brand)
    assert brand.possible_brand_mismatch is True
    assert result.classification == "Likely Phishing"
    assert any("brand" in rf.lower() for rf in result.risk_factors)


def test_thresholds_map_to_ui_labels():
    f = extract_url_features("https://example.com")
    safe = assess_risk(f, HTMLAnalysisResult(), PromptInjectionResult(), [])
    assert safe.ui_label == "Likely Safe"
    assert safe.recommended_action  # non-empty guidance


def test_observed_indicators_gate_account_verification_for_trusted():
    f = extract_url_features("amazon.com")
    html = HTMLAnalysisResult(
        credential_request_detected=True,
        credential_patterns_found=["account verification", "card number"],
    )
    brand = check_brand_domain([], "amazon.com")
    indicators = build_observed_indicators(f, html, PromptInjectionResult(), brand, True)
    # Trusted domain should suppress these as phishing indicators.
    assert indicators["account_verification"] is False
    assert indicators["payment_harvesting"] is False
