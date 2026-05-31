"""Unit tests for the local trusted-domain allowlist and its mitigation."""

from src.config import load_trusted_domains
from src.html_analyzer import HTMLAnalysisResult, check_brand_domain
from src.prompt_injection_detector import PromptInjectionResult
from src.risk_engine import assess_risk
from src.url_features import extract_url_features


def test_allowlist_loads_expected_domains():
    domains = load_trusted_domains()
    assert "amazon.com" in domains
    assert "example.com" in domains


def test_trusted_domain_mitigation_lowers_score():
    f = extract_url_features("amazon.com")
    html = HTMLAnalysisResult(page_title="Amazon")
    untrusted = assess_risk(f, html, PromptInjectionResult(), [], is_trusted_domain=False)
    trusted = assess_risk(f, html, PromptInjectionResult(), [], is_trusted_domain=True)
    assert trusted.score < untrusted.score or trusted.score == 0
    assert any("trusted-domain list" in s.lower() for s in trusted.safe_factors)


def test_trusted_domain_does_not_hide_prompt_injection():
    f = extract_url_features("amazon.com")
    html = HTMLAnalysisResult()
    pi = PromptInjectionResult(
        injection_detected=True,
        matched_patterns=["ignore previous instructions"],
        severity="high",
        found_in_hidden=True,
    )
    result = assess_risk(f, html, pi, [], is_trusted_domain=True)
    # Severe risk must still surface despite the allowlist mitigation.
    assert any("prompt-injection" in rf.lower() for rf in result.risk_factors)


def test_unknown_domain_gets_no_trusted_mitigation():
    f = extract_url_features("secure-login.example-bank.test")
    html = HTMLAnalysisResult()
    result = assess_risk(f, html, PromptInjectionResult(), [], is_trusted_domain=False)
    assert not any("trusted-domain list" in s.lower() for s in result.safe_factors)


def test_amazon_overall_likely_safe():
    """amazon.com with a brand match + trusted allowlist should be Likely Safe."""
    f = extract_url_features("amazon.com")  # https-first -> uses_https True
    html = HTMLAnalysisResult(
        page_title="Amazon.com. Spend less. Smile more.",
        number_of_forms=1,
        number_of_password_fields=0,
        number_of_external_links=40,
        number_of_script_tags=30,
        credential_request_detected=True,
        credential_patterns_found=["sign in", "account"],
        brand_like_words=["amazon"],
    )
    brand = check_brand_domain(["amazon"], "amazon.com")
    result = assess_risk(f, html, PromptInjectionResult(), [], brand_check=brand, is_trusted_domain=True)
    assert result.score < 30
    assert result.classification == "Likely Benign"
    assert result.ui_label == "Likely Safe"
