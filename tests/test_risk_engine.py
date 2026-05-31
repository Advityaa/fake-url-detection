"""Unit tests for the rule-based risk engine."""

from src.config import CLASS_BENIGN, CLASS_PHISHING
from src.html_analyzer import HTMLAnalysisResult
from src.prompt_injection_detector import PromptInjectionResult
from src.risk_engine import assess_risk
from src.schemas import URLFeatureResult


def _benign_url_features() -> URLFeatureResult:
    return URLFeatureResult(
        original_url="https://example.com",
        normalized_url="https://example.com",
        scheme="https",
        hostname="example.com",
        domain="example",
        suffix="com",
        path="",
        query="",
        url_length=19,
        hostname_length=11,
        number_of_dots=1,
        number_of_hyphens=0,
        number_of_digits=0,
        number_of_subdomains=0,
        contains_ip_address=False,
        contains_at_symbol=False,
        contains_punycode=False,
        uses_https=True,
        suspicious_keywords_found=[],
        is_shortened_url=False,
        entropy_score=3.0,
    )


def _malicious_url_features() -> URLFeatureResult:
    return URLFeatureResult(
        original_url="http://192.168.1.10/login@evil",
        normalized_url="http://192.168.1.10/login@evil",
        scheme="http",
        hostname="192.168.1.10",
        domain="",
        suffix="",
        path="/login@evil",
        query="",
        url_length=30,
        hostname_length=12,
        number_of_dots=3,
        number_of_hyphens=0,
        number_of_digits=8,
        number_of_subdomains=0,
        contains_ip_address=True,
        contains_at_symbol=True,
        contains_punycode=False,
        uses_https=False,
        suspicious_keywords_found=["login"],
        is_shortened_url=False,
        entropy_score=3.0,
    )


def test_benign_scores_low_and_classifies_benign():
    result = assess_risk(
        _benign_url_features(),
        HTMLAnalysisResult(page_title="Maple Town Library"),
        PromptInjectionResult(),
        [],
    )
    assert result.score < 40
    assert result.classification == CLASS_BENIGN
    assert result.safe_factors  # HTTPS / no password etc.


def test_phishing_combination_scores_high():
    html = HTMLAnalysisResult(
        page_title="Verify your account",
        number_of_forms=2,
        number_of_password_fields=1,
        number_of_input_fields=5,
        credential_request_detected=True,
        credential_patterns_found=["password", "account verification", "card number"],
    )
    pi = PromptInjectionResult(
        injection_detected=True,
        matched_patterns=["ignore previous instructions"],
        severity="high",
    )
    result = assess_risk(_malicious_url_features(), html, pi, [])
    assert result.score >= 70
    assert result.classification == CLASS_PHISHING
    assert len(result.risk_factors) >= 4


def test_score_is_capped_at_100():
    html = HTMLAnalysisResult(
        number_of_forms=5,
        number_of_password_fields=3,
        number_of_external_links=50,
        number_of_script_tags=50,
        credential_request_detected=True,
        credential_patterns_found=["password", "card number", "cvv"],
    )
    pi = PromptInjectionResult(injection_detected=True, severity="high")
    result = assess_risk(_malicious_url_features(), html, pi, [])
    assert result.score <= 100


def test_password_field_adds_risk_factor():
    html = HTMLAnalysisResult(number_of_password_fields=1)
    result = assess_risk(_benign_url_features(), html, PromptInjectionResult(), [])
    assert any("password" in f.lower() for f in result.risk_factors)
