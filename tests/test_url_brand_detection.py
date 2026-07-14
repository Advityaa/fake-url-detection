"""Tests for offline brand-impersonation / lookalike / TLD detection and the
recalibrated scoring (false-negative and false-positive coverage)."""

from src.html_analyzer import HTMLAnalysisResult, check_brand_domain
from src.prompt_injection_detector import PromptInjectionResult
from src.risk_engine import assess_risk
from src.url_features import (
    detect_brand_impersonation,
    detect_lookalike_brand,
    extract_url_features,
)


# ---------------------------------------------------------------------------
# Brand-in-URL impersonation
# ---------------------------------------------------------------------------
def test_brand_in_subdomain_is_impersonation():
    f = extract_url_features("http://paypal.secure-login.attacker.net/account")
    assert f.impersonated_brand == "paypal"


def test_brand_glued_to_affix_is_impersonation():
    assert detect_brand_impersonation("paypalsecure.com", "paypalsecure.com") == "paypal"
    assert detect_brand_impersonation("applesupport.io", "applesupport.io") == "apple"


def test_legit_brand_domain_is_not_impersonation():
    assert detect_brand_impersonation("www.paypal.com", "paypal.com") == ""
    assert detect_brand_impersonation("accounts.google.com", "google.com") == ""
    # Regression (found by the evaluation harness): office365.com is Microsoft's
    # own domain and must not be flagged as impersonating "office365".
    assert detect_brand_impersonation("office365.com", "office365.com") == ""


def test_unrelated_word_containing_brand_is_not_impersonation():
    # "applebees" contains "apple" but is not impersonation.
    assert detect_brand_impersonation("www.applebees.com", "applebees.com") == ""


# ---------------------------------------------------------------------------
# Lookalike / typosquat
# ---------------------------------------------------------------------------
def test_leetspeak_lookalike():
    assert detect_lookalike_brand("paypa1.com") == "paypal"
    assert detect_lookalike_brand("g00gle.com") == "google"
    assert detect_lookalike_brand("amaz0n.net") == "amazon"


def test_edit_distance_lookalike_on_long_brand():
    assert detect_lookalike_brand("paypol.com") == "paypal"


def test_short_common_word_is_not_lookalike():
    # "ample" is edit-distance 1 from "apple" but must NOT flag (short brand).
    assert detect_lookalike_brand("ample.com") == ""


# ---------------------------------------------------------------------------
# Suspicious TLD
# ---------------------------------------------------------------------------
def test_suspicious_tld_flagged():
    assert extract_url_features("https://free-prize.tk").suspicious_tld is True
    assert extract_url_features("https://example.com").suspicious_tld is False


# ---------------------------------------------------------------------------
# Host vs path keywords (false-positive control)
# ---------------------------------------------------------------------------
def test_path_only_keyword_does_not_penalize_clean_https_site():
    f = extract_url_features("https://github.com/login")
    assert f.suspicious_keywords_in_host == []
    result = assess_risk(f, HTMLAnalysisResult(), PromptInjectionResult(), [])
    assert result.classification == "Likely Benign"
    assert result.score < 30


def test_hostname_keyword_is_penalized():
    f = extract_url_features("https://secure-login-verify.example-host.org")
    assert f.suspicious_keywords_in_host  # secure / login / verify in host
    result = assess_risk(f, HTMLAnalysisResult(), PromptInjectionResult(), [])
    assert result.score > 0


# ---------------------------------------------------------------------------
# End-to-end scoring outcomes
# ---------------------------------------------------------------------------
def test_url_only_impersonation_reaches_high_with_corroboration():
    # http (no HTTPS) + brand-in-url => High Risk even with no page content.
    f = extract_url_features("http://paypal-login.attacker-host.com/verify")
    result = assess_risk(f, HTMLAnalysisResult(), PromptInjectionResult(), [])
    assert result.classification == "Likely Phishing"


def test_lookalike_alone_at_least_needs_caution():
    f = extract_url_features("https://paypa1.com")
    result = assess_risk(f, HTMLAnalysisResult(), PromptInjectionResult(), [])
    assert result.score >= 30  # at least "Needs Caution"


def test_score_breakdown_is_populated():
    f = extract_url_features("http://paypal-login.attacker-host.com/verify")
    result = assess_risk(f, HTMLAnalysisResult(), PromptInjectionResult(), [])
    assert "Brand / impersonation" in result.score_breakdown
    assert result.score_breakdown["Brand / impersonation"] > 0
    assert sum(result.score_breakdown.values()) >= 0


def test_trusted_mitigation_suppressed_by_impersonation():
    # A trusted placeholder domain hosting brand impersonation must NOT be
    # mitigated down to safe.
    f = extract_url_features("http://paypal.login.example.net/account")
    brand = check_brand_domain([], f.registered_domain)
    result = assess_risk(
        f, HTMLAnalysisResult(), PromptInjectionResult(), [],
        brand_check=brand, is_trusted_domain=True,
    )
    assert result.classification != "Likely Benign"
