"""Unit tests for URL normalization and feature extraction."""

from src.url_features import extract_url_features, normalize_url


def test_normalize_is_https_first_and_lowercases_host():
    # Bare domains should be normalized to HTTPS first (Issue 1).
    assert normalize_url("Example.COM/Path") == "https://example.com/Path"
    assert normalize_url("amazon.com") == "https://amazon.com"
    # An explicit scheme is preserved.
    assert normalize_url("  https://Example.com  ") == "https://example.com"
    assert normalize_url("http://example.com") == "http://example.com"


def test_https_first_features_for_bare_domain():
    f = extract_url_features("amazon.com")
    assert f.scheme == "https"
    assert f.uses_https is True


def test_basic_https_features():
    f = extract_url_features("https://example.com")
    assert f.scheme == "https"
    assert f.uses_https is True
    assert f.hostname == "example.com"
    assert f.domain == "example"
    assert f.suffix == "com"
    assert f.contains_ip_address is False
    assert f.contains_at_symbol is False
    assert f.contains_punycode is False


def test_detects_ip_address_url():
    f = extract_url_features("http://192.168.1.10/login")
    assert f.contains_ip_address is True
    assert f.uses_https is False
    assert "login" in f.suspicious_keywords_found


def test_detects_at_symbol():
    f = extract_url_features("http://example.com@evil.example.net/")
    assert f.contains_at_symbol is True


def test_detects_punycode():
    f = extract_url_features("https://xn--example-demo.com/login")
    assert f.contains_punycode is True


def test_detects_shortener():
    f = extract_url_features("https://bit.ly/fake-demo")
    assert f.is_shortened_url is True


def test_suspicious_keywords_found():
    f = extract_url_features(
        "http://secure-login-verification.example.net/account/update"
    )
    # Note: the URL contains "verification" (not the literal token "verify"),
    # so only literal substring matches are expected here.
    for kw in ["secure", "login", "account", "update"]:
        assert kw in f.suspicious_keywords_found
    assert f.number_of_hyphens >= 2


def test_subdomain_count():
    f = extract_url_features("https://a.b.c.d.example.com/")
    assert f.number_of_subdomains == 4


def test_entropy_is_non_negative():
    f = extract_url_features("https://example.com")
    assert f.entropy_score >= 0.0


def test_evidence_messages_present():
    f = extract_url_features("http://192.168.1.10/login")
    assert any("IP address" in m for m in f.evidence_messages)
