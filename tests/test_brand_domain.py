"""Unit tests for brand-domain matching (Issue 5)."""

from src.html_analyzer import check_brand_domain


def test_amazon_brand_matches_domain():
    result = check_brand_domain(["amazon"], "amazon.com")
    assert result.brand_domain_match is True
    assert result.possible_brand_mismatch is False
    assert any("match" in m.lower() for m in result.evidence_messages)


def test_paypal_brand_mismatches_unrelated_domain():
    result = check_brand_domain(["paypal"], "example.com")
    assert result.possible_brand_mismatch is True
    assert result.brand_domain_match is False
    assert any("does not match" in m.lower() for m in result.evidence_messages)


def test_microsoft_mismatch_on_lookalike_domain():
    result = check_brand_domain(["microsoft"], "verify-account.example.net")
    assert result.possible_brand_mismatch is True
    assert result.brand_domain_match is False


def test_no_brands_detected_is_neutral():
    result = check_brand_domain([], "example.com")
    assert result.brand_domain_match is False
    assert result.possible_brand_mismatch is False
