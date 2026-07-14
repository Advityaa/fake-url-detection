"""Tests for the domain-reputation module (WHOIS / DNS / TLS) and its
risk-engine integration.

All lookups are MOCKED via the injectable callables on ``DomainIntelClient`` —
no test ever performs a real WHOIS, DNS, or TLS network call.
"""

import time
from datetime import datetime, timedelta, timezone

from src.domain_intel import (
    CONFLICT_BRAND_DOMAIN_MISMATCH,
    CONFLICT_FREE_EMAIL_AND_NEW_DOMAIN,
    CONFLICT_FREE_EMAIL_REGISTRANT,
    CONFLICT_GEO_REGISTRANT_MISMATCH,
    CONFLICT_IMPERSONATION_WEAK_CERT,
    CONFLICT_VERY_NEW_DOMAIN,
    DomainIntelClient,
    compute_conflicts,
)
from src.html_analyzer import HTMLAnalysisResult
from src.prompt_injection_detector import PromptInjectionResult
from src.risk_engine import assess_risk
from src.schemas import DomainIntelResult
from src.url_features import extract_url_features


def _days_ago(days: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days)


def _dns_ok(domain, timeout):
    return (True, True)


def _dns_no_mx(domain, timeout):
    return (True, False)


def _dns_no_resolve(domain, timeout):
    return (False, False)


def _tls_valid(hostname, timeout):
    return {
        "issuer": "Test CA Org",
        "valid_from": "Jan 1 00:00:00 2026 GMT",
        "valid_until": "Jan 1 00:00:00 2027 GMT",
        "valid": True,
        "self_signed": False,
    }


def _tls_self_signed(hostname, timeout):
    return {"issuer": "", "valid_from": "", "valid_until": "", "valid": False, "self_signed": True}


def _client(**kwargs) -> DomainIntelClient:
    kwargs.setdefault("timeout", 1)
    kwargs.setdefault("new_age_days", 30)
    kwargs.setdefault("enabled", True)
    kwargs.setdefault("whois_fn", lambda d: _days_ago(2000))
    kwargs.setdefault("dns_fn", _dns_ok)
    kwargs.setdefault("tls_fn", _tls_valid)
    return DomainIntelClient(**kwargs)


# ---------------------------------------------------------------------------
# WHOIS age
# ---------------------------------------------------------------------------
def test_new_domain_flagged():
    c = _client(whois_fn=lambda d: _days_ago(5))
    r = c.gather("https://fresh-site.test/", "fresh-site.test")
    assert r.whois_available is True
    assert r.domain_age_days == 5
    assert r.is_newly_registered is True
    assert any("registered only" in m for m in r.evidence_messages)


def test_old_domain_not_flagged():
    c = _client(whois_fn=lambda d: _days_ago(2000))
    r = c.gather("https://old-site.test/", "old-site.test")
    assert r.is_newly_registered is False
    assert r.domain_age_days == 2000


def test_naive_and_aware_creation_dates_both_work():
    naive = datetime.now() - timedelta(days=10)
    c = _client(whois_fn=lambda d: naive)
    r = c.gather("https://x.test/", "x.test")
    assert r.whois_available is True
    assert r.domain_age_days in (9, 10)  # tolerate clock-edge rounding


def test_whois_failure_marks_unavailable():
    def boom(domain):
        raise RuntimeError("registry refused")

    c = _client(whois_fn=boom)
    r = c.gather("https://x.test/", "x.test")
    assert r.whois_available is False
    assert r.domain_age_days is None
    assert any("not available" in m.lower() for m in r.evidence_messages)
    # Other sources still gathered.
    assert r.dns_available is True


def test_whois_hang_times_out_cleanly():
    def hang(domain):
        time.sleep(1.0)
        return _days_ago(5)

    c = _client(timeout=0.1, whois_fn=hang)
    r = c.gather("https://slow.test/", "slow.test")
    assert r.whois_available is False
    assert r.checked is True


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------
def test_no_mx_recorded():
    c = _client(dns_fn=_dns_no_mx)
    r = c.gather("https://nomail.test/", "nomail.test")
    assert r.dns_available is True
    assert r.resolves is True
    assert r.has_mx is False
    assert any("no MX" in m for m in r.evidence_messages)


def test_non_resolving_domain():
    c = _client(dns_fn=_dns_no_resolve)
    r = c.gather("https://ghost.test/", "ghost.test")
    assert r.resolves is False
    assert any("does not resolve" in m for m in r.evidence_messages)


def test_dns_failure_marks_unavailable():
    def boom(domain, timeout):
        raise RuntimeError("no nameservers")

    c = _client(dns_fn=boom)
    r = c.gather("https://x.test/", "x.test")
    assert r.dns_available is False


# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------
def test_valid_cert_recorded():
    c = _client(tls_fn=_tls_valid)
    r = c.gather("https://secure.test/", "secure.test")
    assert r.tls_available is True
    assert r.cert_currently_valid is True
    assert r.cert_issuer == "Test CA Org"


def test_self_signed_cert_recorded():
    c = _client(tls_fn=_tls_self_signed)
    r = c.gather("https://selfsigned.test/", "selfsigned.test")
    assert r.cert_currently_valid is False
    assert r.cert_self_signed is True
    assert any("self-signed" in m for m in r.evidence_messages)


def test_tls_skipped_for_http_urls():
    calls = {"n": 0}

    def counting_tls(hostname, timeout):
        calls["n"] += 1
        return _tls_valid(hostname, timeout)

    c = _client(tls_fn=counting_tls)
    r = c.gather("http://plain.test/", "plain.test")
    assert calls["n"] == 0
    assert r.tls_available is False


def test_disabled_short_circuits():
    c = _client(enabled=False)
    r = c.gather("https://x.test/", "x.test")
    assert r.checked is False
    assert r.whois_available is False


# ---------------------------------------------------------------------------
# Risk-engine integration
# ---------------------------------------------------------------------------
def _features(url="https://some-unknown-site.example.org/"):
    return extract_url_features(url)


def _assess(domain_intel, is_trusted=False, features=None):
    return assess_risk(
        features or _features(),
        HTMLAnalysisResult(),
        PromptInjectionResult(),
        [],
        is_trusted_domain=is_trusted,
        domain_intel=domain_intel,
    )


def test_new_domain_increases_risk():
    d = DomainIntelResult(
        checked=True, whois_available=True, domain_age_days=3, is_newly_registered=True
    )
    result = _assess(d)
    assert result.score_breakdown["Domain reputation"] == 25
    assert any("registered only" in f for f in result.risk_factors)


def test_invalid_cert_increases_risk():
    d = DomainIntelResult(
        checked=True, tls_available=True, cert_currently_valid=False, cert_self_signed=True
    )
    result = _assess(d)
    assert result.score_breakdown["Domain reputation"] == 20
    assert any("self-signed" in f for f in result.risk_factors)


def test_established_domain_with_valid_cert_mitigates():
    d = DomainIntelResult(
        checked=True,
        whois_available=True,
        domain_age_days=4000,
        is_newly_registered=False,
        tls_available=True,
        cert_currently_valid=True,
    )
    result = _assess(d)
    assert result.score_breakdown["Domain reputation"] == -10
    assert any("well established" in s for s in result.safe_factors)


def test_trusted_domain_suppresses_penalties():
    d = DomainIntelResult(
        checked=True,
        whois_available=True,
        domain_age_days=3,
        is_newly_registered=True,
        tls_available=True,
        cert_currently_valid=False,
        cert_self_signed=False,
    )
    result = _assess(d, is_trusted=True)
    assert result.score_breakdown["Domain reputation"] == 0
    assert result.classification == "Likely Benign"


def test_unchecked_domain_intel_adds_nothing():
    result = _assess(DomainIntelResult())
    assert result.score_breakdown["Domain reputation"] == 0


def test_none_domain_intel_is_backwards_compatible():
    result = _assess(None)
    assert result.score_breakdown["Domain reputation"] == 0


def test_no_mx_only_counts_with_other_suspicion():
    d = DomainIntelResult(checked=True, dns_available=True, resolves=True, has_mx=False)
    # Clean HTTPS URL, no other signals -> no points for missing MX.
    clean = _assess(d)
    assert clean.score_breakdown["Domain reputation"] == 0
    # HTTP + keyword-in-host URL (other_suspicious) -> +5.
    feats = _features("http://login-verify.suspicious-host.org/")
    combo = _assess(d, features=feats)
    assert combo.score_breakdown["Domain reputation"] == 5


# ---------------------------------------------------------------------------
# Pipeline integration (injected client -> no network)
# ---------------------------------------------------------------------------
def test_pipeline_includes_domain_intel():
    from src.pipeline import analyze_url
    from src.rag_retriever import RAGRetriever

    client = _client(whois_fn=lambda d: _days_ago(4))
    result = analyze_url(
        "https://brand-new-shop.example-host.test/checkout",
        "phishing",  # sample mode: no crawl, but injected client still runs
        retriever=RAGRetriever(),
        trusted_domains=[],
        domain_client=client,
    )
    assert result is not None
    assert result.domain_intel is not None
    assert result.domain_intel.is_newly_registered is True
    d = result.to_dict()
    assert d["domain_intel"]["whois_available"] is True
    assert "Domain reputation" in d["risk_assessment"]["score_breakdown"]


def test_pipeline_sample_mode_skips_domain_intel_by_default():
    from src.pipeline import analyze_url
    from src.rag_retriever import RAGRetriever

    result = analyze_url(
        "https://maple-town-library.example.org/",
        "benign",
        retriever=RAGRetriever(),
        trusted_domains=[],
    )
    assert result is not None
    assert result.domain_intel is not None
    assert result.domain_intel.checked is False  # no live lookups in sample demos


# ---------------------------------------------------------------------------
# Conflict layer — pure logic on fixed inputs (the novel contribution)
# ---------------------------------------------------------------------------
def _result(**kwargs) -> DomainIntelResult:
    kwargs.setdefault("checked", True)
    kwargs.setdefault("domain", "evil-shop.example")
    return DomainIntelResult(**kwargs)


def test_conflict_brand_domain_mismatch():
    r = _result(domain="secure-login.example")
    conflicts = compute_conflicts(r, page_brands=["paypal"])
    assert CONFLICT_BRAND_DOMAIN_MISMATCH in conflicts


def test_conflict_no_brand_mismatch_on_own_domain():
    r = _result(domain="paypal.com")
    assert CONFLICT_BRAND_DOMAIN_MISMATCH not in compute_conflicts(r, page_brands=["paypal"])


def test_conflict_no_brand_mismatch_for_unknown_word():
    r = _result(domain="shop.example")
    assert compute_conflicts(r, page_brands=["bakery"]) == []


def test_conflict_free_email_registrant():
    r = _result(whois_available=True, registrant_email="admin@gmail.com")
    assert CONFLICT_FREE_EMAIL_REGISTRANT in compute_conflicts(r, [])


def test_conflict_free_email_ignores_corporate_email():
    r = _result(whois_available=True, registrant_email="admin@paypal.com")
    assert CONFLICT_FREE_EMAIL_REGISTRANT not in compute_conflicts(r, [])


def test_conflict_very_new_and_combo():
    r = _result(
        whois_available=True, is_newly_registered=True, registrant_email="x@gmail.com"
    )
    conflicts = compute_conflicts(r, [])
    assert CONFLICT_VERY_NEW_DOMAIN in conflicts
    assert CONFLICT_FREE_EMAIL_REGISTRANT in conflicts
    assert CONFLICT_FREE_EMAIL_AND_NEW_DOMAIN in conflicts


def test_conflict_impersonation_weak_cert():
    r = _result(domain="secure-login.example", tls_available=True, cert_self_signed=True)
    assert CONFLICT_IMPERSONATION_WEAK_CERT in compute_conflicts(r, page_brands=["paypal"])


def test_conflict_no_weak_cert_when_cert_strong():
    # Brand mismatch but the cert has an org and verifies -> no weak-cert conflict.
    r = _result(domain="secure-login.example", tls_available=True,
                cert_currently_valid=True, cert_org="Secure Login LLC")
    conflicts = compute_conflicts(r, page_brands=["paypal"])
    assert CONFLICT_BRAND_DOMAIN_MISMATCH in conflicts
    assert CONFLICT_IMPERSONATION_WEAK_CERT not in conflicts


def test_conflict_weak_cert_requires_tls_observed():
    # No TLS inspected -> cannot claim a weak cert (evidence-conditioned).
    r = _result(domain="secure-login.example", tls_available=False)
    assert CONFLICT_IMPERSONATION_WEAK_CERT not in compute_conflicts(r, page_brands=["paypal"])


def test_conflict_geo_mismatch():
    r = _result(asn_available=True, ip_country="RU", registrant_country="US")
    assert CONFLICT_GEO_REGISTRANT_MISMATCH in compute_conflicts(r, [])


def test_conflict_no_geo_mismatch_when_same_country():
    r = _result(asn_available=True, ip_country="US", registrant_country="US")
    assert CONFLICT_GEO_REGISTRANT_MISMATCH not in compute_conflicts(r, [])


# ---------------------------------------------------------------------------
# Conflict layer — WHOIS richness + gather() integration (mocked)
# ---------------------------------------------------------------------------
def test_gather_extracts_registrar_and_registrant_and_conflicts():
    def whois_rich(domain):
        return {
            "creation_date": _days_ago(10),
            "registrar": "NameCheap",
            "country": "US",
            "email": "admin@gmail.com",
        }

    c = _client(whois_fn=whois_rich, tls_fn=_tls_self_signed)
    r = c.gather("https://paypal-verify.evil.example/", "paypal-verify.evil.example",
                 page_brands=["paypal"])
    assert r.registrar == "NameCheap"
    assert r.registrant_email == "admin@gmail.com"
    assert r.registrant_country == "US"
    # brand mismatch + free-email + new domain + combo + impersonation-weak-cert
    assert CONFLICT_BRAND_DOMAIN_MISMATCH in r.conflicts
    assert CONFLICT_FREE_EMAIL_AND_NEW_DOMAIN in r.conflicts
    assert CONFLICT_IMPERSONATION_WEAK_CERT in r.conflicts
    assert r.conflict_count == len(r.conflicts)
    assert any("conflict" in m.lower() for m in r.evidence_messages)


# ---------------------------------------------------------------------------
# Conflict layer — risk-engine scoring (dedup, geo-low, trusted, cap)
# ---------------------------------------------------------------------------
def test_score_free_email_and_new_domain_combo():
    d = _result(conflicts=[CONFLICT_FREE_EMAIL_REGISTRANT, CONFLICT_VERY_NEW_DOMAIN,
                           CONFLICT_FREE_EMAIL_AND_NEW_DOMAIN], conflict_count=3)
    result = _assess(d)
    assert result.score_breakdown["Cross-signal conflicts"] == 25


def test_score_impersonation_weak_cert():
    d = _result(conflicts=[CONFLICT_BRAND_DOMAIN_MISMATCH, CONFLICT_IMPERSONATION_WEAK_CERT],
                conflict_count=2)
    result = _assess(d)
    assert result.score_breakdown["Cross-signal conflicts"] == 15


def test_score_free_email_alone():
    d = _result(conflicts=[CONFLICT_FREE_EMAIL_REGISTRANT], conflict_count=1)
    assert _assess(d).score_breakdown["Cross-signal conflicts"] == 8


def test_score_geo_is_low_and_not_flagged_alone():
    d = _result(conflicts=[CONFLICT_GEO_REGISTRANT_MISMATCH], conflict_count=1)
    result = _assess(d)
    assert result.score_breakdown["Cross-signal conflicts"] == 3
    assert result.classification == "Likely Benign"  # geo alone never flags


def test_score_already_counted_conflicts_score_zero():
    # brand mismatch + very-new-domain are counted for explainability but scored
    # 0 in the conflict category (already handled by other categories).
    d = _result(conflicts=[CONFLICT_BRAND_DOMAIN_MISMATCH, CONFLICT_VERY_NEW_DOMAIN],
                conflict_count=2)
    assert _assess(d).score_breakdown["Cross-signal conflicts"] == 0


def test_score_conflicts_suppressed_for_trusted_domain():
    d = _result(conflicts=[CONFLICT_FREE_EMAIL_AND_NEW_DOMAIN,
                           CONFLICT_GEO_REGISTRANT_MISMATCH], conflict_count=2)
    result = _assess(d, is_trusted=True)
    assert result.score_breakdown["Cross-signal conflicts"] == 0


def test_score_conflicts_capped():
    d = _result(
        conflicts=[
            CONFLICT_FREE_EMAIL_AND_NEW_DOMAIN,
            CONFLICT_IMPERSONATION_WEAK_CERT,
            CONFLICT_GEO_REGISTRANT_MISMATCH,
        ],
        conflict_count=3,
    )
    # 25 + 15 + 3 = 43, capped at 35.
    assert _assess(d).score_breakdown["Cross-signal conflicts"] == 35


def test_no_conflicts_scores_zero():
    assert _assess(_result(conflicts=[], conflict_count=0)).score_breakdown["Cross-signal conflicts"] == 0
