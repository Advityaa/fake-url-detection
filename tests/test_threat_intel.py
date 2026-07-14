"""Tests for the threat-intelligence module and its risk-engine integration.

The OpenPhish feed is MOCKED via a local fixture (or an injected fetcher); no
test ever touches the network.
"""

from pathlib import Path

from src.html_analyzer import HTMLAnalysisResult
from src.prompt_injection_detector import PromptInjectionResult
from src.risk_engine import assess_risk
from src.schemas import ThreatIntelResult
from src.threat_intel import ThreatIntelClient
from src.url_features import extract_url_features

FIXTURE = Path(__file__).parent / "fixtures" / "openphish_sample.txt"
FEED_TEXT = FIXTURE.read_text(encoding="utf-8")


def _client(tmp_path, **kwargs) -> ThreatIntelClient:
    """A client that reads the fixture feed and never hits the network."""
    kwargs.setdefault("fetcher", lambda url: FEED_TEXT)
    kwargs.setdefault("ttl_seconds", 9999)
    return ThreatIntelClient(cache_dir=str(tmp_path), **kwargs)


# ---------------------------------------------------------------------------
# OpenPhish matching
# ---------------------------------------------------------------------------
def test_exact_url_match(tmp_path):
    c = _client(tmp_path)
    r = c.check("http://paypal-login.example-phish.test/verify")
    assert r.listed is True
    assert r.source == "OpenPhish"
    assert r.checked is True
    assert "high confidence" in r.confidence_note.lower()


def test_domain_level_match_other_path(tmp_path):
    # A different path on a domain present in the feed still matches.
    c = _client(tmp_path)
    r = c.check("http://acme-bank.secure-login.test/some/other/page", "secure-login.test")
    assert r.listed is True
    assert r.source == "OpenPhish"


def test_clean_url_not_listed(tmp_path):
    c = _client(tmp_path)
    r = c.check("https://github.com", "github.com")
    assert r.checked is True
    assert r.listed is False


def test_scheme_insensitive_match(tmp_path):
    # Feed has http://...; an https:// variant of the same URL should still match.
    c = _client(tmp_path)
    r = c.check("https://paypal-login.example-phish.test/verify")
    assert r.listed is True


# ---------------------------------------------------------------------------
# Robustness / offline behaviour
# ---------------------------------------------------------------------------
def test_disabled_short_circuits(tmp_path):
    c = _client(tmp_path, enabled=False)
    r = c.check("http://paypal-login.example-phish.test/verify")
    assert r.checked is False
    assert r.listed is False


def test_offline_no_cache_never_crashes(tmp_path):
    def boom(url):
        raise RuntimeError("network down")

    c = ThreatIntelClient(cache_dir=str(tmp_path), ttl_seconds=0, fetcher=boom)
    r = c.check("http://anything.test/login")
    assert r.checked is False
    assert r.listed is False
    assert "no threat-intelligence data" in r.confidence_note.lower()


def test_stale_cache_used_when_fetch_fails(tmp_path):
    # First client populates the cache.
    _client(tmp_path).check("https://github.com")
    # Second client: cache is stale (ttl=0) AND the network is down -> fall back
    # to the stale cache instead of crashing or losing data.
    def boom(url):
        raise RuntimeError("network down")

    c2 = ThreatIntelClient(cache_dir=str(tmp_path), ttl_seconds=0, fetcher=boom)
    r = c2.check("http://paypal-login.example-phish.test/verify")
    assert r.listed is True  # served from stale cache


# ---------------------------------------------------------------------------
# Caching / TTL
# ---------------------------------------------------------------------------
def test_fresh_cache_avoids_refetch(tmp_path):
    calls = {"n": 0}

    def counting(url):
        calls["n"] += 1
        return FEED_TEXT

    # First client fetches once and writes the cache.
    ThreatIntelClient(cache_dir=str(tmp_path), ttl_seconds=9999, fetcher=counting).check("https://x.test")
    assert calls["n"] == 1
    # Second client with a fresh cache should NOT fetch again.
    ThreatIntelClient(cache_dir=str(tmp_path), ttl_seconds=9999, fetcher=counting).check("https://x.test")
    assert calls["n"] == 1


def test_stale_cache_triggers_refetch(tmp_path):
    calls = {"n": 0}

    def counting(url):
        calls["n"] += 1
        return FEED_TEXT

    ThreatIntelClient(cache_dir=str(tmp_path), ttl_seconds=0, fetcher=counting).check("https://x.test")
    ThreatIntelClient(cache_dir=str(tmp_path), ttl_seconds=0, fetcher=counting).check("https://x.test")
    assert calls["n"] == 2


# ---------------------------------------------------------------------------
# Risk-engine integration
# ---------------------------------------------------------------------------
def _benign_features():
    return extract_url_features("https://some-unknown-site.example.org/")


def test_threat_hit_scored_high():
    threat = ThreatIntelResult(checked=True, listed=True, source="OpenPhish", matched_value="x")
    result = assess_risk(
        _benign_features(), HTMLAnalysisResult(), PromptInjectionResult(), [],
        threat_intel=threat,
    )
    assert result.classification == "Likely Phishing"
    assert result.score_breakdown["Threat intelligence"] >= 60
    assert any("phishing feed" in f.lower() for f in result.risk_factors)


def test_threat_hit_suppressed_for_trusted_domain():
    # A stray feed entry for a trusted domain must NOT flag it.
    threat = ThreatIntelResult(checked=True, listed=True, source="OpenPhish", matched_value="amazon.com")
    f = extract_url_features("amazon.com")
    result = assess_risk(
        f, HTMLAnalysisResult(), PromptInjectionResult(), [],
        is_trusted_domain=True, threat_intel=threat,
    )
    assert result.score_breakdown["Threat intelligence"] == 0
    assert result.classification == "Likely Benign"
    assert any("false positive" in s.lower() for s in result.safe_factors)


def test_no_hit_adds_no_points():
    threat = ThreatIntelResult(checked=True, listed=False, source="")
    result = assess_risk(
        _benign_features(), HTMLAnalysisResult(), PromptInjectionResult(), [],
        threat_intel=threat,
    )
    assert result.score_breakdown["Threat intelligence"] == 0


def test_none_threat_intel_is_safe():
    # Backwards compatible: passing no threat intel behaves as before.
    result = assess_risk(
        _benign_features(), HTMLAnalysisResult(), PromptInjectionResult(), [],
        threat_intel=None,
    )
    assert result.score_breakdown["Threat intelligence"] == 0


# ---------------------------------------------------------------------------
# Pipeline integration (injected client -> no network)
# ---------------------------------------------------------------------------
def test_pipeline_includes_threat_intel(tmp_path):
    from src.pipeline import analyze_url
    from src.rag_retriever import RAGRetriever

    client = _client(tmp_path)
    # Sample mode avoids any live crawl; the URL still feeds the threat check.
    result = analyze_url(
        "http://paypal-login.example-phish.test/verify",
        "phishing",
        retriever=RAGRetriever(),
        trusted_domains=[],
        threat_client=client,
    )
    assert result is not None
    assert result.threat_intel is not None
    d = result.to_dict()
    assert d["threat_intel"]["listed"] is True
    assert d["threat_intel"]["source"] == "OpenPhish"


def test_pipeline_flag_disables_threat_intel(tmp_path):
    """enable_threat_intel=False must skip the feed even if a client is provided.

    This is the evaluation-harness leakage control: labels derived from the feed
    must not be able to influence the score through the threat-intel category.
    """
    from src.pipeline import analyze_url
    from src.rag_retriever import RAGRetriever

    client = _client(tmp_path)  # would match this URL if consulted
    result = analyze_url(
        "http://paypal-login.example-phish.test/verify",
        "phishing",
        retriever=RAGRetriever(),
        trusted_domains=[],
        threat_client=client,
        enable_threat_intel=False,
    )
    assert result is not None
    assert result.threat_intel.checked is False
    assert result.threat_intel.listed is False
    assert result.risk_assessment.score_breakdown["Threat intelligence"] == 0
