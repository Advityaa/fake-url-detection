"""Tests for the UI wiring added for the stage-detail panels + interactive
ablation toggles.

Scope (matches the feature: *UI + wiring only, not detection logic*):
  * ``capabilities()`` reports every toggleable stage with an honest
    available/default/reason shape.
  * The per-request overrides on ``analyze_url`` actually turn stages on/off
    (so the toggles are a real ablation, never a silent no-op).
  * The FastAPI layer exposes ``/api/capabilities`` and accepts the toggle
    fields on ``/api/analyze`` (including backward-compatible ``{url, mode}``).
  * A sample full result carries every schema field the two UIs read verbatim,
    so a schema rename fails here instead of silently blanking a panel.

No test performs real network I/O: sample modes are used, and the one
"domain-intel on" case injects a fully mocked ``DomainIntelClient``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.capabilities import capabilities
from src.domain_intel import DomainIntelClient
from src.pipeline import analyze_url
from src.rag_retriever import RAGRetriever

STAGE_KEYS = {
    "threat_intel",
    "domain_intel",
    "render_playwright",
    "dynamic",
    "multimodal",
    "embedding",
    "llm",
}


@pytest.fixture(scope="module")
def retriever() -> RAGRetriever:
    return RAGRetriever()


def _mock_domain_client() -> DomainIntelClient:
    """A DomainIntelClient whose WHOIS/DNS/TLS calls are all mocked (no network)."""
    old = datetime.now(timezone.utc) - timedelta(days=2000)
    return DomainIntelClient(
        timeout=1,
        new_age_days=30,
        enabled=True,
        whois_fn=lambda d: old,
        dns_fn=lambda domain, timeout: (True, True),
        tls_fn=lambda hostname, timeout: {
            "issuer": "Test CA Org",
            "valid_from": "Jan 1 00:00:00 2026 GMT",
            "valid_until": "Jan 1 00:00:00 2027 GMT",
            "valid": True,
            "self_signed": False,
        },
    )


# ---------------------------------------------------------------------------
# capabilities()
# ---------------------------------------------------------------------------
def test_capabilities_has_every_stage_with_valid_shape():
    caps = capabilities()
    assert set(caps.keys()) == STAGE_KEYS
    for key, cap in caps.items():
        assert set(cap.keys()) == {"available", "default", "reason"}, key
        assert isinstance(cap["available"], bool)
        assert isinstance(cap["default"], bool)
        assert isinstance(cap["reason"], str)


def test_capabilities_reason_present_iff_unavailable():
    for key, cap in capabilities().items():
        if cap["available"]:
            assert cap["reason"] == "", key
        else:
            assert cap["reason"], key  # unavailable stages must say why


def test_threat_and_domain_intel_available_by_default():
    caps = capabilities()
    assert caps["threat_intel"]["available"] is True
    assert caps["domain_intel"]["available"] is True


# ---------------------------------------------------------------------------
# analyze_url per-request overrides (the toggle wiring)
# ---------------------------------------------------------------------------
def test_overrides_turn_live_only_stages_off(retriever):
    result = analyze_url(
        "http://phish.example.net", "phishing",
        retriever=retriever, trusted_domains=set(),
        enable_threat_intel=False, enable_domain_intel=False,
        enable_multimodal=False, enable_dynamic=False,
    )
    assert result is not None
    assert result.threat_intel.checked is False
    assert result.domain_intel.checked is False
    assert result.multimodal.checked is False
    assert result.dynamic_analysis.checked is False


def test_enable_domain_intel_false_overrides_injected_client(retriever):
    # Even with a client injected, the explicit off toggle wins.
    result = analyze_url(
        "http://phish.example.net", "phishing",
        retriever=retriever, trusted_domains=set(),
        domain_client=_mock_domain_client(),
        enable_threat_intel=False, enable_domain_intel=False,
    )
    assert result.domain_intel.checked is False


def test_enable_domain_intel_true_forces_stage_on_in_sample_mode(retriever):
    # The on toggle forces domain intel even outside live mode (mocked client).
    result = analyze_url(
        "http://phish.example.net", "phishing",
        retriever=retriever, trusted_domains=set(),
        domain_client=_mock_domain_client(),
        enable_threat_intel=False, enable_domain_intel=True,
    )
    assert result.domain_intel.checked is True
    assert result.domain_intel.whois_available is True


def test_enable_llm_false_uses_deterministic_fallback(retriever):
    result = analyze_url(
        "http://phish.example.net", "phishing",
        retriever=retriever, trusted_domains=set(),
        enable_threat_intel=False, enable_domain_intel=False, enable_llm=False,
    )
    assert result.explanation_source == "fallback"


def test_render_backend_override_does_not_break_sample_mode(retriever):
    # render_backend only affects live crawling; passing it must be harmless.
    result = analyze_url(
        "http://phish.example.net", "phishing",
        retriever=retriever, trusted_domains=set(),
        render_backend="requests",
        enable_threat_intel=False, enable_domain_intel=False,
    )
    assert result is not None
    assert result.risk_score > 0


def test_defaults_unchanged_when_no_overrides(retriever):
    # Backward compatibility: omitting every override behaves like before.
    result = analyze_url(
        "http://phish.example.net", "phishing",
        retriever=retriever, trusted_domains=set(),
        enable_threat_intel=False,  # only to avoid a live feed lookup in tests
    )
    assert result is not None
    # sample mode + no domain_client => domain intel not run by default
    assert result.domain_intel.checked is False


# ---------------------------------------------------------------------------
# FastAPI layer
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient

    import api

    return TestClient(api.app)


def test_capabilities_endpoint(client):
    resp = client.get("/api/capabilities")
    assert resp.status_code == 200
    assert set(resp.json().keys()) == STAGE_KEYS


def test_analyze_endpoint_accepts_toggle_fields(client):
    resp = client.post("/api/analyze", json={
        "url": "http://phish.example.net",
        "mode": "phishing",
        "enable_threat_intel": False,
        "enable_domain_intel": False,
        "enable_multimodal": False,
        "enable_dynamic": False,
        "enable_llm": False,
        "render_backend": "requests",
        "retriever_backend": "tfidf",
    })
    assert resp.status_code == 200
    data = resp.json()
    for key in ("threat_intel", "domain_intel", "multimodal", "dynamic_analysis", "risk_assessment"):
        assert key in data
    assert data["threat_intel"]["checked"] is False
    assert data["domain_intel"]["checked"] is False


def test_analyze_endpoint_backward_compatible_minimal_body(client):
    resp = client.post("/api/analyze", json={"url": "", "mode": "phishing"})
    assert resp.status_code == 200
    assert "risk_assessment" in resp.json()


def test_analyze_endpoint_rejects_empty_live_url(client):
    resp = client.post("/api/analyze", json={"url": "", "mode": "live"})
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Schema-field coverage: the sample result must carry every field the UIs read
# ---------------------------------------------------------------------------
# Exact field names referenced by the React panels (App.jsx) and the Streamlit
# render_* functions. Kept explicit so renaming a schema field fails here.
_THREAT_FIELDS = {"checked", "listed", "source", "sources_checked", "matched_value", "confidence_note"}
_DOMAIN_FIELDS = {
    "checked", "conflict_count", "conflicts", "whois_available", "registrar",
    "domain_created", "domain_age_days", "is_newly_registered", "registrant_country",
    "dns_available", "resolves", "has_mx", "tls_available", "cert_issuer", "cert_org",
    "cert_valid_until", "cert_currently_valid", "cert_self_signed",
    "asn_available", "ip_country", "asn_org",
}
_MULTIMODAL_FIELDS = {
    "checked", "available", "note", "brand_in_image", "text_divergence",
    "divergence_ratio", "injection_in_ocr", "injection_severity", "ocr_char_count",
    "divergent_terms", "ocr_text_excerpt",
}
_DYNAMIC_FIELDS = {
    "checked", "available", "note", "cloaking_detected", "clicked_login",
    "pre", "post", "delta_forms", "delta_inputs", "delta_password_fields",
    "delta_visible_password_fields", "reasons",
}
_DOM_SNAPSHOT_FIELDS = {"forms", "inputs", "password_fields", "visible_password_fields"}


def test_sample_result_exposes_all_ui_fields(retriever):
    result = analyze_url(
        "http://phish.example.net", "phishing",
        retriever=retriever, trusted_domains=set(),
        enable_threat_intel=False, enable_domain_intel=False,
    )
    data = result.to_dict()

    assert _THREAT_FIELDS <= data["threat_intel"].keys()
    assert _DOMAIN_FIELDS <= data["domain_intel"].keys()
    assert _MULTIMODAL_FIELDS <= data["multimodal"].keys()
    assert _DYNAMIC_FIELDS <= data["dynamic_analysis"].keys()
    assert _DOM_SNAPSHOT_FIELDS <= data["dynamic_analysis"]["pre"].keys()
    assert _DOM_SNAPSHOT_FIELDS <= data["dynamic_analysis"]["post"].keys()

    ra = data["risk_assessment"]
    for key in ("score_breakdown", "ui_label", "recommended_action", "risk_factors", "safe_factors"):
        assert key in ra
    assert isinstance(ra["score_breakdown"], dict)


# ---------------------------------------------------------------------------
# Streamlit UI wiring (import-only; no Streamlit runtime needed)
# ---------------------------------------------------------------------------
def test_streamlit_stage_defs_match_capabilities():
    import app

    stage_keys = {key for key, _label, _desc in app._STAGE_DEFS}
    assert stage_keys == STAGE_KEYS
    # The new render functions exist and are callable.
    for name in (
        "render_stage_toggles", "render_score_breakdown", "render_threat_intel",
        "render_domain_intel", "render_multimodal", "render_dynamic",
    ):
        assert callable(getattr(app, name))


def test_streamlit_analyze_accepts_overrides():
    import inspect

    import app

    params = inspect.signature(app.analyze).parameters
    assert "overrides" in params
