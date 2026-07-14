"""Tests for the dynamic-cloaking detection stage.

The conflict/flagging logic and the risk-engine integration are tested on fixed
inputs with no browser. One end-to-end test drives a REAL headless Chromium over
a LOCAL sample page that injects a password field on scroll — it skips cleanly if
Playwright/Chromium is unavailable.
"""

from pathlib import Path

import pytest

from src.dynamic_analysis import compute_cloaking, run_dynamic_analysis
from src.html_analyzer import HTMLAnalysisResult
from src.prompt_injection_detector import PromptInjectionResult
from src.risk_engine import assess_risk
from src.schemas import DomSnapshot, DynamicAnalysisResult
from src.url_features import extract_url_features

FIXTURE = Path(__file__).parent / "fixtures" / "dynamic_cloaking_example.html"


# ---------------------------------------------------------------------------
# Pure logic — absolute deltas
# ---------------------------------------------------------------------------
def test_cloaking_detected_when_password_appears():
    pre = DomSnapshot(forms=1, inputs=1, password_fields=0)
    post = DomSnapshot(forms=1, inputs=2, password_fields=1)
    detected, reasons = compute_cloaking(pre, post)
    assert detected is True
    assert any("password field" in r for r in reasons)


def test_no_cloaking_when_static():
    snap = DomSnapshot(forms=1, inputs=2, password_fields=1)
    detected, reasons = compute_cloaking(snap, snap)
    assert detected is False
    assert reasons == []


def test_cloaking_on_hidden_password_becoming_visible():
    pre = DomSnapshot(password_fields=1, visible_password_fields=0)
    post = DomSnapshot(password_fields=1, visible_password_fields=1)
    detected, reasons = compute_cloaking(pre, post)
    assert detected is True
    assert any("became visible" in r for r in reasons)


def test_new_form_with_credentials_flagged():
    pre = DomSnapshot(forms=0, password_fields=0)
    post = DomSnapshot(forms=1, password_fields=1)
    detected, reasons = compute_cloaking(pre, post)
    assert detected is True


# ---------------------------------------------------------------------------
# Gating / graceful skip
# ---------------------------------------------------------------------------
def test_disabled_returns_unchecked():
    r = run_dynamic_analysis("https://x.test/", "x.test", enabled=False)
    assert r.checked is False
    assert r.available is False


def test_browser_unavailable_is_graceful(monkeypatch):
    from contextlib import contextmanager

    from src.browser_fetch import BrowserUnavailable

    @contextmanager
    def boom_renderer(url, timeout_seconds=None):
        raise BrowserUnavailable("no chromium")
        yield  # pragma: no cover

    r = run_dynamic_analysis("https://x.test/", "x.test", enabled=True, renderer=boom_renderer)
    assert r.checked is True
    assert r.available is False
    assert "unavailable" in r.note.lower()


def test_mocked_renderer_detects_injected_password():
    # Fake a page whose password count grows after interaction — no real browser.
    from contextlib import contextmanager

    class _FakePage:
        def __init__(self):
            self._calls = 0

        def evaluate(self, script, *args):
            if "querySelectorAll" in script:  # snapshot call
                self._calls += 1
                pw = 0 if self._calls == 1 else 1  # 0 pre, 1 post
                return {"forms": 1, "inputs": 1 + pw, "password_fields": pw,
                        "visible_password_fields": pw, "hidden_inputs": 0}
            return None  # scrollTo

        def wait_for_load_state(self, *a, **k):
            pass

        def wait_for_timeout(self, *a, **k):
            pass

    class _Rendered:
        page = _FakePage()

    @contextmanager
    def fake_renderer(url, timeout_seconds=None):
        yield _Rendered()

    r = run_dynamic_analysis("https://x.test/", "x.test", enabled=True, renderer=fake_renderer)
    assert r.available is True
    assert r.pre.password_fields == 0
    assert r.post.password_fields == 1
    assert r.delta_password_fields == 1
    assert r.cloaking_detected is True


# ---------------------------------------------------------------------------
# Risk-engine integration
# ---------------------------------------------------------------------------
def _assess(dyn, is_trusted=False, features=None):
    return assess_risk(
        features or extract_url_features("https://some-unknown-site.example.org/"),
        HTMLAnalysisResult(), PromptInjectionResult(), [],
        is_trusted_domain=is_trusted, dynamic=dyn,
    )


def test_cloaking_scores_but_not_high_alone():
    dyn = DynamicAnalysisResult(checked=True, available=True, cloaking_detected=True,
                                reasons=["1 password field(s) appeared after interaction"])
    result = _assess(dyn)
    assert result.score_breakdown["Dynamic content"] == 22
    assert result.classification != "Likely Phishing"  # not High on this alone
    assert result.score < 60


def test_cloaking_suppressed_for_trusted_domain():
    dyn = DynamicAnalysisResult(checked=True, available=True, cloaking_detected=True,
                                reasons=["x"])
    result = _assess(dyn, is_trusted=True)
    assert result.score_breakdown["Dynamic content"] == 0


def test_no_cloaking_adds_nothing():
    dyn = DynamicAnalysisResult(checked=True, available=True, cloaking_detected=False)
    assert _assess(dyn).score_breakdown["Dynamic content"] == 0
    assert _assess(None).score_breakdown["Dynamic content"] == 0


def test_cloaking_escalates_with_corroboration():
    # Cloaking (+22) plus an http (no-HTTPS) keyword URL pushes into High Risk.
    dyn = DynamicAnalysisResult(checked=True, available=True, cloaking_detected=True,
                                reasons=["1 password field(s) appeared after interaction"])
    feats = extract_url_features("http://secure-login-verify.attacker-host.example/account")
    result = _assess(dyn, features=feats)
    assert result.score_breakdown["Dynamic content"] == 22
    assert result.score > _assess(dyn).score  # corroboration adds on top


# ---------------------------------------------------------------------------
# End-to-end with a REAL browser over a local fixture (skips if unavailable)
# ---------------------------------------------------------------------------
def test_real_browser_detects_scroll_injected_password():
    pytest.importorskip("playwright")
    from src.browser_fetch import BrowserUnavailable

    file_url = f"file://{FIXTURE.resolve()}"
    try:
        r = run_dynamic_analysis(file_url, "example", enabled=True, timeout_seconds=10)
    except Exception as exc:  # pragma: no cover
        pytest.skip(f"browser unavailable: {exc}")

    if not r.available:
        pytest.skip(f"browser unavailable: {r.note}")

    # Pre-interaction: no password field. Post-scroll: one appears.
    assert r.pre.password_fields == 0
    assert r.post.password_fields == 1
    assert r.delta_password_fields == 1
    assert r.cloaking_detected is True


# ---------------------------------------------------------------------------
# Pipeline integration (injected result -> no browser)
# ---------------------------------------------------------------------------
def test_pipeline_includes_injected_dynamic():
    from src.pipeline import analyze_url
    from src.rag_retriever import RAGRetriever

    dyn = DynamicAnalysisResult(checked=True, available=True, cloaking_detected=True,
                                reasons=["1 password field(s) appeared after interaction"],
                                evidence_messages=["Dynamic cloaking detected: ..."])
    result = analyze_url(
        "https://shop.example-host.test/", "phishing",
        retriever=RAGRetriever(), trusted_domains=[], enable_threat_intel=False,
        dynamic=dyn,
    )
    assert result is not None
    assert result.dynamic_analysis is not None and result.dynamic_analysis.cloaking_detected
    d = result.to_dict()
    assert d["dynamic_analysis"]["cloaking_detected"] is True
    assert "Dynamic content" in d["risk_assessment"]["score_breakdown"]


def test_pipeline_default_dynamic_not_run_in_sample_mode():
    from src.pipeline import analyze_url
    from src.rag_retriever import RAGRetriever

    result = analyze_url(
        "https://demo.example.org/", "benign",
        retriever=RAGRetriever(), trusted_domains=[],
    )
    assert result.dynamic_analysis is not None
    assert result.dynamic_analysis.checked is False
    assert result.risk_assessment.score_breakdown["Dynamic content"] == 0
