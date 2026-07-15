"""Tests for the raw-LLM evaluation baseline and the Gemini wiring.

No test performs a real network call: every LLM call is a mocked ``call_fn`` or a
monkeypatched ``gemini_generate``. Covers response parsing, caching (hits +
failure-not-cached), rate-limit backoff, the clean no-key skip, and the pure
comparison / disagreement helpers.
"""

from __future__ import annotations

import pytest

from evaluation.llm_baseline import (
    VARIANT_URL_AND_TEXT,
    VARIANT_URL_ONLY,
    NaiveLLMBaseline,
    ResponseCache,
    baseline_available,
    build_comparison,
    build_prompt,
    find_disagreements,
    parse_response,
)
from src.gemini_client import GeminiError

NOOP_SLEEP = lambda _s: None  # noqa: E731 - test helper


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "text,expected",
    [
        ('{"is_phishing": true, "reason": "bad"}', True),
        ('{"is_phishing": false, "reason": "ok"}', False),
        ('{"is_phishing": "yes", "reason": "x"}', True),
        ('{"is_phishing": "no", "reason": "x"}', False),
        ('{"is_phishing": 1, "reason": "x"}', True),
        ('{"is_phishing": 0, "reason": "x"}', False),
        ('```json\n{"is_phishing": true, "reason": "fenced"}\n```', True),
        ('Sure! {"is_phishing": false, "reason": "prose around"}', False),
    ],
)
def test_parse_response_valid(text, expected):
    is_phishing, reason = parse_response(text)
    assert is_phishing is expected
    assert isinstance(reason, str)


@pytest.mark.parametrize("text", ["not json at all", "{}", '{"reason":"no verdict"}', '{"is_phishing": "maybe"}'])
def test_parse_response_unusable_returns_none(text):
    is_phishing, _ = parse_response(text)
    assert is_phishing is None


def test_build_prompt_variants_differ():
    assert "page_text" not in build_prompt("http://x.test/")
    assert "page_text" in build_prompt("http://x.test/", page_text="Login to your bank")


# ---------------------------------------------------------------------------
# Caching + classify
# ---------------------------------------------------------------------------
def _baseline(tmp_path, call_fn, **kw):
    return NaiveLLMBaseline(
        model="test-model",
        cache_path=tmp_path / "cache.json",
        min_interval=0.0,
        call_fn=call_fn,
        sleep_fn=NOOP_SLEEP,
        clock_fn=lambda: 0.0,
        **kw,
    )


def test_classify_success_then_cache_hit(tmp_path):
    calls = {"n": 0}

    def call_fn(prompt, system):
        calls["n"] += 1
        return '{"is_phishing": true, "reason": "suspicious"}'

    baseline = _baseline(tmp_path, call_fn)
    first = baseline.classify("http://evil.test/")
    assert first.is_phishing is True and first.cached is False
    assert calls["n"] == 1

    # Same instance: in-memory cache hit, no new call.
    again = baseline.classify("http://evil.test/")
    assert again.cached is True and calls["n"] == 1

    # After persisting (as run() does), a fresh instance reads the cache from
    # disk and must not call the LLM again.
    baseline.cache.save()
    baseline2 = _baseline(tmp_path, call_fn)
    second = baseline2.classify("http://evil.test/")
    assert second.is_phishing is True and second.cached is True
    assert calls["n"] == 1  # no new call


def test_errors_are_not_cached(tmp_path):
    calls = {"n": 0}

    def call_fn(prompt, system):
        calls["n"] += 1
        raise GeminiError("boom", retryable=False)

    baseline = _baseline(tmp_path, call_fn)
    res = baseline.classify("http://x.test/")
    assert res.is_phishing is None and res.error
    # Not cached -> a second attempt calls again (never a silent "not phishing").
    baseline.classify("http://x.test/")
    assert calls["n"] == 2


def test_unparseable_not_cached(tmp_path):
    calls = {"n": 0}

    def call_fn(prompt, system):
        calls["n"] += 1
        return "totally not json"

    baseline = _baseline(tmp_path, call_fn)
    res = baseline.classify("http://x.test/")
    assert res.is_phishing is None and res.error == "unparseable response"
    baseline.classify("http://x.test/")
    assert calls["n"] == 2  # retried, not cached


def test_url_only_and_text_variants_cache_separately(tmp_path):
    calls = {"n": 0}

    def call_fn(prompt, system):
        calls["n"] += 1
        return '{"is_phishing": false, "reason": "r"}'

    baseline = _baseline(tmp_path, call_fn)
    baseline.classify("http://x.test/")  # url_only
    baseline.classify("http://x.test/", page_text="some page text")  # url_and_text
    assert calls["n"] == 2  # different variants => different cache keys


def test_retry_on_transient_then_success(tmp_path):
    attempts = {"n": 0}
    sleeps = []

    def call_fn(prompt, system):
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise GeminiError("429", status=429, retryable=True)
        return '{"is_phishing": true, "reason": "ok"}'

    baseline = NaiveLLMBaseline(
        model="m", cache_path=tmp_path / "c.json", min_interval=0.1,
        max_retries=4, call_fn=call_fn, sleep_fn=lambda s: sleeps.append(s),
        clock_fn=lambda: 0.0,
    )
    res = baseline.classify("http://x.test/")
    assert res.is_phishing is True
    assert attempts["n"] == 3           # two failures + one success
    assert baseline.calls_made == 1     # only the successful call counts
    assert len(sleeps) >= 2             # backed off between retries


def test_non_retryable_error_not_retried(tmp_path):
    attempts = {"n": 0}

    def call_fn(prompt, system):
        attempts["n"] += 1
        raise GeminiError("400 bad key", status=400, retryable=False)

    baseline = _baseline(tmp_path, call_fn)
    res = baseline.classify("http://x.test/")
    assert res.is_phishing is None
    assert attempts["n"] == 1  # not retried


def test_run_over_list_with_progress(tmp_path):
    def call_fn(prompt, system):
        return '{"is_phishing": true, "reason": "r"}'

    baseline = _baseline(tmp_path, call_fn)
    seen = []
    results = baseline.run(
        ["http://a.test/", "http://b.test/"], progress=lambda d, t: seen.append((d, t))
    )
    assert len(results) == 2 and all(r.is_phishing for r in results)
    assert seen and seen[-1] == (2, 2)


# ---------------------------------------------------------------------------
# Availability / skip
# ---------------------------------------------------------------------------
def test_baseline_available_reflects_key(monkeypatch):
    import src.config

    monkeypatch.setattr(src.config.settings, "gemini_api_key", "", raising=False)
    assert baseline_available() is False
    monkeypatch.setattr(src.config.settings, "gemini_api_key", "present", raising=False)
    assert baseline_available() is True


# ---------------------------------------------------------------------------
# Pure comparison / disagreement helpers
# ---------------------------------------------------------------------------
def test_build_comparison_metrics():
    common = [
        {"label": 1, "base_pred": 1, "pipe_no_ti_pred": 1, "pipe_with_ti_pred": 1},
        {"label": 1, "base_pred": 0, "pipe_no_ti_pred": 1, "pipe_with_ti_pred": 1},
        {"label": 0, "base_pred": 0, "pipe_no_ti_pred": 0, "pipe_with_ti_pred": 0},
        {"label": 0, "base_pred": 1, "pipe_no_ti_pred": 0, "pipe_with_ti_pred": 0},
    ]
    comp = build_comparison(common)
    assert comp["n"] == 4
    # baseline: tp=1 fp=1 fn=1 tn=1 -> all .5
    b = comp["raw_llm_baseline"]
    assert b["precision"] == 0.5 and b["recall"] == 0.5 and b["accuracy"] == 0.5
    # pipeline (no TI): perfect on this toy set
    p = comp["pipeline_no_threat_intel"]
    assert p["precision"] == 1.0 and p["recall"] == 1.0 and p["accuracy"] == 1.0


def test_find_disagreements_injection_first():
    rows = [
        {"url": "a", "base_pred": 1, "pipe_pred": 1, "injection_detected": False},   # agree
        {"url": "b", "base_pred": 0, "pipe_pred": 1, "injection_detected": False},   # disagree
        {"url": "c", "base_pred": 1, "pipe_pred": 0, "injection_detected": True},    # disagree + injection
    ]
    dis = find_disagreements(rows)
    assert [r["url"] for r in dis] == ["c", "b"]  # injection-flagged first


def test_response_cache_key_stable_and_variant_sensitive():
    k1 = ResponseCache.make_key("m", VARIANT_URL_ONLY, "http://x/")
    k2 = ResponseCache.make_key("m", VARIANT_URL_ONLY, "http://x/")
    k3 = ResponseCache.make_key("m", VARIANT_URL_AND_TEXT, "http://x/")
    assert k1 == k2 and k1 != k3


# ---------------------------------------------------------------------------
# Gemini client + config + explainer wiring
# ---------------------------------------------------------------------------
def test_gemini_generate_raises_without_key(monkeypatch):
    import src.config
    from src.gemini_client import gemini_generate

    monkeypatch.setattr(src.config.settings, "gemini_api_key", "", raising=False)
    with pytest.raises(GeminiError):
        gemini_generate("hi", api_key="")


def test_settings_gemini_availability(monkeypatch):
    from src.config import Settings

    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.setenv("USE_LLM", "true")
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    s = Settings()
    assert s.llm_is_available() is True


def test_settings_google_api_key_alias(monkeypatch):
    from src.config import Settings

    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("GOOGLE_API_KEY", "aliased")
    s = Settings()
    assert s.gemini_api_key == "aliased"


def test_explainer_dispatches_to_gemini(monkeypatch):
    import src.gemini_client
    from src.llm_explainer import LLMExplainer

    monkeypatch.setattr(src.gemini_client, "gemini_generate", lambda *a, **k: "explained prose")
    explainer = LLMExplainer()
    explainer.provider = "gemini"
    assert explainer._call_llm("system", "user") == "explained prose"
