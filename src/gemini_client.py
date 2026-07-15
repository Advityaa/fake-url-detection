"""Minimal Gemini (Google Generative Language API) REST client.

Shared by the optional LLM explanation path (:mod:`src.llm_explainer`) and the
evaluation raw-LLM baseline (``evaluation/llm_baseline.py``) so there is exactly
ONE client and ONE env-based key/model source (``src.config.settings``).

Uses ``httpx`` directly — already a project dependency — so no extra SDK is
required. The low-level :func:`gemini_generate` RAISES :class:`GeminiError` on
failure (rather than returning ""), so the evaluation baseline can distinguish a
genuine "not phishing" answer from a call that failed. Callers that want the old
"silently fall back" behaviour (the explainer) simply catch it.
"""

from __future__ import annotations

import logging
from typing import Optional

import httpx

from .config import settings

logger = logging.getLogger(__name__)

API_ROOT = "https://generativelanguage.googleapis.com/v1beta"


class GeminiError(RuntimeError):
    """Raised on a failed Gemini call.

    ``retryable`` is True for transient failures (429 rate-limit, 5xx, network
    errors) so callers can back off and retry; ``retry_after`` carries the
    server's Retry-After hint in seconds when present.
    """

    def __init__(
        self,
        message: str,
        *,
        status: Optional[int] = None,
        retryable: bool = False,
        retry_after: Optional[float] = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.retryable = retryable
        self.retry_after = retry_after


def is_configured() -> bool:
    """True if a Gemini API key is present in the environment/config."""
    return bool(settings.gemini_api_key)


def _retry_after_seconds(resp: httpx.Response) -> Optional[float]:
    raw = resp.headers.get("Retry-After")
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        return None


def gemini_generate(
    user: str,
    *,
    system: Optional[str] = None,
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    json_mode: bool = False,
    temperature: float = 0.0,
    max_output_tokens: int = 512,
    timeout: Optional[float] = None,
    thinking_budget: Optional[int] = 0,
) -> str:
    """Call Gemini ``generateContent`` and return the response text.

    Args:
        user: The user prompt text.
        system: Optional system instruction.
        model: Model id (defaults to ``settings.gemini_model``).
        api_key: Override key (defaults to ``settings.gemini_api_key``).
        json_mode: If True, ask the API for ``application/json`` output.
        temperature: Sampling temperature (0.0 = deterministic, best for eval).
        max_output_tokens: Response cap.
        timeout: Per-request timeout (defaults to ``settings.llm_timeout_seconds``).
        thinking_budget: For 2.5-class models, ``0`` disables "thinking" to keep
            calls fast/cheap; ``None`` omits the field entirely.

    Returns:
        The generated text (non-empty).

    Raises:
        GeminiError: on missing key, HTTP error, blocked/empty response.
    """
    key = (api_key or settings.gemini_api_key or "").strip()
    if not key:
        raise GeminiError("no Gemini API key configured", retryable=False)

    model = (model or settings.gemini_model or "gemini-flash-latest").strip()
    timeout = float(timeout if timeout is not None else settings.llm_timeout_seconds)

    generation_config = {
        "temperature": temperature,
        "maxOutputTokens": max_output_tokens,
    }
    if json_mode:
        generation_config["responseMimeType"] = "application/json"
    if thinking_budget is not None:
        generation_config["thinkingConfig"] = {"thinkingBudget": thinking_budget}

    body = {
        "contents": [{"role": "user", "parts": [{"text": user}]}],
        "generationConfig": generation_config,
    }
    if system:
        body["system_instruction"] = {"parts": [{"text": system}]}

    url = f"{API_ROOT}/models/{model}:generateContent"
    try:
        resp = httpx.post(url, params={"key": key}, json=body, timeout=timeout)
    except httpx.HTTPError as exc:  # network/timeout -> retryable
        raise GeminiError(f"request failed: {exc}", retryable=True) from exc

    if resp.status_code == 429:
        raise GeminiError(
            "rate limited (HTTP 429)", status=429, retryable=True,
            retry_after=_retry_after_seconds(resp),
        )
    if resp.status_code >= 500:
        raise GeminiError(
            f"server error (HTTP {resp.status_code})", status=resp.status_code,
            retryable=True, retry_after=_retry_after_seconds(resp),
        )
    if resp.status_code != 200:
        # 4xx (bad key, model not found, bad request) -> not retryable.
        raise GeminiError(
            f"HTTP {resp.status_code}: {resp.text[:200]}",
            status=resp.status_code, retryable=False,
        )

    data = resp.json()
    candidates = data.get("candidates") or []
    if not candidates:
        feedback = data.get("promptFeedback")
        raise GeminiError(f"no candidates returned (blocked? {feedback})", retryable=False)

    parts = (candidates[0].get("content") or {}).get("parts") or []
    text = "".join(p.get("text", "") for p in parts).strip()
    if not text:
        finish = candidates[0].get("finishReason")
        raise GeminiError(f"empty response (finishReason={finish})", retryable=False)
    return text
