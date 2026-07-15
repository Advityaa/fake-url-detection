"""Optional multimodal analysis: render a screenshot and OCR its visible text.

This stage is OFF by default (``USE_MULTIMODAL=false``) and degrades gracefully:
if Playwright, a browser, or the OCR engine is unavailable, it logs a warning and
returns an empty result — the pipeline still runs end-to-end.

Why it exists: HTML-only analysis misses anything rendered as pixels. Two signals
are surfaced that the HTML path can miss:

  1. **Visible-vs-DOM text divergence** — words OCR reads on the rendered page that
     are weakly represented in the HTML text (a hidden-text / cloaking indicator).
  2. **Brand-name-in-image** — a known brand rendered in the screenshot while the
     domain does not belong to that brand (logo/brand impersonation shipped as an
     image to evade HTML brand analysis).

Safety posture (matches ``src/crawler.py``):
  * GET-only navigation to the target URL, a hard timeout, no downloads, no form
    interaction, popups closed rather than followed, JS runs only to render.
  * **All OCR text is UNTRUSTED**, exactly like HTML text. It is scanned with
    ``prompt_injection_detector`` and never executed or obeyed. The "Clouding the
    Mirror" research shows attackers hide instructions as low-contrast/tiny image
    text specifically to hit the OCR channel — so this is an injection surface.

The impure capture/OCR steps are injectable (``capture_fn`` / ``ocr_fn``) so the
signal logic can be unit-tested without a real browser.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from .config import KNOWN_BRANDS, SCREENSHOT_DIR, settings
from .prompt_injection_detector import detect_prompt_injection
from .schemas import MultimodalResult
from .utils import safe_filename_stamp, tokenize_words

logger = logging.getLogger(__name__)

# Divergence is only flagged when it is both proportionally large AND has a
# meaningful absolute count — OCR is noisy, so the thresholds are conservative.
_DIVERGENCE_RATIO_THRESHOLD = 0.5
_DIVERGENCE_MIN_TERMS = 8
_OCR_EXCERPT_LIMIT = 800


# ---------------------------------------------------------------------------
# Pure signal logic (unit-tested without a browser)
# ---------------------------------------------------------------------------
def compute_text_divergence(ocr_text: str, dom_text: str) -> Tuple[bool, float, List[str]]:
    """Return ``(diverged, ratio, sample_terms)`` for OCR-vs-DOM text divergence.

    Measures the share of meaningful OCR word-tokens that do NOT appear in the DOM
    text. A high share suggests text was rendered (visible to a human/OCR) without
    a matching HTML representation — a cloaking / hidden-text indicator.
    """
    ocr_tokens = {t for t in tokenize_words(ocr_text) if len(t) >= 4}
    if not ocr_tokens:
        return False, 0.0, []
    dom_tokens = {t for t in tokenize_words(dom_text) if len(t) >= 4}

    divergent = sorted(ocr_tokens - dom_tokens)
    ratio = len(divergent) / len(ocr_tokens)
    diverged = ratio >= _DIVERGENCE_RATIO_THRESHOLD and len(divergent) >= _DIVERGENCE_MIN_TERMS
    return diverged, round(ratio, 4), divergent[:15]


def detect_brand_in_image(ocr_text: str, registered_domain: str) -> str:
    """Return a known brand present in OCR text whose domain does NOT match.

    Complements the HTML brand check: catches a brand shown only as an image/logo
    (so it never reached the HTML text) on a non-brand domain. Returns "" when no
    mismatched brand is found or when the domain legitimately owns the brand.
    """
    if not ocr_text:
        return ""
    registered = (registered_domain or "").lower()
    lowered = ocr_text.lower()
    for brand, legit_domains in KNOWN_BRANDS.items():
        if registered in legit_domains:
            continue  # the page's own brand on its own domain
        if len(brand) < 4:
            continue  # avoid noisy short-token OCR matches
        if re.search(rf"\b{re.escape(brand)}\b", lowered):
            return brand
    return ""


# ---------------------------------------------------------------------------
# Impure steps (real browser / OCR) — injectable for tests
# ---------------------------------------------------------------------------
def capture_screenshot(url: str, out_path: Path, timeout_seconds: int) -> bool:
    """Render ``url`` in headless Chromium and save a full-page screenshot.

    GET-only navigation, hard timeout, downloads rejected, popups closed. Raises
    on any failure (missing Playwright/browser, navigation error) so the caller
    can record the stage as unavailable.
    """
    from playwright.sync_api import sync_playwright  # lazy: heavy optional dep

    out_path.parent.mkdir(parents=True, exist_ok=True)
    timeout_ms = max(1000, int(timeout_seconds * 1000))
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            context = browser.new_context(
                accept_downloads=False,  # never download files
                user_agent=settings.crawler_user_agent,
            )
            # Close any popup/new tab rather than following it.
            context.on("page", lambda page: page.close() if context.pages and len(context.pages) > 1 else None)
            page = context.new_page()
            page.set_default_timeout(timeout_ms)
            # GET navigation only; wait for the DOM, not arbitrary network activity.
            page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            page.screenshot(path=str(out_path), full_page=True)
        finally:
            browser.close()
    return out_path.exists()


def run_ocr(image_path: Path) -> str:
    """Extract text from an image with Tesseract (via pytesseract). Raises on failure."""
    import pytesseract  # lazy: needs the system `tesseract` binary
    from PIL import Image

    # Point pytesseract at an explicit binary if configured (e.g. conda install).
    if settings.tesseract_cmd:
        pytesseract.pytesseract.tesseract_cmd = settings.tesseract_cmd

    with Image.open(image_path) as img:
        return pytesseract.image_to_string(img) or ""


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def run_multimodal(
    url: str,
    dom_text: str,
    registered_domain: str,
    is_trusted_domain: bool = False,
    *,
    enabled: Optional[bool] = None,
    timeout_seconds: Optional[int] = None,
    capture_fn: Optional[Callable[[str, Path, int], bool]] = None,
    ocr_fn: Optional[Callable[[Path], str]] = None,
) -> MultimodalResult:
    """Run the optional screenshot+OCR stage and derive the two signals.

    Never raises: any capability/rendering/OCR failure is logged and returned as
    an unavailable result so the pipeline continues.
    """
    enabled = settings.use_multimodal if enabled is None else enabled
    result = MultimodalResult()
    if not enabled:
        result.note = "Multimodal analysis disabled (USE_MULTIMODAL=false)."
        return result
    if not url:
        result.note = "No renderable URL for multimodal analysis."
        return result

    result.checked = True
    timeout_seconds = timeout_seconds or settings.multimodal_timeout_seconds
    capture_fn = capture_fn or capture_screenshot
    ocr_fn = ocr_fn or run_ocr

    out_path = SCREENSHOT_DIR / f"shot_{safe_filename_stamp()}.png"
    try:
        if not capture_fn(url, out_path, timeout_seconds):
            result.note = "Screenshot capture produced no image; stage skipped."
            return result
        ocr_text = ocr_fn(out_path) or ""
    except Exception as exc:  # noqa: BLE001 - never crash the pipeline
        logger.warning(
            "Multimodal stage unavailable (%s); skipping screenshot/OCR. "
            "Install Playwright browsers (`playwright install chromium`) and Tesseract to enable it.",
            exc,
        )
        result.note = f"Multimodal stage unavailable: {exc}"
        return result

    result.available = True
    result.screenshot_path = str(out_path)
    result.ocr_char_count = len(ocr_text)
    result.ocr_text_excerpt = ocr_text.strip()[:_OCR_EXCERPT_LIMIT]

    # --- Signal 1: visible-vs-DOM divergence ---
    diverged, ratio, terms = compute_text_divergence(ocr_text, dom_text)
    result.text_divergence = diverged
    result.divergence_ratio = ratio
    result.divergent_terms = terms

    # --- Signal 2: brand-name-in-image ---
    result.brand_in_image = detect_brand_in_image(ocr_text, registered_domain)

    # --- OCR text is UNTRUSTED: scan for injection, never obey it ---
    injection = detect_prompt_injection(visible_text=ocr_text)
    result.injection_in_ocr = injection.injection_detected
    result.injection_severity = injection.severity

    result.evidence_messages = _build_evidence(result, is_trusted_domain)
    return result


def _build_evidence(r: MultimodalResult, is_trusted_domain: bool) -> List[str]:
    messages: List[str] = []
    if r.brand_in_image:
        messages.append(
            f"Screenshot text mentions the brand '{r.brand_in_image}', but the domain does "
            "not belong to that brand — possible logo/brand impersonation rendered as an image."
        )
    if r.text_divergence:
        messages.append(
            f"Rendered (OCR) text diverges from the HTML text "
            f"({int(r.divergence_ratio * 100)}% of visible words are weak/absent in the DOM), "
            "a possible hidden-text/cloaking indicator."
        )
    if r.injection_in_ocr:
        messages.append(
            f"Hidden-instruction patterns were detected in the screenshot's OCR text "
            f"(severity: {r.injection_severity}). This image text is treated as untrusted "
            "evidence and was never followed."
        )
    if is_trusted_domain and (r.brand_in_image or r.text_divergence or r.injection_in_ocr):
        messages.append(
            "Domain is on the trusted allowlist, so the visual signals above were "
            "recorded but not scored (guarding against OCR false positives)."
        )
    if not messages:
        messages.append("No divergence or brand-impersonation signals were found in the screenshot.")
    return messages
