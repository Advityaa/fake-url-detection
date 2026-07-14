"""Dynamic-cloaking detection: diff the DOM before vs after interaction.

Static HTML analysis (and single-snapshot rendering) misses content that a page
reveals only *after* rendering/interaction — a deliberate evasion where a login
form or password field is injected by JavaScript on scroll, a timer, or a click,
so the initial HTML looks benign. This stage renders the page (Playwright),
snapshots credential-relevant DOM counts, performs a **minimal, safe**
interaction, snapshots again, and flags material increases.

Safety posture:
  * Requires the Playwright backend (``src/browser_fetch.py``); if the browser is
    unavailable the stage is skipped with a warning and the pipeline continues on
    static analysis.
  * Interaction is **navigation + scrolling only** by default. Clicking is gated
    behind ``CLICK_LOGIN_BUTTON`` (default False); when enabled, only a control
    whose visible text tightly matches a login/sign-in regex is clicked, and a
    cross-origin navigation is reverted rather than followed.
  * A hard timeout wraps the whole routine; the browser context is always closed
    (``render_page`` uses try/finally).
"""

from __future__ import annotations

import logging
import re
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from typing import Callable, List, Optional, Tuple
from urllib.parse import urlparse

from .browser_fetch import BrowserUnavailable, render_page
from .config import settings
from .schemas import DomSnapshot, DynamicAnalysisResult

logger = logging.getLogger(__name__)

# Tight login/sign-in matcher — only an exact-ish control label is clickable.
_LOGIN_TEXT_RE = re.compile(r"^\s*(log ?in|sign ?in|log ?on|sign ?on)\s*$", re.IGNORECASE)

# Counts credential-relevant DOM elements. "Hidden" = type=hidden or not rendered.
_SNAPSHOT_JS = """
() => {
  const inputs = Array.from(document.querySelectorAll('input'));
  const isHidden = (el) => {
    const t = (el.getAttribute('type') || '').toLowerCase();
    if (t === 'hidden') return true;
    const s = window.getComputedStyle(el);
    if (s.display === 'none' || s.visibility === 'hidden' || parseFloat(s.opacity || '1') === 0)
      return true;
    if (el.offsetParent === null && s.position !== 'fixed') return true;
    return false;
  };
  const pw = inputs.filter((i) => ((i.getAttribute('type') || '').toLowerCase() === 'password'));
  return {
    forms: document.querySelectorAll('form').length,
    inputs: inputs.length,
    password_fields: pw.length,
    visible_password_fields: pw.filter((i) => !isHidden(i)).length,
    hidden_inputs: inputs.filter(isHidden).length,
  };
}
"""


# ---------------------------------------------------------------------------
# Pure logic (unit-tested without a browser)
# ---------------------------------------------------------------------------
def compute_cloaking(pre: DomSnapshot, post: DomSnapshot) -> Tuple[bool, List[str]]:
    """Return ``(cloaking_detected, reasons)`` from a pre/post DOM diff.

    Uses ABSOLUTE deltas — the signal case is a password field going 0 -> 1 after
    interaction. Flags when password/form fields appear or materially increase, or
    when a previously hidden password field becomes visible.
    """
    d_password = post.password_fields - pre.password_fields
    d_forms = post.forms - pre.forms
    d_visible_pw = post.visible_password_fields - pre.visible_password_fields

    reasons: List[str] = []
    if d_password >= 1:
        reasons.append(f"{d_password} password field(s) appeared after interaction")
    if d_forms >= 1 and post.password_fields > 0:
        reasons.append(f"{d_forms} new form(s) with credential inputs appeared after interaction")
    if d_password == 0 and d_visible_pw >= 1:
        reasons.append(
            f"{d_visible_pw} previously hidden password field(s) became visible after interaction"
        )
    return bool(reasons), reasons


def _fill_deltas(result: DynamicAnalysisResult) -> None:
    result.delta_forms = result.post.forms - result.pre.forms
    result.delta_inputs = result.post.inputs - result.pre.inputs
    result.delta_password_fields = result.post.password_fields - result.pre.password_fields
    result.delta_visible_password_fields = (
        result.post.visible_password_fields - result.pre.visible_password_fields
    )
    result.cloaking_detected, result.reasons = compute_cloaking(result.pre, result.post)


# ---------------------------------------------------------------------------
# Browser steps
# ---------------------------------------------------------------------------
def _snapshot(page) -> DomSnapshot:
    data = page.evaluate(_SNAPSHOT_JS) or {}
    return DomSnapshot(
        forms=int(data.get("forms", 0)),
        inputs=int(data.get("inputs", 0)),
        password_fields=int(data.get("password_fields", 0)),
        visible_password_fields=int(data.get("visible_password_fields", 0)),
        hidden_inputs=int(data.get("hidden_inputs", 0)),
    )


def _origin(url: str) -> str:
    p = urlparse(url or "")
    return f"{p.scheme}://{p.netloc}"


def _interact(page, click_login: bool, timeout_ms: int) -> bool:
    """Minimal, safe interaction: settle, scroll in steps, optional login click."""
    try:
        page.wait_for_load_state("networkidle", timeout=timeout_ms)
    except Exception:  # noqa: BLE001 - best effort; continue with what rendered
        pass

    for fraction in (0.34, 0.67, 1.0):
        try:
            page.evaluate(
                "(f) => window.scrollTo(0, document.body.scrollHeight * f)", fraction
            )
            page.wait_for_timeout(300)
        except Exception:  # noqa: BLE001
            break

    clicked = False
    if click_login:
        clicked = _try_login_click(page, timeout_ms)

    page.wait_for_timeout(250)  # let any post-interaction JS settle
    return clicked


def _try_login_click(page, timeout_ms: int) -> bool:
    """Click a single login/sign-in BUTTON (never a link); revert cross-origin nav."""
    origin_before = _origin(page.url)
    try:
        locator = page.get_by_role("button", name=_LOGIN_TEXT_RE)
        if locator.count() == 0:
            return False
        locator.first.click(timeout=min(3000, timeout_ms))
    except Exception:  # noqa: BLE001 - click failed / not found
        return False

    try:
        page.wait_for_timeout(400)
        if _origin(page.url) != origin_before:
            # Never follow a cross-origin navigation — go back if we can.
            try:
                page.go_back(timeout=3000)
            except Exception:  # noqa: BLE001
                pass
            return False
    except Exception:  # noqa: BLE001
        return False
    return True


def _run_with_deadline(fn: Callable, timeout: float):
    executor = ThreadPoolExecutor(max_workers=1)
    try:
        return executor.submit(fn).result(timeout=timeout)
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def run_dynamic_analysis(
    url: str,
    registered_domain: str = "",
    is_trusted_domain: bool = False,
    *,
    enabled: Optional[bool] = None,
    timeout_seconds: Optional[int] = None,
    click_login: Optional[bool] = None,
    renderer: Optional[Callable] = None,
) -> DynamicAnalysisResult:
    """Render the page, diff the DOM across a safe interaction, flag cloaking.

    Never raises: a missing browser or any error/timeout yields an unavailable
    result with a note, so the pipeline continues on static analysis.
    """
    result = DynamicAnalysisResult()
    enabled = (settings.render_backend == "playwright") if enabled is None else enabled
    if not enabled:
        result.note = "Dynamic analysis disabled (render backend is not 'playwright')."
        return result
    if not url:
        result.note = "No renderable URL for dynamic analysis."
        return result

    result.checked = True
    timeout_seconds = timeout_seconds or settings.dynamic_analysis_timeout_seconds
    click_login = settings.click_login_button if click_login is None else click_login
    renderer = renderer or render_page
    timeout_ms = max(1000, int(timeout_seconds * 1000))

    def _run() -> DynamicAnalysisResult:
        r = DynamicAnalysisResult(checked=True)
        # render_page navigates (GET), waits for network-idle, and ALWAYS closes
        # the browser/context on exit (its own try/finally).
        with renderer(url, timeout_seconds) as rendered:
            page = rendered.page
            r.pre = _snapshot(page)
            r.clicked_login = _interact(page, click_login, timeout_ms)
            r.post = _snapshot(page)
        r.available = True
        _fill_deltas(r)
        return r

    try:
        computed = _run_with_deadline(_run, timeout_seconds + 4)
    except BrowserUnavailable as exc:
        logger.warning("Dynamic analysis skipped — browser unavailable (%s).", exc)
        result.note = f"Browser unavailable: {exc}"
        return result
    except (FutureTimeoutError, Exception) as exc:  # noqa: BLE001 - never crash pipeline
        logger.warning("Dynamic analysis failed (%s); skipping this stage.", exc)
        result.note = f"Dynamic analysis unavailable: {exc}"
        return result

    computed.evidence_messages = _build_evidence(computed, is_trusted_domain)
    return computed


def _build_evidence(r: DynamicAnalysisResult, is_trusted_domain: bool) -> List[str]:
    if not r.available:
        return []
    if r.cloaking_detected:
        messages = ["Dynamic cloaking detected: " + "; ".join(r.reasons) + "."]
        if is_trusted_domain:
            messages.append(
                "Domain is on the trusted allowlist, so the dynamic signal was recorded but not scored."
            )
        return messages
    return ["No credential fields appeared after interaction (no dynamic cloaking)."]
