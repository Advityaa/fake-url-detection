"""Optional Playwright (headless Chromium) rendering backend for the crawler.

This is an alternative to the default GET-only ``requests``/httpx crawler in
``src/crawler.py``. It renders the page (so client-side/JS-built content is
visible) and returns a :class:`CrawlResult`, plus — via :func:`render_page` — a
live page handle later interaction features can reuse.

It never replaces the requests path: ``crawler.fetch_live`` selects the backend
from ``settings.render_backend`` and falls back to the requests crawler whenever
Playwright or the Chromium binary is unavailable.

Safety posture (matches ``src/crawler.py``):
  * **Navigation only.** ``page.goto`` to the target URL; this module never
    submits forms or clicks.
  * **Downloads blocked** (``accept_downloads=False``).
  * **Popups are not followed** — any ``window.open`` / new tab is closed
    immediately rather than navigated.
  * **Hard timeout** on navigation and on the network-idle wait (default 8s).
  * The browser context and browser are **always closed in a ``finally``**.

Heavy imports are lazy so importing this module never fails; a missing dependency
surfaces as :class:`BrowserUnavailable`, which the crawler catches to fall back.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Iterator, Optional

from .config import settings
from .schemas import CrawlResult

logger = logging.getLogger(__name__)


class BrowserUnavailable(RuntimeError):
    """Raised when Playwright or the Chromium browser cannot be used.

    Signals the crawler to fall back to the requests backend (as opposed to a
    normal navigation failure, which is returned as an unsuccessful CrawlResult).
    """


class RenderedPage:
    """Thin wrapper around a live Playwright page for reuse by later features.

    Only valid inside the :func:`render_page` context manager — the underlying
    browser/context are closed on exit.
    """

    def __init__(self, page, context) -> None:
        self.page = page
        self.context = context

    @property
    def url(self) -> str:
        return self.page.url

    def html(self) -> str:
        return self.page.content()


def _get_sync_playwright():
    """Return Playwright's ``sync_playwright`` factory, or raise BrowserUnavailable.

    Isolated so tests can monkeypatch it to simulate Playwright being absent.
    """
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # noqa: BLE001 - ImportError or driver problems
        raise BrowserUnavailable(f"Playwright is not installed: {exc}") from exc
    return sync_playwright


def _harden_context(browser, timeout_ms: int):
    """Create a restrictive, navigation-only browsing context."""
    context = browser.new_context(
        accept_downloads=False,  # never download files
        user_agent=settings.crawler_user_agent,
        java_script_enabled=True,  # the whole point of this backend is rendering
        service_workers="block",
    )
    context.set_default_timeout(timeout_ms)
    context.set_default_navigation_timeout(timeout_ms)
    # Do not follow popups / window.open — close any extra page immediately.
    context.on(
        "page",
        lambda pg: pg.close() if len(context.pages) > 1 else None,
    )
    return context


def _timeout_ms(timeout_seconds: Optional[int]) -> int:
    seconds = timeout_seconds if timeout_seconds is not None else settings.render_timeout_seconds
    return max(1000, int(seconds * 1000))


@contextmanager
def render_page(url: str, timeout_seconds: Optional[int] = None) -> Iterator[RenderedPage]:
    """Navigate to ``url`` and yield a live :class:`RenderedPage` for interaction.

    The browser, context, and Playwright driver are always shut down on exit.
    Raises :class:`BrowserUnavailable` if Playwright/Chromium is not installed.
    """
    sync_playwright = _get_sync_playwright()
    timeout_ms = _timeout_ms(timeout_seconds)
    pw = None
    browser = None
    context = None
    try:
        try:
            pw = sync_playwright().start()
            browser = pw.chromium.launch(headless=True)
        except Exception as exc:  # noqa: BLE001 - browser binary missing, etc.
            raise BrowserUnavailable(f"Chromium is not available: {exc}") from exc

        context = _harden_context(browser, timeout_ms)
        page = context.new_page()
        page.goto(url, wait_until="networkidle", timeout=timeout_ms)
        yield RenderedPage(page=page, context=context)
    finally:
        _safe_close(context, browser, pw)


def _safe_close(context, browser, pw) -> None:
    """Best-effort teardown of context/browser/driver (never raises)."""
    for closer in (
        lambda: context.close() if context else None,
        lambda: browser.close() if browser else None,
        lambda: pw.stop() if pw else None,
    ):
        try:
            closer()
        except Exception:  # noqa: BLE001 - teardown must never mask the result
            pass


def fetch_rendered(url: str, timeout_seconds: Optional[int] = None) -> CrawlResult:
    """Render ``url`` in headless Chromium and return a :class:`CrawlResult`.

    Raises :class:`BrowserUnavailable` when Playwright/Chromium is not installed
    (so the caller can fall back). Navigation/render failures with a working
    browser are returned as an unsuccessful CrawlResult, mirroring ``crawl_url``.
    """
    from .crawler import extract_title, extract_visible_text  # lazy: avoid import cycle

    sync_playwright = _get_sync_playwright()
    timeout_ms = _timeout_ms(timeout_seconds)
    pw = None
    browser = None
    context = None
    try:
        try:
            pw = sync_playwright().start()
            browser = pw.chromium.launch(headless=True)
        except Exception as exc:  # noqa: BLE001
            raise BrowserUnavailable(f"Chromium is not available: {exc}") from exc

        context = _harden_context(browser, timeout_ms)
        page = context.new_page()
        try:
            response = page.goto(url, wait_until="networkidle", timeout=timeout_ms)
            html = page.content()
            final_url = page.url
            status = response.status if response is not None else None
            redirect_chain = [final_url]
            return CrawlResult(
                requested_url=url,
                final_url=final_url,
                status_code=status,
                redirect_chain=redirect_chain,
                html=html,
                visible_text=extract_visible_text(html),
                page_title=extract_title(html),
                source="live",
                success=(status is None or status < 400),
                error=None if (status is None or status < 400) else f"HTTP {status}",
            )
        except Exception as exc:  # noqa: BLE001 - navigation/render error (browser worked)
            return CrawlResult(
                requested_url=url,
                final_url=url,
                status_code=None,
                source="live",
                success=False,
                error=f"{type(exc).__name__}: {exc}",
            )
    finally:
        _safe_close(context, browser, pw)
