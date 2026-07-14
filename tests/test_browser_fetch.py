"""Tests for the optional Playwright render backend and its safe fallback.

Playwright is fully mocked — no real browser is launched — so these run anywhere.
The key guarantees checked: the requests path is used by default, the pipeline
falls back cleanly when Playwright/Chromium is unavailable, the rendered path
returns a CrawlResult with a hardened (downloads-blocked) context, and the
browser is always torn down.
"""

import src.browser_fetch as bf
import src.crawler as crawler
from src.browser_fetch import BrowserUnavailable, fetch_rendered
from src.schemas import CrawlResult


# ---------------------------------------------------------------------------
# Minimal fake Playwright stack
# ---------------------------------------------------------------------------
class _FakeResponse:
    def __init__(self, status):
        self.status = status


class _FakePage:
    def __init__(self, response=None, html="<html></html>", url="https://example.test/", goto_exc=None):
        self._response, self._html, self._url, self._goto_exc = response, html, url, goto_exc

    def goto(self, url, wait_until=None, timeout=None):
        if self._goto_exc:
            raise self._goto_exc
        return self._response

    def content(self):
        return self._html

    @property
    def url(self):
        return self._url


class _FakeContext:
    def __init__(self, page):
        self._page = page
        self.pages = []
        self.kwargs = None
        self.closed = False

    def new_page(self):
        self.pages.append(self._page)
        return self._page

    def set_default_timeout(self, *_):
        pass

    def set_default_navigation_timeout(self, *_):
        pass

    def on(self, *_):
        pass

    def close(self):
        self.closed = True


class _FakeBrowser:
    def __init__(self, context):
        self._context = context
        self.closed = False

    def new_context(self, **kwargs):
        self._context.kwargs = kwargs
        return self._context

    def close(self):
        self.closed = True


class _FakeChromium:
    def __init__(self, browser, launch_exc=None):
        self._browser, self._launch_exc = browser, launch_exc

    def launch(self, headless=True):
        if self._launch_exc:
            raise self._launch_exc
        return self._browser


class _FakePW:
    def __init__(self, browser, launch_exc=None):
        self.chromium = _FakeChromium(browser, launch_exc)
        self.stopped = False

    def stop(self):
        self.stopped = True


def _install_fake_playwright(monkeypatch, pw):
    class _SyncPW:
        def start(self_inner):
            return pw

    monkeypatch.setattr(bf, "_get_sync_playwright", lambda: (lambda: _SyncPW()))


def _make_stack(page):
    context = _FakeContext(page)
    browser = _FakeBrowser(context)
    return _FakePW(browser), browser, context


# ---------------------------------------------------------------------------
# fetch_rendered — happy path, safety, cleanup
# ---------------------------------------------------------------------------
def test_fetch_rendered_returns_crawlresult_and_tears_down(monkeypatch):
    page = _FakePage(response=_FakeResponse(200), html="<html><title>Hi</title>x</html>",
                     url="https://example.test/final")
    pw, browser, context = _make_stack(page)
    _install_fake_playwright(monkeypatch, pw)

    result = fetch_rendered("https://example.test/", timeout_seconds=5)

    assert isinstance(result, CrawlResult)
    assert result.success is True
    assert result.status_code == 200
    assert result.final_url == "https://example.test/final"
    assert result.source == "live"
    assert "Hi" == result.page_title
    # Safety: downloads blocked in the browser context.
    assert context.kwargs["accept_downloads"] is False
    # Cleanup always happened.
    assert context.closed and browser.closed and pw.stopped


def test_fetch_rendered_navigation_error_returns_failed_result(monkeypatch):
    page = _FakePage(goto_exc=RuntimeError("Timeout 8000ms exceeded"))
    pw, browser, context = _make_stack(page)
    _install_fake_playwright(monkeypatch, pw)

    result = fetch_rendered("https://slow.test/", timeout_seconds=1)
    # A working browser with a nav failure -> unsuccessful result, NOT BrowserUnavailable.
    assert result.success is False
    assert "Timeout" in (result.error or "")
    assert context.closed and browser.closed and pw.stopped  # still cleaned up


def test_fetch_rendered_raises_browser_unavailable_when_playwright_missing(monkeypatch):
    def boom():
        raise BrowserUnavailable("Playwright is not installed")

    monkeypatch.setattr(bf, "_get_sync_playwright", boom)
    try:
        fetch_rendered("https://x.test/")
        assert False, "expected BrowserUnavailable"
    except BrowserUnavailable:
        pass


def test_fetch_rendered_raises_browser_unavailable_when_chromium_missing(monkeypatch):
    page = _FakePage(response=_FakeResponse(200))
    context = _FakeContext(page)
    browser = _FakeBrowser(context)
    pw = _FakePW(browser, launch_exc=RuntimeError("Executable doesn't exist; run `playwright install`"))
    _install_fake_playwright(monkeypatch, pw)

    try:
        fetch_rendered("https://x.test/")
        assert False, "expected BrowserUnavailable"
    except BrowserUnavailable:
        pass
    assert pw.stopped  # driver still stopped


# ---------------------------------------------------------------------------
# crawler.fetch_live — backend selection + fallback
# ---------------------------------------------------------------------------
def test_fetch_live_uses_requests_by_default(monkeypatch):
    monkeypatch.setattr(crawler.settings, "render_backend", "requests")
    sentinel = CrawlResult(requested_url="u", final_url="u", status_code=200, source="live", success=True)
    monkeypatch.setattr(crawler, "crawl_url", lambda url, timeout=None: sentinel)
    # If the browser path were taken, this would blow up the test.
    monkeypatch.setattr(bf, "fetch_rendered", lambda *a, **k: (_ for _ in ()).throw(AssertionError("browser used")))

    assert crawler.fetch_live("https://x.test/") is sentinel


def test_fetch_live_falls_back_when_browser_unavailable(monkeypatch):
    monkeypatch.setattr(crawler.settings, "render_backend", "playwright")
    sentinel = CrawlResult(requested_url="u", final_url="u", status_code=200, source="live", success=True)
    monkeypatch.setattr(crawler, "crawl_url", lambda url, timeout=None: sentinel)

    def unavailable(*_a, **_k):
        raise BrowserUnavailable("no chromium")

    monkeypatch.setattr(bf, "fetch_rendered", unavailable)

    # Falls back to the requests crawler cleanly — no exception propagates.
    assert crawler.fetch_live("https://x.test/") is sentinel


def test_fetch_live_uses_playwright_when_available(monkeypatch):
    monkeypatch.setattr(crawler.settings, "render_backend", "playwright")
    rendered = CrawlResult(requested_url="u", final_url="u", status_code=200,
                           source="live", success=True, html="<rendered>")
    monkeypatch.setattr(bf, "fetch_rendered", lambda url, timeout=None: rendered)
    monkeypatch.setattr(crawler, "crawl_url",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not fall back")))

    assert crawler.fetch_live("https://x.test/") is rendered


# ---------------------------------------------------------------------------
# Pipeline end-to-end with the playwright backend unavailable
# ---------------------------------------------------------------------------
def test_pipeline_runs_end_to_end_when_playwright_unavailable(monkeypatch):
    from src.domain_intel import DomainIntelClient
    from src.pipeline import analyze_url
    from src.rag_retriever import RAGRetriever

    monkeypatch.setattr(crawler.settings, "render_backend", "playwright")
    monkeypatch.setattr(bf, "fetch_rendered",
                        lambda *a, **k: (_ for _ in ()).throw(BrowserUnavailable("no chromium")))
    # Stub the requests fallback so the test does no network I/O.
    sample = CrawlResult(
        requested_url="https://x.test/", final_url="https://x.test/", status_code=200,
        redirect_chain=["https://x.test/"], html="<html><body>hello</body></html>",
        visible_text="hello", page_title="", source="live", success=True,
    )
    monkeypatch.setattr(crawler, "crawl_url", lambda url, timeout=None: sample)

    result = analyze_url("https://x.test/", "live", retriever=RAGRetriever(),
                         trusted_domains=[], enable_threat_intel=False,
                         domain_client=DomainIntelClient(enabled=False))
    assert result is not None
    assert result.classification  # pipeline completed via the fallback crawler
    assert result.crawl.final_url == "https://x.test/"
