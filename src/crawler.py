"""Safe webpage crawler for the phishing-rag-mvp prototype.

Safety rules enforced here:
  * GET requests only.
  * Forms are never submitted.
  * Files are never downloaded (response size is capped).
  * No JavaScript / scripts are executed; HTML is treated as inert text.
  * Bounded timeout and redirect count.
  * Exceptions are caught and reported, never raised to the UI.

The crawler can also load local sample HTML files, which gives a reliable,
offline, network-free demo mode. Live crawling is deliberately conservative.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from bs4 import BeautifulSoup

from .config import SAMPLE_HTML_DIR, settings
from .schemas import CrawlResult

# Cap how much of a response body we will read (1.5 MB). Prevents downloading
# large files and keeps the prototype responsive.
_MAX_BYTES = 1_500_000

# Map friendly sample names to local files for the Streamlit demo toggles.
SAMPLE_FILES = {
    "benign": "benign_example.html",
    "phishing": "phishing_example.html",
    "prompt_injection": "prompt_injection_example.html",
}


def extract_visible_text(html: str) -> str:
    """Extract human-visible text from an HTML document.

    Script, style, and other non-visible tags are removed first. The HTML is
    never executed; BeautifulSoup parses it purely as text.
    """
    if not html:
        return ""
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript", "template"]):
        tag.decompose()
    text = soup.get_text(separator=" ")
    # Collapse whitespace for readability.
    return " ".join(text.split())


def extract_title(html: str) -> str:
    """Extract the <title> text from an HTML document (empty string if none)."""
    if not html:
        return ""
    soup = BeautifulSoup(html, "html.parser")
    if soup.title and soup.title.string:
        return soup.title.string.strip()
    return ""


def crawl_sample(sample_key: str) -> CrawlResult:
    """Load a bundled sample HTML file as if it had been crawled.

    Args:
        sample_key: One of "benign", "phishing", "prompt_injection".

    Returns:
        A populated ``CrawlResult`` with ``source="sample"``.
    """
    filename = SAMPLE_FILES.get(sample_key)
    if filename is None:
        return CrawlResult(
            requested_url=f"sample:{sample_key}",
            final_url=f"sample:{sample_key}",
            status_code=None,
            source="sample",
            success=False,
            error=f"Unknown sample key: {sample_key!r}",
        )

    path: Path = SAMPLE_HTML_DIR / filename
    try:
        html = path.read_text(encoding="utf-8")
    except OSError as exc:
        return CrawlResult(
            requested_url=f"sample:{filename}",
            final_url=str(path),
            status_code=None,
            source="sample",
            success=False,
            error=f"Could not read sample file: {exc}",
        )

    return CrawlResult(
        requested_url=f"sample:{filename}",
        final_url=str(path),
        status_code=200,
        redirect_chain=[],
        html=html,
        visible_text=extract_visible_text(html),
        page_title=extract_title(html),
        source="sample",
        success=True,
        error=None,
    )


def crawl_url(url: str, timeout: Optional[int] = None) -> CrawlResult:
    """Safely fetch a live URL with a single bounded GET request (HTTPS-first).

    If the URL uses HTTPS and the HTTPS attempt fails with a connection/transport
    error, the crawler retries once over HTTP. The scheme of the *final* URL
    (after redirects) is what downstream scoring should rely on.

    Args:
        url: The (normalized) URL to fetch.
        timeout: Optional override for the request timeout in seconds.

    Returns:
        A populated ``CrawlResult``. On any failure ``success`` is False and
        ``error`` contains a readable message (no exception is raised).
    """
    # Imported lazily so the rest of the pipeline works even if httpx is absent.
    try:
        import httpx
    except ImportError:  # pragma: no cover - httpx is a declared dependency
        return CrawlResult(
            requested_url=url,
            final_url=url,
            status_code=None,
            source="live",
            success=False,
            error="httpx is not installed; cannot perform live crawl.",
        )

    result = _fetch_once(httpx, url, timeout)

    # HTTPS-first fallback: if the secure attempt failed to *connect* (not an
    # HTTP error response), retry over HTTP so that bare domains still work.
    if (
        not result.success
        and url.lower().startswith("https://")
        and result.status_code is None
    ):
        http_url = "http://" + url[len("https://") :]
        fallback = _fetch_once(httpx, http_url, timeout)
        if fallback.success:
            fallback.requested_url = url  # keep the originally requested URL
            return fallback
    return result


def _fetch_once(httpx_mod, url: str, timeout: Optional[int]) -> CrawlResult:
    """Perform a single bounded GET request and build a ``CrawlResult``."""
    timeout = timeout or settings.crawler_timeout_seconds
    headers = {"User-Agent": settings.crawler_user_agent, "Accept": "text/html"}
    redirect_chain: List[str] = []

    try:
        with httpx_mod.Client(
            follow_redirects=True,
            timeout=timeout,
            max_redirects=settings.crawler_max_redirects,
            headers=headers,
        ) as client:
            response = client.get(url)

            # Reconstruct the redirect chain for evidence/reporting.
            for hist in response.history:
                redirect_chain.append(str(hist.url))
            redirect_chain.append(str(response.url))

            content_type = response.headers.get("content-type", "")
            if "html" not in content_type.lower() and content_type:
                return CrawlResult(
                    requested_url=url,
                    final_url=str(response.url),
                    status_code=response.status_code,
                    redirect_chain=redirect_chain,
                    source="live",
                    success=False,
                    error=f"Non-HTML content type ('{content_type}') skipped for safety.",
                )

            # Cap the amount of HTML we keep (avoid downloading large payloads).
            html = response.text[:_MAX_BYTES]

            return CrawlResult(
                requested_url=url,
                final_url=str(response.url),
                status_code=response.status_code,
                redirect_chain=redirect_chain,
                html=html,
                visible_text=extract_visible_text(html),
                page_title=extract_title(html),
                source="live",
                success=response.status_code < 400,
                error=None if response.status_code < 400 else f"HTTP {response.status_code}",
            )
    except Exception as exc:  # noqa: BLE001 - we intentionally swallow all errors
        return CrawlResult(
            requested_url=url,
            final_url=url,
            status_code=None,
            redirect_chain=redirect_chain,
            source="live",
            success=False,
            error=f"{type(exc).__name__}: {exc}",
        )
