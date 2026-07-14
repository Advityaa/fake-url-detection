"""External threat-intelligence lookups (OpenPhish + optional PhishTank).

This module checks a URL/domain against known-phishing feeds:

  * **OpenPhish** — a public feed of phishing URLs is downloaded and cached
    locally (``data/threat_cache/``) with a timestamp. It is only refreshed when
    the cache is older than a configurable TTL (default 6 hours), so we neither
    hammer their servers nor break the demo when offline.
  * **PhishTank** — if an API key is configured in ``.env`` its URL-check API is
    queried; otherwise PhishTank is skipped and only the cached OpenPhish feed is
    used.

Safety posture (consistent with the rest of the project):
  * Read-only, GET/POST-for-lookup only; no crawling of malicious targets.
  * Never raises to the caller: any network/parse failure is logged as a warning
    and yields a "no threat-intel data" result.
  * No real malicious URLs are bundled in the repo; the feed is fetched/cached at
    runtime and git-ignored.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Callable, List, Optional, Set, Tuple
from urllib.parse import urlparse

import tldextract

from .config import THREAT_CACHE_DIR, settings
from .schemas import ThreatIntelResult

logger = logging.getLogger(__name__)

# tldextract configured to avoid network calls (uses the bundled snapshot).
_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

_OPENPHISH = "OpenPhish"
_PHISHTANK = "PhishTank"


def _registered_domain(hostname: str) -> str:
    """Return the registered domain (e.g. ``a.b.example.co.uk`` -> ``example.co.uk``)."""
    if not hostname:
        return ""
    ext = _EXTRACTOR(hostname)
    return ".".join(p for p in [ext.domain, ext.suffix] if p).lower()


def _norm_url(url: str) -> str:
    """Normalize a URL for comparison (scheme-insensitive, no trailing slash)."""
    url = (url or "").strip().lower()
    if not url:
        return ""
    if "://" in url:
        url = url.split("://", 1)[1]
    return url.rstrip("/")


class ThreatIntelClient:
    """Checks URLs/domains against the OpenPhish feed (cached) and PhishTank.

    Args:
        cache_dir: Directory for the cached feed (defaults to config).
        ttl_seconds: How long a cached feed is considered fresh.
        openphish_url: Feed URL to download.
        phishtank_api_key: If set, PhishTank's URL-check API is used.
        fetcher: Optional ``callable(url) -> str`` used to download the feed;
            injected in tests so no network access ever occurs.
        enabled: If False, all lookups short-circuit to "not checked".
    """

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        ttl_seconds: Optional[int] = None,
        openphish_url: Optional[str] = None,
        phishtank_api_key: Optional[str] = None,
        fetcher: Optional[Callable[[str], str]] = None,
        enabled: Optional[bool] = None,
    ) -> None:
        self.cache_dir = Path(cache_dir or THREAT_CACHE_DIR)
        self.ttl_seconds = ttl_seconds if ttl_seconds is not None else settings.threat_cache_ttl_seconds
        self.openphish_url = openphish_url or settings.openphish_feed_url
        self.phishtank_api_key = (
            phishtank_api_key if phishtank_api_key is not None else settings.phishtank_api_key
        )
        self.enabled = settings.threat_intel_enabled if enabled is None else enabled
        self._fetcher = fetcher or self._default_fetcher

        self._loaded = False
        self._urls: Set[str] = set()
        self._hosts: Set[str] = set()
        self._domains: Set[str] = set()

    # ------------------------------------------------------------------ feed I/O
    @property
    def _feed_path(self) -> Path:
        return self.cache_dir / "openphish_feed.txt"

    @property
    def _meta_path(self) -> Path:
        return self.cache_dir / "openphish_meta.json"

    def _default_fetcher(self, url: str) -> str:
        """Download the feed with a single bounded GET request."""
        import httpx  # local import so the rest works without a live network

        headers = {"User-Agent": settings.crawler_user_agent}
        # follow_redirects: OpenPhish's feed URL 302-redirects to its GitHub-hosted copy.
        resp = httpx.get(
            url,
            timeout=settings.crawler_timeout_seconds,
            headers=headers,
            follow_redirects=True,
        )
        resp.raise_for_status()
        return resp.text

    def _cache_is_fresh(self) -> bool:
        try:
            meta = json.loads(self._meta_path.read_text(encoding="utf-8"))
            age = time.time() - float(meta.get("fetched_at", 0))
            return age < self.ttl_seconds and self._feed_path.exists()
        except (OSError, ValueError):
            return False

    def _read_cache(self) -> Optional[str]:
        try:
            return self._feed_path.read_text(encoding="utf-8")
        except OSError:
            return None

    def _write_cache(self, text: str) -> None:
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            self._feed_path.write_text(text, encoding="utf-8")
            self._meta_path.write_text(
                json.dumps({"fetched_at": time.time(), "source_url": self.openphish_url}),
                encoding="utf-8",
            )
        except OSError as exc:  # pragma: no cover - unusual FS failure
            logger.warning("Could not write threat-intel cache: %s", exc)

    def _get_feed_text(self) -> str:
        """Return feed text, refreshing from the network only when stale.

        Falls back to a stale cache when the network is unreachable, and to an
        empty feed when there is nothing cached — never raises.
        """
        if self._cache_is_fresh():
            cached = self._read_cache()
            if cached is not None:
                return cached

        try:
            text = self._fetcher(self.openphish_url)
            self._write_cache(text)
            return text
        except Exception as exc:  # noqa: BLE001 - intentionally never propagate
            logger.warning("OpenPhish feed unreachable (%s); using cached copy if available.", exc)
            stale = self._read_cache()
            return stale if stale is not None else ""

    def _ensure_loaded(self) -> bool:
        """Populate the in-memory lookup sets. Returns True if any data loaded."""
        if self._loaded:
            return bool(self._urls or self._hosts)
        text = self._get_feed_text()
        self._parse_feed(text)
        self._loaded = True
        return bool(self._urls or self._hosts)

    def _parse_feed(self, text: str) -> None:
        for line in (text or "").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            self._urls.add(_norm_url(line))
            host = (urlparse(line).hostname or "").lower()
            if host:
                self._hosts.add(host)
                dom = _registered_domain(host)
                if dom:
                    self._domains.add(dom)

    def feed_urls(self) -> List[str]:
        """Return the raw phishing URLs from the (cached) OpenPhish feed.

        Public accessor used by the evaluation harness to derive ground-truth
        phishing labels. Refreshes the cache only per the normal TTL rules.
        """
        text = self._get_feed_text()
        return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]

    def cache_fetched_at(self) -> Optional[float]:
        """Unix timestamp of when the cached feed was fetched, or None."""
        try:
            meta = json.loads(self._meta_path.read_text(encoding="utf-8"))
            fetched = float(meta.get("fetched_at", 0))
            return fetched or None
        except (OSError, ValueError):
            return None

    # ------------------------------------------------------------------ PhishTank
    def _check_phishtank(self, url: str) -> Optional[Tuple[bool, str]]:
        """Query PhishTank's URL-check API. Returns (listed, note) or None.

        None means PhishTank was not consulted (no key or an error). Never raises.
        """
        if not self.phishtank_api_key:
            return None
        try:
            import base64
            import httpx

            encoded = base64.b64encode(url.encode("utf-8")).decode("ascii")
            data = {"url": encoded, "format": "json", "app_key": self.phishtank_api_key}
            headers = {"User-Agent": settings.crawler_user_agent}
            resp = httpx.post(
                settings.phishtank_check_url,
                data=data,
                headers=headers,
                timeout=settings.crawler_timeout_seconds,
            )
            resp.raise_for_status()
            results = resp.json().get("results", {})
            in_db = bool(results.get("in_database"))
            valid = str(results.get("valid", "")).lower() == "true"
            if in_db and valid:
                return True, "Verified phishing entry in PhishTank."
            return False, "Not present in PhishTank."
        except Exception as exc:  # noqa: BLE001 - never propagate
            logger.warning("PhishTank lookup failed (%s); skipping.", exc)
            return None

    # ------------------------------------------------------------------ public
    def check(self, url: str, registered_domain: str = "") -> ThreatIntelResult:
        """Check a URL/domain against the configured threat feeds.

        Args:
            url: The (final) URL to check.
            registered_domain: The URL's registered domain (optional; derived if
                omitted) used for domain-level feed matches.

        Returns:
            A :class:`ThreatIntelResult`. ``checked`` is False when threat intel
            is disabled or no feed data was available.
        """
        result = ThreatIntelResult()
        if not self.enabled:
            result.confidence_note = "Threat-intelligence lookups are disabled."
            result.evidence_messages = []
            return result

        if not registered_domain:
            registered_domain = _registered_domain(urlparse(_ensure_scheme(url)).hostname or "")
        target_url = _norm_url(url)
        target_host = (urlparse(_ensure_scheme(url)).hostname or "").lower()
        target_domain = (registered_domain or "").lower()

        # --- PhishTank (optional, exact-URL, authoritative) ---
        pt = self._check_phishtank(url)
        if pt is not None:
            result.checked = True
            result.sources_checked.append(_PHISHTANK)
            listed, note = pt
            if listed:
                result.listed = True
                result.source = _PHISHTANK
                result.matched_value = target_url
                result.confidence_note = note
                result.evidence_messages = [
                    f"URL is listed as phishing in {_PHISHTANK}."
                ]
                return result

        # --- OpenPhish (cached feed) ---
        has_data = self._ensure_loaded()
        if has_data:
            result.checked = True
            result.sources_checked.append(_OPENPHISH)
            if target_url and target_url in self._urls:
                result.listed = True
                result.matched_value = target_url
                result.confidence_note = "Exact URL match in the OpenPhish feed (high confidence)."
            elif target_host and target_host in self._hosts:
                result.listed = True
                result.matched_value = target_host
                result.confidence_note = "Host matches an entry in the OpenPhish feed (high confidence)."
            elif target_domain and target_domain in self._domains:
                result.listed = True
                result.matched_value = target_domain
                result.confidence_note = (
                    "Registered domain matches an OpenPhish entry (medium confidence; "
                    "another URL on this domain was reported)."
                )
            if result.listed:
                result.source = _OPENPHISH
                result.evidence_messages = [
                    f"URL/domain appears in the {_OPENPHISH} phishing feed "
                    f"(match: {result.matched_value})."
                ]

        if not result.checked:
            result.confidence_note = (
                "No threat-intelligence data was available (feed offline and no cache)."
            )
        elif not result.listed and not result.confidence_note:
            result.confidence_note = "Not found in the consulted threat feed(s)."
        return result


def _ensure_scheme(url: str) -> str:
    """Add a scheme if missing so ``urlparse`` extracts the hostname correctly."""
    url = (url or "").strip()
    if url and "://" not in url:
        return "https://" + url
    return url


# ---------------------------------------------------------------------------
# Module-level shared client (so the cached feed is loaded once per process).
# ---------------------------------------------------------------------------
_default_client: Optional[ThreatIntelClient] = None


def get_default_client() -> ThreatIntelClient:
    global _default_client
    if _default_client is None:
        _default_client = ThreatIntelClient()
    return _default_client


def check_threat_intel(url: str, registered_domain: str = "") -> ThreatIntelResult:
    """Convenience wrapper using the shared default client."""
    return get_default_client().check(url, registered_domain)
