"""Domain-reputation signals: WHOIS age, DNS records, TLS certificate.

Three independent, read-only lookups for a domain:

  * **WHOIS** (``python-whois``) — domain creation date → age in days. Newly
    registered domains (default < 30 days, configurable) are a well-known
    phishing signal.
  * **DNS** (``dnspython``) — does the domain resolve (A record)? Does it have
    MX records? Many phishing domains have no mail setup.
  * **TLS** (stdlib ``ssl``) — for HTTPS URLs: certificate issuer, validity
    window, and whether the certificate verifies (self-signed/expired certs
    fail verification).

Reliability posture: WHOIS in particular is flaky and can hang, so **every
lookup runs in a worker thread with a hard timeout** (default 5s, configurable).
Any timeout or error yields a clean "unavailable" flag on the result — the
pipeline is never blocked and never sees an exception from this module.

Testability: the three lookups are injectable callables on
:class:`DomainIntelClient`, so unit tests mock them and never touch the network.
"""

from __future__ import annotations

import logging
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from datetime import datetime, timezone
from typing import Callable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

from .config import FREE_EMAIL_PROVIDERS, KNOWN_BRANDS, settings
from .schemas import DomainIntelResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Conflict names (stable identifiers used by the risk engine for scoring).
# ---------------------------------------------------------------------------
CONFLICT_BRAND_DOMAIN_MISMATCH = "brand_domain_mismatch"
CONFLICT_FREE_EMAIL_REGISTRANT = "free_email_registrant"
CONFLICT_VERY_NEW_DOMAIN = "very_new_domain"
CONFLICT_FREE_EMAIL_AND_NEW_DOMAIN = "free_email_and_new_domain"
CONFLICT_IMPERSONATION_WEAK_CERT = "impersonation_with_weak_cert"
CONFLICT_GEO_REGISTRANT_MISMATCH = "geo_registrant_mismatch"


# ---------------------------------------------------------------------------
# Timeout harness
# ---------------------------------------------------------------------------
def _run_with_timeout(fn: Callable, timeout: float):
    """Run ``fn()`` in a worker thread, raising on timeout.

    ``python-whois`` offers no timeout control and can hang on some registries,
    so the thread is abandoned (daemonized by the executor) if it overruns.
    """
    executor = ThreadPoolExecutor(max_workers=1)
    try:
        future = executor.submit(fn)
        return future.result(timeout=timeout)
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


# ---------------------------------------------------------------------------
# Real lookup implementations (each easily replaced in tests)
# ---------------------------------------------------------------------------
def _first(value):
    """WHOIS fields are frequently lists; return the first meaningful scalar."""
    if isinstance(value, (list, tuple)):
        return next((v for v in value if v), None)
    return value


def _whois_lookup(domain: str) -> dict:
    """Return WHOIS details: creation_date, registrar, country, email.

    (An injected ``whois_fn`` may instead return a bare ``datetime`` — the client
    normalizes that legacy shape too.)
    """
    import whois  # local import: only needed when a real lookup runs

    record = whois.whois(domain)
    created = _first(record.creation_date) if record else None
    if isinstance(created, str):
        try:
            created = datetime.fromisoformat(created)
        except ValueError:
            created = None
    email = _first(getattr(record, "emails", None)) or ""
    return {
        "creation_date": created if isinstance(created, datetime) else None,
        "registrar": str(_first(getattr(record, "registrar", None)) or ""),
        "country": str(_first(getattr(record, "country", None)) or ""),
        "email": str(email),
    }


def _geo_lookup(domain: str, timeout: float) -> Optional[dict]:
    """Best-effort ASN / IP-country lookup via a LOCAL GeoLite2 DB.

    Returns ``None`` (and the caller records nothing) unless a local DB is
    configured via ``GEOIP_DB_PATH`` and the ``geoip2`` library is installed.
    Resolving the IP is the only network step; everything else is local.
    """
    db_path = settings.geoip_db_path
    if not db_path:
        return None
    try:
        import socket as _socket

        import geoip2.database

        ip = _socket.gethostbyname(domain)
        with geoip2.database.Reader(db_path) as reader:
            country = reader.country(ip).country.iso_code or ""
        return {"ip_country": country, "asn_org": ""}
    except Exception:  # noqa: BLE001 - optional signal; skip on any problem
        return None


def _dns_records(domain: str, timeout: float) -> Tuple[bool, bool]:
    """Return ``(resolves, has_mx)`` for a domain.

    NXDOMAIN / empty answers are *data* (False), not errors; only transport
    failures (timeouts, no nameservers reachable) raise.
    """
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout

    def _query(rtype: str) -> bool:
        try:
            answer = resolver.resolve(domain, rtype)
            return len(answer) > 0
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return False

    resolves = _query("A")
    has_mx = _query("MX")
    return resolves, has_mx


def _tls_certificate(hostname: str, timeout: float) -> dict:
    """Inspect the TLS certificate served on ``hostname:443``.

    Returns a dict with issuer/validity/valid/self_signed keys. A certificate
    that fails verification is reported (valid=False) rather than raised.
    """
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls:
                cert = tls.getpeercert() or {}
        issuer_parts = dict(x[0] for x in cert.get("issuer", ()))
        subject_parts = dict(x[0] for x in cert.get("subject", ()))
        not_before = cert.get("notBefore", "")
        not_after = cert.get("notAfter", "")
        currently_valid = True  # default-context handshake => verified chain + dates
        return {
            "issuer": issuer_parts.get("organizationName")
            or issuer_parts.get("commonName", ""),
            "org": subject_parts.get("organizationName", ""),  # OV/EV subject org
            "valid_from": not_before,
            "valid_until": not_after,
            "valid": currently_valid,
            "self_signed": False,
        }
    except ssl.SSLCertVerificationError as exc:
        message = (getattr(exc, "verify_message", "") or str(exc)).lower()
        return {
            "issuer": "",
            "org": "",
            "valid_from": "",
            "valid_until": "",
            "valid": False,
            "self_signed": "self-signed" in message or "self signed" in message,
        }


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------
class DomainIntelClient:
    """Gathers WHOIS / DNS / TLS reputation signals for a domain.

    Args:
        timeout: Per-lookup timeout in seconds (defaults to config).
        new_age_days: "Newly registered" threshold in days (defaults to config).
        enabled: If False, :meth:`gather` short-circuits to "not checked".
        whois_fn / dns_fn / tls_fn: Injectable lookup callables (tests use these
            so no real network call ever happens).
    """

    def __init__(
        self,
        timeout: Optional[float] = None,
        new_age_days: Optional[int] = None,
        enabled: Optional[bool] = None,
        whois_fn: Optional[Callable[[str], object]] = None,
        dns_fn: Optional[Callable[[str, float], Tuple[bool, bool]]] = None,
        tls_fn: Optional[Callable[[str, float], dict]] = None,
        geo_fn: Optional[Callable[[str, float], Optional[dict]]] = None,
    ) -> None:
        self.timeout = timeout if timeout is not None else settings.domain_intel_timeout_seconds
        self.new_age_days = (
            new_age_days if new_age_days is not None else settings.new_domain_age_days
        )
        self.enabled = settings.domain_intel_enabled if enabled is None else enabled
        self._whois_fn = whois_fn or _whois_lookup
        self._dns_fn = dns_fn or _dns_records
        self._tls_fn = tls_fn or _tls_certificate
        self._geo_fn = geo_fn or _geo_lookup

    # ------------------------------------------------------------------
    def gather(
        self,
        url: str,
        registered_domain: str,
        page_brands: Optional[Sequence[str]] = None,
    ) -> DomainIntelResult:
        """Collect all available reputation signals for a URL's domain, then tally
        cross-signal conflicts.

        Never raises; each failed/timed-out lookup just leaves its
        ``*_available`` flag False. ``page_brands`` are brand names detected on the
        page (e.g. ``html_analysis.brand_like_words``), used by the conflict layer.
        """
        result = DomainIntelResult(domain=(registered_domain or "").lower())
        if not self.enabled or not result.domain:
            result.evidence_messages = []
            return result
        result.checked = True

        self._gather_whois(result)
        self._gather_dns(result)

        parsed = urlparse(url if "://" in (url or "") else f"https://{url or ''}")
        if parsed.scheme == "https" and parsed.hostname:
            self._gather_tls(result, parsed.hostname)

        self._gather_geo(result)

        # Novel layer: tally logical contradictions across the gathered signals.
        result.conflicts = compute_conflicts(result, page_brands)
        result.conflict_count = len(result.conflicts)

        result.evidence_messages = _build_evidence(result)
        return result

    # ------------------------------------------------------------------
    def _gather_whois(self, result: DomainIntelResult) -> None:
        try:
            raw = _run_with_timeout(lambda: self._whois_fn(result.domain), self.timeout)
        except (FutureTimeoutError, Exception) as exc:  # noqa: BLE001 - never propagate
            logger.warning("WHOIS lookup failed for %s: %s", result.domain, exc)
            return
        if raw is None:
            return
        # Accept the rich dict shape or a legacy bare datetime (creation date).
        info = raw if isinstance(raw, dict) else {"creation_date": raw}
        created = info.get("creation_date")

        result.registrar = str(info.get("registrar") or "")
        result.registrant_country = str(info.get("country") or "")
        result.registrant_email = str(info.get("email") or "")

        if isinstance(created, datetime):
            # Normalize to aware-UTC (WHOIS libraries return a mix of naive/aware).
            created = (
                created.replace(tzinfo=timezone.utc)
                if created.tzinfo is None
                else created.astimezone(timezone.utc)
            )
            age_days = max(0, (datetime.now(timezone.utc) - created).days)
            result.domain_created = created.date().isoformat()
            result.domain_age_days = age_days
            result.is_newly_registered = age_days < self.new_age_days

        # Available if we learned anything at all from WHOIS.
        result.whois_available = bool(
            result.domain_created or result.registrar or result.registrant_email
            or result.registrant_country
        )

    def _gather_dns(self, result: DomainIntelResult) -> None:
        try:
            resolves, has_mx = _run_with_timeout(
                lambda: self._dns_fn(result.domain, self.timeout), self.timeout + 1
            )
        except (FutureTimeoutError, Exception) as exc:  # noqa: BLE001
            logger.warning("DNS lookup failed for %s: %s", result.domain, exc)
            return
        result.dns_available = True
        result.resolves = resolves
        result.has_mx = has_mx

    def _gather_tls(self, result: DomainIntelResult, hostname: str) -> None:
        try:
            cert = _run_with_timeout(
                lambda: self._tls_fn(hostname, self.timeout), self.timeout + 1
            )
        except (FutureTimeoutError, Exception) as exc:  # noqa: BLE001
            logger.warning("TLS inspection failed for %s: %s", hostname, exc)
            return
        result.tls_available = True
        result.cert_issuer = cert.get("issuer", "")
        result.cert_org = cert.get("org", "")
        result.cert_valid_from = cert.get("valid_from", "")
        result.cert_valid_until = cert.get("valid_until", "")
        result.cert_currently_valid = cert.get("valid")
        result.cert_self_signed = cert.get("self_signed")

    def _gather_geo(self, result: DomainIntelResult) -> None:
        try:
            geo = _run_with_timeout(
                lambda: self._geo_fn(result.domain, self.timeout), self.timeout + 1
            )
        except (FutureTimeoutError, Exception) as exc:  # noqa: BLE001
            logger.warning("Geo lookup failed for %s: %s", result.domain, exc)
            return
        if not geo:
            return
        result.asn_available = True
        result.ip_country = str(geo.get("ip_country") or "")
        result.asn_org = str(geo.get("asn_org") or "")


def compute_conflicts(
    result: DomainIntelResult, page_brands: Optional[Sequence[str]] = None
) -> List[str]:
    """Tally logical contradictions across the gathered signals (the novel layer).

    Pure and evidence-conditioned: a conflict only fires when the underlying data
    was actually observed. Returns the list of conflict names that fired (the
    risk engine maps these to weights; strong combinations high, geo low).
    """
    conflicts: List[str] = []
    registered = (result.domain or "").lower()

    # 1. Page claims a known brand, but the domain isn't that brand's.
    brand_mismatch = False
    for raw in page_brands or []:
        brand = str(raw).lower()
        legit = KNOWN_BRANDS.get(brand)
        if legit and registered and registered not in legit:
            brand_mismatch = True
            break
    if brand_mismatch:
        conflicts.append(CONFLICT_BRAND_DOMAIN_MISMATCH)

    # 2. Registrant uses a free/consumer email provider.
    free_email = False
    if result.whois_available and result.registrant_email and "@" in result.registrant_email:
        provider = result.registrant_email.rsplit("@", 1)[-1].lower().strip()
        if provider in FREE_EMAIL_PROVIDERS:
            free_email = True
            conflicts.append(CONFLICT_FREE_EMAIL_REGISTRANT)

    # 3. Very new domain.
    very_new = bool(result.whois_available and result.is_newly_registered)
    if very_new:
        conflicts.append(CONFLICT_VERY_NEW_DOMAIN)

    # 4. Strong combo: free-email registrant AND a very new domain.
    if free_email and very_new:
        conflicts.append(CONFLICT_FREE_EMAIL_AND_NEW_DOMAIN)

    # 5. Page impersonates a brand while the cert is weak/anonymous.
    #    Only meaningful when we actually inspected a certificate.
    weak_cert = result.tls_available and (
        bool(result.cert_self_signed)
        or result.cert_currently_valid is False
        or not result.cert_org
    )
    if brand_mismatch and weak_cert:
        conflicts.append(CONFLICT_IMPERSONATION_WEAK_CERT)

    # 6. (LOW) Hosting country differs from registrant country.
    if (
        result.asn_available
        and result.ip_country
        and result.registrant_country
        and result.ip_country.lower() != result.registrant_country.lower()
    ):
        conflicts.append(CONFLICT_GEO_REGISTRANT_MISMATCH)

    return conflicts


def _build_evidence(r: DomainIntelResult) -> list[str]:
    """Human-readable evidence messages (only for data actually observed)."""
    messages: list[str] = []
    if r.whois_available:
        if r.is_newly_registered:
            messages.append(
                f"Domain was registered only {r.domain_age_days} day(s) ago "
                f"({r.domain_created}); newly registered domains are a common phishing signal."
            )
        else:
            messages.append(
                f"Domain has existed for {r.domain_age_days} days (registered {r.domain_created})."
            )
    else:
        messages.append("WHOIS data not available (lookup failed or timed out).")

    if r.dns_available:
        if not r.resolves:
            messages.append("Domain does not resolve to any address (no A record).")
        if r.resolves and not r.has_mx:
            messages.append(
                "Domain has no MX (mail) records; many phishing domains skip mail setup."
            )
    else:
        messages.append("DNS data not available (lookup failed or timed out).")

    if r.tls_available:
        if r.cert_currently_valid:
            issuer = f" (issuer: {r.cert_issuer})" if r.cert_issuer else ""
            messages.append(f"HTTPS certificate verified successfully{issuer}.")
        elif r.cert_self_signed:
            messages.append("HTTPS certificate is self-signed (fails verification).")
        else:
            messages.append("HTTPS certificate failed verification (expired or untrusted).")

    if r.conflict_count:
        messages.append(
            f"Cross-signal conflicts detected ({r.conflict_count}): "
            + ", ".join(r.conflicts)
            + "."
        )
    return messages


# ---------------------------------------------------------------------------
# Module-level shared client
# ---------------------------------------------------------------------------
_default_client: Optional[DomainIntelClient] = None


def get_default_client() -> DomainIntelClient:
    global _default_client
    if _default_client is None:
        _default_client = DomainIntelClient()
    return _default_client


def gather_domain_intel(
    url: str, registered_domain: str, page_brands: Optional[Sequence[str]] = None
) -> DomainIntelResult:
    """Convenience wrapper using the shared default client."""
    return get_default_client().gather(url, registered_domain, page_brands=page_brands)
