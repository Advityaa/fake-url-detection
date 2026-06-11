"""URL normalization and feature extraction.

This module turns a raw user-supplied URL into a structured ``URLFeatureResult``
containing lexical features that are useful (weak) signals for phishing
detection, plus human-readable evidence messages.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse, urlunparse

import tldextract

from .config import (
    KNOWN_BRANDS,
    SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_TLDS,
    URL_SHORTENER_DOMAINS,
)
from .schemas import URLFeatureResult
from .utils import levenshtein, normalize_leetspeak, shannon_entropy

# tldextract instance configured to avoid network calls (uses bundled snapshot).
_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def normalize_url(url: str) -> str:
    """Normalize a URL into a canonical form.

    - Strips surrounding whitespace.
    - Adds an ``https://`` scheme if none was provided (HTTPS-first), so a bare
      domain like ``amazon.com`` is not immediately penalised as insecure. The
      crawler falls back to HTTP only if HTTPS is unreachable.
    - Lowercases the scheme and hostname (path/query left untouched).
    """
    if url is None:
        return ""
    url = url.strip()
    if not url:
        return ""

    # Add a scheme if the user typed a bare domain like "example.com/login".
    # HTTPS-first: assume secure transport unless proven otherwise.
    if "://" not in url:
        url = "https://" + url

    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()

    normalized = urlunparse(
        (scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)
    )
    return normalized


def _contains_ip_address(hostname: str) -> bool:
    """Return True if the hostname is a raw IP address (IPv4 or IPv6)."""
    if not hostname:
        return False
    host = hostname.strip("[]")  # IPv6 literals are wrapped in brackets.
    if _IPV4_RE.match(host):
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _contains_punycode(hostname: str) -> bool:
    """Return True if any hostname label uses punycode ("xn--")."""
    return "xn--" in (hostname or "").lower()


def _host_tokens(hostname: str) -> list[str]:
    """Split a hostname into lowercase word tokens (on dots and hyphens)."""
    if not hostname:
        return []
    return [t for t in re.split(r"[.\-]", hostname.lower()) if t]


# Phishy affixes that, glued onto a brand token, indicate impersonation
# (e.g. "paypalsecure", "applesupport"). Used to allow boundary-less matches
# without false-positiving on unrelated words like "applebees".
_BRAND_AFFIXES = {
    "login", "signin", "secure", "verify", "account", "accounts", "support",
    "help", "update", "confirm", "online", "auth", "portal", "billing", "pay",
    "payment", "service", "services", "team", "alert", "security", "id", "center",
}


def detect_brand_impersonation(hostname: str, registered_domain: str) -> str:
    """Detect a known brand appearing in the host of a non-brand domain.

    Returns the impersonated brand token if a known brand appears in the hostname
    (subdomain or domain core) but the registered domain is NOT one of that
    brand's legitimate domains (e.g. ``paypal.secure-login.net``,
    ``paypalsecure.com``). Returns "" when the registered domain legitimately
    belongs to the brand, or when the brand only appears as part of an unrelated
    word (e.g. ``applebees.com``).
    """
    if not hostname:
        return ""
    registered = (registered_domain or "").lower()
    tokens = _host_tokens(hostname)
    # Also compare leetspeak-folded tokens so "g00gle" / "paypa1" are caught.
    folded_tokens = [(tok, normalize_leetspeak(tok)) for tok in tokens]
    for brand, legit_domains in KNOWN_BRANDS.items():
        if registered in legit_domains:
            continue  # genuinely the brand's own domain (any subdomain is fine)
        for tok, folded in folded_tokens:
            # Whole-label match: "paypal" in "paypal.secure-login.net" (or "g00gle").
            if tok == brand or folded == brand:
                return brand
            # Brand glued to a known phishy affix: "paypalsecure", "applesupport".
            if tok.startswith(brand) and tok[len(brand):] in _BRAND_AFFIXES:
                return brand
            if tok.endswith(brand) and tok[: -len(brand)] in _BRAND_AFFIXES:
                return brand
    return ""


def detect_lookalike_brand(registered_domain: str) -> str:
    """Detect a registered domain core that is a near-miss of a known brand.

    Catches typosquats via leetspeak folding (``paypa1`` -> ``paypal``) and an
    edit-distance-1 check (``arnazon`` vs ``amazon``), while skipping the brand's
    own legitimate domains. Returns the brand token, or "".
    """
    registered = (registered_domain or "").lower()
    core = registered.split(".")[0]
    if len(core) < 4:
        return ""
    folded = normalize_leetspeak(core)
    for brand, legit_domains in KNOWN_BRANDS.items():
        if registered in legit_domains or core == brand or len(brand) < 4:
            continue
        # Leetspeak match (a digit was swapped for a look-alike letter): strong,
        # low-false-positive signal — "paypa1"->"paypal", "g00gle"->"google".
        if folded == brand and folded != core:
            return brand
        # Edit-distance-1 typo on a longer brand of the same length and first
        # letter ("paypol" vs "paypal"). Restricted to brands >= 6 chars to avoid
        # false positives on short, common-letter words ("ample" vs "apple").
        if (
            len(brand) >= 6
            and len(core) == len(brand)
            and core[0] == brand[0]
            and levenshtein(core, brand) == 1
        ):
            return brand
    return ""


def extract_url_features(url: str) -> URLFeatureResult:
    """Extract lexical features and evidence messages from a URL.

    Args:
        url: The raw URL string supplied by the user.

    Returns:
        A populated ``URLFeatureResult``.
    """
    original_url = (url or "").strip()
    normalized = normalize_url(original_url)
    parsed = urlparse(normalized)

    hostname = parsed.hostname or ""
    scheme = parsed.scheme or ""
    path = parsed.path or ""
    query = parsed.query or ""

    extracted = _EXTRACTOR(hostname)
    domain = extracted.domain or ""
    suffix = extracted.suffix or ""
    subdomain = extracted.subdomain or ""

    # Subdomain count (e.g. "a.b.example.com" -> 2 subdomains).
    number_of_subdomains = len([p for p in subdomain.split(".") if p]) if subdomain else 0

    contains_ip = _contains_ip_address(hostname)
    contains_at = "@" in original_url
    contains_puny = _contains_punycode(hostname)
    uses_https = scheme == "https"

    suspicious_found = sorted(
        {
            kw
            for kw in SUSPICIOUS_KEYWORDS
            if kw.lower() in normalized.lower()
        }
    )
    # Keywords appearing in the HOSTNAME specifically are far more indicative of
    # phishing than keywords in the path (legitimate sites routinely use paths
    # like "/login" or "/account"). Scored separately to cut false positives.
    host_lower = hostname.lower()
    suspicious_in_host = sorted(
        {kw for kw in SUSPICIOUS_KEYWORDS if kw.lower() in host_lower}
    )

    registered_domain = ".".join(p for p in [domain, suffix] if p)
    is_shortened = registered_domain.lower() in URL_SHORTENER_DOMAINS

    impersonated_brand = detect_brand_impersonation(hostname, registered_domain)
    lookalike_brand = detect_lookalike_brand(registered_domain)
    suspicious_tld = suffix.lower().split(".")[-1] in SUSPICIOUS_TLDS if suffix else False

    entropy = shannon_entropy(hostname)

    features = URLFeatureResult(
        original_url=original_url,
        normalized_url=normalized,
        scheme=scheme,
        hostname=hostname,
        domain=domain,
        suffix=suffix,
        path=path,
        query=query,
        url_length=len(normalized),
        hostname_length=len(hostname),
        number_of_dots=normalized.count("."),
        number_of_hyphens=normalized.count("-"),
        number_of_digits=sum(ch.isdigit() for ch in normalized),
        number_of_subdomains=number_of_subdomains,
        contains_ip_address=contains_ip,
        contains_at_symbol=contains_at,
        contains_punycode=contains_puny,
        uses_https=uses_https,
        suspicious_keywords_found=suspicious_found,
        suspicious_keywords_in_host=suspicious_in_host,
        is_shortened_url=is_shortened,
        entropy_score=entropy,
        registered_domain=registered_domain,
        impersonated_brand=impersonated_brand,
        lookalike_brand=lookalike_brand,
        suspicious_tld=suspicious_tld,
    )

    features.evidence_messages = _build_evidence(features)
    return features


def _build_evidence(f: URLFeatureResult) -> list[str]:
    """Build human-readable evidence messages from extracted features."""
    messages: list[str] = []

    if f.impersonated_brand:
        messages.append(
            f"URL references the brand '{f.impersonated_brand}' but is not hosted on that "
            f"brand's official domain (registered domain: '{f.registered_domain}'); "
            "a hallmark of brand impersonation."
        )
    if f.lookalike_brand:
        messages.append(
            f"Registered domain looks like a misspelling of '{f.lookalike_brand}' "
            "(possible typosquatting / lookalike domain)."
        )
    if f.suspicious_tld:
        messages.append(
            f"Domain uses a top-level domain ('.{f.suffix}') frequently abused for phishing."
        )
    if f.contains_ip_address:
        messages.append("URL uses a raw IP address instead of a domain name.")
    if f.contains_at_symbol:
        messages.append("URL contains an '@' symbol, which can hide the real destination.")
    if f.contains_punycode:
        messages.append("Hostname uses punycode ('xn--'), a common homoglyph/spoofing trick.")
    if not f.uses_https:
        messages.append("URL does not use HTTPS (no transport encryption).")
    if f.is_shortened_url:
        messages.append(f"URL uses a known link shortener ('{f.domain}.{f.suffix}').")
    if f.number_of_subdomains > 3:
        messages.append(
            f"URL has many subdomains ({f.number_of_subdomains}), which can be used to look legitimate."
        )
    if f.url_length > 75:
        messages.append(f"URL is long ({f.url_length} characters).")
    if f.suspicious_keywords_found:
        messages.append(
            "URL contains suspicious keywords: " + ", ".join(f.suspicious_keywords_found) + "."
        )
    if f.entropy_score >= 4.0:
        messages.append(
            f"Hostname has high character entropy ({f.entropy_score}), which can indicate a random/generated domain."
        )

    if not messages:
        messages.append("No obvious suspicious lexical features were found in the URL.")
    return messages
