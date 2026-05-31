"""HTML / visible-text analysis for phishing signals.

Parses an HTML document (inertly, never executing it) and extracts structural
and lexical signals: forms, password fields, credential-request language,
external links, scripts, and brand-like words. Produces human-readable evidence
messages used by the risk engine and explainer.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from .config import SUSPICIOUS_KEYWORDS
from .schemas import BrandCheckResult, HTMLAnalysisResult
from .utils import count_occurrences

# Phrases that indicate the page is asking for credentials / sensitive data.
CREDENTIAL_REQUEST_PATTERNS = [
    "password",
    "username",
    "login",
    "sign in",
    "account verification",
    "verify your account",
    "security check",
    "payment information",
    "card number",
    "credit card",
    "cvv",
    "otp",
    "one time password",
    "one-time password",
    "social security",
]

# A small list of well-known brand-like tokens used ONLY to flag possible
# brand impersonation in page text. These are generic words, not real targets.
_BRAND_LIKE_WORDS = [
    "paypal",
    "microsoft",
    "google",
    "apple",
    "amazon",
    "facebook",
    "netflix",
    "bank",
    "wallet",
    "coinbase",
    "outlook",
    "office365",
]

_BRAND_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9]{2,}")


def _is_external_link(href: str, base_host: str) -> bool:
    """Return True if an href points to a different host than the page."""
    if not href:
        return False
    href = href.strip()
    if href.startswith(("#", "mailto:", "tel:", "javascript:")):
        return False
    parsed = urlparse(href)
    if not parsed.netloc:
        return False  # relative link -> same host
    if not base_host:
        return True
    return parsed.netloc.lower() != base_host.lower()


def analyze_html(html: str, visible_text: str = "", base_url: str = "") -> HTMLAnalysisResult:
    """Analyze an HTML document and its visible text.

    Args:
        html: Raw HTML string.
        visible_text: Pre-extracted visible text (falls back to parsing html).
        base_url: The page URL, used to classify links as external.

    Returns:
        A populated ``HTMLAnalysisResult`` with evidence messages.
    """
    result = HTMLAnalysisResult()
    if not html:
        result.evidence_messages.append("No HTML content was available to analyze.")
        return result

    soup = BeautifulSoup(html, "html.parser")
    base_host = urlparse(base_url).netloc if base_url else ""

    # Title.
    if soup.title and soup.title.string:
        result.page_title = soup.title.string.strip()

    # Meta description.
    meta = soup.find("meta", attrs={"name": "description"})
    if meta and meta.get("content"):
        result.meta_description = meta["content"].strip()

    # Forms and inputs.
    forms = soup.find_all("form")
    result.number_of_forms = len(forms)

    inputs = soup.find_all("input")
    result.number_of_input_fields = len(inputs)
    result.number_of_password_fields = sum(
        1 for inp in inputs if (inp.get("type") or "").lower() == "password"
    )

    # Links and scripts.
    links = soup.find_all("a", href=True)
    result.number_of_external_links = sum(
        1 for a in links if _is_external_link(a.get("href", ""), base_host)
    )
    result.number_of_script_tags = len(soup.find_all("script"))

    # Use provided visible text or derive it.
    if not visible_text:
        for tag in soup(["script", "style", "noscript", "template"]):
            tag.decompose()
        visible_text = " ".join(soup.get_text(separator=" ").split())

    haystack = f"{result.page_title} {result.meta_description} {visible_text}".lower()

    # Suspicious keywords (shared vocabulary) found in page text.
    result.suspicious_keywords_found = count_occurrences(haystack, SUSPICIOUS_KEYWORDS)

    # Credential-request patterns.
    found_patterns = count_occurrences(haystack, CREDENTIAL_REQUEST_PATTERNS)
    result.credential_patterns_found = found_patterns
    result.credential_request_detected = bool(found_patterns) or (
        result.number_of_password_fields > 0
    )

    # Brand-like words present in the page text.
    result.brand_like_words = sorted(set(count_occurrences(haystack, _BRAND_LIKE_WORDS)))

    result.evidence_messages = _build_evidence(result)
    return result


def check_brand_domain(
    detected_brands: list[str], registered_domain: str
) -> BrandCheckResult:
    """Compare brand-like words found on the page with the registered domain.

    Logic:
      * If a detected brand word appears inside the registered domain name, this
        is a *match* (the page brand is consistent with where it is hosted).
      * If a detected brand word is present but does NOT appear in the registered
        domain, this is a *possible mismatch* (a hallmark of impersonation).

    Args:
        detected_brands: Brand-like words found in the page text.
        registered_domain: The page's registered domain, e.g. "amazon.com".

    Returns:
        A populated ``BrandCheckResult``.
    """
    result = BrandCheckResult(
        detected_brands=sorted(set(detected_brands)),
        registered_domain=registered_domain or "",
    )

    domain_core = (registered_domain or "").split(".")[0].lower()

    if not result.detected_brands:
        result.evidence_messages.append(
            "No well-known brand names were detected on the page."
        )
        return result

    matched = [b for b in result.detected_brands if b.lower() in domain_core]
    unmatched = [b for b in result.detected_brands if b.lower() not in domain_core]

    if matched:
        result.brand_domain_match = True
        result.evidence_messages.append(
            "Displayed brand appears to match the registered domain "
            f"('{', '.join(matched)}' vs '{registered_domain}')."
        )

    # Only flag a mismatch when a brand is present but none matched the domain.
    if unmatched and not matched:
        result.possible_brand_mismatch = True
        result.evidence_messages.append(
            "Displayed brand does not match the registered domain "
            f"('{', '.join(unmatched)}' vs '{registered_domain}'); possible impersonation."
        )

    return result


def _build_evidence(r: HTMLAnalysisResult) -> list[str]:
    """Build readable evidence messages from the analysis result."""
    messages: list[str] = []

    if r.page_title:
        messages.append(f"Page title: '{r.page_title}'.")
    if r.number_of_password_fields > 0:
        messages.append(
            f"Page contains {r.number_of_password_fields} password input field(s)."
        )
    if r.number_of_forms > 1:
        messages.append(f"Page contains multiple forms ({r.number_of_forms}).")
    elif r.number_of_forms == 1:
        messages.append("Page contains a form.")
    if r.credential_request_detected and r.credential_patterns_found:
        messages.append(
            "Page requests credentials/sensitive data: "
            + ", ".join(r.credential_patterns_found)
            + "."
        )
    if len(r.suspicious_keywords_found) >= 3:
        messages.append(
            "Page contains multiple login/security-related keywords: "
            + ", ".join(r.suspicious_keywords_found)
            + "."
        )
    if r.brand_like_words:
        messages.append(
            "Page mentions brand-like words (possible impersonation): "
            + ", ".join(r.brand_like_words)
            + "."
        )
    if r.number_of_external_links >= 10:
        messages.append(
            f"Page has many external links ({r.number_of_external_links})."
        )
    if r.number_of_script_tags >= 10:
        messages.append(f"Page has many script tags ({r.number_of_script_tags}).")

    if not messages:
        messages.append("No strong phishing signals were found in the page content.")
    return messages
