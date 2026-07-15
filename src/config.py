"""Central configuration for the phishing-rag-mvp prototype.

All values are read from environment variables (optionally loaded from a local
`.env` file via python-dotenv). No secrets are hard-coded. The project is
designed to run fully offline by default (USE_LLM=false).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # pragma: no cover - dotenv is optional at runtime
    # If python-dotenv is unavailable we simply rely on the real environment.
    pass


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
DATA_DIR: Path = PROJECT_ROOT / "data"
SAMPLE_HTML_DIR: Path = DATA_DIR / "sample_html"
OUTPUTS_DIR: Path = PROJECT_ROOT / "outputs"
KNOWLEDGE_BASE_PATH: Path = DATA_DIR / "knowledge_base.json"
SAMPLE_URLS_PATH: Path = DATA_DIR / "sample_urls.csv"
# Local cache for downloaded threat-intelligence feeds (kept out of git).
THREAT_CACHE_DIR: Path = DATA_DIR / "threat_cache"
# Local persistence for the optional embedding vector index (kept out of git).
VECTOR_CACHE_DIR: Path = DATA_DIR / "vector_cache"
# Local output dir for optional multimodal screenshots (kept out of git).
SCREENSHOT_DIR: Path = OUTPUTS_DIR / "screenshots"


def _get_bool(name: str, default: bool = False) -> bool:
    """Read a boolean-like environment variable."""
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _get_int(name: str, default: int) -> int:
    """Read an integer environment variable with a safe fallback."""
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


@dataclass
class Settings:
    """Runtime settings for the prototype."""

    # LLM toggle / provider (off by default -> deterministic fallback).
    use_llm: bool = field(default_factory=lambda: _get_bool("USE_LLM", False))
    llm_provider: str = field(
        default_factory=lambda: os.getenv("LLM_PROVIDER", "anthropic").strip().lower()
    )
    anthropic_api_key: str = field(
        default_factory=lambda: os.getenv("ANTHROPIC_API_KEY", "").strip()
    )
    openai_api_key: str = field(
        default_factory=lambda: os.getenv("OPENAI_API_KEY", "").strip()
    )
    anthropic_model: str = field(
        default_factory=lambda: os.getenv("ANTHROPIC_MODEL", "claude-opus-4-8")
    )
    openai_model: str = field(
        default_factory=lambda: os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    )
    # LLM call safety limits (used only when USE_LLM=true and a key is present).
    llm_timeout_seconds: int = field(
        default_factory=lambda: _get_int("LLM_TIMEOUT_SECONDS", 20)
    )
    llm_max_tokens: int = field(default_factory=lambda: _get_int("LLM_MAX_TOKENS", 400))

    # Crawler safety settings.
    crawler_timeout_seconds: int = field(
        default_factory=lambda: _get_int("CRAWLER_TIMEOUT_SECONDS", 10)
    )
    crawler_max_redirects: int = field(
        default_factory=lambda: _get_int("CRAWLER_MAX_REDIRECTS", 5)
    )
    crawler_user_agent: str = field(
        default_factory=lambda: os.getenv(
            "CRAWLER_USER_AGENT",
            "phishing-rag-mvp-research-bot/0.1 (defensive-research; +local-prototype)",
        )
    )
    # Fetch backend for live crawling: "requests" (default; bounded GET via httpx)
    # or "playwright" (headless Chromium rendering). Falls back to "requests" if
    # Playwright/Chromium is unavailable.
    render_backend: str = field(
        default_factory=lambda: os.getenv("RENDER_BACKEND", "requests").strip().lower()
    )
    render_timeout_seconds: int = field(
        default_factory=lambda: _get_int("RENDER_TIMEOUT_SECONDS", 8)
    )
    # Dynamic-analysis (post-interaction cloaking detection) settings. Runs only
    # with the playwright render backend on live pages. Clicking is OFF by
    # default; when enabled, only a tight login/sign-in control is clicked.
    dynamic_analysis_timeout_seconds: int = field(
        default_factory=lambda: _get_int("DYNAMIC_ANALYSIS_TIMEOUT_SECONDS", 12)
    )
    click_login_button: bool = field(
        default_factory=lambda: _get_bool("CLICK_LOGIN_BUTTON", False)
    )

    # RAG settings.
    rag_top_k: int = 5
    # Retriever backend: "tfidf" (default, zero heavy deps) or "embedding"
    # (local sentence-transformer + Chroma; falls back to tfidf if unavailable).
    retriever_backend: str = field(
        default_factory=lambda: os.getenv("RETRIEVER_BACKEND", "tfidf").strip().lower()
    )
    embedding_model_name: str = field(
        default_factory=lambda: os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2").strip()
    )

    # Optional multimodal (screenshot + OCR) stage. Off by default; needs a
    # Playwright browser and an OCR engine (Tesseract). Falls back to skip if
    # those are unavailable.
    use_multimodal: bool = field(default_factory=lambda: _get_bool("USE_MULTIMODAL", False))
    multimodal_timeout_seconds: int = field(
        default_factory=lambda: _get_int("MULTIMODAL_TIMEOUT_SECONDS", 15)
    )
    # Explicit path to the Tesseract binary (e.g. a conda-forge install not on
    # PATH). Empty -> pytesseract uses "tesseract" from PATH.
    tesseract_cmd: str = field(default_factory=lambda: os.getenv("TESSERACT_CMD", "").strip())

    # Threat-intelligence settings.
    threat_intel_enabled: bool = field(
        default_factory=lambda: _get_bool("THREAT_INTEL_ENABLED", True)
    )
    openphish_feed_url: str = field(
        default_factory=lambda: os.getenv("OPENPHISH_FEED_URL", "https://openphish.com/feed.txt")
    )
    threat_cache_ttl_seconds: int = field(
        default_factory=lambda: _get_int("THREAT_CACHE_TTL_SECONDS", 6 * 60 * 60)
    )
    phishtank_api_key: str = field(
        default_factory=lambda: os.getenv("PHISHTANK_API_KEY", "").strip()
    )
    phishtank_check_url: str = field(
        default_factory=lambda: os.getenv(
            "PHISHTANK_CHECK_URL", "https://checkurl.phishtank.com/checkurl/"
        )
    )

    # Domain-reputation (WHOIS / DNS / TLS) settings.
    domain_intel_enabled: bool = field(
        default_factory=lambda: _get_bool("DOMAIN_INTEL_ENABLED", True)
    )
    domain_intel_timeout_seconds: int = field(
        default_factory=lambda: _get_int("DOMAIN_INTEL_TIMEOUT_SECONDS", 5)
    )
    new_domain_age_days: int = field(
        default_factory=lambda: _get_int("NEW_DOMAIN_AGE_DAYS", 30)
    )
    # Optional local MaxMind GeoLite2 DB for ASN/geo (low-confidence signal).
    # Empty -> geo lookups are skipped entirely (no network at all).
    geoip_db_path: str = field(default_factory=lambda: os.getenv("GEOIP_DB_PATH", "").strip())

    def llm_is_available(self) -> bool:
        """Return True only if LLM use is enabled AND a relevant key exists."""
        if not self.use_llm:
            return False
        if self.llm_provider == "anthropic":
            return bool(self.anthropic_api_key)
        if self.llm_provider == "openai":
            return bool(self.openai_api_key)
        return False


# ---------------------------------------------------------------------------
# Shared vocabulary used across modules (kept here for a single source of truth)
# ---------------------------------------------------------------------------
SUSPICIOUS_KEYWORDS: List[str] = [
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "banking",
    "wallet",
    "password",
    "credential",
    "confirm",
    "billing",
    "payment",
    "reset",
    "authentication",
]

URL_SHORTENER_DOMAINS: List[str] = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "cutt.ly",
    "ow.ly",
]

# Well-known brands frequently impersonated by phishing, mapped to the set of
# legitimate registered domains they actually use. Used for two offline signals:
#   * brand-in-URL impersonation: a brand token appears in the hostname but the
#     registered domain is NOT one of the brand's real domains.
#   * lookalike / typosquat: the registered domain core is a near-miss of a brand
#     token (edit distance / leetspeak), e.g. "paypa1", "g00gle", "arnazon".
# Generic words (e.g. "bank") are deliberately excluded to avoid false positives.
KNOWN_BRANDS: dict[str, set[str]] = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "office.com", "live.com"},
    "office365": {"office.com", "microsoft.com", "office365.com"},
    "outlook": {"outlook.com", "microsoft.com", "live.com"},
    "google": {"google.com"},
    "gmail": {"google.com", "gmail.com"},
    "apple": {"apple.com"},
    "icloud": {"icloud.com", "apple.com"},
    "amazon": {"amazon.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com"},
    "netflix": {"netflix.com"},
    "linkedin": {"linkedin.com"},
    "dropbox": {"dropbox.com"},
    "adobe": {"adobe.com"},
    "ebay": {"ebay.com"},
    "walmart": {"walmart.com"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "citibank": {"citi.com", "citibank.com"},
    "hsbc": {"hsbc.com"},
    "amex": {"americanexpress.com"},
    "americanexpress": {"americanexpress.com"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "usps": {"usps.com"},
    "ups": {"ups.com"},
    "steam": {"steampowered.com", "valvesoftware.com"},
    "discord": {"discord.com", "discordapp.com"},
    "spotify": {"spotify.com"},
    "roblox": {"roblox.com"},
    "tiktok": {"tiktok.com"},
}

# Free/consumer email providers. A registrant email at one of these is a weak
# signal on its own, but a meaningful conflict when combined with a very new
# domain or a brand-impersonating page (domain_intel conflict layer).
FREE_EMAIL_PROVIDERS: set[str] = {
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "hotmail.com",
    "outlook.com", "live.com", "msn.com", "aol.com", "icloud.com", "me.com",
    "protonmail.com", "proton.me", "gmx.com", "gmx.net", "mail.com", "zoho.com",
    "yandex.com", "yandex.ru", "tutanota.com", "hushmail.com", "fastmail.com",
}

# TLDs disproportionately abused for phishing / free-registration abuse. Presence
# adds a small amount of risk (never decisive on its own).
SUSPICIOUS_TLDS: set[str] = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "work", "click",
    "link", "country", "gdn", "kim", "loan", "men", "stream", "download",
    "racing", "win", "review", "date", "zip", "mov", "rest", "cam", "sbs",
}

# Internal classification labels (kept stable for reports / tests).
CLASS_BENIGN = "Likely Benign"
CLASS_SUSPICIOUS = "Suspicious"
CLASS_PHISHING = "Likely Phishing"

# Recalibrated thresholds (inclusive lower bound):
#   0-29  -> Likely Benign  (UI: "Likely Safe")
#   30-59 -> Suspicious     (UI: "Needs Caution")
#   60-100-> Likely Phishing(UI: "High Risk")
SUSPICIOUS_THRESHOLD = 30
PHISHING_THRESHOLD = 60

# User-friendly labels shown in the UI (internal label -> UI label).
UI_LABELS = {
    CLASS_BENIGN: "Likely Safe",
    CLASS_SUSPICIOUS: "Needs Caution",
    CLASS_PHISHING: "High Risk",
}

# Plain-English action recommendations per UI label.
ACTION_RECOMMENDATIONS = {
    CLASS_BENIGN: (
        "No major phishing indicators were found. Still verify before entering "
        "sensitive information."
    ),
    CLASS_SUSPICIOUS: (
        "Some suspicious signals were found. Avoid entering passwords or payment "
        "details unless you are sure."
    ),
    CLASS_PHISHING: (
        "Strong phishing indicators were found. Do not enter credentials or "
        "payment details."
    ),
}


def ui_label(classification: str) -> str:
    """Map an internal classification label to its user-friendly UI label."""
    return UI_LABELS.get(classification, classification)


def action_recommendation(classification: str) -> str:
    """Return the plain-English recommended action for a classification."""
    return ACTION_RECOMMENDATIONS.get(classification, "")


# Local trusted-domain allowlist (MVP demo signal only, not a security guarantee).
TRUSTED_DOMAINS_PATH: Path = DATA_DIR / "trusted_domains.json"


def load_trusted_domains() -> List[str]:
    """Load the local trusted-domain allowlist (lowercased). Empty on failure."""
    import json

    try:
        raw = TRUSTED_DOMAINS_PATH.read_text(encoding="utf-8")
        data = json.loads(raw)
        if isinstance(data, dict):
            data = data.get("domains", [])
        return [str(d).strip().lower() for d in data if str(d).strip()]
    except (OSError, ValueError):
        return []


# A single shared settings instance used by the app and modules.
settings = Settings()
