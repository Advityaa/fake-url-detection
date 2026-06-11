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
        default_factory=lambda: os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-latest")
    )
    openai_model: str = field(
        default_factory=lambda: os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    )

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

    # RAG settings.
    rag_top_k: int = 5

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
    "office365": {"office.com", "microsoft.com"},
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
