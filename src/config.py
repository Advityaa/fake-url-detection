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

# Risk classification thresholds (inclusive lower bound).
CLASS_BENIGN = "Likely Benign"
CLASS_SUSPICIOUS = "Suspicious"
CLASS_PHISHING = "Likely Phishing"

SUSPICIOUS_THRESHOLD = 40
PHISHING_THRESHOLD = 70

# A single shared settings instance used by the app and modules.
settings = Settings()
