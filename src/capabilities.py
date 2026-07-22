"""Single source of truth for which OPTIONAL analysis stages are available.

Both UIs use this to render stage toggles: whether a stage can be enabled (its
dependencies are installed / a key is set), its default on/off state (from
``settings``), and a short reason when it is unavailable. The FastAPI app exposes
it at ``/api/capabilities``; the Streamlit app imports it directly. There is only
one dependency-check path — the UIs never re-implement it.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
from typing import Dict

from .config import settings


def _importable(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except Exception:  # noqa: BLE001 - a broken module path counts as unavailable
        return False


def _ocr_present() -> bool:
    if _importable("easyocr"):
        return True
    cmd = settings.tesseract_cmd or "tesseract"
    if os.path.sep in cmd:
        return os.path.exists(cmd)
    return shutil.which(cmd) is not None


def llm_key_present() -> bool:
    """True if a provider API key is configured (independent of USE_LLM)."""
    if settings.llm_provider == "anthropic":
        return bool(settings.anthropic_api_key)
    if settings.llm_provider == "openai":
        return bool(settings.openai_api_key)
    if settings.llm_provider == "gemini":
        return bool(settings.gemini_api_key)
    return False


def _cap(available: bool, default: bool, reason: str = "") -> Dict:
    return {"available": bool(available), "default": bool(default), "reason": "" if available else reason}


def capabilities() -> Dict[str, Dict]:
    """Return per-stage ``{available, default, reason}`` for the optional stages."""
    playwright = _importable("playwright")
    ocr = _ocr_present()
    embedding = _importable("sentence_transformers") and _importable("chromadb")

    return {
        "threat_intel": _cap(True, settings.threat_intel_enabled),
        "domain_intel": _cap(True, settings.domain_intel_enabled),
        "render_playwright": _cap(
            playwright, settings.render_backend == "playwright",
            "Playwright not installed (pip install playwright && playwright install chromium)",
        ),
        "dynamic": _cap(
            playwright, settings.render_backend == "playwright",
            "needs the Playwright render backend",
        ),
        "multimodal": _cap(
            playwright and ocr, settings.use_multimodal,
            "needs Playwright + an OCR engine (EasyOCR or Tesseract)",
        ),
        "embedding": _cap(
            embedding, settings.retriever_backend == "embedding",
            "needs sentence-transformers + chromadb",
        ),
        "llm": _cap(
            llm_key_present(), settings.use_llm,
            "no LLM API key set in .env",
        ),
    }
