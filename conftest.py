"""Pytest configuration: ensure the project root is importable as ``src``."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def _hermetic_runtime(monkeypatch):
    """Keep the whole suite offline and deterministic regardless of the local
    ``.env``.

    The live-demo config enables ``USE_LLM=true`` and ``RENDER_BACKEND=playwright``
    (and ``.env`` may hold a real API key). Those values are loaded into the shared
    ``settings`` at import time, so without this fixture the suite could make a real
    LLM call or launch Chromium. Every test starts from the offline baseline; tests
    that exercise the LLM or the browser opt back in explicitly (e.g. by patching
    ``settings.use_llm`` / ``settings.render_backend`` themselves).
    """
    from src.config import settings

    monkeypatch.setattr(settings, "use_llm", False, raising=False)
    monkeypatch.setattr(settings, "render_backend", "requests", raising=False)
