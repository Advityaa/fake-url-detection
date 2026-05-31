"""Small, dependency-light helper utilities shared across modules."""

from __future__ import annotations

import math
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Iterable, List


_WORD_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9]{2,}")


def shannon_entropy(text: str) -> float:
    """Compute the Shannon entropy (in bits) of a string.

    Higher entropy can indicate random-looking / machine-generated hostnames,
    which is a weak phishing signal. Returns 0.0 for empty input.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return round(entropy, 4)


def utc_timestamp() -> str:
    """Return an ISO-8601 UTC timestamp string (deterministic format)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def safe_filename_stamp() -> str:
    """Return a filesystem-safe timestamp suitable for output file names."""
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def tokenize_words(text: str) -> List[str]:
    """Extract lowercase word tokens (length >= 3) from arbitrary text."""
    if not text:
        return []
    return [match.group(0).lower() for match in _WORD_RE.finditer(text)]


def count_occurrences(text: str, keywords: Iterable[str]) -> List[str]:
    """Return the subset of ``keywords`` that appear (case-insensitive) in text."""
    if not text:
        return []
    lowered = text.lower()
    found = []
    for keyword in keywords:
        if keyword.lower() in lowered:
            found.append(keyword)
    return found


def truncate(text: str, max_length: int = 160) -> str:
    """Truncate text for compact display, appending an ellipsis if needed."""
    if text is None:
        return ""
    text = text.strip()
    if len(text) <= max_length:
        return text
    return text[: max_length - 1].rstrip() + "…"
