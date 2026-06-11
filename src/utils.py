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


# Common "leetspeak" digit-for-letter substitutions used in lookalike domains
# (e.g. "paypa1", "g00gle", "amaz0n", "micr0s0ft").
_LEET_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b"})


def normalize_leetspeak(text: str) -> str:
    """Fold common digit-for-letter substitutions back to letters.

    Used to catch typosquatting domains that swap digits for similar-looking
    letters (``paypa1`` -> ``paypal``). Returns a lowercased, letters-only string.
    """
    if not text:
        return ""
    folded = text.lower().translate(_LEET_MAP)
    return "".join(ch for ch in folded if ch.isalpha())


def levenshtein(a: str, b: str) -> int:
    """Compute the Levenshtein (edit) distance between two strings.

    A small, dependency-free implementation used for lookalike/typosquat
    detection. Returns the number of single-character insertions, deletions or
    substitutions needed to turn ``a`` into ``b``.
    """
    a = a or ""
    b = b or ""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            insert = current[j - 1] + 1
            delete = previous[j] + 1
            substitute = previous[j - 1] + (ca != cb)
            current.append(min(insert, delete, substitute))
        previous = current
    return previous[-1]
