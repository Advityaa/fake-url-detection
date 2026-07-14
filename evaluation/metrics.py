"""Pure metric helpers for the evaluation harness.

Kept dependency-free (no sklearn) so the math is explicit, auditable, and unit
tested. Convention: the POSITIVE class is "phishing" (label 1); benign is 0.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Dict, List, Sequence, Set

# Internal classification labels produced by the risk engine.
BAND_PHISHING = "Likely Phishing"   # score 60-100 (UI: High Risk)
BAND_SUSPICIOUS = "Suspicious"      # score 30-59  (UI: Needs Caution)
BAND_BENIGN = "Likely Benign"       # score 0-29   (UI: Likely Safe)

# The two positive-prediction definitions reported side by side.
POSITIVE_DEFINITIONS: Dict[str, Set[str]] = {
    "high_risk_positive": {BAND_PHISHING},
    "caution_or_high_positive": {BAND_PHISHING, BAND_SUSPICIOUS},
}


@dataclass
class ConfusionCounts:
    """2x2 confusion-matrix counts (positive class = phishing)."""

    tp: int = 0  # phishing predicted phishing
    fp: int = 0  # benign predicted phishing
    fn: int = 0  # phishing predicted benign
    tn: int = 0  # benign predicted benign

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.fn + self.tn

    def to_dict(self) -> Dict[str, int]:
        return asdict(self)


def bands_to_predictions(bands: Sequence[str], positive_bands: Set[str]) -> List[int]:
    """Map classification bands to binary predictions (1 = phishing)."""
    return [1 if band in positive_bands else 0 for band in bands]


def confusion_counts(y_true: Sequence[int], y_pred: Sequence[int]) -> ConfusionCounts:
    """Count the 2x2 confusion matrix. Sequences must be equal length."""
    if len(y_true) != len(y_pred):
        raise ValueError(f"length mismatch: {len(y_true)} labels vs {len(y_pred)} predictions")
    c = ConfusionCounts()
    for t, p in zip(y_true, y_pred):
        if t == 1 and p == 1:
            c.tp += 1
        elif t == 0 and p == 1:
            c.fp += 1
        elif t == 1 and p == 0:
            c.fn += 1
        else:
            c.tn += 1
    return c


def precision(c: ConfusionCounts) -> float:
    """TP / (TP + FP); 0.0 when nothing was predicted positive."""
    denom = c.tp + c.fp
    return c.tp / denom if denom else 0.0


def recall(c: ConfusionCounts) -> float:
    """TP / (TP + FN); 0.0 when there are no positive labels."""
    denom = c.tp + c.fn
    return c.tp / denom if denom else 0.0


def f1(c: ConfusionCounts) -> float:
    """Harmonic mean of precision and recall; 0.0 when both are 0."""
    p, r = precision(c), recall(c)
    return 2 * p * r / (p + r) if (p + r) else 0.0


def accuracy(c: ConfusionCounts) -> float:
    """(TP + TN) / total; 0.0 on an empty set."""
    return (c.tp + c.tn) / c.total if c.total else 0.0


def false_positive_rate(c: ConfusionCounts) -> float:
    """FP / (FP + TN); 0.0 when there are no negative labels."""
    denom = c.fp + c.tn
    return c.fp / denom if denom else 0.0


def summarize(y_true: Sequence[int], y_pred: Sequence[int]) -> Dict:
    """Compute all metrics for one (labels, predictions) pairing."""
    c = confusion_counts(y_true, y_pred)
    return {
        "confusion": c.to_dict(),
        "precision": round(precision(c), 4),
        "recall": round(recall(c), 4),
        "f1": round(f1(c), 4),
        "accuracy": round(accuracy(c), 4),
        "false_positive_rate": round(false_positive_rate(c), 4),
        "n": c.total,
    }


def summarize_bands(y_true: Sequence[int], bands: Sequence[str]) -> Dict[str, Dict]:
    """Compute metrics under every positive-prediction definition."""
    return {
        name: summarize(y_true, bands_to_predictions(bands, positive))
        for name, positive in POSITIVE_DEFINITIONS.items()
    }
