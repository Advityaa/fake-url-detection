"""Unit tests for the evaluation metric helpers (pure math, no network)."""

import pytest

from evaluation.metrics import (
    BAND_BENIGN,
    BAND_PHISHING,
    BAND_SUSPICIOUS,
    ConfusionCounts,
    accuracy,
    bands_to_predictions,
    confusion_counts,
    f1,
    false_positive_rate,
    precision,
    recall,
    summarize,
    summarize_bands,
)


def test_perfect_predictions():
    y_true = [1, 1, 0, 0]
    y_pred = [1, 1, 0, 0]
    c = confusion_counts(y_true, y_pred)
    assert (c.tp, c.fp, c.fn, c.tn) == (2, 0, 0, 2)
    assert precision(c) == 1.0
    assert recall(c) == 1.0
    assert f1(c) == 1.0
    assert accuracy(c) == 1.0
    assert false_positive_rate(c) == 0.0


def test_all_wrong():
    c = confusion_counts([1, 0], [0, 1])
    assert (c.tp, c.fp, c.fn, c.tn) == (0, 1, 1, 0)
    assert precision(c) == 0.0
    assert recall(c) == 0.0
    assert f1(c) == 0.0
    assert accuracy(c) == 0.0


def test_known_mixed_case():
    # 3 phishing (2 caught), 3 benign (1 flagged).
    y_true = [1, 1, 1, 0, 0, 0]
    y_pred = [1, 1, 0, 1, 0, 0]
    c = confusion_counts(y_true, y_pred)
    assert (c.tp, c.fp, c.fn, c.tn) == (2, 1, 1, 2)
    assert precision(c) == pytest.approx(2 / 3)
    assert recall(c) == pytest.approx(2 / 3)
    assert f1(c) == pytest.approx(2 / 3)
    assert accuracy(c) == pytest.approx(4 / 6)
    assert false_positive_rate(c) == pytest.approx(1 / 3)


def test_zero_division_guards():
    # Nothing predicted positive and no positive labels.
    c = ConfusionCounts(tp=0, fp=0, fn=0, tn=5)
    assert precision(c) == 0.0
    assert recall(c) == 0.0
    assert f1(c) == 0.0
    assert accuracy(c) == 1.0
    assert false_positive_rate(c) == 0.0
    assert accuracy(ConfusionCounts()) == 0.0  # fully empty


def test_length_mismatch_raises():
    with pytest.raises(ValueError):
        confusion_counts([1, 0], [1])


def test_bands_to_predictions_definitions():
    bands = [BAND_PHISHING, BAND_SUSPICIOUS, BAND_BENIGN]
    assert bands_to_predictions(bands, {BAND_PHISHING}) == [1, 0, 0]
    assert bands_to_predictions(bands, {BAND_PHISHING, BAND_SUSPICIOUS}) == [1, 1, 0]


def test_summarize_bands_reports_both_definitions():
    y_true = [1, 1, 0]
    bands = [BAND_PHISHING, BAND_SUSPICIOUS, BAND_BENIGN]
    out = summarize_bands(y_true, bands)
    # Strict definition misses the Suspicious phishing page...
    assert out["high_risk_positive"]["recall"] == pytest.approx(0.5)
    # ...the wider definition catches it.
    assert out["caution_or_high_positive"]["recall"] == pytest.approx(1.0)
    assert out["caution_or_high_positive"]["n"] == 3


def test_summarize_shape():
    out = summarize([1, 0], [1, 0])
    assert set(out) == {
        "confusion", "precision", "recall", "f1", "accuracy",
        "false_positive_rate", "n",
    }
    assert out["confusion"] == {"tp": 1, "fp": 0, "fn": 0, "tn": 1}
