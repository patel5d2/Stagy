"""Tests for the detection-evaluation backbone.

These pin the properties that make a reported detection figure trustworthy.
"""

import itertools
import math

import numpy as np
import pytest

from stagy.analysis import corpus
from stagy.analysis.evaluate import (
    CalibrationSet,
    evaluate,
    fit_calibration,
    fuse,
    roc,
    tpr_at_fpr,
)


def _separable(n=400, seed=0):
    rng = np.random.default_rng(seed)
    scores = np.r_[rng.normal(0.2, 0.15, n), rng.normal(0.6, 0.15, n)].tolist()
    return [0] * n + [1] * n, scores


def test_roc_starts_at_origin_and_is_monotone() -> None:
    labels, scores = _separable()
    fpr, tpr, _ = roc(labels, scores)
    assert fpr[0] == 0.0 and tpr[0] == 0.0
    assert np.all(np.diff(fpr) >= 0) and np.all(np.diff(tpr) >= 0)
    assert fpr[-1] == pytest.approx(1.0) and tpr[-1] == pytest.approx(1.0)


def test_perfect_and_random_separation() -> None:
    labels = [0] * 50 + [1] * 50
    assert evaluate("perfect", labels, [0.0] * 50 + [1.0] * 50).auc == pytest.approx(1.0)
    rng = np.random.default_rng(1)
    assert 0.35 < evaluate("noise", labels, rng.random(100).tolist()).auc < 0.65


def test_recall_grows_with_fpr_budget() -> None:
    labels, scores = _separable()
    assert tpr_at_fpr(labels, scores, 0.01)[0] <= tpr_at_fpr(labels, scores, 0.10)[0]


def test_requires_both_classes() -> None:
    with pytest.raises(ValueError):
        evaluate("bad", [1, 1, 1], [0.1, 0.2, 0.3])


def test_fpr_resolution_flags_underpowered_corpus() -> None:
    """A corpus with 12 clean files cannot express a 1% false-positive rate."""
    m = evaluate("small", [0] * 12 + [1] * 12, [0.1] * 12 + [0.9] * 12)
    assert m.fpr_resolution == pytest.approx(1 / 12)
    assert not m.resolves(0.01)
    assert m.resolves(0.10)


def test_calibration_is_monotone_and_ranking_preserving() -> None:
    """Binned calibration must not reorder cases.

    Piecewise-constant bins created ties that collapsed the fused detector to
    0% recall at a 1% FPR budget while the raw signal underneath reached 83%.
    """
    labels, scores = _separable()
    cal = fit_calibration("s", labels, scores)
    lrs = [cal.log_likelihood_ratio(s) for s in sorted(scores)]
    assert all(b >= a - 1e-9 for a, b in itertools.pairwise(lrs))

    # Calibration must not cost ranking quality. It is not bit-identical: the
    # isotonic pass pools adjacent bins, which deliberately ties scores that
    # carry equal evidence.
    raw = evaluate("raw", labels, scores)
    calibrated = evaluate("cal", labels, [cal.log_likelihood_ratio(s) for s in scores])
    assert calibrated.auc >= raw.auc - 1e-3


def test_uninformative_signal_leaves_prior_untouched() -> None:
    labels = [0] * 100 + [1] * 100
    cal = fit_calibration("flat", labels, [0.5] * 200)
    assert fuse([cal.log_likelihood_ratio(0.5)], prior=0.01) == pytest.approx(0.01)


def test_fusion_is_bayesian_not_a_max() -> None:
    """The whole reason max() fusion was wrong: it can only ratchet upward."""
    lr = math.log(19.0)
    one = fuse([lr], prior=1e-3)
    assert fuse([lr, lr], prior=1e-3) > one  # agreement strengthens
    assert fuse([lr, -lr], prior=1e-3) < one  # contradiction weakens
    assert fuse([-lr, -lr], prior=1e-3) < 1e-3  # both quiet -> below the prior


def test_base_rate_dominates_a_good_looking_detector() -> None:
    """95% recall at 5% FPR is only a ~2% posterior at a 1-in-1000 base rate."""
    assert fuse([math.log(0.95 / 0.05)], prior=1e-3) == pytest.approx(0.0186, abs=0.002)


def test_calibration_round_trips_with_provenance() -> None:
    labels, scores = _separable()
    cs = CalibrationSet(
        prior=1e-3,
        signals={"s": fit_calibration("s", labels, scores)},
        operating={"likely_stego": 0.02, "suspicious": 0.005},
        meta={"cover_source": "synthetic", "n_covers": "200"},
    )
    back = CalibrationSet.from_json(cs.to_json())
    assert back == cs
    assert back.meta["cover_source"] == "synthetic"


def test_corpus_splits_by_cover_not_by_case(tmp_path) -> None:
    """A cover's clean and stego cases must never straddle the split.

    Splitting by case leaks the answer: calibration would see the very cover it
    is later scored against.
    """
    cases = corpus.build(str(tmp_path), n_synth=8, stego_per_cover=2, seed=0)
    by_cover: dict[str, set[str]] = {}
    for c in cases:
        by_cover.setdefault(c.cover_id, set()).add(c.split)
    assert all(len(splits) == 1 for splits in by_cover.values())
    assert {c.label for c in cases} == {0, 1}
    assert {c.split for c in cases} == {"train", "test"}
