"""Tests for Sample Pair Analysis (roadmap Task 6.3).

Acceptance criteria under test:
  * estimated rate tracks actual embedding rate across 10/25/50/100% fill
  * near-zero estimate on clean images
  * catches keyed embedding (the gap chi-square leaves)
  * independently agrees with RS analysis — the point of a second estimator
  * saturation is reported as saturation, never as "clean"
"""

import itertools
import os

import numpy as np
import pytest
from PIL import Image

import stagy
from stagy.analysis import corpus, rs_analysis, sample_pairs
from stagy.analysis.sample_pairs import _solve_rate


def _cover(path: str, seed: int = 3) -> None:
    corpus.synth_cover(path, seed=seed)


def _capacity(path: str) -> int:
    from stagy.codecs import CODECS

    return int(CODECS["image"].capacity(path, bits=1, channels="RGB"))


def _embed(cover: str, dest: str, rate: float, mode: str) -> None:
    n = int(_capacity(cover) * rate) - 96  # container overhead
    stagy.hide(cover, os.urandom(n), dest, passphrase="pw", mode=mode)


def test_clean_image_estimates_near_zero(tmp_path) -> None:
    p = tmp_path / "clean.png"
    _cover(str(p))
    assert sample_pairs.analyze(str(p)).rate < 0.10


@pytest.mark.parametrize("mode", ["keyed", "sequential"])
def test_estimate_tracks_embedding_rate(tmp_path, mode) -> None:
    clean = tmp_path / "clean.png"
    _cover(str(clean))

    estimates = []
    for rate in (0.10, 0.25, 0.50, 1.00):
        dest = tmp_path / f"{mode}_{int(rate * 100)}.png"
        _embed(str(clean), str(dest), rate, mode)
        estimates.append(sample_pairs.analyze(str(dest)).rate)

    assert all(b >= a - 0.10 for a, b in itertools.pairwise(estimates))
    assert estimates[1] == pytest.approx(0.25, abs=0.15)  # 25% fill
    assert estimates[2] == pytest.approx(0.50, abs=0.20)  # 50% fill


def test_catches_keyed_embedding(tmp_path) -> None:
    clean = tmp_path / "clean.png"
    _cover(str(clean))
    keyed = tmp_path / "keyed.png"
    _embed(str(clean), str(keyed), 0.25, "keyed")

    clean_sp = sample_pairs.analyze(str(clean)).rate
    keyed_sp = sample_pairs.analyze(str(keyed)).rate
    assert keyed_sp > clean_sp + 0.10


def test_agrees_with_rs_analysis(tmp_path) -> None:
    """Two independent structural estimators must land in the same neighbourhood.

    That agreement is the entire justification for running a second one — it is
    what turns a single noisy estimate into a confident verdict.
    """
    clean = tmp_path / "clean.png"
    _cover(str(clean))
    stego = tmp_path / "stego.png"
    _embed(str(clean), str(stego), 0.50, "keyed")

    sp = sample_pairs.analyze(str(stego)).rate
    rs = rs_analysis.analyze(str(stego)).rate
    assert abs(sp - rs) < 0.15


def test_saturated_solver_does_not_report_clean() -> None:
    """A negative discriminant means saturation, never absence of embedding."""
    # Fully degenerate (all counts zero): must saturate, not read clean.
    rate0, deg0 = _solve_rate(x=0, y=0, k=0, n=0)
    assert deg0 and rate0 == 1.0
    # Negative discriminant (4ac > b^2, c > 0): the trace curves have already
    # met, which only happens as embedding saturates. Must saturate to full.
    rate1, deg1 = _solve_rate(x=50, y=60, k=1000, n=100)
    assert deg1 and rate1 == 1.0


def test_tiny_image_is_not_fitted(tmp_path) -> None:
    p = tmp_path / "tiny.png"
    Image.fromarray(np.zeros((4, 4, 3), dtype=np.uint8), "RGB").save(p)
    res = sample_pairs.analyze(str(p))
    assert res.per_channel == []
    assert res.rate == 0.0


def test_sample_pairs_is_a_report_signal(tmp_path) -> None:
    from stagy.analysis import report

    clean = tmp_path / "clean.png"
    _cover(str(clean))
    names = {s.name for s in report.raw_signals(str(clean))}
    assert "sample-pairs" in names
