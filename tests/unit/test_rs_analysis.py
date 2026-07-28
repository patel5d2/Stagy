"""Tests for RS analysis (roadmap Task 6.2).

Acceptance criteria under test:
  * estimated length tracks actual embedding rate across 10/25/50/100% fill
  * near-zero estimate on clean images
  * catches *keyed* embedding, which is the gap chi-square leaves
"""

import itertools
import os

import numpy as np
import pytest
from PIL import Image

import stagy
from stagy.analysis import corpus, rs_analysis
from stagy.analysis.rs_analysis import _flip, _solve_rate


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
    assert rs_analysis.analyze(str(p)).rate < 0.10


@pytest.mark.parametrize("mode", ["keyed", "sequential"])
def test_estimate_tracks_embedding_rate(tmp_path, mode) -> None:
    """The roadmap's acceptance criterion: the estimate must track actual fill."""
    clean = tmp_path / "clean.png"
    _cover(str(clean))

    estimates = []
    for rate in (0.10, 0.25, 0.50, 1.00):
        dest = tmp_path / f"{mode}_{int(rate * 100)}.png"
        _embed(str(clean), str(dest), rate, mode)
        estimates.append(rs_analysis.analyze(str(dest)).rate)

    # Monotone in embedding rate, with slack for estimator noise.
    assert all(b >= a - 0.10 for a, b in itertools.pairwise(estimates))
    # And the estimate must be in the right neighbourhood, not merely ordered.
    assert estimates[1] == pytest.approx(0.25, abs=0.15)  # 25% fill
    assert estimates[2] == pytest.approx(0.50, abs=0.20)  # 50% fill


def test_catches_keyed_embedding_that_chi_square_misses(tmp_path) -> None:
    """The entire reason this analyzer exists.

    Chi-square reads the histogram, so keyed scattering hides from it (measured:
    9% recall at 5% fill). RS reads spatial correlation of the LSB plane, which
    keyed placement does not disturb.
    """
    from stagy.analysis import chi_square

    clean = tmp_path / "clean.png"
    _cover(str(clean))
    keyed = tmp_path / "keyed.png"
    _embed(str(clean), str(keyed), 0.25, "keyed")

    clean_rs = rs_analysis.analyze(str(clean)).rate
    keyed_rs = rs_analysis.analyze(str(keyed)).rate
    assert keyed_rs > clean_rs + 0.10  # RS separates them clearly

    # Chi-square is much quieter on the same pair — the documented gap.
    cs_gap = chi_square.analyze(str(keyed)).score - chi_square.analyze(str(clean)).score
    assert (keyed_rs - clean_rs) > cs_gap


def test_saturated_solver_does_not_report_clean() -> None:
    """A negative discriminant means saturation, never absence of embedding.

    At full fill d0 and d1 both approach zero and the discriminant goes slightly
    negative (measured: d0=0.0006, disc=-0.0059). Returning 0.0 there would
    report the most-embedded file possible as perfectly clean — the worst
    direction for a detector to fail in.
    """
    rate, saturated = _solve_rate(0.0006, 0.3774, -0.0026, 0.3784)
    assert saturated
    assert rate == 1.0

    # Fully degenerate input (all gaps collapsed) must also saturate, not zero.
    rate2, sat2 = _solve_rate(0.0, 0.0, 0.0, 0.0)
    assert sat2 and rate2 == 1.0


def test_flip_uses_signed_intermediates() -> None:
    """F-1 maps 0 -> -1 and 255 -> 256; both must not wrap around uint8."""
    groups = np.array([[0, 0, 255, 255]], dtype=np.uint8)
    out = _flip(groups, np.array([-1, 0, -1, 0], dtype=np.int8))
    assert out[0, 0] == -1  # would be 255 if it wrapped
    assert out[0, 2] == 256  # would be 0 if it wrapped

    # F1 is an involution: applying it twice is the identity.
    mask = np.array([0, 1, 1, 0], dtype=np.int8)
    twice = _flip(_flip(groups, mask), mask)
    assert np.array_equal(twice.astype(np.uint8), groups)


def test_tiny_image_is_not_fitted(tmp_path) -> None:
    """Too few groups to fit must yield no estimate, not a noisy guess."""
    p = tmp_path / "tiny.png"
    Image.fromarray(np.zeros((4, 4, 3), dtype=np.uint8), "RGB").save(p)
    res = rs_analysis.analyze(str(p))
    assert res.per_channel == []
    assert res.rate == 0.0
