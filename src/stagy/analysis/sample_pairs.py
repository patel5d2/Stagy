"""Sample Pair Analysis (Dumitrescu, Wu & Wang, 2003) — an LSB rate estimator.

The independent cross-check for RS analysis. RS reads the R/S group statistics;
SPA reads the transition counts between adjacent samples. They rest on different
cover assumptions, so when both estimate the same embedding rate the verdict is
far stronger than either alone — which is the whole reason to run two structural
estimators instead of one.

**How it works.** Take adjacent sample pairs (u, v). Under LSB embedding each
sample's LSB is randomised, which shuffles pairs between "trace" sets whose
cardinalities the finite-state machine relates by a quadratic. Counting, over
all pairs:

  * ``x`` — pairs the embedding tends to move one way: (v's LSB = 0 and u < v)
    or (v's LSB = 1 and u > v).
  * ``y`` — the opposite direction: (v's LSB = 0 and u > v) or (v's LSB = 1 and
    u < v).
  * ``k`` — pairs sharing their top 7 bits (``u >> 1 == v >> 1``); these stay in
    the same trace set under any LSB change and set the quadratic's curvature.

gives ``2k·b^2 + 2(2x - N)·b + (y - x) = 0`` for N pairs, whose root ``b`` is the
fraction of flipped LSBs. The embedding rate (fraction of LSB capacity used) is
``2b``, matching what ``rs_analysis`` reports so the two are directly comparable.

**On the degenerate case.** As embedding saturates, ``k``-curvature and the
linear term collapse together and the discriminant goes negative. Returning 0.0
there would call the most-embedded file possible perfectly clean — the worst way
a detector can fail — so a negative discriminant saturates to rate 1.0 instead,
exactly as ``rs_analysis`` does. Root selection and that guard are the only
subtle code here and carry their own tests.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np
from PIL import Image

_MIN_PAIRS = 256  # below this the trace-set counts are too noisy to solve


@dataclass(frozen=True)
class SPAResult:
    """Estimated embedding rate, overall and per channel."""

    rate: float  # 0..1, estimated fraction of LSB capacity used
    score: float  # 0..1 detector score (== rate; named for the Signal contract)
    per_channel: list[float]
    degenerate: bool  # True if the solver hit the saturated / no-real-root case


def _solve_rate(x: int, y: int, k: int, n: int) -> tuple[float, bool]:
    """Solve the SPA quadratic for the embedding rate. Returns (rate, degenerate).

    ``2k·b^2 + 2(2x - N)·b + (y - x) = 0``. The physically meaningful root is the
    one nearest zero (b is a small flip fraction in [0, 0.5]); rate = 2b.
    """
    a = 2.0 * k
    b = 2.0 * (2.0 * x - n)
    c = float(y - x)

    if abs(a) < 1e-12:  # no curvature — the fit is linear
        if abs(b) < 1e-12:
            return 1.0, True  # fully degenerate: everything collapsed
        beta = -c / b
        return float(np.clip(2.0 * beta, 0.0, 1.0)), False

    disc = b * b - 4.0 * a * c
    if disc < 0.0:
        # No real intersection: the trace curves have already met, which happens
        # only as embedding saturates. Saturated, not clean.
        return 1.0, True

    root = math.sqrt(disc)
    b1 = (-b + root) / (2.0 * a)
    b2 = (-b - root) / (2.0 * a)
    beta = b1 if abs(b1) < abs(b2) else b2
    return float(np.clip(2.0 * beta, 0.0, 1.0)), False


def _channel_rate(plane: np.ndarray) -> tuple[float, bool] | None:
    """Estimated rate for one 2-D channel, or None if too small to solve.

    Pairs are horizontally adjacent samples (each pixel and its right neighbour).
    """
    u = plane[:, :-1].astype(np.int64)
    v = plane[:, 1:].astype(np.int64)
    n = u.size
    if n < _MIN_PAIRS:
        return None

    v_lsb = v & 1
    u_lt = u < v
    u_gt = u > v
    x = int(np.count_nonzero(((v_lsb == 0) & u_lt) | ((v_lsb == 1) & u_gt)))
    y = int(np.count_nonzero(((v_lsb == 0) & u_gt) | ((v_lsb == 1) & u_lt)))
    k = int(np.count_nonzero((u >> 1) == (v >> 1)))
    return _solve_rate(x, y, k, n)


def analyze(image_path: str, *, channels: str = "RGB") -> SPAResult:
    """Estimate the LSB embedding rate of an image via sample-pair analysis."""
    img = Image.open(image_path).convert("RGBA" if "A" in channels.upper() else "RGB")
    arr = np.asarray(img, dtype=np.uint8)
    idx = [{"R": 0, "G": 1, "B": 2, "A": 3}[c] for c in channels.upper()]

    rates: list[float] = []
    degenerate = False
    for i in idx:
        got = _channel_rate(arr[..., i])
        if got is None:
            continue
        rate, deg = got
        rates.append(rate)
        degenerate = degenerate or deg

    if not rates:
        return SPAResult(0.0, 0.0, [], False)
    # Median for the same reason RS uses it: one channel's solver hitting the
    # degenerate branch must not drag the whole estimate.
    overall = float(np.median(rates))
    return SPAResult(rate=overall, score=overall, per_channel=rates, degenerate=degenerate)
