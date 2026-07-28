"""RS analysis (Fridrich, Goljan & Du) — estimates the LSB embedding rate.

The detector that catches what chi-square cannot. Chi-square reads the
*histogram*, so keyed scattering hides from it: measured recall on keyed
embedding at 5% fill was 9%. RS reads the *spatial correlation* of the LSB
plane instead, which keyed placement does not disturb, so it sees keyed and
sequential embedding alike.

**How it works.** Partition samples into groups of 4. A discrimination function
`f` sums absolute differences within a group — low `f` means smooth, natural
pixels. Apply a flipping mask and re-measure:

  * **Regular** (R): `f` increases — flipping made the group *less* natural.
  * **Singular** (S): `f` decreases.

In a natural image `R > S`, and the gap under mask `m` differs from the gap
under `-m`. LSB embedding randomizes the plane and drives `R` and `S` together.
Measuring at the original image and at "all LSBs flipped" (which is embedding
rate 1) gives four points; fitting the quadratic through them extrapolates back
to the actual embedded length.

**On the degenerate case.** At full embedding `d0` and `d1` both approach zero,
the quadratic's leading coefficient vanishes, and the discriminant goes
slightly negative. Measured: at 100% fill `d0 = 0.0006` and `disc = -0.0059`.
The naive handling — return 0.0 when the solver fails — reports the *most*
embedded file possible as perfectly clean, which is the worst direction a
detector can fail in. A negative discriminant means the curves have already
converged, so it saturates to 1.0 instead. `_solve_rate` is the only subtle
code here and it carries its own test.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from PIL import Image

_MASK = np.array([0, 1, 1, 0], dtype=np.int8)
"""Classic Fridrich mask. Groups of 4 with the middle pair flipped."""

_GROUP = 4
_MIN_GROUPS = 64  # below this the R/S fractions are too noisy to fit


@dataclass(frozen=True)
class RSResult:
    """Estimated embedding rate, overall and per channel."""

    rate: float  # 0..1, estimated fraction of LSB capacity used
    score: float  # 0..1 detector score (== rate; named for the Signal contract)
    per_channel: list[float]
    saturated: bool  # True if the solver hit the p->1 degenerate case


def _flip(groups: np.ndarray, mask: np.ndarray) -> np.ndarray:
    """Apply the flipping function element-wise per mask entry.

    mask +1 -> F1:  0<->1, 2<->3 ...      (x XOR 1)
    mask -1 -> F-1: -1<->0, 1<->2 ...     (((x+1) XOR 1) - 1)
    mask  0 -> identity

    Signed intermediates are required: F-1 maps 0 to -1 and 255 to 256, both
    outside uint8. The discrimination function only uses differences, so the
    out-of-range values are consistent, but they must not wrap.
    """
    out = groups.astype(np.int16, copy=True)
    plus = mask == 1
    minus = mask == -1
    if plus.any():
        out[:, plus] ^= 1
    if minus.any():
        out[:, minus] = ((out[:, minus] + 1) ^ 1) - 1
    return out


def _discrimination(groups: np.ndarray) -> np.ndarray:
    """Sum of absolute adjacent differences per group. Low = smooth = natural."""
    return np.abs(np.diff(groups.astype(np.int32), axis=1)).sum(axis=1)


def _rs_fractions(groups: np.ndarray, mask: np.ndarray) -> tuple[float, float]:
    """Fraction of Regular and Singular groups under `mask`."""
    base = _discrimination(groups)
    flipped = _discrimination(_flip(groups, mask))
    return float((flipped > base).mean()), float((flipped < base).mean())


def _solve_rate(d0: float, dn0: float, d1: float, dn1: float) -> tuple[float, bool]:
    """Solve the RS quadratic for the embedding rate. Returns (rate, saturated).

    `d0`/`dn0` are the R-S gaps under mask and negated mask on the image as
    given; `d1`/`dn1` are the same after flipping every LSB. Curve intersection
    gives `z`, and the rate is `z / (z - 0.5)`.
    """
    a = 2.0 * (d1 + d0)
    b = dn0 - dn1 - d1 - 3.0 * d0
    c = d0 - dn0

    if abs(a) < 1e-12:  # curves are parallel — the fit is linear
        if abs(b) < 1e-12:
            return 1.0, True  # fully degenerate: both gaps collapsed
        z = -c / b
    else:
        disc = b * b - 4.0 * a * c
        if disc < 0.0:
            # No real intersection. This happens only as d0, d1 -> 0, i.e. the
            # R and S curves have already met: saturated embedding, not clean.
            return 1.0, True
        root = np.sqrt(disc)
        r1 = (-b + root) / (2.0 * a)
        r2 = (-b - root) / (2.0 * a)
        z = r1 if abs(r1) < abs(r2) else r2

    denom = z - 0.5
    if abs(denom) < 1e-12:
        return 1.0, True
    return float(np.clip(z / denom, 0.0, 1.0)), False


def _channel_rate(plane: np.ndarray) -> tuple[float, bool] | None:
    """Estimated rate for one 2-D channel, or None if too small to fit."""
    flat = plane.reshape(-1)
    n = (flat.size // _GROUP) * _GROUP
    if n // _GROUP < _MIN_GROUPS:
        return None
    groups = flat[:n].reshape(-1, _GROUP)

    rm, sm = _rs_fractions(groups, _MASK)
    rn, sn = _rs_fractions(groups, -_MASK)
    # Flipping every LSB is exactly embedding rate 1 — the second measurement
    # point the quadratic needs.
    flipped = groups ^ 1
    rm1, sm1 = _rs_fractions(flipped, _MASK)
    rn1, sn1 = _rs_fractions(flipped, -_MASK)

    return _solve_rate(rm - sm, rn - sn, rm1 - sm1, rn1 - sn1)


def analyze(image_path: str, *, channels: str = "RGB") -> RSResult:
    """Estimate the LSB embedding rate of an image."""
    img = Image.open(image_path).convert("RGBA" if "A" in channels.upper() else "RGB")
    arr = np.asarray(img, dtype=np.uint8)
    idx = [{"R": 0, "G": 1, "B": 2, "A": 3}[c] for c in channels.upper()]

    rates: list[float] = []
    saturated = False
    for i in idx:
        got = _channel_rate(arr[..., i])
        if got is None:
            continue
        rate, sat = got
        rates.append(rate)
        saturated = saturated or sat

    if not rates:
        return RSResult(0.0, 0.0, [], False)
    # Median, not mean: one channel's solver hitting the degenerate branch
    # should not drag the whole estimate.
    overall = float(np.median(rates))
    return RSResult(rate=overall, score=overall, per_channel=rates, saturated=saturated)
