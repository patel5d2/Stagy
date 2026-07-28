"""Detector evaluation and calibration — the measurement backbone of the blue-team half.

An unmeasured detector is a rumour. This module turns "the analyzer flagged it"
into a number you can defend in an incident review:

  * `roc` / `auc`            — threshold-independent separability.
  * `tpr_at_fpr`             — the metric that actually matters in a SOC. A
                               detector with 90% recall at 30% FPR is useless
                               against a million-file corpus; one with 40%
                               recall at 0.1% FPR is deployable. Report recall
                               at a *fixed low* false-positive budget, the way
                               the ALASKA#2 steganalysis benchmark weights its
                               ranking toward the low-FPR region.
  * `fit_calibration`/`fuse` — turn raw analyzer scores into likelihood ratios
                               and combine them correctly.

Why fusion needs calibration: combining analyzers with `max()` is a logical OR.
Each added analyzer strictly *raises* the false-positive rate, so a richer
detector suite gets worse at triage. The correct combination is additive in
log-likelihood-ratio space (Bayes), which lets a quiet analyzer *lower* the
posterior instead of only ever raising it.

The base rate is the whole ballgame. At a 1-in-1000 prior, a signal with 95%
recall and 5% FPR yields a posterior of only ~2%. That is not a broken
detector, that is arithmetic — and it is the single most important thing a
detection-engineering trainee has to internalise.
"""

from __future__ import annotations

import json
import math
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path

import numpy as np
import numpy.typing as npt

DEFAULT_PRIOR = 1e-3
"""Assumed share of files carrying hidden data among those actually scanned.

Deliberately pessimistic. Real-world stego prevalence in an enterprise file
stream is far lower still; tune per deployment with `--prior`. Raising this is
how you model a targeted hunt ("we already believe this host is compromised"),
lowering it models bulk scanning.
"""

Vector = npt.NDArray[np.float64]


def _as_arrays(labels: Sequence[int], scores: Sequence[float]) -> tuple[Vector, Vector]:
    y = np.asarray(labels, dtype=np.float64)
    s = np.asarray(scores, dtype=np.float64)
    if y.size != s.size:
        raise ValueError("labels and scores must be the same length")
    if y.size == 0 or not (y == 1).any() or not (y == 0).any():
        raise ValueError("need at least one clean (0) and one stego (1) case")
    return y, s


def roc(labels: Sequence[int], scores: Sequence[float]) -> tuple[Vector, Vector, Vector]:
    """Return (fpr, tpr, threshold) points. Label 1 = stego, 0 = clean.

    Points are ordered by descending threshold and start at the origin, so
    `auc` can integrate directly.
    """
    y, s = _as_arrays(labels, scores)
    order = np.argsort(-s, kind="mergesort")
    s, y = s[order], y[order]
    tps = np.cumsum(y == 1)
    fps = np.cumsum(y == 0)
    # Collapse ties: a threshold can only sit *between* distinct scores.
    keep = np.r_[np.flatnonzero(np.diff(s)), s.size - 1]
    tpr = np.r_[0.0, tps[keep] / tps[-1]]
    fpr = np.r_[0.0, fps[keep] / fps[-1]]
    thr = np.r_[np.inf, s[keep]]
    return fpr, tpr, thr


def auc(fpr: Vector, tpr: Vector) -> float:
    """Trapezoidal area under the ROC curve."""
    return float(np.sum(np.diff(fpr) * (tpr[1:] + tpr[:-1]) / 2.0))


def tpr_at_fpr(
    labels: Sequence[int], scores: Sequence[float], max_fpr: float = 0.01
) -> tuple[float, float]:
    """Best recall achievable without exceeding `max_fpr`, and the threshold for it.

    This is the number to put in a report. "AUC 0.97" hides that the detector
    may need a 20% false-positive rate to reach its good recall.
    """
    fpr, tpr, thr = roc(labels, scores)
    i = int(np.flatnonzero(fpr <= max_fpr)[-1])  # index 0 is always fpr=0
    return float(tpr[i]), float(thr[i])


@dataclass(frozen=True)
class Metrics:
    """Detection performance for one signal (or the fused detector) on a corpus."""

    name: str
    n_clean: int
    n_stego: int
    auc: float
    tpr_at_1pct_fpr: float
    threshold_at_1pct_fpr: float
    tpr_at_10pct_fpr: float
    threshold_at_10pct_fpr: float

    @property
    def fpr_resolution(self) -> float:
        """Smallest non-zero false-positive rate this corpus can express.

        One clean sample is one step on the FPR axis. With 12 clean files the
        axis moves in 8.3% jumps, so a reported "1% FPR" is really "zero false
        positives out of 12" — a number with no power behind it.
        """
        return 1.0 / self.n_clean if self.n_clean else 1.0

    def resolves(self, max_fpr: float) -> bool:
        """True if the corpus has enough clean samples to measure `max_fpr`."""
        return self.fpr_resolution <= max_fpr

    def summary(self) -> str:
        return (
            f"{self.name}: AUC={self.auc:.3f}  "
            f"recall@1%FPR={self.tpr_at_1pct_fpr:.1%}  "
            f"recall@10%FPR={self.tpr_at_10pct_fpr:.1%}  "
            f"(n={self.n_clean}+{self.n_stego})"
        )


def evaluate(name: str, labels: Sequence[int], scores: Sequence[float]) -> Metrics:
    """Full metric set for one signal."""
    y, _ = _as_arrays(labels, scores)
    fpr, tpr, _ = roc(labels, scores)
    t1, th1 = tpr_at_fpr(labels, scores, 0.01)
    t10, th10 = tpr_at_fpr(labels, scores, 0.10)
    return Metrics(
        name=name,
        n_clean=int((y == 0).sum()),
        n_stego=int((y == 1).sum()),
        auc=auc(fpr, tpr),
        tpr_at_1pct_fpr=t1,
        threshold_at_1pct_fpr=th1,
        tpr_at_10pct_fpr=t10,
        threshold_at_10pct_fpr=th10,
    )


@dataclass(frozen=True)
class SignalCalibration:
    """Maps one analyzer's raw score to a log-likelihood ratio.

    Stored as (knot score, log-LR) pairs and evaluated by linear interpolation
    rather than as piecewise-constant bins. That detail matters: constant bins
    map every score inside a bin to one value, creating ties that collapse the
    ROC curve exactly where it counts. On the benchmark, binned calibration
    dropped the fused detector to 0% recall at a 1% false-positive budget while
    the raw signal underneath managed 83%. Interpolating between knots keeps
    the ranking, so fusion can only add information, never destroy it.
    """

    name: str
    knots: list[float]  # ascending representative score per bin
    log_lr: list[float]  # non-decreasing (enforced by isotonic fit)

    def log_likelihood_ratio(self, score: float) -> float:
        if len(self.knots) == 1:
            return self.log_lr[0]
        return float(np.interp(score, np.asarray(self.knots), np.asarray(self.log_lr)))


def _isotonic(values: list[float], weights: list[float]) -> list[float]:
    """Pool-adjacent-violators: nearest non-decreasing fit, weighted.

    A higher analyzer score must never yield *less* evidence of embedding.
    Small-sample noise routinely inverts a bin or two; left alone those
    inversions reorder cases and cost real recall.
    """
    v = list(values)
    w = list(weights)
    n_of = [1] * len(v)
    i = 0
    while i < len(v) - 1:
        if v[i] <= v[i + 1]:
            i += 1
            continue
        tw = w[i] + w[i + 1]
        v[i] = (v[i] * w[i] + v[i + 1] * w[i + 1]) / tw
        w[i] = tw
        n_of[i] += n_of[i + 1]
        del v[i + 1], w[i + 1], n_of[i + 1]
        if i > 0:
            i -= 1
    return [val for val, count in zip(v, n_of, strict=True) for _ in range(count)]


def fit_calibration(
    name: str, labels: Sequence[int], scores: Sequence[float], *, bins: int = 12
) -> SignalCalibration:
    """Learn score -> log-likelihood-ratio from a labeled corpus.

    Quantile bins over observed scores, a Laplace-smoothed ratio of per-bin
    stego density to clean density, then an isotonic pass to enforce
    monotonicity. Smoothing is what stops a bin that happens to contain zero
    clean samples from claiming infinite certainty.
    """
    y, s = _as_arrays(labels, scores)
    edges = np.unique(np.quantile(s, np.linspace(0.0, 1.0, bins + 1)))
    if edges.size < 2:  # every score identical — the signal carries no information
        return SignalCalibration(name, [float(s[0])], [0.0])
    n_bins = edges.size - 1
    idx = np.clip(np.searchsorted(edges, s, side="right") - 1, 0, n_bins - 1)

    n1, n0 = float((y == 1).sum()), float((y == 0).sum())
    raw: list[float] = []
    knots: list[float] = []
    weights: list[float] = []
    for b in range(n_bins):
        in_bin = idx == b
        c1 = float((in_bin & (y == 1)).sum())
        c0 = float((in_bin & (y == 0)).sum())
        p1 = (c1 + 0.5) / (n1 + 0.5 * n_bins)
        p0 = (c0 + 0.5) / (n0 + 0.5 * n_bins)
        raw.append(math.log(p1 / p0))
        # Knot at the bin's observed mean score, falling back to its midpoint.
        knots.append(
            float(s[in_bin].mean()) if in_bin.any() else float((edges[b] + edges[b + 1]) / 2)
        )
        weights.append(c1 + c0 + 1.0)
    # Knots must stay strictly ascending for np.interp.
    for i in range(1, len(knots)):
        if knots[i] <= knots[i - 1]:
            knots[i] = knots[i - 1] + 1e-12
    return SignalCalibration(name, knots, _isotonic(raw, weights))


@dataclass(frozen=True)
class CalibrationSet:
    """Fitted calibration for every signal, plus the prior it assumes.

    `meta` carries provenance — what corpus produced these numbers, how big it
    was, and when. A calibration is a fitted model that silently decides what
    the tool calls suspicious; shipping one with no record of what it was
    trained on makes every downstream verdict unauditable, and calibration
    fitted on synthetic covers does not transfer cleanly to real photographs.
    """

    prior: float
    signals: dict[str, SignalCalibration]
    operating: dict[str, float] = field(default_factory=dict)
    meta: dict[str, str] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(
            {
                "prior": self.prior,
                "meta": self.meta,
                "operating": self.operating,
                "signals": {k: asdict(v) for k, v in sorted(self.signals.items())},
            },
            indent=2,
        )

    @classmethod
    def from_json(cls, text: str) -> CalibrationSet:
        d = json.loads(text)
        return cls(
            prior=float(d["prior"]),
            signals={
                k: SignalCalibration(name=v["name"], knots=v["knots"], log_lr=v["log_lr"])
                for k, v in d["signals"].items()
            },
            operating={k: float(v) for k, v in d.get("operating", {}).items()},
            meta=dict(d.get("meta", {})),
        )

    def save(self, path: str | Path) -> None:
        Path(path).write_text(self.to_json())

    @classmethod
    def load(cls, path: str | Path) -> CalibrationSet:
        return cls.from_json(Path(path).read_text())


def fuse(log_lrs: Sequence[float], *, prior: float = DEFAULT_PRIOR) -> float:
    """Combine independent log-likelihood ratios into a posterior probability.

    posterior_odds = prior_odds * PROD(LR_i)  ->  additive in log space.

    Assumes conditional independence between signals, which is optimistic:
    chi-square and sample-pair analysis both read the same LSB plane and will
    correlate. Independence overstates confidence when several correlated
    analyzers agree, so treat the posterior as an upper bound until the
    corpus is large enough to fit a joint model.
    """
    if not 0.0 < prior < 1.0:
        raise ValueError("prior must be strictly between 0 and 1")
    odds = math.log(prior / (1.0 - prior)) + float(sum(log_lrs))
    return 1.0 / (1.0 + math.exp(-max(min(odds, 700.0), -700.0)))


def demo() -> None:
    """Self-check: the properties that must hold for any of this to be trusted."""
    rng = np.random.default_rng(0)
    # A separable-but-imperfect signal: clean ~ N(0.2), stego ~ N(0.6).
    clean = rng.normal(0.2, 0.15, 500)
    stego = rng.normal(0.6, 0.15, 500)
    labels = [0] * 500 + [1] * 500
    scores = np.r_[clean, stego].tolist()

    m = evaluate("demo", labels, scores)
    assert 0.85 < m.auc < 1.0, m.auc
    assert m.tpr_at_1pct_fpr <= m.tpr_at_10pct_fpr, "recall must not shrink as FPR budget grows"

    # A pure-noise signal cannot beat a coin flip by much.
    noise = evaluate("noise", labels, rng.normal(0, 1, 1000).tolist())
    assert 0.4 < noise.auc < 0.6, noise.auc

    # Calibration: a high score must be evidence *for* stego, a low score against.
    cal = fit_calibration("demo", labels, scores)
    assert cal.log_likelihood_ratio(0.9) > 0 > cal.log_likelihood_ratio(0.0)

    # An uninformative signal must not move the posterior off the prior.
    flat = fit_calibration("flat", labels, [0.5] * 1000)
    assert abs(fuse([flat.log_likelihood_ratio(0.5)], prior=0.01) - 0.01) < 1e-6

    # The base-rate lesson, asserted: 95% recall at 5% FPR is LR=19, and at a
    # 1-in-1000 prior that is still only a ~2% posterior.
    assert abs(fuse([math.log(0.95 / 0.05)], prior=1e-3) - 0.0186) < 0.002

    # Fusing agreeing signals must raise the posterior above any one of them.
    lr = math.log(19.0)
    assert fuse([lr, lr], prior=1e-3) > fuse([lr], prior=1e-3)
    # ...and a contradicting signal must pull it back down. This is the whole
    # reason max() fusion was wrong: it can only ever ratchet upward.
    assert fuse([lr, -lr], prior=1e-3) < fuse([lr], prior=1e-3)

    # Round-trip the serialized form.
    cs = CalibrationSet(prior=DEFAULT_PRIOR, signals={"demo": cal})
    assert CalibrationSet.from_json(cs.to_json()).signals["demo"] == cal

    print("evaluate.py self-check OK")


if __name__ == "__main__":
    demo()
