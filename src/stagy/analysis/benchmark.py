"""The benchmark run: build ground truth, score every analyzer, fit calibration.

`stagy bench` is the command that keeps the blue-team half honest. It

  1. generates a labeled corpus (`corpus.build`),
  2. runs every analyzer over it and records raw scores,
  3. fits calibration on the **train** split only,
  4. reports metrics on the held-out **test** split, per signal and fused,
  5. breaks the fused result down by embedding rate and technique.

Step 3/4 separation is not ceremony. Fitting and scoring on the same files
produces an inflated number that quietly becomes a marketing claim.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from ..version import __version__
from .corpus import Case
from .evaluate import (
    DEFAULT_PRIOR,
    CalibrationSet,
    Metrics,
    SignalCalibration,
    evaluate,
    fit_calibration,
    fuse,
)
from .report import raw_signals


@dataclass(frozen=True)
class Breakdown:
    """Detection rate for one slice of the corpus at a fixed threshold."""

    technique: str
    rate: float
    n: int
    detected: float  # fraction whose posterior cleared the operating threshold


@dataclass(frozen=True)
class BenchResult:
    calibration: CalibrationSet
    per_signal: list[Metrics]
    fused: Metrics
    breakdown: list[Breakdown]
    operating_threshold: float  # posterior at the 1%-FPR operating point


def _score_corpus(cases: list[Case], *, with_reference: bool = False) -> dict[str, list[float]]:
    """Raw score per signal name, aligned with `cases` order. Missing = 0.0.

    With `with_reference`, each case is compared against its own clean cover —
    the paired corpus design paying off. A clean case is compared to itself and
    correctly yields no evidence.
    """
    covers = {c.cover_id: c.path for c in cases if c.label == 0}
    rows = [
        {
            s.name: s.score
            for s in raw_signals(
                c.path, reference=covers.get(c.cover_id) if with_reference else None
            )
            # Deterministic analyzers (file-carve, entropy) carry their own log_lr
            # and are not calibrated; the corpus has no appended-data ground truth.
            if s.log_lr is None
        }
        for c in cases
    ]
    names = sorted({n for r in rows for n in r})
    return {n: [r.get(n, 0.0) for r in rows] for n in names}


def run(
    cases: list[Case], *, prior: float = DEFAULT_PRIOR, cover_source: str = "synthetic"
) -> BenchResult:
    """Score, calibrate on train, evaluate on test."""
    train = [i for i, c in enumerate(cases) if c.split == "train"]
    test = [i for i, c in enumerate(cases) if c.split == "test"]
    if not train or not test:
        raise ValueError("corpus needs both a train and a test split")

    labels = [c.label for c in cases]

    def _fit(name: str, vals: list[float]) -> SignalCalibration:
        return fit_calibration(name, [labels[i] for i in train], [vals[i] for i in train])

    def _eval(name: str, vals: list[float]) -> Metrics:
        return evaluate(name, [labels[i] for i in test], [vals[i] for i in test])

    # Blind pass: no known-clean original. This is the realistic SOC case, so it
    # alone drives FUSED and the operating points.
    blind = _score_corpus(cases)
    fitted = {name: _fit(name, vals) for name, vals in blind.items()}
    per_signal = [_eval(name, vals) for name, vals in blind.items()]

    posterior = [
        fuse([fitted[n].log_likelihood_ratio(blind[n][i]) for n in blind], prior=prior)
        for i in range(len(cases))
    ]
    fused = _eval("FUSED", posterior)

    # Reference pass, calibrated but deliberately kept out of FUSED. Comparing
    # against a known-clean original is near-conclusive, so folding it into the
    # headline number would describe a situation a SOC almost never has.
    for name, vals in _score_corpus(cases, with_reference=True).items():
        if name not in fitted:
            fitted[name] = _fit(name, vals)
            per_signal.append(_eval(f"{name} (reference mode)", vals))

    cal = CalibrationSet(
        prior=prior,
        signals=fitted,
        # Verdict thresholds are *measured*, not chosen: the posterior at which
        # the blind detector costs a 1% (likely-stego) or 10% (suspicious)
        # false-positive rate on held-out data. Fixed posterior cutoffs cannot
        # do this — from a 1-in-1000 prior a single detector rarely lifts the
        # posterior past a few percent, so a "> 50% = stego" rule calls a fully
        # embedded cover clean while ranking it correctly all along.
        operating={
            "likely_stego": fused.threshold_at_1pct_fpr,
            "suspicious": fused.threshold_at_10pct_fpr,
        },
        meta={
            "fitted_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "cover_source": cover_source,
            "n_covers": str(len({c.cover_id for c in cases})),
            "n_train": str(len(train)),
            "n_test": str(len(test)),
            "techniques": ",".join(sorted({c.technique for c in cases if c.label == 1})),
            "stagy_version": __version__,
        },
    )

    # Break the fused detector down by how much payload was hidden — the axis
    # that actually predicts whether a detector will work in production.
    slices: dict[tuple[str, float], list[int]] = {}
    for i in test:
        c = cases[i]
        if c.label == 1:
            slices.setdefault((c.technique, c.rate), []).append(i)
    thr = fused.threshold_at_1pct_fpr
    breakdown = [
        Breakdown(
            technique=t,
            rate=r,
            n=len(idxs),
            detected=sum(1 for i in idxs if posterior[i] >= thr) / len(idxs),
        )
        for (t, r), idxs in sorted(slices.items())
    ]
    return BenchResult(cal, sorted(per_signal, key=lambda m: -m.auc), fused, breakdown, thr)
