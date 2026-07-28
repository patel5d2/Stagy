"""Unified steganalysis report: run applicable analyzers, aggregate a verdict.

The aggregation is the interesting part. Analyzers each emit a raw score in
0..1; a fitted calibration (see `evaluate.py`, refreshed by `stagy bench`)
converts each score into a log-likelihood ratio, and the ratios add to a
posterior probability under an explicit prior.

This replaces the obvious-but-wrong `max(scores)`. Taking the maximum is a
logical OR: every analyzer you add can only push the verdict *up*, so a
six-analyzer suite has a worse false-positive rate than any single analyzer in
it. Log-likelihood fusion lets a quiet analyzer argue *against* embedding, and
makes the false-positive cost of adding a detector measurable instead of
hidden.

Reported alongside the verdict is `probability` — the posterior that this file
carries hidden data, given the assumed base rate. Read it before trusting a
verdict: at Stagy's default 1-in-1000 prior, even a confident-looking signal
often lands well under 50%, and that is correct, not a bug.

Maps to MITRE ATT&CK T1027.003 (Obfuscated Files or Information: Steganography).
"""

from __future__ import annotations

import json
import math
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path

import numpy as np
from PIL import Image

from . import chi_square, entropy, filecarve, rs_analysis, sample_pairs
from .evaluate import DEFAULT_PRIOR, CalibrationSet, fuse

_IMAGE_EXT = (".png", ".bmp", ".gif", ".jpg", ".jpeg", ".tiff", ".webp")

ATTACK_TECHNIQUE = "T1027.003"

CALIBRATION_PATH = Path(__file__).with_name("calibration.json")

# Fallback verdict thresholds, used only when no fitted calibration ships an
# `operating` block. Real thresholds come from the benchmark: the posterior at
# which the fused detector costs a 1% (likely-stego) or 10% (suspicious)
# false-positive rate on held-out data.
#
# Fixed posterior cutoffs cannot do this job. From a 1-in-1000 prior a single
# detector rarely lifts the posterior past a few percent, so a "> 50% = stego"
# rule calls a 100%-filled cover clean while ranking it correctly all along.
# Thresholds have to be calibrated against a measured false-positive budget,
# not picked to look reassuring.
FALLBACK_LIKELY_STEGO_AT = 0.02
FALLBACK_SUSPICIOUS_AT = 0.005

# An uncalibrated signal still has to count for something, but it must not be
# able to swamp calibrated evidence. +/-3 caps it at a likelihood ratio of ~20.
_UNCALIBRATED_LOG_LR_CAP = 3.0


@dataclass
class Signal:
    name: str
    score: float  # 0..1 raw analyzer output, higher = more suspicious
    detail: str
    log_lr: float | None = None  # calibrated evidence weight; None = uncalibrated


@dataclass
class Report:
    path: str
    verdict: str  # clean | suspicious | likely-stego
    probability: float  # posterior P(stego | signals), given `prior`
    prior: float
    calibrated: bool  # False => probability is a fallback, not a fitted estimate
    signals: list[Signal] = field(default_factory=list)
    attack_technique: str = ATTACK_TECHNIQUE
    flag_threshold: float = 0.0  # posterior at/above which the verdict leaves "clean"

    @property
    def score(self) -> float:
        """Backwards-compatible alias for the headline number."""
        return self.probability

    def to_json(self) -> str:
        d = asdict(self)
        d["score"] = self.probability
        return json.dumps(d, indent=2)


def _load_calibration() -> CalibrationSet | None:
    if not CALIBRATION_PATH.exists():
        return None
    try:
        return CalibrationSet.load(CALIBRATION_PATH)
    except (ValueError, KeyError, json.JSONDecodeError):
        return None  # a corrupt calibration must degrade, never crash a scan


def _lsb_diff_signal(suspect: str, reference: str) -> Signal:
    """Compare a suspect against a known-clean original.

    The discriminating question is *not* "how many bits changed" — a small
    payload changes very few. It is "are the changes confined to bit 0". LSB
    replacement alters only the least significant bit, so every differing
    sample satisfies `a XOR b == 1`. Ordinary re-encoding, resizing or
    recompression perturbs higher bits too.

    Scoring on magnitude was the earlier mistake: a 5%-fill payload flips ~2.5%
    of LSBs, which read as a *low* score and therefore as evidence against
    embedding — inverting the strongest signal the tool has. Fraction-confined-
    to-bit-0 is the right axis, and it is near-conclusive: for two genuinely
    different images to differ *only* in bit 0 everywhere is essentially
    impossible by chance.
    """
    a = np.asarray(Image.open(reference).convert("RGB"), dtype=np.uint8)
    b = np.asarray(Image.open(suspect).convert("RGB"), dtype=np.uint8)
    if a.shape != b.shape:
        return Signal("reference-diff", 0.5, "dimension mismatch — cannot diff directly")

    diff = a ^ b
    changed = diff != 0
    n_changed = int(changed.sum())
    if n_changed == 0:
        return Signal("reference-diff", 0.0, "byte-identical to reference — no embedding")

    lsb_only = float((diff[changed] == 1).mean())
    lsb_changed = float(((a & 1) != (b & 1)).mean())
    verdict = (
        "consistent with LSB embedding"
        if lsb_only > 0.99
        else "higher bit-planes also changed — re-encoded, inference unreliable"
    )
    return Signal(
        "reference-diff",
        lsb_only,
        f"{lsb_changed:.2%} of LSBs differ; {lsb_only:.1%} of all changes confined "
        f"to bit 0 — {verdict}",
    )


def _lsb_signals(path: str) -> list[Signal]:
    """Structural LSB analyzers — image-only (they read the pixel plane)."""
    cs = chi_square.analyze(path)
    rs = rs_analysis.analyze(path)
    sp = sample_pairs.analyze(path)
    return [
        Signal(
            "chi-square",
            cs.score,
            f"min chi/df={cs.min_chi_ratio:.2f} over {len(cs.region_p)} regions "
            f"(<1 means histogram pairs are equalized — the LSB signature); "
            f"{cs.flagged_fraction:.0%} of regions flagged",
        ),
        Signal(
            "rs-analysis",
            rs.score,
            f"estimated LSB fill {rs.rate:.1%}"
            + (" (solver saturated — rate is a floor, not a measurement)"
               if rs.saturated else "")
            + "; reads spatial correlation, so keyed scattering does not hide from it",
        ),
        Signal(
            "sample-pairs",
            sp.score,
            f"estimated LSB fill {sp.rate:.1%}"
            + (" (solver saturated — rate is a floor, not a measurement)"
               if sp.degenerate else "")
            + "; independent trace-set estimator, cross-checks rs-analysis",
        ),
    ]


def _appended_signals(path: str) -> list[Signal]:
    """Appended-data analyzers — apply to any file. Deterministic evidence, so
    each carries its own ``log_lr`` and bypasses the LSB-fitted calibration.
    """
    fc = filecarve.analyze(path)
    en = entropy.analyze(path)
    return [
        Signal("file-carve", fc.score, fc.detail, log_lr=fc.log_lr),
        Signal("entropy", en.score, en.detail, log_lr=en.log_lr),
    ]


def raw_signals(path: str, *, reference: str | None = None) -> list[Signal]:
    """Run every applicable analyzer for the file type and return their scores.

    The benchmark harness calls this directly — it needs raw scores to fit the
    calibration that `analyze` then consumes. Signals that carry a pre-set
    ``log_lr`` (the deterministic appended-data analyzers) are not calibrated.
    """
    signals: list[Signal] = []
    if path.lower().endswith(_IMAGE_EXT):
        signals += _lsb_signals(path)
        if reference:
            signals.append(_lsb_diff_signal(path, reference))
    signals += _appended_signals(path)
    return signals


def _operating(cal: CalibrationSet | None) -> tuple[float, float]:
    """(likely_stego, suspicious) posterior thresholds, fitted or fallback."""
    op = cal.operating if cal else {}
    return (
        op.get("likely_stego", FALLBACK_LIKELY_STEGO_AT),
        op.get("suspicious", FALLBACK_SUSPICIOUS_AT),
    )


def _verdict(probability: float, cal: CalibrationSet | None) -> str:
    likely, suspicious = _operating(cal)
    if probability >= likely:
        return "likely-stego"
    if probability >= suspicious:
        return "suspicious"
    return "clean"


def _heuristic_log_lr(score: float) -> float:
    """Evidence weight for a signal with no fitted calibration.

    Every signal must contribute something. Dropping uncalibrated ones would
    silently discard the strongest evidence the tool has — `reference-diff`
    never appears in the benchmark corpus (it needs a known-clean original), so
    a drop-on-missing rule would ignore precisely the signal that makes a
    verdict near-certain.
    """
    raw = math.log(max(score, 1e-3) / max(1.0 - score, 1e-3))
    return max(-_UNCALIBRATED_LOG_LR_CAP, min(_UNCALIBRATED_LOG_LR_CAP, raw))


def analyze_image(
    path: str,
    *,
    reference: str | None = None,
    calibration: CalibrationSet | None = None,
    prior: float | None = None,
) -> Report:
    signals = raw_signals(path, reference=reference)
    cal = calibration if calibration is not None else _load_calibration()
    p = prior if prior is not None else (cal.prior if cal else DEFAULT_PRIOR)

    fully_calibrated = cal is not None
    lsb_log_lrs: list[float] = []
    appended_log_lr = 0.0
    for s in signals:
        if s.log_lr is not None:
            appended_log_lr += s.log_lr  # deterministic appended-data evidence (>= 0)
            continue
        if (sc := cal.signals.get(s.name) if cal else None) is not None:
            s.log_lr = sc.log_likelihood_ratio(s.score)
        else:
            s.log_lr = _heuristic_log_lr(s.score)
            fully_calibrated = False
        lsb_log_lrs.append(s.log_lr)

    lsb_prob = fuse(lsb_log_lrs, prior=p) if lsb_log_lrs else p
    # Appended-data evidence tests an *orthogonal* hiding technique, so a clean
    # LSB plane must not cancel it: a viewable image with a ZIP after its EOF is
    # stego regardless of what its pixels look like. When it fires, it sets a
    # floor on the verdict rather than being summed with (and diluted by) the
    # LSB signals. Absence (log_lr 0) leaves the LSB verdict untouched.
    prob = max(lsb_prob, fuse([appended_log_lr], prior=p)) if appended_log_lr > 0 else lsb_prob
    _likely, suspicious = _operating(cal)
    return Report(path, _verdict(prob, cal), prob, p, fully_calibrated, signals,
                  flag_threshold=suspicious)


def _analyze_appended(
    path: str, *, calibration: CalibrationSet | None = None, prior: float | None = None
) -> Report:
    """Verdict for a non-image file, from the appended-data analyzers alone.

    Their evidence is deterministic and one-sided: nothing found means log_lr 0,
    not negative. With no analyzer able to argue *for* cleanliness, a zero-
    evidence file must stay at the prior and read clean — otherwise the fitted
    thresholds (which sit below the prior on the synthetic corpus) would flag
    every ordinary file. So the verdict is driven by whether a signal fired.
    """
    signals = _appended_signals(path)
    cal = calibration if calibration is not None else _load_calibration()
    p = prior if prior is not None else (cal.prior if cal else DEFAULT_PRIOR)
    log_lrs = [s.log_lr or 0.0 for s in signals]
    fired = any(v > 0.0 for v in log_lrs)
    prob = fuse(log_lrs, prior=p) if fired else p
    _likely, suspicious = _operating(cal)
    verdict = _verdict(prob, cal) if fired else "clean"
    return Report(path, verdict, prob, p, True, signals, flag_threshold=suspicious)


def analyze(
    path: str,
    *,
    reference: str | None = None,
    calibration: CalibrationSet | None = None,
    prior: float | None = None,
) -> Report:
    """Dispatch by file type. Images get the full LSB + appended-data suite;
    other files get the appended-data analyzers, which apply to any bytes."""
    if path.lower().endswith(_IMAGE_EXT):
        return analyze_image(path, reference=reference, calibration=calibration, prior=prior)
    return _analyze_appended(path, calibration=calibration, prior=prior)


def _error_report(path: str, exc: Exception, prior: float | None) -> Report:
    """A file that could not be read/parsed — surfaced, not silently dropped."""
    p = prior if prior is not None else DEFAULT_PRIOR
    return Report(path, "error", 0.0, p, False,
                  [Signal("scan-error", 0.0, f"could not scan: {exc}")])


def analyze_many(
    paths: Iterable[str],
    *,
    calibration: CalibrationSet | None = None,
    prior: float | None = None,
) -> list[Report]:
    """Score many files for a bulk/triage scan, ranked by descending probability.

    This is why a directory scan belongs in the library and not a shell loop over
    ``stagy detect``: the calibration is loaded and parsed **once** and reused for
    every file, and the results come back in triage order (most-suspicious first)
    — the low-false-positive ranking the whole detection design optimizes for. A
    file that cannot be scanned becomes an ``error`` verdict instead of aborting
    the sweep, so one truncated image never kills a million-file run.
    """
    cal = calibration if calibration is not None else _load_calibration()
    reports: list[Report] = []
    for p in paths:
        try:
            reports.append(analyze(p, calibration=cal, prior=prior))
        except Exception as exc:  # noqa: BLE001 — one unreadable file must not abort a bulk scan
            reports.append(_error_report(p, exc, prior))
    reports.sort(key=lambda r: r.probability, reverse=True)
    return reports
