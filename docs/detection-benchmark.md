# Detection benchmark & calibration

How Stagy knows whether its detectors work, and how to read the numbers they
produce. If you only take one thing from this document: **a detector you have
not measured against labeled ground truth is a rumour, and the metric that
matters is recall at a fixed low false-positive budget, not accuracy.**

Run it:

```bash
stagy bench --covers /path/to/real/photos --fit
```

---

## Why this exists

The blue-team half of Stagy plans six analyzers. Without ground truth there is
no way to answer the only questions that matter:

- Does this analyzer beat a coin flip?
- What does it cost in false positives to catch 80% of embeddings?
- Does adding an analyzer make the suite better or worse?

That last one is not rhetorical. The original aggregation took the **maximum**
score across signals. Maximum is a logical OR: if each of six analyzers
false-positives on 5% of clean files, the suite false-positives on roughly
`1 - 0.95^6 = 26%`. Every detector added made the tool worse at triage while
looking like progress. Fusion is now additive in log-likelihood-ratio space,
where a quiet analyzer can argue *against* embedding.

## What the harness found on day one

Both of these were shipping, and both were invisible without measurement.

**1. The chi-square score was statistically invalid.** It reported
`p_max` — the maximum per-region embedding probability. `region_p` is a
chi-square upper-tail p-value, so under the clean hypothesis those values are
roughly uniform on (0,1) and their maximum over N regions tends to 1.0 *for
every clean image*. It is an uncorrected multiple comparison. Measured: clean
covers scored `p_max = 1.0000` with 100% of regions flagged, and the detector
managed **AUC 0.566** — barely better than a coin flip.

The fix reports `exp(-min(chi/df))`, built on the normalized statistic:

| `chi/df` | meaning |
|---|---|
| `>> 1` | adjacent histogram bins differ — a natural image |
| `~ 0` | adjacent bins equalized — the LSB-embedding signature |

Result: **AUC 0.951, 76.5% recall at a 1% false-positive budget.** The region
count is now a fixed constant, because the null distribution of a minimum over
N regions depends on N — letting it vary with image size would invalidate the
calibration.

**2. The reference diff scored on the wrong axis.** It graded by *magnitude* of
LSB change. A 5%-fill payload flips only ~2.5% of LSBs, which scored 0.05 and
therefore counted as evidence **against** embedding — inverting the strongest
signal the tool has. What discriminates is not how many bits changed but
whether the changes are **confined to bit 0**: LSB replacement alters only the
least significant bit, while re-encoding or resizing perturbs higher planes.
Rescored on bit-confinement, reference mode reaches **AUC 1.000**.

## Metrics

**Recall at 1% / 10% FPR** is the headline. A detector with 90% recall at 30%
FPR is unusable against a million-file share; one with 40% recall at 0.1% FPR
is deployable. This mirrors how the ALASKA#2 steganalysis benchmark weights its
ranking toward the low-false-positive region.

**AUC** is reported as a secondary, threshold-independent summary. On its own
it hides the operating point entirely.

**FPR resolution** guards against quoting precision you do not have. One clean
sample is one step on the false-positive axis, so a corpus with 12 clean files
moves in 8.3% jumps and *cannot* express a 1% FPR — a "1% FPR" figure there
really means "zero false positives out of 12". `stagy bench` warns when the
corpus is too small to resolve the rate it is printing. **Measuring a 1% FPR
honestly needs at least 100 clean files in the held-out split.**

## Corpus construction

- **Paired.** Every stego case derives from a specific clean cover, and that
  cover also appears as a clean case. A detector cannot win by learning "this
  cover looks odd" — both labels share the source image.
- **Split by cover, not by case.** All cases from one cover land in the same
  split. Splitting by case would put a cover's clean and stego versions on
  opposite sides, leaking the answer into calibration.
- **Rate is swept** from 5% to 100% of capacity. Detection difficulty is
  dominated by payload size, and real payloads are small.
- **The grid is sampled, not exhausted.** The full (rate x mode) cross-product
  yields one clean file per ten stego files, so a corpus large enough to
  resolve a 1% FPR would need ten times the embedding work. Sampling spends the
  same compute on more distinct covers — the axis the false-positive rate
  actually depends on.

### Synthetic covers are a regression guard, not a performance claim

Use `--covers` with real photographs before quoting any figure.

This is not boilerplate caution. Adding Gaussian noise with sigma >= 3
convolves the intensity histogram until adjacent bins are equal to within
Poisson error — **which is precisely the signature LSB embedding produces**.
Measured on covers built that way, clean images sat at `chi/df = 0.57`, making
a clean file indistinguishable from a fully embedded one and rendering the
corpus unable to validate any histogram-based detector at all.

The synthetic generator therefore uses piecewise-flat regions (standing in for
scene content — sky, walls, surfaces) with deliberately low grain, which is
what gives real photographs their spiky regional histograms. `_SYNTH_NOISE_SIGMA`
is the most load-bearing constant in `corpus.py`.

## Calibration

Each analyzer's raw score is mapped to a log-likelihood ratio by quantile
binning with Laplace smoothing, then an isotonic (pool-adjacent-violators) pass
to enforce monotonicity — a higher score must never mean *less* evidence.

Calibration is evaluated by **interpolation between knots, not as piecewise
constant bins**. Constant bins map every score inside a bin to one value,
creating ties that collapse the ROC curve exactly where it counts: on the
benchmark, binned calibration dropped the fused detector to 0% recall at a 1%
FPR budget while the raw signal underneath reached 83%.

Fitting happens on the **train** split only; all reported metrics come from the
held-out **test** split. Fitting and scoring on the same files produces an
inflated number that quietly becomes a marketing claim.

The shipped `calibration.json` carries provenance — corpus size, cover source,
technique list, timestamp, version. A calibration silently decides what the
tool calls suspicious; shipping one with no record of its training data makes
every downstream verdict unauditable. **A calibration fitted on synthetic
covers does not transfer cleanly to real photographs.**

## Reading a verdict

```
verdict: likely-stego  P(hidden data) = 2.6%  (prior 0.100%, ATT&CK T1027.003)
```

Those two numbers are not in conflict, and understanding why is the single most
important thing in this document.

**Verdict thresholds are measured, not chosen.** "likely-stego" is the
posterior at which the blind detector costs a 1% false-positive rate on
held-out data; "suspicious" is the 10% budget. Fixed posterior cutoffs cannot
do this job — from a 1-in-1000 prior a single detector rarely lifts the
posterior past a few percent, so a "> 50% = stego" rule would label a fully
embedded cover clean while ranking it correctly all along.

**The posterior reflects the base rate.** At a 1-in-1000 prior, a signal with
95% recall and 5% FPR yields a posterior of about 2%. That is not a broken
detector — it is arithmetic, and it is why analysts drown in alerts when the
base rate is ignored. Raise `--prior` to model a targeted hunt ("we already
believe this host is compromised"); lower it for bulk scanning.

## Current results

Synthetic covers, 200 covers / 600 cases, half held out. **Regression guard
only — not a performance claim.**

| detector | AUC | recall @1% FPR | recall @10% FPR |
|---|---|---|---|
| reference-diff (reference mode) | 1.000 | 100.0% | 100.0% |
| sample-pairs (Dumitrescu–Wu–Wang) | 0.998 | 96.0% | 100.0% |
| rs-analysis (Fridrich) | 0.997 | 95.5% | 99.0% |
| chi-square (Westfeld–Pfitzmann) | 0.947 | 76.5% | 86.0% |
| FUSED (blind) | 1.000 | 99.5% | 100.0% |

Reference mode is calibrated but deliberately **excluded from FUSED**.
Comparing against a known-clean original is near-conclusive, so folding it into
the headline number would describe a situation a SOC almost never has.

### Where detection breaks down

| technique | 5% | 10% | 25% | 50% | 100% |
|---|---|---|---|---|---|
| image-lsb-sequential | 100% | 100% | 100% | 100% | 100% |
| image-lsb-keyed | 96% | 100% | 100% | 100% | 100% |

This table is the project's central claim, measured rather than asserted:
**keyed embedding defeats the histogram-based chi-square attack, but not the two
structural estimators.** Chi-square reads the intensity histogram, which keyed
scattering leaves intact; RS analysis and sample-pair analysis read the LSB
plane's *spatial correlation*, which keyed placement does not disturb. With both
fused, blind detection of keyed embedding at 5% fill rose from 9% (chi-square
alone) to 96%. The two estimators rest on different cover assumptions, so their
independent agreement — not either score alone — is what makes a low-rate
verdict trustworthy.
