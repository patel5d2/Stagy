"""Labeled stego/clean corpus generation — ground truth for the detection suite.

Every detector in `analysis/` is scored against a corpus built here. The rules
that make the numbers mean something:

  * **Paired.** Each stego case is derived from a specific clean cover, and that
    same cover appears as a clean case. A detector cannot win by learning
    "this cover looks suspicious" — both labels share the source image.
  * **Split by cover, not by case.** All cases from one cover land in the same
    split. Splitting by case would put a cover's clean and stego versions on
    opposite sides, leaking the answer into the calibration set.
  * **Swept embedding rate.** Detection difficulty is dominated by payload
    size. A detector that only catches 100%-fill is near-useless; real payloads
    are small. Rates run down to 5% of capacity for that reason.

**Synthetic covers overestimate detection.** The generated covers here are
smooth gradients plus texture — their LSB planes are far cleaner than a real
photograph's sensor noise, so every analyzer scores better than it deserves.
Numbers from a synthetic corpus are a regression guard, not a performance
claim. Pass `covers=` a directory of real photographs before quoting any
figure. See `docs/detection-benchmark.md`.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from pathlib import Path

import numpy as np
from PIL import Image

import stagy

from ..codecs import CODECS

DEFAULT_RATES = (0.05, 0.10, 0.25, 0.50, 1.00)
DEFAULT_MODES = ("keyed", "sequential")
_COVER_EXT = (".png", ".bmp")
_CONTAINER_OVERHEAD = 96  # header+salt+nonce+tag+crc, plus slack for a filename


@dataclass(frozen=True)
class Case:
    """One labeled file in the corpus."""

    path: str
    label: int  # 1 = stego, 0 = clean
    technique: str  # "clean" | "image-lsb-keyed" | "image-lsb-sequential"
    rate: float  # payload as a fraction of cover capacity (0.0 for clean)
    cover_id: str  # groups derived cases with their source cover
    split: str  # "train" (fit calibration) | "test" (report metrics)


_SYNTH_NOISE_SIGMA = 1.8
"""Grain amplitude for synthetic covers. Small on purpose, and the most
load-bearing constant in this module.

Adding Gaussian noise with sigma >= 3 convolves the intensity histogram until
adjacent bins (2i, 2i+1) are equal to within Poisson error — which is precisely
the signature LSB embedding produces. Measured on the benchmark: sigma=6 drove
clean covers to chi/df = 0.57 and made a *clean* image indistinguishable from a
fully embedded one. Raise this and the corpus silently becomes unable to
validate any histogram-based detector.
"""


def synth_cover(path: str, *, width: int = 256, height: int = 256, seed: int = 0) -> None:
    """Write a synthetic cover with a realistically structured histogram.

    Piecewise-flat regions (a nearest-seed / Voronoi partition) stand in for
    scene content — sky, walls, surfaces — because real photographs have spiky
    regional histograms dominated by a few tones, not the smooth ones a
    gradient produces. See the module warning: this is a regression guard, not
    a substitute for real covers.
    """
    rng = np.random.default_rng(seed)
    n_seeds = 200
    sy = rng.integers(0, height, n_seeds)
    sx = rng.integers(0, width, n_seeds)
    levels = rng.uniform(15.0, 240.0, (n_seeds, 3))
    yy, xx = np.mgrid[0:height, 0:width]
    nearest = np.argmin((yy[..., None] - sy) ** 2 + (xx[..., None] - sx) ** 2, axis=2)
    arr = levels[nearest] + rng.normal(0.0, _SYNTH_NOISE_SIGMA, (height, width, 3))
    Image.fromarray(arr.clip(0, 255).astype(np.uint8), "RGB").save(path)


def _covers(source: str | None, out_dir: Path, n_synth: int, seed: int) -> list[Path]:
    if source:
        found = sorted(p for p in Path(source).iterdir() if p.suffix.lower() in _COVER_EXT)
        if not found:
            raise ValueError(f"no {'/'.join(_COVER_EXT)} covers found in {source}")
        return found
    synth_dir = out_dir / "covers"
    synth_dir.mkdir(parents=True, exist_ok=True)
    made = []
    for i in range(n_synth):
        p = synth_dir / f"synth_{i:03d}.png"
        synth_cover(str(p), seed=seed + i)
        made.append(p)
    return made


def build(
    out_dir: str,
    *,
    covers: str | None = None,
    n_synth: int = 200,
    rates: tuple[float, ...] = DEFAULT_RATES,
    modes: tuple[str, ...] = DEFAULT_MODES,
    stego_per_cover: int | None = 2,
    test_fraction: float = 0.5,
    seed: int = 0,
) -> list[Case]:
    """Generate clean/stego pairs and return their labels.

    Each cover yields one clean Case plus `stego_per_cover` stego Cases drawn
    from the (rate x mode) grid — or the full grid when `stego_per_cover` is
    None.

    **Sampling the grid rather than exhausting it is what makes a low-FPR
    number measurable.** The full cross-product gives one clean file per ten
    stego files, so a corpus large enough to resolve a 1% false-positive rate
    (>=100 clean cases in the held-out split) would need ten times the
    embedding work. Sampling spends the same compute on more distinct covers,
    which is the axis the false-positive rate actually depends on.
    """
    out = Path(out_dir)
    (out / "stego").mkdir(parents=True, exist_ok=True)
    cover_paths = _covers(covers, out, n_synth, seed)

    rng = np.random.default_rng(seed)
    order = rng.permutation(len(cover_paths))
    n_test = max(1, int(len(cover_paths) * test_fraction))
    test_ids = {int(i) for i in order[:n_test]}
    grid = [(r, m) for r in rates for m in modes]

    cases: list[Case] = []
    for i, cover in enumerate(cover_paths):
        cover_id = cover.stem
        split = "test" if i in test_ids else "train"
        cases.append(Case(str(cover), 0, "clean", 0.0, cover_id, split))

        capacity = CODECS["image"].capacity(str(cover), bits=1, channels="RGB")
        if stego_per_cover is None:
            chosen = grid
        else:
            picks = rng.choice(len(grid), size=min(stego_per_cover, len(grid)), replace=False)
            chosen = [grid[int(p)] for p in picks]

        for rate, mode in chosen:
            n_bytes = int(capacity * rate) - _CONTAINER_OVERHEAD
            if n_bytes < 16:
                continue
            dest = out / "stego" / f"{cover_id}_{mode}_{int(rate * 100):03d}.png"
            stagy.hide(
                str(cover),
                os.urandom(n_bytes),
                str(dest),
                passphrase="corpus-benchmark-key",
                encrypt=True,
                mode=mode,
            )
            cases.append(Case(str(dest), 1, f"image-lsb-{mode}", rate, cover_id, split))
    return cases


def save_manifest(cases: list[Case], path: str) -> None:
    """Write the labels next to the files so a run is reproducible and auditable."""
    import json

    Path(path).write_text(json.dumps([asdict(c) for c in cases], indent=2))


def load_manifest(path: str) -> list[Case]:
    import json

    return [Case(**d) for d in json.loads(Path(path).read_text())]
