import os

import numpy as np
from PIL import Image

import stagy
from stagy.analysis import bitplane, chi_square, corpus, report


def _cover(path: str, seed: int = 7) -> None:
    """A cover with a realistically structured histogram."""
    corpus.synth_cover(path, seed=seed)


def _smooth_photo(path: str, w: int = 256, h: int = 256) -> None:
    """Smooth gradient + heavy Gaussian noise — the chi-square blind spot."""
    rng = np.random.default_rng(7)
    base = np.linspace(0, 255, w, dtype=np.float64)
    arr = np.tile(base, (h, 1))[..., None].repeat(3, axis=2)
    arr = (arr + rng.normal(0, 8, arr.shape)).clip(0, 255).astype(np.uint8)
    Image.fromarray(arr, "RGB").save(path)


def test_chi_square_clean_low(tmp_path) -> None:
    p = tmp_path / "clean.png"
    _cover(str(p))
    assert chi_square.analyze(str(p)).score < 0.5


def test_chi_square_sequential_beats_keyed(tmp_path) -> None:
    clean = tmp_path / "clean.png"
    _cover(str(clean))
    payload = os.urandom(6000)  # fill a good chunk to make the signal clear

    seq = tmp_path / "seq.png"
    stagy.hide(str(clean), payload, str(seq), encrypt=False, mode="sequential")
    keyed = tmp_path / "keyed.png"
    stagy.hide(str(clean), payload, str(keyed), passphrase="pw", mode="keyed")

    clean_s = chi_square.analyze(str(clean)).score
    seq_s = chi_square.analyze(str(seq)).score
    keyed_s = chi_square.analyze(str(keyed)).score
    assert seq_s > clean_s  # sequential is loud
    assert seq_s > keyed_s  # keyed scatters -> quieter, exactly why it exists


def test_p_max_saturates_with_region_count_but_score_does_not(tmp_path) -> None:
    """Guards the multiple-comparison bug that made this detector useless.

    `region_p` is a per-region upper-tail p-value, so the maximum over N
    regions drifts toward 1.0 on *clean* images purely from taking N draws.
    Scoring on `p_max` measured AUC 0.566 — barely above chance. This pins both
    halves: the saturation is real and grows with region count, and the fixed
    16-region `score` does not inherit it. It is why REGIONS is a constant
    rather than a function of image size.
    """
    p = tmp_path / "clean.png"
    _cover(str(p))
    default = chi_square.analyze(str(p))
    many = chi_square.analyze(str(p), regions=256)

    assert default.p_max < 0.5  # properly powered regions behave
    assert many.p_max > 0.9  # more regions -> the maximum saturates
    assert default.score < 0.5  # the headline score stays honest on a clean file
    assert default.min_chi_ratio > 1.0  # a clean image's pairs are NOT equalized


def test_chi_square_elevated_by_smooth_noise(tmp_path) -> None:
    """A known, documented limitation — pinned so it cannot regress silently.

    Gaussian noise with sigma >= 3 convolves the histogram until adjacent bins
    are equal to within Poisson error, the same signature LSB embedding leaves.
    A clean but heavily smoothed cover therefore scores elevated and can reach
    'suspicious'. This is why the benchmark corpus keeps its grain low, and why
    real photographs are required before quoting any detection figure.
    """
    smooth = tmp_path / "smooth.png"
    structured = tmp_path / "structured.png"
    _smooth_photo(str(smooth))
    _cover(str(structured))

    assert chi_square.analyze(str(smooth)).score > chi_square.analyze(str(structured)).score
    assert report.analyze(str(smooth)).verdict != "clean"  # a false positive, by design


def test_bitplane_shape(tmp_path) -> None:
    p = tmp_path / "clean.png"
    _cover(str(p))
    plane = bitplane.extract_plane(str(p), 0)
    assert plane.shape == (256, 256)
    assert set(np.unique(plane).tolist()).issubset({0, 255})


def test_report_clean_and_reference_catches_keyed(tmp_path) -> None:
    clean = tmp_path / "clean.png"
    _cover(str(clean))
    assert report.analyze(str(clean)).verdict == "clean"

    keyed = tmp_path / "keyed.png"
    stagy.hide(str(clean), os.urandom(4000), str(keyed), passphrase="pw", mode="keyed")
    # Without a reference, keyed may slip past chi-square (documented tradeoff).
    # With the known-clean original, the LSB diff makes it near-certain.
    rep = report.analyze(str(keyed), reference=str(clean))
    assert rep.verdict == "likely-stego"
    assert rep.probability > report.analyze(str(keyed)).probability


def test_reference_diff_scores_on_bit_confinement_not_magnitude(tmp_path) -> None:
    """A small payload changes few LSBs; that must not read as evidence *against*.

    Scoring the reference diff by magnitude inverted the tool's strongest
    signal: a 5%-fill payload flips ~2.5% of LSBs, which scored 0.05 and pushed
    the posterior down. What discriminates is that the changes are confined to
    bit 0, not how many there are.
    """
    clean = tmp_path / "clean.png"
    _cover(str(clean))
    tiny = tmp_path / "tiny.png"
    stagy.hide(str(clean), os.urandom(200), str(tiny), passphrase="pw", mode="keyed")

    (sig,) = [s for s in report.raw_signals(str(tiny), reference=str(clean))
              if s.name == "reference-diff"]
    assert sig.score > 0.99  # near-conclusive despite a tiny payload

    # A clean file against itself is the opposite: no evidence at all.
    (same,) = [s for s in report.raw_signals(str(clean), reference=str(clean))
               if s.name == "reference-diff"]
    assert same.score == 0.0


def test_report_json_is_serializable(tmp_path) -> None:
    import json

    p = tmp_path / "clean.png"
    _cover(str(p))
    d = json.loads(report.analyze(str(p)).to_json())
    assert d["attack_technique"] == "T1027.003"
    assert 0.0 <= d["probability"] <= 1.0
    assert d["verdict"] in {"clean", "suspicious", "likely-stego"}
