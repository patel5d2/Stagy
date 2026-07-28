"""Tests for entropy analysis and file-carving (roadmap Task 6.5).

Acceptance criteria under test:
  * the file-carver locates a ZIP appended after a PNG's IEND marker
  * the entropy scan highlights an appended high-entropy (encrypted) region
  * clean covers and ordinary non-image files are not flagged

The appended-ZIP fixture is built directly here (byte-identical to what the
Task 4.1 AppendedDataCodec will emit); a real end-to-end test against 4.1 should
follow once that codec lands.
"""

import io
import zipfile
from pathlib import Path

import numpy as np
from PIL import Image

from stagy.analysis import entropy, filecarve, report


def _clean_png(path: str, w: int = 64, h: int = 64) -> None:
    rng = np.random.default_rng(0)
    Image.fromarray(rng.integers(0, 256, (h, w, 3), dtype=np.uint8), "RGB").save(path)


def _zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("secret.txt", "the hidden message")
    return buf.getvalue()


def _png_with_appended(path: str, blob: bytes) -> None:
    clean = Path(str(path) + ".clean.png")
    _clean_png(str(clean))
    Path(path).write_bytes(clean.read_bytes() + blob)


# ---- file-carving -------------------------------------------------------------

def test_carver_finds_appended_zip(tmp_path) -> None:
    poly = tmp_path / "poly.png"
    _png_with_appended(str(poly), _zip_bytes())

    res = filecarve.analyze(str(poly))
    assert res.score == 1.0
    assert res.log_lr > 0
    assert any(c.after_eof and "ZIP" in c.description for c in res.carved)
    # The polyglot must still open as a normal PNG.
    Image.open(poly).load()


def test_clean_png_carves_nothing(tmp_path) -> None:
    p = tmp_path / "clean.png"
    _clean_png(str(p))
    res = filecarve.analyze(str(p))
    assert res.score == 0.0
    assert res.log_lr == 0.0


def test_primary_eof_detects_containers(tmp_path) -> None:
    p = tmp_path / "c.png"
    _clean_png(str(p))
    data = p.read_bytes()
    eof = filecarve.primary_eof(data)
    assert eof is not None and eof == len(data)  # clean PNG ends exactly at IEND
    assert filecarve.primary_eof(b"not a container") is None


# ---- entropy ------------------------------------------------------------------

def test_shannon_bounds() -> None:
    assert entropy.shannon(b"\x00" * 1000) == 0.0  # single symbol -> 0 bits
    uniform = bytes(range(256)) * 8
    assert entropy.shannon(uniform) > 7.99  # all symbols equal -> ~8 bits


def test_entropy_flags_appended_encrypted_blob(tmp_path) -> None:
    poly = tmp_path / "poly.png"
    blob = np.random.default_rng(1).integers(0, 256, 3000, dtype=np.uint8).tobytes()
    _png_with_appended(str(poly), blob)

    res = entropy.analyze(str(poly))
    assert res.appended_bytes == 3000
    assert res.appended_entropy > 7.0
    assert res.log_lr > 0


def test_clean_png_has_no_appended_region(tmp_path) -> None:
    p = tmp_path / "clean.png"
    _clean_png(str(p))
    res = entropy.analyze(str(p))
    assert res.appended_bytes == 0
    assert res.log_lr == 0.0


# ---- report integration -------------------------------------------------------

def test_report_flags_polyglot_and_lists_signal(tmp_path) -> None:
    poly = tmp_path / "poly.png"
    _png_with_appended(str(poly), _zip_bytes())
    rep = report.analyze(str(poly))
    assert rep.verdict == "likely-stego"
    assert "file-carve" in {s.name for s in rep.signals}


def test_non_image_clean_file_is_clean(tmp_path) -> None:
    """The false-positive guard: a zero-evidence non-image file must read clean,
    despite fitted thresholds sitting below the prior."""
    f = tmp_path / "notes.bin"
    f.write_bytes(b"just some ordinary bytes, nothing hidden here\n" * 50)
    rep = report.analyze(str(f))
    assert rep.verdict == "clean"
    assert {"file-carve", "entropy"} <= {s.name for s in rep.signals}
