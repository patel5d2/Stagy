"""Tests for the appended-data / polyglot codec (roadmap Task 4.1).

Acceptance criteria under test:
  * append -> recover round-trips (PNG and JPEG covers)
  * the output image still opens normally and its pixels are untouched
  * the appended region is byte-identical to the framed container
  * capacity is bounded by disk, not cover size
  * the polyglot output is both a viewable image and a readable ZIP

Plus the attack/detector loop: the blue-team analyzers from Phase 6.5 catch what
this red-team codec hides.
"""

import io
import os
import zipfile

import numpy as np
import pytest
from PIL import Image

import stagy
from stagy.analysis import corpus, report
from stagy.codecs import CODECS
from stagy.codecs.metadata import make_polyglot
from stagy.container import KeyMaterial, encode
from stagy.crypto import derive_keys
from stagy.errors import NoPayloadError


def _png(path: str) -> None:
    corpus.synth_cover(path, seed=5)


def _jpeg(path: str) -> None:
    rng = np.random.default_rng(5)
    Image.fromarray(rng.integers(0, 256, (64, 64, 3), dtype=np.uint8), "RGB").save(path, "JPEG")


def _zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("loot.txt", "the exfiltrated data")
    return buf.getvalue()


@pytest.mark.parametrize("make,ext", [(_png, "png"), (_jpeg, "jpg")])
def test_roundtrip_and_image_intact(tmp_path, make, ext) -> None:
    cover = tmp_path / f"cover.{ext}"
    stego = tmp_path / f"stego.{ext}"
    make(str(cover))
    payload = os.urandom(2048)

    stagy.hide(str(cover), payload, str(stego), codec="appended", passphrase="pw")
    got = stagy.reveal(str(stego), codec="appended", passphrase="pw")
    assert got.payload == payload

    # The image still opens and is pixel-for-pixel the original cover.
    before = np.asarray(Image.open(cover).convert("RGB"))
    after = np.asarray(Image.open(stego).convert("RGB"))
    assert np.array_equal(before, after)


def test_appended_region_is_byte_identical(tmp_path) -> None:
    cover = tmp_path / "c.png"
    stego = tmp_path / "s.png"
    _png(str(cover))
    salt = os.urandom(16)
    blob = encode(os.urandom(500), key_material=KeyMaterial(derive_keys("pw", salt).aes_key, salt))
    CODECS["appended"].embed(str(cover), blob, str(stego), seed=b"x" * 32)
    assert CODECS["appended"].extract(str(stego)) == blob
    # And the stego file is exactly cover-bytes + the container.
    assert stego.read_bytes() == cover.read_bytes() + blob


def test_extract_survives_eoi_marker_in_container(tmp_path) -> None:
    """Regression: an appended container that itself contains the JPEG EOI bytes
    (FF D9) must still be located. Recovering by rfind of the 2-byte marker found
    a spurious end inside the container ~3% of the time; the CRC scan does not."""
    cover = tmp_path / "c.jpg"
    stego = tmp_path / "s.jpg"
    _jpeg(str(cover))
    blob = encode(b"\xff\xd9" * 32, encrypt=False)  # container bytes contain FF D9
    assert b"\xff\xd9" in blob
    CODECS["appended"].embed(str(cover), blob, str(stego))
    assert CODECS["appended"].extract(str(stego)) == blob


def test_capacity_is_disk_bounded(tmp_path) -> None:
    cover = tmp_path / "c.png"
    _png(str(cover))
    cap = CODECS["appended"].capacity(str(cover))
    assert cap > cover.stat().st_size * 100  # not bounded by the cover


def test_extract_clean_file_raises(tmp_path) -> None:
    cover = tmp_path / "clean.png"
    _png(str(cover))
    with pytest.raises(NoPayloadError):
        CODECS["appended"].extract(str(cover))


def test_polyglot_is_image_and_zip(tmp_path) -> None:
    cover = tmp_path / "c.png"
    poly = tmp_path / "poly.png"
    _png(str(cover))
    make_polyglot(str(cover), _zip_bytes(), str(poly))

    Image.open(poly).load()  # opens as an image
    with zipfile.ZipFile(poly) as z:  # and as a ZIP
        assert z.read("loot.txt") == b"the exfiltrated data"


# ---- attack / detector loop ---------------------------------------------------

def test_detector_catches_appended_encrypted_blob(tmp_path) -> None:
    """Encrypted append has no file signature, so file-carve can't see it — but
    its high entropy gives it away. The complementary analyzer earns its keep."""
    cover = tmp_path / "c.png"
    stego = tmp_path / "s.png"
    _png(str(cover))
    stagy.hide(str(cover), os.urandom(4096), str(stego), codec="appended", passphrase="pw")

    rep = report.analyze(str(stego))
    assert rep.verdict == "likely-stego"
    fired = {s.name for s in rep.signals if (s.log_lr or 0) > 0}
    assert "entropy" in fired


def test_detector_catches_polyglot_via_filecarve(tmp_path) -> None:
    cover = tmp_path / "c.png"
    poly = tmp_path / "poly.png"
    _png(str(cover))
    make_polyglot(str(cover), _zip_bytes(), str(poly))

    rep = report.analyze(str(poly))
    assert rep.verdict == "likely-stego"
    assert "file-carve" in {s.name for s in rep.signals if (s.log_lr or 0) > 0}
