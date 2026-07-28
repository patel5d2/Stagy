"""Tests for the EXIF metadata codec (roadmap Task 4.2).

Acceptance criteria under test:
  * write -> read a small payload through a JPEG's EXIF
  * unrelated image data is untouched (only the APP1 segment changes)
  * metadata_scan surfaces the hidden UserComment for the analyzer
  * missing optional dependency fails with a clear StagyError
"""

import os
import sys

import numpy as np
import pytest
from PIL import Image

import stagy
from stagy.codecs import CODECS, metadata
from stagy.container import KeyMaterial, encode
from stagy.crypto import derive_keys
from stagy.errors import NoPayloadError, StagyError, UnsupportedFormatError


def _jpeg(path: str, w: int = 64, h: int = 64) -> None:
    rng = np.random.default_rng(5)
    Image.fromarray(rng.integers(0, 256, (h, w, 3), dtype=np.uint8), "RGB").save(path, "JPEG")


def _container(payload: bytes) -> bytes:
    salt = os.urandom(16)
    return encode(payload, key_material=KeyMaterial(derive_keys("pw", salt).aes_key, salt))


def test_pipeline_roundtrip(tmp_path) -> None:
    cover = tmp_path / "c.jpg"
    stego = tmp_path / "s.jpg"
    _jpeg(str(cover))
    payload = os.urandom(256)
    stagy.hide(str(cover), payload, str(stego), codec="exif", passphrase="pw", filename="s.bin")
    got = stagy.reveal(str(stego), codec="exif", passphrase="pw")
    assert got.payload == payload
    assert got.filename == "s.bin"


def test_image_data_untouched(tmp_path) -> None:
    cover = tmp_path / "c.jpg"
    stego = tmp_path / "s.jpg"
    _jpeg(str(cover))
    stagy.hide(str(cover), os.urandom(128), str(stego), codec="exif", passphrase="pw")
    before = np.asarray(Image.open(cover).convert("RGB"))
    after = np.asarray(Image.open(stego).convert("RGB"))
    assert np.array_equal(before, after)  # only APP1 changed; DCT data copied verbatim


def test_codec_roundtrip_bit_identical(tmp_path) -> None:
    cover = tmp_path / "c.jpg"
    stego = tmp_path / "s.jpg"
    _jpeg(str(cover))
    blob = _container(os.urandom(200))
    CODECS["exif"].embed(str(cover), blob, str(stego))
    assert CODECS["exif"].extract(str(stego)) == blob


def test_extract_clean_jpeg_raises(tmp_path) -> None:
    cover = tmp_path / "clean.jpg"
    _jpeg(str(cover))
    with pytest.raises(NoPayloadError):
        CODECS["exif"].extract(str(cover))


def test_reject_non_jpeg(tmp_path) -> None:
    png = tmp_path / "c.png"
    Image.fromarray(np.zeros((16, 16, 3), dtype=np.uint8), "RGB").save(png)
    with pytest.raises(UnsupportedFormatError):
        CODECS["exif"].embed(str(png), b"x", str(tmp_path / "o.jpg"))
    jpg = tmp_path / "c.jpg"
    _jpeg(str(jpg))
    with pytest.raises(UnsupportedFormatError):
        CODECS["exif"].embed(str(jpg), b"x", str(tmp_path / "o.png"))


def test_over_capacity_raises(tmp_path) -> None:
    cover = tmp_path / "c.jpg"
    _jpeg(str(cover))
    from stagy.errors import CapacityError

    with pytest.raises(CapacityError):
        stagy.hide(str(cover), os.urandom(80_000), str(tmp_path / "o.jpg"),
                   codec="exif", passphrase="pw")


def test_metadata_scan_surfaces_usercomment(tmp_path) -> None:
    cover = tmp_path / "c.jpg"
    stego = tmp_path / "s.jpg"
    _jpeg(str(cover))
    stagy.hide(str(cover), os.urandom(200), str(stego), codec="exif", passphrase="pw")

    clean_scan = metadata.metadata_scan(str(cover))
    assert "UserComment" not in clean_scan.get("exif", {}).get("Exif", {})

    stego_scan = metadata.metadata_scan(str(stego))
    assert "UserComment" in stego_scan["exif"]["Exif"]


def test_missing_piexif_is_clear_error(tmp_path, monkeypatch) -> None:
    # Simulate piexif not installed: None in sys.modules makes `import piexif` fail.
    monkeypatch.setitem(sys.modules, "piexif", None)
    with pytest.raises(StagyError, match="docs-fmt"):
        metadata._piexif()
    # metadata_scan degrades gracefully rather than crashing.
    cover = tmp_path / "c.jpg"
    _jpeg(str(cover))
    assert metadata.metadata_scan(str(cover)) == {}
