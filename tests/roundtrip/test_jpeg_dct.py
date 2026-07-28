"""JPEG DCT codec round-trips (roadmap 8.1).

Acceptance: embed->extract round-trips through a *valid* JPEG in both modes;
over-capacity raises; the output opens in a normal decoder; a non-JPEG output
path is refused. The payload survives a byte-for-byte copy but not re-encoding —
which is inherent to JPEG steganography, and is pinned here so it stays a known
property rather than a surprise.
"""

from __future__ import annotations

import shutil

import numpy as np
import pytest
from PIL import Image

import stagy

pytest.importorskip("jpeglib")
from stagy.codecs import CODECS


@pytest.fixture
def cover(tmp_path):
    """A textured JPEG cover with plenty of non-zero AC coefficients."""
    p = tmp_path / "cover.jpg"
    rng = np.random.default_rng(0)
    Image.fromarray(rng.integers(0, 256, (256, 256, 3), dtype=np.uint8)).save(p, quality=90)
    return p


def test_jpeg_codec_is_registered() -> None:
    assert "jpeg" in CODECS


@pytest.mark.parametrize("mode", ["keyed", "sequential"])
def test_round_trip_through_valid_jpeg(cover, tmp_path, mode) -> None:
    out = tmp_path / f"stego_{mode}.jpg"
    secret = b"CTF{jpeg_dct_jsteg}" * 5
    stagy.hide(str(cover), secret, str(out), codec="jpeg", passphrase="pw", mode=mode)

    # The output must be a JPEG a standard decoder opens without error.
    Image.open(out).load()

    res = stagy.reveal(str(out), codec="jpeg", passphrase="pw", mode=mode)
    assert res.payload == secret


def test_over_capacity_raises(cover, tmp_path) -> None:
    from stagy.errors import CapacityError

    cap = CODECS["jpeg"].capacity(str(cover), mode="sequential")
    out = tmp_path / "x.jpg"
    with pytest.raises(CapacityError):
        stagy.hide(str(cover), b"\x00" * (cap + 64), str(out),
                   codec="jpeg", passphrase="pw", mode="sequential")


def test_wrong_key_does_not_recover(cover, tmp_path) -> None:
    from stagy.errors import StagyError

    out = tmp_path / "s.jpg"
    stagy.hide(str(cover), b"secret", str(out), codec="jpeg", passphrase="right", mode="keyed")
    with pytest.raises(StagyError):
        stagy.reveal(str(out), codec="jpeg", passphrase="wrong", mode="keyed")


def test_non_jpeg_output_refused(cover, tmp_path) -> None:
    from stagy.errors import UnsupportedFormatError

    with pytest.raises(UnsupportedFormatError):
        stagy.hide(str(cover), b"x", str(tmp_path / "out.png"),
                   codec="jpeg", passphrase="pw", mode="keyed")


def test_survives_copy(cover, tmp_path) -> None:
    """A byte-for-byte copy preserves the payload (unlike a re-encode)."""
    out = tmp_path / "s.jpg"
    stagy.hide(str(cover), b"copy-safe", str(out), codec="jpeg", passphrase="pw", mode="keyed")
    copied = tmp_path / "copy.jpg"
    shutil.copyfile(out, copied)
    assert stagy.reveal(str(copied), codec="jpeg", passphrase="pw", mode="keyed").payload == b"copy-safe"


def test_reencode_destroys_payload(cover, tmp_path) -> None:
    """Re-saving through a JPEG encoder requantizes coefficients and wipes it.

    Documents the fragility class: JPEG DCT stego survives copying, not
    re-encoding. Extraction must fail cleanly, not return corruption.
    """
    from stagy.errors import StagyError

    out = tmp_path / "s.jpg"
    stagy.hide(str(cover), b"fragile", str(out), codec="jpeg", passphrase="pw", mode="keyed")
    reencoded = tmp_path / "re.jpg"
    Image.open(out).save(reencoded, quality=70)  # a real re-encode
    with pytest.raises(StagyError):
        stagy.reveal(str(reencoded), codec="jpeg", passphrase="pw", mode="keyed")
