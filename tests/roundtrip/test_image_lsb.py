import os

import numpy as np
import pytest
from PIL import Image

import stagy
from stagy.codecs import CODECS
from stagy.container import KeyMaterial
from stagy.crypto import derive_keys
from stagy.errors import CapacityError, UnsupportedFormatError


def _make_png(path: str, w: int = 512, h: int = 512) -> None:
    rng = np.random.default_rng(0)
    arr = rng.integers(0, 256, size=(h, w, 3), dtype=np.uint8)
    Image.fromarray(arr, "RGB").save(path)


@pytest.mark.parametrize("mode", ["keyed", "sequential"])
def test_codec_roundtrip(tmp_path, mode: str) -> None:
    cover = tmp_path / "c.png"
    stego = tmp_path / "s.png"
    _make_png(str(cover))
    payload = os.urandom(5 * 1024)
    salt = os.urandom(16)
    blob = __import__("stagy.container", fromlist=["encode"]).encode(
        payload, key_material=KeyMaterial(derive_keys("pw", salt).aes_key, salt)
    )
    seed = b"s" * 32
    opts = {"mode": mode, "seed": seed} if mode == "keyed" else {"mode": mode}
    CODECS["image"].embed(str(cover), blob, str(stego), **opts)
    out = CODECS["image"].extract(str(stego), **opts)
    assert out == blob


def test_full_pipeline_roundtrip(tmp_path) -> None:
    cover = tmp_path / "c.png"
    stego = tmp_path / "s.png"
    _make_png(str(cover))
    payload = os.urandom(2048)
    stagy.hide(str(cover), payload, str(stego), passphrase="pw", compress=True, filename="secret.bin")
    got = stagy.reveal(str(stego), passphrase="pw")
    assert got.payload == payload
    assert got.filename == "secret.bin"


def test_over_capacity_raises(tmp_path) -> None:
    cover = tmp_path / "c.png"
    _make_png(str(cover), 8, 8)
    with pytest.raises(CapacityError):
        stagy.hide(str(cover), os.urandom(10_000), str(tmp_path / "o.png"), passphrase="pw")


def test_refuse_lossy_output(tmp_path) -> None:
    cover = tmp_path / "c.png"
    _make_png(str(cover), 64, 64)
    with pytest.raises(UnsupportedFormatError):
        stagy.hide(str(cover), b"x", str(tmp_path / "o.jpg"), passphrase="pw")


def test_stego_visually_close(tmp_path) -> None:
    cover = tmp_path / "c.png"
    stego = tmp_path / "s.png"
    _make_png(str(cover))
    stagy.hide(str(cover), os.urandom(1024), str(stego), passphrase="pw")
    a = np.asarray(Image.open(cover).convert("RGB"), dtype=np.float64)
    b = np.asarray(Image.open(stego).convert("RGB"), dtype=np.float64)
    mse = float(((a - b) ** 2).mean())
    assert mse < 1.0
