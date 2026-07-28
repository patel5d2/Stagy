"""Tests for the WAV LSB codec (roadmap Task 3.1 / 3.2).

Acceptance criteria under test:
  * round-trip through a stereo 16-bit WAV in keyed and sequential modes
  * output is bit-for-bit identical above the LSB (sounds identical at bits=1)
  * over-capacity raises; non-16-bit and lossy output are refused
  * capacity is num_samples * bits // 8
"""

import os
import wave

import numpy as np
import pytest

import stagy
from stagy.codecs import CODECS
from stagy.container import KeyMaterial, encode
from stagy.crypto import derive_keys
from stagy.errors import CapacityError, UnsupportedFormatError


def _make_wav(path: str, nframes: int = 20000, nchannels: int = 2, sampwidth: int = 2) -> None:
    rng = np.random.default_rng(0)
    with wave.open(path, "wb") as w:
        w.setnchannels(nchannels)
        w.setsampwidth(sampwidth)
        w.setframerate(44100)
        if sampwidth == 2:
            data = rng.integers(-30000, 30000, size=nframes * nchannels, dtype=np.int16)
            w.writeframes(data.astype("<i2").tobytes())
        else:  # 8-bit unsigned PCM, for the rejection test
            data8 = rng.integers(0, 256, size=nframes * nchannels, dtype=np.uint8)
            w.writeframes(data8.tobytes())


def _samples(path: str) -> np.ndarray:
    with wave.open(path, "rb") as w:
        return np.frombuffer(w.readframes(w.getnframes()), dtype="<i2")


def _container(payload: bytes) -> bytes:
    salt = os.urandom(16)
    return encode(payload, key_material=KeyMaterial(derive_keys("pw", salt).aes_key, salt))


@pytest.mark.parametrize("mode", ["keyed", "sequential"])
def test_codec_roundtrip(tmp_path, mode: str) -> None:
    cover = tmp_path / "c.wav"
    stego = tmp_path / "s.wav"
    _make_wav(str(cover))
    blob = _container(os.urandom(2048))
    opts = {"mode": mode, "seed": b"s" * 32} if mode == "keyed" else {"mode": mode}
    CODECS["audio"].embed(str(cover), blob, str(stego), **opts)
    assert CODECS["audio"].extract(str(stego), **opts) == blob


def test_full_pipeline_roundtrip(tmp_path) -> None:
    cover = tmp_path / "c.wav"
    stego = tmp_path / "s.wav"
    _make_wav(str(cover))
    payload = os.urandom(1500)
    stagy.hide(str(cover), payload, str(stego), codec="audio", passphrase="pw",
               compress=True, filename="s.bin")
    got = stagy.reveal(str(stego), codec="audio", passphrase="pw")
    assert got.payload == payload
    assert got.filename == "s.bin"


def test_only_lsb_changes(tmp_path) -> None:
    cover = tmp_path / "c.wav"
    stego = tmp_path / "s.wav"
    _make_wav(str(cover))
    stagy.hide(str(cover), os.urandom(1024), str(stego), codec="audio", passphrase="pw")
    a, b = _samples(str(cover)), _samples(str(stego))
    # bits=1: every sample differs by at most its LSB, higher bits untouched.
    assert np.array_equal(a.astype(np.uint16) >> 1, b.astype(np.uint16) >> 1)


def test_capacity(tmp_path) -> None:
    cover = tmp_path / "c.wav"
    _make_wav(str(cover), nframes=20000, nchannels=2)
    assert CODECS["audio"].capacity(str(cover), bits=1) == 20000 * 2 * 1 // 8


def test_over_capacity_raises(tmp_path) -> None:
    cover = tmp_path / "c.wav"
    _make_wav(str(cover), nframes=1000, nchannels=1)  # 1000 samples -> 125 bytes cap
    with pytest.raises(CapacityError):
        stagy.hide(str(cover), os.urandom(10_000), str(tmp_path / "o.wav"),
                   codec="audio", passphrase="pw")


def test_reject_non_16bit(tmp_path) -> None:
    cover = tmp_path / "c8.wav"
    _make_wav(str(cover), sampwidth=1)
    with pytest.raises(UnsupportedFormatError):
        CODECS["audio"].capacity(str(cover), bits=1)


def test_reject_lossy_output(tmp_path) -> None:
    cover = tmp_path / "c.wav"
    _make_wav(str(cover))
    with pytest.raises(UnsupportedFormatError):
        stagy.hide(str(cover), b"x", str(tmp_path / "o.mp3"), codec="audio", passphrase="pw")
