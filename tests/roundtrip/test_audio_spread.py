"""Spread-spectrum audio codec (roadmap 8.2).

Acceptance: exact round-trip (the container CRC demands it), lower capacity than
LSB, keyed-only, and — the reason the technique exists — the payload survives
additive noise that annihilates LSB embedding.
"""

from __future__ import annotations

import wave

import numpy as np
import pytest

import stagy
from stagy.codecs import CODECS
from stagy.errors import CapacityError, StagyError


def _write_wav(path, samples, sr=44100) -> None:
    with wave.open(str(path), "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(sr)
        w.writeframes(np.clip(np.rint(samples), -32768, 32767).astype("<i2").tobytes())


def _read_wav(path) -> np.ndarray:
    with wave.open(str(path), "rb") as w:
        return np.frombuffer(w.readframes(w.getnframes()), dtype="<i2").astype(np.float64)


@pytest.fixture
def cover(tmp_path):
    """A loud, tonal 30s host — the worst case for correlation-based recovery."""
    p = tmp_path / "cover.wav"
    sr = 44100
    t = np.linspace(0, 30, sr * 30, endpoint=False)
    sig = (8000 * np.sin(2 * np.pi * 220 * t)
           + 5000 * np.sin(2 * np.pi * 440 * t)
           + 3000 * np.random.default_rng(1).standard_normal(t.size))
    _write_wav(p, sig, sr)
    return p


def test_codec_is_registered() -> None:
    assert "audiospread" in CODECS


def test_exact_round_trip(cover, tmp_path) -> None:
    out = tmp_path / "stego.wav"
    secret = b"CTF{spread_spectrum_audio}"
    stagy.hide(str(cover), secret, str(out), codec="audiospread", passphrase="pw")
    assert stagy.reveal(str(out), codec="audiospread", passphrase="pw").payload == secret


def test_capacity_is_far_below_lsb(cover) -> None:
    ss = CODECS["audiospread"].capacity(str(cover))
    lsb = CODECS["audio"].capacity(str(cover))
    assert 0 < ss < lsb  # one bit per block, not one per sample


def test_keyed_only(cover, tmp_path) -> None:
    """No passphrase means no chip sequence, so embedding must be refused."""
    with pytest.raises((ValueError, StagyError)):
        stagy.hide(str(cover), b"x", str(tmp_path / "o.wav"),
                   codec="audiospread", encrypt=False, passphrase=None)


def test_wrong_key_does_not_recover(cover, tmp_path) -> None:
    out = tmp_path / "s.wav"
    stagy.hide(str(cover), b"secret", str(out), codec="audiospread", passphrase="right")
    with pytest.raises(StagyError):
        stagy.reveal(str(out), codec="audiospread", passphrase="wrong")


def test_survives_noise_that_destroys_lsb(cover, tmp_path) -> None:
    """The point of spread spectrum: robustness LSB cannot offer.

    Add Gaussian noise of std 50 — far more than enough to randomize every
    sample LSB — and the correlation still recovers the payload exactly.
    """
    out = tmp_path / "s.wav"
    secret = b"robust-payload"
    stagy.hide(str(cover), secret, str(out), codec="audiospread", passphrase="pw")

    noisy = tmp_path / "noisy.wav"
    b = _read_wav(out)
    _write_wav(noisy, b + np.random.default_rng(2).normal(0, 50, b.size))
    assert stagy.reveal(str(noisy), codec="audiospread", passphrase="pw").payload == secret


def test_over_capacity_raises(tmp_path) -> None:
    p = tmp_path / "short.wav"
    _write_wav(p, np.zeros(44100))  # 1s -> ~5 bytes capacity
    with pytest.raises(CapacityError):
        stagy.hide(str(p), b"way too much payload for one second of audio" * 10,
                   str(tmp_path / "o.wav"), codec="audiospread", passphrase="pw")
