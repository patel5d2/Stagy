"""Deterministic keyed index shuffle for scattering payload bits."""

from __future__ import annotations

import hashlib

import numpy as np


def keyed_indices(n: int, seed: bytes) -> np.ndarray:
    """A deterministic permutation of range(n), driven only by seed.

    Same seed -> identical array on every machine/numpy version, because the
    derivation (sha256 -> first 8 bytes -> PCG64 default_rng) is pinned.
    """
    digest = hashlib.sha256(seed).digest()[:8]
    rng = np.random.default_rng(int.from_bytes(digest, "big"))
    return rng.permutation(n)
