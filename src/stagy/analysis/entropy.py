"""Sliding-window Shannon entropy — finds appended encrypted/compressed blobs.

Stagy's own appended-data codec hides the *encrypted* container after the
cover's EOF, so it carries no file signature for `filecarve` to catch. What it
cannot hide is its entropy: ciphertext and compressed data sit near the 8.0
bits/byte ceiling, well above ordinary file structure. A high-entropy region
appended after a container's end is the tell.

The windowed profile also localizes *where* the anomaly is, which powers the web
app's entropy-strip view. Like `filecarve`, evidence here is asymmetric — a
high-entropy appended tail is suspicious, but its absence is neutral, so the
analyzer supplies its own weight rather than being calibrated on the LSB corpus.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from .filecarve import primary_eof

_WINDOW = 2048
_STEP = 1024
_MIN_APPENDED = 16  # bytes; a shorter tail cannot support an entropy estimate
_HIGH_ENTROPY = 7.0  # bits/byte; encrypted/compressed data lives above this
_LOG_LR_APPENDED_BLOB = 3.0


@dataclass(frozen=True)
class EntropyResult:
    score: float  # 0..1 (appended-tail entropy / 8), strength of the anomaly
    log_lr: float  # deterministic evidence weight (asymmetric: absence -> 0)
    max_entropy: float  # bits/byte, peak over all windows
    appended_bytes: int  # size of the region past the container EOF (0 if none)
    appended_entropy: float  # entropy of that appended region (0 if none)
    detail: str
    windows: list[float] = field(default_factory=list)  # per-window profile, for viz


def shannon(block: bytes) -> float:
    """Shannon entropy of a byte block in bits/byte (0..8)."""
    if not block:
        return 0.0
    counts = np.bincount(np.frombuffer(block, dtype=np.uint8), minlength=256).astype(np.float64)
    p = counts[counts > 0] / counts.sum()
    return float(-(p * np.log2(p)).sum())


def _profile(data: bytes) -> list[float]:
    if len(data) <= _WINDOW:
        return [shannon(data)] if data else []
    return [shannon(data[i : i + _WINDOW]) for i in range(0, len(data) - _WINDOW + 1, _STEP)]


def analyze(path: str, *, window: int = _WINDOW) -> EntropyResult:
    data = Path(path).read_bytes()
    windows = _profile(data)
    max_e = max(windows) if windows else 0.0

    eof = primary_eof(data)
    tail = data[eof:] if eof is not None else b""
    if len(tail) >= _MIN_APPENDED:
        tail_e = shannon(tail)
        if tail_e >= _HIGH_ENTROPY:
            return EntropyResult(
                score=tail_e / 8.0,
                log_lr=_LOG_LR_APPENDED_BLOB,
                max_entropy=max_e,
                appended_bytes=len(tail),
                appended_entropy=tail_e,
                detail=f"{len(tail)} bytes appended after the container EOF at "
                f"{tail_e:.2f}/8 bits/byte — consistent with an encrypted or compressed blob",
                windows=windows,
            )
        return EntropyResult(
            0.0, 0.0, max_e, len(tail), tail_e,
            f"{len(tail)} bytes appended after EOF but only {tail_e:.2f}/8 bits/byte "
            "— not high-entropy hidden data",
            windows,
        )
    return EntropyResult(
        0.0, 0.0, max_e, 0, 0.0,
        f"no appended region; peak window entropy {max_e:.2f}/8 bits/byte",
        windows,
    )
