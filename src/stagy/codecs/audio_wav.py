"""WAV PCM (16-bit) LSB codec. Reuses bitstream + permutation; carries framed bytes.

The same keyed/sequential LSB machinery as the image codec, applied to audio
samples instead of pixels. Only 16-bit PCM is supported in v1; anything else
(24-bit, float, compressed) is refused rather than silently mangled.

ponytail: the flat-array LSB embed/extract here mirrors image_lsb's. Two uses do
not yet justify a shared _lsbcore module (rule of three); extract one if a third
sample-based codec appears.
"""

from __future__ import annotations

import wave

import numpy as np

from ..container import header_prefix_len, total_len
from ..errors import CapacityError, NoPayloadError, UnsupportedFormatError
from ..permutation import keyed_indices
from .base import register

_SAMPLE_WIDTH = 2  # bytes; 16-bit PCM only


def _opts(opts: dict[str, object]) -> tuple[int, str, bytes | None]:
    bits = int(opts.get("bits", 1))  # type: ignore[call-overload]
    if not 1 <= bits <= 4:
        raise ValueError("bits must be 1..4")
    mode = str(opts.get("mode", "keyed"))
    if mode not in ("keyed", "sequential"):
        raise ValueError("mode must be 'keyed' or 'sequential'")
    seed = opts.get("seed")
    seed = seed if isinstance(seed, bytes) else None
    return bits, mode, seed


def _require_seed(mode: str, seed: bytes | None) -> None:
    if mode == "keyed" and seed is None:
        raise ValueError("keyed mode requires a passphrase (to seed the permutation)")


def _read_pcm(path: str) -> tuple[np.ndarray, wave._wave_params]:
    """Return (samples as uint16, params). Samples are viewed unsigned so the LSB
    math is identical to the image codec's; the raw 16-bit words are unchanged."""
    with wave.open(path, "rb") as w:
        params = w.getparams()
        if params.sampwidth != _SAMPLE_WIDTH:
            raise UnsupportedFormatError(
                f"only 16-bit PCM WAV is supported, got {params.sampwidth * 8}-bit"
            )
        if params.comptype != "NONE":
            raise UnsupportedFormatError(f"compressed WAV ({params.comptype}) is not supported")
        frames = w.readframes(params.nframes)
    samples = np.frombuffer(frames, dtype="<u2").copy()
    return samples, params


def _order(n_slots: int, needed: int, mode: str, seed: bytes | None) -> np.ndarray:
    if mode == "keyed":
        assert seed is not None
        return keyed_indices(n_slots, seed)[:needed]
    return np.arange(needed, dtype=np.int64)


class WavLSBCodec:
    name = "audio"

    def capacity(self, cover_path: str, **opts: object) -> int:
        bits, _mode, _seed = _opts(opts)
        samples, _params = _read_pcm(cover_path)
        return int(samples.size) * bits // 8

    def embed(self, cover_path: str, container: bytes, out_path: str, **opts: object) -> None:
        if not out_path.lower().endswith(".wav"):
            raise UnsupportedFormatError(
                f"WAV codec writes .wav only, got {out_path!r} (re-encoding would destroy LSBs)"
            )
        bits, mode, seed = _opts(opts)
        _require_seed(mode, seed)
        samples, params = _read_pcm(cover_path)
        n_slots = samples.size * bits

        payload_bits = np.unpackbits(np.frombuffer(container, dtype=np.uint8))
        needed = payload_bits.size
        if needed > n_slots:
            raise CapacityError(f"payload needs {needed // 8} bytes, cover holds {n_slots // 8}")

        slots = _order(n_slots, needed, mode, seed)
        sample_idx = slots // bits
        plane = (slots % bits).astype(np.uint16)
        for p in range(bits):
            m = plane == p
            if not m.any():
                continue
            s = sample_idx[m]
            b = payload_bits[m].astype(np.uint16)
            samples[s] = (samples[s] & ~np.uint16(1 << p)) | (b << p)

        with wave.open(out_path, "wb") as w:
            w.setparams(params)
            w.writeframes(samples.astype("<u2").tobytes())

    def extract(self, stego_path: str, **opts: object) -> bytes:
        bits, mode, seed = _opts(opts)
        _require_seed(mode, seed)
        samples, _params = _read_pcm(stego_path)
        n_slots = samples.size * bits
        order = _order(n_slots, n_slots, mode, seed)

        def read(nbytes: int) -> bytes:
            k = min(nbytes * 8, order.size)
            sub = order[:k]
            vals = (samples[sub // bits] >> (sub % bits).astype(np.uint16)) & 1
            return np.packbits(vals.astype(np.uint8)).tobytes()

        head = read(8)
        if len(head) < 4 or head[:4] != b"STGY":
            raise NoPayloadError("no Stagy container found (check codec options/seed)")
        prefix = header_prefix_len(read(40))
        total = total_len(read(prefix))
        return read(total)[:total]


register(WavLSBCodec())
