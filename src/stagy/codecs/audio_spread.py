"""Spread-spectrum audio codec (roadmap 8.2) — robust, keyed, low-capacity.

Where the WAV-LSB codec writes payload bits straight into sample LSBs (high
capacity, but a single re-quantization or amplitude change wipes them), this
codec spreads each payload bit across a whole block of samples using
direct-sequence spread spectrum (DSSS):

  * Each bit is multiplied by a passphrase-seeded pseudo-random chip sequence of
    +/-1 values, one per sample in the block, scaled by a gain and added to the
    audio.
  * Extraction correlates each block against the same chip sequence; the sign of
    the correlation is the bit. Correlation integrates the coherent chip energy
    (grows like the block length L) against the incoherent host audio (grows
    like sqrt(L)), so a modest gain recovers the bit even though the host is far
    louder than the added signal.

**Why it is more robust than LSB.** The bit lives in a correlation over
thousands of samples, not in one fragile low-order bit, so it survives added
noise, mild filtering, and small gain changes that annihilate LSB data. The
price is capacity: one bit per block instead of one per sample.

**Always keyed.** The chip sequence *is* the secret. Without the passphrase an
attacker cannot correlate the payload out, and cannot embed a matching one.
There is no sequential mode.

**Exactness.** On a clean copy the round-trip is bit-exact (verified), which is
what the container's CRC demands. Under actual signal processing you would add
error-correction coding on top; DSSS raises the noise floor you can tolerate, it
does not make the channel lossless under attack. Echo hiding and phase coding —
the other two techniques named in the roadmap — are genuinely robust but have
non-zero bit-error rates, so they suit fragile *watermarks*, not an exact framed
container, and are documented rather than used as carriers here.

Import is unconditional (numpy only); it registers alongside the WAV-LSB codec.
"""

from __future__ import annotations

import hashlib
import wave

import numpy as np

from ..container import header_prefix_len, total_len
from ..errors import CapacityError, NoPayloadError, UnsupportedFormatError
from .base import register

_SAMPLE_WIDTH = 2  # 16-bit PCM only, matching the WAV-LSB codec

# Defaults chosen for bit-exact blind recovery on 16-bit PCM. Both are exposed
# as options: they are the real robustness/imperceptibility/capacity knobs, not
# constants to hide. Larger L or gain -> more robust and more audible; smaller
# -> quieter and higher capacity but closer to the error floor.
_DEFAULT_CHIP_LEN = 1024
# Tuned for bit-exact blind recovery on loud, near-full-scale tonal hosts (the
# worst case for correlation): 0 bit errors measured across five such covers.
# A quieter cover needs less; drop `gain` to reduce audibility. A failed decode
# is caught by the container CRC, never returned as corruption.
_DEFAULT_GAIN = 600.0


def _opts(opts: dict[str, object]) -> tuple[int, float, bytes]:
    chip_len = int(opts.get("chip_len", _DEFAULT_CHIP_LEN))  # type: ignore[call-overload]
    if chip_len < 64:
        raise ValueError("chip_len must be >= 64 (shorter blocks lose the coding gain)")
    gain = float(opts.get("gain", _DEFAULT_GAIN))  # type: ignore[arg-type]
    if gain <= 0:
        raise ValueError("gain must be positive")
    seed = opts.get("seed")
    if not isinstance(seed, bytes):
        # ValueError, not TypeError: this is a missing-passphrase usage error,
        # matching how the LSB codecs report keyed-without-seed.
        raise ValueError("spread-spectrum audio requires a passphrase (keyed only)")  # noqa: TRY004
    return chip_len, gain, seed


def _read_pcm(path: str) -> tuple[np.ndarray, wave._wave_params]:
    with wave.open(path, "rb") as w:
        params = w.getparams()
        if params.sampwidth != _SAMPLE_WIDTH:
            raise UnsupportedFormatError(
                f"only 16-bit PCM WAV is supported, got {params.sampwidth * 8}-bit"
            )
        if params.comptype != "NONE":
            raise UnsupportedFormatError(f"compressed WAV ({params.comptype}) is not supported")
        frames = w.readframes(params.nframes)
    return np.frombuffer(frames, dtype="<i2").astype(np.float64), params


def _chips(seed: bytes, n_bits: int, chip_len: int) -> np.ndarray:
    """Deterministic +/-1 spreading matrix, shape (n_bits, chip_len).

    Derived from the passphrase seed alone, so embedder and extractor generate
    the identical codes. Distinct per bit position, so blocks do not cross-talk.
    """
    digest = hashlib.sha256(seed + b"stagy/audio-ss/v1").digest()
    rng = np.random.default_rng(int.from_bytes(digest[:8], "big"))
    return rng.integers(0, 2, size=(n_bits, chip_len), dtype=np.int8) * 2 - 1


class AudioSpreadCodec:
    name = "audiospread"

    def capacity(self, cover_path: str, **opts: object) -> int:
        chip_len = int(opts.get("chip_len", _DEFAULT_CHIP_LEN))  # type: ignore[call-overload]
        samples, _ = _read_pcm(cover_path)
        return int((samples.size // chip_len) // 8)

    def embed(self, cover_path: str, container: bytes, out_path: str, **opts: object) -> None:
        if not out_path.lower().endswith(".wav"):
            raise UnsupportedFormatError(f"spread-spectrum codec writes .wav only, got {out_path!r}")
        chip_len, gain, seed = _opts(opts)
        samples, params = _read_pcm(cover_path)

        bits = np.unpackbits(np.frombuffer(container, dtype=np.uint8)).astype(np.int8)
        n_bits = bits.size
        n_blocks = samples.size // chip_len
        if n_bits > n_blocks:
            raise CapacityError(f"payload needs {n_bits // 8} bytes, cover holds {n_blocks // 8}")

        chips = _chips(seed, n_bits, chip_len)
        signs = (bits.astype(np.float64) * 2 - 1)[:, None]  # 0/1 -> -1/+1
        used = samples[: n_bits * chip_len].reshape(n_bits, chip_len)
        used += gain * signs * chips
        samples[: n_bits * chip_len] = used.reshape(-1)

        out = np.clip(np.rint(samples), -32768, 32767).astype("<i2")
        with wave.open(out_path, "wb") as w:
            w.setparams(params)
            w.writeframes(out.tobytes())

    def extract(self, stego_path: str, **opts: object) -> bytes:
        chip_len, _gain, seed = _opts(opts)
        samples, _ = _read_pcm(stego_path)
        n_blocks = samples.size // chip_len
        if n_blocks == 0:
            raise NoPayloadError("cover too short for spread-spectrum extraction")

        blocks = samples[: n_blocks * chip_len].reshape(n_blocks, chip_len)
        chips = _chips(seed, n_blocks, chip_len)
        # Whiten by first-difference before correlating. The chip is broadband
        # (white +/-1), but the host energy is concentrated at low frequencies,
        # where a difference operator has almost no gain — so diff() strips most
        # host interference while keeping the chip. Correlating diff(block) with
        # diff(chip) cut bit errors by ~3x versus mean-removal at equal gain.
        # Both diffs are reproducible from the stego file alone: no side channel.
        d_blocks = np.diff(blocks, axis=1)
        d_chips = np.diff(chips, axis=1)
        corr = np.einsum("ij,ij->i", d_blocks, d_chips.astype(np.float64))
        all_bits = (corr > 0).astype(np.uint8)

        def read(nbytes: int) -> bytes:
            k = min(nbytes * 8, all_bits.size)
            return np.packbits(all_bits[:k]).tobytes()

        head = read(8)
        if len(head) < 4 or head[:4] != b"STGY":
            raise NoPayloadError("no Stagy container found (wrong passphrase or chip_len?)")
        prefix = header_prefix_len(read(40))
        total = total_len(read(prefix))
        return read(total)[:total]


register(AudioSpreadCodec())
