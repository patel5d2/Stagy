"""PNG/BMP LSB codec. Reuses bitstream + permutation; carries framed bytes only."""

from __future__ import annotations

from typing import cast

import numpy as np
from PIL import Image

from ..container import header_prefix_len, total_len
from ..errors import CapacityError, NoPayloadError, UnsupportedFormatError
from ..permutation import keyed_indices
from .base import register

_CHANNEL_INDEX = {"R": 0, "G": 1, "B": 2, "A": 3}
_LOSSY_EXT = (".jpg", ".jpeg", ".webp", ".gif")


def _opts(opts: dict[str, object]) -> tuple[int, list[int], str, bytes | None]:
    bits = int(cast("int", opts.get("bits", 1)))
    if not 1 <= bits <= 4:
        raise ValueError("bits must be 1..4")
    channels = str(opts.get("channels", "RGB")).upper()
    if any(c not in _CHANNEL_INDEX for c in channels) or not channels:
        raise ValueError(f"bad channels: {channels!r}")
    mode = str(opts.get("mode", "keyed"))
    if mode not in ("keyed", "sequential"):
        raise ValueError("mode must be 'keyed' or 'sequential'")
    seed = opts.get("seed")
    seed = seed if isinstance(seed, bytes) else None
    return bits, [_CHANNEL_INDEX[c] for c in channels], mode, seed


def _require_seed(mode: str, seed: bytes | None) -> None:
    if mode == "keyed" and seed is None:
        raise ValueError("keyed mode requires a passphrase (to seed the permutation)")


def _load_samples(path: str, chan_idx: list[int]) -> tuple[np.ndarray, tuple[int, int], str]:
    img = Image.open(path)
    if getattr(img, "is_animated", False):
        raise UnsupportedFormatError("animated images are not supported")
    target = "RGBA" if 3 in chan_idx else "RGB"
    rgb = img.convert(target)
    arr = np.asarray(rgb, dtype=np.uint8)
    h, w = arr.shape[:2]
    flat = arr[..., chan_idx].reshape(-1).copy()
    return flat, (h, w), target


def _order(n_slots: int, needed: int, mode: str, seed: bytes | None) -> np.ndarray:
    if mode == "keyed":
        assert seed is not None
        return keyed_indices(n_slots, seed)[:needed]
    return np.arange(needed, dtype=np.int64)


class ImageLSBCodec:
    name = "image"

    def capacity(self, cover_path: str, **opts: object) -> int:
        bits, chan_idx, _mode, _seed = _opts(opts)
        w, h = Image.open(cover_path).size
        return h * w * len(chan_idx) * bits // 8

    def embed(self, cover_path: str, container: bytes, out_path: str, **opts: object) -> None:
        if out_path.lower().endswith(_LOSSY_EXT):
            raise UnsupportedFormatError(
                f"refusing lossy output {out_path!r}: LSB data would be destroyed; use .png/.bmp"
            )
        bits, chan_idx, mode, seed = _opts(opts)
        _require_seed(mode, seed)
        flat, (h, w), _target = _load_samples(cover_path, chan_idx)
        n_slots = flat.size * bits

        payload_bits = np.unpackbits(np.frombuffer(container, dtype=np.uint8))
        needed = payload_bits.size
        if needed > n_slots:
            raise CapacityError(
                f"payload needs {needed // 8} bytes, cover holds {n_slots // 8}"
            )

        slots = _order(n_slots, needed, mode, seed)
        sample_idx = slots // bits
        plane = (slots % bits).astype(np.uint8)
        for p in range(bits):
            m = plane == p
            if not m.any():
                continue
            s = sample_idx[m]
            b = payload_bits[m].astype(np.uint8)
            flat[s] = (flat[s] & ~np.uint8(1 << p)) | (b << p)

        img = Image.open(cover_path).convert("RGBA" if 3 in chan_idx else "RGB")
        arr = np.asarray(img, dtype=np.uint8).copy()
        arr[..., chan_idx] = flat.reshape(h, w, len(chan_idx))
        Image.fromarray(arr).save(out_path)

    def extract(self, stego_path: str, **opts: object) -> bytes:
        bits, chan_idx, mode, seed = _opts(opts)
        _require_seed(mode, seed)
        flat, _hw, _target = _load_samples(stego_path, chan_idx)
        n_slots = flat.size * bits
        order = _order(n_slots, n_slots, mode, seed)

        def read(nbytes: int) -> bytes:
            k = min(nbytes * 8, order.size)
            sub = order[:k]
            vals = (flat[sub // bits] >> (sub % bits).astype(np.uint8)) & 1
            return np.packbits(vals.astype(np.uint8)).tobytes()

        head = read(8)
        if len(head) < 4 or head[:4] != b"STGY":
            raise NoPayloadError("no Stagy container found (check codec options/seed)")
        # Grow the read until we know the full frame length.
        prefix = header_prefix_len(read(40))
        total = total_len(read(prefix))
        return read(total)[:total]


register(ImageLSBCodec())
