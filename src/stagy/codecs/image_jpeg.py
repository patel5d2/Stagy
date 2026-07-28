"""JPEG DCT codec (roadmap 8.1) — JSteg-style embedding in quantized coefficients.

Spatial LSB dies the instant an image is saved as JPEG, because the DCT +
quantization stage discards exactly the low-order detail LSB embedding relies
on. So this codec works one level down: it embeds in the LSBs of the *quantized
DCT coefficients themselves*, the values JPEG actually stores. The file stays a
valid, standards-decodable JPEG.

**How JSteg embeds reversibly.** Message bits overwrite the LSBs of AC
coefficients, skipping any coefficient equal to 0 or 1. That skip is what makes
it reversible: the "usable" set U = every integer except 0 and 1 is closed under
LSB overwrite —

  * positive: 2<->3, 4<->5, …  (never reaches 0 or 1)
  * negative: -1<->-2, -3<->-4, …  (never reaches 0 or 1)

so a coefficient that was usable at embed time is still usable at extract time,
and the receiver rebuilds the identical coefficient ordering without any side
channel. The DC coefficient of each block is skipped as well: DC changes are the
most visible, and dropping it costs one slot in 64.

**Keyed vs sequential.** Sequential fills usable coefficients in raster order —
classic JSteg, and detectable by a histogram attack. Keyed mode scatters via the
passphrase-seeded permutation, the same defense the spatial codecs use. Keyed is
the default.

**Fragility.** Survives copying, but not re-encoding: opening the stego JPEG in
an editor and re-saving requantizes the coefficients and wipes the payload.
That is inherent to JPEG steganography, not a bug here.

Import is guarded (roadmap gotcha): ``import stagy`` must work without jpeglib,
so this codec registers only if the dependency is present.
"""

from __future__ import annotations

from typing import cast

import jpeglib
import numpy as np

from ..container import header_prefix_len, total_len
from ..errors import CapacityError, NoPayloadError, UnsupportedFormatError
from ..permutation import keyed_indices
from .base import register

_JPEG_EXT = (".jpg", ".jpeg")


def _opts(opts: dict[str, object]) -> tuple[str, bytes | None]:
    mode = str(opts.get("mode", "keyed"))
    if mode not in ("keyed", "sequential"):
        raise ValueError("mode must be 'keyed' or 'sequential'")
    seed = opts.get("seed")
    seed = seed if isinstance(seed, bytes) else None
    if mode == "keyed" and seed is None:
        raise ValueError("keyed mode requires a passphrase (to seed the permutation)")
    return mode, seed


def _components(im: jpeglib.DCTJPEG) -> list[np.ndarray]:
    """Present components (Y always; Cb/Cr absent for grayscale)."""
    return [c for c in (im.Y, im.Cb, im.Cr) if c is not None]


def _ac_coeffs(comps: list[np.ndarray]) -> np.ndarray:
    """All AC coefficients across all components, flattened in a fixed order.

    Each component is (blocks_v, blocks_h, 8, 8); position 0 of every 8x8 block
    is the DC term and is excluded. Returns a 1-D int32 copy — the caller edits
    it and scatters it back with `_write_ac`.
    """
    return np.concatenate(
        [c.reshape(-1, 64)[:, 1:].reshape(-1) for c in comps]
    ).astype(np.int32)


def _write_ac(comps: list[np.ndarray], ac: np.ndarray) -> None:
    """Inverse of `_ac_coeffs`: write the edited AC values back into components."""
    off = 0
    for c in comps:
        r = c.reshape(-1, 64)
        n = r.shape[0] * 63
        r[:, 1:] = ac[off : off + n].reshape(r.shape[0], 63).astype(c.dtype)
        off += n


def _usable(ac: np.ndarray) -> np.ndarray:
    """Indices of coefficients JSteg may carry a bit in: everything but 0 and 1.

    Stable across embedding — LSB overwrite never moves a value into or out of
    {0, 1} — so embed and extract derive the identical index set.
    """
    return cast("np.ndarray", np.nonzero((ac != 0) & (ac != 1))[0])


def _order(n_usable: int, needed: int, mode: str, seed: bytes | None) -> np.ndarray:
    if mode == "keyed":
        assert seed is not None
        return keyed_indices(n_usable, seed)[:needed]
    return np.arange(needed, dtype=np.int64)


class JpegDCTCodec:
    name = "jpeg"

    def capacity(self, cover_path: str, **opts: object) -> int:
        _opts(opts)
        im = jpeglib.read_dct(cover_path)
        return int(_usable(_ac_coeffs(_components(im))).size) // 8

    def embed(self, cover_path: str, container: bytes, out_path: str, **opts: object) -> None:
        if not out_path.lower().endswith(_JPEG_EXT):
            raise UnsupportedFormatError(
                f"JPEG DCT codec writes .jpg/.jpeg only, got {out_path!r}"
            )
        mode, seed = _opts(opts)

        im = jpeglib.read_dct(cover_path)
        comps = _components(im)
        ac = _ac_coeffs(comps)
        usable = _usable(ac)

        payload_bits = np.unpackbits(np.frombuffer(container, dtype=np.uint8))
        needed = payload_bits.size
        if needed > usable.size:
            raise CapacityError(
                f"payload needs {needed // 8} bytes, cover holds {usable.size // 8}"
            )

        target = usable[_order(usable.size, needed, mode, seed)]
        # Overwrite the LSB in place. Works on the signed two's-complement value:
        # for -1 (…1111) clearing the LSB yields -2, setting it yields -1, so the
        # {-2,-1} pair stays inside the usable set. (See module docstring.)
        ac[target] = (ac[target] & ~1) | payload_bits.astype(np.int32)

        _write_ac(comps, ac)
        im.write_dct(out_path)

    def extract(self, stego_path: str, **opts: object) -> bytes:
        mode, seed = _opts(opts)
        im = jpeglib.read_dct(stego_path)
        ac = _ac_coeffs(_components(im))
        usable = _usable(ac)
        order = usable[_order(usable.size, usable.size, mode, seed)]

        def read(nbytes: int) -> bytes:
            k = min(nbytes * 8, order.size)
            vals = (ac[order[:k]] & 1).astype(np.uint8)
            return np.packbits(vals).tobytes()

        head = read(8)
        if len(head) < 4 or head[:4] != b"STGY":
            raise NoPayloadError("no Stagy container found (check codec options/seed)")
        prefix = header_prefix_len(read(40))
        total = total_len(read(prefix))
        return read(total)[:total]


register(JpegDCTCodec())
