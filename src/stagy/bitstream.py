"""bytes <-> bits and LSB plane helpers. Pure functions, no codec knowledge."""

from __future__ import annotations

from collections.abc import Iterable, Iterator


def bytes_to_bits(data: bytes) -> Iterator[int]:
    """Yield bits MSB-first (bit 7 down to bit 0 of each byte)."""
    for byte in data:
        for shift in range(7, -1, -1):
            yield (byte >> shift) & 1


def bits_to_bytes(bits: Iterable[int]) -> bytes:
    """Pack MSB-first bits into bytes. Trailing partial byte is dropped."""
    out = bytearray()
    acc = 0
    count = 0
    for bit in bits:
        acc = (acc << 1) | (bit & 1)
        count += 1
        if count == 8:
            out.append(acc)
            acc = 0
            count = 0
    return bytes(out)


def set_lsb(value: int, bit: int, plane: int = 0) -> int:
    """Set the given bit-plane of value to bit (0/1)."""
    mask = 1 << plane
    return (value & ~mask) | ((bit & 1) << plane)


def get_lsb(value: int, plane: int = 0) -> int:
    """Read the given bit-plane of value."""
    return (value >> plane) & 1
