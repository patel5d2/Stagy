"""Network covert channel (roadmap 5.1) — LAB USE ONLY.

Hides the framed container in a header field that carries no meaning to the
application: the IP identification field, or the TCP initial sequence number.
One chunk of payload rides in each packet.

    ┌──────────────── field bits ────────────────┐
    │   sequence number   │      data chunk       │
    └─────────────────────┴───────────────────────┘

The **sequence number** is what makes the channel survive a real network. The
receiver sorts packets by it, so reordering is corrected rather than merely
detected; a missing number is packet loss, and a duplicate is a replay — both
raise instead of silently returning corrupt bytes. With a passphrase, the data
half of each field is XORed with a keyed, per-sequence keystream, so an observer
without the key sees field values that look like ordinary random IP ids.

**Layering.** The coding layer below (`encode_packets` / `decode_packets`) is
pure and has no network dependency — it is the part with the fiddly logic and it
is fully unit-tested. Scapy is imported lazily, only when you actually transmit,
so `import stagy` and the codec tests need neither scapy nor root.

**Why lab-only (roadmap §12).** Transmitting requires root / CAP_NET_RAW and a
receiver you control. NAT and firewalls rewrite `IP.id`, and stateful firewalls
drop crafted TCP segments, so this works on a flat lab network (two VMs on one
bridge, a veth pair, loopback) and nowhere else. Do not point it at a host you
do not own.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Any

import numpy as np

from ..container import header_prefix_len, total_len
from ..errors import CapacityError, NoPayloadError, StagyError


@dataclass(frozen=True)
class FieldSpec:
    """A carrier field: its width, and how it splits into sequence + data."""

    name: str
    total_bits: int
    seq_bits: int

    @property
    def data_bits(self) -> int:
        return self.total_bits - self.seq_bits

    @property
    def max_packets(self) -> int:
        return 1 << self.seq_bits


# Two carriers cover the 16-bit and 32-bit cases. Adding another (TTL low bits,
# TCP options) is one entry here plus a branch in the transport helpers.
FIELDS: dict[str, FieldSpec] = {
    "ip_id": FieldSpec("ip_id", total_bits=16, seq_bits=8),  # <=256 pkts x 1 byte
    "tcp_seq": FieldSpec("tcp_seq", total_bits=32, seq_bits=16),  # <=65536 pkts x 2 bytes
}


def _spec(field: str) -> FieldSpec:
    try:
        return FIELDS[field]
    except KeyError:
        raise StagyError(f"unknown field {field!r}; have {sorted(FIELDS)}") from None


def _keystream(seed: bytes | None, n: int, data_bits: int) -> np.ndarray:
    """Per-packet keystream masking the data half. Zeros when unkeyed."""
    if seed is None:
        return np.zeros(n, dtype=np.int64)
    digest = hashlib.sha256(seed + b"stagy/net/v1").digest()
    rng = np.random.default_rng(int.from_bytes(digest[:8], "big"))
    return rng.integers(0, 1 << data_bits, size=n, dtype=np.int64)


def encode_packets(container: bytes, field: str = "ip_id", seed: bytes | None = None) -> list[int]:
    """Framed container bytes -> the sequence of field values to transmit."""
    spec = _spec(field)
    bits = np.unpackbits(np.frombuffer(container, dtype=np.uint8))
    pad = (-bits.size) % spec.data_bits
    if pad:
        bits = np.concatenate([bits, np.zeros(pad, dtype=np.uint8)])
    chunks = bits.reshape(-1, spec.data_bits)
    # MSB-first pack of each data_bits-wide row into an integer.
    weights = (1 << np.arange(spec.data_bits - 1, -1, -1)).astype(np.int64)
    data = chunks.astype(np.int64) @ weights

    n = data.size
    if n > spec.max_packets:
        raise CapacityError(
            f"{container!r} needs {n} packets, but {field} addresses only "
            f"{spec.max_packets} (seq is {spec.seq_bits} bits)"
        )
    data ^= _keystream(seed, n, spec.data_bits)
    seq = np.arange(n, dtype=np.int64)
    return [int(v) for v in (seq << spec.data_bits) | data]


def decode_packets(values: list[int], field: str = "ip_id", seed: bytes | None = None) -> bytes:
    """The received field values -> framed container bytes.

    Sorts by embedded sequence number (correcting reorder) and rejects loss or
    duplication before reassembling.
    """
    spec = _spec(field)
    if not values:
        raise NoPayloadError("no packets to decode")

    data_mask = (1 << spec.data_bits) - 1
    seqs = np.array([v >> spec.data_bits for v in values], dtype=np.int64)
    data = np.array([v & data_mask for v in values], dtype=np.int64)

    order = np.argsort(seqs, kind="stable")
    seqs, data = seqs[order], data[order]
    expected = np.arange(len(values), dtype=np.int64)
    if not np.array_equal(seqs, expected):
        raise NoPayloadError(
            "packet loss, reordering, or duplication detected "
            "(sequence numbers are not a contiguous 0..N-1 run)"
        )

    data = data ^ _keystream(seed, data.size, spec.data_bits)
    bit_rows = ((data[:, None] >> np.arange(spec.data_bits - 1, -1, -1)) & 1).astype(np.uint8)
    blob = np.packbits(bit_rows.reshape(-1)).tobytes()

    if len(blob) < 8 or blob[:4] != b"STGY":
        raise NoPayloadError("reassembled bytes are not a Stagy container (wrong field/key?)")

    # A contiguous 0..N-1 run rules out a *middle* gap, but dropping the final
    # packet(s) just yields a shorter contiguous run. The container declares its
    # own length, so tail loss shows up as fewer reassembled bytes than declared.
    try:
        _ = header_prefix_len(blob)
        total = total_len(blob)
    except (NoPayloadError, struct.error) as e:
        raise NoPayloadError(f"reassembled container is truncated (packet loss?): {e}") from e
    if len(blob) < total:
        raise NoPayloadError(
            f"packet loss: reassembled {len(blob)} bytes but the container "
            f"declares {total} (final packet(s) missing)"
        )
    return blob[:total]


# --------------------------------------------------------------------------- #
# Transport. Everything below needs scapy + root and a receiver you control.
# Imported lazily so the coding layer above stays dependency-free.
# --------------------------------------------------------------------------- #

def _scapy() -> Any:
    # scapy ships no type stubs, so it is intentionally opaque (Any) to mypy.
    try:
        import scapy.all as scapy
    except ImportError as e:  # pragma: no cover - environment-dependent
        raise StagyError(
            "network transport needs scapy: pip install 'stagy[network]'"
        ) from e
    return scapy


def build_packets(values: list[int], dst: str, field: str) -> list[Any]:
    """Craft one scapy packet per field value. Pure construction, no transmit."""
    scapy = _scapy()
    if field == "ip_id":
        return [scapy.IP(dst=dst, id=v) / scapy.ICMP() for v in values]
    if field == "tcp_seq":
        return [scapy.IP(dst=dst) / scapy.TCP(dport=80, flags="S", seq=v) for v in values]
    raise StagyError(f"no transport for field {field!r}")


def packet_value(pkt: Any, field: str) -> int:
    """Read the carrier field back out of a received/parsed packet."""
    scapy = _scapy()
    if field == "ip_id":
        return int(pkt[scapy.IP].id)
    if field == "tcp_seq":
        return int(pkt[scapy.TCP].seq)
    raise StagyError(f"no transport for field {field!r}")


def _default_filter(field: str) -> str:
    return {"ip_id": "icmp", "tcp_seq": "tcp"}.get(field, "")


def send_covert(
    container: bytes,
    dst: str,
    *,
    field: str = "ip_id",
    iface: str | None = None,
    seed: bytes | None = None,
    inter: float = 0.0,
) -> int:
    """Transmit the container over the covert channel. Returns packets sent.

    Needs root/CAP_NET_RAW. LAB ONLY — see module docstring.
    """
    scapy = _scapy()
    pkts = build_packets(encode_packets(container, field, seed), dst, field)
    scapy.send(pkts, iface=iface, inter=inter, verbose=False)
    return len(pkts)


def recv_covert(
    *,
    count: int,
    field: str = "ip_id",
    iface: str | None = None,
    seed: bytes | None = None,
    timeout: float | None = None,
    bpf: str | None = None,
) -> bytes:
    """Sniff `count` covert packets and reassemble the container. LAB ONLY."""
    scapy = _scapy()
    pkts = scapy.sniff(count=count, iface=iface, timeout=timeout, filter=bpf or _default_filter(field))
    values = [packet_value(p, field) for p in pkts]
    return decode_packets(values, field, seed)
