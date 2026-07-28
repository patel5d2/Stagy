"""Tests for the network covert channel (roadmap 5.1).

The pure coding layer (`encode_packets` / `decode_packets`) carries the fiddly
logic — sequencing, reorder correction, loss detection, keying — and needs
neither scapy nor root, so it is tested exhaustively here. A separate test
exercises the scapy transport by serializing crafted packets to wire bytes and
parsing them back; nothing is transmitted.
"""

from __future__ import annotations

import os
import random

import pytest

from stagy import container, crypto
from stagy.codecs import network as net
from stagy.container import KeyMaterial
from stagy.errors import CapacityError, NoPayloadError


def _container(payload: bytes = b"CTF{covert_channel}", *, encrypt: bool = True) -> bytes:
    km = None
    if encrypt:
        salt = os.urandom(16)
        keys = crypto.derive_keys("pw", salt)
        km = KeyMaterial(aes_key=keys.aes_key, salt=salt, kdf="argon2id")
    return container.encode(payload, filename="msg.txt", encrypt=encrypt, key_material=km)


@pytest.mark.parametrize("field", ["ip_id", "tcp_seq"])
class TestCodingLayer:
    def test_round_trip(self, field: str) -> None:
        blob = _container()
        vals = net.encode_packets(blob, field, seed=b"k")
        assert net.decode_packets(vals, field, seed=b"k") == blob

    def test_reordering_is_corrected(self, field: str) -> None:
        """The sequence number's whole purpose: shuffled packets still decode."""
        blob = _container()
        vals = net.encode_packets(blob, field, seed=b"k")
        shuffled = vals[:]
        random.Random(1).shuffle(shuffled)
        assert net.decode_packets(shuffled, field, seed=b"k") == blob

    def test_packet_loss_is_detected(self, field: str) -> None:
        blob = _container()
        vals = net.encode_packets(blob, field, seed=b"k")
        with pytest.raises(NoPayloadError, match="loss|reorder|duplicat"):
            net.decode_packets(vals[:-1], field, seed=b"k")

    def test_duplicate_is_detected(self, field: str) -> None:
        blob = _container()
        vals = net.encode_packets(blob, field, seed=b"k")
        with pytest.raises(NoPayloadError):
            net.decode_packets(vals[:-1] + vals[:1], field, seed=b"k")

    def test_wrong_key_does_not_recover(self, field: str) -> None:
        blob = _container()
        vals = net.encode_packets(blob, field, seed=b"right")
        with pytest.raises(NoPayloadError):
            net.decode_packets(vals, field, seed=b"wrong")

    def test_unkeyed_round_trip(self, field: str) -> None:
        blob = _container(encrypt=False)
        vals = net.encode_packets(blob, field, seed=None)
        assert net.decode_packets(vals, field, seed=None) == blob


def test_capacity_is_bounded_by_sequence_space() -> None:
    """ip_id addresses only 256 packets (8-bit seq); overflowing must raise."""
    spec = net.FIELDS["ip_id"]
    # Each packet carries data_bits=8 -> 1 byte. One byte past the sequence
    # space is one packet too many.
    too_big = b"\x00" * (spec.max_packets + 1)
    with pytest.raises(CapacityError, match="packets"):
        net.encode_packets(too_big, "ip_id")


def test_empty_decode_raises() -> None:
    with pytest.raises(NoPayloadError):
        net.decode_packets([], "ip_id")


def test_unknown_field_raises() -> None:
    with pytest.raises(Exception, match="unknown field"):
        net.encode_packets(_container(), "not_a_field")


class TestTransport:
    """Craft real scapy packets, serialize to wire bytes, parse back, decode.

    This is the closest verification to the wire that needs no root: it exercises
    scapy's actual field serialization and parsing. Nothing is transmitted — the
    packets are only turned into bytes and back. dst is loopback to make that
    intent unambiguous.
    """

    def test_ip_id_survives_serialization(self) -> None:
        scapy = pytest.importorskip("scapy.all")
        blob = _container()
        vals = net.encode_packets(blob, "ip_id", seed=b"k")
        pkts = net.build_packets(vals, "127.0.0.1", "ip_id")
        wire = [bytes(p) for p in pkts]  # real serialization; not sent
        parsed = [scapy.IP(w) for w in wire]
        got = [net.packet_value(p, "ip_id") for p in parsed]
        assert net.decode_packets(got, "ip_id", seed=b"k") == blob

    def test_tcp_seq_survives_serialization(self) -> None:
        scapy = pytest.importorskip("scapy.all")
        blob = _container()
        vals = net.encode_packets(blob, "tcp_seq", seed=b"k")
        pkts = net.build_packets(vals, "127.0.0.1", "tcp_seq")
        parsed = [scapy.IP(bytes(p)) for p in pkts]
        got = [net.packet_value(p, "tcp_seq") for p in parsed]
        assert net.decode_packets(got, "tcp_seq", seed=b"k") == blob
