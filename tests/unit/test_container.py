import os

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from stagy import container, crypto
from stagy.container import KeyMaterial
from stagy.errors import IntegrityError, NoPayloadError


def _km(passphrase: str = "pw") -> KeyMaterial:
    salt = os.urandom(16)
    return KeyMaterial(aes_key=crypto.derive_keys(passphrase, salt).aes_key, salt=salt)


@given(st.binary(max_size=4096))
@settings(max_examples=50, deadline=None)
def test_encrypted_roundtrip(data: bytes) -> None:
    blob = container.encode(data, key_material=_km(), filename="f.txt")
    got = container.decode(blob, passphrase="pw")
    assert got.payload == data
    assert got.filename == "f.txt"
    assert got.was_encrypted


def test_plain_roundtrip_and_compress() -> None:
    blob = container.encode(b"x" * 1000, encrypt=False, compress=True)
    got = container.decode(blob)
    assert got.payload == b"x" * 1000
    assert not got.was_encrypted


def test_empty_and_no_filename() -> None:
    blob = container.encode(b"", key_material=_km())
    got = container.decode(blob, passphrase="pw")
    assert got.payload == b""
    assert got.filename is None


def test_corrupt_byte_raises_integrity() -> None:
    blob = bytearray(container.encode(b"hello", key_material=_km()))
    blob[20] ^= 0x01
    with pytest.raises(IntegrityError):
        container.decode(bytes(blob), passphrase="pw")


def test_bad_magic_raises() -> None:
    with pytest.raises(NoPayloadError):
        container.decode(b"\x00" * 32)


def test_wire_vector_stable() -> None:
    # Unencrypted frame is deterministic -> pins the wire format.
    blob = container.encode(b"hi", encrypt=False)
    assert blob.hex() == "535447590100000000000002686971e6f0bb"
