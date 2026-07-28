from hypothesis import given
from hypothesis import strategies as st

from stagy.bitstream import bits_to_bytes, bytes_to_bits, get_lsb, set_lsb


@given(st.binary(max_size=512))
def test_bits_roundtrip(data: bytes) -> None:
    assert bits_to_bytes(bytes_to_bits(data)) == data


@given(st.integers(0, 255), st.integers(0, 1), st.integers(0, 7))
def test_lsb_roundtrip(value: int, bit: int, plane: int) -> None:
    assert get_lsb(set_lsb(value, bit, plane), plane) == bit
