import os

import pytest

from stagy import crypto
from stagy.errors import WrongKeyError


def test_encrypt_decrypt_roundtrip() -> None:
    keys = crypto.derive_keys("hunter2", os.urandom(16))
    nonce, ct, tag = crypto.encrypt(b"secret", keys.aes_key)
    assert crypto.decrypt(nonce, ct, tag, keys.aes_key) == b"secret"


def test_wrong_key_raises() -> None:
    salt = os.urandom(16)
    a = crypto.derive_keys("right", salt)
    b = crypto.derive_keys("wrong", salt)
    nonce, ct, tag = crypto.encrypt(b"secret", a.aes_key)
    with pytest.raises(WrongKeyError):
        crypto.decrypt(nonce, ct, tag, b.aes_key)


def test_fresh_nonce_differs() -> None:
    keys = crypto.derive_keys("pw", os.urandom(16))
    n1, c1, _ = crypto.encrypt(b"same", keys.aes_key)
    n2, c2, _ = crypto.encrypt(b"same", keys.aes_key)
    assert (n1, c1) != (n2, c2)


def test_prng_seed_salt_independent_and_deterministic() -> None:
    assert crypto.derive_prng_seed("pw") == crypto.derive_prng_seed("pw")
    assert crypto.derive_prng_seed("pw") != crypto.derive_prng_seed("other")
