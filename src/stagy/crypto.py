"""KDF + AES-256-GCM + PRNG-seed derivation.

The passphrase derives one KDF output, then HKDF-Expand splits it into an
independent AES key and PRNG seed via distinct info labels — the seed can never
leak the key.
"""

from __future__ import annotations

from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .errors import WrongKeyError

# Argon2id params: memory-hard, sane defaults for an interactive tool.
_ARGON2_TIME = 3
_ARGON2_MEM_KIB = 64 * 1024  # 64 MiB
_ARGON2_LANES = 4
_KDF_OUT = 32

# ponytail: scrypt params fixed; expose as opts if a constrained target needs them.
_SCRYPT_N = 2**15
_SCRYPT_R = 8
_SCRYPT_P = 1


@dataclass(frozen=True)
class KeyBundle:
    aes_key: bytes  # 32 bytes
    prng_seed: bytes  # 32 bytes


def derive_keys(passphrase: str, salt: bytes, *, kdf: str = "argon2id") -> KeyBundle:
    pw = passphrase.encode("utf-8")
    if kdf == "argon2id":
        master = hash_secret_raw(
            secret=pw,
            salt=salt,
            time_cost=_ARGON2_TIME,
            memory_cost=_ARGON2_MEM_KIB,
            parallelism=_ARGON2_LANES,
            hash_len=_KDF_OUT,
            type=Type.ID,
        )
    elif kdf == "scrypt":
        master = Scrypt(salt=salt, length=_KDF_OUT, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P).derive(pw)
    else:
        raise ValueError(f"unknown kdf: {kdf}")

    aes_key = _hkdf_expand(master, b"stagy/aes-key/v1")
    prng_seed = _hkdf_expand(master, b"stagy/prng-seed/v1")
    return KeyBundle(aes_key=aes_key, prng_seed=prng_seed)


def _hkdf_expand(key_material: bytes, info: bytes) -> bytes:
    return HKDFExpand(algorithm=hashes.SHA256(), length=32, info=info).derive(key_material)


def derive_prng_seed(passphrase: str) -> bytes:
    """Permutation seed from passphrase alone (no per-message salt).

    Salt-independent by design: the salt lives inside the payload the permutation
    scatters, so keyed extraction can't depend on it. Same passphrase -> same
    permutation, which is exactly what the extractor needs to reproduce.
    """
    import hashlib

    base = hashlib.sha256(b"stagy/prng/v1" + passphrase.encode("utf-8")).digest()
    return _hkdf_expand(base, b"stagy/prng-seed/v1")


def encrypt(plaintext: bytes, aes_key: bytes) -> tuple[bytes, bytes, bytes]:
    """Return (nonce, ciphertext, tag). Fresh 12-byte nonce every call."""
    import os

    nonce = os.urandom(12)
    sealed = AESGCM(aes_key).encrypt(nonce, plaintext, None)
    ciphertext, tag = sealed[:-16], sealed[-16:]
    return nonce, ciphertext, tag


def decrypt(nonce: bytes, ciphertext: bytes, tag: bytes, aes_key: bytes) -> bytes:
    try:
        return AESGCM(aes_key).decrypt(nonce, ciphertext + tag, None)
    except InvalidTag as e:
        raise WrongKeyError("decryption failed: wrong key or tampered data") from e
