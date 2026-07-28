"""Stagy: hide, reveal, and (later) detect hidden data across covers.

hide/reveal are the one entry point the CLI and web both call. They wire the
container (crypto) to a dumb bit-carrier codec.
"""

from __future__ import annotations

import os

from . import container, crypto
from .codecs import CODECS
from .codecs.base import StegoCodec
from .container import DecodedPayload, KeyMaterial
from .errors import StagyError
from .version import __version__

__all__ = ["DecodedPayload", "StagyError", "__version__", "hide", "reveal"]


def _codec(name: str) -> StegoCodec:
    try:
        return CODECS[name]
    except KeyError:
        raise StagyError(f"unknown codec {name!r}; have {sorted(CODECS)}") from None


def _seal(
    payload: bytes,
    *,
    passphrase: str | None,
    encrypt: bool,
    compress: bool,
    filename: str | None,
) -> bytes:
    """Build a framed (optionally encrypted/compressed) container.

    The step every carrier shares, factored out of `hide` so carriers without a
    cover file — the network channel — build the identical container.
    """
    if encrypt and not passphrase:
        raise StagyError("encryption requested but no passphrase given")
    km = None
    if encrypt:
        assert passphrase is not None
        salt = os.urandom(16)
        keys = crypto.derive_keys(passphrase, salt)
        km = KeyMaterial(aes_key=keys.aes_key, salt=salt, kdf="argon2id")
    return container.encode(
        payload, filename=filename, encrypt=encrypt, compress=compress, key_material=km
    )


def hide(
    cover: str,
    payload: bytes,
    out: str,
    *,
    codec: str = "image",
    passphrase: str | None = None,
    encrypt: bool = True,
    compress: bool = False,
    filename: str | None = None,
    **codec_opts: object,
) -> None:
    blob = _seal(
        payload, passphrase=passphrase, encrypt=encrypt, compress=compress, filename=filename
    )

    opts = dict(codec_opts)
    if opts.get("mode", "keyed") == "keyed" and passphrase:
        opts["seed"] = crypto.derive_prng_seed(passphrase)
    _codec(codec).embed(cover, blob, out, **opts)


def reveal(
    stego: str,
    *,
    codec: str = "image",
    passphrase: str | None = None,
    max_decompressed: int = container.MAX_DECOMPRESSED,
    **codec_opts: object,
) -> DecodedPayload:
    """Recover a payload from a stego file.

    `max_decompressed` bounds the zlib expansion of a compressed payload.
    Callers handling untrusted input (the web API) should lower it: the
    compressed bytes are attacker-controlled and the CRC32 is not a MAC.
    """
    opts = dict(codec_opts)
    if opts.get("mode", "keyed") == "keyed" and passphrase:
        opts["seed"] = crypto.derive_prng_seed(passphrase)
    blob = _codec(codec).extract(stego, **opts)
    return container.decode(blob, passphrase=passphrase, max_decompressed=max_decompressed)
