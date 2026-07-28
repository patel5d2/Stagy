"""The Stagy container frame — encode/decode per roadmap §2.

Wire layout (big-endian):
  0   4    MAGIC = b"STGY"
  4   1    VERSION = 0x01
  5   1    FLAGS  bit0 encrypted, bit1 compressed, bit2 has_filename
  6   1    ALGO_ID 0x00 none, 0x01 AES-256-GCM
  7   1    KDF_ID  0x00 none, 0x01 scrypt, 0x02 argon2id
  8   16   SALT           (only if encrypted)
  --  12   NONCE          (only if encrypted)
  --  2    FILENAME_LEN   (only if has_filename)
  --  var  FILENAME utf-8 (only if has_filename)
  --  4    PAYLOAD_LEN uint32
  --  var  PAYLOAD  = ciphertext | raw/compressed bytes
  --  16   GCM_TAG        (only if encrypted)
  --  4    CRC32 over MAGIC..last payload/tag byte
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass
from pathlib import PurePosixPath, PureWindowsPath

from . import crypto
from .errors import IntegrityError, NoPayloadError, StagyError

MAX_DECOMPRESSED = 256 * 1024 * 1024
"""Default ceiling on decompressed payload size.

The compressed payload is attacker-controlled and the CRC32 is not a MAC — an
attacker recomputes it freely — so an unbounded ``zlib.decompress`` is a
decompression bomb. Measured: 400 KB of container expands to 400 MB (1,028x).
Callers exposed to hostile input (the web API) should pass a much lower
``max_decompressed``.
"""

MAGIC = b"STGY"
VERSION = 0x01

_FLAG_ENCRYPTED = 0b001
_FLAG_COMPRESSED = 0b010
_FLAG_HAS_FILENAME = 0b100

_ALGO_NONE = 0x00
_ALGO_AESGCM = 0x01

_KDF_NONE = 0x00
_KDF_SCRYPT = 0x01
_KDF_ARGON2 = 0x02
_KDF_NAME = {_KDF_SCRYPT: "scrypt", _KDF_ARGON2: "argon2id"}
_KDF_ID = {v: k for k, v in _KDF_NAME.items()}


@dataclass(frozen=True)
class KeyMaterial:
    """What encode needs to seal a payload: derived AES key + the salt to store."""

    aes_key: bytes
    salt: bytes  # 16 bytes, stored in the frame
    kdf: str = "argon2id"


@dataclass(frozen=True)
class DecodedPayload:
    payload: bytes
    filename: str | None
    """Sanitized to a bare basename — never a path. See `safe_filename`."""
    was_encrypted: bool


def safe_filename(name: str) -> str:
    """Reduce a container-supplied filename to a basename safe to write.

    The filename comes from inside the file under analysis, so it is fully
    attacker-controlled. Writing to it verbatim is an arbitrary file write:
    embedding ``filename="../PWNED.txt"`` and running ``stagy image extract``
    with no ``-o`` wrote outside the analyst's working directory. It needs no
    passphrase, because an unencrypted container is readable by anyone.

    Both POSIX and Windows separators are stripped: a lone ``PurePosixPath``
    treats ``..\\evil`` as one filename, which is still traversal on Windows.
    """
    cleaned = name.replace("\x00", "")
    base = PureWindowsPath(PurePosixPath(cleaned).name).name
    if not base or base in (".", "..") or "/" in base or "\\" in base:
        raise IntegrityError(f"unsafe filename in container: {name!r}")
    return base


def _bounded_decompress(data: bytes, limit: int) -> bytes:
    """zlib.decompress with a hard output ceiling, to defuse bombs."""
    d = zlib.decompressobj()
    try:
        out = d.decompress(data, limit)
    except zlib.error as e:
        raise IntegrityError(f"corrupt compressed payload: {e}") from e
    if d.unconsumed_tail or not d.eof:
        raise IntegrityError(
            f"decompressed payload exceeds {limit:,} bytes — refusing (decompression bomb?)"
        )
    return out


def encode(
    payload: bytes,
    *,
    filename: str | None = None,
    encrypt: bool = True,
    compress: bool = False,
    key_material: KeyMaterial | None = None,
) -> bytes:
    if encrypt and key_material is None:
        raise ValueError("encrypt=True requires key_material")

    body = zlib.compress(payload) if compress else payload

    flags = 0
    algo = _ALGO_NONE
    kdf_id = _KDF_NONE
    salt = b""
    nonce = b""
    tag = b""

    if compress:
        flags |= _FLAG_COMPRESSED
    if filename is not None:
        flags |= _FLAG_HAS_FILENAME

    if encrypt:
        assert key_material is not None
        flags |= _FLAG_ENCRYPTED
        algo = _ALGO_AESGCM
        kdf_id = _KDF_ID[key_material.kdf]
        salt = key_material.salt
        nonce, body, tag = crypto.encrypt(body, key_material.aes_key)

    out = bytearray()
    out += MAGIC
    out.append(VERSION)
    out.append(flags)
    out.append(algo)
    out.append(kdf_id)
    if encrypt:
        out += salt
        out += nonce
    if filename is not None:
        fn = filename.encode("utf-8")
        out += struct.pack(">H", len(fn))
        out += fn
    out += struct.pack(">I", len(body))
    out += body
    if encrypt:
        out += tag
    out += struct.pack(">I", zlib.crc32(bytes(out)) & 0xFFFFFFFF)
    return bytes(out)


def header_prefix_len(blob: bytes) -> int:
    """Bytes needed to know PAYLOAD_LEN — lets a codec read the frame incrementally.

    Returns the offset just past PAYLOAD_LEN. Raises NoPayloadError on bad MAGIC.
    """
    if len(blob) < 8 or blob[:4] != MAGIC:
        raise NoPayloadError("no Stagy container (bad MAGIC)")
    flags = blob[5]
    off = 8
    if flags & _FLAG_ENCRYPTED:
        off += 16 + 12  # salt + nonce
    if flags & _FLAG_HAS_FILENAME:
        (fn_len,) = struct.unpack_from(">H", blob, off)
        off += 2 + fn_len
    return off + 4  # + PAYLOAD_LEN field


def total_len(blob: bytes) -> int:
    """Full container length, derivable once header_prefix_len bytes are present."""
    prefix = header_prefix_len(blob)
    (payload_len,) = struct.unpack_from(">I", blob, prefix - 4)
    total = prefix + int(payload_len) + 4  # + CRC32
    if blob[5] & _FLAG_ENCRYPTED:
        total += 16  # GCM tag
    return total


def crc_ok(blob: bytes) -> bool:
    """True if blob *begins* with a complete, CRC-valid container.

    Lets a codec that recovers bytes by scanning (e.g. appended data) tell a real
    container from a coincidental MAGIC in cover data — the CRC makes a false
    positive ~1 in 2^32, which no 2-byte format marker can promise.
    """
    if len(blob) < 12 or blob[:4] != MAGIC:
        return False
    try:
        total = total_len(blob)
    except (NoPayloadError, struct.error):
        return False
    if not 12 <= total <= len(blob):
        return False
    (stored,) = struct.unpack_from(">I", blob, total - 4)
    return bool(zlib.crc32(blob[: total - 4]) & 0xFFFFFFFF == stored)


def decode(
    blob: bytes,
    *,
    passphrase: str | None = None,
    max_decompressed: int = MAX_DECOMPRESSED,
) -> DecodedPayload:
    if len(blob) < 12 or blob[:4] != MAGIC:
        raise NoPayloadError("no Stagy container (bad MAGIC)")

    stored_crc = struct.unpack_from(">I", blob, len(blob) - 4)[0]
    if zlib.crc32(blob[:-4]) & 0xFFFFFFFF != stored_crc:
        raise IntegrityError("CRC32 mismatch — corrupt extraction or wrong parameters")

    flags = blob[5]
    encrypted = bool(flags & _FLAG_ENCRYPTED)
    compressed = bool(flags & _FLAG_COMPRESSED)
    has_filename = bool(flags & _FLAG_HAS_FILENAME)
    kdf_id = blob[7]

    off = 8
    salt = nonce = b""
    if encrypted:
        salt = blob[off : off + 16]
        nonce = blob[off + 16 : off + 28]
        off += 28

    filename: str | None = None
    if has_filename:
        (fn_len,) = struct.unpack_from(">H", blob, off)
        off += 2
        raw_name = blob[off : off + fn_len]
        if len(raw_name) < fn_len:
            raise IntegrityError("truncated filename field")
        try:
            filename = safe_filename(raw_name.decode("utf-8"))
        except UnicodeDecodeError as e:
            raise IntegrityError(f"filename is not valid utf-8: {e}") from e
        off += fn_len

    (payload_len,) = struct.unpack_from(">I", blob, off)
    off += 4
    body = blob[off : off + payload_len]
    off += payload_len

    if encrypted:
        if passphrase is None:
            raise StagyError("container is encrypted but no passphrase given")
        if kdf_id not in _KDF_NAME:
            raise IntegrityError(f"unknown KDF id {kdf_id:#04x}")
        tag = blob[off : off + 16]
        keys = crypto.derive_keys(passphrase, salt, kdf=_KDF_NAME[kdf_id])
        body = crypto.decrypt(nonce, body, tag, keys.aes_key)

    if compressed:
        body = _bounded_decompress(body, max_decompressed)

    return DecodedPayload(payload=body, filename=filename, was_encrypted=encrypted)
