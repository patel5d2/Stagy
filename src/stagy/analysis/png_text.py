"""PNG text-chunk analyzer — finds payloads hidden in tEXt/zTXt/iTXt chunks.

PNG stores metadata as text chunks: ``tEXt`` (uncompressed), ``zTXt`` (zlib), and
``iTXt`` (UTF-8, optionally zlib). They legitimately carry small strings —
``Software``, ``Comment``, a ``Creation Time`` — but nothing stops a tool from
parking a whole payload there, and viewers never show it. The LSB analyzers read
the pixel plane and ``filecarve``/``entropy`` read the appended region, so a
text-chunk payload slips past all of them. This closes that gap.

The evidence is deterministic and asymmetric, like its siblings: a text chunk
that decodes to a real file/container is near-conclusive, a large high-entropy
chunk is suspicious, and *absence of any such chunk is neutral* — so the analyzer
supplies its own weight instead of being calibrated on the LSB corpus.
"""

from __future__ import annotations

import base64
import re
import zlib
from dataclasses import dataclass, field
from pathlib import Path

from .entropy import shannon

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_TEXT_TYPES = (b"tEXt", b"zTXt", b"iTXt")

# A text value that decodes to one of these is a hidden file, not metadata.
_MAGICS: tuple[tuple[bytes, str], ...] = (
    (b"STGY", "Stagy container"),
    (b"PK\x03\x04", "ZIP / OOXML"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"%PDF-", "PDF document"),
    (b"\x1f\x8b\x08", "GZIP stream"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
)

_MIN_PAYLOAD = 512  # bytes; below this a high-entropy chunk is likely benign
_HIGH_ENTROPY = 5.0  # bits/byte; base64 ~6.0, ciphertext ~8.0, prose ~4.3, XML ~4.7
_INFLATE_CAP = 4 * 1024 * 1024  # zTXt/iTXt decompress ceiling — defuse a bomb

# Near-conclusive (decodes to a real file) vs merely suspicious (opaque blob).
_LOG_LR_MAGIC = 6.0
_LOG_LR_ENTROPY = 3.0

_B64_RE = re.compile(rb"^[A-Za-z0-9+/]+={0,2}$")


@dataclass(frozen=True)
class TextChunk:
    keyword: str
    kind: str  # tEXt | zTXt | iTXt
    size: int  # decoded value size in bytes
    entropy: float
    verdict: str  # clean | suspicious | payload
    note: str


@dataclass(frozen=True)
class PngTextResult:
    score: float  # 0..1
    log_lr: float  # deterministic weight (asymmetric: absence -> 0.0)
    detail: str
    chunks: list[TextChunk] = field(default_factory=list)


def _inflate(data: bytes) -> bytes | None:
    """zlib-inflate with a hard output cap; None on error or overflow."""
    d = zlib.decompressobj()
    try:
        out = d.decompress(data, _INFLATE_CAP)
    except zlib.error:
        return None
    return None if d.unconsumed_tail else out


def _iter_text_values(data: bytes) -> list[tuple[str, str, bytes]]:
    """(keyword, chunk-type, decoded-value-bytes) for each text chunk.

    A truncated or malformed chunk ends parsing rather than raising — a corrupt
    PNG must not crash a bulk scan.
    """
    if not data.startswith(_PNG_MAGIC):
        return []
    out: list[tuple[str, str, bytes]] = []
    off = 8
    n = len(data)
    while off + 8 <= n:
        length = int.from_bytes(data[off : off + 4], "big")
        ctype = data[off + 4 : off + 8]
        start = off + 8
        end = start + length
        if end + 4 > n:  # length runs past the file — truncated
            break
        if ctype in _TEXT_TYPES:
            parsed = _decode_text(ctype, data[start:end])
            if parsed is not None:
                out.append((parsed[0], ctype.decode("ascii"), parsed[1]))
        off = end + 4  # + CRC
        if ctype == b"IEND":
            break
    return out


def _decode_text(ctype: bytes, body: bytes) -> tuple[str, bytes] | None:
    """Return (keyword, value-bytes) for one text chunk, or None if unparseable."""
    nul = body.find(b"\x00")
    if nul == -1:
        return None
    keyword = body[:nul].decode("latin-1", "replace")
    rest = body[nul + 1 :]
    if ctype == b"tEXt":
        return keyword, rest
    if ctype == b"zTXt":
        # method byte, then zlib stream
        inflated = _inflate(rest[1:]) if rest else None
        return (keyword, inflated) if inflated is not None else None
    # iTXt: comp_flag, comp_method, lang \0 translated \0 text
    if len(rest) < 2:
        return None
    comp_flag = rest[0]
    after = rest[2:]
    p = after.find(b"\x00")
    q = after.find(b"\x00", p + 1) if p != -1 else -1
    if q == -1:
        return None
    text = after[q + 1 :]
    if comp_flag == 1:
        text = _inflate(text) or b""
    return keyword, text


def _match_magic(value: bytes) -> str | None:
    for sig, name in _MAGICS:
        if value.startswith(sig):
            return name
    return None


def _decoded_magic(value: bytes) -> str | None:
    """A file signature in the raw value, or in its base64 decoding."""
    if (m := _match_magic(value)) is not None:
        return m
    s = value.strip()
    if len(s) >= 8 and len(s) % 4 == 0 and _B64_RE.match(s):
        try:
            return _match_magic(base64.b64decode(s))
        except ValueError:  # binascii.Error subclasses ValueError
            return None
    return None


def _classify(keyword: str, kind: str, value: bytes) -> TextChunk:
    ent = shannon(value)
    if (magic := _decoded_magic(value)) is not None:
        return TextChunk(keyword, kind, len(value), ent, "payload", f"decodes to a {magic}")
    # XMP is legitimately large XML (and may embed a base64 thumbnail) — exclude
    # it from the opaque-blob heuristic, but never from the magic check above.
    is_xml = keyword.lower().startswith("xml")
    if not is_xml and len(value) >= _MIN_PAYLOAD and ent >= _HIGH_ENTROPY:
        return TextChunk(keyword, kind, len(value), ent, "suspicious",
                         f"{len(value)} bytes at {ent:.2f}/8 bits/byte — opaque, not metadata")
    return TextChunk(keyword, kind, len(value), ent, "clean", "")


def analyze(path: str) -> PngTextResult:
    data = Path(path).read_bytes()
    chunks = [_classify(kw, kind, value) for kw, kind, value in _iter_text_values(data)]
    payloads = [c for c in chunks if c.verdict == "payload"]
    suspicious = [c for c in chunks if c.verdict == "suspicious"]

    if payloads:
        names = ", ".join(f"{c.keyword!r} ({c.note})" for c in payloads)
        return PngTextResult(1.0, _LOG_LR_MAGIC,
                             f"PNG text chunk carries a hidden file: {names}", chunks)
    if suspicious:
        worst = max(suspicious, key=lambda c: c.entropy)
        return PngTextResult(worst.entropy / 8.0, _LOG_LR_ENTROPY,
                             f"PNG text chunk {worst.keyword!r}: {worst.note}", chunks)
    if chunks:
        return PngTextResult(0.0, 0.0, f"{len(chunks)} text chunk(s), none suspicious", chunks)
    return PngTextResult(0.0, 0.0, "no PNG text chunks", chunks)
