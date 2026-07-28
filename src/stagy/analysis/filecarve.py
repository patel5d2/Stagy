"""binwalk-style signature carving — finds files hidden *after* a cover's end.

Most viewers stop parsing a container at its end marker (PNG at ``IEND``, JPEG
at ``FFD9``). Bytes after that marker are ignored by the viewer but sit in the
file, which is the cheapest, highest-capacity image steganography there is — and
exactly what a file carver is built to catch.

This scans the appended region (everything past the primary EOF marker) for
known file signatures. A recognised header there — a ZIP, a second image, a PDF
— is near-conclusive: nothing legitimate writes a ZIP local-file header after a
PNG's ``IEND``. Absence proves nothing, though: LSB embedding and a clean cover
both leave the appended region empty, so a "no signatures" result is neutral
evidence, never a clean verdict. That asymmetry is why this analyzer supplies
its own evidence weight instead of being calibrated against the LSB corpus.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

# Signature -> human description. Kept to headers distinctive enough that a hit
# in an appended region is meaningful rather than random.
_SIGNATURES: dict[bytes, str] = {
    b"PK\x03\x04": "ZIP archive (or DOCX/XLSX/JAR/APK)",
    b"\x89PNG\r\n\x1a\n": "PNG image",
    b"\xff\xd8\xff": "JPEG image",
    b"GIF87a": "GIF image",
    b"GIF89a": "GIF image",
    b"%PDF-": "PDF document",
    b"\x1f\x8b\x08": "GZIP stream",
    b"Rar!\x1a\x07": "RAR archive",
    b"7z\xbc\xaf\x27\x1c": "7-Zip archive",
    b"BZh": "BZIP2 stream",
    b"ustar": "TAR archive",
    b"OggS": "OGG stream",
}

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_PNG_IEND = b"IEND\xaeB`\x82"  # IEND chunk + its fixed CRC — the true PNG end
_JPEG_MAGIC = b"\xff\xd8\xff"
_JPEG_EOI = b"\xff\xd9"

# A found artifact after EOF is near-conclusive; give it more weight than any
# calibrated statistical estimator can reach. Absence is neutral (0.0).
_LOG_LR_POST_EOF = 6.0


@dataclass(frozen=True)
class Carved:
    offset: int
    signature: str  # hex of the matched magic
    description: str
    after_eof: bool


@dataclass(frozen=True)
class CarveResult:
    carved: list[Carved]
    score: float  # 0..1, presence/strength of appended artifacts
    log_lr: float  # deterministic evidence weight (asymmetric: absence -> 0)
    detail: str


def primary_eof(data: bytes) -> int | None:
    """Offset just past a known container's end marker, or None if not a container.

    Uses the *last* end marker: a PNG can carry ``IEND`` inside embedded data,
    but the structurally-final one bounds the real image.
    """
    if data.startswith(_PNG_MAGIC):
        i = data.rfind(_PNG_IEND)
        return i + len(_PNG_IEND) if i != -1 else None
    if data[:3] == _JPEG_MAGIC:
        i = data.rfind(_JPEG_EOI)
        return i + len(_JPEG_EOI) if i != -1 else None
    return None


def scan(path: str) -> list[Carved]:
    """Locate known file signatures. For containers, only the appended region is
    scanned (pixel data throws random short-signature false positives); for other
    files the whole body is scanned, skipping the file's own header at offset 0.
    """
    data = Path(path).read_bytes()
    eof = primary_eof(data)
    base = eof if eof is not None else 0
    region = data[base:]

    found: list[Carved] = []
    for sig, desc in _SIGNATURES.items():
        start = 0
        while (i := region.find(sig, start)) != -1:
            abs_off = base + i
            if abs_off != 0:  # skip the container's own header
                found.append(Carved(abs_off, sig.hex(), desc, after_eof=eof is not None))
            start = i + 1
    return sorted(found, key=lambda c: c.offset)


def analyze(path: str) -> CarveResult:
    carved = scan(path)
    post = [c for c in carved if c.after_eof]
    if post:
        descs = ", ".join(dict.fromkeys(c.description for c in post))  # unique, ordered
        return CarveResult(
            carved, 1.0, _LOG_LR_POST_EOF,
            f"{len(post)} file signature(s) appended after the container's EOF: {descs}",
        )
    if carved:
        # Signatures in a non-container file: report, but do not drive the verdict
        # on their own (a real archive legitimately contains many local headers).
        return CarveResult(
            carved, 0.3, 0.0,
            f"{len(carved)} embedded signature(s) found; none past a container EOF",
        )
    return CarveResult([], 0.0, 0.0, "no appended file signatures")
