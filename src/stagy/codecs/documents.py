"""Document codecs (roadmap Task 4.3): zero-width text, PDF, and DOCX.

Three carriers, one framed container each:

* **Zero-width text** — encode the container's bits as zero-width spaces (bit 0)
  and zero-width non-joiners (bit 1), interleaved into a visible carrier string.
  Invisible when rendered; high deniability, low capacity.
* **PDF** — stash the base64 container in a custom document-info key. Pages render
  unchanged.
* **DOCX** — a ``.docx`` is a ZIP (OOXML); add the container as an extra part. The
  append trick of Task 4.1, applied to the OOXML package.

All three are fragile — a re-save, a metadata strip, or a "remove hidden data"
pass wipes them — and the blue-team side (a metadata dump, a zip listing, a
zero-width scan) finds them easily. That asymmetry is the design.
"""

from __future__ import annotations

import base64
import zipfile
from pathlib import Path
from typing import Any

from ..bitstream import bits_to_bytes, bytes_to_bits
from ..container import header_prefix_len, total_len
from ..errors import NoPayloadError, StagyError, UnsupportedFormatError
from .base import register

# Capacity for these techniques is not bounded by cover size; report a large,
# honest-enough ceiling rather than a false per-cover number.
_DOC_CAPACITY = 1 << 30

_ZW0 = "\u200b"  # ZERO WIDTH SPACE -> bit 0
_ZW1 = "\u200c"  # ZERO WIDTH NON-JOINER -> bit 1

_PDF_KEY = "/StagyData"
_DOCX_PART = "stagy/payload.bin"


def _validated(blob: bytes) -> bytes:
    """Confirm blob is a Stagy container and trim to its exact length."""
    header_prefix_len(blob)  # validates MAGIC; raises NoPayloadError otherwise
    total = total_len(blob)
    if total > len(blob):
        raise NoPayloadError("container is truncated")
    return blob[:total]


class ZeroWidthCodec:
    """Interleave the container's bits into a carrier text as zero-width chars."""

    name = "zerowidth"

    def capacity(self, cover_path: str, **opts: object) -> int:
        return _DOC_CAPACITY

    def embed(self, cover_path: str, container: bytes, out_path: str, **opts: object) -> None:
        carrier = Path(cover_path).read_text(encoding="utf-8")
        zw = [_ZW1 if bit else _ZW0 for bit in bytes_to_bits(container)]
        chars: list[str] = []
        zi = 0
        for ch in carrier:
            chars.append(ch)
            if zi < len(zw):  # one hidden bit after each visible character
                chars.append(zw[zi])
                zi += 1
        chars.extend(zw[zi:])  # any remainder rides along at the end
        Path(out_path).write_text("".join(chars), encoding="utf-8")

    def extract(self, stego_path: str, **opts: object) -> bytes:
        text = Path(stego_path).read_text(encoding="utf-8")
        bits = [1 if ch == _ZW1 else 0 for ch in text if ch in (_ZW0, _ZW1)]
        if not bits:
            raise NoPayloadError("no zero-width characters found")
        return _validated(bits_to_bytes(bits))


def _pypdf() -> Any:
    try:
        import pypdf
    except ImportError as e:
        raise StagyError(
            "the PDF codec requires pypdf — install it with: pip install 'stagy[docs-fmt]'"
        ) from e
    return pypdf


class PdfCodec:
    """Hide the base64 container in a custom PDF document-info key."""

    name = "pdf"

    def capacity(self, cover_path: str, **opts: object) -> int:
        return _DOC_CAPACITY

    def embed(self, cover_path: str, container: bytes, out_path: str, **opts: object) -> None:
        pypdf = _pypdf()
        reader = pypdf.PdfReader(cover_path)
        writer = pypdf.PdfWriter()
        writer.append(reader)
        if reader.metadata:  # keep the cover's own metadata alongside ours
            writer.add_metadata({k: v for k, v in reader.metadata.items() if isinstance(v, str)})
        writer.add_metadata({_PDF_KEY: base64.b64encode(container).decode("ascii")})
        with open(out_path, "wb") as f:
            writer.write(f)

    def extract(self, stego_path: str, **opts: object) -> bytes:
        pypdf = _pypdf()
        meta = pypdf.PdfReader(stego_path).metadata
        value = meta.get(_PDF_KEY) if meta else None
        if not value:
            raise NoPayloadError("no Stagy container in this PDF's metadata")
        try:
            blob = base64.b64decode(value, validate=True)
        except (ValueError, TypeError) as e:
            raise NoPayloadError("PDF metadata is not a valid Stagy container") from e
        return _validated(blob)


class DocxCodec:
    """Store the container as an extra part inside the DOCX (OOXML) ZIP package."""

    name = "docx"

    def capacity(self, cover_path: str, **opts: object) -> int:
        return _DOC_CAPACITY

    def embed(self, cover_path: str, container: bytes, out_path: str, **opts: object) -> None:
        try:
            with zipfile.ZipFile(cover_path, "r") as zin:
                items = zin.infolist()
                payloads = {it.filename: zin.read(it.filename) for it in items}
        except zipfile.BadZipFile as e:
            raise UnsupportedFormatError(f"{cover_path!r} is not a DOCX/ZIP package") from e
        with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zout:
            for it in items:
                if it.filename == _DOCX_PART:
                    continue  # drop any prior payload so re-embedding is idempotent
                zout.writestr(it, payloads[it.filename])
            zout.writestr(_DOCX_PART, container)

    def extract(self, stego_path: str, **opts: object) -> bytes:
        try:
            with zipfile.ZipFile(stego_path, "r") as z:
                if _DOCX_PART not in z.namelist():
                    raise NoPayloadError("no Stagy part in this DOCX package")
                blob = z.read(_DOCX_PART)
        except zipfile.BadZipFile as e:
            raise UnsupportedFormatError(f"{stego_path!r} is not a DOCX/ZIP package") from e
        return _validated(blob)


register(ZeroWidthCodec())
register(PdfCodec())
register(DocxCodec())
