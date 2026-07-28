"""Metadata-family codecs: appended-data / polyglot (Task 4.1) and EXIF (Task 4.2).

Appended data (``AppendedDataCodec``): most image formats stop parsing at an end
marker — PNG at ``IEND``, JPEG at ``FFD9``. Bytes after it are ignored by viewers
but ride along in the file: the cheapest, highest-capacity image steganography
there is. Embed appends the framed container past the marker; extract scans from
the marker to EOF. The polyglot variant (`make_polyglot`) appends a whole valid
archive so the file is *both* a viewable image and an openable ZIP.

EXIF (``ExifCodec``): base64 the framed container into a JPEG EXIF tag (default
``UserComment``). Only the APP1 metadata segment is rewritten, so the compressed
image data is untouched.

Both are fragile by design — they survive a byte-for-byte copy but a re-encode
(or a metadata strip, for EXIF) wipes them, and the blue-team analyzers spot them
easily (a carver for the polyglot, entropy for an appended blob, a metadata dump
for EXIF). That asymmetry is the point.
"""

from __future__ import annotations

import base64
import shutil
from pathlib import Path
from typing import Any

from ..container import MAGIC, crc_ok, header_prefix_len, total_len
from ..errors import CapacityError, NoPayloadError, StagyError, UnsupportedFormatError
from .base import register

_JPEG_EXT = (".jpg", ".jpeg")
# EXIF UserComment / metadata sits in a JPEG APP1 segment capped at 64 KB; base64
# inflates the payload by 4/3, so the usable container size is ~3/4 of that.
_EXIF_CAPACITY = (0xFFFF - 1024) * 3 // 4
# 8-byte EXIF character-code prefixes that may lead a UserComment value.
_EXIF_CHARSET_CODES = (
    b"ASCII\x00\x00\x00",
    b"UNICODE\x00",
    b"JIS\x00\x00\x00\x00\x00",
    b"\x00\x00\x00\x00\x00\x00\x00\x00",
)

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_PNG_IEND = b"IEND\xaeB`\x82"  # IEND chunk + its fixed CRC — the true PNG end
_JPEG_MAGIC = b"\xff\xd8\xff"
_JPEG_EOI = b"\xff\xd9"


def _primary_eof(data: bytes) -> int | None:
    """Offset just past a known container's end marker, or None if not a container.

    ponytail: same format knowledge as analysis.filecarve.primary_eof, kept
    separate so codecs never depend on the analysis layer. Extract one helper if
    a third caller appears.
    """
    if data.startswith(_PNG_MAGIC):
        i = data.rfind(_PNG_IEND)
        return i + len(_PNG_IEND) if i != -1 else None
    if data[:3] == _JPEG_MAGIC:
        i = data.rfind(_JPEG_EOI)
        return i + len(_JPEG_EOI) if i != -1 else None
    return None


class AppendedDataCodec:
    name = "appended"

    def capacity(self, cover_path: str, **opts: object) -> int:
        # Bounded by free disk, not the cover — appended data has no size limit.
        return int(shutil.disk_usage(Path(cover_path).resolve().parent).free)

    def embed(self, cover_path: str, container: bytes, out_path: str, **opts: object) -> None:
        data = Path(cover_path).read_bytes()
        eof = _primary_eof(data)
        base = data[:eof] if eof is not None else data
        Path(out_path).write_bytes(base + container)

    def extract(self, stego_path: str, **opts: object) -> bytes:
        data = Path(stego_path).read_bytes()
        # Scan for a CRC-valid container rather than trusting a format end marker:
        # an appended *encrypted* container is random bytes and readily contains a
        # 2-byte JPEG EOI, so locating it by the marker is unreliable. The CRC is.
        start = 0
        while (i := data.find(MAGIC, start)) != -1:
            if crc_ok(data[i:]):
                return data[i : i + total_len(data[i:])]
            start = i + 1
        raise NoPayloadError("no Stagy container appended to this file")


def make_polyglot(cover_path: str, archive: bytes, out_path: str) -> None:
    """Append a whole valid archive (e.g. a ZIP) after the cover's end marker so
    the output is both a viewable image and an openable archive."""
    data = Path(cover_path).read_bytes()
    eof = _primary_eof(data)
    base = data[:eof] if eof is not None else data
    Path(out_path).write_bytes(base + archive)


def _piexif() -> Any:
    """Lazily import piexif. Optional dep (`stagy[docs-fmt]`); keep it out of the
    import path so `import stagy` works without it (AppendedDataCodec must not
    depend on it)."""
    try:
        import piexif  # type: ignore[import-untyped]
    except ImportError as e:
        raise StagyError(
            "the EXIF codec requires piexif — install it with: pip install 'stagy[docs-fmt]'"
        ) from e
    return piexif


def _strip_charset(value: bytes) -> bytes:
    for code in _EXIF_CHARSET_CODES:
        if value.startswith(code):
            return value[len(code) :]
    return value


class ExifCodec:
    """Hide the framed container, base64-encoded, in a JPEG EXIF tag.

    Only the APP1 (EXIF) segment is rewritten; the compressed image data is copied
    verbatim, so the picture is pixel-for-pixel unchanged.
    """

    name = "exif"

    def capacity(self, cover_path: str, **opts: object) -> int:
        return _EXIF_CAPACITY

    def _tag(self, opts: dict[str, object]) -> int:
        piexif = _piexif()
        raw = opts.get("tag")
        return int(raw) if isinstance(raw, int) else int(piexif.ExifIFD.UserComment)

    def embed(self, cover_path: str, container: bytes, out_path: str, **opts: object) -> None:
        if not cover_path.lower().endswith(_JPEG_EXT):
            raise UnsupportedFormatError(f"EXIF codec needs a JPEG cover, got {cover_path!r}")
        if not out_path.lower().endswith(_JPEG_EXT):
            raise UnsupportedFormatError(f"EXIF codec writes JPEG only, got {out_path!r}")
        piexif = _piexif()
        tag = self._tag(opts)
        exif: dict[str, Any] = piexif.load(cover_path)
        exif.setdefault("Exif", {})[tag] = b"ASCII\x00\x00\x00" + base64.b64encode(container)
        exif_bytes = piexif.dump(exif)
        # The APP1 segment length is a uint16 (marker + length word + data), so
        # anything past 64 KB cannot be written — catch it before insert does.
        if len(exif_bytes) + 2 > 0xFFFF:
            raise CapacityError(
                f"payload does not fit in a JPEG EXIF segment (~{_EXIF_CAPACITY} bytes max)"
            )
        piexif.insert(exif_bytes, cover_path, out_path)

    def extract(self, stego_path: str, **opts: object) -> bytes:
        piexif = _piexif()
        tag = self._tag(opts)
        value = piexif.load(stego_path).get("Exif", {}).get(tag)
        if not value:
            raise NoPayloadError("no Stagy container in this JPEG's EXIF")
        try:
            blob = base64.b64decode(_strip_charset(value), validate=True)
        except (ValueError, TypeError) as e:
            raise NoPayloadError("EXIF tag is not a valid Stagy container") from e
        header_prefix_len(blob)  # validates MAGIC; raises NoPayloadError otherwise
        total = total_len(blob)
        if total > len(blob):
            raise NoPayloadError("EXIF container is truncated")
        return blob[:total]


def metadata_scan(path: str) -> dict[str, Any]:
    """Dump all EXIF (and any XMP packet) for the analyzer / `stagy meta scan`.

    Returns {"exif": {ifd: {tag_name: value}}, "xmp": str | None}. Empty dict if
    piexif is unavailable or the file carries no EXIF.
    """
    try:
        piexif = _piexif()
    except StagyError:
        return {}
    try:
        loaded = piexif.load(path)
    except Exception:  # noqa: BLE001 — a metadata scan must never crash on odd input
        return {}

    exif: dict[str, dict[str, Any]] = {}
    for ifd in ("0th", "Exif", "GPS", "1st"):
        entries = loaded.get(ifd) or {}
        if not entries:
            continue
        named: dict[str, Any] = {}
        for tag_id, value in entries.items():
            name = piexif.TAGS.get(ifd, {}).get(tag_id, {}).get("name", str(tag_id))
            named[name] = _readable(value)
        exif[ifd] = named

    data = Path(path).read_bytes()
    start = data.find(b"<x:xmpmeta")
    end = data.find(b"</x:xmpmeta>")
    xmp = data[start : end + len(b"</x:xmpmeta>")].decode("utf-8", "replace") if start != -1 and end != -1 else None
    return {"exif": exif, "xmp": xmp}


def _readable(value: Any) -> Any:
    """Render an EXIF value JSON-safely: bytes -> short repr with length."""
    if isinstance(value, bytes):
        preview = value[:32].decode("latin-1", "replace")
        return f"<{len(value)} bytes: {preview!r}{'…' if len(value) > 32 else ''}>"
    return value


register(AppendedDataCodec())
register(ExifCodec())
