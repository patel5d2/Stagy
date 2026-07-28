"""Upload limits, cover-type whitelisting, and rate limiting.

Every control here exists because the API accepts files from anyone and hands
them to parsers. Roadmap 7.1: "Process files in-memory or in a per-request temp
dir and delete immediately — never persist user uploads. Enforce a max upload
size. Add rate limiting. Validate/whitelist file types before handing to codecs."
"""

from __future__ import annotations

import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request, UploadFile

MAX_UPLOAD_BYTES = 16 * 1024 * 1024
"""Hard ceiling per uploaded file."""

MAX_DECOMPRESSED_BYTES = 32 * 1024 * 1024
"""Ceiling passed to container.decode.

Far below the library default: a public endpoint is exactly where a
decompression bomb pays off. Measured amplification on the unpatched
container was 1,028x, so 16 MB of upload could have claimed ~16 GB of RAM.
"""

# Magic-number whitelist. Extensions are attacker-supplied and mean nothing;
# these are the formats the LSB codec can actually open losslessly.
_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"BM", "image/bmp"),
)

RATE_LIMIT_REQUESTS = 30
RATE_LIMIT_WINDOW_S = 60.0

# ponytail: in-process sliding window, fine for one worker. Swap for Redis if
# this is ever run multi-process — the counters are per-process, not shared.
_HITS: defaultdict[str, deque[float]] = defaultdict(deque)


def rate_limit(request: Request) -> None:
    """Sliding-window limiter keyed on client IP. FastAPI dependency."""
    client = request.client.host if request.client else "unknown"
    now = time.monotonic()
    hits = _HITS[client]
    while hits and now - hits[0] > RATE_LIMIT_WINDOW_S:
        hits.popleft()
    if len(hits) >= RATE_LIMIT_REQUESTS:
        raise HTTPException(
            429,
            f"rate limit: {RATE_LIMIT_REQUESTS} requests per "
            f"{int(RATE_LIMIT_WINDOW_S)}s",
        )
    hits.append(now)


def reset_rate_limits() -> None:
    """Test hook — clears the window so suites don't trip each other."""
    _HITS.clear()


async def read_upload(upload: UploadFile, *, field: str) -> bytes:
    """Read an upload into memory, enforcing the size cap while streaming.

    Reads one chunk past the limit rather than trusting Content-Length, which
    a client controls independently of what it actually sends.
    """
    buf = bytearray()
    while chunk := await upload.read(1024 * 1024):
        buf += chunk
        if len(buf) > MAX_UPLOAD_BYTES:
            raise HTTPException(
                413,
                f"{field} exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit",
            )
    if not buf:
        raise HTTPException(400, f"{field} is empty")
    return bytes(buf)


def require_supported_cover(data: bytes, *, field: str = "cover") -> str:
    """Whitelist by magic number, not by filename. Returns the MIME type."""
    for sig, mime in _SIGNATURES:
        if data.startswith(sig):
            return mime
    raise HTTPException(
        415,
        f"{field} must be PNG or BMP (lossless). JPEG/WebP re-encoding "
        f"destroys LSB data, so they are refused rather than silently corrupted.",
    )
