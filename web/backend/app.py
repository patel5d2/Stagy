"""Stagy web API — roadmap Task 7.1.

Every endpoint is a thin call into `stagy.hide` / `stagy.reveal` /
`analysis.report`. No stego logic lives here; the API is a transport.

**Uploads are never persisted.** Files are held in memory for the life of the
request and handed to codecs through a per-request temp dir that is removed on
the way out, including on error. Nothing is written to a durable path.

**Network endpoints are deliberately absent.** The roadmap is explicit that raw
packet crafting does not belong behind a web form; `stagy net` stays CLI-only.

Deployment note: the passphrase transits the request body, so this must sit
behind TLS. Server-side processing means user files touch the server — that is
inherent to the design and is stated in the API description.
"""

from __future__ import annotations

import base64
import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, Form, HTTPException, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

import stagy
from stagy.analysis import bitplane, report
from stagy.codecs import CODECS
from stagy.container import DecodedPayload
from stagy.errors import (
    CapacityError,
    IntegrityError,
    NoPayloadError,
    StagyError,
    UnsupportedFormatError,
    WrongKeyError,
)

from .limits import (
    MAX_DECOMPRESSED_BYTES,
    MAX_UPLOAD_BYTES,
    rate_limit,
    read_upload,
    require_supported_cover,
)

app = FastAPI(
    title="Stagy API",
    version=stagy.__version__,
    description=(
        "Hide, reveal, and detect hidden data in images.\n\n"
        "**Uploads are processed in memory and never persisted.** "
        "Passphrases transit the request body — deploy behind TLS only. "
        "Network steganography is intentionally not exposed over HTTP."
    ),
)

# Dev default only. In deployment, set STAGY_CORS_ORIGINS to the real origin.
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get(
        "STAGY_CORS_ORIGINS", "http://localhost:5173"
    ).split(","),
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

_RateLimited = Depends(rate_limit)


@contextmanager
def _scratch() -> Iterator[str]:
    """Per-request temp dir, removed on the way out even if the body raises."""
    with tempfile.TemporaryDirectory(prefix="stagy-req-") as d:
        yield d


def _write(directory: str, name: str, data: bytes) -> str:
    path = os.path.join(directory, name)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


# Every `_*_sync` below is deliberately synchronous and is dispatched through
# `run_in_threadpool`. Embedding and steganalysis are seconds of blocking numpy
# on a large cover; running them directly in an `async def` would stall the
# event loop and every concurrent request with it.


# StagyError -> HTTP status. Anything unmapped is a 500 and stays generic, so
# internal detail never leaks to the client.
# Plain ints, not starlette.status constants: several were renamed across
# versions (HTTP_413_REQUEST_ENTITY_TOO_LARGE -> HTTP_413_CONTENT_TOO_LARGE).
_STATUS = {
    CapacityError: 422,
    UnsupportedFormatError: 415,
    WrongKeyError: 403,
    NoPayloadError: 404,
    IntegrityError: 422,
}


@app.exception_handler(StagyError)
async def _stagy_error(_req: object, exc: StagyError) -> Response:
    code = _STATUS.get(type(exc), 400)
    return Response(
        content=f'{{"detail":{_json_str(str(exc))}}}',
        status_code=code,
        media_type="application/json",
    )


def _json_str(s: str) -> str:
    import json

    return json.dumps(s)


class HealthOut(BaseModel):
    status: str
    version: str
    codecs: list[str]
    max_upload_bytes: int


@app.get("/api/health", response_model=HealthOut, tags=["meta"])
def health() -> HealthOut:
    return HealthOut(
        status="ok",
        version=stagy.__version__,
        codecs=sorted(CODECS),
        max_upload_bytes=MAX_UPLOAD_BYTES,
    )


class CapacityOut(BaseModel):
    capacity_bytes: int
    cover_type: str
    bits: int
    channels: str


@app.post("/api/capacity", response_model=CapacityOut, tags=["hide"],
          dependencies=[_RateLimited])
async def capacity(
    cover: UploadFile,
    bits: Annotated[int, Form(ge=1, le=4)] = 1,
    channels: Annotated[str, Form()] = "RGB",
) -> CapacityOut:
    """Bytes this cover can carry. Drives the frontend's live capacity meter."""
    data = await read_upload(cover, field="cover")
    mime = require_supported_cover(data)

    def _sync() -> int:
        with _scratch() as d:
            path = _write(d, "cover", data)
            return int(CODECS["image"].capacity(path, bits=bits, channels=channels))

    n = await run_in_threadpool(_sync)
    return CapacityOut(capacity_bytes=n, cover_type=mime, bits=bits, channels=channels)


@app.post("/api/embed", tags=["hide"], dependencies=[_RateLimited],
          response_class=Response)
async def embed(
    cover: UploadFile,
    payload: UploadFile,
    passphrase: Annotated[str, Form()] = "",
    encrypt: Annotated[bool, Form()] = True,
    compress: Annotated[bool, Form()] = False,
    bits: Annotated[int, Form(ge=1, le=4)] = 1,
    channels: Annotated[str, Form()] = "RGB",
    mode: Annotated[str, Form()] = "keyed",
) -> Response:
    """Embed a payload and stream back the stego PNG."""
    cover_bytes = await read_upload(cover, field="cover")
    require_supported_cover(cover_bytes)
    payload_bytes = await read_upload(payload, field="payload")

    if encrypt and not passphrase:
        raise HTTPException(
            400, "encryption requested but no passphrase given"
        )

    # The client's filename is attacker-controlled; store only a sanitized
    # basename. container.decode() sanitizes again on the way back out.
    stored_name = os.path.basename(payload.filename or "payload.bin")

    def _sync() -> bytes:
        with _scratch() as d:
            cover_path = _write(d, "cover.png", cover_bytes)
            out_path = os.path.join(d, "stego.png")
            stagy.hide(
                cover_path,
                payload_bytes,
                out_path,
                passphrase=passphrase or None,
                encrypt=encrypt,
                compress=compress,
                filename=stored_name,
                bits=bits,
                channels=channels,
                mode=mode,
            )
            with open(out_path, "rb") as fh:
                return fh.read()

    stego = await run_in_threadpool(_sync)
    return Response(
        content=stego,
        media_type="image/png",
        headers={"Content-Disposition": 'attachment; filename="stego.png"'},
    )


class ExtractOut(BaseModel):
    filename: str | None
    was_encrypted: bool
    size_bytes: int
    payload_b64: str


@app.post("/api/extract", response_model=ExtractOut, tags=["reveal"],
          dependencies=[_RateLimited])
async def extract(
    stego: UploadFile,
    passphrase: Annotated[str, Form()] = "",
    bits: Annotated[int, Form(ge=1, le=4)] = 1,
    channels: Annotated[str, Form()] = "RGB",
    mode: Annotated[str, Form()] = "keyed",
) -> ExtractOut:
    """Recover a hidden payload. Returned base64 — never written to a path.

    `filename` is sanitized to a bare basename by `container.decode`; a client
    that writes it to disk must still join it to a directory it controls.
    """
    data = await read_upload(stego, field="stego")
    require_supported_cover(data, field="stego")

    def _sync() -> DecodedPayload:
        with _scratch() as d:
            path = _write(d, "stego.png", data)
            return stagy.reveal(
                path,
                passphrase=passphrase or None,
                bits=bits,
                channels=channels,
                mode=mode,
                max_decompressed=MAX_DECOMPRESSED_BYTES,
            )

    result = await run_in_threadpool(_sync)
    return ExtractOut(
        filename=result.filename,
        was_encrypted=result.was_encrypted,
        size_bytes=len(result.payload),
        payload_b64=base64.b64encode(result.payload).decode("ascii"),
    )


class SignalOut(BaseModel):
    name: str
    score: float
    detail: str
    log_lr: float | None = None


class DetectOut(BaseModel):
    verdict: str  # clean | suspicious | likely-stego
    probability: float  # posterior P(stego | signals), given the prior
    prior: float
    calibrated: bool  # False => probability is a fallback, not a fitted estimate
    flag_threshold: float
    signals: list[SignalOut]
    bitplane_png_b64: str | None = None


@app.post("/api/detect", response_model=DetectOut, tags=["detect"],
          dependencies=[_RateLimited])
async def detect(
    suspect: UploadFile,
    reference: UploadFile | None = None,
    include_bitplane: Annotated[bool, Form()] = True,
) -> DetectOut:
    """Run the steganalysis suite. Optional reference gives a near-certain verdict."""
    data = await read_upload(suspect, field="suspect")
    require_supported_cover(data, field="suspect")
    ref_bytes = await read_upload(reference, field="reference") if reference else None
    if ref_bytes:
        require_supported_cover(ref_bytes, field="reference")

    def _sync() -> tuple[report.Report, str | None]:
        with _scratch() as d:
            path = _write(d, "suspect.png", data)
            ref_path = _write(d, "reference.png", ref_bytes) if ref_bytes else None
            rep = report.analyze(path, reference=ref_path)
            plane_b64 = None
            if include_bitplane:
                plane_b64 = base64.b64encode(
                    bitplane.plane_png_bytes(path, 0)
                ).decode("ascii")
            return rep, plane_b64

    rep, plane_b64 = await run_in_threadpool(_sync)
    return DetectOut(
        verdict=rep.verdict,
        probability=rep.probability,
        prior=rep.prior,
        calibrated=rep.calibrated,
        flag_threshold=rep.flag_threshold,
        signals=[
            SignalOut(name=s.name, score=s.score, detail=s.detail, log_lr=s.log_lr)
            for s in rep.signals
        ],
        bitplane_png_b64=plane_b64,
    )
