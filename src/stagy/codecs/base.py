"""Codec contract + registry. Codecs are dumb bit carriers — no crypto, no container."""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class StegoCodec(Protocol):
    name: str

    def capacity(self, cover_path: str, **opts: object) -> int:
        """Max payload BYTES this cover can hold with these options."""

    def embed(self, cover_path: str, container: bytes, out_path: str, **opts: object) -> None:
        """Store the already-framed container bytes into the cover."""

    def extract(self, stego_path: str, **opts: object) -> bytes:
        """Pull the framed container bytes back out. Raises if none found."""


CODECS: dict[str, StegoCodec] = {}


def register(codec: StegoCodec) -> StegoCodec:
    CODECS[codec.name] = codec
    return codec
