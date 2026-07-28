"""Codec registry. Importing this registers the built-in codecs."""

from __future__ import annotations

from . import (
    audio_spread,  # noqa: F401  (registers AudioSpreadCodec)
    audio_wav,  # noqa: F401  (registers WavLSBCodec)
    documents,  # noqa: F401  (registers ZeroWidth/Pdf/Docx codecs)
    image_lsb,  # noqa: F401  (registers ImageLSBCodec)
    metadata,  # noqa: F401  (registers AppendedData/Exif codecs)
)
from .base import CODECS, StegoCodec, register

# Optional codec. jpeglib is a native dep that must not be an import-time
# requirement — `import stagy` has to work on a base install — so the JPEG DCT
# codec registers only if jpeglib is present (roadmap §0.1 gotcha).
#
# The network module (codecs/network.py) is imported on demand by the CLI, not
# here: it registers no StegoCodec (it is a sender/receiver pair, not a file
# carrier) and its scapy transport is imported lazily, so there is nothing to
# register at startup.
try:
    from . import image_jpeg  # noqa: F401  (registers JpegDCTCodec; needs jpeglib)
except ImportError:
    pass

__all__ = ["CODECS", "StegoCodec", "register"]
