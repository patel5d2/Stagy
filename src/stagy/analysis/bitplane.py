"""Bit-plane extraction. A clean photo's LSB plane looks like noise; embedded
data often shows structure or a sharp noise/clean boundary."""

from __future__ import annotations

import numpy as np
from PIL import Image


def extract_plane(image_path: str, plane: int = 0, *, channel: str = "L") -> np.ndarray:
    """Return the given bit-plane as a 0/255 uint8 image array.

    channel: "L" for luminance, or one of "R"/"G"/"B".
    """
    if not 0 <= plane <= 7:
        raise ValueError("plane must be 0..7")
    if channel == "L":
        arr = np.asarray(Image.open(image_path).convert("L"), dtype=np.uint8)
    else:
        idx = {"R": 0, "G": 1, "B": 2}[channel]
        arr = np.asarray(Image.open(image_path).convert("RGB"), dtype=np.uint8)[..., idx]
    return (((arr >> plane) & 1) * 255).astype(np.uint8)


def plane_png_bytes(image_path: str, plane: int = 0, *, channel: str = "L") -> bytes:
    """Render a bit-plane to PNG bytes (for the web app / reports)."""
    import io

    buf = io.BytesIO()
    Image.fromarray(extract_plane(image_path, plane, channel=channel), "L").save(buf, format="PNG")
    return buf.getvalue()
