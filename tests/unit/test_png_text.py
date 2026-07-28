"""PNG text-chunk analyzer: catches payloads hidden in tEXt/zTXt/iTXt chunks."""

import base64
import os

import numpy as np
from PIL import Image
from PIL.PngImagePlugin import PngInfo

from stagy import container
from stagy.analysis import png_text, report


def _png(path, texts=(), itexts=(), *, zip_text=False) -> None:
    """A plain cover carrying the given (key, value) text / iTXt chunks."""
    info = PngInfo()
    for k, v in texts:
        info.add_text(k, v, zip=zip_text)
    for k, v in itexts:
        info.add_itxt(k, v)
    arr = np.full((48, 48, 3), 127, dtype=np.uint8)
    Image.fromarray(arr, "RGB").save(path, pnginfo=info)


def test_base64_container_is_payload(tmp_path) -> None:
    blob = container.encode(b"a hidden secret", encrypt=False)
    p = tmp_path / "s.png"
    _png(p, texts=[("data", base64.b64encode(blob).decode())])
    r = png_text.analyze(str(p))
    assert r.log_lr == png_text._LOG_LR_MAGIC
    assert "Stagy container" in r.detail


def test_raw_zip_header_is_payload(tmp_path) -> None:
    value = (b"PK\x03\x04" + os.urandom(600)).decode("latin-1")
    p = tmp_path / "z.png"
    _png(p, texts=[("blob", value)])
    r = png_text.analyze(str(p))
    assert r.log_lr == png_text._LOG_LR_MAGIC
    assert "ZIP" in r.detail


def test_compressed_ztxt_payload(tmp_path) -> None:
    blob = container.encode(b"secret via zTXt", encrypt=False)
    p = tmp_path / "c.png"
    _png(p, texts=[("data", base64.b64encode(blob).decode())], zip_text=True)
    r = png_text.analyze(str(p))
    assert r.log_lr == png_text._LOG_LR_MAGIC


def test_high_entropy_blob_is_suspicious(tmp_path) -> None:
    value = ("blob:" + os.urandom(1024).decode("latin-1"))  # opaque, no file magic
    p = tmp_path / "h.png"
    _png(p, texts=[("x", value)])
    r = png_text.analyze(str(p))
    assert r.log_lr == png_text._LOG_LR_ENTROPY


def test_normal_metadata_is_clean(tmp_path) -> None:
    p = tmp_path / "ok.png"
    _png(p, texts=[("Software", "Stagy 1.0"), ("Comment", "a photo of the beach")])
    r = png_text.analyze(str(p))
    assert r.log_lr == 0.0


def test_xmp_is_whitelisted(tmp_path) -> None:
    # Large, high-entropy XMP (embedded base64 thumbnail) must not false-positive.
    xmp = "<?xpacket?>" + base64.b64encode(os.urandom(2000)).decode()
    p = tmp_path / "xmp.png"
    _png(p, itexts=[("XML:com.adobe.xmp", xmp)])
    r = png_text.analyze(str(p))
    assert r.log_lr == 0.0, r.detail


def test_non_png_is_neutral(tmp_path) -> None:
    p = tmp_path / "x.jpg"
    Image.fromarray(np.zeros((16, 16, 3), dtype=np.uint8), "RGB").save(p, "JPEG")
    assert png_text.analyze(str(p)).log_lr == 0.0


def test_report_flags_png_text_payload(tmp_path) -> None:
    blob = container.encode(b"payload in a text chunk", encrypt=False)
    p = tmp_path / "s.png"
    _png(p, texts=[("data", base64.b64encode(blob).decode())])
    rep = report.analyze(str(p))
    assert rep.verdict != "clean"
    pt = next(s for s in rep.signals if s.name == "png-text")
    assert pt.log_lr is not None and pt.log_lr > 0
