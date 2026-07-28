"""Tests for the document codecs (roadmap Task 4.3): zero-width, PDF, DOCX.

Acceptance criteria under test:
  * each technique round-trips
  * the carrier document still opens / renders normally (visible text, PDF pages,
    and OOXML parts are all preserved unchanged)
"""

import os
import zipfile

import pytest

import stagy
from stagy.codecs import CODECS
from stagy.codecs.documents import _ZW0, _ZW1
from stagy.container import KeyMaterial, encode
from stagy.crypto import derive_keys
from stagy.errors import NoPayloadError, UnsupportedFormatError

_CARRIER = "The quick brown fox jumps over the lazy dog.\n" * 6

_CT = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"""
_RELS = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"""
_DOC = b'<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>hello</w:t></w:r></w:p></w:body></w:document>'


def _container(payload: bytes) -> bytes:
    salt = os.urandom(16)
    return encode(payload, key_material=KeyMaterial(derive_keys("pw", salt).aes_key, salt))


def _make_pdf(path: str) -> None:
    from pypdf import PdfWriter

    w = PdfWriter()
    w.add_blank_page(width=200, height=200)
    with open(path, "wb") as f:
        w.write(f)


def _make_docx(path: str) -> None:
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("[Content_Types].xml", _CT)
        z.writestr("_rels/.rels", _RELS)
        z.writestr("word/document.xml", _DOC)


# ---- zero-width ---------------------------------------------------------------

def test_zerowidth_roundtrip_and_carrier_visible(tmp_path) -> None:
    cover, stego = tmp_path / "c.txt", tmp_path / "s.txt"
    cover.write_text(_CARRIER, encoding="utf-8")
    payload = os.urandom(64)
    stagy.hide(str(cover), payload, str(stego), codec="zerowidth", passphrase="pw")
    assert stagy.reveal(str(stego), codec="zerowidth", passphrase="pw").payload == payload
    # Stripping the invisible chars must give back the original carrier verbatim.
    visible = stego.read_text(encoding="utf-8").replace(_ZW0, "").replace(_ZW1, "")
    assert visible == _CARRIER


def test_zerowidth_codec_bit_identical(tmp_path) -> None:
    cover, stego = tmp_path / "c.txt", tmp_path / "s.txt"
    cover.write_text(_CARRIER, encoding="utf-8")
    blob = _container(os.urandom(40))
    CODECS["zerowidth"].embed(str(cover), blob, str(stego))
    assert CODECS["zerowidth"].extract(str(stego)) == blob


def test_zerowidth_extract_clean_raises(tmp_path) -> None:
    p = tmp_path / "plain.txt"
    p.write_text("no hidden bits here", encoding="utf-8")
    with pytest.raises(NoPayloadError):
        CODECS["zerowidth"].extract(str(p))


# ---- PDF ----------------------------------------------------------------------

def test_pdf_roundtrip_pages_intact(tmp_path) -> None:
    from pypdf import PdfReader

    cover, stego = tmp_path / "c.pdf", tmp_path / "s.pdf"
    _make_pdf(str(cover))
    payload = os.urandom(128)
    stagy.hide(str(cover), payload, str(stego), codec="pdf", passphrase="pw")
    assert stagy.reveal(str(stego), codec="pdf", passphrase="pw").payload == payload
    assert len(PdfReader(str(stego)).pages) == 1  # renders the same page


def test_pdf_codec_bit_identical(tmp_path) -> None:
    cover, stego = tmp_path / "c.pdf", tmp_path / "s.pdf"
    _make_pdf(str(cover))
    blob = _container(os.urandom(100))
    CODECS["pdf"].embed(str(cover), blob, str(stego))
    assert CODECS["pdf"].extract(str(stego)) == blob


def test_pdf_extract_clean_raises(tmp_path) -> None:
    cover = tmp_path / "c.pdf"
    _make_pdf(str(cover))
    with pytest.raises(NoPayloadError):
        CODECS["pdf"].extract(str(cover))


# ---- DOCX ---------------------------------------------------------------------

def test_docx_roundtrip_parts_intact(tmp_path) -> None:
    cover, stego = tmp_path / "c.docx", tmp_path / "s.docx"
    _make_docx(str(cover))
    payload = os.urandom(96)
    stagy.hide(str(cover), payload, str(stego), codec="docx", passphrase="pw")
    assert stagy.reveal(str(stego), codec="docx", passphrase="pw").payload == payload
    # Every original part survives unchanged; only our extra part is added.
    with zipfile.ZipFile(cover) as a, zipfile.ZipFile(stego) as b:
        assert set(a.namelist()) < set(b.namelist())
        assert b.read("word/document.xml") == _DOC


def test_docx_codec_bit_identical(tmp_path) -> None:
    cover, stego = tmp_path / "c.docx", tmp_path / "s.docx"
    _make_docx(str(cover))
    blob = _container(os.urandom(80))
    CODECS["docx"].embed(str(cover), blob, str(stego))
    assert CODECS["docx"].extract(str(stego)) == blob


def test_docx_extract_clean_raises(tmp_path) -> None:
    cover = tmp_path / "c.docx"
    _make_docx(str(cover))
    with pytest.raises(NoPayloadError):
        CODECS["docx"].extract(str(cover))


def test_docx_reject_non_zip(tmp_path) -> None:
    plain = tmp_path / "not.docx"
    plain.write_text("plainly not a zip", encoding="utf-8")
    with pytest.raises(UnsupportedFormatError):
        CODECS["docx"].embed(str(plain), b"x", str(tmp_path / "o.docx"))
