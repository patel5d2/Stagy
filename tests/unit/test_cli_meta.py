"""CLI wiring tests for the `stagy meta` group (roadmap Task 4.4)."""

import numpy as np
from PIL import Image
from typer.testing import CliRunner

import stagy
from stagy.cli.main import app

runner = CliRunner()


def test_meta_embed_extract_roundtrip(tmp_path) -> None:
    cover = tmp_path / "c.txt"
    cover.write_text("ordinary carrier text " * 20, encoding="utf-8")
    secret = tmp_path / "s.bin"
    secret.write_bytes(b"top secret")
    stego = tmp_path / "o.txt"
    rec = tmp_path / "r.bin"

    r = runner.invoke(app, ["meta", "embed", "-c", str(cover), "-p", str(secret),
                            "-o", str(stego), "--technique", "zerowidth", "--key", "pw"])
    assert r.exit_code == 0, r.output
    r = runner.invoke(app, ["meta", "extract", "-i", str(stego), "-o", str(rec),
                            "--technique", "zerowidth", "--key", "pw"])
    assert r.exit_code == 0, r.output
    assert rec.read_bytes() == b"top secret"


def test_meta_extract_wrong_key_exits_nonzero(tmp_path) -> None:
    cover = tmp_path / "c.txt"
    cover.write_text("carrier " * 40, encoding="utf-8")
    secret = tmp_path / "s.bin"
    secret.write_bytes(b"data")
    stego = tmp_path / "o.txt"
    runner.invoke(app, ["meta", "embed", "-c", str(cover), "-p", str(secret),
                        "-o", str(stego), "--technique", "zerowidth", "--key", "right"])
    r = runner.invoke(app, ["meta", "extract", "-i", str(stego),
                            "--technique", "zerowidth", "--key", "wrong"])
    assert r.exit_code == 1


def test_meta_scan_surfaces_hidden_exif(tmp_path) -> None:
    cover = tmp_path / "c.jpg"
    Image.fromarray(np.zeros((32, 32, 3), dtype=np.uint8), "RGB").save(cover, "JPEG")
    stego = tmp_path / "s.jpg"
    stagy.hide(str(cover), b"hidden in exif", str(stego), codec="exif", passphrase="pw")

    r = runner.invoke(app, ["meta", "scan", "-i", str(stego)])
    assert r.exit_code == 0, r.output
    assert "UserComment" in r.output
