"""Tests for the Stagy web API (roadmap Task 7.1).

Roadmap acceptance criteria under test:
  * OpenAPI docs render
  * embed -> download -> re-upload -> extract round-trips through the API
  * detect returns a valid report
  * oversized upload is rejected cleanly

Plus the security controls 7.1 mandates: no persistence, type whitelisting,
rate limiting, and the two container vulnerabilities that a public endpoint
would otherwise turn from local into remote.
"""

from __future__ import annotations

import base64

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient
from web.backend import limits
from web.backend.app import app

from stagy.analysis import corpus


@pytest.fixture(autouse=True)
def _clear_limits():
    limits.reset_rate_limits()
    yield
    limits.reset_rate_limits()


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def cover_png(tmp_path) -> bytes:
    p = tmp_path / "cover.png"
    corpus.synth_cover(str(p), seed=7)
    return p.read_bytes()


def test_openapi_and_health(client: TestClient) -> None:
    assert client.get("/openapi.json").status_code == 200
    body = client.get("/api/health").json()
    assert body["status"] == "ok"
    assert "image" in body["codecs"]


def test_capacity(client: TestClient, cover_png: bytes) -> None:
    r = client.post(
        "/api/capacity",
        files={"cover": ("c.png", cover_png, "image/png")},
        data={"bits": "1", "channels": "RGB"},
    )
    assert r.status_code == 200
    assert r.json()["capacity_bytes"] > 0


def test_full_roundtrip_through_the_api(client: TestClient, cover_png: bytes) -> None:
    """The headline acceptance criterion: embed -> download -> re-upload -> extract."""
    secret = b"blue team was here \x00\xff binary safe"

    r = client.post(
        "/api/embed",
        files={
            "cover": ("c.png", cover_png, "image/png"),
            "payload": ("secret.txt", secret, "text/plain"),
        },
        data={"passphrase": "correct horse", "encrypt": "true", "compress": "true"},
    )
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "image/png"
    stego = r.content

    r2 = client.post(
        "/api/extract",
        files={"stego": ("s.png", stego, "image/png")},
        data={"passphrase": "correct horse"},
    )
    assert r2.status_code == 200, r2.text
    out = r2.json()
    assert base64.b64decode(out["payload_b64"]) == secret
    assert out["filename"] == "secret.txt"
    assert out["was_encrypted"] is True


def test_wrong_passphrase_is_403(client: TestClient, cover_png: bytes) -> None:
    r = client.post(
        "/api/embed",
        files={"cover": ("c.png", cover_png, "image/png"),
               "payload": ("p.bin", b"x" * 64, "application/octet-stream")},
        data={"passphrase": "right"},
    )
    r2 = client.post(
        "/api/extract",
        files={"stego": ("s.png", r.content, "image/png")},
        data={"passphrase": "wrong"},
    )
    assert r2.status_code in (403, 404)


def test_detect_returns_a_valid_report(client: TestClient, cover_png: bytes) -> None:
    r = client.post(
        "/api/detect",
        files={"suspect": ("s.png", cover_png, "image/png")},
        data={"include_bitplane": "true"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["verdict"] in ("clean", "suspicious", "likely-stego")
    assert 0.0 <= body["probability"] <= 1.0
    assert {s["name"] for s in body["signals"]} >= {"chi-square", "rs-analysis"}
    # The bit-plane must be a real PNG the frontend can put in an <img>.
    assert base64.b64decode(body["bitplane_png_b64"]).startswith(b"\x89PNG\r\n\x1a\n")


def test_detect_flags_a_stego_file(client: TestClient, cover_png: bytes) -> None:
    embed = client.post(
        "/api/embed",
        files={"cover": ("c.png", cover_png, "image/png"),
               "payload": ("p.bin", b"S" * 20000, "application/octet-stream")},
        data={"passphrase": "pw"},
    )
    r = client.post(
        "/api/detect",
        files={"suspect": ("s.png", embed.content, "image/png")},
    )
    assert r.json()["verdict"] != "clean"


def _stego_bytes(cover_png: bytes, tmp_path) -> bytes:
    import stagy

    cover = tmp_path / "c.png"
    cover.write_bytes(cover_png)
    out = tmp_path / "s.png"
    stagy.hide(str(cover), b"S" * 20000, str(out), encrypt=False, mode="sequential")
    return out.read_bytes()


def test_detect_batch_ranks_and_flags(client: TestClient, cover_png: bytes, tmp_path) -> None:
    stego = _stego_bytes(cover_png, tmp_path)
    r = client.post("/api/detect-batch", files=[
        ("files", ("clean.png", cover_png, "image/png")),
        ("files", ("stego.png", stego, "image/png")),
    ])
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["scanned"] == 2 and body["flagged"] >= 1
    # Ranked most-suspicious first: the stego must lead.
    assert body["items"][0]["filename"] == "stego.png"
    assert body["items"][0]["verdict"] != "clean"


def test_detect_batch_unsupported_is_error_row_not_415(
    client: TestClient, cover_png: bytes
) -> None:
    jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF" + b"\0" * 128
    r = client.post("/api/detect-batch", files=[
        ("files", ("ok.png", cover_png, "image/png")),
        ("files", ("bad.jpg", jpeg, "image/jpeg")),
    ])
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["errors"] == 1
    bad = next(it for it in body["items"] if it["filename"] == "bad.jpg")
    assert bad["verdict"] == "error"


def test_detect_batch_too_many_files_413(client: TestClient, cover_png: bytes) -> None:
    files = [("files", (f"{i}.png", cover_png, "image/png"))
             for i in range(limits.MAX_BATCH_FILES + 1)]
    r = client.post("/api/detect-batch", files=files)
    assert r.status_code == 413


def test_detect_batch_requires_files(client: TestClient) -> None:
    r = client.post("/api/detect-batch")
    assert r.status_code in (400, 422)


class TestSecurityControls:
    def test_oversized_upload_rejected_cleanly(self, client: TestClient) -> None:
        big = b"\x89PNG\r\n\x1a\n" + b"\0" * (limits.MAX_UPLOAD_BYTES + 1024)
        r = client.post("/api/capacity", files={"cover": ("big.png", big, "image/png")})
        assert r.status_code == 413
        assert "limit" in r.json()["detail"].lower()

    def test_non_image_rejected_by_magic_not_extension(self, client: TestClient) -> None:
        """A .png extension on a non-PNG must not get through."""
        r = client.post(
            "/api/capacity",
            files={"cover": ("lies.png", b"MZ\x90\x00 this is a PE", "image/png")},
        )
        assert r.status_code == 415

    def test_jpeg_refused_rather_than_silently_corrupted(self, client: TestClient) -> None:
        jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF" + b"\0" * 128
        r = client.post("/api/capacity", files={"cover": ("x.jpg", jpeg, "image/jpeg")})
        assert r.status_code == 415

    def test_empty_upload_rejected(self, client: TestClient) -> None:
        r = client.post("/api/capacity", files={"cover": ("e.png", b"", "image/png")})
        assert r.status_code == 400

    def test_rate_limit_enforced(self, client: TestClient, cover_png: bytes) -> None:
        limits.reset_rate_limits()
        codes = [
            client.post(
                "/api/capacity", files={"cover": ("c.png", cover_png, "image/png")}
            ).status_code
            for _ in range(limits.RATE_LIMIT_REQUESTS + 3)
        ]
        assert 429 in codes, "rate limiter never engaged"

    def test_uploads_are_not_persisted(self, client: TestClient, cover_png: bytes,
                                       monkeypatch, tmp_path) -> None:
        """No request may leave a file behind in the temp dir."""
        scratch = tmp_path / "tmp"
        scratch.mkdir()
        monkeypatch.setenv("TMPDIR", str(scratch))
        import tempfile

        monkeypatch.setattr(tempfile, "tempdir", str(scratch))

        client.post("/api/detect", files={"suspect": ("s.png", cover_png, "image/png")})
        leftovers = [p for p in scratch.rglob("*") if p.is_file()]
        assert leftovers == [], f"request left files behind: {leftovers}"

    def test_traversal_filename_is_defanged_over_http(
        self, client: TestClient, cover_png: bytes
    ) -> None:
        """The arbitrary-write PoC, replayed through the API.

        A client uploading a payload named "../../../../etc/cron.d/pwn" must get
        back a bare basename, never a path a naive frontend would write through.
        """
        r = client.post(
            "/api/embed",
            files={"cover": ("c.png", cover_png, "image/png"),
                   "payload": ("../../../../etc/cron.d/pwn", b"owned", "text/plain")},
            data={"passphrase": "pw"},
        )
        assert r.status_code == 200
        out = client.post(
            "/api/extract",
            files={"stego": ("s.png", r.content, "image/png")},
            data={"passphrase": "pw"},
        ).json()
        assert "/" not in out["filename"] and ".." not in out["filename"]

    def test_decompression_bomb_refused_over_http(
        self, client: TestClient, cover_png: bytes, tmp_path
    ) -> None:
        """A bomb embedded by an attacker must not OOM the server."""
        import stagy

        # Needs a cover roomy enough to carry the compressed bomb (~65 KB).
        cover = tmp_path / "big.png"
        corpus.synth_cover(str(cover), width=1024, height=1024, seed=2)
        evil = tmp_path / "evil.png"
        # 64 MB of zeros compresses to ~65 KB but blows the API's 32 MB ceiling.
        stagy.hide(str(cover), b"\0" * (64 * 1024 * 1024), str(evil),
                   encrypt=False, compress=True, mode="sequential")

        r = client.post(
            "/api/extract",
            files={"stego": ("s.png", evil.read_bytes(), "image/png")},
            data={"mode": "sequential"},
        )
        assert r.status_code == 422
        assert "bomb" in r.json()["detail"].lower()

    def test_network_endpoints_are_absent(self, client: TestClient) -> None:
        """Raw packet crafting must never be exposed over HTTP."""
        paths = client.get("/openapi.json").json()["paths"]
        assert not any("net" in p for p in paths), paths.keys()


def test_capacity_error_maps_to_422(client: TestClient, cover_png: bytes) -> None:
    cap = client.post(
        "/api/capacity", files={"cover": ("c.png", cover_png, "image/png")}
    ).json()["capacity_bytes"]
    r = client.post(
        "/api/embed",
        files={"cover": ("c.png", cover_png, "image/png"),
               "payload": ("p.bin", b"x" * (cap + 5000), "application/octet-stream")},
        data={"passphrase": "pw"},
    )
    assert r.status_code == 422
    assert "cover holds" in r.json()["detail"]


def test_clean_file_extract_is_404(client: TestClient, cover_png: bytes) -> None:
    r = client.post(
        "/api/extract",
        files={"stego": ("s.png", cover_png, "image/png")},
        data={"passphrase": "pw"},
    )
    assert r.status_code == 404
