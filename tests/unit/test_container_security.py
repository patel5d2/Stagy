"""Security regression tests for the container decode path.

Both bugs below were confirmed exploitable with working PoCs against the CLI
before the fix. Neither needs a passphrase: an unencrypted container is
readable by anyone, and the CRC32 is not a MAC, so an attacker recomputes it
freely. These tests exist so the fixes cannot silently regress.
"""

import zlib

import pytest

import stagy
from stagy import container
from stagy.analysis import corpus
from stagy.errors import IntegrityError


def _raw_container(flags: int, body: bytes, filename: bytes = b"") -> bytes:
    """Hand-build a container the way an attacker would, CRC included."""
    blob = bytearray(b"STGY" + bytes([1, flags, 0, 0]))
    if filename:
        blob += len(filename).to_bytes(2, "big") + filename
    blob += len(body).to_bytes(4, "big") + body
    blob += (zlib.crc32(bytes(blob)) & 0xFFFFFFFF).to_bytes(4, "big")
    return bytes(blob)


class TestPathTraversal:
    """Container filenames are attacker-controlled and must never be paths.

    PoC before the fix: embedding filename="../PWNED.txt" and running
    `stagy image extract -i evil.png --mode sequential` (no -o) wrote
    "../PWNED.txt" outside the analyst's working directory.
    """

    @pytest.mark.parametrize(
        "hostile",
        [
            "../PWNED.txt",
            "../../../../etc/cron.d/pwn",
            "/etc/passwd",
            "..\\..\\windows\\system32\\evil.dll",  # Windows separators
            "subdir/nested.txt",
        ],
    )
    def test_traversal_is_reduced_to_basename(self, hostile: str) -> None:
        safe = container.safe_filename(hostile)
        assert "/" not in safe and "\\" not in safe
        assert not safe.startswith("..")

    @pytest.mark.parametrize("bad", ["", ".", "..", "/", "\x00"])
    def test_unusable_names_are_rejected(self, bad: str) -> None:
        with pytest.raises(IntegrityError):
            container.safe_filename(bad)

    def test_decode_sanitizes_end_to_end(self) -> None:
        blob = _raw_container(0b100, b"payload", filename=b"../PWNED.txt")
        assert container.decode(blob).filename == "PWNED.txt"

    def test_cli_extract_cannot_escape_cwd(self, tmp_path, monkeypatch) -> None:
        """The full exploit path, end to end."""
        cover = tmp_path / "cover.png"
        corpus.synth_cover(str(cover), seed=1)
        evil = tmp_path / "evil.png"
        stagy.hide(cover.as_posix(), b"owned", evil.as_posix(),
                   encrypt=False, mode="sequential", filename="../PWNED.txt")

        workdir = tmp_path / "analyst"
        workdir.mkdir()
        monkeypatch.chdir(workdir)

        result = stagy.reveal(evil.as_posix(), mode="sequential")
        assert result.filename == "PWNED.txt"  # de-fanged

        # Writing to the returned name stays inside the analyst's directory.
        from pathlib import Path

        Path(result.filename).write_bytes(result.payload)
        assert (workdir / "PWNED.txt").exists()
        assert not (tmp_path / "PWNED.txt").exists()


class TestDecompressionBomb:
    """Measured 1,028x amplification: 400 KB of container -> 400 MB of output."""

    def test_bomb_is_refused(self) -> None:
        bomb = zlib.compress(b"\0" * (8 * 1024 * 1024), 9)
        blob = _raw_container(0b010, bomb)
        with pytest.raises(IntegrityError, match="decompression bomb"):
            container.decode(blob, max_decompressed=1024 * 1024)

    def test_legitimate_compression_still_works(self) -> None:
        body = b"real payload " * 100
        blob = _raw_container(0b010, zlib.compress(body))
        assert container.decode(blob).payload == body

    def test_default_ceiling_is_enforced(self) -> None:
        assert container.MAX_DECOMPRESSED == 256 * 1024 * 1024

    def test_corrupt_compressed_body_raises_stagy_error(self) -> None:
        blob = _raw_container(0b010, b"not really zlib data")
        with pytest.raises(IntegrityError):
            container.decode(blob)


def test_encrypted_without_passphrase_raises_stagy_error() -> None:
    """Was a bare ValueError, which escaped the CLI's StagyError handler."""
    from stagy.errors import StagyError

    cover_blob = _raw_container(0b001, b"x" * 40)
    with pytest.raises(StagyError):
        container.decode(cover_blob)
