"""Bulk directory scan: `report.analyze_many` + `stagy detect -i <dir>`."""

import json
import os

from typer.testing import CliRunner

import stagy
from stagy.analysis import corpus, report
from stagy.cli.main import app

runner = CliRunner()


def _tree(root) -> None:
    """A clean cover, a loud (sequential) stego, a non-image, and a bad image."""
    clean = root / "clean.png"
    corpus.synth_cover(str(clean), seed=7)
    stego = root / "stego.png"
    stagy.hide(str(clean), os.urandom(9000), str(stego), encrypt=False, mode="sequential")
    (root / "notes.txt").write_text("just some text", encoding="utf-8")
    (root / "broken.png").write_bytes(b"\x89PNG\r\n\x1a\n not really a png")


def test_analyze_many_ranks_stego_above_clean(tmp_path) -> None:
    _tree(tmp_path)
    paths = [str(p) for p in sorted(tmp_path.iterdir())]
    reports = report.analyze_many(paths)

    # Ranked most-suspicious first, so the stego must outrank its own clean cover
    # regardless of whether a fitted calibration ships.
    by_name = {os.path.basename(r.path): r for r in reports}
    assert by_name["stego.png"].probability > by_name["clean.png"].probability
    order = [os.path.basename(r.path) for r in reports]
    assert order.index("stego.png") < order.index("clean.png")


def test_analyze_many_surfaces_unreadable_file(tmp_path) -> None:
    _tree(tmp_path)
    reports = report.analyze_many([str(p) for p in sorted(tmp_path.iterdir())])
    broken = next(r for r in reports if os.path.basename(r.path) == "broken.png")
    assert broken.verdict == "error"  # surfaced, not raised, not silently dropped


def test_detect_cli_directory_text(tmp_path) -> None:
    _tree(tmp_path)
    r = runner.invoke(app, ["detect", "-i", str(tmp_path)])
    assert r.exit_code == 0, r.output
    assert "scanned" in r.output


def test_detect_cli_directory_json_is_an_array(tmp_path) -> None:
    _tree(tmp_path)
    r = runner.invoke(app, ["detect", "-i", str(tmp_path), "--report", "json"])
    assert r.exit_code == 0, r.output
    rows = json.loads(r.output)
    assert isinstance(rows, list) and len(rows) == 4
    assert {"path", "verdict", "probability"} <= rows[0].keys()


def test_detect_reference_rejected_for_directory(tmp_path) -> None:
    _tree(tmp_path)
    ref = tmp_path / "clean.png"
    r = runner.invoke(app, ["detect", "-i", str(tmp_path), "--reference", str(ref)])
    assert r.exit_code == 1  # --reference is a single-file comparison


def test_fail_on_flag_exit_code(tmp_path) -> None:
    _tree(tmp_path)  # contains a loud stego -> something is flagged
    hit = runner.invoke(app, ["detect", "-i", str(tmp_path), "--fail-on-flag"])
    assert hit.exit_code == 2, hit.output

    clean_dir = tmp_path / "clean_only"
    clean_dir.mkdir()
    corpus.synth_cover(str(clean_dir / "a.png"), seed=1)
    ok = runner.invoke(app, ["detect", "-i", str(clean_dir), "--fail-on-flag"])
    assert ok.exit_code == 0, ok.output
