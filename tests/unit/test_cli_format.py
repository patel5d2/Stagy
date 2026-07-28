"""Guards the verdict/probability display bug: a positive posterior must never
render as 0.0%, so the verdict label can never contradict its own number."""

from stagy.analysis import report
from stagy.cli.main import _fmt_prob


def test_positive_prob_never_reads_zero() -> None:
    # The fitted 'suspicious' operating point (~3.4e-5) once rendered as "0.0%".
    for p in (3.4e-5, 1.6e-4, 5e-4, 9e-4):
        assert _fmt_prob(p) not in ("0.0%", "0%")


def test_normal_range_formatting() -> None:
    assert _fmt_prob(0.406) == "40.6%"
    assert _fmt_prob(1.0) == "100.0%"
    assert _fmt_prob(0.0) == "0%"
    assert _fmt_prob(0.005) == "0.5%"


def test_report_exposes_flag_threshold(tmp_path) -> None:
    # analyze() must populate the threshold the CLI shows next to a verdict.
    from stagy.analysis import corpus

    p = tmp_path / "clean.png"
    corpus.synth_cover(str(p), seed=1)
    rep = report.analyze(str(p))
    assert rep.flag_threshold > 0.0
