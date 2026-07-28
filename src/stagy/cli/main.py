"""Stagy CLI (Typer). Image embed/extract/capacity + detect. More groups per phase."""

from __future__ import annotations

import json
import os
import sys
from enum import Enum
from pathlib import Path
from typing import NoReturn

import typer
from rich.console import Console
from rich.table import Table

from .. import __version__, _seal, hide, reveal
from ..analysis import report as report_mod
from ..analysis.evaluate import DEFAULT_PRIOR
from ..codecs import CODECS
from ..codecs.metadata import metadata_scan
from ..errors import StagyError


class Technique(str, Enum):
    """Metadata / document hiding techniques (each maps to a codec name)."""

    appended = "appended"
    exif = "exif"
    zerowidth = "zerowidth"
    pdf = "pdf"
    docx = "docx"

_VERDICT_STYLE = {"clean": "green", "suspicious": "yellow", "likely-stego": "bold red",
                  "error": "dim"}


def _fmt_prob(p: float) -> str:
    """Format a posterior as a percentage that never rounds a positive to 0.0%.

    The fitted operating thresholds sit far below 0.1%, so a fixed .1% display
    would show 'suspicious ... 0.0%' — the verdict contradicting its own number.
    Two significant figures below 1% keeps any non-zero posterior legible.
    """
    if p <= 0.0:
        return "0%"
    pct = p * 100.0
    return f"{pct:.1f}%" if pct >= 1.0 else f"{pct:.2g}%"

# add_completion=True exposes --install-completion / --show-completion (bash, zsh,
# fish, powershell) via typer's shellingham backend — no new dependency.
app = typer.Typer(add_completion=True, help="Stagy — hide, extract, and detect hidden data.")
image_app = typer.Typer(help="Image LSB (PNG/BMP) embed/extract/capacity.")
app.add_typer(image_app, name="image")
audio_app = typer.Typer(help="Audio (16-bit PCM WAV) LSB + spread-spectrum.")
app.add_typer(audio_app, name="audio")
jpeg_app = typer.Typer(help="JPEG DCT (JSteg) embed/extract/capacity.")
app.add_typer(jpeg_app, name="jpeg")
meta_app = typer.Typer(help="Metadata/document embed/extract + metadata scan.")
app.add_typer(meta_app, name="meta")
net_app = typer.Typer(help="Network covert channel (LAB ONLY — see 'stagy net').")
app.add_typer(net_app, name="net")

console = Console()
err = Console(stderr=True)


def _resolve_key(key: str | None, *, needed: bool) -> str | None:
    if key:
        return key
    env = os.environ.get("STAGY_KEY")
    if env:
        return env
    if needed:
        return str(typer.prompt("Passphrase", hide_input=True))
    return None


def _fail(msg: str) -> NoReturn:
    err.print(f"[red]error:[/red] {msg}")
    raise typer.Exit(code=1)


@app.command()
def version() -> None:
    """Print version."""
    console.print(f"stagy {__version__}")


@image_app.command("capacity")
def image_capacity(
    cover: Path = typer.Option(..., "-c", "--cover", exists=True, dir_okay=False),
    bits: int = typer.Option(1, "--bits", min=1, max=4),
    channels: str = typer.Option("RGB", "--channels"),
) -> None:
    """Max payload bytes this cover can hold."""
    try:
        n = CODECS["image"].capacity(str(cover), bits=bits, channels=channels)
    except StagyError as e:
        _fail(str(e))
    table = Table(show_header=False)
    table.add_row("cover", str(cover))
    table.add_row("bits/channel", str(bits))
    table.add_row("channels", channels)
    table.add_row("capacity", f"{n:,} bytes")
    console.print(table)


@image_app.command("embed")
def image_embed(
    cover: Path = typer.Option(..., "-c", "--cover", exists=True, dir_okay=False),
    payload: Path = typer.Option(..., "-p", "--payload", exists=True, dir_okay=False),
    out: Path = typer.Option(..., "-o", "--out", dir_okay=False),
    key: str | None = typer.Option(None, "--key"),
    bits: int = typer.Option(1, "--bits", min=1, max=4),
    channels: str = typer.Option("RGB", "--channels"),
    mode: str = typer.Option("keyed", "--mode"),
    encrypt: bool = typer.Option(True, "--encrypt/--no-encrypt"),
    compress: bool = typer.Option(False, "--compress"),
) -> None:
    """Embed PAYLOAD into COVER, write stego image to OUT."""
    passphrase = _resolve_key(key, needed=encrypt or mode == "keyed")
    data = payload.read_bytes()
    try:
        hide(
            str(cover),
            data,
            str(out),
            codec="image",
            passphrase=passphrase,
            encrypt=encrypt,
            compress=compress,
            filename=payload.name,
            bits=bits,
            channels=channels,
            mode=mode,
        )
    except StagyError as e:
        _fail(str(e))
    console.print(f"[green]embedded[/green] {len(data):,} bytes → {out}")


@image_app.command("extract")
def image_extract(
    stego: Path = typer.Option(..., "-i", "--in", exists=True, dir_okay=False),
    out: Path | None = typer.Option(None, "-o", "--out", dir_okay=False),
    key: str | None = typer.Option(None, "--key"),
    bits: int = typer.Option(1, "--bits", min=1, max=4),
    channels: str = typer.Option("RGB", "--channels"),
    mode: str = typer.Option("keyed", "--mode"),
    stdout: bool = typer.Option(False, "--stdout", help="Write recovered bytes to stdout."),
) -> None:
    """Extract a hidden payload from STEGO."""
    passphrase = _resolve_key(key, needed=mode == "keyed")
    try:
        result = reveal(
            str(stego),
            codec="image",
            passphrase=passphrase,
            bits=bits,
            channels=channels,
            mode=mode,
        )
    except StagyError as e:
        _fail(str(e))
    dest = out or (Path(result.filename) if result.filename else None)
    if stdout or dest is None:
        sys.stdout.buffer.write(result.payload)
        return
    dest.write_bytes(result.payload)
    console.print(f"[green]extracted[/green] {len(result.payload):,} bytes → {dest}")


@audio_app.command("capacity")
def audio_capacity(
    cover: Path = typer.Option(..., "-c", "--cover", exists=True, dir_okay=False),
    bits: int = typer.Option(1, "--bits", min=1, max=4),
    method: str = typer.Option("lsb", "--method", help="lsb (high capacity) or spread (robust)."),
    chip_len: int = typer.Option(1024, "--chip-len", help="Samples per bit (spread only)."),
) -> None:
    """Max payload bytes this WAV can hold."""
    try:
        if method == "spread":
            n = CODECS["audiospread"].capacity(str(cover), chip_len=chip_len)
        else:
            n = CODECS["audio"].capacity(str(cover), bits=bits)
    except StagyError as e:
        _fail(str(e))
    table = Table(show_header=False)
    table.add_row("cover", str(cover))
    table.add_row("method", method)
    table.add_row("bits/sample" if method == "lsb" else "samples/bit",
                  str(bits) if method == "lsb" else str(chip_len))
    table.add_row("capacity", f"{n:,} bytes")
    console.print(table)


@audio_app.command("embed")
def audio_embed(
    cover: Path = typer.Option(..., "-c", "--cover", exists=True, dir_okay=False),
    payload: Path = typer.Option(..., "-p", "--payload", exists=True, dir_okay=False),
    out: Path = typer.Option(..., "-o", "--out", dir_okay=False),
    key: str | None = typer.Option(None, "--key"),
    method: str = typer.Option("lsb", "--method", help="lsb (high capacity) or spread (robust)."),
    bits: int = typer.Option(1, "--bits", min=1, max=4),
    mode: str = typer.Option("keyed", "--mode"),
    chip_len: int = typer.Option(1024, "--chip-len", help="Samples per bit (spread only)."),
    gain: float = typer.Option(600.0, "--gain", help="Chip amplitude (spread only)."),
    encrypt: bool = typer.Option(True, "--encrypt/--no-encrypt"),
    compress: bool = typer.Option(False, "--compress"),
) -> None:
    """Embed PAYLOAD into a WAV COVER, write stego WAV to OUT."""
    data = payload.read_bytes()
    try:
        if method == "spread":
            # Spread spectrum is keyed-only: the chip sequence is the secret.
            passphrase = _resolve_key(key, needed=True)
            hide(str(cover), data, str(out), codec="audiospread", passphrase=passphrase,
                 encrypt=encrypt, compress=compress, filename=payload.name,
                 chip_len=chip_len, gain=gain)
        else:
            passphrase = _resolve_key(key, needed=encrypt or mode == "keyed")
            hide(str(cover), data, str(out), codec="audio", passphrase=passphrase,
                 encrypt=encrypt, compress=compress, filename=payload.name, bits=bits, mode=mode)
    except StagyError as e:
        _fail(str(e))
    console.print(f"[green]embedded[/green] {len(data):,} bytes ({method}) → {out}")


@audio_app.command("extract")
def audio_extract(
    stego: Path = typer.Option(..., "-i", "--in", exists=True, dir_okay=False),
    out: Path | None = typer.Option(None, "-o", "--out", dir_okay=False),
    key: str | None = typer.Option(None, "--key"),
    method: str = typer.Option("lsb", "--method", help="lsb or spread (must match embed)."),
    bits: int = typer.Option(1, "--bits", min=1, max=4),
    mode: str = typer.Option("keyed", "--mode"),
    chip_len: int = typer.Option(1024, "--chip-len", help="Samples per bit (spread only)."),
    stdout: bool = typer.Option(False, "--stdout", help="Write recovered bytes to stdout."),
) -> None:
    """Extract a hidden payload from a WAV."""
    try:
        if method == "spread":
            passphrase = _resolve_key(key, needed=True)
            result = reveal(str(stego), codec="audiospread", passphrase=passphrase, chip_len=chip_len)
        else:
            passphrase = _resolve_key(key, needed=mode == "keyed")
            result = reveal(str(stego), codec="audio", passphrase=passphrase, bits=bits, mode=mode)
    except StagyError as e:
        _fail(str(e))
    dest = out or (Path(result.filename) if result.filename else None)
    if stdout or dest is None:
        sys.stdout.buffer.write(result.payload)
        return
    dest.write_bytes(result.payload)
    console.print(f"[green]extracted[/green] {len(result.payload):,} bytes → {dest}")


# --------------------------------------------------------------------------- #
# JPEG DCT (JSteg). Registered only when jpeglib is installed.
# --------------------------------------------------------------------------- #

def _require_jpeg() -> None:
    if "jpeg" not in CODECS:
        _fail("JPEG codec unavailable — install the extra: pip install 'stagy[jpeg]'")


@jpeg_app.command("capacity")
def jpeg_capacity(
    cover: Path = typer.Option(..., "-c", "--cover", exists=True, dir_okay=False),
) -> None:
    """Max payload bytes this JPEG can carry in its DCT coefficients."""
    _require_jpeg()
    try:
        n = CODECS["jpeg"].capacity(str(cover), mode="sequential")
    except StagyError as e:
        _fail(str(e))
    table = Table(show_header=False)
    table.add_row("cover", str(cover))
    table.add_row("capacity", f"{n:,} bytes")
    console.print(table)


@jpeg_app.command("embed")
def jpeg_embed(
    cover: Path = typer.Option(..., "-c", "--cover", exists=True, dir_okay=False),
    payload: Path = typer.Option(..., "-p", "--payload", exists=True, dir_okay=False),
    out: Path = typer.Option(..., "-o", "--out", dir_okay=False),
    key: str | None = typer.Option(None, "--key"),
    mode: str = typer.Option("keyed", "--mode"),
    encrypt: bool = typer.Option(True, "--encrypt/--no-encrypt"),
    compress: bool = typer.Option(False, "--compress"),
) -> None:
    """Embed PAYLOAD into a JPEG COVER's DCT coefficients, write to OUT (.jpg)."""
    _require_jpeg()
    passphrase = _resolve_key(key, needed=encrypt or mode == "keyed")
    data = payload.read_bytes()
    try:
        hide(str(cover), data, str(out), codec="jpeg", passphrase=passphrase,
             encrypt=encrypt, compress=compress, filename=payload.name, mode=mode)
    except StagyError as e:
        _fail(str(e))
    console.print(f"[green]embedded[/green] {len(data):,} bytes → {out}")
    console.print("[yellow]note:[/yellow] survives copying, not re-encoding (a re-save wipes it)")


@jpeg_app.command("extract")
def jpeg_extract(
    stego: Path = typer.Option(..., "-i", "--in", exists=True, dir_okay=False),
    out: Path | None = typer.Option(None, "-o", "--out", dir_okay=False),
    key: str | None = typer.Option(None, "--key"),
    mode: str = typer.Option("keyed", "--mode"),
    stdout: bool = typer.Option(False, "--stdout", help="Write recovered bytes to stdout."),
) -> None:
    """Extract a hidden payload from a JPEG."""
    _require_jpeg()
    passphrase = _resolve_key(key, needed=mode == "keyed")
    try:
        result = reveal(str(stego), codec="jpeg", passphrase=passphrase, mode=mode)
    except StagyError as e:
        _fail(str(e))
    dest = out or (Path(result.filename) if result.filename else None)
    if stdout or dest is None:
        sys.stdout.buffer.write(result.payload)
        return
    dest.write_bytes(result.payload)
    console.print(f"[green]extracted[/green] {len(result.payload):,} bytes → {dest}")


# --------------------------------------------------------------------------- #
# Network covert channel. LAB ONLY.
# --------------------------------------------------------------------------- #

_NET_BANNER = (
    "[bold red]LAB USE ONLY.[/bold red] Crafting raw packets needs root and a "
    "receiver you control. NAT/firewalls rewrite these fields, so run this only "
    "on a flat lab network (two VMs on one bridge, a veth pair, or loopback). "
    "Never point it at a host you do not own."
)


@net_app.command("send")
def net_send(
    payload: Path = typer.Option(..., "-p", "--payload", exists=True, dir_okay=False),
    dst: str = typer.Option(..., "--dst", help="Destination IP (a host you control)."),
    field: str = typer.Option("ip_id", "--field", help="Carrier field: ip_id | tcp_seq."),
    key: str | None = typer.Option(None, "--key"),
    iface: str | None = typer.Option(None, "--iface"),
    inter: float = typer.Option(0.0, "--inter", help="Seconds between packets."),
    encrypt: bool = typer.Option(True, "--encrypt/--no-encrypt"),
    compress: bool = typer.Option(False, "--compress"),
) -> None:
    """Transmit PAYLOAD over a header-field covert channel."""
    from ..codecs import network as net
    from ..crypto import derive_prng_seed

    err.print(_NET_BANNER)
    passphrase = _resolve_key(key, needed=encrypt)
    seed = derive_prng_seed(passphrase) if passphrase else None
    try:
        blob = _seal(payload.read_bytes(), passphrase=passphrase, encrypt=encrypt,
                     compress=compress, filename=payload.name)
        sent = net.send_covert(blob, dst, field=field, iface=iface, seed=seed, inter=inter)
    except StagyError as e:
        _fail(str(e))
    console.print(f"[green]sent[/green] {sent} packets to {dst} via {field}")
    console.print(f"[dim]receiver: stagy net recv --count {sent} --field {field}[/dim]")


@net_app.command("recv")
def net_recv(
    count: int = typer.Option(..., "--count", help="Number of packets to sniff (from sender)."),
    out: Path | None = typer.Option(None, "-o", "--out", dir_okay=False),
    field: str = typer.Option("ip_id", "--field", help="Carrier field: ip_id | tcp_seq."),
    key: str | None = typer.Option(None, "--key"),
    iface: str | None = typer.Option(None, "--iface"),
    timeout: float | None = typer.Option(None, "--timeout", help="Seconds to wait."),
    stdout: bool = typer.Option(False, "--stdout"),
) -> None:
    """Sniff COUNT covert packets and reassemble the payload."""
    from .. import container as container_mod
    from ..codecs import network as net
    from ..crypto import derive_prng_seed

    err.print(_NET_BANNER)
    passphrase = _resolve_key(key, needed=False)
    seed = derive_prng_seed(passphrase) if passphrase else None
    try:
        blob = net.recv_covert(count=count, field=field, iface=iface, seed=seed, timeout=timeout)
        result = container_mod.decode(blob, passphrase=passphrase)
    except StagyError as e:
        _fail(str(e))
    dest = out or (Path(result.filename) if result.filename else None)
    if stdout or dest is None:
        sys.stdout.buffer.write(result.payload)
        return
    dest.write_bytes(result.payload)
    console.print(f"[green]received[/green] {len(result.payload):,} bytes → {dest}")


@meta_app.command("embed")
def meta_embed(
    cover: Path = typer.Option(..., "-c", "--cover", exists=True, dir_okay=False),
    payload: Path = typer.Option(..., "-p", "--payload", exists=True, dir_okay=False),
    out: Path = typer.Option(..., "-o", "--out", dir_okay=False),
    technique: Technique = typer.Option(..., "--technique", help="appended|exif|zerowidth|pdf|docx"),
    key: str | None = typer.Option(None, "--key"),
    encrypt: bool = typer.Option(True, "--encrypt/--no-encrypt"),
    compress: bool = typer.Option(False, "--compress"),
) -> None:
    """Embed PAYLOAD into COVER using a metadata/document technique."""
    passphrase = _resolve_key(key, needed=encrypt)
    data = payload.read_bytes()
    try:
        hide(
            str(cover), data, str(out),
            codec=technique.value, passphrase=passphrase,
            encrypt=encrypt, compress=compress, filename=payload.name,
        )
    except StagyError as e:
        _fail(str(e))
    console.print(f"[green]embedded[/green] {len(data):,} bytes via {technique.value} → {out}")


@meta_app.command("extract")
def meta_extract(
    stego: Path = typer.Option(..., "-i", "--in", exists=True, dir_okay=False),
    technique: Technique = typer.Option(..., "--technique", help="appended|exif|zerowidth|pdf|docx"),
    out: Path | None = typer.Option(None, "-o", "--out", dir_okay=False),
    key: str | None = typer.Option(None, "--key"),
    stdout: bool = typer.Option(False, "--stdout", help="Write recovered bytes to stdout."),
) -> None:
    """Extract a hidden payload embedded with a metadata/document technique."""
    passphrase = _resolve_key(key, needed=True)
    try:
        result = reveal(str(stego), codec=technique.value, passphrase=passphrase)
    except StagyError as e:
        _fail(str(e))
    dest = out or (Path(result.filename) if result.filename else None)
    if stdout or dest is None:
        sys.stdout.buffer.write(result.payload)
        return
    dest.write_bytes(result.payload)
    console.print(f"[green]extracted[/green] {len(result.payload):,} bytes → {dest}")


@meta_app.command("scan")
def meta_scan(
    file: Path = typer.Option(..., "-i", "--in", exists=True, dir_okay=False),
) -> None:
    """Dump all EXIF/XMP metadata for a file (the tell a hidden payload leaves)."""
    data = metadata_scan(str(file))
    exif = data.get("exif", {})
    if not exif and not data.get("xmp"):
        console.print("[dim]no EXIF/XMP metadata found (or piexif not installed)[/dim]")
        return
    table = Table("IFD", "tag", "value", title=f"metadata: {file.name}")
    for ifd, entries in exif.items():
        for tag, value in entries.items():
            table.add_row(ifd, tag, str(value))
    console.print(table)
    if data.get("xmp"):
        console.print(f"[cyan]XMP packet present[/cyan] ({len(data['xmp']):,} chars)")


def _scannable_files(root: Path) -> list[Path]:
    """Regular files under root, skipping dot-directories (.git, .venv, …)."""
    return sorted(
        p for p in root.rglob("*")
        if p.is_file() and not any(part.startswith(".") for part in p.relative_to(root).parts)
    )


def _print_single(rep: report_mod.Report) -> None:
    style = _VERDICT_STYLE.get(rep.verdict, "white")
    threshold_note = (
        "" if rep.verdict == "clean" else f", flagged ≥ {_fmt_prob(rep.flag_threshold)}"
    )
    console.print(
        f"verdict: [{style}]{rep.verdict}[/{style}]  "
        f"P(hidden data) = {_fmt_prob(rep.probability)}  "
        f"[dim](prior {_fmt_prob(rep.prior)}{threshold_note}, ATT&CK {rep.attack_technique})[/dim]"
    )
    if not rep.calibrated:
        err.print(
            "[yellow]warning:[/yellow] no fitted calibration found — probability is a "
            "conservative fallback. Run [bold]stagy bench --fit[/bold] to calibrate."
        )
    table = Table("signal", "score", "evidence (log LR)", "detail")
    for s in rep.signals:
        table.add_row(
            s.name,
            f"{s.score:.2f}",
            "—" if s.log_lr is None else f"{s.log_lr:+.2f}",
            s.detail,
        )
    console.print(table)


_FLAGGED = ("suspicious", "likely-stego")


def _detect_tree(
    root: Path, *, reference: Path | None, report: str, out: Path | None,
    prior: float | None, show_all: bool, fail_on_flag: bool,
) -> None:
    if reference is not None:
        _fail("--reference compares two single files; it does not apply to a directory scan")
    files = _scannable_files(root)
    if not files:
        _fail(f"no files to scan under {root}")

    with console.status(f"scanning {len(files)} files…"):
        reports = report_mod.analyze_many((str(f) for f in files), prior=prior)

    def row(r: report_mod.Report) -> dict[str, object]:
        return {"path": str(Path(r.path).relative_to(root)), "verdict": r.verdict,
                "probability": r.probability, "prior": r.prior, "calibrated": r.calibrated}

    flagged = [r for r in reports if r.verdict in _FLAGGED]
    errors = [r for r in reports if r.verdict == "error"]

    if out is not None:
        out.write_text(json.dumps([row(r) for r in reports], indent=2))
    if report == "json":
        console.print_json(json.dumps([row(r) for r in reports]))
    else:
        console.print(
            f"scanned [bold]{len(reports)}[/bold] files under {root} — "
            f"[bold red]{len(flagged)}[/bold red] flagged, "
            f"{len(reports) - len(flagged) - len(errors)} clean"
            + (f", [dim]{len(errors)} unreadable[/dim]" if errors else "")
        )
        shown = reports if show_all else flagged
        if shown:
            table = Table("P(hidden data)", "verdict", "file",
                          title="ranked most-suspicious first")
            for r in shown:
                style = _VERDICT_STYLE.get(r.verdict, "white")
                table.add_row(_fmt_prob(r.probability), f"[{style}]{r.verdict}[/{style}]",
                              str(Path(r.path).relative_to(root)))
            console.print(table)
        else:
            console.print("[green]nothing flagged.[/green] Re-run with --all to list every file.")

    if fail_on_flag and flagged:
        raise typer.Exit(2)  # distinct from 1 (usage/error), for pipelines


@app.command()
def detect(
    suspect: Path = typer.Option(..., "-i", "--in", exists=True,
                                 help="A file, or a directory to bulk-scan and rank."),
    reference: Path | None = typer.Option(
        None, "--reference", exists=True, dir_okay=False, help="Known-clean original for a near-certain verdict."
    ),
    report: str = typer.Option("text", "--report", help="text | json"),
    out: Path | None = typer.Option(None, "-o", "--out", help="Write JSON report here."),
    prior: float = typer.Option(
        None, "--prior", min=1e-9, max=0.999,
        help="Assumed base rate of stego among scanned files. Lower = more skeptical.",
    ),
    show_all: bool = typer.Option(False, "--all", help="Directory scan: list every file, not just flagged."),
    fail_on_flag: bool = typer.Option(
        False, "--fail-on-flag", help="Exit non-zero (2) if any file is flagged — for cron/CI."
    ),
) -> None:
    """Scan a file — or a whole directory — for hidden data and rank the verdicts."""
    if suspect.is_dir():
        _detect_tree(suspect, reference=reference, report=report, out=out,
                     prior=prior, show_all=show_all, fail_on_flag=fail_on_flag)
        return
    rep = report_mod.analyze(
        str(suspect),
        reference=str(reference) if reference else None,
        prior=prior,
    )
    if out is not None:
        out.write_text(rep.to_json())
    if report == "json":
        console.print_json(rep.to_json())
    else:
        _print_single(rep)
    if fail_on_flag and rep.verdict in _FLAGGED:
        raise typer.Exit(2)


@app.command()
def bench(
    out_dir: Path = typer.Option(Path("samples/bench"), "--dir", help="Where to build the corpus."),
    covers: Path | None = typer.Option(
        None, "--covers", exists=True, file_okay=False,
        help="Directory of real PNG/BMP covers. Strongly recommended — synthetic covers inflate every score.",
    ),
    n_synth: int = typer.Option(200, "--n-synth", min=4, help="Synthetic covers to make if --covers is absent."),
    prior: float = typer.Option(DEFAULT_PRIOR, "--prior", min=1e-9, max=0.999),
    fit: bool = typer.Option(False, "--fit", help="Write the fitted calibration into the package."),
    seed: int = typer.Option(0, "--seed"),
) -> None:
    """Benchmark every detector against a labeled corpus and report real metrics."""
    from ..analysis import benchmark
    from ..analysis import corpus as corpus_mod

    if covers is None:
        err.print(
            "[yellow]note:[/yellow] using synthetic covers. Their LSB planes are cleaner than "
            "real sensor noise, so these numbers are a regression guard, not a performance claim. "
            "Pass --covers with real photographs before quoting any figure."
        )
    with console.status("building labeled corpus…"):
        cases = corpus_mod.build(
            str(out_dir), covers=str(covers) if covers else None, n_synth=n_synth, seed=seed
        )
        corpus_mod.save_manifest(cases, str(out_dir / "manifest.json"))
    with console.status(f"scoring {len(cases)} cases…"):
        res = benchmark.run(
            cases, prior=prior, cover_source=str(covers) if covers else "synthetic"
        )

    n_train = sum(1 for c in cases if c.split == "train")
    console.print(
        f"\ncorpus: {len(cases)} cases from {len({c.cover_id for c in cases})} covers "
        f"({n_train} train / {len(cases) - n_train} test)\n"
    )

    f = res.fused
    if not f.resolves(0.01):
        err.print(
            f"[yellow]note:[/yellow] only {f.n_clean} clean files in the test split, so the "
            f"false-positive axis moves in {f.fpr_resolution:.1%} steps. The @1% FPR column below "
            f"really means 'zero false positives' and is not measurable at that precision — "
            f"use >={int(1 / 0.01)} clean covers to resolve it."
        )

    t = Table("detector", "AUC", "recall @1% FPR", "recall @10% FPR", title="Held-out test split")
    for m in res.per_signal:
        t.add_row(m.name, f"{m.auc:.3f}", f"{m.tpr_at_1pct_fpr:.1%}", f"{m.tpr_at_10pct_fpr:.1%}")
    t.add_row(
        "[bold]FUSED[/bold]", f"[bold]{f.auc:.3f}[/bold]",
        f"[bold]{f.tpr_at_1pct_fpr:.1%}[/bold]", f"[bold]{f.tpr_at_10pct_fpr:.1%}[/bold]",
    )
    console.print(t)

    b = Table("technique", "embed rate", "n", "detected @1% FPR", title="Where detection breaks down")
    for row in res.breakdown:
        colour = "green" if row.detected >= 0.8 else "yellow" if row.detected >= 0.4 else "red"
        b.add_row(row.technique, f"{row.rate:.0%}", str(row.n),
                  f"[{colour}]{row.detected:.0%}[/{colour}]")
    console.print(b)

    if fit:
        res.calibration.save(report_mod.CALIBRATION_PATH)
        console.print(f"\n[green]calibration written[/green] → {report_mod.CALIBRATION_PATH}")
    else:
        console.print("\n[dim]re-run with --fit to write this calibration into the package.[/dim]")


if __name__ == "__main__":
    app()
