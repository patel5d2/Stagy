# Changelog

Notable changes, newest first. Format follows
[Keep a Changelog](https://keepachangelog.com/); versions are
[SemVer](https://semver.org/). Planned work lives in [ROADMAP.md](ROADMAP.md).

## [Unreleased]

### Added
- **Bulk directory triage scan.** `stagy detect -i <dir>` walks a tree, scores
  every file, and prints them **ranked most-suspicious first**. Supports `--all`
  (list every file, not just flagged), `--report json` (a machine-readable
  array), and `--fail-on-flag` (exit code 2 on any hit, for cron/CI). Backed by
  `analysis.report.analyze_many`, which loads the calibration once for the whole
  sweep and turns an unreadable file into an `error` row instead of aborting.
- **PNG text-chunk detection.** A new deterministic analyzer inspects PNG
  `tEXt`/`zTXt`/`iTXt` chunks — a hiding spot the LSB, file-carve, and entropy
  analyzers all miss. It flags a chunk that decodes to a real file/container
  (raw or base64) as a payload, and a large opaque high-entropy chunk as
  suspicious, while leaving legitimate metadata and XMP alone.
- **Web batch-detect endpoint.** `POST /api/detect-batch` scans many uploaded
  covers at once and returns them ranked most-suspicious first (with
  scanned/flagged/clean/error counts) — the CLI's directory scan over HTTP. File
  count is capped (`MAX_BATCH_FILES`); an unsupported or unreadable file becomes
  an `error` row instead of failing the whole request.
- **Release provenance.** Each release now attaches a CycloneDX SBOM of the
  shipped runtime dependencies and a `SHA256SUMS` file, so a download can be
  verified (`sha256sum -c SHA256SUMS`) and its dependency tree audited. Also
  documents `pipx` as the isolated way to install the CLI.

## [1.0.0] - 2026-07-28

Initial release. Container format + AES-256-GCM/Argon2id crypto; carriers for
PNG/BMP LSB, WAV LSB, JPEG DCT (JSteg), spread-spectrum audio, appended-data,
EXIF, zero-width/PDF/DOCX, and a lab-only network covert channel; a calibrated
detection suite (chi-square, RS, sample-pairs, entropy, file-carving) with a
benchmark/calibration harness; a FastAPI + React web app; and Docker self-host.
