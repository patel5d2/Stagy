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

## [1.0.0] - 2026-07-28

Initial release. Container format + AES-256-GCM/Argon2id crypto; carriers for
PNG/BMP LSB, WAV LSB, JPEG DCT (JSteg), spread-spectrum audio, appended-data,
EXIF, zero-width/PDF/DOCX, and a lab-only network covert channel; a calibrated
detection suite (chi-square, RS, sample-pairs, entropy, file-carving) with a
benchmark/calibration harness; a FastAPI + React web app; and Docker self-host.
