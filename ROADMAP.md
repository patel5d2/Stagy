# Roadmap

The core roadmap (container/crypto, the carrier codecs, the detection suite, the
web app, Docker) is **shipped** — see the capability matrix in the
[README](README.md). This file tracks what comes *after* 1.0: features that
close a real gap, ordered by value over cost. Each entry says why it earns its
place, so nothing here is a speculative "might be nice."

Format: **[status]** feature — the gap it closes · rough size.

---

## Shipped after 1.0

- **[done]** **Bulk directory triage scan** — `stagy detect -i <dir>` walks a
  tree, scores every file, and prints the results **ranked most-suspicious
  first**, with a `--report json` array and a scriptable `--fail-on-flag`
  (exit 2 on any hit) for cron/CI. Closes the gap between the detection docs —
  which are written around "bulk scanning a million-file share" — and a CLI that
  could only take one file. The calibration is loaded and parsed **once** for the
  whole sweep (`report.analyze_many`), and one unreadable file becomes an
  `error` row instead of aborting the run. A shell loop over `stagy detect` can
  do neither.

- **[done]** **PNG text-chunk analyzer** (`analysis/png_text.py`). The LSB
  analyzers read the pixel plane and `filecarve`/`entropy` read the appended
  region, so a payload parked in a `tEXt`/`zTXt`/`iTXt` chunk — a classic hiding
  spot viewers never show — slipped past everything. The new deterministic
  analyzer (own `log_lr`, no calibration, absence stays neutral) decodes each
  text chunk, calls it a **payload** when it decodes to a real file/container
  (raw or base64 — near-conclusive, `log_lr` 6.0) and **suspicious** when it is a
  large opaque high-entropy blob (`log_lr` 3.0), while whitelisting legitimate
  large XML/XMP. Wired into `_appended_signals`, so it sets a floor on the
  verdict independent of the pixel plane.

- **[done]** **Web batch-detect endpoint** — `POST /api/detect-batch` takes
  repeated `files=` and returns them **ranked most-suspicious first** (`scanned`
  / `flagged` / `clean` / `errors` counts plus per-file verdict + probability):
  `stagy detect -i <dir>` over HTTP. It reuses `analyze_many` (calibration loaded
  once), the per-file size cap, and threadpool dispatch, adds a file-count cap
  (`MAX_BATCH_FILES`), and turns an unsupported/unreadable file into an `error`
  row instead of a 415 that would sink the batch.

## Next — ready to pick up

1. **Progress + parallelism for large trees** · small, then measure. The bulk
   scan shows a spinner; swap it for a `rich.Progress` bar over the file count.
   Only *then* consider a `--jobs` process pool: steganalysis is CPU-bound numpy,
   so parallelism helps — but measure the serial wall-time on a real tree first,
   because a pool adds pickling and shutdown complexity that a fast-enough serial
   scan does not need.

2. **Read each file once per scan** · small. `filecarve`, `entropy`, and
   `png-text` each call `Path.read_bytes` on the same file. Fine for one file;
   on a million-file tree it is three reads where one would do. Thread the bytes
   through `_appended_signals` once the bulk scan proves it matters.

## Later — additive, not gap-closing

4. **More lossless carriers** · per-format. Uncompressed TIFF and lossless WebP
   are viable LSB hosts the image codec does not yet accept. Additive codec work
   behind the same container; each needs its own re-encode-refusal guard.

5. **Shell completion** · one line. `typer` ships it; the app currently sets
   `add_completion=False`. Turn it on once the command surface is stable.

## Project health (not features, but overdue)

- Keep [CHANGELOG.md](CHANGELOG.md) current with each shipped item above.
- A calibration refit on **real photographs** (`stagy bench --covers … --fit`)
  before any number in the docs is quoted as a performance claim — the shipped
  calibration is a synthetic-cover regression guard, and it says so.

---

**How to read this list.** An item graduates from "next" to "shipped" only with
a test that fails if the feature breaks and a docs line describing it — the same
bar the 1.0 code held. Items are deliberately small: the honest unit of progress
is one closed gap with its check, not a quarter-long epic.
