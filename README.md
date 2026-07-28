# Stagy

A steganography suite that hides, extracts, and **detects** hidden data across
covers. One core library; a CLI and a web app wrap it. Red-team side embeds;
blue-team side finds. What's next: [ROADMAP.md](ROADMAP.md).

> **Authorized use only.** Stagy is dual-use — built and framed as a
> security-research and detection tool. Use it on your own files and networks.

## Status

All roadmap phases are implemented. Container format and crypto layer; a broad
set of carriers — keyed LSB for **PNG/BMP images** and **16-bit PCM WAV audio**,
**JPEG DCT (JSteg)**, **spread-spectrum audio**, **appended-data / polyglot**,
JPEG **EXIF**, document carriers (**zero-width text**, **PDF**, **DOCX**), and a
lab-only **network covert channel**. The detection half (Phase 6) is complete:
chi-square, RS analysis, and sample-pair analysis for LSB, plus entropy and
file-carving for appended data, fused into one calibrated verdict backed by a
benchmark/calibration harness. The attack/detector loop is closed. The **web
app** (Phase 7) ships a FastAPI backend and a React/Tailwind frontend (Hide /
Reveal / Detect), and **Docker** files (Phase 9) self-host both behind nginx.

See the **capability matrix** below, and
[docs/advanced-techniques.md](docs/advanced-techniques.md) for the JPEG DCT,
spread-spectrum, and network channels with their honest tradeoffs.

## Capability matrix

| Technique | CLI | Cover | Capacity | Robustness | Detectability | Extra |
|---|---|---|---|---|---|---|
| Image LSB (keyed) | `image` | PNG/BMP | high | dies on re-encode | RS / sample-pairs catch it | — |
| JPEG DCT (JSteg) | `jpeg` | JPEG | medium | survives copy, not re-encode | histogram attack (sequential) | `[jpeg]` |
| Audio LSB | `audio` | WAV PCM16 | high | dies on requantize | chi-square / RS | — |
| Audio spread-spectrum | `audio --method spread` | WAV PCM16 | low | survives noise/filtering | hard (keyed, sub-noise) | — |
| Appended / polyglot | `meta --technique appended` | any | unlimited | survives copy, not re-parse | file-carver (instant) | — |
| EXIF field | `meta --technique exif` | JPEG | small | dies on metadata strip | `meta scan` (instant) | `[docs-fmt]` |
| Zero-width / PDF / DOCX | `meta --technique …` | text/PDF/DOCX | low–med | fragile | varies | `[docs-fmt]` |
| Network covert channel | `net` **(lab only)** | IP/TCP headers | tiny | NAT/firewall rewrites | timing/field analysis | `[network]` + root |

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Design in one breath

`plaintext → [compress] → encrypt (AES-256-GCM) → frame (Stagy container) → keyed-scatter into cover LSBs`

- **Codecs are dumb bit carriers.** They store/retrieve framed bytes; they know
  nothing about crypto. Crypto and framing live one layer up (`container.py`).
- **Encrypt, then embed.** Detected ≠ decrypted.
- **The passphrase does two jobs.** Derives the AES key *and* seeds the
  pseudo-random LSB selection, so the payload scatters instead of filling
  left-to-right (which a chi-square test spots in seconds).
- **Never re-encode a lossless carrier as lossy.** The image codec refuses to
  save `.jpg`/`.jpeg`.

## CLI

```bash
stagy image capacity -c cover.png --bits 1 --channels RGB
stagy image embed   -c cover.png -p secret.txt -o stego.png --key "passphrase"
stagy image extract -i stego.png -o recovered.txt --key "passphrase"

stagy audio capacity -c cover.wav --bits 1
stagy audio embed   -c cover.wav -p secret.txt -o stego.wav --key "passphrase"
stagy audio extract -i stego.wav -o recovered.txt --key "passphrase"

# JPEG DCT (JSteg) — survives copying, not re-encoding.  needs: pip install 'stagy[jpeg]'
stagy jpeg embed   -c cover.jpg -p secret.txt -o stego.jpg --key "passphrase"
stagy jpeg extract -i stego.jpg -o recovered.txt --key "passphrase"

# Spread-spectrum audio — robust to noise, low capacity, keyed-only.
stagy audio embed   -c cover.wav -p secret.txt -o stego.wav --method spread --key "passphrase"
stagy audio extract -i stego.wav -o recovered.txt --method spread --key "passphrase"

# metadata / document techniques: appended | exif | zerowidth | pdf | docx
stagy meta embed   --technique exif -c cover.jpg -p secret.txt -o stego.jpg --key "passphrase"
stagy meta extract --technique exif -i stego.jpg -o recovered.txt --key "passphrase"
stagy meta scan    -i suspect.jpg    # dump EXIF/XMP — the tell a hidden payload leaves

# Network covert channel — LAB ONLY (needs root + a receiver you control):
#   pip install 'stagy[network]'
#   stagy net send -p secret.txt --dst 10.0.0.2 --field ip_id --key "passphrase"
#   stagy net recv --count 86 --field ip_id -o recovered.txt --key "passphrase"
```

Passphrase comes from `--key`, the `STAGY_KEY` env var, or an interactive
prompt (never echoed). Recovered bytes go to `-o` (or `--stdout` explicitly),
never printed by default.

## Detection

```bash
stagy detect -i suspect.png                      # calibrated verdict + posterior
stagy detect -i suspect.png --reference orig.png # near-conclusive with the original
stagy detect -i ./share                          # bulk-scan a tree, ranked most-suspicious first
stagy detect -i ./share --fail-on-flag           # exit 2 if anything is flagged (cron/CI)
stagy bench --covers ./photos --fit              # measure every detector, recalibrate
```

Pointing `detect` at a directory scans it recursively and prints the files
**ranked by P(hidden data)** — the low-false-positive triage order the whole
detector design optimizes for — with `--all` to list every file and
`--report json` for a machine-readable array. The calibration is loaded once for
the sweep, and one unreadable file is reported, not fatal.

`detect` reports a **posterior probability**, not just a label, and the verdict
thresholds come from measured operating points — the score at which the
detector costs a 1% (likely-stego) or 10% (suspicious) false-positive rate on
held-out data. Maps to MITRE ATT&CK
[T1027.003](https://attack.mitre.org/techniques/T1027/003/).

Read the posterior with the base rate in mind: at the default 1-in-1000 prior,
even a strong signal often lands a few percent. That is arithmetic, not a bug.
Use `--prior` to model a targeted hunt versus bulk scanning.

`stagy bench` is what keeps the blue-team half honest — it builds labeled
ground truth, scores every analyzer on a held-out split, and reports **recall at
a fixed low false-positive budget** rather than accuracy. Current measured
baseline (synthetic covers, regression guard only):

| detector | AUC | recall @1% FPR |
|---|---|---|
| reference-diff (with known-clean original) | 1.000 | 100.0% |
| sample-pairs (Dumitrescu–Wu–Wang) | 0.998 | 96.0% |
| rs-analysis (Fridrich) | 0.997 | 95.5% |
| chi-square (Westfeld–Pfitzmann) | 0.947 | 76.5% |
| **FUSED (blind, no reference)** | **1.000** | **99.5%** |

The two structural estimators — RS and sample-pairs — read the LSB plane's
spatial correlation, so *keyed* scattering does not hide from them the way it
hides from the histogram-based chi-square. Blind detection of keyed embedding at
5% fill rose from 9% (chi-square alone) to **96%** once both estimators fuse, and
their independent agreement is what makes the verdict trustworthy rather than a
single noisy guess. See
[docs/detection-benchmark.md](docs/detection-benchmark.md).

A separate pair of analyzers catches *appended-data* steganography — a file
hidden after a cover's EOF marker. **File-carving** scans the appended region for
known signatures (ZIP, secondary PNG/JPEG, PDF, …); **entropy analysis** flags a
high-entropy appended blob even when it has no signature (an encrypted payload).
Both give deterministic evidence — a hidden ZIP after a PNG's `IEND` is a fact,
not a probability — so they are weighted directly rather than calibrated, and
absence is treated as neutral, never as a clean verdict.

## Web app

```bash
pip install -e ".[web]"
uvicorn web.backend.app:app --reload        # API on :8000, docs at /docs
npm --prefix web/frontend install
npm --prefix web/frontend run dev           # UI on :5173
```

Three flows: **Hide** (cover + payload + passphrase, live capacity meter),
**Reveal** (stego + passphrase → payload), and **Detect** (verdict, per-detector
evidence, rendered LSB bit-plane, and the value-pair histogram that makes the
embedding signature visible).

Uploads are **processed in memory and never persisted** — each request gets a
temp dir that is removed on the way out, including on error. Cover types are
whitelisted by magic number rather than by filename extension, uploads are
capped at 16 MB, and requests are rate-limited per IP. Embedding and
steganalysis run in a threadpool so a large cover cannot stall the event loop.
Network steganography is deliberately **not** exposed over HTTP — raw packet
crafting does not belong behind a web form.

The passphrase transits the request body, so deploy behind TLS. Design tokens
and their rationale: [web/frontend/DESIGN.md](web/frontend/DESIGN.md).

## Self-host (Docker)

```bash
docker compose up --build        # UI on http://localhost:8080
```

Two containers: `api` (uvicorn) and `web` (the built frontend served by nginx,
proxying `/api` to the API over the compose network). The API is **not** exposed
to the host — only the web UI is — so the whole app is same-origin. Drops into a
Proxmox homelab behind Traefik + a Cloudflare Tunnel: point the tunnel at the
`web` service for a demo URL.

## Library

```python
import stagy
stagy.hide("cover.png", b"secret bytes", "stego.png", passphrase="pw", compress=True)
result = stagy.reveal("stego.png", passphrase="pw")
result.payload  # -> b"secret bytes"
```

## License

MIT
