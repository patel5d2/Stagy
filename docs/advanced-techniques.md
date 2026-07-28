# Advanced techniques — Phases 5 & 8

Three carriers beyond spatial LSB, and the honest tradeoffs behind each. All
carry the same Stagy container (encrypt → frame → embed), so encryption,
compression, and integrity checking work identically across them.

---

## JPEG DCT (JSteg) — Phase 8.1

**Module:** [`codecs/image_jpeg.py`](../src/stagy/codecs/image_jpeg.py) · needs
`pip install 'stagy[jpeg]'` · CLI: `stagy jpeg`

Spatial LSB dies the moment an image is saved as JPEG: the DCT + quantization
stage discards exactly the low-order detail LSB relies on. So this codec works
one level down — in the **quantized DCT coefficients** that JPEG actually
stores, accessed losslessly through `jpeglib`.

**Why it is reversible.** Message bits overwrite the LSBs of AC coefficients,
skipping any coefficient equal to 0 or 1. The usable set — every integer except
0 and 1 — is closed under LSB overwrite (`2↔3`, `-1↔-2`, …, never reaching 0 or
1), so a coefficient usable at embed time is still usable at extract time and
the receiver rebuilds the identical ordering with no side channel. The DC term
of each block is skipped too: DC changes are the most visible.

**Modes.** Sequential is classic JSteg (raster order, detectable by a histogram
attack). Keyed scatters the payload with the passphrase-seeded permutation — the
same defense the spatial codecs use, and the default.

**Fragility class.** Survives a byte-for-byte **copy**, not a **re-encode**:
opening the stego JPEG in an editor and re-saving requantizes the coefficients
and wipes the payload. This is inherent to JPEG steganography, and Stagy's tests
pin both behaviors (`test_survives_copy`, `test_reencode_destroys_payload`).

---

## Spread-spectrum audio — Phase 8.2

**Module:** [`codecs/audio_spread.py`](../src/stagy/codecs/audio_spread.py) ·
numpy only · CLI: `stagy audio … --method spread`

Where WAV-LSB writes payload bits into sample LSBs (high capacity, wiped by any
requantization or gain change), this spreads each bit across a whole block of
samples with direct-sequence spread spectrum. Each bit is multiplied by a
passphrase-seeded ±1 chip sequence, scaled by a gain, and added to the audio;
extraction correlates each block against the same sequence and reads the sign.

**Why it is robust.** The bit lives in a correlation over ~1000 samples, not one
fragile LSB, so it survives additive noise and mild filtering that annihilate
LSB data. Measured: the payload survives ±50-amplitude Gaussian noise that
randomizes every sample LSB (`test_survives_noise_that_destroys_lsb`).

**The tradeoffs, stated plainly.**

* **Capacity** is far lower — one bit per block, not per sample. A 30 s mono clip
  carries ~160 bytes versus ~27 KB for LSB.
* **Audibility.** The default gain (600) is tuned for bit-exact recovery on
  loud, near-full-scale tonal hosts — the worst case for correlation. On a
  quieter cover, lower `--gain` to reduce audible noise.
* **Exactness.** On a clean copy the round-trip is bit-exact, which the
  container CRC demands. Under actual processing you would layer error-correction
  coding on top; spread spectrum raises the noise floor you can tolerate, it does
  not make the channel lossless under attack. A failed decode is caught by the
  CRC and surfaces as an error, never as silent corruption.

**Why not echo hiding or phase coding?** Both are named in the roadmap and both
are genuinely robust, but they have non-zero bit-error rates by nature — they
suit fragile *watermarks* (a few bits, survive re-encoding) rather than an exact
framed container, where a single wrong bit fails the CRC. Spread spectrum is the
technique in this family that carries a container exactly, so it is the one
implemented as a carrier.

---

## Network covert channel — Phase 5 · **LAB ONLY**

**Module:** [`codecs/network.py`](../src/stagy/codecs/network.py) · needs
`pip install 'stagy[network]'` and root · CLI: `stagy net`

Hides the container in a header field that carries no meaning to the
application — the IP identification field (16 bits/packet) or the TCP initial
sequence number (32 bits/packet). One payload chunk rides in each packet:

```
┌──────────────── field bits ────────────────┐
│   sequence number   │      data chunk       │
└─────────────────────┴───────────────────────┘
```

The **sequence number** is what makes it survive a real network: the receiver
sorts by it (so reordering is *corrected*, not merely detected), a missing
number is packet loss, and a duplicate is a replay — both raise rather than
return corrupt bytes. With a passphrase, the data half is XORed with a keyed
per-sequence keystream, so an observer without the key sees field values that
look like ordinary random IP ids.

**Layering.** The coding layer (`encode_packets` / `decode_packets`) is pure and
has no network dependency — it holds all the fiddly logic and is exhaustively
unit-tested (round-trip, reorder, loss, duplication, keying, capacity). Scapy is
imported lazily, only at transmit time, so `import stagy` and the tests need
neither scapy nor root.

### Responsible use

This module crafts and transmits raw packets. It requires root / `CAP_NET_RAW`
and a receiver you control. NAT and stateful firewalls rewrite `IP.id` and drop
crafted TCP segments, so it works on a **flat lab network only** — two VMs on one
bridge, a veth pair, or loopback with a BPF filter. **Never point it at a host
you do not own.** The CLI prints this warning on every `send` and `recv`.

The capacity is deliberately tiny (`ip_id` addresses only 256 packets → 256
bytes; `tcp_seq` reaches ~128 KB). A covert channel trades bandwidth for
inconspicuousness; that is the point, not a limitation.
