import { useEffect, useState } from "react";

/**
 * Value-pair histogram, computed in the browser from the uploaded image.
 *
 * Client-side on purpose: the file is already in the page, so computing here
 * costs no upload, no API surface, and no round-trip. The backend's /api/detect
 * returns a verdict, not pixel data.
 *
 * What it shows, and why this particular histogram: LSB embedding does not
 * change *which* pair of values a sample belongs to (2i, 2i+1) — only which
 * member of the pair it is. So embedding drives the two bars of every pair
 * toward equal height while leaving the pair's total untouched. That flattening
 * IS the chi-square signature, made visible. A clean photo shows jagged,
 * unequal pairs; a filled cover shows pairs levelling off.
 */

interface Props {
  file: File;
}

interface Bins {
  counts: Uint32Array; // 256 luminance bins
  pairDelta: number[]; // 128 normalized |even - odd| per pair, 0..1
}

async function computeBins(file: File): Promise<Bins | null> {
  const bitmap = await createImageBitmap(file).catch(() => null);
  if (!bitmap) return null;

  // Downscale large images: 512px on the long edge keeps the histogram shape
  // while bounding the work on a 16 MB upload.
  const scale = Math.min(1, 512 / Math.max(bitmap.width, bitmap.height));
  const w = Math.max(1, Math.round(bitmap.width * scale));
  const h = Math.max(1, Math.round(bitmap.height * scale));

  const canvas = document.createElement("canvas");
  canvas.width = w;
  canvas.height = h;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  if (!ctx) return null;
  ctx.drawImage(bitmap, 0, 0, w, h);
  bitmap.close();

  const { data } = ctx.getImageData(0, 0, w, h);
  const counts = new Uint32Array(256);
  for (let i = 0; i < data.length; i += 4) {
    // Rec. 601 luma, integer-rounded.
    const y = (data[i]! * 299 + data[i + 1]! * 587 + data[i + 2]! * 114) / 1000;
    counts[Math.min(255, Math.round(y))]!++;
  }

  const pairDelta: number[] = [];
  for (let p = 0; p < 128; p++) {
    const a = counts[2 * p]!;
    const b = counts[2 * p + 1]!;
    const total = a + b;
    // 0 = perfectly equalized (the embedding signature), 1 = maximally skewed.
    pairDelta.push(total === 0 ? 0 : Math.abs(a - b) / total);
  }
  return { counts, pairDelta };
}

export function Histogram({ file }: Props) {
  const [bins, setBins] = useState<Bins | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let alive = true;
    setBins(null);
    setFailed(false);
    computeBins(file).then((b) => {
      if (!alive) return;
      if (b) setBins(b);
      else setFailed(true);
    });
    return () => {
      alive = false;
    };
  }, [file]);

  if (failed) {
    return <p className="text-xs text-ink-500">histogram unavailable for this file</p>;
  }
  if (!bins) return <p className="num text-xs text-ink-500">computing histogram…</p>;

  const max = Math.max(...bins.counts);
  const W = 512;
  const H = 120;

  // Mean pair imbalance. Natural images sit high; embedding pushes it toward 0.
  const meanDelta = bins.pairDelta.reduce((a, b) => a + b, 0) / bins.pairDelta.length;

  return (
    <div className="space-y-4">
      <figure>
        <figcaption className="mb-1.5 text-xs text-ink-500">
          Luminance histogram
        </figcaption>
        <svg
          viewBox={`0 0 ${W} ${H}`}
          className="h-24 w-full"
          role="img"
          aria-label="Luminance histogram of the uploaded image"
          preserveAspectRatio="none"
        >
          {Array.from(bins.counts).map((c, i) =>
            c === 0 ? null : (
              <rect
                key={i}
                x={(i / 256) * W}
                y={H - (c / max) * H}
                width={W / 256}
                height={(c / max) * H}
                fill="var(--color-accent-500)"
                opacity={0.85}
              />
            ),
          )}
        </svg>
      </figure>

      <figure>
        <figcaption className="mb-1.5 text-xs text-ink-500">
          Value-pair imbalance — LSB embedding flattens these toward zero
        </figcaption>
        <svg
          viewBox={`0 0 ${W} 60`}
          className="h-16 w-full"
          role="img"
          aria-label="Per-pair histogram imbalance"
          preserveAspectRatio="none"
        >
          {bins.pairDelta.map((d, i) => (
            <rect
              key={i}
              x={(i / 128) * W}
              y={60 - d * 60}
              width={W / 128}
              height={d * 60}
              fill={
                meanDelta < 0.15
                  ? "var(--color-verdict-stego)"
                  : "var(--color-verdict-clean)"
              }
              opacity={0.8}
            />
          ))}
        </svg>
        <p className="num mt-1 text-xs text-ink-500">
          mean imbalance {meanDelta.toFixed(3)}{" "}
          {meanDelta < 0.15
            ? "— pairs are unusually level, consistent with LSB embedding"
            : "— pairs are uneven, as a natural image should be"}
        </p>
      </figure>
    </div>
  );
}
