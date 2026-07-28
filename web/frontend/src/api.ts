/**
 * Typed client for the Stagy API (web/backend/app.py).
 *
 * These types mirror the backend's pydantic models exactly. If a field name
 * drifts here the UI silently renders `undefined`, so they are kept literal
 * rather than loosened with optionals.
 */

export interface Health {
  status: string;
  version: string;
  codecs: string[];
  max_upload_bytes: number;
}

export interface Capacity {
  capacity_bytes: number;
  cover_type: string;
  bits: number;
  channels: string;
}

export interface Extracted {
  filename: string | null;
  was_encrypted: boolean;
  size_bytes: number;
  payload_b64: string;
}

export interface Signal {
  name: string;
  score: number;
  detail: string;
  log_lr: number | null;
}

export type Verdict = "clean" | "suspicious" | "likely-stego";

export interface Detection {
  verdict: Verdict;
  probability: number;
  prior: number;
  calibrated: boolean;
  flag_threshold: number;
  signals: Signal[];
  bitplane_png_b64: string | null;
}

export interface EmbedOptions {
  passphrase: string;
  encrypt: boolean;
  compress: boolean;
  bits: number;
  channels: string;
  mode: "keyed" | "sequential";
}

/** An API error carrying the backend's `detail` string and HTTP status. */
export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function fail(res: Response): Promise<never> {
  // The backend answers errors as {"detail": "..."}; anything else (a proxy
  // error page, a 500) must still surface something readable.
  let detail = `${res.status} ${res.statusText}`;
  try {
    const body = (await res.json()) as { detail?: unknown };
    if (typeof body.detail === "string") detail = body.detail;
    else if (Array.isArray(body.detail)) detail = "invalid request parameters";
  } catch {
    /* non-JSON body — keep the status line */
  }
  throw new ApiError(detail, res.status);
}

export async function health(): Promise<Health> {
  const res = await fetch("/api/health");
  if (!res.ok) return fail(res);
  return (await res.json()) as Health;
}

export async function capacity(
  cover: File,
  bits: number,
  channels: string,
): Promise<Capacity> {
  const fd = new FormData();
  fd.append("cover", cover);
  fd.append("bits", String(bits));
  fd.append("channels", channels);
  const res = await fetch("/api/capacity", { method: "POST", body: fd });
  if (!res.ok) return fail(res);
  return (await res.json()) as Capacity;
}

/** Returns the stego PNG as a Blob, ready for a download link. */
export async function embed(
  cover: File,
  payload: File,
  opts: EmbedOptions,
): Promise<Blob> {
  const fd = new FormData();
  fd.append("cover", cover);
  fd.append("payload", payload);
  fd.append("passphrase", opts.passphrase);
  fd.append("encrypt", String(opts.encrypt));
  fd.append("compress", String(opts.compress));
  fd.append("bits", String(opts.bits));
  fd.append("channels", opts.channels);
  fd.append("mode", opts.mode);
  const res = await fetch("/api/embed", { method: "POST", body: fd });
  if (!res.ok) return fail(res);
  return await res.blob();
}

export async function extract(
  stego: File,
  passphrase: string,
  bits: number,
  channels: string,
  mode: string,
): Promise<Extracted> {
  const fd = new FormData();
  fd.append("stego", stego);
  fd.append("passphrase", passphrase);
  fd.append("bits", String(bits));
  fd.append("channels", channels);
  fd.append("mode", mode);
  const res = await fetch("/api/extract", { method: "POST", body: fd });
  if (!res.ok) return fail(res);
  return (await res.json()) as Extracted;
}

export async function detect(
  suspect: File,
  reference: File | null,
): Promise<Detection> {
  const fd = new FormData();
  fd.append("suspect", suspect);
  if (reference) fd.append("reference", reference);
  fd.append("include_bitplane", "true");
  const res = await fetch("/api/detect", { method: "POST", body: fd });
  if (!res.ok) return fail(res);
  return (await res.json()) as Detection;
}

/** base64 -> Blob, for handing recovered bytes to a download link. */
export function b64ToBlob(b64: string, type = "application/octet-stream"): Blob {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new Blob([bytes], { type });
}

/**
 * Format a probability without collapsing small magnitudes to "0.0000".
 *
 * Calibrated thresholds run to 1e-6 (the fitted flag threshold on the current
 * corpus is 1.288e-6). Fixed 4-decimal formatting renders that as "0.0000",
 * which reads as "flags at zero" — i.e. that everything is flagged — the exact
 * opposite of a strict threshold. Below 1e-4 we switch to exponential.
 */
export function formatProb(p: number): string {
  if (p === 0) return "0";
  if (p >= 1e-4) return p.toFixed(4);
  return p.toExponential(2);
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}
