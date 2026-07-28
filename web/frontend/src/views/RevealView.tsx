import { useEffect, useState } from "react";
import * as api from "../api";
import { Dropzone } from "../components/Dropzone";

/** Preview recovered bytes as text when they look like text, else offer download. */
function textOrNull(bytes: Uint8Array): string | null {
  const slice = bytes.subarray(0, 4096);
  let printable = 0;
  for (const b of slice) {
    if (b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127)) printable++;
  }
  if (slice.length === 0 || printable / slice.length < 0.9) return null;
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, 8192));
  } catch {
    return null;
  }
}

export function RevealView() {
  const [stego, setStego] = useState<File | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [bits, setBits] = useState(1);
  const [channels, setChannels] = useState("RGB");
  const [mode, setMode] = useState("keyed");

  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [out, setOut] = useState<{
    meta: api.Extracted;
    url: string;
    text: string | null;
  } | null>(null);

  useEffect(() => () => { if (out) URL.revokeObjectURL(out.url); }, [out]);

  async function submit() {
    if (!stego) return;
    setBusy(true);
    setError(null);
    setOut((old) => {
      if (old) URL.revokeObjectURL(old.url);
      return null;
    });
    try {
      const meta = await api.extract(stego, passphrase, bits, channels, mode);
      const blob = api.b64ToBlob(meta.payload_b64);
      const bytes = new Uint8Array(await blob.arrayBuffer());
      setOut({ meta, url: URL.createObjectURL(blob), text: textOrNull(bytes) });
    } catch (e) {
      setError(e instanceof api.ApiError ? e.message : "extract failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <section className="panel space-y-5 p-5">
        <Dropzone
          label="Stego image"
          hint="PNG or BMP"
          accept="image/png,image/bmp"
          file={stego}
          onFile={setStego}
          preview
        />

        <div>
          <label htmlFor="rpass" className="mb-1.5 block text-sm font-medium text-ink-300">
            Passphrase
          </label>
          <input
            id="rpass"
            type="password"
            className="field"
            autoComplete="off"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
          />
        </div>

        <fieldset className="grid grid-cols-3 gap-3">
          <legend className="sr-only">Extraction options</legend>
          <label className="text-xs text-ink-300">
            bits
            <select className="field mt-1" value={bits} onChange={(e) => setBits(Number(e.target.value))}>
              {[1, 2, 3, 4].map((b) => <option key={b} value={b}>{b}</option>)}
            </select>
          </label>
          <label className="text-xs text-ink-300">
            channels
            <select className="field mt-1" value={channels} onChange={(e) => setChannels(e.target.value)}>
              {["RGB", "R", "G", "B", "RGBA"].map((c) => <option key={c} value={c}>{c}</option>)}
            </select>
          </label>
          <label className="text-xs text-ink-300">
            mode
            <select className="field mt-1" value={mode} onChange={(e) => setMode(e.target.value)}>
              <option value="keyed">keyed</option>
              <option value="sequential">sequential</option>
            </select>
          </label>
        </fieldset>

        <p className="text-xs text-ink-500">
          These must match how the file was embedded. A mismatch reads garbage and
          fails the container check — which looks identical to "nothing hidden here."
        </p>

        <button className="btn btn-primary w-full" disabled={!stego || busy} onClick={submit}>
          {busy ? "Extracting…" : "Extract"}
        </button>

        {error && <p role="alert" className="text-sm text-verdict-stego">{error}</p>}
      </section>

      <section className="panel p-5">
        <h2 className="mb-3 text-sm font-medium text-ink-300">Recovered payload</h2>
        {out ? (
          <div className="space-y-3">
            <dl className="num grid grid-cols-2 gap-y-1.5 text-xs">
              <dt className="text-ink-500">filename</dt>
              <dd className="truncate text-ink-100">{out.meta.filename ?? "—"}</dd>
              <dt className="text-ink-500">size</dt>
              <dd className="text-ink-100">{api.formatBytes(out.meta.size_bytes)}</dd>
              <dt className="text-ink-500">encrypted</dt>
              <dd className={out.meta.was_encrypted ? "text-verdict-clean" : "text-verdict-suspicious"}>
                {out.meta.was_encrypted ? "yes (AES-256-GCM)" : "no"}
              </dd>
            </dl>

            {out.text !== null ? (
              <pre className="num max-h-64 overflow-auto rounded-lg border border-base-700 bg-base-800 p-3 text-xs whitespace-pre-wrap text-ink-100">
                {out.text}
              </pre>
            ) : (
              <p className="text-xs text-ink-500">
                Binary payload — no safe text preview.
              </p>
            )}

            <a
              className="btn btn-primary w-full"
              href={out.url}
              download={out.meta.filename ?? "payload.bin"}
            >
              Download payload
            </a>
          </div>
        ) : (
          <p className="text-sm text-ink-500">
            Recovered bytes appear here. Nothing is written to disk until you
            choose to download.
          </p>
        )}
      </section>
    </div>
  );
}
