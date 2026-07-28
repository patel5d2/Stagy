import { useEffect, useState } from "react";
import * as api from "../api";
import { CapacityMeter } from "../components/CapacityMeter";
import { Dropzone } from "../components/Dropzone";

export function HideView() {
  const [cover, setCover] = useState<File | null>(null);
  const [payload, setPayload] = useState<File | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [encrypt, setEncrypt] = useState(true);
  const [compress, setCompress] = useState(false);
  const [bits, setBits] = useState(1);
  const [channels, setChannels] = useState("RGB");
  const [mode, setMode] = useState<"keyed" | "sequential">("keyed");

  const [cap, setCap] = useState<number | null>(null);
  const [capLoading, setCapLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{ url: string; size: number } | null>(null);

  // Live capacity: refetch whenever the cover or the bit/channel options change.
  useEffect(() => {
    if (!cover) {
      setCap(null);
      return;
    }
    let alive = true;
    setCapLoading(true);
    setError(null);
    api
      .capacity(cover, bits, channels)
      .then((c) => alive && setCap(c.capacity_bytes))
      .catch((e: unknown) => {
        if (!alive) return;
        setCap(null);
        setError(e instanceof api.ApiError ? e.message : "capacity check failed");
      })
      .finally(() => alive && setCapLoading(false));
    return () => {
      alive = false;
    };
  }, [cover, bits, channels]);

  // Object URLs for the produced PNG must be revoked or they leak per embed.
  useEffect(() => () => { if (result) URL.revokeObjectURL(result.url); }, [result]);

  const canSubmit =
    !!cover && !!payload && !busy && (!encrypt || passphrase.length > 0);

  async function submit() {
    if (!cover || !payload) return;
    setBusy(true);
    setError(null);
    setResult((old) => {
      if (old) URL.revokeObjectURL(old.url);
      return null;
    });
    try {
      const blob = await api.embed(cover, payload, {
        passphrase,
        encrypt,
        compress,
        bits,
        channels,
        mode,
      });
      setResult({ url: URL.createObjectURL(blob), size: blob.size });
    } catch (e) {
      setError(e instanceof api.ApiError ? e.message : "embed failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <section className="panel space-y-5 p-5">
        <Dropzone
          label="Cover image"
          hint="PNG or BMP — lossless only"
          accept="image/png,image/bmp"
          file={cover}
          onFile={setCover}
          preview
        />
        <Dropzone
          label="Payload"
          hint="any file"
          file={payload}
          onFile={setPayload}
        />

        <CapacityMeter
          capacityBytes={cap}
          payloadBytes={payload?.size ?? 0}
          loading={capLoading}
        />

        <div>
          <label htmlFor="pass" className="mb-1.5 block text-sm font-medium text-ink-300">
            Passphrase
          </label>
          <input
            id="pass"
            type="password"
            className="field"
            autoComplete="new-password"
            placeholder={encrypt ? "required" : "optional (seeds keyed scatter)"}
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
          />
          <p className="mt-1 text-xs text-ink-500">
            Does two jobs: derives the AES-256-GCM key and seeds the pseudo-random
            LSB scatter.
          </p>
        </div>

        <fieldset className="grid grid-cols-2 gap-3">
          <legend className="sr-only">Embedding options</legend>
          <label className="text-xs text-ink-300">
            bits / channel
            <select
              className="field mt-1"
              value={bits}
              onChange={(e) => setBits(Number(e.target.value))}
            >
              {[1, 2, 3, 4].map((b) => (
                <option key={b} value={b}>{b}</option>
              ))}
            </select>
          </label>
          <label className="text-xs text-ink-300">
            channels
            <select
              className="field mt-1"
              value={channels}
              onChange={(e) => setChannels(e.target.value)}
            >
              {["RGB", "R", "G", "B", "RGBA"].map((c) => (
                <option key={c} value={c}>{c}</option>
              ))}
            </select>
          </label>
          <label className="text-xs text-ink-300">
            mode
            <select
              className="field mt-1"
              value={mode}
              onChange={(e) => setMode(e.target.value as "keyed" | "sequential")}
            >
              <option value="keyed">keyed (scattered)</option>
              <option value="sequential">sequential</option>
            </select>
          </label>
          <div className="flex flex-col justify-end gap-1.5 text-xs text-ink-300">
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={encrypt}
                onChange={(e) => setEncrypt(e.target.checked)}
              />
              encrypt
            </label>
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={compress}
                onChange={(e) => setCompress(e.target.checked)}
              />
              compress
            </label>
          </div>
        </fieldset>

        {mode === "sequential" && (
          <p className="rounded border border-verdict-suspicious/40 bg-verdict-suspicious/10 p-2.5 text-xs text-verdict-suspicious">
            Sequential fills LSBs left to right, which a chi-square test detects
            in seconds. Keyed mode exists for exactly this reason — use it unless
            you are deliberately generating a detectable sample for training.
          </p>
        )}

        <button
          className="btn btn-primary w-full"
          disabled={!canSubmit}
          onClick={submit}
        >
          {busy ? "Embedding…" : "Embed"}
        </button>

        {error && (
          <p role="alert" className="text-sm text-verdict-stego">{error}</p>
        )}
      </section>

      <section className="panel p-5">
        <h2 className="mb-3 text-sm font-medium text-ink-300">Result</h2>
        {result ? (
          <div className="space-y-3">
            <img
              src={result.url}
              alt="Stego image result"
              className="w-full rounded-lg border border-base-700"
            />
            <p className="num text-xs text-ink-500">
              {api.formatBytes(result.size)} · visually identical to the cover
            </p>
            <a className="btn btn-primary w-full" href={result.url} download="stego.png">
              Download stego.png
            </a>
          </div>
        ) : (
          <p className="text-sm text-ink-500">
            The stego image appears here. It will look identical to the cover —
            that is the point. Run it through <strong>Detect</strong> to see what
            the blue-team side finds.
          </p>
        )}
      </section>
    </div>
  );
}
