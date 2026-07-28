import { useState } from "react";
import * as api from "../api";
import { Dropzone } from "../components/Dropzone";
import { Histogram } from "../components/Histogram";
import { BitPlane, VerdictPanel } from "../components/Verdict";

export function DetectView() {
  const [suspect, setSuspect] = useState<File | null>(null);
  const [reference, setReference] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [det, setDet] = useState<api.Detection | null>(null);

  async function submit() {
    if (!suspect) return;
    setBusy(true);
    setError(null);
    setDet(null);
    try {
      setDet(await api.detect(suspect, reference));
    } catch (e) {
      setError(e instanceof api.ApiError ? e.message : "detection failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,22rem)_minmax(0,1fr)]">
      <section className="panel space-y-5 p-5">
        <Dropzone
          label="Suspect file"
          hint="PNG or BMP"
          accept="image/png,image/bmp"
          file={suspect}
          onFile={setSuspect}
          preview
        />
        <Dropzone
          label="Known-clean original"
          hint="optional"
          accept="image/png,image/bmp"
          file={reference}
          onFile={setReference}
          preview
        />
        <p className="text-xs text-ink-500">
          With a reference, detection becomes a direct comparison instead of a
          statistical inference — near-certain rather than probabilistic.
        </p>

        <button className="btn btn-primary w-full" disabled={!suspect || busy} onClick={submit}>
          {busy ? "Analyzing…" : "Analyze"}
        </button>

        {error && <p role="alert" className="text-sm text-verdict-stego">{error}</p>}

        <p className="border-t border-base-700 pt-4 text-xs text-ink-500">
          <strong className="text-ink-300">Detection floor.</strong> Small payloads
          in large covers are invisible to statistical analysis — around 0.5% fill
          reads clean. A clean verdict means "no evidence found," not "nothing
          hidden."
        </p>
      </section>

      <section className="space-y-6">
        {det ? (
          <>
            <VerdictPanel d={det} />
            <div className="panel space-y-6 p-5">
              {det.bitplane_png_b64 && <BitPlane b64={det.bitplane_png_b64} />}
              {suspect && <Histogram file={suspect} />}
            </div>
          </>
        ) : (
          <div className="panel p-5">
            <p className="text-sm text-ink-500">
              Drop a file and analyze. You will get a calibrated verdict, the
              per-detector evidence behind it, the rendered LSB bit-plane, and the
              value-pair histogram that makes the embedding signature visible.
            </p>
          </div>
        )}
      </section>
    </div>
  );
}
