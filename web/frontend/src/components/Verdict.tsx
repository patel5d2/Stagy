import { formatProb } from "../api";
import type { Detection, Signal, Verdict } from "../api";

/**
 * Verdict + per-signal breakdown.
 *
 * Shows the evidence, not just the label. An analyst who cannot see *which*
 * detector fired cannot judge whether to trust the verdict, and a bare
 * "likely-stego" is not actionable in a report.
 */

const STYLE: Record<Verdict, { text: string; bg: string; label: string }> = {
  clean: {
    text: "text-verdict-clean",
    bg: "bg-verdict-clean/10 border-verdict-clean/40",
    label: "Clean",
  },
  suspicious: {
    text: "text-verdict-suspicious",
    bg: "bg-verdict-suspicious/10 border-verdict-suspicious/40",
    label: "Suspicious",
  },
  "likely-stego": {
    text: "text-verdict-stego",
    bg: "bg-verdict-stego/10 border-verdict-stego/40",
    label: "Likely stego",
  },
};

function SignalRow({ s }: { s: Signal }) {
  const pct = Math.round(Math.max(0, Math.min(1, s.score)) * 100);
  return (
    <li className="border-t border-base-700 py-2.5 first:border-t-0">
      <div className="flex items-baseline justify-between gap-3">
        <span className="num text-sm text-ink-100">{s.name}</span>
        <span className="num text-xs text-ink-300">{s.score.toFixed(3)}</span>
      </div>
      <div className="my-1.5 h-1 overflow-hidden rounded-full bg-base-800">
        <div
          className="h-full rounded-full bg-accent-500"
          style={{ width: `${pct}%` }}
        />
      </div>
      <p className="text-xs leading-relaxed text-ink-500">{s.detail}</p>
    </li>
  );
}

export function VerdictPanel({ d }: { d: Detection }) {
  const st = STYLE[d.verdict];
  return (
    <div className="space-y-4">
      <div className={`rounded-lg border p-4 ${st.bg}`}>
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <span className={`text-lg font-semibold ${st.text}`}>{st.label}</span>
          <span className="num text-sm text-ink-300">
            P(stego) = {formatProb(d.probability)}
          </span>
        </div>
        <p className="num mt-1.5 text-xs text-ink-500">
          prior {formatProb(d.prior)} · flags at {formatProb(d.flag_threshold)}
        </p>
        {!d.calibrated && (
          <p className="mt-2 text-xs text-verdict-suspicious">
            Not fully calibrated — at least one signal fell back to a heuristic
            weight, so treat this probability as indicative, not measured.
          </p>
        )}
      </div>

      <div>
        <h3 className="mb-1 text-sm font-medium text-ink-300">Signals</h3>
        <ul className="panel px-3 py-1">
          {d.signals.map((s) => (
            <SignalRow key={s.name} s={s} />
          ))}
        </ul>
      </div>
    </div>
  );
}

export function BitPlane({ b64 }: { b64: string }) {
  return (
    <figure>
      <figcaption className="mb-1.5 text-xs text-ink-500">
        LSB bit-plane — a clean photo looks like static; structure, banding, or a
        sharp noise boundary means data
      </figcaption>
      <img
        src={`data:image/png;base64,${b64}`}
        alt="Least-significant bit plane of the analyzed image"
        className="w-full rounded-lg border border-base-700 bg-base-800 [image-rendering:pixelated]"
      />
    </figure>
  );
}
