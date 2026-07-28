import { formatBytes } from "../api";

interface Props {
  capacityBytes: number | null;
  payloadBytes: number;
  loading: boolean;
}

/**
 * Live capacity gauge (roadmap 7.2).
 *
 * The container adds ~96 bytes of framing on top of the payload, so a payload
 * that measures just under capacity can still fail with CapacityError. The
 * meter charges for that overhead rather than showing a green bar that then
 * 422s on submit.
 */
const FRAME_OVERHEAD = 96;

export function CapacityMeter({ capacityBytes, payloadBytes, loading }: Props) {
  if (loading) {
    return <p className="num text-xs text-ink-500">measuring capacity…</p>;
  }
  if (capacityBytes === null) return null;

  const needed = payloadBytes > 0 ? payloadBytes + FRAME_OVERHEAD : 0;
  const pct = capacityBytes > 0 ? Math.min(100, (needed / capacityBytes) * 100) : 0;
  const over = needed > capacityBytes;

  return (
    <div>
      <div className="mb-1 flex items-baseline justify-between gap-2 text-xs">
        <span className="text-ink-500">capacity</span>
        <span className={`num ${over ? "text-verdict-stego" : "text-ink-300"}`}>
          {formatBytes(needed)} / {formatBytes(capacityBytes)}
        </span>
      </div>
      <div
        className="h-2 overflow-hidden rounded-full bg-base-800"
        role="progressbar"
        aria-valuenow={Math.round(pct)}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label="cover capacity used"
      >
        <div
          className={`h-full rounded-full transition-[width] duration-200 ${
            over
              ? "bg-verdict-stego"
              : pct > 80
                ? "bg-verdict-suspicious"
                : "bg-accent-500"
          }`}
          style={{ width: `${pct}%` }}
        />
      </div>
      {over && (
        <p className="num mt-1 text-xs text-verdict-stego">
          payload exceeds capacity by {formatBytes(needed - capacityBytes)} — use a
          larger cover, more bits, or enable compression
        </p>
      )}
    </div>
  );
}
