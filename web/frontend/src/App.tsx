import { useEffect, useState } from "react";
import * as api from "./api";
import { DetectView } from "./views/DetectView";
import { HideView } from "./views/HideView";
import { RevealView } from "./views/RevealView";

type Tab = "hide" | "reveal" | "detect";

const TABS: { id: Tab; label: string; blurb: string }[] = [
  { id: "hide", label: "Hide", blurb: "Embed an encrypted payload into a cover image." },
  { id: "reveal", label: "Reveal", blurb: "Recover a payload from a stego file." },
  { id: "detect", label: "Detect", blurb: "Analyze a file for hidden data." },
];

export default function App() {
  const [tab, setTab] = useState<Tab>("detect");
  const [health, setHealth] = useState<api.Health | null>(null);
  const [offline, setOffline] = useState(false);

  useEffect(() => {
    api.health().then(setHealth).catch(() => setOffline(true));
  }, []);

  const active = TABS.find((t) => t.id === tab)!;

  return (
    <div className="mx-auto min-h-dvh max-w-6xl px-4 py-6 sm:px-6 sm:py-10">
      <header className="mb-6">
        <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
          <h1 className="text-xl font-semibold tracking-tight">
            Stagy
            <span className="ml-2 text-sm font-normal text-ink-500">
              steganography &amp; steganalysis
            </span>
          </h1>
          <span className="num text-xs text-ink-500">
            {offline ? (
              <span className="text-verdict-stego">API unreachable</span>
            ) : health ? (
              `v${health.version} · ${health.codecs.length} codecs · max ${api.formatBytes(health.max_upload_bytes)}`
            ) : (
              "connecting…"
            )}
          </span>
        </div>
        <p className="mt-1 text-sm text-ink-500">{active.blurb}</p>
      </header>

      {offline && (
        <p role="alert" className="panel mb-6 border-verdict-stego/40 bg-verdict-stego/10 p-3 text-sm text-verdict-stego">
          Cannot reach the Stagy API. Start it with{" "}
          <code className="num">uvicorn web.backend.app:app --reload</code>.
        </p>
      )}

      {/* Tablist: roving arrow-key navigation, as the ARIA pattern requires. */}
      <div role="tablist" aria-label="Stagy workflows" className="mb-6 flex gap-1 border-b border-base-700">
        {TABS.map((t) => (
          <button
            key={t.id}
            role="tab"
            id={`tab-${t.id}`}
            aria-selected={tab === t.id}
            aria-controls={`panel-${t.id}`}
            tabIndex={tab === t.id ? 0 : -1}
            onClick={() => setTab(t.id)}
            onKeyDown={(e) => {
              const i = TABS.findIndex((x) => x.id === tab);
              if (e.key === "ArrowRight") setTab(TABS[(i + 1) % TABS.length]!.id);
              if (e.key === "ArrowLeft") setTab(TABS[(i - 1 + TABS.length) % TABS.length]!.id);
            }}
            className={`-mb-px border-b-2 px-4 py-2.5 text-sm font-medium transition-colors ${
              tab === t.id
                ? "border-accent-500 text-ink-100"
                : "border-transparent text-ink-500 hover:text-ink-300"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      <main role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>
        {tab === "hide" && <HideView />}
        {tab === "reveal" && <RevealView />}
        {tab === "detect" && <DetectView />}
      </main>

      <footer className="mt-10 border-t border-base-700 pt-4 text-xs text-ink-500">
        Authorized use only. Files are processed in memory and never persisted;
        passphrases transit the request body, so run this behind TLS.
      </footer>
    </div>
  );
}
