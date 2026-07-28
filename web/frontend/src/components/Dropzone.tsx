import { useCallback, useRef, useState } from "react";
import { formatBytes } from "../api";

interface Props {
  label: string;
  hint?: string;
  accept?: string;
  file: File | null;
  onFile: (f: File | null) => void;
  /** Show a thumbnail. Only meaningful for images. */
  preview?: boolean;
}

/**
 * Drag-and-drop file input.
 *
 * Keyboard- and screen-reader-operable, not just droppable: it is a real
 * <button> wrapping a hidden <input type="file">, so Enter/Space open the
 * picker. A div with an onDrop handler would strand keyboard users.
 */
export function Dropzone({ label, hint, accept, file, onFile, preview }: Props) {
  const [over, setOver] = useState(false);
  const [url, setUrl] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const take = useCallback(
    (f: File | null) => {
      setUrl((old) => {
        if (old) URL.revokeObjectURL(old);
        return f && preview ? URL.createObjectURL(f) : null;
      });
      onFile(f);
    },
    [onFile, preview],
  );

  return (
    <div>
      <div className="mb-1.5 flex items-baseline justify-between gap-2">
        <span className="text-sm font-medium text-ink-300">{label}</span>
        {hint && <span className="text-xs text-ink-500">{hint}</span>}
      </div>

      <button
        type="button"
        onClick={() => inputRef.current?.click()}
        onDragOver={(e) => {
          e.preventDefault();
          setOver(true);
        }}
        onDragLeave={() => setOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setOver(false);
          take(e.dataTransfer.files[0] ?? null);
        }}
        className={`w-full rounded-lg border border-dashed p-4 text-left transition-colors ${
          over
            ? "border-accent-500 bg-accent-600/10"
            : "border-base-600 bg-base-800/40 hover:border-base-600"
        }`}
      >
        <input
          ref={inputRef}
          type="file"
          accept={accept}
          className="sr-only"
          onChange={(e) => take(e.target.files?.[0] ?? null)}
        />
        {file ? (
          <div className="flex items-center gap-3">
            {url && (
              <img
                src={url}
                alt=""
                className="h-12 w-12 shrink-0 rounded border border-base-700 object-cover"
              />
            )}
            <div className="min-w-0">
              <div className="num truncate text-sm text-ink-100">{file.name}</div>
              <div className="num text-xs text-ink-500">{formatBytes(file.size)}</div>
            </div>
          </div>
        ) : (
          <div className="text-sm text-ink-500">
            Drop a file here, or <span className="text-accent-400">browse</span>
          </div>
        )}
      </button>

      {file && (
        <button
          type="button"
          onClick={() => take(null)}
          className="mt-1.5 text-xs text-ink-500 underline hover:text-ink-300"
        >
          clear
        </button>
      )}
    </div>
  );
}
