# Stagy design system — Task 7.3

The visual contract for the web app. Tokens live in
[`src/index.css`](src/index.css) as Tailwind v4 `@theme` variables; this
document is the reasoning behind them. Change the tokens, not the components.

> The roadmap points at a `frontend-design` skill for visual direction. That
> skill was not available in this environment, so this spec derives from the
> roadmap's own brief: *"dark security-console aesthetic (deep neutral
> background, one restrained accent, monospace for hex/technical readouts), a
> verdict color scale (green clean → amber suspicious → red likely-stego)."*

## The one rule

**Color means something here.** This is an analysis tool whose entire output is
a judgement call about a file. If the interface is decorated with color, the
verdict stops being the loudest thing on screen, and the verdict is the only
thing the user actually came for.

Everything below follows from that.

## Palette

Colors are authored in OKLCH so lightness steps are perceptually even — a
`0.17 → 0.21 → 0.25` ramp reads as three equal steps, which the same ramp in
hex does not.

### Surfaces — deep neutral, cool-shifted

| Token | Value | Use |
|---|---|---|
| `base-900` | `oklch(0.17 0.012 250)` | Page background |
| `base-850` | `oklch(0.21 0.013 250)` | Panels |
| `base-800` | `oklch(0.25 0.014 250)` | Inputs, raised surfaces |
| `base-700` | `oklch(0.32 0.015 250)` | Borders |
| `base-600` | `oklch(0.45 0.015 250)` | Emphasized borders |

Three surface levels, not five. A fourth tier produces mush — two panels a
hair apart read as a rendering bug rather than a hierarchy.

The slight cool shift (hue 250) exists so the cyan accent reads as *warmer*
than its surroundings and advances toward the viewer. On a neutral-grey base
the same cyan sits flat.

**Why this particular darkness:** bit-plane images are pure black-and-white
noise. On a white UI they read as damage; on a pure-black UI the black pixels
disappear into the page and the plane looks like it has holes. A background at
L≈0.17 is neither endpoint, so a bit-plane reads as *data* — which is the whole
point of rendering it.

### Text

| Token | Use |
|---|---|
| `ink-100` | Primary text, values |
| `ink-300` | Labels, secondary text |
| `ink-500` | Captions, hints, muted detail |

### Accent — exactly one

`accent-400/500/600`, a cyan at hue 200. **Interactive affordances only:**
buttons, focus rings, active tab, links, signal-strength bars, the capacity
meter in its normal state.

Never used for decoration, never for emphasis in prose, never on a container
that isn't clickable.

### Verdict ramp — reserved

| Token | Verdict |
|---|---|
| `verdict-clean` | `clean` — green, hue 155 |
| `verdict-suspicious` | `suspicious` — amber, hue 85 |
| `verdict-stego` | `likely-stego` — red, hue 25 |

**These three hues appear nowhere else in the interface.** Seeing red on this UI
must mean one thing. The narrow exceptions are semantically the same statement:
the capacity meter turns amber near the limit and red past it (a failure
prediction), and error text uses `verdict-stego` (a failure).

Do not add a fourth verdict color. Do not reuse green for a success toast — a
green flash after an embed would be the same hue that means "this file is
clean," in a flow where nothing was analyzed.

## Typography

Two families:

- **Sans** (system UI stack) — prose, labels, headings.
- **Mono** (`--font-mono`) — anything read character by character: filenames,
  byte counts, probabilities, signal scores, hex, version strings, code.

The `.num` utility applies mono **plus `font-variant-numeric: tabular-nums`**.
This is load-bearing, not polish: the capacity meter updates on every option
change, and proportional digits make the number jitter horizontally as it
updates. Tabular figures hold the column still.

**Probabilities never use fixed decimal places.** Calibrated thresholds run to
`1e-6`; `toFixed(4)` renders the real flag threshold of `1.288e-6` as
`0.0000`, which reads as "flags at zero" — the precise opposite of a strict
threshold. `formatProb()` switches to exponential below `1e-4`. This was a real
bug caught in the live UI, not a hypothetical.

## Layout

- Max width `72rem`, centered.
- Two-column on `lg:` and up; single column below. Detect uses an asymmetric
  `22rem` control column so evidence gets the remaining space.
- Panels: `0.75rem` radius, 1px `base-700` border, `1.25rem` padding.
- **Nothing may scroll horizontally.** Verified at 375px: zero overflowing
  elements.

## Component states

Every interactive element defines rest / hover / focus-visible / disabled.

- **Focus** is a 2px `accent-500` outline at 2px offset, on `:focus-visible`.
  Tailwind's reset removes the UA outline, and this tool is driven by keyboard
  during incident work — restoring focus is not optional.
- **Disabled** drops to `base-700` on `ink-500` with `cursor: not-allowed`.
  Disabled buttons state *why* nearby rather than leaving the user guessing.

## Accessibility

- Dropzones are real `<button>` elements wrapping a visually-hidden
  `<input type="file">`, so Enter and Space open the picker. A `<div>` with an
  `onDrop` handler strands every keyboard user.
- Tabs implement the ARIA tablist pattern with roving arrow-key navigation.
- The capacity meter is a `role="progressbar"` with live `aria-valuenow`.
- Bit-plane and histogram images carry real `alt` / `aria-label` text.
- Errors are `role="alert"`.
- `prefers-reduced-motion` collapses all transitions.

## Writing tone

Labels are plain. Explanatory text says what a control *does to the file*, not
what it is. "Sequential fills LSBs left to right, which a chi-square test
detects in seconds" beats "Embedding mode."

State limits where the user will hit them. The Detect panel says a clean
verdict means "no evidence found," not "nothing hidden" — because a user who
trusts a clean verdict on a 0.5%-fill file has been misled by the tool.
