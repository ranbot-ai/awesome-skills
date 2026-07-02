---
name: design-system
description: Mechanical implementation invariants for frontend design: token architecture, typography hierarchy, loading order, FOUT prevention, chrome stability, motion timing, color semantics. Use with design wh
category: Document Processing
source: antigravity
tags: [react, ai, design, document, image, security, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-system
---


# Design system
## When to Use

Use this skill when you need mechanical implementation invariants for frontend design: token architecture, typography hierarchy, loading order, FOUT prevention, chrome stability, motion timing, color semantics. Use with design when building components, pages, or design systems. (Aesthetic direction lives in...


Apply with **design** when implementing UI: components, pages, or design systems. Every color, type, and motion choice should trace back to these rules.

## Token architecture

All colors map to a small set of primitives. No random hex values.

- **Foreground**: Text hierarchy (primary, secondary, muted).
- **Background**: Surface elevation (base, raised, overlay).
- **Border**: Separation hierarchy (subtle, default, emphasis).
- **Brand**: Identity and primary accent.
- **Semantic**: Destructive, warning, success (and optional info).

Use tokens in code (CSS variables, theme objects); never hardcode hex for UI.

## Typography

- **Hierarchy**: Headlines — heavier weight, tighter letter-spacing for presence. Body — comfortable weight for readability. Labels/UI — medium weight, works at smaller sizes. Data — monospace, `tabular-nums` for alignment.
- Combine size, weight, and letter-spacing so hierarchy is clear at a glance. If you squint and can't tell headline from body, hierarchy is too weak.
- **Fonts**: pair a display font with a body font; keep hierarchy legible at a glance. *Which* fonts is direction, not mechanics — pick from the domain and push off your first/default instinct (the mean); see design-spatial §2.
- **Data (functional only)**: real aligned numbers, IDs, timestamps in monospace with `tabular-nums` — mono earns its place when values line up in a column. Do NOT sprinkle mono on decorative eyebrow/metadata microtext ("35MM · DEVELOP · SCAN", fake spec captions) for a "technical" look — that's the current trend-slop, not data. See design-spatial §2.

## Loading order — first seen, first loaded

The first viewport must paint complete and correct, fast. Order every resource by whether the user sees it first; the rest waits.

- **Prioritize only the above-the-fold set** (hero text, hero image/video, brand mark). Preloading everything is the same as preloading nothing — the true criticals lose the bandwidth race. Pick the few things in the first screenful and prioritize *those*.
- **Fonts: self-host WOFF2.** Convert OTF/TTF → WOFF2 (Brotli; ~half the bytes, identical glyphs) and `<link rel="preload" as="font" type="font/woff2" crossorigin>` the weights used in the first viewport. Never a render-blocking third-party font stylesheet — a Google Fonts `<link>` adds a CSS round-trip plus extra DNS/TLS before the font even starts downloading; self-host instead.
- **LCP image/video:** `fetchpriority="high"` on the hero image (or the video poster); `<link rel="preload" as="image">` it when it's CSS-referenced (the parser can't see CSS `url()`s early). The hero box must never be empty — ship a poster/low-res placeholder so there's no blank frame.
- **Below the fold:** `loading="lazy" decoding="async"` on images; `preload="none"` (or `"metadata"`) on video; `defer` non-critical JS. Always reserve space (`aspect-ratio`, or `width`+`height`) so deferred media can't shift layout (CLS).
- Keep the render-blocking head minimal: inline critical CSS, defer the rest.

## Never let fonts pop in (no FOUT) — ever

`font-display: swap` **is** the pop — it paints a fallback face, then swaps to the webfont and reflows. Do not use it for any text the user watches load (titles, wordmarks, hero copy). The rule is absolute: title/display text must never flash a fallback or reflow.

- **Gate visibility on the real font.** Synchronously in `<head>`, add a `fonts-pending` class to `<html>` that holds the display-font text at `opacity: 0`. On `document.fonts.ready` — kick it with `document.fonts.load('<weight> 1em "Family"')` for each critical face — swap to `fonts-ready` and fade the text in (~0.5s). Always include a safety timeout (~2.5s) that reveals regardless, so a font failure can never leave text permanently hidden.
- Pair this with preload + WOFF2 (above) so the hidden window is a few hundred ms, not seconds — the fade reads as intentional, not as a stall.
- For body text where a sub-perceptual swap is tolerable, at minimum kill the reflow: define a fallback `@font-face` (or `font-family` fallback) tuned with `size-adjust` / `ascent-override` / `descent-override` so the fallback occupies the same metrics as the webfont and the swap shifts nothing.

Worked example — an AR product-research page: a head script toggles `fonts-pending → fonts-ready` (titles fade in on `fonts.ready`, 2.5s fallback), preloads the four above-the-fold WOFF2 weights, and self-hosts the brand face so there's no Google round-trip.

## Slow-loading content — never show the ugly intermediate state

Anything that *could* take a noticeable moment to be ready — fonts (above), large images, video, `<canvas>` scen
