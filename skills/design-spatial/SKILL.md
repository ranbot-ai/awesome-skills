---
name: design-spatial
description: Design — spatial composition 
category: Document Processing
source: antigravity
tags: [python, mcp, ai, agent, template, design, document, image, security, aws]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-spatial
---


# Design — spatial composition
## When to Use

Use this skill when you need design — spatial composition.


A model cannot trust its own UI output. Everything else follows from two failures.

## 1. It can't see what it made

UI is generated as a token stream, never as pixels — so the model cannot perceive collisions, overlap, imbalance, or broken spacing. It will write a headline that runs into the hero image and have no idea.

**Render it and judge the image, not the code.** Serve with any static server (e.g. `python3 -m http.server` or `npx serve`) and screenshot headless via Playwright. Screenshot at a few widths.

**Critique with fresh eyes — not your own.** Grading your own output rationalizes it; the builder looks at its overlapping headline and calls it fine (this is exactly how a real collision shipped in testing). Use a separate judge — a subagent that did *not* write the page — and tell it to hunt for what's *wrong*: collisions, edge tangents, ragged alignment, lopsided weight, no clear focal point, breaks at some width. Fix, re-render, re-judge.

## 2. Its first idea is the average

Whatever it produces first is the mean of its training data — and there is more than one mean:

- the **generic-AI mean**: Inter, purple-on-white gradients, centered single column, three equal cards;
- the **designer-trend mean**: oversized condensed caps, dark-mode + grain, monospace "vibes" microtext, sticker badges.

Landing on the second isn't taste — it's a more flattering average, which is why it slips past. **Treat your first instinct as the mean and deviate deliberately — toward *this product's specific world*** (use design-thinking's domain / color-world / signature as the direction), **not toward another trend.** If the result could be any startup, you shipped the mean.

## 3. So don't prescribe a style

Any fixed rule — a 12-col grid, an 8-point scale, "mono = data" — *becomes* next cycle's mean, and a blind model executes it into collisions anyway. Prescribe the **process, not the look**: see it with fresh eyes, and push off the average toward the domain. Taste supplies the direction (design-thinking / design-philosophy); this skill only insists you **look** and **don't ship the mean**.

For iterative spatial tuning, a local page with live controls (sliders, pickers, drag handles) beats one-shot critique.

## 4. NEVER ship horizontal overflow — THE mandatory gate, no exceptions

> **BLOCKING GATE. You may not call any web UI "done", "working", "fixed", or
> "looks good" until you have run the `scrollWidth` check below at a narrow width
> THIS turn and seen `0`. Not "I added overflow-x:clip so it's fine." Not "it
> looked fine at my width." MEASURE. Narrow. Every time. If you didn't measure,
> it isn't done — say "haven't checked overflow yet" instead of claiming done.**

A side-to-side scrollbar that doesn't match the content is the **single most common
and most embarrassing** layout failure, and it ships *over and over* because the dev
viewport is wide enough to hide it — the overflow only appears once the window is
narrower than some element. It is **invisible at desktop width**, so the §1
render-critique loop will NOT catch it unless you screenshot narrow. Separate,
explicit, non-negotiable gate.

**It recurs because layouts GROW after they were last checked.** Every time you add a
nav tab, a toolbar button, a header control, a chip, a wider equation/`<pre>`, or any
new item to a `flex`/`inline` row, you have invalidated the last overflow check — the
row that fit yesterday now pushes past the edge between ~720–1200px while your 1440px
dev window shows nothing wrong. (Real ship, 2026-06, TWICE: a progress-bar edge label
overflowed 23px; then a `flex-wrap:nowrap` header that grew 4 tabs scrolled the whole
page 309px across 720–1200px — both invisible at dev width, both caught only by
measuring narrow.) **So: any change that adds an element to a horizontal row re-arms
this gate. Re-measure.**

**Default defenses to apply up front (so the gate passes by construction):**
- **Header / nav / toolbar rows: `flex-wrap: wrap`, never `nowrap`.** A growing
  single-row flex is the #1 source of this bug. Wrapping is a no-op when it fits and
  saves you when it doesn't.
- **`body { overflow-x: clip }`** as a backstop on every app (clip, not hidden — keeps
  sticky/anchored layouts working). A backstop, NOT a substitute for measuring.

**The check — run before calling ANY page done:** `document.documentElement.scrollWidth - document.documentElement.clientWidth` must equal `0`, tested at your dev width AND resized narrow (≤1024px, and a phone width ~390px). If > 0, find the offender:
```js
document.querySelectorAll('*').forEach(el=>{const r=el.getBoundingClientRect();
  if(r.right>innerWidth+1||r.left<-1) console.log(Math.round(r.right), el);});
```

**Safety net:** `overflow-x: clip` on `body` (prefer `clip` over `hidden` — it clips without creating a scroll container, so it won't break `position:sticky`/anchored lay
