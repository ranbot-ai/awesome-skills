---
name: ckw-design
description: Frontend design entry point: direction, design system, visual philosophy. Use whenever building or touching the look of any web UI (components, pages, dashboards, React/Vue/HTML-CSS) or when the user 
category: Document Processing
source: antigravity
tags: [react, api, claude, ai, llm, gpt, automation, workflow, design, document]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/ckw-design
---

## When to Use

Use whenever building or styling web UIs — components, pages, dashboards, landing pages, React/Vue/HTML-CSS layouts — or whenever the user asks to make something "look better/nicer", fix spacing/layout, or mentions styling, color, typography, fonts, responsive design, polish, or aesthetics, even without the word "design".

_Source: [connerkward/ckw-design-skill](https://github.com/connerkward/ckw-design-skill) (MIT)._

# Design (entry)

Use this skill when the user asks to build or style web UIs: components, pages, dashboards, landing pages, React/Vue/HTML-CSS layouts, or any frontend interface. Goal: distinctive, production-grade output that avoids generic AI aesthetics.

**Before reporting any design "done": render it and have a *separate* judge critique the image** (not the code, not self-grading) — see design-spatial §1. Blind generation can't see its own collisions; this applies to all design output, not just spatial work.

> **MANDATORY HORIZONTAL-OVERFLOW GATE — runs before ANY web UI is "done".**
> Measure `document.documentElement.scrollWidth - document.documentElement.clientWidth`
> at a **narrow width (~390px and ~1024px), this turn**, and confirm it's `0`. This
> bug is invisible at desktop width and re-appears every time a row (header, nav,
> toolbar) gains an item, so it ships repeatedly. Default to `flex-wrap:wrap` on
> header/toolbar rows + `body{overflow-x:clip}`, and **re-measure after adding any
> element to a horizontal row.** Full procedure + recurrence cases: design-spatial §4.
> If you haven't measured narrow, you are not done — don't claim it.

## Sub-skills (load when relevant)

- **design-thinking** — Load for every design task. Defines purpose, tone, domain, color world, review bar, and cross-domain lens (cinema, architecture, marketing, UX, automotive, industrial design). See [design-thinking/SKILL.md](https://github.com/connerkward/ckw-design-skill/blob/main/design-thinking/SKILL.md).
- **design-system** — Load when implementing: tokens, typography, motion, color semantics, backgrounds. Use when building components, pages, or design systems. See [design-system/SKILL.md](https://github.com/connerkward/ckw-design-skill/blob/main/design-system/SKILL.md).
- **design-spatial** — Load when composing layout: explicit grid + 8-point spacing constraints, visual-weight/balance/alignment, and a render-then-critique vision loop. The fix for "spatial understanding is off" — generated layout that's centered mush, misaligned, or breaks at some widths. See [design-spatial/SKILL.md](https://github.com/connerkward/ckw-design-skill/blob/main/deterministic-design/design-spatial/SKILL.md).
- **design-ux** — Load when auditing USABILITY (not just looks): a UI that "feels off"/"sucks to use", is hard to learn, needs an instruction wall, or any interactive tool/editor/app before shipping. Scores the rendered UI against Nielsen's 10 + interaction heuristics via a SEPARATE fresh-eyes judge → prioritized fix list. Usability ≠ aesthetics. See [design-ux/SKILL.md](https://github.com/connerkward/ckw-design-skill/blob/main/deterministic-design/design-ux/SKILL.md).
- **design-philosophy** — Load for high-concept work, campaigns, or when the user asks for a visual philosophy, manifesto, or unmistakable art-like aesthetic. See [design-philosophy/SKILL.md](https://github.com/connerkward/ckw-design-skill/blob/main/design-philosophy/SKILL.md).

## Visual assets — generate or source

When design-thinking identifies a need for visual assets (logos, icons, hero images, textures, backgrounds):

1. **Generate** → use an image-generation model or API for synthetic/branded assets.
2. **Source a real/archival one** → free stock or archival image search, often cheaper and more authentic than generating.
3. Use design-thinking output (tone, domain, color world) to craft prompts / queries.
4. Evaluate against the design philosophy, refine, integrate into the build.

## LLM-assisted work — always annotate model + cost

When design work involves running an LLM (generative assets, VLM analysis, layout critique, prompt generation, etc.):

- **Before running:** state which model will be used and the estimated cost (e.g., "gpt-4o-mini · ~$0.005/image" or "FLUX v1 · ~$0.006 per gen").
- **After results:** annotate the output with the model used, actual cost if different from estimate, and any key params (seed, prompt, settings). Cost goes *visible to the user* (in the message, contact sheet header, or asset caption), not buried in logs.
- **Why:** the user is deciding whether the cost-to-quality trade-off is worth it. Unlabeled or hidden costs hide the most important lever. This rule mirrors `media-attribution-rule` for generative assets and extends it to any LLM operation in the design workflow.

**Examples:**
- "Running gpt-4o-mini layout critique on 8 designs · est. ~$0.04 total" (before).
- Contact sheet header: "FLUX v1 · $0.48 total (6 gen × $0.08)" (after).
- Asset caption: "hero_banner_flux-dev_seed3891.jpg" 
