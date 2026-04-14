---
name: landing-page-generator
description: Generates high-converting Next.js/React landing pages with Tailwind CSS. Uses PAS, AIDA, and BAB frameworks for optimized copy/components (Heroes, Features, Pricing). Focuses on Core Web Vitals/SEO. 
category: Document Processing
source: antigravity
tags: [react, nextjs, claude, ai, workflow, template, design, spreadsheet, image, tailwind]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/landing-page-generator
---


# Landing Page Generator

Generate high-converting landing pages from a product description. Output complete Next.js/React components with multiple section variants, proven copy frameworks, SEO optimization, and performance-first patterns. Not lorem ipsum — actual copy that converts.

**Target:** LCP < 1s · CLS < 0.1 · FID < 100ms  
**Output:** TSX components + Tailwind styles + SEO meta + copy variants

## When to Use
- You need to generate a marketing landing page in Next.js or React.
- The task involves conversion-focused page structure, section variants, Tailwind styling, or SEO-aware copy.
- You want complete landing-page output from a product description rather than isolated UI fragments.

## Core Capabilities

- 5 hero section variants (centered, split, gradient, video-bg, minimal)
- Feature sections (grid, alternating, cards with icons)
- Pricing tables (2–4 tiers with feature lists and toggle)
- FAQ accordion with schema markup
- Testimonials (grid, carousel, single-quote)
- CTA sections (banner, full-page, inline)
- Footer (simple, mega, minimal)
- 4 design styles with Tailwind class sets

---

## Generation Workflow

Follow these steps in order for every landing page request:

1. **Gather inputs** — collect product name, tagline, audience, pain point, key benefit, pricing tiers, design style, and copy framework using the trigger format below. Ask only for missing fields.
2. **Analyze brand voice** (recommended) — if the user has existing brand content (website copy, blog posts, marketing materials), run it through `marketing-skill/content-production/scripts/brand_voice_analyzer.py` to get a voice profile (formality, tone, perspective). Use the profile to inform design style and copy framework selection:
   - formal + professional → **enterprise** style, **AIDA** framework
   - casual + friendly → **bold-startup** style, **BAB** framework
   - professional + authoritative → **dark-saas** style, **PAS** framework
   - casual + conversational → **clean-minimal** style, **BAB** framework
3. **Select design style** — map the user's choice (or infer from brand voice analysis) to one of the four Tailwind class sets in the Design Style Reference.
4. **Apply copy framework** — write all headline and body copy using the chosen framework (PAS / AIDA / BAB) before generating components. Match the voice profile's formality and tone throughout.
5. **Generate sections in order** — Hero → Features → Pricing → FAQ → Testimonials → CTA → Footer. Skip sections not relevant to the product.
6. **Validate against SEO checklist** — run through every item in the SEO Checklist before outputting final code. Fix any gaps inline.
7. **Output final components** — deliver complete, copy-paste-ready TSX files with all Tailwind classes, SEO meta, and structured data included.

---

## Triggering This Skill

```
Product: [name]
Tagline: [one sentence value prop]
Target audience: [who they are]
Key pain point: [what problem you solve]
Key benefit: [primary outcome]
Pricing tiers: [free/pro/enterprise or describe]
Design style: dark-saas | clean-minimal | bold-startup | enterprise
Copy framework: PAS | AIDA | BAB
```

---

## Design Style Reference

| Style | Background | Accent | Cards | CTA Button |
|---|---|---|---|---|
| **Dark SaaS** | `bg-gray-950 text-white` | `violet-500/400` | `bg-gray-900 border border-gray-800` | `bg-violet-600 hover:bg-violet-500` |
| **Clean Minimal** | `bg-white text-gray-900` | `blue-600` | `bg-gray-50 border border-gray-200 rounded-2xl` | `bg-blue-600 hover:bg-blue-700` |
| **Bold Startup** | `bg-white text-gray-900` | `orange-500` | `shadow-xl rounded-3xl` | `bg-orange-500 hover:bg-orange-600 text-white` |
| **Enterprise** | `bg-slate-50 text-slate-900` | `slate-700` | `bg-white border border-slate-200 shadow-sm` | `bg-slate-900 hover:bg-slate-800 text-white` |

> **Bold Startup** headings: add `font-black tracking-tight` to all `<h1>`/`<h2>` elements.

---

## Copy Frameworks

**PAS (Problem → Agitate → Solution)**
- H1: Painful state they're in
- Sub: What happens if they don't fix it
- CTA: What you offer
- *Example — H1:* "Your team wastes 3 hours a day on manual reporting" / *Sub:* "Every hour spent on spreadsheets is an hour not closing deals. Your competitors are already automated." / *CTA:* "Automate your reports in 10 minutes →"

**AIDA (Attention → Interest → Desire → Action)**
- H1: Bold attention-grabbing statement → Sub: Interesting fact or benefit → Features: Desire-building proof points → CTA: Clear action

**BAB (Before → After → Bridge)**
- H1: "[Before state] → [After state]" → Sub: "Here's how [product] bridges the gap" → Features: How it works (the bridge)

---

## Representative Component: Hero (Centered Gradient — Dark SaaS)

Use this as the structural template for all hero variants. Swap layout classes, gradient direction, and image placement for split, video-bg, and minimal variants.

```tsx
export function HeroCentered() {
  return (
    <section className="relative flex 
