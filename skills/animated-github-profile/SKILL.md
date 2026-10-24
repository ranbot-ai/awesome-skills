---
name: animated-github-profile
description: Build high-impact, animated GitHub profile READMEs that play like mini-movies using pure SVG, CSS, and SMIL animations. Covers dark/light theme switching, swinging lanyard ID badges, tech orbits, loca
category: Document Processing
source: antigravity
tags: [python, javascript, typescript, markdown, api, claude, ai, agent, gpt, workflow]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/animated-github-profile
---


# Animated GitHub Profile Skill

A comprehensive guide and agent instruction set for designing, generating, and deploying animated GitHub profile READMEs that work within GitHub's JavaScript restrictions using pure SVG and CSS/SMIL animations.

---

## When to Use This Skill

- Use when designing, revamping, or generating an animated GitHub profile README (`username/username`).
- Use when working within GitHub's Markdown HTML sanitization to render interactive or motion elements using pure SVG, CSS `@keyframes`, and SMIL.
- Use when creating theme-adaptive assets (dark/light mode) using `<picture>` elements.
- Use when automating dynamic contribution graphs, snakes, or 3D cityscapes via GitHub Actions.

---

## Why SVG Animations?

1. **GitHub Security Model**: GitHub sanitizes all Markdown files and strips out all `<script>` tags, inline JavaScript, and iframes. Normal web motion libraries (Framer Motion, GSAP, Three.js) cannot execute in a GitHub README.
2. **Native SVG Motion**: Pure SVG with `@keyframes` CSS and SMIL (`<animate>`, `<animateTransform>`) is one animation option; animated GIFs are another, and SVG animation support varies by browser and image context.
3. **Zero Third-Party Downtime**: Unlike external status generators (e.g., `github-readme-stats`, `shields.io`) that frequently fail when GitHub API rate-limits are reached, self-contained SVGs committed to the profile repository avoid a live third-party generator dependency, though rendering and cache behavior still need testing.

---

## Architectural Layout

A top-tier animated profile combines the following modules stacked vertically in `README.md`:

```text
┌────────────────────────────────────────────────────────┐
│ 1. HERO BANNER (Dark / Light Auto-Switching via <picture>)
│    - Typing terminal prompt & blinking cursor          │
│    - Shimmering gradient name (letter-by-letter reveal)│
│    - Cycling typed role headlines                      │
│    - Hologram scanline laser sweep                     │
│    - Live code editor typing real project snippet      │
├──────────────────────────┬─────────────────────────────┤
│ 2. SWINGING LANYARD      │ 3. 3D TECH ORBIT            │
│    - Damped pendulum     │    - Satellites orbiting    │
│      swing physics       │      an atomic core         │
│    - Holographic glare   │    - Categorized capability │
│    - Avatar & barcode    │      matrix                 │
├──────────────────────────┴─────────────────────────────┤
│ 4. FEATURED ENGINEERING & WORKFLOW PROJECTS (Markdown) │
├────────────────────────────────────────────────────────┤
│ 5. AUTOMATED CONTRIBUTION VISUALIZER                   │
│    - Snake eating contribution dots (Platane/snk) OR   │
│    - 3D Isometric Night Skyline City                   │
├────────────────────────────────────────────────────────┤
│ 6. VERIFIED TECH BADGES & CONNECT LINKS                │
└────────────────────────────────────────────────────────┘
```

---

## Step-by-Step Implementation Workflow

### Step 1: Character Art / Avatar Generation

Prompt any AI image generator (ChatGPT/DALL-E, Midjourney, Gemini) to generate a clean character illustration. A pure white or transparent background is critical for clean cutouts.

#### Master Character Prompt:
```text
High-quality anime-style digital illustration of a young developer sitting relaxed in a sleek modern ergonomic chair with a dark laptop on their lap, softly smiling at the viewer. Sunglasses resting on head, wearing a cozy dark zip-up hoodie over a tech t-shirt, jeans. Beside them on a small glass-top table: a stack of programming books with spines reading "Python", "Agentic AI", "Docker", "System Architecture"; a takeaway coffee cup with "Code. Coffee. Repeat." written on it; and a small potted desk plant. Pure white background, warm soft rim lighting, clean detailed anime art style, vibrant colors, high resolution, full body in frame.
```

*Tip: Generate 3–4 variations and select the one with the cleanest edges and clearest facial crop for the lanyard badge.*

---

### Step 2: Generate Core Animated SVGs

Use the master prompts below with an AI coding assistant to create standalone SVG files.

#### 1. Hero Banner (`banner.svg` & `banner-light.svg`)
* **Dimensions**: `viewBox="0 0 1200 480"` (responsive, width="100%").
* **Left Section**:
  * macOS window control dots (`#ef4444`, `#f59e0b`, `#10b981`).
  * Live status pill with pulsing green indicator (`OPEN TO COLLABS`).
  * Terminal greeting `$ whoami --verbose`.
  * Bold name with animated multi-stop SVG gradient shimmer.
  * Cycling role headlines using CSS `@keyframes` with staggered opacities.
  * Value proposition and meta pills (Location, Experience, Roles).
* **Right Section**:
  * Simulated IDE code editor window (`0.95` opacity).
  * Syntax-highlighted code snippet typing out core domain logic (e.g. Python, Agentic AI, TypeScript).
  * Blinking rectangular cursor (`#22d3ee`).
* **Motion FX**:
  * Full-width laser scanner bar sweeping t
