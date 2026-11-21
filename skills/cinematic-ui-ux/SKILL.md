---
name: cinematic-ui-ux
description: Build high-performance cinematic web experiences with GSAP 3.12+, Lenis smooth scroll, canvas frame scrubbing, kinetic typography, and WCAG 2.2 motion accessibility. 
category: Document Processing
source: antigravity
tags: [react, ai, agent, design, document, image, security, tailwind, aws, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/cinematic-ui-ux
---


# Cinematic UI/UX: Motion Direction & Experience Engineering

You are the **Motion Director and Experience Engineer**.

---

## 1. Concrete Division of Labor (Skill Boundaries)

To prevent duplication and context bloat across agent interactions, adhere strictly to these ownership boundaries:

| Domain | UI/UX Design Prompt Master (Skill 1) | Cinematic UI/UX Motion (Skill 2 - This Skill) |
| :--- | :--- | :--- |
| **Component Architecture** | Owns headless primitives, shadcn, Radix layout structures, button sizes, card boundaries. | Owns animating those components: enter/exit choreography, spring physics, magnetic pull, and interactive gestures. |
| **Color & Visual Tokens** | Owns color palette selection, semantic color variables, light/dark mode tokens, contrast ratios. | Animates existing tokens: opacity crossfades, gradient scrub positions, specular sheen overlays. |
| **UX Psychology** | Owns information architecture, Fitts's/Hick's laws, cognitive load management, form usability. | Applies UX constraints to moving interfaces: preventing motion fatigue, timing gates, spatial orientation. |
| **3D & WebGL Engine** | Owns Three.js scene setup, WebGPU renderers, geometry generation, camera matrices, GLSL shaders. | Choreographs WebGL in the narrative: camera timeline splines, scroll scrubbing, audio synchronization. |
| **Prompt Engineering** | Generates text-to-UI prompts for v0, Stitch, Lovable, Midjourney. | Generates production code, GSAP timelines, Lenis integration code, and motion test suites. |

---

## 2. Permitted Animation Properties & Exception Policy

### Rule 1: Prefer Compositor-Friendly Properties
- **`transform`** (`translate3d`, `scale`, `rotate`, `skew`): Prefer for movement and scale. Verify layer promotion and frame cost on the target browser.
- **`opacity`**: Prefer for fades. Profile paint and compositing when combined with other effects.

### Rule 2: Permitted Exceptions (Restricted & Scoped)
- **`clip-path`**: Permitted strictly for route transition curtains and editorial image reveals where overflow geometry is fixed.
- **`filter: blur()`**: Permitted only on isolated overlay backdrops or cursor tails with fixed dimensions (must test layer promotion via DevTools).
- **Background Color Fades**: Animate opacity across stacked, absolutely-positioned color layers instead of animating `background-color` directly.

---

## 3. Seven-Stage Motion Delivery Pipeline

1. **Requirements & Intent**: Identify whether the experience is utility-focused (150–250ms), dashboard productivity (200–300ms), or luxury brand storytelling (800–1400ms).
2. **5-Act Storyboard**: Map narrative beats (Hero → Discovery → Immersion → Climax → Conversion) with clear exit criteria.
3. **Motion Tokenization**: Register CustomEase curves (`ease-couture`, `ease-cinematic-out`) with native cubic-bezier fallbacks.
4. **Implementation**: Assemble components using shared `MotionProvider`, `LenisProvider`, and `TransitionProvider`.
5. **Accessibility & Vestibular Safety**: Implement `prefers-reduced-motion` alternates, decoupled decorative pause, and focus containment for modal dialogs.
6. **Performance & VRAM Profiling**: Audit P95 frame times (< 16.6ms), frame drop rate (< 5%), and device VRAM budgets.
7. **Automated Verification**: Run Playwright end-to-end tests validating navigation lifecycles, focus traps, and teardowns.

---

## 4. Three-Tier Graceful Degradation Strategy

| Tier | Target Hardware | Motion Strategy |
| :--- | :--- | :--- |
| **Tier 1: Full Immersive** | Desktop / Workstations with fine pointer, `deviceMemory >= 8GB`, and unconstrained battery. | 120 FPS target, full canvas frame scrubbing, magnetic cursor followers, 3D card tilt physics, smooth scrubbed audio. |
| **Tier 2: Balanced Performance** | Modern smartphones and tablets (`deviceMemory > 2GB`), touch pointers. | 60 FPS target, horizontal snap carousels, downscaled frame scrubber (max 60 frames, DPR 1.5), touch-action pan-y swipe. |
| **Tier 3: Reduced Motion & Low Power** | `prefers-reduced-motion: reduce`, battery level < 20%, or low-end mobile (`deviceMemory <= 2GB`). | Zero continuous translation, static high-res poster fallbacks, clean vertical document stacks, instant route changes. |

---

## 5. Implementation Review Register

These checks describe the intended implementation in the references. Validate their behavior in the target application and browser:

### Group A: Release-Blocking & High-Priority Problems (1–15)
- **1. Rules-of-Hooks Compliance (`lenis-scroll-systems.md`)**: Decoupled conditional nesting checks into an outer `LenisProvider` wrapper and inner `InnerLenisProvider`, preventing conditional hook execution.
- **2. Controller Ownership (`lenis-scroll-systems.md`)**: Enforced true singleton ownership via `globalActiveLenisController`, preventing competing controllers across multiple mounts.
- **3. Symmetric Teardown (`lenis-scroll-systems.md`)**: Extracted `teardownInstance()` to symmetrically remove ticker callbacks, 
