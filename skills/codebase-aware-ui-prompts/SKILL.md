---
name: codebase-aware-ui-prompts
description: Transform product requirements into precise, architecture-preserving UI implementation prompts for Cursor, Claude Code, v0, Lovable, and Stitch without duplicating packages or breaking design tokens. 
category: Document Processing
source: antigravity
tags: [react, node, pdf, markdown, api, claude, ai, agent, llm, template]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/codebase-aware-ui-prompts
---


# Codebase-Aware UI Implementation Prompts

Transform feature requests and visual requirements into precise, architecture-preserving implementation briefs for AI coding agents (**Cursor, Claude Code, Antigravity CLI, GitHub Copilot**) and UI generators (**v0.dev, Lovable, Bolt.new, Google Stitch**).

This skill enforces strict codebase discovery, token reuse, dependency preservation, component-applicable interaction states, and five-tier verification to prevent AI code generation from introducing duplicate libraries, hardcoded hex colors, and broken accessibility patterns.

---

## 1. Concrete Division of Labor (Skill Boundaries)

To prevent duplication and context bloat across agent interactions, adhere strictly to these ownership boundaries:

| Domain Area | Codebase-Aware UI Prompts (This Skill) | UI/UX Pro Max (`ui-ux-pro-max`) | Design System (`design-system`) | Cinematic UI/UX (`cinematic-ui-ux`) |
| :--- | :--- | :--- | :--- | :--- |
| **Primary Mission** | Transforms feature requests into architecture-preserving prompts & implementation briefs. | Reference catalog of 50+ styles, 96 palettes, 57 font pairings, and 99 UX heuristics. | Mechanical rules for token architecture, FOUT prevention, and loading order. | Production GSAP timelines, Lenis smooth scroll, canvas frame scrubbing, route transitions. |
| **Existing Codebases** | Audits installed packages, forces reuse of `@/components/ui/*` and existing CSS variables. | Look up optimal aesthetic style for a domain. | Defines 3-tier token hierarchy from scratch. | Animates existing components with physics and gesture mechanics. |
| **Prompt Engineering** | Platform-specific contracts (Cursor, v0, Lovable, Stitch) with applicable state matrices. | None; reference lookup. | None; CSS guidelines. | Illustrative Playwright E2E motion test fixtures. |
| **Interaction States** | Calibrated matrix defining which of the 8 states apply to which component types. | General UX guidelines on touch targets and hover states. | Surface elevation tokens (base, raised, overlay). | Decorator pause controller and reduced-motion branches. |
| **Dependency Guard** | Forbids installing competing packages or hardcoding hex colors. | Recommends libraries based on technology stack. | Forbids arbitrary hex colors in CSS tokens. | Coordinates Lenis with ScrollTrigger ticker authority. |

---

## 2. The Five Core Preservation Invariants

When prompting an AI agent to build a feature inside an existing codebase, enforce these non-negotiable constraints:

1. **Zero New Competing Dependencies**: Never install a package if an equivalent already exists in `package.json` (e.g., do not add `framer-motion` if `motion` or `tailwindcss-animate` is present; do not add `lucide-react` if `@radix-ui/react-icons` is present).
2. **Token Inheritance Over Hex Values**: Never allow hardcoded hex colors (`bg-[#0B0F19]`). All visual styles must inherit existing semantic CSS variables or theme classes (`bg-background`, `bg-card`, `text-card-foreground`, `border-border`, `text-primary`).
3. **Component Composition Over Duplication**: Never re-scaffold a basic primitive. If `button.tsx` or `dialog.tsx` exists in `@/components/ui/`, the prompt must instruct the agent to import and compose it.
4. **Synthetic Data Disclosure**: All mock metrics, user names, and test records must carry explicit `isMock: true` properties or `[MOCK_DATA]` labels to prevent placeholder data from masquerading as verified live telemetry.
5. **Non-Destructive File Scope**: Confine code creation to dedicated feature directories (e.g., `@/components/features/[feature-name]/[component].tsx`). Prohibit unauthorized overwrites of root configs (`package.json`, `tailwind.config.*`, `app/layout.tsx`).

---

## 3. Seven-Stage Codebase Discovery Protocol

Before writing an implementation prompt or generating UI code, inspect these seven structural dimensions:

1. **Framework & Runtime**: Detect Next.js App Router (requires `'use client'` for hooks), Pages Router, Vite/SPA, or Astro.
2. **Component Foundation**: Detect existing primitives: shadcn/ui with Radix UI vs modern Base UI (`@base-ui/react`), Mantine, or custom primitives.
3. **Styling Engine**: Detect Tailwind CSS v3 (`tailwind.config.*`) vs Tailwind CSS v4 (`@theme` in CSS), CSS Modules, or CSS-in-JS.
4. **Iconography System**: Detect installed icon library (`lucide-react`, `@radix-ui/react-icons`, `@heroicons/react`).
5. **Data & State Boundaries**: Detect Server Actions, TanStack Query, SWR, or local React state.
6. **Form & Validation**: Detect `react-hook-form` + `zod` vs native form elements.
7. **Testing & Quality Tooling**: Detect Playwright, Vitest, Jest, and existing accessibility test configurations.

*See [references/codebase-discovery-protocol.md](references/codebase-discovery-protocol.md) for detailed detection heuristics and the JSON audit output schema.*

---

## 4. Platform-Specific Prompt Contracts

Select the exact contract matching the execution environment:
