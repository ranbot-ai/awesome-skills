---
name: frontend-lighthouse
description: Add a portable Lighthouse CI gate for production frontend builds with Core Web Vitals budgets, category floors, median runs, and CI artifacts. 
category: Creative & Media
source: antigravity
tags: [node, claude, ai, agent, workflow, image, seo, cro, marketing]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/frontend-lighthouse
---


# Frontend Lighthouse (portable performance gate)

> Portable skill — readable by Claude Code, OpenCode, Codex, Cursor, Windsurf, and others.
> This skill describes a **CI performance gate** — a Lighthouse CI config plus a workflow — not a
> component library or a visual style. It pairs with the **frontend-seo** and
> **frontend-architecture** skills: SEO writes the metadata, Lighthouse proves it ships fast.

The goal: every pull request is **blocked unless the production build meets explicit Core Web
Vitals budgets and category score floors**. Budgets live in **one** `lighthouserc.cjs`, runs are
**median-of-N** so the gate doesn't flake, and the same config runs locally and in CI.

## When to Use This Skill

- Use when adding a Lighthouse CI performance gate to a web app.
- Use when setting Core Web Vitals budgets for LCP, CLS, and TBT as the lab proxy for INP.
- Use when configuring category score floors for performance, SEO, accessibility, and best practices.
- Use when debugging flaky Lighthouse runs or making reports visible as CI artifacts.

---

## 0. The five core ideas

1. **One config, one source of truth.** All budgets and assertions live in a single `lighthouserc.cjs`. Named constants for each budget — no magic numbers buried in assertion objects.
2. **Gate the production build, never dev.** Lighthouse runs against `build` + `start` (the real, optimized output). Dev-server numbers are meaningless for a budget.
3. **Median-of-N kills flakiness.** Run 3+ times and assert on the median run, so per-run jitter (cold caches, CI noise) never red-flags a healthy build.
4. **Budgets encode Google's "good" thresholds.** LCP ≤ 2500 ms, INP ≤ 200 ms (gated via the TBT lab proxy), CLS ≤ 0.1 — the values that earn green scores, not "needs improvement".
5. **Blocking in CI, visible as artifacts.** A GitHub Action runs the gate on every PR touching the app and uploads the HTML/JSON reports so failures are debuggable.

---

## 1. Files this skill adds

```
apps/web/                          (or your app root)
├── lighthouserc.cjs               ← the gate: budgets + assertions + collect settings
├── package.json                   ← "lhci": "lhci autorun --config=./lighthouserc.cjs"
└── .github/workflows/lighthouse.yml  ← PR-blocking CI job (build → start → lhci → upload)
```

Plus a dev dependency: `@lhci/cli`.

```bash
pnpm add -D @lhci/cli        # or npm i -D / yarn add -D
```

---

## 2. The config (`lighthouserc.cjs`)

`.cjs` (CommonJS) so it loads without ESM/TS transpilation. Every budget is a **named constant**
with a comment explaining the threshold — never a bare number inside an assertion.

```js
/**
 * Lighthouse CI configuration — Core Web Vitals budgets for the marketing surface.
 *
 * Enforces Google's mobile "good" CWV thresholds:
 *   - Largest Contentful Paint (LCP) ≤ 2500 ms
 *   - Cumulative Layout Shift (CLS)  ≤ 0.1
 *   - Interaction to Next Paint (INP) ≤ 200 ms
 *
 * INP is a *field* metric with no direct lab audit, so in the lab we gate on
 * Total Blocking Time (TBT) — Lighthouse's recommended lab proxy — at the same
 * budget, and assert the experimental INP audit directly as a warning where the
 * build exposes it.
 *
 * Collection runs against the *production* server (build + start) on Lighthouse's
 * default mobile (Moto G4 / slow 4G) emulation.
 */

/** The fixed port the production server is started on for the audit. */
const PORT = 3100;
const BASE_URL = `http://localhost:${PORT}`;

/** Pages whose budgets are enforced in CI. */
const MARKETING_URLS = [`${BASE_URL}/`];

/**
 * Core Web Vitals budgets on mobile — Google's "good" thresholds.
 * These are the values that earn the best Lighthouse scores.
 */
const LCP_BUDGET_MS = 2500; // good
const INP_BUDGET_MS = 200; // good (TBT lab proxy)
const CLS_BUDGET = 0.1; // good

module.exports = {
  ci: {
    collect: {
      // Build is run separately in CI; here we only serve the production output.
      startServerCommand: `pnpm start --port ${PORT}`,
      startServerReadyPattern: "Ready in", // framework's "server ready" log line
      startServerReadyTimeout: 120000,
      url: MARKETING_URLS,
      // Median of multiple runs keeps the gate stable against per-run jitter.
      numberOfRuns: 3,
      settings: {
        // Default mobile emulation; opt into desktop via env for a second run.
        preset:
          process.env.LHCI_FORM_FACTOR === "desktop" ? "desktop" : undefined,
        // Only gate the categories we care about; skip PWA category noise.
        onlyCategories: [
          "performance",
          "seo",
          "accessibility",
          "best-practices",
        ],
      },
    },
    assert: {
      // Median across runs is the value compared against each budget.
      aggregationMethod: "median-run",
      assertions: {
        // --- Core Web Vitals budgets (the contract) ---------------------
        "largest-contentful-paint": [
          "error",
          { maxNumericValue: LCP_BUDGET_MS },
        ],
