---
name: frontend-observability
description: A portable, framework-agnostic field-side observability system for any React or React Native app. Establishes one typed event taxonomy (canonical event-name constants, never inline strings), a best-ef
category: AI & Agents
source: antigravity
tags: [react, node, api, claude, ai, agent, security, firebase, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/frontend-observability
---


# Frontend Observability (the field side)
## When to Use

Use this skill when you need a portable, framework-agnostic field-side observability system for any React or React Native app. Establishes one typed event taxonomy (canonical event-name constants, never inline strings), a best-effort non-blocking provider fan-out so a failing or absent analytics provider can never...


> Portable skill — readable by Claude Code, OpenCode, Codex, Cursor, Windsurf, and others.
> This skill describes a **field-side observability system** — event taxonomy, provider fan-out,
> real-user vitals, error reporting, consent — not a dashboard or a specific vendor. It is the
> **field complement to the frontend-lighthouse skill**: Lighthouse is the _lab_ gate (synthetic,
> pre-merge); this is the _field_ (what real users actually experience). It lives in a
> `services/analytics/` module per the **frontend-architecture** skill.

The goal: you can answer "what are real users doing, and what are they experiencing?" — with a
**typed event vocabulary** (no stringly-typed `track("clicked_thing")` scattered everywhere), a
fan-out that is **best-effort** (a broken provider never breaks the app), real **Core Web Vitals
from the field**, and **consent** respected before anything fires.

---

## 0. The five core ideas

1. **Events are a typed vocabulary.** Event names are canonical constants with a union type — never inline string literals. The taxonomy is reviewable in one file and the compiler rejects typos.
2. **Fan-out is best-effort and non-blocking.** `track()` dispatches to every provider, each in its own try/catch. A missing global, a thrown provider, an unloaded script — none can throw into the caller or stop the other providers.
3. **One entry point, SSR-safe.** A single `track(event, props)` is the only way to record. It's reached through a context hook that no-ops outside a provider and on the server, so instrumented components render safely anywhere.
4. **Field vitals complement lab budgets.** Real-user LCP/INP/CLS are reported to the same fan-out. Lighthouse proves the build _can_ be fast; field vitals prove it _is_ — together they close the loop.
5. **Consent gates everything.** No telemetry (events, vitals, error reports with PII) fires before opt-in. Consent state is checked at the fan-out boundary, not sprinkled through call sites.

---

## 1. Directory layout

The system is one service module plus its constants (per frontend-architecture).

```
src/
├── constants/
│   └── analytics.ts           ← canonical event names + AnalyticsEvent union
├── services/analytics/
│   ├── index.ts               ← barrel: track, adapters, types
│   ├── track.ts               ← the best-effort fan-out (single entry point)
│   ├── adapters.ts            ← one (event, props) => void per provider, window-guarded
│   ├── web-vitals.ts          ← report real-user LCP/INP/CLS into track()
│   └── consent.ts             ← consent gate read by the fan-out
├── providers/
│   └── AnalyticsProvider.tsx  ← 'use client' context exposing useAnalytics().track
└── error/
    └── ErrorBoundary.tsx      ← reports caught render errors via the fan-out
```

---

## 2. The event taxonomy (typed, never inline)

One file owns every event name. Components reference constants; the union type makes typos a compile
error and the catalog a single source of truth.

```ts
// constants/analytics.ts
export const ANALYTICS_EVENTS = {
  PROJECT_CLICK: "project_click",
  GITHUB_CLICK: "github_click",
  RESUME_DOWNLOAD: "resume_download",
  CONTACT_SUBMISSION: "contact_submission",
} as const;

export type AnalyticsEvent =
  (typeof ANALYTICS_EVENTS)[keyof typeof ANALYTICS_EVENTS];
```

```ts
// CORRECT — typed constant, autocompletes, can't typo
track(ANALYTICS_EVENTS.GITHUB_CLICK, { url });

// WRONG — stringly-typed, drifts, no compile check
track("github-click"); // ❌ silently a different event from "github_click"
```

**Hard rules:**

- No inline event-name strings anywhere; only `ANALYTICS_EVENTS.*`.
- Event names are snake_case and stable — renaming one breaks historical dashboards, so treat the catalog as a contract.
- Keep `props` shapes small and PII-light (see §6); prefer ids over names, never raw emails.

---

## 3. Best-effort, non-blocking fan-out

`track()` is the single entry point. It iterates the adapter registry, guarding **each** call so one
provider can't affect the caller or the others.

```ts
// services/analytics/track.ts
import type { AnalyticsEvent } from "@/constants/analytics";
import { analyticsAdapters } from "./adapters";
import { hasConsent } from "./consent";

export function track(
  event: AnalyticsEvent,
  props?: Record<string, unknown>,
): void {
  if (!hasConsent()) return; // §6 — nothing fires before opt-in
  for (const adapter of analyticsAdapters) {
    try {
      adapter(event, props);
    } catch {
      /* best-effort: a failing/absent provider must never throw into the
         caller or block dispatch to the remaining provider
