---
name: frontend-architecture
description: A portable, framework-agnostic architecture style for any React or React Native frontend. Organizes apps into feature modules with page/screen directories, a strict server-state vs UI-state split, bar
category: Document Processing
source: antigravity
tags: [react, api, claude, ai, agent, template, design, document, security, tailwind]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/frontend-architecture
---


# Frontend Architecture (portable, module-based)
## When to Use

Use this skill when you need a portable, framework-agnostic architecture style for any React or React Native frontend. Organizes apps into feature modules with page/screen directories, a strict server-state vs UI-state split, barrel-only cross-module imports, co-located styles, and clear component-promotion rules....


> Portable skill — readable by Claude Code, OpenCode, Codex, Cursor, Windsurf, and others.
> This skill describes a **structure and a set of rules**, not a component library, a state library, or a visual style.
> It is deliberately global: the same module/page/state model maps onto
> **Next.js (App Router)**, **React + Vite (SPA)**, **Remix**, and **Expo / React Native**, and it works
> with **any** state-management and styling stack.

The goal: a codebase where any contributor can instantly answer three questions —
**"where does this code live?"**, **"what is allowed to import what?"**, and **"is this server state or UI state?"** —
without asking anyone. The structure makes the answers obvious.

---

## 0. The five core ideas

1. **Feature modules own their world.** Each feature is a self-contained `modules/{feature}/` folder with its own pages, components, hooks, state, types, and a single public barrel.
2. **Pages/screens are directories, not files.** A route is a folder that co-locates its component, its styles, and the components/hooks used only by it.
3. **State is split by origin.** Server data lives in a query/cache layer. UI/client state lives in a store. They never overlap — regardless of which libraries you pick.
4. **Imports cross boundaries only through barrels.** Reaching into another module's internals is forbidden; you import from `@/modules/{feature}` and nothing deeper.
5. **Code is promoted, not pre-placed.** It starts as local as possible and moves outward only when a second consumer appears.

Everything below is the mechanical application of these five ideas. None of it is tied to a specific library — pick your stack in Sections 4 and 6.

---

## 1. Directory layout

The shape is identical across frameworks; only the routing layer on top differs (see Section 7).

```
src/
├── app/ or routes/ or navigation/   ← framework routing layer (thin — see §7)
├── modules/                         ← feature modules (the heart of the app)
│   └── {feature}/
│       ├── index.ts                 ← PUBLIC BARREL — the only cross-module entry point
│       ├── README.md                ← what this module owns, its routes, its data deps
│       ├── components/              ← components reused by 2+ pages IN THIS MODULE
│       ├── pages/                   ← page/screen directories (one per route)
│       │   └── {page}/
│       │       ├── {page}.tsx               ← the page/screen component
│       │       ├── {page}.styles.ts         ← ALL styling for this page
│       │       ├── index.ts                 ← re-exports the page component
│       │       ├── components/              ← components used ONLY by this page
│       │       ├── hooks/                   ← hooks used ONLY by this page
│       │       ├── constants/
│       │       └── README.md                ← route, params, permissions, data deps
│       ├── hooks/                   ← data hooks (query/mutation) + module hooks
│       ├── stores/                  ← UI/client state store(s) — never server data
│       ├── services/                ← data-access (API calls) for this feature
│       ├── utils/                   ← pure module utilities (co-located *.test.ts)
│       ├── constants/
│       └── types/                   ← module request/response + view-model types
└── shared/                          ← cross-module building blocks
    ├── components/                  ← components used by 2+ MODULES
    ├── hooks/                       ← cross-cutting hooks
    ├── api-client/                  ← one typed client; the only place that talks to the network
    ├── store/                       ← root store wiring (if your state lib needs one — see §4)
    ├── utils/                       ← formatters, cn()/clsx, helpers
    ├── constants/
    └── types/
```

Every folder that can be empty at scaffold time keeps a `.gitkeep` so the structure is visible from day one.

---

## 2. Feature modules

A module is a vertical slice of the product (e.g. `auth`, `billing`, `dashboard`, `settings`). It contains everything that feature needs and exposes a deliberately small surface.

### 2.1 The barrel (`index.ts`) is the contract

`modules/{feature}/index.ts` is the **only** thing other modules and the routing layer may import from. It re-exports:

- Page/screen components the router mounts.
- Data hooks other features legitimately need.
- The store hook/slice and its public types.
- Shared constants / types other features depend on.

```ts
// CORRECT — consume the public surface
import { InvoiceListPage, useInvoiceList } from "@/modules/invoice";

// WRONG — reaching into i
