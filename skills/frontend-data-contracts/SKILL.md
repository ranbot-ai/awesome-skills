---
name: frontend-data-contracts
description: A portable, framework-agnostic discipline for type safety at the network edge of any React or React Native app. Establishes one typed API client as the single fetch boundary, a parse-don't-validate ru
category: AI & Agents
source: antigravity
tags: [react, api, claude, ai, agent, security, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/frontend-data-contracts
---


# Frontend Data Contracts (typed network boundary)
## When to Use

Use this skill when you need a portable, framework-agnostic discipline for type safety at the network edge of any React or React Native app. Establishes one typed API client as the single fetch boundary, a parse-don't-validate rule that turns wire JSON into trusted domain types before it enters the app, a single...


> Portable skill — readable by Claude Code, OpenCode, Codex, Cursor, Windsurf, and others.
> This skill describes a **discipline at the network edge** — one client, one envelope, one error
> type, validated types — not a state library or a styling system. It pairs with the
> **frontend-architecture** skill (the client lives in `shared/api-client/`) and is the foundation
> the **frontend-optimistic-mutations** skill builds on.

The goal: the moment data crosses from the network into the app, it stops being `any`-shaped wire
JSON and becomes a **trusted, typed domain value** — or it becomes a **single, typed error**.
There is exactly one place this transformation happens, and nothing untyped escapes it.

---

## 0. The five core ideas

1. **One client is the only fetch boundary.** A single typed `apiClient` wraps `fetch`. Components and hooks never call `fetch`/`axios` directly — the boundary is enforceable in review and lint.
2. **Parse, don't validate.** Wire JSON is parsed into domain types at the boundary. After the client returns, the value is trusted everywhere downstream — no defensive `?.` chains, no re-checking shapes in components.
3. **One envelope.** Every response is `{ data }` on success or `{ error }` on failure. The client unwraps `data` and throws on `error`, so callers receive the payload directly or a typed throw.
4. **One normalized error type.** Server error envelope, non-2xx status, malformed body, network failure, and abort all become a single `ApiError` with a machine code, status, and optional per-field errors. Callers handle one shape.
5. **Identifiers are branded.** Domain IDs are nominal types (`InvoiceId`, `CustomerId`) so the compiler rejects passing one where another is expected — the most common silent bug in data-heavy UIs.

---

## 1. Directory layout

The boundary is one folder in `shared/` (per the frontend-architecture skill).

```
src/shared/api-client/
├── index.ts        ← barrel: apiClient, ApiError, types
├── client.ts       ← the fetch wrapper: buildUrl, headers, parse, verbs
├── config.ts       ← base URL resolution, default headers
├── error.ts        ← the ApiError class + code→message-key mapping
├── types.ts        ← envelope types, HttpMethod, RequestOptions, field errors
└── client.test.ts  ← boundary behavior tests (envelope, errors, network)
```

Domain entity types and their **schemas** live with their feature module
(`modules/{feature}/types/`) or a shared contract package; the client is generic over `T`.

---

## 2. One client, the only fetch boundary

Every verb returns the **unwrapped** `data` payload typed by the caller, and **throws** an
`ApiError` on any failure. Components never see envelopes or raw responses.

```ts
// shared/api-client/client.ts (essence)
export const apiClient = {
  get<T>(path: string, options?: RequestOptions): Promise<T> {
    return request<T>("GET", path, undefined, options);
  },
  post<T>(path: string, body?: unknown, options?: RequestOptions): Promise<T> {
    return request<T>("POST", path, body, options);
  },
  patch<T>(path: string, body?: unknown, options?: RequestOptions): Promise<T> {
    /* … */
  },
  put<T>(path: string, body?: unknown, options?: RequestOptions): Promise<T> {
    /* … */
  },
  delete<T>(path: string, options?: RequestOptions): Promise<T> {
    /* … */
  },
} as const;

export type ApiClient = typeof apiClient;
```

```ts
// CORRECT — a feature hook wraps the client, typed by the caller
const invoice = await apiClient.get<Invoice>(`/invoices/${id}`, { signal });

// WRONG — a raw fetch in a component bypasses the boundary entirely
const res = await fetch(`/api/invoices/${id}`); // untyped, unhandled errors, no envelope
```

**Hard rules:**

- No `fetch`/`axios`/`XMLHttpRequest` outside `shared/api-client/` — enforce with an ESLint `no-restricted-imports`/`no-restricted-globals` rule.
- The client is **framework-free**: no toasts, no router, no React. Side effects (toasts, redirects) live in the query layer's `onError` (see §6).
- Pass `AbortSignal` through `RequestOptions` so the query layer can cancel (wired by TanStack Query).

---

## 3. Parse, don't validate (the boundary transform)

"Validate" leaves you with the same untyped value and a boolean. "Parse" returns a **new, typed
value** — so downstream code is guaranteed correct by the type system. Run a schema parse at the
boundary; after that, the value is trusted.

```ts
// modules/invoice/types/invoice.schema.ts
import { z } from "zod";

export const invoiceSchema = z.object({
  id: z.string().transform(toInvoiceId), // brand it (see §5)
  number: z.string(),
