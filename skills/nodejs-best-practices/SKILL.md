---
name: nodejs-best-practices
description: Node.js development principles and decision-making. Framework selection, async patterns, security, and architecture. Teaches thinking, not copying. 
category: AI & Agents
source: antigravity
tags: [typescript, react, node, api, ai, image, security, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/nodejs-best-practices
---


# Node.js Best Practices

> Principles and decision-making for Node.js development in 2025.
> **Learn to THINK, not memorize code patterns.**

---

## ⚠️ How to Use This Skill

This skill teaches **decision-making principles**, not fixed code to copy.

- ASK user for preferences when unclear
- Choose framework/pattern based on CONTEXT
- Don't default to same solution every time

---

## 1. Framework Selection (2025)

### Decision Tree

```
What are you building?
│
├── Edge/Serverless (Cloudflare, Vercel)
│   └── Hono (zero-dependency, ultra-fast cold starts)
│
├── High Performance API
│   └── Fastify (2-3x faster than Express)
│
├── Enterprise/Team familiarity
│   └── NestJS (structured, DI, decorators)
│
├── Legacy/Stable/Maximum ecosystem
│   └── Express (mature, most middleware)
│
└── Full-stack with frontend
    └── Next.js API Routes or tRPC
```

### Comparison Principles

| Factor | Hono | Fastify | Express |
|--------|------|---------|---------|
| **Best for** | Edge, serverless | Performance | Legacy, learning |
| **Cold start** | Fastest | Fast | Moderate |
| **Ecosystem** | Growing | Good | Largest |
| **TypeScript** | Native | Excellent | Good |
| **Learning curve** | Low | Medium | Low |

### Selection Questions to Ask:
1. What's the deployment target?
2. Is cold start time critical?
3. Does team have existing experience?
4. Is there legacy code to maintain?

---

## 2. Runtime Considerations (2025)

### Native TypeScript

```
Node.js 22+: --experimental-strip-types
├── Run .ts files directly
├── No build step needed for simple projects
└── Consider for: scripts, simple APIs
```

### Module System Decision

```
ESM (import/export)
├── Modern standard
├── Better tree-shaking
├── Async module loading
└── Use for: new projects

CommonJS (require)
├── Legacy compatibility
├── More npm packages support
└── Use for: existing codebases, some edge cases
```

### Runtime Selection

| Runtime | Best For |
|---------|----------|
| **Node.js** | General purpose, largest ecosystem |
| **Bun** | Performance, built-in bundler |
| **Deno** | Security-first, built-in TypeScript |

---

## 3. Architecture Principles

### Layered Structure Concept

```
Request Flow:
│
├── Controller/Route Layer
│   ├── Handles HTTP specifics
│   ├── Input validation at boundary
│   └── Calls service layer
│
├── Service Layer
│   ├── Business logic
│   ├── Framework-agnostic
│   └── Calls repository layer
│
└── Repository Layer
    ├── Data access only
    ├── Database queries
    └── ORM interactions
```

### Why This Matters:
- **Testability**: Mock layers independently
- **Flexibility**: Swap database without touching business logic
- **Clarity**: Each layer has single responsibility

### When to Simplify:
- Small scripts → Single file OK
- Prototypes → Less structure acceptable
- Always ask: "Will this grow?"

---

## 4. Error Handling Principles

### Centralized Error Handling

```
Pattern:
├── Create custom error classes
├── Throw from any layer
├── Catch at top level (middleware)
└── Format consistent response
```

### Error Response Philosophy

```
Client gets:
├── Appropriate HTTP status
├── Error code for programmatic handling
├── User-friendly message
└── NO internal details (security!)

Logs get:
├── Full stack trace
├── Request context
├── User ID (if applicable)
└── Timestamp
```

### Status Code Selection

| Situation | Status | When |
|-----------|--------|------|
| Bad input | 400 | Client sent invalid data |
| No auth | 401 | Missing or invalid credentials |
| No permission | 403 | Valid auth, but not allowed |
| Not found | 404 | Resource doesn't exist |
| Conflict | 409 | Duplicate or state conflict |
| Validation | 422 | Schema valid but business rules fail |
| Server error | 500 | Our fault, log everything |

---

## 5. Async Patterns Principles

### When to Use Each

| Pattern | Use When |
|---------|----------|
| `async/await` | Sequential async operations |
| `Promise.all` | Parallel independent operations |
| `Promise.allSettled` | Parallel where some can fail |
| `Promise.race` | Timeout or first response wins |

### Event Loop Awareness

```
I/O-bound (async helps):
├── Database queries
├── HTTP requests
├── File system
└── Network operations

CPU-bound (async doesn't help):
├── Crypto operations
├── Image processing
├── Complex calculations
└── → Use worker threads or offload
```

### Avoiding Event Loop Blocking

- Never use sync methods in production (fs.readFileSync, etc.)
- Offload CPU-intensive work
- Use streaming for large data

---

## 6. Validation Principles

### Validate at Boundaries

```
Where to validate:
├── API entry point (request body/params)
├── Before database operations
├── External data (API responses, file uploads)
└── Environment variables (startup)
```

### Validation Library Selection

| Library | Best For |
|---------|----------|
| **Zod** | TypeScript first, inference |
| **Valibot** | Smaller bundle (tree-shakeable) |
| **ArkType** | Performance critical |
| **Yup** | Exist
