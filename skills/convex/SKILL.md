---
name: convex
description: Convex reactive backend expert: schema design, TypeScript functions, real-time subscriptions, auth, file storage, scheduling, and deployment. 
category: Document Processing
source: antigravity
tags: [typescript, react, node, nextjs, api, ai, automation, workflow, template, design]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/convex
---


# Convex

You are an expert in Convex — the open-source, reactive backend platform where queries are TypeScript code. You have deep knowledge of schema design, function authoring (queries, mutations, actions), real-time data subscriptions, authentication, file storage, scheduling, and deployment workflows across React, Next.js, Angular, Vue, Svelte, React Native, and server-side environments.

## When to Use
- Use when building a new project with Convex as the backend
- Use when adding Convex to an existing React, Next.js, Angular, Vue, Svelte, or React Native app
- Use when designing schemas for a Convex document-relational database
- Use when writing or debugging Convex functions (queries, mutations, actions)
- Use when implementing real-time/reactive data patterns
- Use when setting up authentication with Convex Auth or third-party providers (Clerk, Auth0, etc.)
- Use when working with Convex file storage, scheduled functions, or cron jobs
- Use when deploying or managing Convex projects

## Core Concepts

Convex is a **document-relational** database with a fully managed backend. Key differentiators:

- **Reactive by default**: Queries automatically re-run and push updates to all connected clients when underlying data changes
- **TypeScript-first**: All backend logic — queries, mutations, actions, schemas — is written in TypeScript
- **ACID transactions**: Serializable isolation with optimistic concurrency control
- **No infrastructure to manage**: Serverless, scales automatically, zero config
- **End-to-end type safety**: Types flow from schema → backend functions → client hooks

### Function Types

| Type            | Purpose                   | Can Read DB    | Can Write DB      | Can Call External APIs | Cached/Reactive |
| :-------------- | :------------------------ | :------------- | :---------------- | :--------------------- | :-------------- |
| **Query**       | Read data                 | ✅             | ❌                | ❌                     | ✅              |
| **Mutation**    | Write data                | ✅             | ✅                | ❌                     | ❌              |
| **Action**      | Side effects              | via `runQuery` | via `runMutation` | ✅                     | ❌              |
| **HTTP Action** | Webhooks/custom endpoints | via `runQuery` | via `runMutation` | ✅                     | ❌              |

## Project Setup

### New Project (Next.js)

```bash
npx create-next-app@latest my-app
cd my-app && npm install convex
npx convex dev
```

### Add to Existing Project

```bash
npm install convex
npx convex dev
```

The `npx convex dev` command:

1. Prompts you to log in (GitHub)
2. Creates a project and deployment
3. Generates `convex/` folder for backend functions
4. Syncs functions to your dev deployment in real-time
5. Creates `.env.local` with `CONVEX_DEPLOYMENT` and `NEXT_PUBLIC_CONVEX_URL`

### Folder Structure

```
my-app/
├── convex/
│   ├── _generated/        ← Auto-generated (DO NOT EDIT)
│   │   ├── api.d.ts
│   │   ├── dataModel.d.ts
│   │   └── server.d.ts
│   ├── schema.ts          ← Database schema definition
│   ├── tasks.ts           ← Query/mutation functions
│   └── http.ts            ← HTTP actions (optional)
├── .env.local             ← CONVEX_DEPLOYMENT, NEXT_PUBLIC_CONVEX_URL
└── convex.json            ← Project config (optional)
```

## Schema Design

Define your schema in `convex/schema.ts` using the validator library:

```typescript
import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

export default defineSchema({
  users: defineTable({
    name: v.string(),
    email: v.string(),
    avatarUrl: v.optional(v.string()),
    tokenIdentifier: v.string(),
  })
    .index("by_token", ["tokenIdentifier"])
    .index("by_email", ["email"]),

  messages: defineTable({
    authorId: v.id("users"),
    channelId: v.id("channels"),
    body: v.string(),
    attachmentId: v.optional(v.id("_storage")),
  })
    .index("by_channel", ["channelId"])
    .searchIndex("search_body", { searchField: "body" }),

  channels: defineTable({
    name: v.string(),
    description: v.optional(v.string()),
    isPrivate: v.boolean(),
  }),
});
```

### Validator Types

| Validator                         | TypeScript Type       | Notes                                          |
| :-------------------------------- | :-------------------- | :--------------------------------------------- |
| `v.string()`                      | `string`              |                                                |
| `v.number()`                      | `number`              | IEEE 754 float                                 |
| `v.bigint()`                      | `bigint`              |                                                |
| `v.boolean()`                     | `boolean`             |                                                |
| `v.null()`                        | `null`                |                                            
