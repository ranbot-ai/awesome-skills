---
name: drizzle-orm-expert
description: Expert in Drizzle ORM for TypeScript — schema design, relational queries, migrations, and serverless database integration. Use when building type-safe database layers with Drizzle. 
category: Document Processing
source: antigravity
tags: [typescript, react, api, ai, workflow, design, document, prisma, supabase]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/drizzle-orm-expert
---


# Drizzle ORM Expert

You are a production-grade Drizzle ORM expert. You help developers build type-safe, performant database layers using Drizzle ORM with TypeScript. You know schema design, the relational query API, Drizzle Kit migrations, and integrations with Next.js, tRPC, and serverless databases (Neon, PlanetScale, Turso, Supabase).

## When to Use This Skill

- Use when the user asks to set up Drizzle ORM in a new or existing project
- Use when designing database schemas with Drizzle's TypeScript-first approach
- Use when writing complex relational queries (joins, subqueries, aggregations)
- Use when setting up or troubleshooting Drizzle Kit migrations
- Use when integrating Drizzle with Next.js App Router, tRPC, or Hono
- Use when optimizing database performance (prepared statements, batching, connection pooling)
- Use when migrating from Prisma, TypeORM, or Knex to Drizzle

## Core Concepts

### Why Drizzle

Drizzle ORM provides TypeScript query builders that generate SQL at runtime. Runtime/driver compatibility and overhead depend on the selected adapter and deployment. Key properties:

- **SQL-like API**: If you know SQL, you know Drizzle
- **Adapter-specific deployment**: Verify the driver and bundle for Cloudflare Workers, edge runtimes or Deno
- **Full type inference**: Schema → types → queries are all connected at compile time
- **Relational Query API**: Prisma-like nested includes without N+1 problems

## Schema Design Patterns

### Table Definitions

```typescript
// db/schema.ts
import { pgTable, text, integer, timestamp, boolean, uuid, pgEnum } from "drizzle-orm/pg-core";
import { relations } from "drizzle-orm";

// Enums
export const roleEnum = pgEnum("role", ["admin", "user", "moderator"]);

// Users table
export const users = pgTable("users", {
  id: uuid("id").defaultRandom().primaryKey(),
  email: text("email").notNull().unique(),
  name: text("name").notNull(),
  role: roleEnum("role").default("user").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

// Posts table with foreign key
export const posts = pgTable("posts", {
  id: uuid("id").defaultRandom().primaryKey(),
  title: text("title").notNull(),
  content: text("content"),
  published: boolean("published").default(false).notNull(),
  authorId: uuid("author_id").references(() => users.id, { onDelete: "cascade" }).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});
```

### Relations

```typescript
// db/relations.ts
export const usersRelations = relations(users, ({ many }) => ({
  posts: many(posts),
}));

export const postsRelations = relations(posts, ({ one }) => ({
  author: one(users, {
    fields: [posts.authorId],
    references: [users.id],
  }),
}));
```

### Type Inference

```typescript
// Infer types directly from your schema — no separate type files needed
import type { InferSelectModel, InferInsertModel } from "drizzle-orm";

export type User = InferSelectModel<typeof users>;
export type NewUser = InferInsertModel<typeof users>;
export type Post = InferSelectModel<typeof posts>;
export type NewPost = InferInsertModel<typeof posts>;
```

The schema/relations examples use one relational-query API generation; verify it against the installed Drizzle version. db/relations.ts needs explicit imports and its exports must be included in the schema passed to drizzle. updatedAt defaultNow initializes only; it does not automatically change on updates. Driver support differs: neon-http does not support the interactive transaction callback shown below, and db.batch/prepared statements/returning are adapter-specific. Choose a supported transactional driver or a documented non-interactive batch when atomic dependent writes are required. Preview migration SQL against a backed-up target; generated SQL is not proof of safe data preservation.

## Query Patterns

### Select Queries (SQL-like API)

```typescript
import { eq, and, like, desc, count, sql } from "drizzle-orm";

// Basic select
const allUsers = await db.select().from(users);

// Filtered with conditions
const admins = await db.select().from(users).where(eq(users.role, "admin"));

// Partial select (only specific columns)
const emails = await db.select({ email: users.email }).from(users);

// Join query
const postsWithAuthors = await db
  .select({
    title: posts.title,
    authorName: users.name,
  })
  .from(posts)
  .innerJoin(users, eq(posts.authorId, users.id))
  .where(eq(posts.published, true))
  .orderBy(desc(posts.createdAt))
  .limit(10);

// Aggregation
const postCounts = await db
  .select({
    authorId: posts.authorId,
    postCount: count(posts.id),
  })
  .from(posts)
  .groupBy(posts.authorId);
```

### Relational Queries (Prisma-like API)

```typescript
// Nested includes — Drizzle resolves in a single query
const usersWithPosts = await db.query.users.findMany({
  with: {
    posts: {
      where: eq(posts.published, true),
      orderBy: [desc
