---
name: neon-postgres
description: Expert patterns for Neon serverless Postgres, branching, connection pooling, and Prisma/Drizzle integration 
category: AI & Agents
source: antigravity
tags: [node, nextjs, api, ai, automation, workflow, prisma, aws, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/neon-postgres
---


# Neon Postgres

Expert patterns for Neon serverless Postgres, branching, connection pooling, and Prisma/Drizzle integration

## Patterns

### Prisma with Neon Connection

Configure Prisma for Neon with connection pooling.

Use two connection strings:
- DATABASE_URL: Pooled connection for Prisma Client
- DIRECT_URL: Direct connection for Prisma Migrate

The pooled connection uses PgBouncer for up to 10K connections.
Direct connection required for migrations (DDL operations).

### Code_example

# .env
# Pooled connection for application queries
DATABASE_URL="postgres://user:password@ep-xxx-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require"
# Direct connection for migrations
DIRECT_URL="postgres://user:password@ep-xxx.us-east-2.aws.neon.tech/neondb?sslmode=require"

// prisma/schema.prisma
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider  = "postgresql"
  url       = env("DATABASE_URL")
  directUrl = env("DIRECT_URL")
}

model User {
  id        String   @id @default(cuid())
  email     String   @unique
  name      String?
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
}

// lib/prisma.ts
import { PrismaClient } from '@prisma/client';

const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined;
};

export const prisma = globalForPrisma.prisma ?? new PrismaClient({
  log: process.env.NODE_ENV === 'development'
    ? ['query', 'error', 'warn']
    : ['error'],
});

if (process.env.NODE_ENV !== 'production') {
  globalForPrisma.prisma = prisma;
}

// Run migrations
// Uses DIRECT_URL automatically
npx prisma migrate dev
npx prisma migrate deploy

### Anti_patterns

- Pattern: Using pooled connection for migrations | Why: DDL operations fail through PgBouncer | Fix: Set directUrl in schema.prisma
- Pattern: Not using connection pooling | Why: Serverless functions exhaust connection limits | Fix: Use -pooler endpoint in DATABASE_URL

### References

- https://neon.com/docs/guides/prisma
- https://www.prisma.io/docs/orm/overview/databases/neon

### Drizzle with Neon Serverless Driver

Use Drizzle ORM with Neon's serverless HTTP driver for
edge/serverless environments.

Two driver options:
- neon-http: Single queries over HTTP (fastest for one-off queries)
- neon-serverless: WebSocket for transactions and sessions

### Code_example

# Install dependencies
npm install drizzle-orm @neondatabase/serverless
npm install -D drizzle-kit

// lib/db/schema.ts
import { pgTable, serial, text, timestamp } from 'drizzle-orm/pg-core';

export const users = pgTable('users', {
  id: serial('id').primaryKey(),
  email: text('email').notNull().unique(),
  name: text('name'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
});

// lib/db/index.ts (for serverless - HTTP driver)
import { neon } from '@neondatabase/serverless';
import { drizzle } from 'drizzle-orm/neon-http';
import * as schema from './schema';

const sql = neon(process.env.DATABASE_URL!);
export const db = drizzle(sql, { schema });

// Usage in API route
import { db } from '@/lib/db';
import { users } from '@/lib/db/schema';

export async function GET() {
  const allUsers = await db.select().from(users);
  return Response.json(allUsers);
}

// lib/db/index.ts (for WebSocket - transactions)
import { Pool } from '@neondatabase/serverless';
import { drizzle } from 'drizzle-orm/neon-serverless';
import * as schema from './schema';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
export const db = drizzle(pool, { schema });

// With transactions
await db.transaction(async (tx) => {
  await tx.insert(users).values({ email: 'test@example.com' });
  await tx.update(users).set({ name: 'Updated' });
});

// drizzle.config.ts
import { defineConfig } from 'drizzle-kit';

export default defineConfig({
  schema: './lib/db/schema.ts',
  out: './drizzle',
  dialect: 'postgresql',
  dbCredentials: {
    url: process.env.DATABASE_URL!,
  },
});

// Run migrations
npx drizzle-kit generate
npx drizzle-kit migrate

### Anti_patterns

- Pattern: Using pg driver in serverless | Why: TCP connections don't work in all edge environments | Fix: Use @neondatabase/serverless driver
- Pattern: HTTP driver for transactions | Why: HTTP driver doesn't support transactions | Fix: Use WebSocket driver (Pool) for transactions

### References

- https://neon.com/docs/guides/drizzle
- https://orm.drizzle.team/docs/connect-neon

### Connection Pooling with PgBouncer

Neon provides built-in connection pooling via PgBouncer.

Key limits:
- Up to 10,000 concurrent connections to pooler
- Connections still consume underlying Postgres connections
- 7 connections reserved for Neon superuser

Use pooled endpoint for application, direct for migrations.

### Code_example

# Connection string formats

# Pooled connection (for application)
# Note: -pooler in hostname
postgres://user:pass@ep-cool-name-pooler.us-east-2.aws.neon.tech/neondb
