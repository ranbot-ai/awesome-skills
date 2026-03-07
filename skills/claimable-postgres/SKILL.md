---
name: claimable-postgres
description: Provision instant temporary Postgres databases via Claimable Postgres by Neon (pg.new). No login or credit card required. Use for quick Postgres environments and throwaway DATABASE_URL for prototyping
category: AI & Agents
source: antigravity
tags: [typescript, node, api, ai, agent, workflow, prisma, aws, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/claimable-postgres
---


# Claimable Postgres

Instant Postgres databases for local development, demos, prototyping, and test environments. No account required. Databases expire after 72 hours unless claimed to a Neon account.

## Quick Start

```bash
curl -s -X POST "https://pg.new/api/v1/database" \
  -H "Content-Type: application/json" \
  -d '{"ref": "agent-skills"}'
```

Parse `connection_string` and `claim_url` from the JSON response. Write `connection_string` to the project's `.env` as `DATABASE_URL`.

For other methods (CLI, SDK, Vite plugin), see [Which Method?](#which-method) below.

## Which Method?

- **REST API**: Returns structured JSON. No runtime dependency beyond `curl`. Preferred when the agent needs predictable output and error handling.
- **CLI** (`npx get-db@latest --yes`): Provisions and writes `.env` in one command. Convenient when Node.js is available and the user wants a simple setup.
- **SDK** (`get-db/sdk`): Scripts or programmatic provisioning in Node.js.
- **Vite plugin** (`vite-plugin-db`): Auto-provisions on `vite dev` if `DATABASE_URL` is missing. Use when the user has a Vite project.
- **Browser**: User cannot run CLI or API. Direct to https://pg.new.

## REST API

**Base URL:** `https://pg.new/api/v1`

### Create a database

```bash
curl -s -X POST "https://pg.new/api/v1/database" \
  -H "Content-Type: application/json" \
  -d '{"ref": "agent-skills"}'
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `ref` | Yes | Tracking tag that identifies who provisioned the database. Use `"agent-skills"` when provisioning through this skill. |
| `enable_logical_replication` | No | Enable logical replication (default: false, cannot be disabled once enabled) |

The `connection_string` returned by the API is a pooled connection URL. For a direct (non-pooled) connection (e.g. Prisma migrations), remove `-pooler` from the hostname. The CLI writes both pooled and direct URLs automatically.

**Response:**

```json
{
  "id": "019beb39-37fb-709d-87ac-7ad6198b89f7",
  "status": "UNCLAIMED",
  "neon_project_id": "gentle-scene-06438508",
  "connection_string": "postgresql://...",
  "claim_url": "https://pg.new/claim/019beb39-...",
  "expires_at": "2026-01-26T14:19:14.580Z",
  "created_at": "2026-01-23T14:19:14.580Z",
  "updated_at": "2026-01-23T14:19:14.580Z"
}
```

### Check status

```bash
curl -s "https://pg.new/api/v1/database/{id}"
```

Returns the same response shape. Status transitions: `UNCLAIMED` -> `CLAIMING` -> `CLAIMED`. After the database is claimed, `connection_string` returns `null`.

### Error responses

| Condition | HTTP | Message |
|-----------|------|---------|
| Missing or empty `ref` | 400 | `Missing referrer` |
| Invalid database ID | 400 | `Database not found` |
| Invalid JSON body | 500 | `Failed to create the database.` |

## CLI

```bash
npx get-db@latest --yes
```

Provisions a database and writes the connection string to `.env` in one step. Always use `@latest` and `--yes` (skips interactive prompts that would stall the agent).

### Pre-run Check

Check if `DATABASE_URL` (or the chosen key) already exists in the target `.env`. The CLI exits without provisioning if it finds the key.

If the key exists, offer the user three options:

1. Remove or comment out the existing line, then rerun.
2. Use `--env` to write to a different file (e.g. `--env .env.local`).
3. Use `--key` to write under a different variable name.

Get confirmation before proceeding.

### Options

| Option | Alias | Description | Default |
|--------|-------|-------------|---------|
| `--yes` | `-y` | Skip prompts, use defaults | `false` |
| `--env` | `-e` | .env file path | `./.env` |
| `--key` | `-k` | Connection string env var key | `DATABASE_URL` |
| `--prefix` | `-p` | Prefix for generated public env vars | `PUBLIC_` |
| `--seed` | `-s` | Path to seed SQL file | none |
| `--logical-replication` | `-L` | Enable logical replication | `false` |
| `--ref` | `-r` | Referrer id (use `agent-skills` when provisioning through this skill) | none |

Alternative package managers: `yarn dlx get-db@latest`, `pnpm dlx get-db@latest`, `bunx get-db@latest`, `deno run -A get-db@latest`.

### Output

The CLI writes to the target `.env`:

```
DATABASE_URL=postgresql://...              # pooled (use for application queries)
DATABASE_URL_DIRECT=postgresql://...       # direct (use for migrations, e.g. Prisma)
PUBLIC_POSTGRES_CLAIM_URL=https://pg.new/claim/...
```

## SDK

Use for scripts and programmatic provisioning flows.

```typescript
import { instantPostgres } from 'get-db';

const { databaseUrl, databaseUrlDirect, claimUrl, claimExpiresAt } = await instantPostgres({
  referrer: 'agent-skills',
  seed: { type: 'sql-script', path: './init.sql' },
});
```

Returns `databaseUrl` (pooled), `databaseUrlDirect` (direct, for migrations), `claimUrl`, and `claimExpiresAt` (Date object). The `referrer` parameter is required.

## Vite Plugin

For Vite projects, `vite-plugin-db` auto-provisions a database on `vite de
