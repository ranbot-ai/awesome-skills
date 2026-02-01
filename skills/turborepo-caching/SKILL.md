---
name: turborepo-caching
description: Configure Turborepo for efficient monorepo builds with local and remote caching. Use when setting up Turborepo, optimizing build pipelines, or implementing distributed caching. 
category: Document Processing
source: antigravity
tags: [typescript, node, api, ai, workflow, template, document, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/turborepo-caching
---


# Turborepo Caching

Production patterns for Turborepo build optimization.

## Do not use this skill when

- The task is unrelated to turborepo caching
- You need a different domain or tool outside this scope

## Instructions

- Clarify goals, constraints, and required inputs.
- Apply relevant best practices and validate outcomes.
- Provide actionable steps and verification.
- If detailed examples are required, open `resources/implementation-playbook.md`.

## Use this skill when

- Setting up new Turborepo projects
- Configuring build pipelines
- Implementing remote caching
- Optimizing CI/CD performance
- Migrating from other monorepo tools
- Debugging cache misses

## Core Concepts

### 1. Turborepo Architecture

```
Workspace Root/
├── apps/
│   ├── web/
│   │   └── package.json
│   └── docs/
│       └── package.json
├── packages/
│   ├── ui/
│   │   └── package.json
│   └── config/
│       └── package.json
├── turbo.json
└── package.json
```

### 2. Pipeline Concepts

| Concept | Description |
|---------|-------------|
| **dependsOn** | Tasks that must complete first |
| **cache** | Whether to cache outputs |
| **outputs** | Files to cache |
| **inputs** | Files that affect cache key |
| **persistent** | Long-running tasks (dev servers) |

## Templates

### Template 1: turbo.json Configuration

```json
{
  "$schema": "https://turbo.build/schema.json",
  "globalDependencies": [
    ".env",
    ".env.local"
  ],
  "globalEnv": [
    "NODE_ENV",
    "VERCEL_URL"
  ],
  "pipeline": {
    "build": {
      "dependsOn": ["^build"],
      "outputs": [
        "dist/**",
        ".next/**",
        "!.next/cache/**"
      ],
      "env": [
        "API_URL",
        "NEXT_PUBLIC_*"
      ]
    },
    "test": {
      "dependsOn": ["build"],
      "outputs": ["coverage/**"],
      "inputs": [
        "src/**/*.tsx",
        "src/**/*.ts",
        "test/**/*.ts"
      ]
    },
    "lint": {
      "outputs": [],
      "cache": true
    },
    "typecheck": {
      "dependsOn": ["^build"],
      "outputs": []
    },
    "dev": {
      "cache": false,
      "persistent": true
    },
    "clean": {
      "cache": false
    }
  }
}
```

### Template 2: Package-Specific Pipeline

```json
// apps/web/turbo.json
{
  "$schema": "https://turbo.build/schema.json",
  "extends": ["//"],
  "pipeline": {
    "build": {
      "outputs": [".next/**", "!.next/cache/**"],
      "env": [
        "NEXT_PUBLIC_API_URL",
        "NEXT_PUBLIC_ANALYTICS_ID"
      ]
    },
    "test": {
      "outputs": ["coverage/**"],
      "inputs": [
        "src/**",
        "tests/**",
        "jest.config.js"
      ]
    }
  }
}
```

### Template 3: Remote Caching with Vercel

```bash
# Login to Vercel
npx turbo login

# Link to Vercel project
npx turbo link

# Run with remote cache
turbo build --remote-only

# CI environment variables
TURBO_TOKEN=your-token
TURBO_TEAM=your-team
```

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main]
  pull_request:

env:
  TURBO_TOKEN: ${{ secrets.TURBO_TOKEN }}
  TURBO_TEAM: ${{ vars.TURBO_TEAM }}

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Build
        run: npx turbo build --filter='...[origin/main]'

      - name: Test
        run: npx turbo test --filter='...[origin/main]'
```

### Template 4: Self-Hosted Remote Cache

```typescript
// Custom remote cache server (Express)
import express from 'express';
import { createReadStream, createWriteStream } from 'fs';
import { mkdir } from 'fs/promises';
import { join } from 'path';

const app = express();
const CACHE_DIR = './cache';

// Get artifact
app.get('/v8/artifacts/:hash', async (req, res) => {
  const { hash } = req.params;
  const team = req.query.teamId || 'default';
  const filePath = join(CACHE_DIR, team, hash);

  try {
    const stream = createReadStream(filePath);
    stream.pipe(res);
  } catch {
    res.status(404).send('Not found');
  }
});

// Put artifact
app.put('/v8/artifacts/:hash', async (req, res) => {
  const { hash } = req.params;
  const team = req.query.teamId || 'default';
  const dir = join(CACHE_DIR, team);
  const filePath = join(dir, hash);

  await mkdir(dir, { recursive: true });

  const stream = createWriteStream(filePath);
  req.pipe(stream);

  stream.on('finish', () => {
    res.json({ urls: [`${req.protocol}://${req.get('host')}/v8/artifacts/${hash}`] });
  });
});

// Check artifact exists
app.head('/v8/artifacts/:hash', async (req, res) => {
  const { hash } = req.params;
  const team = req.query.teamId || 'default';
  const filePath = join(CACHE_DIR, team, hash);

  try {
    await fs.access(filePath);
    res.status(200).end();
  } catch {
    res.status(404).end();
  }
});

app.listen(3000);
```

```json
// turbo.json for self-hosted cache
{
  "remoteCache": {
    "signature": false
