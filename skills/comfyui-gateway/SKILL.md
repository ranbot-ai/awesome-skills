---
name: comfyui-gateway
description: REST API gateway for ComfyUI servers. Workflow management, job queuing, webhooks, caching, auth, rate limiting, and image delivery (URL + base64). 
category: Creative & Media
source: antigravity
tags: [python, javascript, typescript, node, api, claude, ai, llm, workflow, template]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/comfyui-gateway
---


# ComfyUI Gateway

## Overview

REST API gateway for ComfyUI servers. Workflow management, job queuing, webhooks, caching, auth, rate limiting, and image delivery (URL + base64).

## When to Use This Skill

- When the user mentions "comfyui" or related topics
- When the user mentions "comfy ui" or related topics
- When the user mentions "stable diffusion api gateway" or related topics
- When the user mentions "gateway comfyui" or related topics
- When the user mentions "api gateway imagens" or related topics
- When the user mentions "queue imagens" or related topics

## Do Not Use This Skill When

- The task is unrelated to comfyui gateway
- A simpler, more specific tool can handle the request
- The user needs general-purpose assistance without domain expertise

## How It Works

A production-grade REST API gateway that transforms any ComfyUI server into a universal,
secure, and scalable service. Supports workflow templates with placeholders, job queuing
with priorities, webhook callbacks, result caching, and multiple storage backends.

## Architecture Overview

```
┌─────────────┐     ┌──────────────────────────────────┐     ┌──────────┐
│   Clients    │────▶│        ComfyUI Gateway           │────▶│ ComfyUI  │
│ (curl, n8n,  │     │                                  │     │ Server   │
│  Claude,     │     │  ┌─────────┐  ┌──────────────┐  │     │ (local/  │
│  Lovable,    │     │  │ Fastify │  │ BullMQ Queue │  │     │  remote) │
│  Supabase)   │     │  │ API     │──│ (or in-mem)  │  │     └──────────┘
│              │◀────│  └─────────┘  └──────────────┘  │
│              │     │  ┌─────────┐  ┌──────────────┐  │     ┌──────────┐
│              │     │  │ Auth +  │  │ Storage      │  │────▶│ S3/MinIO │
│              │     │  │ RateL.  │  │ (local/S3)   │  │     │(optional)│
│              │     │  └─────────┘  └──────────────┘  │     └──────────┘
└─────────────┘     └──────────────────────────────────┘
```

## Components

| Component | Purpose | File(s) |
|-----------|---------|---------|
| **API Gateway** | REST endpoints, validation, CORS | `src/api/` |
| **Worker** | Processes jobs, talks to ComfyUI | `src/worker/` |
| **ComfyUI Client** | HTTP + WebSocket to ComfyUI | `src/comfyui/` |
| **Workflow Manager** | Template storage, placeholder rendering | `src/workflows/` |
| **Storage Provider** | Local disk + S3-compatible | `src/storage/` |
| **Cache** | Hash-based deduplication | `src/cache/` |
| **Notifier** | Webhook with HMAC signing | `src/notifications/` |
| **Auth** | API key + JWT + rate limiting | `src/auth/` |
| **DB** | SQLite (better-sqlite3) or Postgres | `src/db/` |
| **CLI** | Init, add-workflow, run, worker | `src/cli/` |

## Quick Start

```bash

## 1. Install

cd comfyui-gateway
npm install

## 2. Configure

cp .env.example .env

## 3. Initialize

npx tsx src/cli/index.ts init

## 4. Add A Workflow

npx tsx src/cli/index.ts add-workflow ./workflows/sdxl_realism_v1.json \
  --id sdxl_realism_v1 --schema ./workflows/sdxl_realism_v1.schema.json

## 5. Start (Api + Worker In One Process)

npm run dev

## Or Separately:

npm run start:api   # API only
npm run start:worker # Worker only
```

## Environment Variables

All configuration is via `.env` — nothing is hardcoded:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | API server port |
| `HOST` | `0.0.0.0` | API bind address |
| `COMFYUI_URL` | `http://127.0.0.1:8188` | ComfyUI server URL |
| `COMFYUI_TIMEOUT_MS` | `300000` | Max wait for ComfyUI (5min) |
| `API_KEYS` | `""` | Comma-separated API keys (`key:role`) |
| `JWT_SECRET` | `""` | JWT signing secret (empty = JWT disabled) |
| `REDIS_URL` | `""` | Redis URL (empty = in-memory queue) |
| `DATABASE_URL` | `./data/gateway.db` | SQLite path or Postgres URL |
| `STORAGE_PROVIDER` | `local` | `local` or `s3` |
| `STORAGE_LOCAL_PATH` | `./data/outputs` | Local output directory |
| `S3_ENDPOINT` | `""` | S3/MinIO endpoint |
| `S3_BUCKET` | `""` | S3 bucket name |
| `S3_ACCESS_KEY` | `""` | S3 access key |
| `S3_SECRET_KEY` | `""` | S3 secret key |
| `S3_REGION` | `us-east-1` | S3 region |
| `WEBHOOK_SECRET` | `""` | HMAC signing secret for webhooks |
| `WEBHOOK_ALLOWED_DOMAINS` | `*` | Comma-separated allowed callback domains |
| `MAX_CONCURRENCY` | `1` | Parallel jobs per GPU |
| `MAX_IMAGE_SIZE` | `2048` | Maximum dimension (width or height) |
| `MAX_BATCH_SIZE` | `4` | Maximum batch size |
| `CACHE_ENABLED` | `true` | Enable result caching |
| `CACHE_TTL_SECONDS` | `86400` | Cache TTL (24h) |
| `RATE_LIMIT_MAX` | `100` | Requests per window |
| `RATE_LIMIT_WINDOW_MS` | `60000` | Rate limit window (1min) |
| `LOG_LEVEL` | `info` | Pino log level |
| `PRIVACY_MODE` | `false` | Redact prompts from logs |
| `CORS_ORIGINS` | `*` | Allowed CORS origins |
| `NODE_ENV` | `development` | Environment |

## Health & Capabilities

```
GET /health
→ { ok: true, version, comfyui: { reachable, url, models? }, uptime }

GET /capabilities
→ { workflows: [..
