---
name: cloudflare-workers
description: Build and deploy edge functions with Cloudflare Workers and Wrangler. Use for APIs, cron jobs, and edge middleware. 
category: AI & Agents
source: antigravity
tags: [javascript, typescript, node, api, ai, agent, template, image, security, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/cloudflare-workers
---


# Cloudflare Workers

Deploy JavaScript and TypeScript functions to Cloudflare's global edge network with sub-millisecond cold starts.

## When to Use

- Building lightweight APIs and microservices at the edge.
- Adding middleware (auth, rate limiting, header injection) in front of origin servers.
- Running cron jobs on a schedule without maintaining infrastructure.
- Processing webhooks, image transformations, or A/B testing logic.
- Serving dynamic content from KV, D1, or R2 storage bindings.

## Prerequisites

- Node.js 18+ installed locally.
- Wrangler CLI: `npm install -g wrangler`.
- Cloudflare account (free plan supports 100,000 requests/day).
- Authenticated: `wrangler login` or set `CLOUDFLARE_API_TOKEN`.

## Quick Start

```bash
# Scaffold a new Worker project
npm create cloudflare@latest my-worker
cd my-worker

# Login to Cloudflare
npx wrangler login

# Start local development server (port 8787)
npx wrangler dev

# Deploy to production
npx wrangler deploy
```

## Essential Wrangler Commands

```bash
# Local development with remote bindings (KV, D1, R2)
npx wrangler dev --remote

# Deploy to a specific environment
npx wrangler deploy --env staging

# Set a secret (prompts for value)
npx wrangler secret put API_TOKEN
npx wrangler secret put API_TOKEN --env staging

# List secrets
npx wrangler secret list

# Tail production logs in real time
npx wrangler tail

# Tail with filters
npx wrangler tail --status=error --search="timeout"

# View deployment versions
npx wrangler deployments list

# Rollback to a previous deployment
npx wrangler rollback
```

## Wrangler Configuration

```toml
# wrangler.toml
name = "my-api"
main = "src/index.ts"
compatibility_date = "2024-09-01"
compatibility_flags = ["nodejs_compat"]

# Custom routes
routes = [
  { pattern = "api.example.com/*", zone_name = "example.com" }
]

# Or use a workers.dev subdomain
# workers_dev = true

# Environment variables (non-secret)
[vars]
ENVIRONMENT = "production"
API_VERSION = "v2"

# Staging environment override
[env.staging]
name = "my-api-staging"
routes = [
  { pattern = "api-staging.example.com/*", zone_name = "example.com" }
]
[env.staging.vars]
ENVIRONMENT = "staging"
```

## Worker Examples

### Basic API Router

```typescript
// src/index.ts
export interface Env {
  ENVIRONMENT: string;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    switch (url.pathname) {
      case "/":
        return new Response("OK", { status: 200 });

      case "/api/health":
        return Response.json({
          status: "healthy",
          env: env.ENVIRONMENT,
          timestamp: new Date().toISOString(),
        });

      case "/api/data":
        if (request.method !== "POST") {
          return new Response("Method Not Allowed", { status: 405 });
        }
        const body = await request.json();
        // Process in the background after returning response
        ctx.waitUntil(logToAnalytics(body));
        return Response.json({ received: true });

      default:
        return new Response("Not Found", { status: 404 });
    }
  },
};

async function logToAnalytics(data: unknown): Promise<void> {
  await fetch("https://analytics.example.com/ingest", {
    method: "POST",
    body: JSON.stringify(data),
    headers: { "Content-Type": "application/json" },
  });
}
```

### Middleware: Rate Limiting with KV

```typescript
// src/rate-limiter.ts
interface Env {
  RATE_LIMIT_KV: KVNamespace;
  ORIGIN_URL: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    const key = `ratelimit:${ip}`;
    const window = 60; // seconds
    const maxRequests = 100;

    const current = parseInt((await env.RATE_LIMIT_KV.get(key)) || "0");

    if (current >= maxRequests) {
      return new Response("Too Many Requests", {
        status: 429,
        headers: { "Retry-After": String(window) },
      });
    }

    await env.RATE_LIMIT_KV.put(key, String(current + 1), {
      expirationTtl: window,
    });

    // Forward to origin
    const originRequest = new Request(env.ORIGIN_URL + new URL(request.url).pathname, request);
    return fetch(originRequest);
  },
};
```

## KV Storage Binding

```toml
# wrangler.toml
[[kv_namespaces]]
binding = "MY_KV"
id = "abc123def456"

# Preview namespace for local dev
[[kv_namespaces]]
binding = "MY_KV"
id = "abc123def456"
preview_id = "preview789"
```

```typescript
// KV operations in a Worker
interface Env {
  MY_KV: KVNamespace;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Write with TTL
    await env.MY_KV.put("session:abc", JSON.stringify({ user: "alice" }), {
      expirationTtl: 3600,
    });

    // Read
    const session = await env.MY_KV.get("session:abc", "json");

    // List keys by prefix
    const list = await env.MY_KV.list({ prefix: "session:", limit:
