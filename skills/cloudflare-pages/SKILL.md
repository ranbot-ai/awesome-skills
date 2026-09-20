---
name: cloudflare-pages
description: Deploy static sites and full-stack apps on Cloudflare Pages with previews, functions, and custom domains. 
category: AI & Agents
source: antigravity
tags: [typescript, react, node, api, ai, agent, workflow, template, security, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/cloudflare-pages
---


# Cloudflare Pages

Deploy frontend projects with preview builds, edge functions, and global CDN delivery on Cloudflare's network.

## When to Use

- Deploying static sites (React, Vue, Astro, Hugo, Next.js static export).
- Full-stack applications using Pages Functions for server-side logic.
- Projects that need automatic preview deployments per pull request.
- Teams that want zero-config CDN with custom domain and TLS.
- Migrating from Vercel, Netlify, or GitHub Pages to Cloudflare's ecosystem.

## Prerequisites

- Node.js 18+ and npm installed locally.
- A Cloudflare account (free tier works for most projects).
- Wrangler CLI installed: `npm install -g wrangler`.
- Authenticated via `wrangler login` or `CLOUDFLARE_API_TOKEN` environment variable.
- Source code in a Git repository (GitHub or GitLab for dashboard integration).

## Project Setup via Wrangler

### Create a New Project

```bash
# Create a new Pages project
npx wrangler pages project create my-site

# List existing projects
npx wrangler pages project list

# Delete a project (removes all deployments)
npx wrangler pages project delete my-site
```

### Deploy from Local Build Output

```bash
# Build your framework first
npm run build

# Deploy the output directory
npx wrangler pages deploy dist --project-name=my-site

# Deploy with a custom branch name (triggers preview URL)
npx wrangler pages deploy dist --project-name=my-site --branch=feature-auth

# Deploy and get the deployment URL in JSON
npx wrangler pages deploy dist --project-name=my-site --branch=main 2>&1 | tail -1
```

### List and Manage Deployments

```bash
# List recent deployments
npx wrangler pages deployment list --project-name=my-site

# Tail live logs from a deployment
npx wrangler pages deployment tail --project-name=my-site --environment=production
```

## Dashboard Git Integration

1. Navigate to **Workers & Pages > Create application > Pages**.
2. Connect your GitHub or GitLab account.
3. Select the repository and configure:
   - **Production branch**: `main`
   - **Build command**: `npm run build`
   - **Build output directory**: `dist` (or `build`, `.next`, `public` depending on framework)
4. Set environment variables per environment (Production vs Preview).

### Framework Presets

Cloudflare auto-detects frameworks. Override if needed:

| Framework  | Build Command        | Output Directory |
|------------|----------------------|------------------|
| React CRA  | `npm run build`      | `build`          |
| Vite       | `npm run build`      | `dist`           |
| Next.js    | `npx @cloudflare/next-on-pages` | `.vercel/output/static` |
| Astro      | `npm run build`      | `dist`           |
| Hugo       | `hugo`               | `public`         |
| SvelteKit  | `npm run build`      | `.svelte-kit/cloudflare` |

## Preview Deployments

Every non-production branch gets a unique preview URL automatically.

```
# URL format for preview deployments
https://<commit-hash>.<project-name>.pages.dev
https://<branch-name>.<project-name>.pages.dev
```

### Branch-Based Access Control

```bash
# Set preview branch patterns in wrangler.toml (Pages-specific)
# Or configure via dashboard: Settings > Builds & deployments
# Include branches: feature/*, staging
# Exclude branches: dependabot/*
```

### Preview Comment on Pull Requests

Enable the Cloudflare Pages GitHub App to post deployment URLs as PR comments. Configure under **Settings > Builds & deployments > Preview comment**.

## Pages Functions

Pages Functions provide server-side logic deployed alongside your static site. Place files in a `functions/` directory at the project root.

### Basic API Route

```typescript
// functions/api/hello.ts
export const onRequestGet: PagesFunction = async (context) => {
  return new Response(JSON.stringify({ message: "Hello from the edge" }), {
    headers: { "Content-Type": "application/json" },
  });
};

// functions/api/users/[id].ts — dynamic route parameter
export const onRequestGet: PagesFunction = async (context) => {
  const userId = context.params.id;
  return new Response(JSON.stringify({ userId }), {
    headers: { "Content-Type": "application/json" },
  });
};
```

### Middleware

```typescript
// functions/_middleware.ts — runs before all routes
export const onRequest: PagesFunction = async (context) => {
  const authHeader = context.request.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return new Response("Unauthorized", { status: 401 });
  }
  return context.next();
};
```

### Functions with Bindings

```typescript
// functions/api/data.ts — using KV and D1 bindings
interface Env {
  MY_KV: KVNamespace;
  MY_DB: D1Database;
  MY_BUCKET: R2Bucket;
}

export const onRequestGet: PagesFunction<Env> = async (context) => {
  // Read from KV
  const cached = await context.env.MY_KV.get("key");
  if (cached) return new Response(cached);

  // Query D1
  const result = await context.env.MY_DB.prepare(
    "SELECT * FROM items LIMIT 10"
  ).al
