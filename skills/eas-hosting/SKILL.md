---
name: eas-hosting
description: Curated upstream guidance for Eas Hosting; use when the workflow matches the user goal. 
category: AI & Agents
source: antigravity
tags: [typescript, react, node, api, ai, agent, gpt, workflow, supabase, firebase]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/eas-hosting
---

# EAS Hosting

> **EAS service - costs apply.** EAS Hosting is a paid Expo Application Services product with free-tier limits; production deploys use your plan's request and bandwidth allowance. See https://expo.dev/pricing. Authoring API routes and exporting the web bundle are free and open source, and you can self-host the exported server output instead of EAS Hosting.

EAS Hosting deploys your Expo **web app and API routes** to Expo's managed edge (Cloudflare Workers). Export the web bundle with `npx expo export -p web` and ship it with `eas deploy` - the same command deploys any Expo Router API routes bundled alongside it. This skill covers deploying a website, authoring API routes, and the hosting runtime; see the Deployment section below for the deploy workflow.

## When to Use API Routes

Use API routes when you need:

- **Server-side secrets** — API keys, database credentials, or tokens that must never reach the client
- **Database operations** — Direct database queries that shouldn't be exposed
- **Third-party API proxies** — Hide API keys when calling external services (OpenAI, Stripe, etc.)
- **Server-side validation** — Validate data before database writes
- **Webhook endpoints** — Receive callbacks from services like Stripe or GitHub
- **Rate limiting** — Control access at the server level
- **Heavy computation** — Offload processing that would be slow on mobile

## When NOT to Use API Routes

Avoid API routes when:

- **Data is already public** — Use direct fetch to public APIs instead
- **No secrets required** — Static data or client-safe operations
- **Real-time updates needed** — Use WebSockets or services like Supabase Realtime
- **Simple CRUD** — Consider Firebase, Supabase, or Convex for managed backends
- **File uploads** — Use direct-to-storage uploads (S3 presigned URLs, Cloudflare R2)
- **Authentication only** — Use Clerk, Auth0, or Firebase Auth instead

## File Structure

API routes live in the `app` directory with `+api.ts` suffix:

```
app/
  api/
    hello+api.ts          → GET /api/hello
    users+api.ts          → /api/users
    users/[id]+api.ts     → /api/users/:id
  (tabs)/
    index.tsx
```

## Basic API Route

```ts
// app/api/hello+api.ts
export function GET(request: Request) {
  return Response.json({ message: "Hello from Expo!" });
}
```

## HTTP Methods

Export named functions for each HTTP method:

```ts
// app/api/items+api.ts
export function GET(request: Request) {
  return Response.json({ items: [] });
}

export async function POST(request: Request) {
  const body = await request.json();
  return Response.json({ created: body }, { status: 201 });
}

export async function PUT(request: Request) {
  const body = await request.json();
  return Response.json({ updated: body });
}

export async function DELETE(request: Request) {
  return new Response(null, { status: 204 });
}
```

## Dynamic Routes

```ts
// app/api/users/[id]+api.ts
export function GET(request: Request, { id }: { id: string }) {
  return Response.json({ userId: id });
}
```

## Request Handling

### Query Parameters

```ts
export function GET(request: Request) {
  const url = new URL(request.url);
  const page = url.searchParams.get("page") ?? "1";
  const limit = url.searchParams.get("limit") ?? "10";

  return Response.json({ page, limit });
}
```

### Headers

```ts
export function GET(request: Request) {
  const auth = request.headers.get("Authorization");

  if (!auth) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }

  return Response.json({ authenticated: true });
}
```

### JSON Body

```ts
export async function POST(request: Request) {
  const { email, password } = await request.json();

  if (!email || !password) {
    return Response.json({ error: "Missing fields" }, { status: 400 });
  }

  return Response.json({ success: true });
}
```

## Environment Variables

Use `process.env` for server-side secrets:

```ts
// app/api/ai+api.ts
export async function POST(request: Request) {
  const { prompt } = await request.json();

  const response = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
    },
    body: JSON.stringify({
      model: "gpt-4",
      messages: [{ role: "user", content: prompt }],
    }),
  });

  const data = await response.json();
  return Response.json(data);
}
```

Set environment variables:

- **Local**: Create `.env` file (never commit)
- **EAS Hosting**: Use `eas env:create` or Expo dashboard

## CORS Headers

Add CORS for web clients:

```ts
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

export function OPTIONS() {
  return new Response(null, { headers: corsHeaders });
}

export function GET() {
  return Response.json({ data: "value" }, { headers
