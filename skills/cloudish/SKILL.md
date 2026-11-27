---
name: cloudish
description: Deploy a Dockerfile, source folder, or existing image to Cloudish as a running container at a live URL, built server-side with no local Docker, with confirmation before spending credits. 
category: Document Processing
source: antigravity
tags: [python, javascript, typescript, api, claude, ai, agent, gpt, automation, document]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/cloudish
---


# Cloudish

## Overview

Cloudish (https://cloudish.ai) runs a container from a Dockerfile, a source folder, or an existing
image and serves it at a live HTTPS URL. Images are built on Cloudish's servers, so no local Docker
daemon is needed. The agent creates its own API key with one unauthenticated call, and usage is paid
from that key's prepaid credits, which it can never exceed. A human can claim the key later to add
credits and see a dashboard. This skill makes the agent prepare the project, deploy it, report the
URL, and diagnose failures from real build and container logs.

## When to Use This Skill

- Use when the user asks to deploy, host, or put online an app, API, bot, or website on Cloudish.
- Use when the user wants a container run without installing Docker locally.
- Use when a database-backed service needs a persistent volume (SQLite or Postgres inside the container).
- Use when the user asks for a Cloudish API key or a link to add credits to one.
- Do not use for platforms other than Cloudish, or for static sites the user wants on a different host.

## How It Works

Last updated 2026-11-24 ([changelog](references/changelog.md)).

Cloudish is an agent-first, API-key/credit, container-deployment platform: it
builds images server-side, so no local Docker or `docker build` is needed —
a local build is CPU/memory-heavy and often more than the machine you're on
can spare, and there's no registry to manage either way.
Cloudish hosts a private registry and runs the resulting containers with
attached storage. Everything from getting a key to deploying takes only the
calls below: nothing to install, no account to create.

Never print API keys or secrets into chat, source code or logs. Never
report a deploy as succeeded until you've verified it: the build reached
`succeeded`, and the app's logs (section 7) show it started and is
listening. Try its URL too if you can reach it, but some environments reach
cloudish.ai but not the apps' own domain, so a URL you can't
open isn't a failure by itself.

### 0. Get an API key

Creating a key itself needs no credential — every other call below
authenticates with the key it returns (`Authorization: Bearer
$CLOUDISH_API_KEY`). New keys include 0.1 credits to start, subject to availability. Mint new keys or delegate credits from one you have, as fits: a sub-agent
or container that needs its own credential gets a key under yours, funded by
transfer (credits.md).

```bash
curl -X POST https://cloudish.ai/api/v1/keys -H "content-type: application/json" \
  -d '{"alias": "<alias>", "agent": "<agent>", "model": "<model>", "source": "<source>"}'
```

The key comes back in the response:

```json
{ "apiKey": { "alias": "my-app", "balance": 0.1, ... }, "key": "cld_****", "claimUrl": "https://..." }
```

`key` authenticates every call below (`Authorization: Bearer
$CLOUDISH_API_KEY`). If you already have a key for this work (from an
earlier run, or one your environment provides), reuse it instead of
minting another. Claiming is optional: `claimUrl` attaches this key to the
Cloudish account of whoever opens it and signs in, for a dashboard and
adding credits; the claim may also add a small credit bonus to that account,
which they can move into this key. It works once and expires in 30 minutes;
`GET /api/v1/credits/claim` returns a new one (section 9).

`alias` is optional: a short name for what you're deploying (e.g.
`todo-app`) makes a good one, or leave it out for a random one. You get
that name if it's free, or a close variant (e.g. `my-app-otter`) if not,
and it can be renamed later (`PATCH /api/v1/me`). Use the
`apiKey.alias` that comes back, the `{alias}` in every project path below.

`agent`, `model` and `source` are all optional; leave out any you don't know.
`agent` is the product you run in (`claude-code`, `claude`, `chatgpt`,
`codex`, `cursor`, `grok`, ...), `model` you use (`claude-opus-5-5`,
`gpt-5.5`, `deepseek-v4-pro`, ...), and `source` what brought you to
Cloudish (`user-request`, `plugin-request`, `skill-request`,
`agent-choice`, `automation`, `evaluating`, or your own words). Leave it
out rather than guess. They only tell Cloudish which agents use it and
where they came from.

*Advanced minting: see [minting.md](references/minting.md).*

### 1. Create (or update) a project and deploy it — one call

`POST /api/v1/projects` creates the project if it doesn't exist yet (or
updates it if it does — same call either way, so a redeploy script can
always call this unconditionally), and optionally attaches an image in the
same request. Two ways to attach one, mutually exclusive:

**An image you already have** — registered immediately:

```bash
curl -X POST https://cloudish.ai/api/v1/projects \
  -H "Authorization: Bearer $CLOUDISH_API_KEY" -H "content-type: application/json" \
  -d '{"name": "my-app", "image": "ghcr.io/acme/my-app:1.0.0", "port": 8080, "alwaysOn": true}'
# -> { "project": { "path": "your-alias/my-app", ... }, "app": { "status": "registered", ... },
#
