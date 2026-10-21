---
name: dropthehassle-publish
description: Publish a finished static site to a free HTTPS link with DropTheHassle: build it if needed, deploy, hand over the claim link, verify it is live, never spend money. 
category: AI & Agents
source: antigravity
tags: [react, node, api, mcp, claude, ai, agent, image, security, stripe]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/dropthehassle-publish
---


# DropTheHassle publish

## External tool prerequisite

Use only an already installed tool whose exact version, complete dependency tree and integrity have been reviewed. This skill does not bootstrap tools or activate external plugins. If the prerequisite is missing, stop that executable path and report it; continue with static analysis when possible. A separate installation task must pin immutable artifacts, stage them outside active agent directories with lifecycle scripts disabled, inspect every bundled file and executable entry point (including tests and hooks), and obtain approval before activation or host configuration changes. Do not substitute a same-named workspace script or fetch a moving branch.


## Overview

DropTheHassle (https://dropthehassle.com) hosts finished static files (HTML, CSS, JS, images) on a
free `name.dropthehassle.app` link with HTTPS, and can later put the same site on a real domain
with no DNS editing. A first deploy needs no account: it returns a live URL and a claim link. This
skill makes the agent check that the folder is a finished build, deploy it with the CLI or MCP
server, give the human the claim link, and verify the site is live. No DropTheHassle tool can pay,
and the agent must never try to. Adapted from the official skill, which also ships a local
preflight script and longer references: https://github.com/bosmdavid-gif/dropthehassle-skill

## When to Use This Skill

- Use when the user asks to publish, deploy, host or share a site they built with an AI tool and
  wants DropTheHassle, or wants it on a free link or their own domain without DNS work and has not
  picked another host.
- Use when the folder is static output: a hand-written `index.html`, or a Vite, Astro, Create React
  App, Nuxt generate, Next.js `output: 'export'` or TanStack Start SPA build.
- Do not use for apps that need a server at runtime (SSR, API routes, server functions, PHP). Say
  that DropTheHassle only hosts static files.

## How It Works

### Step 1: Find the finished folder

- Plain folder with `index.html` at the top: that is the site.
- Project with a `build` script or a `vite.config.*`, `next.config.*`, `astro.config.*` or
  `nuxt.config.*`: look for `index.html` in `dist/`, `build/`, `out/` or `.output/public/`. If
  there is none, install with the lockfile's package manager and run the build first. Next.js
  needs `output: 'export'` (writes `out/`).
- An `index.html` that loads `/src/main.tsx` or another `.ts`, `.tsx`, `.jsx` or `/src/` script
  is a dev entry. Build it.
- The DropTheHassle CLI and MCP server never run the build. On unbuilt source they stop and print
  the build command.

### Step 2: Check the limits

Before the site is claimed: 25 MB and 1,000 files, and no executables or archives
(`.exe .msi .apk .dmg .scr .bat .zip .rar .7z .iso`). Signed in: 100 MB and 5,000 files. One
network can create 5 new unclaimed sites per hour and 20 per day. `node_modules`, `.git` and
hidden files are left out, except `.well-known`.

### Step 3: Deploy

CLI, run on the project folder after the build (or on the plain site folder):

```bash
dropthehassle deploy .
```

It prints the live URL and a claim link, and writes `.dropthehassle.json` in that folder so the
next deploy from it updates the same site. That file holds the site's key: keep it out of git.
`--login` puts the site on the human's account after a browser approval; `--slug name` only works
with `--login`; `--code XXXX-XXXX` uses a 15-minute dashboard code for an existing site.

MCP, in Claude Code:

```bash
claude mcp add dropthehassle -- dropthehassle-mcp
```

Then call `deploy_site` with `folder` set to the absolute path. The hosted connector
`https://dropthehassle.com/mcp` cannot read the disk: send `files` inline as
`{path, content, encoding}` (`utf8` or `base64`). Account tools need the human's token from
dropthehassle.com, menu, Connect your AI, set as `DTH_TOKEN` by the human in their own config.

### Step 4: Hand over and verify

Tell the human the live URL and the claim link, and that the claim link works for 7 days. An
unclaimed site can be removed after that. Then check:

```bash
curl -s "https://dropthehassle.com/api/v1/check?host=NAME.dropthehassle.app"
```

`outcome` should be `live` and `secure` true. The same check is on
https://dropthehassle.com/is-my-website-down.

### Step 5: Domains, only if asked

Check names with the MCP `search_domain` tool or
`curl -s "https://dropthehassle.com/api/v1/domains/search?q=NAME.com"`, and report only names the
answer marks `available`, with the price it returned. Buying is the human's step: after they claim
the site, `get_checkout_link` returns a `checkout.stripe.com` link for them to open and pay.

## Examples

### Example 1: Vite project

```text
User: Put this site online.
Agent: No dist/ yet, so runs npm install && npm run build, then dropthehassle deploy .
       Reports: Live at https://yourname.dropthehassle.app, plus the claim link (7 days).
       Runs the live chec
