---
name: client-secret-exposure-audit
description: Audit a deployed web app for secrets exposed to the browser: hardcoded API keys/tokens in JS, secrets in HTML meta/attributes/comments, publicly reachable source/config/deploy files, and header/CORS m
category: Security & Systems
source: antigravity
tags: [javascript, markdown, api, claude, ai, workflow, design, security, vulnerability, stripe]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/client-secret-exposure-audit
---


# Client-Side Secret & Sensitive-File Exposure Audit

## Overview

Modern web apps ship a lot of code and config to the browser. When credentials
leak into that client-visible surface — hardcoded in JavaScript, tucked into HTML
`meta`/`data-*` attributes or comments, or served as raw source/config/deploy
files that were never meant to be public — anyone can read them with `curl` and a
browser. This skill is a **defensive, read-only** workflow for finding that class
of exposure on a web app **you are authorized to assess**.

It maps to OWASP **A02:2021 Cryptographic Failures** (sensitive data exposure),
**A05:2021 Security Misconfiguration**, and CWE-798 (hardcoded credentials),
CWE-200 (sensitive information exposure), CWE-540 (source code in a production
build). It only fetches resources the server already hands to any anonymous
visitor — it does not exploit, brute-force, or mutate anything.

## When to Use This Skill

- Use when you need to check whether a deployed site leaks API keys, tokens, or
  passwords in its client-side bundle before shipping or during a review.
- Use when working with a static/SPA deployment (Vercel, Netlify, Nginx, S3,
  GitHub Pages) and you want to confirm no source/config/deploy files are
  publicly reachable.
- Use when the user asks to "find secrets," "audit exposed files," "check the
  JS/HTML for credentials," or run a lightweight sensitive-data-exposure pass on
  a URL they own or are authorized to test.
- Do **not** use this to attack third-party sites. See *Security & Safety Notes*.

## How It Works

Set the target once. Every command below reads only what the server serves
publicly.

```bash
BASE="https://TARGET.example"     # authorized target, no trailing path
umask 077
WORK="$(mktemp -d)" || exit 1
cd "$WORK" || exit 1
```

### Step 1: Fetch the page and inspect response headers

```bash
curl --silent --show-error --connect-timeout 5 --max-time 20 \
  --max-filesize 1048576 --proto '=https' -D headers.txt -o body.html "$BASE/"
# Inspect locally; redact Set-Cookie and credential-bearing values before sharing.
```

Flag on the headers:

- `access-control-allow-origin: *` can be appropriate for public assets. Browsers
  reject wildcard origins for credentialed reads; assess actual sensitive endpoint
  responses and credential mode before claiming a CORS vulnerability.
- Missing `Content-Security-Policy`, `X-Frame-Options`/`frame-ancestors`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`.
- Missing/weak `Strict-Transport-Security`.
- `Server`/framework version banners that fingerprint the stack.

### Step 2: Grep the HTML for secrets and sinks

Use a local parser/scanner to report only file paths, line numbers, candidate types
and redacted fingerprints. Do not print matching lines or whole HTML comments/meta
tags into terminal/model output: they may contain the very secrets being audited.
Pattern matches are candidates, not proof of valid credentials; public/publishable
keys and placeholders require contextual classification.

### Step 3: Validate discovered scripts before fetching

Do not automatically fetch discovered URLs. Extract candidates as inert data with an HTML parser and URL parser, resolve against the authorized base, and reject any scheme other than HTTPS, embedded credentials, unexpected ports or origins. Before a request, verify all resolved destination addresses are public (not loopback, link-local, private, multicast, reserved or unspecified), pin the approved address for that connection to prevent DNS rebinding, and disable redirects. A redirect or additional origin requires separate scope validation. Use a trusted network client that enforces these checks, or stop at an inventory of candidate scripts. Never follow `require`/`import` paths or sourcemaps without the same validation. Store responses privately and redact secret values before terminal or model output.

Also scan any sourcemaps (`*.js.map`) — they can rebuild original source with
comments intact.

### Step 4: Probe for publicly reachable source / config / deploy files

SPAs often have a catch-all rewrite that returns `index.html` for unknown paths,
so compare status, content type and normalized content against multiple nonexistent
paths. Different sizes alone do not prove a file: dynamic error/SPA pages vary.

```bash
FALLBACK=$(curl --silent --show-error --connect-timeout 5 --max-time 20 --max-filesize 1048576 "$BASE/____nope____$RANDOM" | wc -c)   # SPA fallback size
for p in /.env /.env.local /.env.production /.git/config /.git/HEAD \
  /package.json /package-lock.json /vercel.json /.vercel/project.json \
  /Dockerfile /docker-compose.yml /wrangler.toml /.gitignore \
  /server/index.js /src/config/app.config.js /config.js \
  /src/services/payment.service.js /webpack.config.js /next.config.js; do
    read -r code size < <(curl --silent --show-error --connect-timeout 5 --max-time 20 --max-filesize 1048576 -o /dev/null -w "%{http_code} %{size_download}" "$BAS
