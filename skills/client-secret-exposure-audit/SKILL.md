---
name: client-secret-exposure-audit
description: Audit a deployed web app for secrets exposed to the browser: hardcoded API keys/tokens in JS, secrets in HTML meta/attributes/comments, publicly reachable source/config/deploy files, and header/CORS m
category: AI & Agents
source: antigravity
tags: [javascript, markdown, api, claude, ai, workflow, security, stripe, docker, aws]
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
WORK="$(mktemp -d)"; cd "$WORK"
```

### Step 1: Fetch the page and inspect response headers

```bash
curl -s -D headers.txt -o body.html "$BASE/"
cat headers.txt
```

Flag on the headers:

- `access-control-allow-origin: *` — permissive CORS (worse when paired with
  credentials).
- Missing `Content-Security-Policy`, `X-Frame-Options`/`frame-ancestors`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`.
- Missing/weak `Strict-Transport-Security`.
- `Server`/framework version banners that fingerprint the stack.

### Step 2: Grep the HTML for secrets and sinks

```bash
grep -inE "secret|passwd|password|api[_-]?key|apikey|token|bearer|authorization|\
akia|sk_live|sk_test|pk_live|whsec_|ghp_|aiza|private[_-]?key|mongodb(\+srv)?://|\
data-[a-z-]*(secret|token|key|access)" body.html
grep -inE "<!--" body.html            # read every HTML comment
grep -ioE '<meta[^>]+>' body.html     # meta tags often carry keys/ids
grep -ioE '<script[^>]+src="[^"]+"'   body.html   # enumerate JS bundles
```

Secrets hide in `data-*` attributes, `<meta>` tags, `hidden` `<div>`s, and
`<!-- comments -->` at least as often as in scripts.

### Step 3: Pull every JavaScript bundle and scan it

```bash
# extract script srcs, resolve relative paths against $BASE, fetch and scan
grep -ioE 'src="[^"]+\.js"' body.html | sed -E 's/^src="//; s/"$//' \
 | while read -r p; do
     u="$p"; case "$p" in http*) ;; /*) u="$BASE$p";; *) u="$BASE/$p";; esac
     f="js_$(echo "$p" | tr '/:' '__')"
     curl -s "$u" -o "$f" && echo "== $u =="
   done
grep -rinE "secret|password|api[_-]?key|token|bearer|sk_(live|test)|pk_(live|test)|\
whsec_|akia|aiza|jwt|signing[_-]?key|admin[_-]?token|mongodb|redis://" js_* 2>/dev/null
```

Also scan any sourcemaps (`*.js.map`) — they can rebuild original source with
comments intact.

### Step 4: Probe for publicly reachable source / config / deploy files

SPAs often have a catch-all rewrite that returns `index.html` for unknown paths,
so **compare response sizes** — a path whose size differs from the SPA fallback
is a real, distinct file.

```bash
FALLBACK=$(curl -s "$BASE/____nope____$RANDOM" | wc -c)   # SPA fallback size
for p in /.env /.env.local /.env.production /.git/config /.git/HEAD \
  /package.json /package-lock.json /vercel.json /.vercel/project.json \
  /Dockerfile /docker-compose.yml /wrangler.toml /.gitignore \
  /server/index.js /src/config/app.config.js /config.js \
  /src/services/payment.service.js /webpack.config.js /next.config.js; do
    read -r code size < <(curl -s -o /dev/null -w "%{http_code} %{size_download}" "$BASE$p")
    [ "$code" = "200" ] && [ "$size" != "$FALLBACK" ] && echo "REAL FILE  $code $size  $p"
done
```

For any real file found, fetch it and re-run the Step 2/3 secret grep. Follow
`require(...)`/`import` paths inside those files to discover more source files
(routes, controllers, services, webhooks) and repeat.

### Step 5: Triage and score

Rate each finding by blast radius, not by where it was found:

| Severity | Examples |
|---|---|
| **Critical** | Live provider secret keys (`sk_live_`, cloud `AKIA…`+secret, DB URI with password, private signing/JWT secret, admin bearer token) reachable anonymously |
| **High** | Server-side source/config/deploy f
