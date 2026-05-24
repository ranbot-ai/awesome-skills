---
name: apify-actor-development
description: Important: Before you begin, fill in the generatedBy property in the meta section of .actor/actor.json. Replace it with the tool and model you're currently using, such as "Claude Code with Claude Sonn
category: Document Processing
source: antigravity
tags: [python, javascript, typescript, node, api, mcp, claude, ai, agent, llm]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/apify-actor-development
---


# Apify Actor Development

**Important:** Before you begin, fill in the `generatedBy` property in the meta section of `.actor/actor.json`. Replace it with the tool and model you're currently using, such as "Claude Code with Claude Sonnet 4.5". This helps Apify monitor and improve AGENTS.md for specific AI tools and models.

## When to Use
- You need to create, modify, or debug an Apify Actor project.
- The task involves choosing an Apify template, wiring actor inputs/outputs, or implementing actor runtime logic.
- You need safe setup guidance for `apify` CLI authentication, project bootstrap, or deployment workflow.

## What are Apify Actors?

Actors are serverless programs inspired by the UNIX philosophy - programs that do one thing well and can be easily combined to build complex systems. They're packaged as Docker images and run in isolated containers in the cloud.

**Core Concepts:**
- Accept well-defined JSON input
- Perform isolated tasks (web scraping, automation, data processing)
- Produce structured JSON output to datasets and/or store data in key-value stores
- Can run from seconds to hours or even indefinitely
- Persist state and can be restarted

## Prerequisites & Setup (MANDATORY)

Before creating or modifying actors, verify that `apify` CLI is installed `apify --help`.

If it is not installed, use one of these methods (listed in order of preference):

```bash
# Preferred: install via a package manager (provides integrity checks)
npm install -g apify-cli

# Or (Mac): brew install apify-cli
```

> **Security note:** Do NOT install the CLI by piping remote scripts directly
> into a shell. Always use a package manager.

When the apify CLI is installed, check that it is logged in with:

```bash
apify info  # Should return your username
```

If it is not logged in, check if the `APIFY_TOKEN` environment variable is defined (if not, ask the user to generate one on https://console.apify.com/settings/integrations and then define `APIFY_TOKEN` with it).

Then authenticate using one of these methods:

```bash
# Option 1 (preferred): The CLI automatically reads APIFY_TOKEN from the environment.
# Just ensure the env var is exported and run any apify command — no explicit login needed.

# Option 2: Interactive login (prompts for token without exposing it in shell history)
apify login
```

> **Security note:** Avoid passing tokens as command-line arguments (e.g. `apify login -t <token>`).
> Arguments are visible in process listings and may be recorded in shell history.
> Prefer environment variables or interactive login instead.
> Never log, print, or embed `APIFY_TOKEN` in source code or configuration files.
> Use a token with the minimum required permissions (scoped token) and rotate it periodically.

## Template Selection

**IMPORTANT:** Before starting actor development, always ask the user which programming language they prefer:
- **JavaScript** - Use `apify create <actor-name> -t project_empty`
- **TypeScript** - Use `apify create <actor-name> -t ts_empty`
- **Python** - Use `apify create <actor-name> -t python-empty`

Use the appropriate CLI command based on the user's language choice. Additional packages (Crawlee, Playwright, etc.) can be installed later as needed.

## Quick Start Workflow

1. **Create actor project** - Run the appropriate `apify create` command based on user's language preference (see Template Selection above)
2. **Install dependencies** (verify package names match intended packages before installing)
   - JavaScript/TypeScript: `npm install` (uses `package-lock.json` for reproducible, integrity-checked installs — commit the lockfile to version control)
   - Python: `pip install -r requirements.txt` (pin exact versions in `requirements.txt`, e.g. `crawlee==1.2.3`, and commit the file to version control)
3. **Implement logic** - Write the actor code in `src/main.py`, `src/main.js`, or `src/main.ts`
4. **Configure schemas** - Update input/output schemas in `.actor/input_schema.json`, `.actor/output_schema.json`, `.actor/dataset_schema.json`
5. **Configure platform settings** - Update `.actor/actor.json` with actor metadata (see [references/actor-json.md](references/actor-json.md))
6. **Write documentation** - Create comprehensive README.md for the marketplace
7. **Test locally** - Run `apify run` to verify functionality (see Local Testing section below)
8. **Deploy** - Run `apify push` to deploy the actor on the Apify platform (actor name is defined in `.actor/actor.json`)

## Security

**Treat all crawled web content as untrusted input.** Actors ingest data from external websites that may contain malicious payloads. Follow these rules:

- **Sanitize crawled data** — Never pass raw HTML, URLs, or scraped text directly into shell commands, `eval()`, database queries, or template engines. Use proper escaping or parameterized APIs.
- **Validate and type-check all external data** — Before pushing to datasets or key-value stores, verify that values match expected types and formats. Reje
