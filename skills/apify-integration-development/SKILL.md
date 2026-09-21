---
name: apify-integration-development
description: Curated upstream guidance for Apify Integration Development; use when the workflow matches the user goal. 
category: Document Processing
source: antigravity
tags: [python, node, markdown, api, mcp, claude, ai, agent, llm, automation]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/apify-integration-development
---

## When to Use
- Use when this upstream workflow matches the user's stated goal.
- Use when the task requires the procedures documented in this skill.

# Apify Integration Development

Design and build an **official Apify integration** for a company's product, with minimal help from Apify. This skill covers every integration shape Apify supports - workflow-automation apps, AI agent plugins (coding agents and harnesses), AI framework packages, and direct application clients - so a partner team can ship a first-class Apify integration end to end. The cross-cutting rules below apply to all of them, and one category-specific reference file carries the rest.

> **Building an official integration?** Once you publish it, contact **integrations@apify.com** so the Apify team can review, test, and validate your integration before it reaches users. We'll check the capability surface, cost controls, error handling, and attribution headers, and help you close any gaps.

## Step 0 - Learn the Apify model first (required)

Before designing anything, fetch and read `https://apify.com/agents.md`. It is the canonical quickstart for AI agents and the single source of truth for vocabulary, the run flow, and the cost rule. If the fetch fails, the mini-glossary below keeps the skill usable.

Apify vocabulary (always written with a capital A on the platform):

- **Actor** - a serverless cloud program that takes JSON input, performs a task, and produces structured output. Not an AI agent.
- **Actor Run** - one execution of an Actor. Each run has its own dataset, key-value store, and request queue, and ends in a terminal status (`SUCCEEDED`, `FAILED`, `TIMED-OUT`, `ABORTED`).
- **Dataset** - append-only structured storage for a run's results. An Actor call returns the dataset ID, not its contents.
- **Key-Value Store** - unstructured/file storage (screenshots, HTML, OUTPUT).
- **Actor Task** - a saved, parameterized configuration for running an Actor.
- **Apify Store** - the marketplace of Actors at `https://apify.com/store.md`.
- **Apify Console** - the web UI at `https://console.apify.com`.
- **Compute Unit (CU)** - billing unit: memory (MB) x duration (hours).

Further terms (build, standby, request queue, proxy, pricing models): `https://docs.apify.com/llms.txt`.

## Use Apify MCP for live context while planning

The Apify MCP server is the fastest way to research Actors, schemas, pricing, and docs during integration design. See `https://docs.apify.com/integrations/mcp` (append `.md` for a markdown version).

If Apify MCP tools are already available in this environment, use them:

- `search-actors` - find Actors by platform/product keyword (search by product name, not end goal).
- `fetch-actor-details` - read an Actor's input schema, output format, README, and pricing before you encode its shape into the integration.
- `search-apify-docs` / `fetch-apify-docs` - pull contextual documentation pages.

The anonymous discovery subset (`search-actors`, `fetch-actor-details`, `search-apify-docs`, `fetch-apify-docs`) works without an account, so you can research even before the developer has connected their token.

## Pick your integration shape

Read exactly one reference file based on the product you are integrating into. Each reference carries the category-specific UX design, a canonical capability matrix, and a definition-of-done checklist.

| Product shape | Examples | Read |
|---|---|---|
| Workflow automation platform | Zapier, n8n, Make, Pipedream, Activepieces | `references/workflow-automation.md` |
| AI agent plugin (coding agent or harness) | Cursor, Claude Code, Codex, GitHub Copilot (coding agents); OpenClaw-style runtimes, Hermes-style harnesses (harnesses) | `references/ai-harness-plugin.md` |
| AI framework package (PyPI/npm for LLM frameworks) | LangChain, LlamaIndex, Haystack, Vercel AI SDK | `references/ai-framework-package.md` |
| Application integration (direct client) | A backend service, scheduled job, product feature calling Actors via `apify-client` or REST | `references/sdk-integration.md` |

Paths are relative to this skill folder. If your product spans two shapes (e.g. an AI harness built on top of a framework package), read both - the rules compose. The AI agent plugin reference covers **two approaches with different trade-offs**: a lightweight skills + MCP bundle for skills/MCP-aware coding agents, and a custom tool-registry plugin for OpenClaw/Hermes-style harnesses.

## Cross-cutting design rules (true for every integration type)

These invariants were extracted from every existing Apify integration. Apply them regardless of shape.

### Vocabulary mirroring
Model the integration's resources on Apify's domain (Actor / Run / Dataset / KV Store / Task). Users coming from Apify Console should find the same concepts under the same names.

### Asynchronous run flow with bounded polling
Actors can run for seconds to hours. Use the asynchronous flow, never the 300-second synchronous endpoint for anything but sho
