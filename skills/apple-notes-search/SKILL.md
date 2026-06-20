---
name: apple-notes-search
description: Semantic + keyword search and connection-discovery across the user's own Apple Notes via the apple-notes MCP server. Use when the user wants to find, recall, or synthesize something from their notes, 
category: AI & Agents
source: antigravity
tags: [api, mcp, claude, ai, llm, gpt, security, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/apple-notes-search
---


# Apple Notes search & connection-discovery

`apple-notes` is an MCP server for semantic search and connection-discovery across the
user's own Apple Notes — hybrid search, Swanson-ABC bridges, entity threads, and cited
synthesis over everything they've written. Embeddings, search, BM25, clustering, and
bridges run **on-device**; only **synthesis generation** calls an LLM (local OR cloud,
the user's choice).

This skill covers (1) the one-time setup you must walk the user through, and (2) which
tool to reach for, since the server exposes many.

## When to Use This Skill

- Use when the user wants to **find, recall, or look up** something from their own Apple
  Notes ("search my notes for X", "what did I write about X", "did I ever note Y").
- Use when the user wants to surface **non-obvious connections** across their notes
  ("find bridges/connections across my notes", "what links X and Y", "show related notes").
- Use when the user wants to **synthesize a position** from their notes ("summarize what I
  think about X from my notes", "pull together everything I've written on X").
- Also use for "index my Apple Notes", tag/folder queries, and "what's connected to X".
- Do **not** use for creating reminders, or for non-Apple-Notes note systems.

## First: is the MCP connected?

If `apple-notes` tools are not available, the server isn't registered yet — do the
**Setup** below before anything else. If tools exist but a search returns "not indexed"
or empty, run `index-notes` first (see Ranking caveats).

## Setup (walk the user through this — it's the skill's real value)

The server reads Apple Notes' SQLite store directly, so the **bun** binary needs Full
Disk Access. Steps, in order:

1. **Install bun** (if absent): `brew install oven-sh/bun/bun`
2. **Clone + install deps:**
   ```bash
   git clone https://github.com/connerkward/mcp-apple-notes
   cd mcp-apple-notes
   git checkout <reviewed-tag-or-commit>
   bun install
   ```
3. **Grant Full Disk Access to bun.** Run `which bun`, then open System Settings →
   Privacy & Security → Full Disk Access, click `+`, and add that exact `bun` binary
   path (commonly `/opt/homebrew/bin/bun` or `/usr/local/bin/bun`). Without this the
   server cannot read NoteStore.sqlite and every call fails with a permissions error.
   (`bun install`'s postinstall tries to open this pane automatically.)
4. **Register the MCP server** (pick the user's client):
   - Claude Code: `claude mcp add apple-notes -- bun /absolute/path/to/mcp-apple-notes/index.ts --stdio`
   - Claude Desktop: add to `claude_desktop_config.json`:
     ```json
     { "mcpServers": { "apple-notes": {
         "command": "/Users/<you>/.bun/bin/bun",
         "args": ["/Users/<you>/mcp-apple-notes/index.ts", "--stdio"] } } }
     ```
   - As a Claude Code plugin (bundles this skill too): `/plugin marketplace add connerkward/ckw-skills` then `/plugin install apple-notes@connerkward`.
5. **Restart the client**, then tell the user to ask **"Index my Apple Notes"** (or call
   `index-notes`). First index of ~1,800 notes takes a few seconds.

## Tool map — which tool for which job

| Tool | Use when |
|------|----------|
| `index-notes` | First run, or to force a rebuild. Background job with live progress. |
| `search-notes` | **Default search.** Hybrid semantic + BM25, re-ranked. Optional `folder`, `modifiedAfter`, `modifiedBefore`. "What did I write about X." |
| `find-notes` | Exact substring match (like the Apple Notes search box). Use when the user wants a literal string, not meaning. Optional `folder`, date range. |
| `get-note` | Fetch one full note by title (fuzzy fallback). |
| `list-notes` | Notes by recency. Optional `folder`, date range, `limit`. |
| `list-folders` | All folders + note counts. |
| `list-tags` / `search-by-tag` | `#hashtag` inventory / notes carrying a given tag. |
| `related-notes` | Notes related to a given one via shared tags, `[[wikilinks]]`, and vector similarity. "Show me related notes." |
| `bridge-notes` | **Swanson-ABC bridges** — non-obvious connections: pairs (A, C) not directly similar but both strongly tied to a shared intermediary B. "Find non-obvious connections across my notes." Optional `folder`, `limit`. No LLM. |
| `feed` | Ranked evidence-first connection stream (bridges + abstraction pairs + entity threads) as JSON. Optional `limit`. |
| `entity-notes` / `list-entities` | "Where else do I talk about Mercedes?" Entity chips → notes by mention weight. **Needs the optional entity graph db** (`~/.mcp-apple-notes/layered_graph.db`); if absent these report how to generate it. |
| `get-tables` | Pull pipe/tab tables out of a note. |
| `create-note` / `update-note` | Create or edit a note. |
| `check-changes` | Did notes change since last index? (does not trigger re-index) |
| `index-health` | Sync status, last-indexed time, note count. Run this if results seem stale. |

For "synthesize what I think about X" the synthesis lives in the **web app** endpoint
(`GET /api/synthesize?
