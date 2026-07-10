---
name: efficient-web-research
description: Protocol for token-efficient web research. Use when accessing URLs, GitHub repos, or running search queries. Prevents full-page fetching waste. 
category: Document Processing
source: antigravity
tags: [python, javascript, react, pdf, markdown, api, ai, agent, document, aws]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/efficient-web-research
---


# Efficient Web Research Skill

A protocol for accessing web content in the most token-efficient, accurate, and structured way —
using the right tool at the right depth, and stopping as soon as the question is answerable.

---

## When to Use
- Use this skill when the task matches this description: Protocol for token-efficient web research. Use when accessing URLs, GitHub repos, or running search queries. Prevents full-page fetching waste.

## Core Principle

> **Fetch the minimum needed to answer. Skim before you dive. Stop when you can answer.**

Every unnecessary fetch wastes tokens and adds noise. This skill enforces a layered approach
where you escalate fetch depth only when shallower layers fail.

---

## Step 1 — Classify the Input

Before fetching anything, identify what kind of input you received:

| Input Type | Example | Go To |
|---|---|---|
| GitHub repo URL | `github.com/user/repo` | [GitHub Protocol](#github-protocol) |
| Specific page URL | `docs.python.org/3/library/os` | [URL Protocol](#url-protocol) |
| Topic / query (no URL) | "how does RAFT consensus work" | [Search Protocol](#search-protocol) |
| Multiple URLs | List of links | [Multi-URL Protocol](#multi-url-protocol) |
| PDF / file link | `.pdf`, `.txt`, `.md` URL | [File Protocol](#file-protocol) |

---

## GitHub Protocol

Use when input is a GitHub URL (repo, file, PR, issue, etc.)

### Step 1 — Parse the URL

```
github.com/{owner}/{repo}                → Repo root
github.com/{owner}/{repo}/tree/{branch}  → Directory
github.com/{owner}/{repo}/blob/{branch}/{path} → Single file
github.com/{owner}/{repo}/issues/{n}     → Issue
github.com/{owner}/{repo}/pull/{n}       → Pull request
```

### Step 2 — Use GitHub API (preferred over scraping)

Always prefer the GitHub API. It returns clean JSON — no HTML parsing needed.

```
# Repo metadata (name, description, language, stars, topics)
GET https://api.github.com/repos/{owner}/{repo}

# File tree (see what files exist — very cheap)
GET https://api.github.com/repos/{owner}/{repo}/git/trees/{ref}?recursive=1

# Single file content (base64 encoded)
GET https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={ref}

# README only (usually enough to understand the repo)
GET https://api.github.com/repos/{owner}/{repo}/readme
```

### Step 3 — Layered Fetch for Repos

```
Layer 1 (always do first):
  → Fetch repo metadata + README only
  → Can you answer the user's question now? YES → STOP. NO → continue.

Layer 2 (only if needed):
  → Fetch file tree to understand structure
  → Identify the 1-3 most relevant files based on the question
  → Can you answer now? YES → STOP. NO → continue.

Layer 3 (last resort):
  → Fetch specific relevant files only (never fetch all files)
  → Prioritize: main entry point, config files, key modules
```

### Token Rules for GitHub

- README alone answers ~70% of "what does this repo do" questions — always try it first
- Never fetch more than 3 files in a single research turn
- If a file exceeds ~300 lines, read only the top (imports + class/function signatures)
- Decode base64 content from API before passing to context

---

## URL Protocol

Use when the user gives a specific non-GitHub URL (docs, articles, blogs, etc.)

### Step 1 — Assess the URL type

| Site type | Likely works with | Notes |
|---|---|---|
| Static docs / MDN / ReadTheDocs | `read_url_content` | Fast, clean, cheap |
| News articles / blogs | `read_url_content` | Usually fine |
| SPAs / React/Next.js apps | `browser_subagent` | JS-rendered |
| Auth-gated pages | `browser_subagent` | Needs login |
| Raw GitHub files (raw.githubusercontent) | `read_url_content` | Direct text |

### Step 2 — Layered Fetch

```
Layer 1 — Skim
  → Fetch the URL with read_url_content
  → Read only headings (H1, H2, H3) and first paragraph
  → Does this page contain what the user needs? NO → try a different URL or search. YES → continue.

Layer 2 — Targeted Extract
  → If the page has anchor links (e.g. /docs/page#section), fetch with the anchor
  → Extract only the relevant section (200–500 tokens max)
  → Can you answer? YES → STOP.

Layer 3 — Full Fetch
  → Fetch full page, strip boilerplate (nav, footer, ads, cookie banners, sidebars)
  → Cap at 2000 tokens. Summarize before passing to answer.

Layer 4 — Browser Subagent (last resort only)
  → Use ONLY if read_url_content returns empty, garbled, or JS-placeholder content
  → Instruct subagent: "Navigate to [URL], wait for content to load, extract [specific section]"
  → Do NOT use browser_subagent for static pages — it's expensive
```

### What to Strip from Fetched Pages

Always remove before using fetched content:
- Navigation menus and breadcrumbs
- Cookie banners and GDPR notices
- "Related articles" / "You might also like" blocks
- Footer content (copyright, links)
- Social share buttons
- Ads and sponsored content

Extract and keep:
- Main article / documentation body
- Code blocks
- Tables with data
- Numbered steps or procedures

---

## Search Pr
