---
name: competitor-analysis
description: Research competitors with Browserbase discovery, enrichment lanes, screenshots, matrices, and HTML reports. 
category: Document Processing
source: antigravity
tags: [python, node, markdown, api, mcp, claude, ai, agent, llm, automation]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/competitor-analysis
---


# Competitor Analysis

## When to Use

Use when the user needs structured competitor research with Browserbase discovery, enrichment lanes, screenshots, comparison matrices, and a final HTML report.


_Source: [browserbase/skills](https://github.com/browserbase/skills) (MIT)._

Analyze a user's competitors. Uses Browserbase Search API for discovery and a 4-lane Plan→Research→Synthesize pattern for enrichment — outputting an HTML report with overview, per-competitor deep dives, a side-by-side feature/pricing matrix, and a chronological mentions feed.

**Required**: `BROWSERBASE_API_KEY` env var and the `browse` CLI installed (`npm install -g browse`).

**First-run setup**: On the first run you'll be prompted to approve `browse cloud fetch`, `browse cloud search`, `cat`, `mkdir`, `sed`, etc. Select **"Yes, and don't ask again for: browse cloud fetch:\*"** (or equivalent) for each. To permanently approve, add these to your `~/.claude/settings.json` under `permissions.allow`:
```json
"Bash(browse:*)", "Bash(bunx:*)", "Bash(bun:*)", "Bash(node:*)",
"Bash(cat:*)", "Bash(mkdir:*)", "Bash(sed:*)", "Bash(head:*)", "Bash(tr:*)", "Bash(rm:*)"
```

**Path rules**: Always use full literal paths in Bash — NOT `~` or `$HOME`. Resolve the home directory once and use it everywhere. When building subagent prompts, replace `{SKILL_DIR}` with the full literal path.

**Output directory**: All output goes to `~/Desktop/{company_slug}_competitors_{YYYY-MM-DD}/`. This directory contains one `.md` file per competitor plus the generated HTML views and CSV.

**CRITICAL — Tool restrictions (applies to main agent AND all subagents)**:
- All web searches: use `browse cloud search`. NEVER WebSearch.
- All page fetches: use `browse cloud fetch --allow-redirects` (returns markdown by default; add `--format raw` if you need the original HTML, then pipe through `sed ... | tr -s ' \n'` to extract text). NEVER WebFetch. 1 MB response limit — fall back to `browse get markdown` (after `browse open <url> --remote`) for JS-heavy pages.
- All research output: subagents write **one markdown file per competitor** to `{OUTPUT_DIR}/{competitor-slug}.md` using bash heredoc. NEVER use the Write tool or `python3 -c`. See `references/example-research.md` for the file format.
- Report compilation: use `node {SKILL_DIR}/scripts/compile_report.mjs {OUTPUT_DIR} --user-company "{user_company}" --open` — generates `index.html`, `competitors/*.html`, `matrix.html`, `mentions.html`, `results.csv` in one step and opens overview.
- URL deduplication: `node {SKILL_DIR}/scripts/list_urls.mjs /tmp --prefix competitor`.
- **Subagents must use ONLY the Bash tool.**
- **Main agent NEVER reads raw discovery JSON batch files.**

**CRITICAL — Minimize permission prompts**:
- Subagents MUST batch ALL file writes into a SINGLE Bash call using chained heredocs.
- Batch ALL searches and ALL fetches into single Bash calls via `&&` chaining.

## Pipeline Overview

Follow these 8 steps in order. Do not skip or reorder.

1. **User Company Research** — Deeply understand the user's company, produce `precise_category` + `category_include_keywords` + `exclusion_list`
2. **Depth Mode + Seed Input** — Choose depth, accept optional seed competitor URLs
3. **Discovery (3 parallel waves)** — Wave A (alternatives), Wave B (precise category), Wave C (comparison-page graph via "X vs Y" title parsing)
4. **Gate** — `scripts/gate_candidates.mjs` fetches each candidate's hero text (via `browse cloud fetch`) and drops wrong-category URLs
5. **Confirm enrichment set with the user** — Present PASS / UNKNOWN / rejected-brand-matches via `AskUserQuestion`. User ticks the real ones, adds any the discovery missed. Skipping this step is wasteful because enrichment is expensive (25 subagents × depth budget) and the gate is imperfect (JS-heavy homepages, Cloudflare challenges, semantic-variant taglines)
6. **Deep Enrichment (5 subagents per competitor in deep/deeper modes)** — Marketing, Discussion, Social, News, Technical — each lane a separate subagent writing to `partials/`; then `merge_partials.mjs` consolidates. In deep/deeper modes, **Step 5d** adds a 6th Battle Card synthesis lane AFTER Step 5c fact-check completes — produces per-competitor Landmines / Objection Handlers / Talk Tracks grounded in cited evidence.
7. **Screenshots** — `capture_screenshots.mjs` via the `browse` CLI captures a 1280×800 homepage hero per competitor
8. **HTML Report** — Overview + per-competitor (with embedded hero screenshot + Battle Card card) + matrix + mentions views

---

## Step 0: Setup Output Directory

```bash
OUTPUT_DIR=~/Desktop/{company_slug}_competitors_{YYYY-MM-DD}
mkdir -p "$OUTPUT_DIR"
```

Replace `{company_slug}` with the user's company name (lowercase, hyphenated) and `{YYYY-MM-DD}` with today's date. Pass `{OUTPUT_DIR}` as a full literal path to every subagent.

Clean up discovery batch files from prior runs:
```bash
rm -f /tmp/competitor_discovery_batch_*.json
```

**Re-runs must start from a clean `$
