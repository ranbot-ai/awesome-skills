---
name: daily-news-report
description: Scrapes content based on a preset URL list, filters high-quality technical information, and generates daily Markdown reports. 
category: Business & Marketing
source: antigravity
tags: [markdown, api, mcp, ai, agent, template, cro, marketing]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/daily-news-report
---


# Daily News Report v3.0

> **Architecture Upgrade**: Main Agent Orchestration + SubAgent Execution + Browser Scraping + Smart Caching

## Core Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Main Agent (Orchestrator)                    │
│  Role: Scheduling, Monitoring, Evaluation, Decision, Aggregation    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│   │ 1. Init     │ → │ 2. Dispatch │ → │ 3. Monitor  │ → │ 4. Evaluate │     │
│   │ Read Config │    │ Assign Tasks│    │ Collect Res │    │ Filter/Sort │     │
│   └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘     │
│         │                  │                  │                  │           │
│         ▼                  ▼                  ▼                  ▼           │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│   │ 5. Decision │ ← │ Enough 20?  │    │ 6. Generate │ → │ 7. Update   │     │
│   │ Cont/Stop   │    │ Y/N         │    │ Report File │    │ Cache Stats │     │
│   └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘     │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
         ↓ Dispatch                          ↑ Return Results
┌─────────────────────────────────────────────────────────────────────┐
│                        SubAgent Execution Layer                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐              │
│   │ Worker A    │   │ Worker B    │   │ Browser     │              │
│   │ (WebFetch)  │   │ (WebFetch)  │   │ (Headless)  │              │
│   │ Tier1 Batch │   │ Tier2 Batch │   │ JS Render   │              │
│   └─────────────┘   └─────────────┘   └─────────────┘              │
│         ↓                 ↓                 ↓                        │
│   ┌─────────────────────────────────────────────────────────────┐   │
│   │                    Structured Result Return                 │   │
│   │  { status, data: [...], errors: [...], metadata: {...} }    │   │
│   └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Configuration Files

This skill uses the following configuration files:

| File | Purpose |
|------|---------|
| `sources.json` | Source configuration, priorities, scrape methods |
| `cache.json` | Cached data, historical stats, deduplication fingerprints |

## Execution Process Details

### Phase 1: Initialization

```yaml
Steps:
  1. Determine date (user argument or current date)
  2. Read sources.json for source configurations
  3. Read cache.json for historical data
  4. Create output directory NewsReport/
  5. Check if a partial report exists for today (append mode)
```

### Phase 2: Dispatch SubAgents

**Strategy**: Parallel dispatch, batch execution, early stopping mechanism

```yaml
Wave 1 (Parallel):
  - Worker A: Tier1 Batch A (HN, HuggingFace Papers)
  - Worker B: Tier1 Batch B (OneUsefulThing, Paul Graham)

Wait for results → Evaluate count

If < 15 high-quality items:
  Wave 2 (Parallel):
    - Worker C: Tier2 Batch A (James Clear, FS Blog)
    - Worker D: Tier2 Batch B (HackerNoon, Scott Young)

If still < 20 items:
  Wave 3 (Browser):
    - Browser Worker: ProductHunt, Latent Space (Require JS rendering)
```

### Phase 3: SubAgent Task Format

Task format received by each SubAgent:

```yaml
task: fetch_and_extract
sources:
  - id: hn
    url: https://news.ycombinator.com
    extract: top_10
  - id: hf_papers
    url: https://huggingface.co/papers
    extract: top_voted

output_schema:
  items:
    - source_id: string      # Source Identifier
      title: string          # Title
      summary: string        # 2-4 sentence summary
      key_points: string[]   # Max 3 key points
      url: string            # Original URL
      keywords: string[]     # Keywords
      quality_score: 1-5     # Quality Score

constraints:
  filter: "Cutting-edge Tech/Deep Tech/Productivity/Practical Info"
  exclude: "General Science/Marketing Puff/Overly Academic/Job Posts"
  max_items_per_source: 10
  skip_on_error: true

return_format: JSON
```

### Phase 4: Main Agent Monitoring & Feedback

Main Agent Responsibilities:

```yaml
Monitoring:
  - Check SubAgent return status (success/partial/failed)
  - Count collected items
  - Record success rate per source

Feedback Loop:
  - If a SubAgent fails, decide whether to retry or skip
  - If a source fails per
