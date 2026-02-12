---
name: Ahrefs Automation
description: Automate SEO research with Ahrefs -- analyze backlink profiles, research keywords, track domain metrics history, audit organic rankings, and perform batch URL analysis through the Composio Ahrefs inte
category: Development & Code Tools
source: composio
tags: [api, json, mcp, automation, ai, claude]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/ahrefs-automation
---


# Ahrefs Automation

Run **Ahrefs** SEO analytics directly from Claude Code. Analyze backlink profiles, research keywords, track domain authority over time, audit organic keyword rankings, and batch-analyze multiple URLs without leaving your terminal.

**Toolkit docs:** [composio.dev/toolkits/ahrefs](https://composio.dev/toolkits/ahrefs)

---

## Setup

1. Add the Composio MCP server to your configuration:
   ```
   https://rube.app/mcp
   ```
2. Connect your Ahrefs account when prompted. The agent will provide an authentication link.
3. Most tools require a `target` (domain or URL) and a `country` code (ISO 3166-1 alpha-2). Some also require a `date` in `YYYY-MM-DD` format.

---

## Core Workflows

### 1. Site Explorer Metrics

Retrieve comprehensive SEO metrics for a domain including backlink counts, referring domains, organic keyword rankings, and traffic estimates.

**Tool:** `AHREFS_RETRIEVE_SITE_EXPLORER_METRICS`

Key parameters:
- `target` (required) -- domain or URL to analyze
- `date` (required) -- metrics date in `YYYY-MM-DD` format
- `country` -- ISO country code (e.g., `us`, `gb`, `de`)
- `mode` -- scope: `exact`, `prefix`, `domain`, or `subdomains` (default)
- `protocol` -- `both`, `http`, or `https`
- `volume_mode` -- `monthly` or `average`

Example prompt: *"Get Ahrefs site metrics for example.com as of today in the US"*

---

### 2. Historical Metrics Tracking

Track how a domain's SEO metrics have changed over time for trend analysis and competitive benchmarking.

**Tools:** `AHREFS_RETRIEVE_SITE_EXPLORER_METRICS_HISTORY`, `AHREFS_DOMAIN_RATING_HISTORY`

For full metrics history:
- `target` (required) -- domain to track
- `date_from` (required) -- start date in `YYYY-MM-DD`
- `date_to` -- end date
- `history_grouping` -- `daily`, `weekly`, or `monthly` (default)
- `select` -- columns like `date,org_cost,org_traffic,paid_cost,paid_traffic`

For Domain Rating (DR) history:
- `target` (required), `date_from` (required), `date_to`, `history_grouping`

Example prompt: *"Show me the monthly Domain Rating history for example.com over the last year"*

---

### 3. Backlink Analysis

Retrieve a comprehensive list of backlinks including source URLs, anchor text, link attributes, and referring domain metrics.

**Tool:** `AHREFS_FETCH_ALL_BACKLINKS`

Key parameters:
- `target` (required) -- domain or URL
- `select` (required) -- comma-separated columns (e.g., `url_from,url_to,anchor,domain_rating_source,first_seen_link`)
- `limit` (default 1000) -- number of results
- `aggregation` -- `similar_links` (default), `1_per_domain`, or `all`
- `mode` -- `exact`, `prefix`, `domain`, or `subdomains`
- `history` -- `live`, `since:YYYY-MM-DD`, or `all_time`
- `where` -- rich filter expressions on columns like `is_dofollow`, `domain_rating_source`, `anchor`

Example prompt: *"Get the top 100 dofollow backlinks to example.com with anchor text and referring DR"*

---

### 4. Keyword Research

Get keyword overview metrics and discover matching keyword variations for content strategy.

**Tools:** `AHREFS_EXPLORE_KEYWORDS_OVERVIEW`, `AHREFS_EXPLORE_MATCHING_TERMS_FOR_KEYWORDS`

For keyword overview:
- `select` (required) -- columns to return (volume, difficulty, CPC, etc.)
- `country` (required) -- ISO country code
- `keywords` -- comma-separated keyword list
- `where` -- filter by volume, difficulty, intent, etc.

For matching terms:
- `select` (required) and `country` (required)
- `keywords` -- comma-separated seed keywords
- `match_mode` -- `terms` (any order) or `phrase` (exact order)
- `terms` -- `all` or `questions` (question-format keywords only)

Example prompt: *"Find keyword variations for 'project management' in the US with volume and difficulty"*

---

### 5. Organic Keywords Audit

See which keywords a domain ranks for in organic search, with position tracking and historical comparison.

**Tool:** `AHREFS_RETRIEVE_ORGANIC_KEYWORDS`

Key parameters:
- `target` (required) -- domain or URL
- `country` (required) -- ISO country code
- `date` (required) -- date in `YYYY-MM-DD`
- `select` -- columns to return (keyword, position, volume, traffic, URL, etc.)
- `date_compared` -- compare against a previous date
- `where` -- rich filter expressions on `keyword`, `volume`, `best_position`, intent flags, etc.
- `limit` (default 1000), `order_by`

Example prompt: *"Show all organic keywords where example.com ranks in the top 10 in the US"*

---

### 6. Batch URL Analysis

Analyze up to 100 URLs or domains simultaneously to compare SEO metrics across competitors or site sections.

**Tool:** `AHREFS_BATCH_URL_ANALYSIS`

Key parameters:
- `targets` (required) -- array of objects with `url`, `mode` (`exact`/`prefix`/`domain`/`subdomains`), and `protocol` (`both`/`http`/`https`)
- `select` (required) -- array of column identifiers
- `country` -- ISO country code
- `output` -- `json` or `php`

Example prompt: *"Compare SEO metrics for competitor1.com, competitor2.com, and competitor3.com"*

---

## Known Pitfalls

- **Colum
