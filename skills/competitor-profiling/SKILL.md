---
name: competitor-profiling
description: When the user wants to research, profile, or analyze competitors from their URLs. 
category: Document Processing
source: antigravity
tags: [markdown, api, mcp, claude, ai, agent, template, document, security, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/competitor-profiling
---


# Competitor Profiling
## When to Use

Use this skill when you need when the user wants to research, profile, or analyze competitors from their URLs. Also use when the user mentions 'competitor profile,' 'competitor research,' 'competitor analysis,' 'profile this competitor,' 'analyze competitor,' 'competitive intelligence,' 'competitor deep dive,'...


You are an expert competitive intelligence analyst. Your goal is to take a list of competitor URLs and produce comprehensive, structured competitor profile documents by combining live site scraping with SEO and market data.

## Initial Assessment

**Check for product marketing context first:**
If `.agents/product-marketing.md` exists (or `.claude/product-marketing.md`, or the legacy `product-marketing-context.md` filename, in older setups), read it before asking questions. Use that context and only ask for information not already covered.

Before profiling, confirm:

1. **Competitor URLs** — the list of competitor website URLs to profile
2. **Your product** — what you do (if not in product marketing context)
3. **Depth level** — quick scan (key facts only) or deep profile (full research)
4. **Focus areas** — any specific dimensions to prioritize (e.g., pricing, positioning, SEO strength, content strategy)

If the user provides URLs and context is available, proceed without asking.

---

## Core Principles

### 1. Facts Over Opinions
Every claim in a profile should be traceable to a source — scraped page content, review data, or SEO metrics. Label inferences clearly.

### 2. Structured and Comparable
All profiles follow the same template so they can be compared side by side. Consistency matters more than completeness on any single profile.

### 3. Current Data
Profiles are snapshots. Always include the date generated. Flag anything that looks stale (e.g., "pricing page last updated 2023").

### 4. Honest Assessment
Don't exaggerate competitor weaknesses or downplay their strengths. Accurate profiles are useful profiles.

---

## Saving Raw Data

Before synthesizing the profile, persist all raw scrape, SEO, and review data to disk so it can be re-read, audited, or re-used later without re-running expensive API calls.

**Directory layout** (relative to project root):

```
competitor-profiles/
├── raw/
│   └── <competitor-slug>/
│       └── <YYYY-MM-DD>/
│           ├── scrapes/    # one .md file per scraped page (homepage.md, pricing.md, ...)
│           ├── seo/        # one .json file per DataForSEO call (backlinks-summary.json, ranked-keywords.json, ...)
│           └── reviews/    # one .md or .json file per review source (g2.md, capterra.md, ...)
├── <competitor-slug>.md    # final synthesized profile
└── _summary.md             # cross-competitor summary
```

Rules:

- `<competitor-slug>` is lowercase, hyphenated (e.g. `responsehub`, `safe-base`)
- `<YYYY-MM-DD>` is the date the data was pulled — supports re-running and diffing snapshots over time
- Save each Firecrawl scrape as raw markdown to `scrapes/<page-name>.md`
- Save each DataForSEO response as raw JSON to `seo/<endpoint-name>.json`
- Save each review source to `reviews/<source>.md` (cleaned text) or `.json` (raw)
- Always create the date folder fresh on a new run; never overwrite a prior date's data

The synthesized profile (`<competitor-slug>.md`) should reference the raw data folder it was built from in its `## Raw Data Sources` section.

---

## Research Process

### Phase 1: Site Scraping (Firecrawl)

For each competitor URL, scrape key pages to extract positioning, features, pricing, and messaging.

#### Step 1: Map the site

Use **Firecrawl Map** to discover the competitor's site structure and identify key pages:

```
firecrawl_map → competitor URL
```

From the map, identify and prioritize these page types:
- Homepage
- Pricing page
- Features / product pages
- About / company page
- Blog (top-level, for content strategy signals)
- Customers / case studies page
- Integrations page
- Changelog / what's new (if exists)

#### Step 2: Scrape key pages

Use **Firecrawl Scrape** on each identified page:

```
firecrawl_scrape → each key page URL
```

Save each result to `competitor-profiles/raw/<competitor-slug>/<YYYY-MM-DD>/scrapes/<page-name>.md` before extracting fields.

Extract from each page:

| Page | What to Extract |
|------|----------------|
| **Homepage** | Headline, subheadline, value proposition, primary CTA, social proof claims, target audience signals |
| **Pricing** | Tiers, prices, feature breakdown per tier, billing options, free tier/trial details, enterprise pricing signals |
| **Features** | Feature categories, key capabilities, how they describe each feature, screenshots/demo signals |
| **About** | Founding story, team size, funding, mission statement, headquarters |
| **Customers** | Named customers, logos, industries served, case study themes |
| **Integrations** | Integration count, key integrations, categories |
| **Changelog** | Release velocity, recent focus areas, 
