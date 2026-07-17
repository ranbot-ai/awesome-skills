---
name: competitor-ad-intelligence
description: Research public competitor ads, analyze creative patterns and landing pages, and produce an evidence-labeled strategic teardown. 
category: Security & Systems
source: antigravity
tags: [markdown, api, claude, ai, agent, automation, design, document, image, vulnerability]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/competitor-ad-intelligence
---


# Competitor Ad Intelligence

## Overview

Research competitor ads from Meta and Google, analyze creative patterns, map observable landing-page funnels, and produce a strategic teardown — hooks, formats, positioning bets, vulnerabilities, and counter-plays.

**Core principle:** A competitor's public ad portfolio is partial evidence about its growth strategy. Long-running ads can indicate continued investment, but public libraries do not expose conversion performance or spend. Separate observations from hypotheses, cite every observed ad or page, and label all performance and budget inferences explicitly.

## When to Use This Skill

- "What ads are my competitors running?"
- "Tear down [competitor]'s ad strategy"
- "Find new creative angles for our paid campaigns"
- "Reverse-engineer [competitor]'s paid funnel"
- "What hooks are working in [our space]?"
- "Audit the ad landscape before we launch"
- "Find weaknesses in [competitor]'s ad strategy"
- "What format — video, image, carousel — is dominant in our category?"

## Phase 0: Intake

Gather from the user:

1. **Competitor names + domains** (e.g., `apollo.io`, `clay.run`)
2. **Your product/domain** — for comparison framing
3. **Channels:** Meta only, Google only, or both? (default: both)
4. **Depth level:**
   - **Standard:** Ad scrape + creative analysis + landing page analysis
   - **Deep:** Standard + historical comparison + funnel reconstruction + counter-plays
5. **Product category** — helps frame analysis
6. **Known competitor landing pages?** — any URLs already spotted in their ads

## Phase 1: Research Meta Ads

For each competitor domain, research ads visible in Meta Ad Library and public search results.

Use `web_search` only to discover first-party library pages and candidate references:

```
web_search: site:facebook.com/ads/library "[competitor_name]"
web_search: "[competitor_name]" Meta Ad Library active ads
web_search: "[competitor_name]" facebook ads examples
```

You can also visit the Meta Ad Library directly: `https://www.facebook.com/ads/library/?active_status=active&ad_type=all&country=US&q=<competitor_name>`

Prefer manual browser research. Use automated collection only when the platform expressly permits it and the user has authorized it; comply with current terms, robots directives, and rate limits. If the page is blocked, incomplete, dynamic-only, or requires authentication, report the coverage gap; do not bypass the control or invent missing ads or attributes.

**Collect per ad:**
- Ad copy (headline + primary text)
- Visual type (image / video / carousel)
- CTA button text
- Landing page URL
- Active duration (first seen, still running or stopped)
- Platforms (Facebook, Instagram, Audience Network)
- Ad variations (A/B tests — same landing page, different creative)

## Phase 2: Research Google Ads

For each competitor domain, research ads visible in Google Ads Transparency Center.

Use `web_search` to find competitor ads in Google Ads Transparency Center (publicly accessible):

```
web_search: site:adstransparency.google.com "[competitor_name]"
web_search: "[competitor_name]" Google Ads transparency
web_search: "[competitor_name]" google search ads examples
```

You can also visit directly: `https://adstransparency.google.com/?search_text=<competitor_name>`

Prefer manual browser research. Treat search snippets and third-party examples as secondary evidence and identify them as such. Use automated fetching only when permitted and authorized.

**Collect per ad:**
- Headline variants (up to 3)
- Description lines
- Ad type (Search / Display / YouTube / Shopping)
- Landing page URL
- Geographic targeting (if visible)

## Phase 3: Analyze Creative Patterns

After collecting all ads, perform structured analysis.

### Hook Pattern Clustering

Group all ad headlines/openers by hook type:

| Hook Type | Pattern | Example |
|-----------|---------|---------|
| **Fear/Loss** | Risk of missing out or falling behind | "Your competitors are already using AI SDRs" |
| **Outcome** | Direct result promise | "10x your pipeline in 30 days" |
| **Question** | Challenges current assumption | "Still doing outbound manually?" |
| **Social proof** | Names customers or numbers | "Join 500+ B2B teams using [product]" |
| **Contrarian** | Challenges conventional wisdom | "Cold email isn't dead. Your copy is." |
| **Empathy** | Validates their pain | "We know SDR ramp time is brutal" |
| **Product-led** | Feature as hook | "[Feature] is live — see what's new" |

Count how many ads per competitor use each hook type. This reveals their primary messaging strategy.

### Format Distribution

| Format | Meta | Google |
|--------|------|--------|
| Static image | [N] | N/A |
| Video | [N] | [N] |
| Carousel | [N] | N/A |
| Search text | N/A | [N] |
| Display banner | N/A | [N] |

### CTA Taxonomy

List all unique CTAs found. Common patterns:
- **Urgency:** "Start free", "Try now", "Get started today"
- **Low-friction:** "See how it works", "Watch demo", "Learn mo
