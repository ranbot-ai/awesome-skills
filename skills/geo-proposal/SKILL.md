---
name: geo-proposal
description: Auto-generate a professional, client-ready GEO service proposal from audit data. 
category: Document Processing
source: antigravity
tags: [pdf, markdown, claude, ai, agent, llm, gpt, workflow, template, document]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/geo-proposal
---


# GEO Proposal Generator

## Purpose

Generate a fully customized, client-ready GEO service proposal that:
1. Pulls findings directly from the prospect's GEO audit
2. Translates technical gaps into business pain points
3. Presents 3 service tiers with clear pricing
4. Includes a realistic ROI projection
5. Outputs a professional markdown document ready to send

---

## Command

```
/geo proposal <domain-or-audit-file> [--tier basic|standard|premium] [--client-name "Name"] [--monthly EUR]
```

**Examples:**
```
/geo proposal electron-srl.com
/geo proposal electron-srl.com --tier standard --client-name "Electron Srl"
/geo proposal ~/.geo-prospects/audits/electron-srl.com-2026-03-12.md
```

---

## Workflow

### Step 1: Load Audit Data

1. Check if `~/.geo-prospects/audits/<domain>*.md` exists
2. If not, suggest running `/geo quick <domain>` first
3. Extract from audit:
   - GEO Score (overall and per-category)
   - Top 3 critical findings
   - Quick wins list
   - Business type
   - Estimated organic traffic impact

### Step 2: Customize the Proposal

Auto-fill proposal template with:
- Company name (from domain or prospect record)
- GEO score and tier label
- 3 most critical pain points (translated to business language)
- Estimated revenue at risk from AI search shift
- Recommended service tier based on score:
  - Score 0-40 → Recommend Premium (critical issues need full attention)
  - Score 41-60 → Recommend Standard (significant gaps, needs monthly work)
  - Score 61-75 → Recommend Basic (solid base, needs monitoring)

### Step 3: Generate Proposal File

Output to `~/.geo-prospects/proposals/<domain>-proposal-<date>.md`
Also update prospect record if it exists in `~/.geo-prospects/prospects.json`

---

## Proposal Template

Generate the following document, filling all `[PLACEHOLDERS]` with real audit data:

---

```markdown
# GEO Optimization Proposal
## [COMPANY NAME] — AI Search Visibility

**Prepared by:** [YOUR AGENCY NAME]
**Prepared for:** [CONTACT NAME], [COMPANY NAME]
**Date:** [DATE]
**Valid until:** [DATE + 30 DAYS]
**Reference:** GEO-PROP-[YYMMDD]-[DOMAIN]

---

## Executive Summary

[COMPANY NAME] operates in [INDUSTRY] and serves customers across [GEOGRAPHY].
Our GEO audit of [DOMAIN], conducted on [DATE], reveals a GEO Readiness Score
of **[SCORE]/100 ([TIER LABEL])**.

This means your website currently has [TIER DESCRIPTION — use score interpretation table].
As AI-powered search (ChatGPT, Google AI Overviews, Perplexity) now influences
**[X]% of online discovery** and is growing at 527% year-over-year, this gap
represents a measurable risk to your pipeline.

The three most urgent issues are:
1. **[CRITICAL FINDING 1]** — [Business impact in one sentence]
2. **[CRITICAL FINDING 2]** — [Business impact in one sentence]
3. **[CRITICAL FINDING 3]** — [Business impact in one sentence]

We recommend the **[TIER NAME] package** at **€[PRICE]/month**, which addresses
all critical issues within 90 days and positions [COMPANY] as an AI-visible
authority in [INDUSTRY].

---

## The Opportunity: Why GEO Matters for [COMPANY NAME]

### The AI Search Shift Is Already Happening

| Metric | Value |
|--------|-------|
| AI-referred traffic growth (2025) | +527% YoY |
| AI traffic conversion vs. organic | 4.4x higher |
| ChatGPT weekly active users | 900M+ |
| Google AI Overviews monthly reach | 1.5B users, 200+ countries |
| Gartner: traditional search traffic drop by 2028 | -50% |
| Marketers investing in GEO today | Only 23% |

**First-mover advantage is real.** Companies that invest in GEO now will
capture the AI search channel before competitors do.

### Your Current Position

| Metric | [COMPANY] | Industry Average | Top Performers |
|--------|-----------|------------------|----------------|
| GEO Score | [SCORE]/100 | 45/100 | 75+/100 |
| AI Crawlers Allowed | [X]/14 | 8/14 | 14/14 |
| Brand Mentions (AI platforms) | [STATUS] | Moderate | High |
| Schema Coverage | [STATUS] | Partial | Complete |
| llms.txt | [Yes/No] | 12% have it | 78% have it |

---

## Audit Findings Summary

### GEO Score Breakdown

| Category | Your Score | Weight | Weighted | Priority |
|----------|-----------|--------|---------|----------|
| AI Citability & Visibility | [SCORE]/100 | 25% | [WEIGHTED] | [HIGH/MED/LOW] |
| Brand Authority Signals | [SCORE]/100 | 20% | [WEIGHTED] | [HIGH/MED/LOW] |
| Content Quality & E-E-A-T | [SCORE]/100 | 20% | [WEIGHTED] | [HIGH/MED/LOW] |
| Technical Foundations | [SCORE]/100 | 15% | [WEIGHTED] | [HIGH/MED/LOW] |
| Structured Data | [SCORE]/100 | 10% | [WEIGHTED] | [HIGH/MED/LOW] |
| Platform Optimization | [SCORE]/100 | 10% | [WEIGHTED] | [HIGH/MED/LOW] |
| **TOTAL GEO SCORE** | | | **[SCORE]/100** | **[TIER]** |

### Critical Issues Found

[For each critical issue from audit:]

#### 🔴 [ISSUE TITLE]
**What we found:** [Technical finding in plain language]
**Business impact:** [What this means for their revenue/visibility]
**Our fix:** [What we will do to resolve it]
**Timeline:** [When the
