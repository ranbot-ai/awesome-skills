---
name: geo-compare
description: Monthly delta tracking and progress reporting for GEO clients. 
category: Document Processing
source: antigravity
tags: [pdf, markdown, claude, ai, agent, llm, gpt, workflow, template, document]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/geo-compare
---


# GEO Monthly Delta Report Generator

## Purpose

The single most powerful retention tool for a GEO agency: show clients **exactly**
what improved since they started working with you. Every point gained on the GEO
score is proof of value. This skill generates the "here's your progress" report.

---

## Commands

```
/geo compare <domain>
/geo compare <baseline-file> <current-file>
/geo compare electron-srl.com --month march-2026
```

**Examples:**
```
/geo compare electron-srl.com
/geo compare ~/.geo-prospects/audits/electron-srl.com-2026-01-15.md ~/.geo-prospects/audits/electron-srl.com-2026-03-12.md
```

---

## Workflow

### Step 1: Find Audit Files

If only domain is provided:
1. Look in `~/.geo-prospects/audits/` for files matching `<domain>-*.md`
2. Sort by date
3. Use oldest as baseline, newest as current
4. If only one file exists: use it as baseline, run a fresh quick audit as current
5. If no files exist: suggest running `/geo prospect audit <domain>` first

### Step 2: Parse Both Audits

Extract from each audit file:
- Overall GEO Score
- Per-category scores (6 categories)
- Per-platform scores (5 platforms)
- AI crawler status (14 crawlers)
- Critical issues list
- Action items list with status

### Step 3: Calculate Deltas

For each metric:
- Delta = Current - Baseline
- Trend = ▲ (improved), ▼ (declined), ── (unchanged)
- Color coding in report: green (+), red (-), gray (=)

### Step 4: Generate Monthly Report

Output to `~/.geo-prospects/reports/<domain>-monthly-<date>.md`

---

## Report Template

Generate the following document:

```markdown
# GEO Monthly Progress Report
## [COMPANY NAME] — [MONTH YEAR]

**Reporting period:** [BASELINE DATE] → [CURRENT DATE]
**Prepared by:** [AGENCY NAME]
**Report reference:** GEO-MONTHLY-[DOMAIN]-[YYMMDD]

---

## Executive Summary

[2-3 sentences: What improved, what's the trend, what to focus on next month.]

Example: "Electron Srl's GEO Score improved from 32 to 44 this month (+12 points),
placing the site firmly in the 'Below Average' tier and on track to reach 'Moderate'
by May. The biggest wins were AI crawler access (+3 crawlers now allowed) and schema
implementation (+Organization and LocalBusiness schemas live). Next month's focus is
content citability — the highest-weighted remaining gap."

---

## GEO Score Progress

```
OVERALL GEO SCORE

  Baseline   [▓▓▓▓░░░░░░░░░░░░░░░░]  32/100  (Critical)
  Current    [▓▓▓▓▓▓▓▓░░░░░░░░░░░░]  44/100  (Below Average)
  Change     ▲ +12 points (+37.5%)

  Target:    65/100 by Month 6 (on track ✓)
```

---

## Score Breakdown: Before vs. After

| Category | Baseline | Current | Change | Trend |
|----------|---------|---------|--------|-------|
| AI Citability & Visibility | [X]/100 | [X]/100 | [+/-X] | [▲/▼/──] |
| Brand Authority Signals | [X]/100 | [X]/100 | [+/-X] | [▲/▼/──] |
| Content Quality & E-E-A-T | [X]/100 | [X]/100 | [+/-X] | [▲/▼/──] |
| Technical Foundations | [X]/100 | [X]/100 | [+/-X] | [▲/▼/──] |
| Structured Data | [X]/100 | [X]/100 | [+/-X] | [▲/▼/──] |
| Platform Optimization | [X]/100 | [X]/100 | [+/-X] | [▲/▼/──] |
| **TOTAL** | **[X]/100** | **[X]/100** | **[+/-X]** | **[▲/▼]** |

---

## Platform Readiness: Before vs. After

| AI Platform | Baseline | Current | Change |
|-------------|---------|---------|--------|
| Google AI Overviews | [X]/100 | [X]/100 | [+/-X] |
| ChatGPT Web Search | [X]/100 | [X]/100 | [+/-X] |
| Perplexity AI | [X]/100 | [X]/100 | [+/-X] |
| Google Gemini | [X]/100 | [X]/100 | [+/-X] |
| Bing Copilot | [X]/100 | [X]/100 | [+/-X] |

---

## AI Crawler Access Changes

| Crawler | Baseline | Current | Change |
|---------|---------|---------|--------|
| GPTBot (ChatGPT) | Blocked/Allowed | Blocked/Allowed | ✓ Fixed / No change |
| ClaudeBot (Anthropic) | Blocked/Allowed | Blocked/Allowed | ✓ Fixed / No change |
| PerplexityBot | Blocked/Allowed | Blocked/Allowed | ✓ Fixed / No change |
| Google-Extended (Gemini) | Blocked/Allowed | Blocked/Allowed | ✓ Fixed / No change |
| Bingbot | Blocked/Allowed | Blocked/Allowed | ✓ Fixed / No change |

[Show only crawlers that changed, or all if few crawlers.]

---

## Action Plan Progress

### Quick Wins — Status Update

| # | Action | Assigned | Status | Impact |
|---|--------|---------|--------|--------|
| 1 | Allow all AI crawlers in robots.txt | Client dev | ✅ Done | +3 crawlers |
| 2 | Add Organization schema to homepage | Client dev | ✅ Done | Schema score +15 |
| 3 | Create llms.txt | Agency | ✅ Done | AI visibility +8 |
| 4 | Add author bylines to all articles | Client content | 🔄 In Progress | — |
| 5 | Fix meta descriptions (47 pages missing) | Client dev | ❌ Not started | — |

**Quick wins completed: [X]/[Y] ([%])**

### Medium-Term — Status Update

| # | Action | Target Month | Status |
|---|--------|-------------|--------|
| 1 | Rewrite top 10 pages with Q&A structure | Month 2 | 🔄 3/10 done |
| 2 | E-E-A-T: Create author pages | Month 2 | ❌ Not started |
| 3 | Register Bing Webmaster Tools | Month 1 | ✅ Done |
