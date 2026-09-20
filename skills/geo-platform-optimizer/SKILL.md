---
name: geo-platform-optimizer
description: Platform-specific AI search optimization — audit and optimize for Google AI Overviews, ChatGPT, Perplexity, Gemini, and Bing Copilot individually 
category: Document Processing
source: antigravity
tags: [pdf, markdown, api, claude, ai, agent, llm, gpt, template, document]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/geo-platform-optimizer
---


# GEO Platform Optimizer

## Core Insight

Only **11% of domains** are cited by BOTH ChatGPT and Google AI Overviews for the same query. Each AI search platform uses different indexes, ranking logic, and source preferences. A page optimized for Google AI Overviews may be invisible to ChatGPT, and vice versa. Platform-specific optimization is not optional — it is the foundation of any serious GEO strategy.

## How to Use This Skill

1. Collect the target URL and the site's primary topic/industry
2. Run each platform checklist below against the site
3. Score each platform on the 0-100 rubric
4. Generate GEO-PLATFORM-OPTIMIZATION.md with per-platform scores, gaps, and action items

---

## Platform 1: Google AI Overviews (AIO)

### How AIO Selects Sources
- 92% of AIO citations come from pages already ranking in the **top 10 organic results** — traditional SEO is the gateway
- However, 47% of citations come from pages ranking **below position 5** — AIO has its own selection logic favoring clarity and directness over raw rank
- AIO strongly favors pages with **clean structure, direct answers, and scannable formatting**
- Featured snippet optimization has ~70% overlap with AIO optimization
- AIO prefers **concise, factual, unambiguous answers** — hedging and filler reduce citation probability

### Optimization Checklist

1. **Question-Based Headings**: Use H2/H3 headings phrased as questions matching real user queries. Check Google's "People Also Ask" for the target topic and mirror those exact phrasings.
2. **Direct Answer in First Paragraph**: After each question heading, provide a clear 1-2 sentence answer immediately. Then expand with supporting detail. The first sentence should be a standalone citation candidate.
3. **Tables and Structured Comparisons**: AIO heavily cites tables. Convert any comparison, pricing, specification, or feature data into HTML tables. Use clear column headers.
4. **Ordered and Unordered Lists**: Step-by-step processes should use ordered lists. Feature lists should use unordered lists. AIO extracts these directly.
5. **FAQ Sections**: Add a dedicated FAQ section with 5-10 real questions. Use proper H3 headings for each question. While FAQPage schema rich results are restricted to govt/health sites since Aug 2023, the content pattern still helps AIO extraction.
6. **Definitions and Glossary Boxes**: For any industry-specific term, provide a clear definition. Format: "**[Term]** is [concise definition]." AIO frequently cites definitions.
7. **Statistics with Sources**: Include specific numbers with attribution. "According to [Source], [statistic]." AIO prefers citeable, specific claims over vague assertions.
8. **Publication Date**: Include a visible publication date and last-updated date. AIO deprioritizes undated content for time-sensitive queries.
9. **Author Byline**: Display author name with credentials. Link to an author page with bio, credentials, and sameAs links.
10. **Page Depth**: Keep target pages within 3 clicks of homepage. AIO rarely cites deep, orphaned content.

### Scoring Rubric (0-100)

| Criterion | Points | How to Score |
|---|---|---|
| Ranks in top 10 for target queries | 20 | 20 if yes, 10 if top 20, 0 if beyond |
| Question-based headings present | 10 | 2 points per question heading, max 10 |
| Direct answers after headings | 15 | 3 points per direct answer, max 15 |
| Tables present for comparison data | 10 | 10 if tables used appropriately, 5 if partial, 0 if absent |
| Lists for processes/features | 10 | 10 if present, 5 if partial |
| FAQ section with 5+ questions | 10 | 10 if 5+, 5 if 1-4, 0 if none |
| Statistics with citations | 10 | 2 points per cited stat, max 10 |
| Publication/updated date visible | 5 | 5 if both dates, 3 if one, 0 if none |
| Author byline with credentials | 5 | 5 if full byline, 3 if name only, 0 if none |
| Clean URL + heading hierarchy | 5 | 5 if H1>H2>H3 clean, 3 if minor issues, 0 if broken |

---

## Platform 2: ChatGPT Web Search

### How ChatGPT Selects Sources
- Uses **Bing's search index** as its foundation (not Google)
- Top citation sources by domain share: **Wikipedia (47.9%)**, Reddit (11.3%), YouTube, major news outlets
- ChatGPT heavily weights **entity recognition** — if your brand exists as a structured entity (Wikipedia, Wikidata, Crunchbase), it is far more likely to be cited
- Prefers **authoritative, well-established sources** over new or niche sites
- Longer, more comprehensive articles get cited more often than short pieces
- ChatGPT tends to cite **the most canonical source** for a claim rather than the original

### Optimization Checklist

1. **Wikipedia Presence**: Check if the brand/person/product has a Wikipedia article. If not, assess notability criteria. If notable, create a draft. If an article exists, ensure it is accurate and current.
2. **Wikidata Entity**: Verify the entity exists on Wikidata (wikidata.org). If not, create a Wikidata item with key properties: instance of, official website, soci
