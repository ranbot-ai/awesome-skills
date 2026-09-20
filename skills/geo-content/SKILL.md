---
name: geo-content
description: Content quality and E-E-A-T assessment for AI citability — evaluate experience, expertise, authoritativeness, trustworthiness, and content structure 
category: Document Processing
source: antigravity
tags: [pdf, markdown, claude, ai, agent, llm, template, document, rag, seo]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/geo-content
---


# GEO Content Quality & E-E-A-T Assessment

## Purpose

AI search platforms do not just find content — they evaluate whether content deserves to be cited. The primary framework for this evaluation is **E-E-A-T** (Experience, Expertise, Authoritativeness, Trustworthiness), which per Google's December 2025 Quality Rater Guidelines update now applies to **ALL competitive queries**, not just YMYL (Your Money Your Life) topics. Content that scores high on E-E-A-T is dramatically more likely to be cited by AI platforms.

This skill evaluates content through two lenses:
1. **E-E-A-T signals** — does the content demonstrate real expertise and trust?
2. **AI citability** — is the content structured so AI platforms can extract and cite specific claims?

## How to Use This Skill

1. Fetch the target page(s) — homepage, key blog posts, service/product pages
2. Evaluate E-E-A-T across the 4 dimensions (25% each)
3. Assess content quality metrics (structure, readability, depth)
4. Check for AI content quality signals
5. Evaluate topical authority across the site
6. Score and generate GEO-CONTENT-ANALYSIS.md

---

## E-E-A-T Framework (100 points total)

### Experience — 25 points
First-hand knowledge and direct involvement with the topic. AI platforms increasingly distinguish between content that reports on a topic and content from someone who has DONE it.

**Signals to evaluate:**

| Signal | Points | How to Score |
|---|---|---|
| First-person accounts ("I tested...", "We implemented...") | 5 | 5 if present and specific, 3 if generic, 0 if absent |
| Original research or data not available elsewhere | 5 | 5 if original data, 3 if references original work, 0 if none |
| Case studies with specific results | 4 | 4 if detailed with numbers, 2 if general, 0 if none |
| Screenshots, photos, or evidence of direct use | 3 | 3 if authentic evidence, 1 if stock/generic, 0 if none |
| Specific examples from personal experience | 4 | 4 if specific and unique, 2 if somewhat specific, 0 if generic |
| Demonstrations of process (not just outcome) | 4 | 4 if step-by-step from experience, 2 if partial, 0 if none |

**What to flag as weak Experience:**
- Content that only summarizes what other sources say without adding new perspective
- Generic advice that could apply to any situation ("It depends on your needs")
- No mention of actual usage, testing, or direct involvement
- Hedging language that suggests lack of direct knowledge ("reportedly", "supposedly", "some say")

### Expertise — 25 points
Demonstrated knowledge depth and professional competence in the subject matter.

**Signals to evaluate:**

| Signal | Points | How to Score |
|---|---|---|
| Author credentials visible (bio, degrees, certifications) | 5 | 5 if full credentials, 3 if basic bio, 0 if no author |
| Technical depth appropriate to topic | 5 | 5 if thorough technical treatment, 3 if adequate, 0 if superficial |
| Methodology explanation (how conclusions were reached) | 4 | 4 if clear methodology, 2 if some explanation, 0 if none |
| Data-backed claims (statistics, research citations) | 4 | 4 if well-sourced, 2 if some data, 0 if unsupported claims |
| Industry-specific terminology used correctly | 3 | 3 if accurate specialized language, 1 if basic, 0 if errors |
| Author page with detailed professional background | 4 | 4 if dedicated author page, 2 if brief bio, 0 if none |

**What to flag as weak Expertise:**
- Claims without supporting evidence or sources
- Surface-level coverage of complex topics
- Misuse of technical terminology
- No visible author or author without relevant credentials
- Content that is broad and generic rather than deep and specific

### Authoritativeness — 25 points
Recognition by others as a credible source on the topic.

**Signals to evaluate:**

| Signal | Points | How to Score |
|---|---|---|
| Inbound citations from authoritative sources | 5 | 5 if cited by major sources, 3 if some citations, 0 if none |
| Author quoted or cited in press/media | 4 | 4 if media mentions, 2 if industry mentions, 0 if none |
| Industry awards or recognition mentioned | 3 | 3 if relevant awards, 1 if tangential, 0 if none |
| Speaker credentials (conferences, events) | 3 | 3 if listed, 0 if none |
| Published in peer-reviewed or respected outlets | 4 | 4 if tier-1 publications, 2 if industry outlets, 0 if none |
| Comprehensive topic coverage (topical authority) | 3 | 3 if site covers topic thoroughly, 1 if some coverage, 0 if isolated |
| Brand mentioned on Wikipedia or authoritative references | 3 | 3 if Wikipedia, 2 if other encyclopedic refs, 0 if none |

**What to flag as weak Authoritativeness:**
- Single-topic site with no depth of coverage
- No external validation of expertise claims
- No backlinks from authoritative sources
- Claims of authority without evidence (self-proclaimed "expert")

### Trustworthiness — 25 points
Signals that the content and its publisher are reliable and transparent.

**Signals to evaluate:**

| Signal | Points | How to Sc
