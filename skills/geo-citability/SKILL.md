---
name: geo-citability
description: AI citability scoring and optimization. 
category: Creative & Media
source: antigravity
tags: [pdf, markdown, claude, ai, agent, llm, gpt, template, rag, seo]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/geo-citability
---


# AI Citability Scoring Skill

## Core Insight

AI language models cite passages that meet specific structural criteria. Research from Princeton, Georgia Tech, and IIT Delhi (2024) found that GEO-optimized content achieves 30-115% higher visibility in AI-generated responses. The key finding: AI systems preferentially extract and cite passages that are **134-167 words long**, **self-contained** (understandable without surrounding context), **fact-rich** (containing specific statistics, dates, or named entities), and **directly answer a question** in the first 1-2 sentences.

This is fundamentally different from traditional SEO copywriting, which optimizes for keyword density and user engagement metrics. GEO citability optimizes for **extractability** -- the ease with which an AI system can pull a passage from your content and present it as a direct answer.

---

## Citability Scoring Rubric (0-100)

### Category 1: Answer Block Quality (30% of total score)

This measures whether content contains clear, quotable answer passages that AI systems can extract verbatim.

**Scoring Criteria:**

| Score | Criteria |
|---|---|
| **90-100** | Every major section opens with a 1-2 sentence direct answer. Uses "X is..." or "X refers to..." patterns. First 40-60 words of each section can stand alone as a complete answer. |
| **70-89** | Most sections have clear answer openings. Some definition patterns present. Answers are identifiable but may need minor context. |
| **50-69** | Some sections have answer-like openings but many bury the answer in the middle or end of paragraphs. Few explicit definition patterns. |
| **30-49** | Answers are generally buried in long paragraphs. No consistent definition patterns. Content is narrative-driven rather than answer-driven. |
| **0-29** | No identifiable answer blocks. Content is entirely narrative, conversational, or fragmented. AI would struggle to extract any quotable passage. |

**What to look for:**

- **Definition patterns:** "X is [definition]." / "X refers to [explanation]." / "X means [meaning]."
- **Answer-first structure:** The answer appears in the first sentence, followed by supporting detail.
- **Quantified answers:** "The average cost of X is $Y" rather than "Many factors affect the cost of X."
- **Comparison answers:** "X differs from Y in three ways: [list]" rather than "X and Y are often confused."

**High-citability example:**
```
Content delivery networks (CDNs) are distributed server systems that cache and serve
web content from locations geographically close to end users. A CDN reduces latency
by 50-70% on average by serving assets from edge servers rather than a single origin
server. The three largest CDN providers as of 2025 are Cloudflare (serving approximately
20% of all websites), Amazon CloudFront, and Akamai Technologies.
```
Word count: 58. Self-contained: Yes. Facts: 3 specific data points. Definition pattern: Yes.

**Low-citability example:**
```
If you've ever wondered why some websites load faster than others, the answer might
surprise you. There's this amazing technology that has been around for a while now.
It's changed the way we think about web performance. Let me explain how it works and
why you should care about it for your business.
```
Word count: 52. Self-contained: No (no topic identified). Facts: 0. Definition pattern: No.

---

### Category 2: Passage Self-Containment (25% of total score)

This measures whether individual passages can be extracted and understood without needing the surrounding content.

**Scoring Criteria:**

| Score | Criteria |
|---|---|
| **90-100** | 80%+ of content blocks are fully self-contained. Each passage names its subject explicitly. No reliance on pronouns referencing earlier content. Contains specific facts within the passage. |
| **70-89** | 60-79% of content blocks are self-contained. Most passages name their subject. Occasional pronoun references that require context. |
| **50-69** | 40-59% of content blocks are self-contained. Mixed use of explicit subjects and pronouns. Some passages require reading prior sections. |
| **30-49** | 20-39% of content blocks are self-contained. Heavy reliance on pronouns and contextual references. Most passages need surrounding text. |
| **0-29** | Under 20% self-contained. Content reads as a continuous narrative where extracting any paragraph loses meaning. |

**Self-containment checklist for each passage:**

1. Does the passage explicitly name the subject (not "it," "this," "they")?
2. Can someone understand the main point reading ONLY this passage?
3. Does the passage contain at least one specific fact, statistic, or named entity?
4. Is the passage between 50-200 words (the optimal extraction length)?
5. Does the passage avoid starting with conjunctions ("But," "However," "And") that imply prior context?

---

### Category 3: Structural Readability (20% of total score)

This measures the structural formatting that helps AI systems parse and segment content.

**Scoring 
