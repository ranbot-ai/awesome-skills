---
name: geo-crawlers
description: AI crawler access analysis. 
category: Development & Code Tools
source: antigravity
tags: [javascript, pdf, markdown, claude, ai, agent, llm, gpt, template, image]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/geo-crawlers
---


# AI Crawler Access Analysis Skill

## Purpose

This skill analyzes a website's accessibility to AI crawlers -- the bots that AI companies use to discover, index, and train on web content. If AI crawlers are blocked, the site's content cannot appear in AI-generated responses regardless of its quality. Crawler access is the foundational technical requirement for GEO.

## Key Insight

As of early 2026, many websites inadvertently block AI crawlers through overly aggressive robots.txt rules, inherited from legacy SEO configurations. An Originality.ai 2025 study found that over 35% of the top 1,000 websites block at least one major AI crawler, and 5-10% block all AI crawlers. Blocking AI crawlers is the single fastest way to become invisible in AI-generated search results.

---

## Complete AI Crawler Reference

### Tier 1: Critical for AI Search Visibility (RECOMMEND: ALLOW)

These crawlers power the AI search products where users actively look for answers. Blocking them directly reduces your visibility in AI-generated responses.

#### GPTBot
- **Operator:** OpenAI
- **User-Agent:** `GPTBot`
- **Full User-Agent String:** `Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)`
- **Purpose:** Fetches content for ChatGPT's web browsing, plugins, and search features. Content accessed by GPTBot may be used to improve OpenAI models.
- **Impact of Blocking:** Content will NOT appear in ChatGPT Search results or be accessible when users ask ChatGPT to browse the web. This is the highest-impact AI crawler to allow.
- **Recommendation:** **ALLOW** -- ChatGPT has 300M+ weekly active users as of 2025. Blocking GPTBot removes your content from one of the largest AI search surfaces.

#### OAI-SearchBot
- **Operator:** OpenAI
- **User-Agent:** `OAI-SearchBot`
- **Full User-Agent String:** `Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; OAI-SearchBot/1.0; +https://docs.openai.com/bots/overview)`
- **Purpose:** Specifically powers ChatGPT's search feature. Unlike GPTBot, content accessed by OAI-SearchBot is NOT used for model training -- only for live search results.
- **Impact of Blocking:** Content will not appear in ChatGPT's search results even if GPTBot is allowed.
- **Recommendation:** **ALLOW** -- This is a search-only crawler with no training implications. There is no strategic reason to block it.

#### ChatGPT-User
- **Operator:** OpenAI
- **User-Agent:** `ChatGPT-User`
- **Full User-Agent String:** `Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ChatGPT-User/1.0; +https://openai.com/bot)`
- **Purpose:** Used when a ChatGPT user explicitly asks the model to visit a specific URL. Acts like a browser agent on behalf of the user.
- **Impact of Blocking:** ChatGPT cannot visit your pages when users ask it to read or summarize them. This prevents direct user-initiated traffic.
- **Recommendation:** **ALLOW** -- Blocking this bot prevents users who are actively trying to engage with your content from accessing it through ChatGPT.

#### ClaudeBot
- **Operator:** Anthropic
- **User-Agent:** `ClaudeBot`
- **Full User-Agent String:** `ClaudeBot/1.0; +https://www.anthropic.com/claude-bot`
- **Purpose:** Fetches web content for Claude's features including web search, citations, and analysis tools.
- **Impact of Blocking:** Content will not be accessible to Claude for web search or when users ask Claude to analyze specific URLs.
- **Recommendation:** **ALLOW** -- Claude is a major AI assistant with growing market share. Blocking ClaudeBot reduces your AI search footprint.

#### PerplexityBot
- **Operator:** Perplexity AI
- **User-Agent:** `PerplexityBot`
- **Full User-Agent String:** `Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)`
- **Purpose:** Powers Perplexity's AI search engine, which provides sourced answers with direct citations and links back to source pages.
- **Impact of Blocking:** Content will not appear in Perplexity search results. Perplexity is one of the best referral traffic sources among AI search products because it always displays source links.
- **Recommendation:** **ALLOW** -- Perplexity drives actual referral traffic and always attributes sources. High-value AI crawler for publishers and businesses.

---

### Tier 2: Important for Broader AI Ecosystem (RECOMMEND: ALLOW)

These crawlers serve large AI platforms or search ecosystems. Allowing them increases your content's reach.

#### Google-Extended
- **Operator:** Google
- **User-Agent:** `Google-Extended`
- **Purpose:** Controls whether Google uses your content for Gemini model training and AI Overviews improvement. **CRITICAL NOTE:** Blocking Google-Extended does NOT affect your Google Search rankings or your appearance in Google Search results. That is controlled by the standard Googlebot.
- **Impact of Blocking:** Content may not be used for Gemini training or to improve AI Overviews. However, your con
