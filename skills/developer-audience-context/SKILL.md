---
name: developer-audience-context
description: When the user wants to establish or update their developer audience context. Also use when starting any other developer marketing skill to ensure foundational context is loaded. Trigger phrases includ
category: Document Processing
source: antigravity
tags: [markdown, api, ai, agent, document, security, tailwind, supabase, stripe, docker]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/developer-audience-context
---


# Developer Audience Context
## When to Use

Use this skill when you need when the user wants to establish or update their developer audience context. Also use when starting any other developer marketing skill to ensure foundational context is loaded. Trigger phrases include "developer persona," "target developers," "who are our developers," "developer...


This skill helps you create and maintain `.agents/developer-audience-context.md` — a foundational document that captures everything about your target developers. All other developer marketing skills reference this document first, so you only define your audience once.

---

## Before You Start

Check if `.agents/developer-audience-context.md` exists:

- **If it exists**: Read it and offer to update specific sections
- **If it doesn't exist**: Create the directory and file, then walk through each section

---

## Two Ways to Build Context

### Option 1: Auto-Draft from Codebase (Recommended)

Analyze existing materials to draft an initial version:

1. **README.md** — Product description, features, getting started
2. **Documentation** — `/docs`, API reference, tutorials
3. **Landing pages** — `index.html`, marketing copy
4. **package.json / pyproject.toml** — Dependencies reveal ecosystem
5. **GitHub Issues** — Common questions, frustrations, use cases
6. **Existing blog posts** — Technical content, tutorials

After drafting, walk through each section to validate and fill gaps.

### Option 2: Start from Scratch

Ask questions section-by-section. Don't advance until the current section is complete.

---

## The 10 Sections to Capture

### 1. Product Overview

| Field | What to capture |
|-------|-----------------|
| Product name | Official name and any aliases |
| One-liner | "We help [developers] do [X] without [Y]" |
| Category | API, SDK, CLI, SaaS, open source library, infrastructure |
| Core technology | Languages, frameworks, platforms supported |
| Pricing model | Free/open source, freemium, usage-based, seat-based |

### 2. Developer Persona

Not "developers" generically — get specific:

| Field | What to capture |
|-------|-----------------|
| Primary role | Backend, frontend, full-stack, DevOps, data, ML, mobile |
| Seniority | Junior, mid, senior, staff, lead, architect |
| Company size | Solo, startup, scale-up, enterprise |
| Industry verticals | Fintech, healthtech, e-commerce, gaming, B2B SaaS |
| Tech stack | Languages, frameworks, cloud providers they use |
| Decision authority | Individual contributor, team lead, buyer, influencer |

**Ask**: "Describe the developer who gets the most value from your product in one paragraph. What's their day-to-day like?"

### 3. Where They Hang Out

Developers research before they buy. Know where:

| Channel | Specifics to capture |
|---------|---------------------|
| Communities | Specific subreddits, Discord servers, Slack groups |
| Social | Twitter/X hashtags, LinkedIn groups |
| Content | Blogs they read, newsletters they subscribe to, podcasts |
| Events | Conferences, meetups, hackathons |
| Code | GitHub topics, Stack Overflow tags |

**Pro tip**: Use social listening tools to monitor conversations across Hacker News, Reddit, Stack Overflow, GitHub, and Twitter. See where discussions about your problem space happen organically.

### 4. Problems & Pain Points

Capture the actual problems, not your solution's features:

| Level | What to capture |
|-------|-----------------|
| Functional | "I can't do X" / "X takes too long" / "X is error-prone" |
| Emotional | Frustration, anxiety, embarrassment, fear |
| Situational | When does the pain occur? What triggers the search? |

**Ask**: "What's the #1 frustration that brings developers to you?"

**Research**: Search Reddit, Hacker News, and Stack Overflow for complaints about your problem space. Capture verbatim quotes.

### 5. Current Alternatives

What are developers using today instead of you?

| Alternative type | Examples |
|-----------------|----------|
| Direct competitors | Tools that solve the same problem |
| DIY / build it yourself | Custom scripts, internal tools |
| Indirect solutions | Workarounds, manual processes |
| Do nothing | Live with the pain |

For each alternative, capture:
- Why developers choose it
- What's frustrating about it
- What would make them switch

### 6. Key Differentiators

What makes you different — in developer terms:

| Differentiator type | Example |
|--------------------|---------|
| Technical | "10x faster," "No dependencies," "Type-safe" |
| DX (Developer Experience) | "5-minute setup," "Great docs," "First-class CLI" |
| Ecosystem | "Works with X," "Built for Y framework" |
| Philosophy | "Open source," "Privacy-first," "Local-first" |

**Warning**: Avoid marketing fluff. Developers see through "best-in-class" and "enterprise-grade." Use specific, provable claims.

### 7. Verbatim Developer Language

Capture exact phrases developers use — not polished marketing copy:

| Category | Examples |
|----------|---
