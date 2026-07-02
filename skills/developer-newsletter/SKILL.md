---
name: developer-newsletter
description: When the user wants to create, write, or improve a newsletter for developer audiences. Trigger phrases include "newsletter," "email marketing," "developer email," "weekly digest," "dev newsletter," "e
category: Document Processing
source: antigravity
tags: [python, javascript, typescript, react, node, markdown, api, ai, agent, automation]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/developer-newsletter
---


# Developer Newsletter
## When to Use

Use this skill when you need when the user wants to create, write, or improve a newsletter for developer audiences. Trigger phrases include "newsletter," "email marketing," "developer email," "weekly digest," "dev newsletter," "email subscribers," "newsletter growth," or "email list.".


This skill helps you build and write newsletters that developers actually open, read, and look forward to receiving. Covers content strategy, writing, growth, and deliverability.

---

## Before You Start

**Load your audience context first.** Read `.agents/developer-audience-context.md` to understand:

- Who you're writing for (role, seniority, tech stack)
- What content resonates (problems, interests)
- Where else they consume content (to avoid duplicate effort)
- Voice & tone (how casual/technical)

If the context file doesn't exist, run the `developer-audience-context` skill first.

---

## Newsletter Strategy

### Define Your Newsletter Type

| Type | Description | Example |
|------|-------------|---------|
| **Product updates** | Changelog, new features, tips | Vercel's updates |
| **Curated links** | Best content from around the web | TLDR, Bytes |
| **Original content** | Your own articles, tutorials | Cassidy Williams |
| **Community digest** | What happened in your community | Dev community roundups |
| **Educational series** | Teaching a topic over time | Course-style newsletters |

**Best practice**: Pick ONE primary type. You can mix in others, but have a clear identity.

### Frequency Matrix

| Frequency | Best For | Risk |
|-----------|----------|------|
| **Daily** | Curated links, news | Fatigue, hard to maintain |
| **Weekly** | Most newsletters | Sweet spot for most |
| **Bi-weekly** | Original content heavy | Can lose momentum |
| **Monthly** | Product updates, digests | Easy to forget you exist |

**Developer preference**: Weekly is the sweet spot. Developers are busy and inbox-protective.

---

## Content Mix Framework

### The 70-20-10 Rule

| Percentage | Content Type | Purpose |
|------------|--------------|---------|
| **70%** | Value content | Teach, inform, help |
| **20%** | Product content | Updates, features, how-tos |
| **10%** | Promotional | CTAs, asks, sales |

### Content Categories

Build a rotation of these:

| Category | Examples |
|----------|----------|
| **Tutorials** | "How to implement X" |
| **News analysis** | "What Y announcement means for you" |
| **Tool/library roundups** | "5 libraries for handling Z" |
| **Code snippets** | "Quick tip: better error handling" |
| **Community highlights** | "Best from our Discord this week" |
| **Industry takes** | "Why I think X is overhyped" |
| **Behind the scenes** | "How we built feature Y" |
| **Q&A** | "You asked, we answered" |

---

## Writing Developer Emails

### Subject Line Framework

What works for developers:

| Pattern | Example | Why It Works |
|---------|---------|--------------|
| **Specific benefit** | "Cut your build time by 40%" | Concrete value |
| **Technical curiosity** | "The JavaScript feature nobody uses" | Triggers curiosity |
| **Direct announcement** | "v2.0 is here: async/await support" | Clear, newsworthy |
| **Number + topic** | "7 TypeScript tricks senior devs use" | Scannable, specific |
| **Question** | "Are you still using callbacks?" | Pattern interrupt |
| **Breaking news** | "React 19 is out: what you need to know" | Timely, urgent |

What doesn't work:

| Avoid | Why |
|-------|-----|
| ALL CAPS | Spam signals |
| "Quick question" | Manipulative |
| Excessive emoji | Looks like marketing |
| "You won't believe..." | Clickbait fatigue |
| No subject line | Just... no |

### Pre-header Text

The preview text after the subject line. Use it.

| Subject | Pre-header |
|---------|------------|
| "v2.0 is here" | "Plus: breaking changes to watch for" |
| "This week in Node.js" | "fetch() drama, npm security, and a cool CLI" |

### Email Structure

```
[Short personal intro - 1-2 sentences]

[Main content sections with clear headers]

[Code snippet if relevant]

[Quick links section]

[Sign-off with personality]
```

### Code in Email

Code rendering is tricky in email. Options:

| Approach | Pros | Cons |
|----------|------|------|
| **Inline code** (`backticks`) | Works everywhere | No highlighting |
| **Plain text block** | Reliable | Ugly |
| **Image of code** | Beautiful | Can't copy, accessibility issues |
| **"View in browser" link** | Full formatting | Friction |
| **Styled HTML tables** | Decent formatting | Complex, can break |

**Recommendation**: Keep code short. Use inline code for small snippets, link to full examples.

```html
<pre style="background-color: #1e1e1e; color: #d4d4d4; padding: 16px; border-radius: 4px; font-family: 'Fira Code', monospace; font-size: 14px; overflow-x: auto;">
const result = await fetch('/api/data');
</pre>
```

---

## Subject Line Testing

### A/B Test Framework

Test one variable at a time:

| Variable | Version A | Version 
