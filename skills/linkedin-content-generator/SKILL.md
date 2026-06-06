---
name: linkedin-content-generator
description: AI-powered LinkedIn content suite: generate posts, carousels, newsletters, and 30-day calendars with niche-specific SEO rules and a reinforcement-learning personal memory system. 
category: Document Processing
source: antigravity
tags: [python, markdown, api, mcp, claude, ai, agent, automation, workflow, template]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/linkedin-content-generator
---


# LinkedIn Content Generator

## Overview

A full LinkedIn content-creation suite for Claude Code that turns a topic and niche into
publish-ready posts, multi-slide carousels, long-form newsletter editions, and 30-day content
calendars — all wired through a personal reinforcement-learning memory system so every output
improves as you give feedback.

Seven coordinated commands cover the full content workflow:

| Command | Purpose |
|---|---|
| `/generate-post` | Single ready-to-publish LinkedIn post |
| `/generate-carousel` | Numbered slide content + caption |
| `/generate-newsletter` | Long-form newsletter edition |
| `/generate-calendar` | 30-day posting calendar with Markdown table |
| `/show-memory` | Display current preferences and feedback log |
| `/feedback` | Save what worked for future outputs |
| `/clear-memory` | Reset memory to factory defaults |

All helper scripts are bundled inside `skills/linkedin-content-generator/scripts/` and ship
alongside this `SKILL.md`. They build richly engineered prompts, inject your saved
preferences, and enforce LinkedIn SEO rules before Claude generates output.
A local `memory.md` file persists your style, tone, successful hooks, and top-performing
formats across every session.

## When to Use This Skill

- Use when you need a ready-to-paste LinkedIn post with SEO-optimised hooks and hashtags.
- Use when building a multi-slide carousel deck for LinkedIn Documents.
- Use when writing a long-form LinkedIn Newsletter edition with structured sections.
- Use when planning an entire month of content with format variety and pacing rules.
- Use when you want content that adapts to your personal voice over time via saved feedback.
- Use when working in any niche (AI, SaaS, Marketing, Finance, Healthcare, etc.) and need
  platform-native formatting that avoids common LinkedIn algorithmic pitfalls.

## Prerequisites

**Python 3.8 or later** must be available in your shell path.

The skill is self-contained. Install it from the antigravity skills library:

```bash
# Install via antigravity CLI (recommended)
antigravity install linkedin-content-generator

# Or copy manually into your Claude Code skills directory
cp -r skills/linkedin-content-generator ~/.claude/skills/
```

All six Python scripts and the default `memory.md` are bundled inside the
`scripts/` subdirectory of this skill. No additional cloning or downloads are required.
No API keys, external services, or network access are needed.

## How It Works

### Architecture

```
User command (/generate-post ...)
        │
        ▼
SKILL.md parses $ARGUMENTS
        │
        ▼
Python script builds prompt
  • Injects LinkedIn SEO rules
  • Injects memory.md preferences
        │
        ▼
Claude generates publish-ready output
        │
        ▼
/feedback saves what worked → memory.md
        (loop — every future output improves)
```

### Step 1: Set Up Your Niche (One-Time)

Open `~/.claude/skills/linkedin-content-generator/scripts/memory.md` and update the
**Primary Niche** field:

```markdown
## Core Identity & Tone
- **Primary Niche:** AI & Technology   ← change this
```

This field is injected into every prompt. Without it, the skill defaults to
`"AI & Technology"`.

### Step 2: Generate Content

Run any of the seven commands described in the **Commands Reference** section below.
Claude reads the script output and produces the final content directly in the chat.

### Step 3: Save What Works

After each output, save successful patterns with `/feedback`:

```
/feedback the storytelling hook in this post got 3x more comments than usual
```

The feedback is appended to `memory.md` and automatically injected into all future
generation prompts.

## Commands Reference

### `/generate-post` — Single LinkedIn Post

Generates a scroll-stopping, SEO-optimised LinkedIn text post.

**Usage:**
```
/generate-post <topic> [in <niche>] [tone: controversial|storytelling|educational|motivational|professional]
```

**Parameters:**

| Parameter | Default | Options |
|---|---|---|
| `topic` | required | any subject |
| `niche` | `"AI & Technology"` | any industry |
| `tone` | `professional` | `professional` · `storytelling` · `controversial` · `educational` · `motivational` |
| `style` | `list-based` | `list-based` · `text-only` · `storytelling` · `data-driven` · `contrarian` |

**Examples:**

```
/generate-post why most developers fail at time management in Software Engineering tone: storytelling
```

```
/generate-post the real cost of technical debt in SaaS tone: controversial
```

```
/generate-post 5 things I wish I knew before my first startup in Entrepreneurship tone: educational style: list-based
```

**Output structure:**
1. Scroll-stopping hook (2 lines, triggers "see more")
2. Context / problem setup (2–3 short sentences)
3. Core value (numbered list or bullets, max 7 items)
4. Key takeaway (1–2 punchy sentences)
5. Specific call to action
6. 3–5 hashtags (broad + niche + community mix)

---

### `/generate-carousel` — LinkedIn
