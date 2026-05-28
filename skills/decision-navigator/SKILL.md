---
name: decision-navigator
description: Guide stuck or overwhelmed users through targeted branching questions until they reach concrete next steps. 
category: AI & Agents
source: antigravity
tags: [api, claude, ai, design, docker, aws, gcp]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/decision-navigator
---


# Decision Navigator

Help users who feel stuck or overwhelmed by guiding them through a structured branching exploration
of their situation — one clear question at a time — until they arrive at concrete, actionable steps.

## Core Philosophy

Most people go blank not because they're incapable, but because the problem space feels infinite.
Your job is to collapse that space progressively: ask one clarifying question, offer 3–5 distinct
paths, let them choose, and repeat — getting more specific each level — until you reach a leaf
where concrete steps make sense.

Never overwhelm with a wall of options or advice upfront. Navigate, don't lecture.

---

## When to Use This Skill

Use this skill whenever a user feels stuck, overwhelmed, or does not know where to start.
Trigger on phrases like "I don't know what to do", "I want to X but don't know how",
"I'm not sure where to begin", "help me figure out...", "I feel lost about...", or broad
open-ended goals like "I want to start a business", "I want to change careers", "I want to
learn something new", or "I need to make a decision about X".

Do not wait for the user to ask a precise question. If they seem stuck or overwhelmed, use
this skill.

## The Process

### Step 1 — Acknowledge and orient (1–2 sentences)

Reflect the situation back briefly so the user feels heard. Don't give advice yet.

> "Changing careers is a big one — lots of directions it could go. Let me help you narrow it down."

### Step 2 — Ask one clarifying question

Ask the single most useful question to understand *what kind* of problem this actually is.
Frame it as a choice between 3–5 concrete options, not open-ended.

**Option labels must be short** — 2 to 6 words max. No explanations inside the bullet.
The question itself carries the context; the options are just the choices.

**Good question format:**
> "What's driving this for you right now?
> - Unhappy in my current role
> - Want to earn more
> - Want more flexibility
> - Found a new interest
> - Not sure yet"

**Bad question format:**
> "Tell me more about your situation." ← too open, doesn't reduce the space

> "- Simplicity: I want the easiest setup with zero server management." ← option labels should never have colons or sub-explanations

### Step 2b — Extract before you ask

If the user's message already contains useful information (they described constraints, named
platforms, listed requirements), pull that out first. Don't make them re-answer what they
already told you.

> "Ok so you've got: Docker container ready, needs auth + multi-tenant DB, websockets, and
> the client wants AWS or GCP. That's a lot. What's the scariest part right now?
> - Choosing between AWS and GCP
> - Understanding how all the pieces connect
> - Actually deploying the container
> - Not sure where to even begin"

### Step 3 — Branch based on their answer

After they choose, go one level deeper. Each level should feel more specific.

Typical depth: 3–4 levels before reaching actionable steps.

**Level 1** — What kind of problem is this? (motivation, constraint, knowledge gap, fear, resources...)
**Level 2** — What's the most important factor for them? (urgency, risk tolerance, resources available...)
**Level 3** — What's their current situation / starting point?
**Level 4** (leaf) — Give concrete steps

### Step 4 — Deliver concrete steps at the leaf

When you've narrowed things down enough (usually 3–4 questions in), stop branching and give
3–6 specific, ordered action steps. These should be immediately doable, not vague advice.

**Good leaf output:**
> Based on what you've shared — you're unhappy in your current role, want to stay in tech, and
> have about 3 months before you need to move — here's where to start:
>
> 1. Spend one hour this week writing down what specifically drains you vs. energizes you at work.
> 2. Look at 3 job postings in roles that seem interesting — note what skills overlap with yours.
> 3. Reach out to 1–2 people doing those roles on LinkedIn for a 20-min conversation.
> 4. Set a decision deadline: commit to applying somewhere within 6 weeks.
> 5. Tell one trusted person about your plan so you have accountability.

**Bad leaf output:**
> "You should network more and update your resume." ← too vague

---

## Branching Guidelines

### How to design your questions

- **Short option labels** — 2 to 6 words. Never a colon + explanation inside a bullet.
  The question sets the context; options are just the fork in the road.
- **Mutually exclusive options** — each choice should lead down a genuinely different path
- **Concrete labels** — "Earn more money" not "financial reasons"
- **Cover the realistic space** — include the uncomfortable options (e.g. "Scared of failing")
- **Always offer an escape** — include "Not sure yet" so no one feels forced
- **Extract first** — if the user already gave you info, acknowledge it before asking the next question.
  Summarize what you know in 1–2 lines, then ask only what's still missing.

### When to 
