---
name: not-a-vibe-coder
description: Turns vague prompts into 8 structured planning files for brand new projects. DO NOT use on existing codebases. 
category: Document Processing
source: antigravity
tags: [typescript, api, ai, workflow, design, document, firebase, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/not-a-vibe-coder
---


# Not-a-Vibe-Coder

A skill that turns any project idea — no matter how vague — into 8 living planning
documents that act as the project's persistent memory across a long context window.
The documents are the source of truth for "what we agreed on"; the user's live
instructions are always the final authority and can override the docs at any time.

## Core Principles (never violate these)

1. **User command > files > AI assumptions.** If the user says something that
   contradicts a file, the user wins — and the relevant file(s) should then be
   updated to reflect the new instruction.
2. **No silent additions.** Never add features, tech choices, pages, tables, or
   rules the user did not ask for or approve. If something seems missing, ask —
   don't assume. Exception: when the user explicitly says "fill it in",
   "brainstorm the rest", "you decide", etc. — see Phase 3.
3. **Design.md is special.** NEVER fill Design.md with your own taste. Always ask
   the user for style direction (e.g. minimal, playful, corporate, dark mode,
   neumorphic, etc.) and a color palette (or offer 2-3 palette options to pick
   from) before writing anything into it.
4. **One file at a time, in order**, during initial planning — don't dump all 8
   files at once unless the user explicitly asks for that.
5. **Tracker.md is append-only progress tracking** — update it whenever work is
   completed, never rewrite history, just check items off and add new ones as
   they emerge.
6. **Mid-project changes ripple.** If the user requests a change mid-build that
   affects earlier decisions (e.g. "actually let's use Postgres instead of
   Firebase", "add a booking feature"), update ALL affected files yourself,
   without being asked file-by-file. Then summarize what changed.
7. **Read before you write.** At the start of any session, if these files
   already exist in the project, read all 8 before doing anything else — they
   are your memory.

## The 8 Files

| File | Purpose |
|---|---|
| PRD.md | What the app does, features, goals, user requirements |
| TechSpec.md | Architecture, tech stack, APIs, database choices |
| AppFlow.md | User flows and navigation |
| Design.md | UI/UX guidelines, layout, style, color palette |
| Schema.md | Database tables, relationships, data models |
| ImplementationPlan.md | Step-by-step development roadmap |
| Tracker.md | Completed work, pending tasks, progress |
| Rules.md | Coding standards, constraints, project rules |

## Workflow

### Phase 0 — Detect intent

- ONLY for brand new projects. If project has existing code files, ABORT and do not use this skill.
- If the user gives a one-liner idea ("build me a restaurant ordering app") for a new project,
  this is the trigger to start Phase 1.
- If the user gives a fully detailed spec already, you can still create the
  files but populate them directly from what they said — skip redundant
  questions.

### Phase 1 — PRD.md first

This is the foundation. Everything else depends on it.

- Take whatever the user gave you (even just "restaurant app") and ask a small
  number of clarifying questions to flesh out the PRD — target audience, core
  features, platforms (web/mobile/both), must-haves vs nice-to-haves, monetization
  if any, etc. Use `ask_user_input_v0` for quick multiple-choice clarifications
  where natural.
- The user can also choose to skip Q&A and just write directly into PRD.md
  themselves — if they say "I'll fill it in", create a skeleton PRD.md with
  section headers and placeholders, and wait for them.
- Do not invent features. If the user's answer is vague, ask again or offer
  options — don't fill gaps with assumptions.
- Once the PRD feels solid, write PRD.md, show it to the user, and get
  confirmation before moving to the next file.

### Phase 2 — Remaining files, one by one (except Design.md)

In this order: TechSpec.md → AppFlow.md → Schema.md → ImplementationPlan.md →
Rules.md → Tracker.md → Design.md (last, see Phase 2.5).

For each file:
- Propose a draft based on the PRD and any prior files, OR ask the user
  questions if there's a real decision to make (e.g. "Should this use
  PostgreSQL or a simpler option like SQLite/Firebase?").
- Show the draft, ask for confirmation or edits.
- Only move to the next file after the user is satisfied with the current one.

If the user says "just fill out the rest yourself, no assumptions, brainstorm
properly" — this means: make reasonable, justifiable choices consistent with
the PRD and any constraints already stated (not random/lazy defaults), but
still present everything to the user afterward for review before building
starts. "No assumptions" here means "don't contradict or extend the PRD's
intent" — not "ask about every detail."

### Phase 2.5 — Design.md (always interactive)

Never write Design.md without asking the user:
- Overall style direction (e.g. minimal / modern / playful / corporate / retro /
  brutalist / glassmorphism / dark-first) — offer `ask_user_input_v0` choices
  if 
