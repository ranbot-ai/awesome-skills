---
name: goal-loop
description: Draft and explain persistent goal-loop prompts for long-running agent work with clear stop conditions. 
category: Document Processing
source: antigravity
tags: [markdown, api, claude, ai, agent, gpt, automation, workflow, template, design]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/goal-loop
---


# Agent `/goal` Loop

## What `/goal` is

`/goal` is a slash command that turns an agent prompt into a **persistent agent** looping `plan → act → test → review → iterate` until a stop condition is met, the user pauses, or the token budget runs out. Internally called the "Ralph loop."

Agents with the `/goal` feature right now: **Codex, Claude Code, and Hermes Agent**.

Key difference from a normal prompt: when a turn ends but the goal isn't met, the agent **auto-continues** instead of waiting for input.

**Lifecycle states:** `pursuing`, `paused`, `achieved`, `unmet`, `budget-limited`.

When monitoring a running `/goal`, every check should include a one-line update to the user: what the agent is doing and whether it is on track. Keep it extremely concise.

**Not:** a budget command, a safety boundary, "run forever", or a replacement for `/plan`. It's a contract enforcer with a verification loop.

## Requirements

- An agent with the `/goal` feature — right now: Codex, Claude Code, or Hermes Agent
- The goals feature enabled in the agent's config
- **Subscription auth** — API-key auth does **not** work. A pro-tier plan is the realistic minimum for long runs.

## When to Use it

Use only when **all three** are true:
1. Task is >30 min of mechanical work.
2. There's a **verifiable stop condition** (tests pass, coverage hit, eval ≥ X, build green).
3. Repo is agent-ready (working build, decent tests, `AGENTS.md` present).

Fits: migrations, coverage lifts, TDD feature builds, refactors with contract tests, prompt/eval optimization, deploy retry loops, bug-repro-then-fix.

Bad fits: exploratory work, vague "improve this", anything without a "done" definition, prod credentials, destructive shared-infra ops.

## The 5-part contract (every goal needs this)

1. **Objective** — one sentence, one concrete outcome.
2. **Constraints** — what must NOT change (public API, files, libs, conventions).
3. **Validation command** — the exact shell command that proves progress (`pytest -q`, `pnpm test`, etc.).
4. **Stop condition** — verifiable: "Stop when X passes" OR "when further changes need human/product input."
5. **Documentation** — one sentence instructing the agent to write concise, targeted docs for every change, either creating new `.md` files or updating existing ones.

Plus: tell the agent what to read first, ask it to work in checkpoints with a short progress log.

## Writing a goal (the core deliverable)

When the user wants a quick `/goal` instruction, produce a structured markdown block with one line per contract item (proper newlines, not flowing prose). **Do not prefix the output with `/goal`** — the user adds the slash command themselves in the composer. Emit only the contract body. Template:

```
**Objective:** <one-sentence objective>
**Read first:** <files/PLAN.md/issue>
**Constraints:** <what not to change, libs, conventions>
**Validate:** `<exact command>` after each change
**Document:** Write concise, targeted documentation for all changes — create new `.md` files or update existing docs as needed.
**Checkpoints:** work in checkpoints and log progress briefly
**Stop when:** <verifiable condition>, OR when further changes require human/product input
```

### Example (migration)

```
**Objective:** Migrate this project from Pydantic v1 to v2.
**Read first:** pyproject.toml, src/, tests/
**Constraints:** no public API changes; keep imports backwards-compatible via shims if needed; no new dependencies
**Validate:** `pytest -q` after each change
**Checkpoints:** work in checkpoints; log progress briefly
**Stop when:** full suite passes with zero deprecation warnings, OR when a change requires architecture decisions
```

### Example (coverage lift)

```
**Objective:** Raise coverage in src/auth/ from ~38% to ≥75%.
**Read first:** src/auth/, tests/auth/, AGENTS.md
**Constraints:** no new deps; mirror existing test style; do not modify production code unless strictly required for testability
**Validate:** `pytest --cov=src/auth --cov-report=term-missing`
**Checkpoints:** work in checkpoints; log coverage delta each one
**Stop when:** coverage ≥75% AND all tests pass, OR when uncovered code needs design changes
```

### Writing rules
- **One objective, one stop condition.** Not a backlog.
- **Documentation is mandatory.** Every `/goal` prompt must include a single sentence committing the agent to concise, targeted docs — new `.md` files or focused updates to existing docs.
- **Never instruct the agent to create new ADRs** — ADRs require the user's explicit approval, so goal prompts must not pre-approve or encourage them.
- **Forbid reward-hacking explicitly:** "Do not delete, skip, weaken, or narrow tests to make the goal pass." Otherwise the agent may game the stop condition.
- **4,000-char limit** on the objective. If longer, put detail in a file (`PLAN.md`/`GOAL_BRIEF.md`) and make the goal point to it — keep the goal itself compact.
- Use **literal strings** for paths, commands, issue numbers — exact.
- For
