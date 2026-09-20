---
name: constraint-driven-development
description: Write the project quality bar as enforced CONSTRAINTS.md so agents stop quietly lowering it: coverage, performance, accessibility thresholds watched on every diff. 
category: Security & Systems
source: antigravity
tags: [python, markdown, mcp, claude, ai, agent, automation, workflow, security, vulnerability]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/constraint-driven-development
---


# Constraint-Driven Development

## Overview

Other skills in this pack describe what good looks like. `code-review-and-quality` gives you five axes. `test-driven-development` gives you a cycle. `security-and-hardening` gives you a threat list. All of that lives in prose the agent reads and may or may not follow, and none of it survives the end of the session.

This skill produces something different: a written record of **this project's** bar, with numbers, that outlives the conversation and can be checked mechanically.

The reason matters. When you wrote the code, reading it told you whether it was any good. An agent writes more in an afternoon than you will read that week, so the judgement moves out of your head and into checks that run around the loop. Those checks need to exist, they need numbers you actually chose, and they need to fire close enough to the work that the agent fixes its own output.

Spec-driven development says what to build. Test-driven development proves it works. Constraint-driven development defines what "good enough to ship" means, before anyone argues about it in a pull request.

## When to Use

Apply this skill when:

- Starting a project or a significant feature and no quality bar is written down
- The user asks to "set up constraints", "add quality gates", "define our standards", or "stop the agent shipping junk"
- An agent is producing volume nobody is reading line by line
- CI has checks but nobody can say which ones block a merge and which ones are decoration
- Coverage, performance, or accessibility numbers get argued about per-PR instead of decided once
- You're about to run `/build auto` or any autonomous loop, and the only thing standing between it and main is a test suite the agent also wrote

**When NOT to use:**

- The project already has a `CONSTRAINTS.md` and the user isn't changing it — read it and follow it instead
- One-off scripts, spikes, throwaway prototypes
- The user wants a code review right now (`code-review-and-quality`) or a CI pipeline built (`ci-cd-and-automation`)
- Pre-product-market-fit code with a two-week expected lifetime — the floor below is still worth it, the rest isn't

## Loading Constraints

The interview needs a live user. **Don't run it in non-interactive contexts** (CI, `/loop`, autonomous runs). If constraints are missing and you're in one of those, apply the Floor below, note that you did, and flag the rest for a human.

## The Process

### Step 1: Detect before you ask

Never ask what you can read. Before the first question, gather:

| What | Where to look |
|------|---------------|
| Language and stack | `package.json`, `pyproject.toml`, `go.mod`, `Cargo.toml` |
| Test runner | dev dependencies, `test` script, existing test files |
| Existing linters | `eslint.config.*`, `biome.json`, `.ruff.toml` |
| Coverage today | `coverage/` output, or run the suite once |
| CI | `.github/workflows/`, `.gitlab-ci.yml` |
| Agent harness | `.claude/`, `.codex/`, `AGENTS.md` |

Report what you found in two lines, then ask only what's left.

### Step 2: Four questions, each with a default

Follow the one-question-at-a-time discipline from `interview-me`, with one change: every question here has a default, so "I don't know" is a complete answer that still produces a working config.

```
Q1: Beyond the floor, which of these do you want enforced?
    (a) Test coverage on new code
    (b) Security scanning
    (c) Performance budgets
    (d) Accessibility
    (e) Architecture boundaries
GUESS: (a) and (b) — you have a test runner already and you're handling user input.
DEFAULT if unsure: (a) and (b).
Say what each pick costs: (c) and (d) need a running URL, (e) needs a rules file written.
```

```
Q2: When a check fails while the agent is mid-task, should it block or warn?
GUESS: Block. You're running agents unattended and a warning nobody reads is a warning.
DEFAULT if unsure: Block on the floor, warn on everything else for the first two weeks.
```

```
Q3: Do you have target numbers in mind, or should I measure where you are today and hold that line?
GUESS: Measure. Most teams don't have a number, and an invented one gets ignored.
DEFAULT if unsure: Measure and hold. See "Ratchets" below.
```

```
Q4: What's the slowest check you'll tolerate before the agent hands work back?
GUESS: About 90 seconds. Longer and you'll stop running it.
DEFAULT if unsure: 90 seconds at task end, unlimited in CI.
```

Stop at four. A twelve-question intake produces a config nobody understands and a user who regrets starting.

### Step 3: Write CONSTRAINTS.md

One file at the repo root. Any agent on any harness can read it, and a change to it shows up in review where it belongs.

```markdown
# Constraints

Last reviewed: 2026-08-08 by @addy

## Floor (always enforced, no setup required)

- No new suppression comments: `@ts-ignore`, `eslint-disable`, `# noqa`, `# type: ignore`
- No unimplemented stubs: `throw new Error("Not implemented")`, empty `catch {}`
- No skipped or
