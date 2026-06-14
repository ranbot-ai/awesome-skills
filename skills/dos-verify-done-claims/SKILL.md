---
name: dos-verify-done-claims
description: Before accepting an agent's 'done / shipped / fixed' claim, verify it against ground truth (git ancestry + the commit's own diff) using the DOS kernel's `dos verify` and `dos commit-audit` — never t
category: AI & Agents
source: antigravity
tags: [api, claude, ai, agent, llm, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/dos-verify-done-claims
---


# Verify done-claims against ground truth, not the agent's word

## Overview

When an AI agent says "done", "shipped", or "fixed", that is a **claim**, not a
fact — and a claim the agent checks by re-reading its own work is *consistency,
not grounding*. This skill replaces that self-report with a verdict from a
witness the agent did not author: it shells the **DOS kernel** (`dos verify`,
`dos commit-audit`) to confirm the claimed effect from git ancestry and the
commit's actual diff. DOS is deterministic — no API key, no LLM. The verdict is
git-only and offline as used here; the one exception is `dos verify` in a
workspace that wires a CI oracle, which `--no-ci` suppresses (see Security &
Safety Notes).

This skill adapts the DOS reference "witness-claim" pattern
(`anthony-chaudhary/dos-kernel`) into a host-agnostic screenplay.

## When to Use This Skill

- Use when an agent reports a task/phase/feature as **complete** and you want
  that "done" confirmed from evidence before building on it.
- Use right after a commit, to confirm the commit's **message matches its diff**
  (catch a `fix:` that only touched a README, or a "tests pass" that deleted the
  assertions).
- Use when folding many sub-agents' results — verify each claimed effect instead
  of trusting the return string.
- **Do not** use it to judge whether code is *correct* — that is what the test
  suite is for. This skill checks did-the-claimed-thing-actually-ship.

## How It Works

### Step 1: Install the kernel (once)

```bash
pip install dos-kernel        # provides the `dos` CLI; deterministic, no key
```

### Step 2: Audit the latest commit's claim vs its diff

A commit subject is forgeable (whoever wrote the message authored it); the files
it touched are not (git did). `dos commit-audit` grades the subject against the
actual diff:

```bash
dos commit-audit --workspace . HEAD --json
```

`commit-audit --json` prints a JSON **array** of audited commits (one element
even for a single `HEAD`), so read `verdict` from the first element — e.g.
`dos commit-audit --workspace . HEAD --json | jq -r '.[0].verdict'`. (Without
`--json` the same verdict prints as a one-line text row: `· OK …`,
`⚑ UNWITNESSED …`, or `· abstain …`.) The verdicts are: `OK` (the diff backs the
claim's *kind*), `CLAIM_UNWITNESSED` (the subject's claim is not evidenced by the
diff — treat the "done" as unproven), or `ABSTAIN`. This judges the *kind* of
change, never correctness — run the tests for that.

### Step 3: Verify a named phase actually shipped

If the agent claims a specific plan/phase landed, confirm it from git history
rather than the transcript:

```bash
dos verify --workspace . PLAN PHASE --json --no-ci
```

`--no-ci` keeps the verdict git-only (see the Security note below). With `--json`
you get the `shipped` and `source` fields. (The default text form prints
`SHIPPED PLAN PHASE (via grep)` or `NOT_SHIPPED PLAN PHASE (via none)` — the same
verdict, and the process exit code is non-zero when not shipped.)

Grade `shipped: true` by the `source`, because git fallback grades itself by
**forgeability** — and forgeable evidence is exactly what this skill exists to
distrust:

- `registry` or `grep-artifact` — **non-forgeable** (a registry row, or an
  artefact/diff rung). This closes the claim.
- `grep-subject` (or bare `grep`) — **forgeable**: a commit *subject* or body
  carried the phase token, which an agent can write without doing the work (even
  on an empty commit). Treat this as *shipped-per-the-subject*, not confirmed —
  corroborate it (run `dos commit-audit` on that commit, below) before you close.
- `none` — no positive evidence; accept as "not shipped", not as a tool failure.

### Step 4: Fold only confirmed effects

Accept the agent's "done" **only** when Step 2/3 corroborate it. If
`CLAIM_UNWITNESSED` or `shipped: false`, the work is not done regardless of how
confidently the agent narrated it — send it back.

## Examples

### Example 1: gate an agent's "I fixed the bug" claim

```bash
# The agent committed and said it's fixed. Check the diff backs the claim.
# commit-audit --json returns an array, so read the first element's verdict:
dos commit-audit --workspace . HEAD --json | jq -r '.[0].verdict'
# OK                -> the change is of the claimed kind; now run the tests
# CLAIM_UNWITNESSED -> the commit doesn't do what it says; reject
```

### Example 2: confirm a feature phase shipped before closing a ticket

```bash
dos verify --workspace . AUTH AUTH2 --json --no-ci
# shipped: true, source: registry|grep-artifact -> non-forgeable; safe to close
# shipped: true, source: grep-subject|grep       -> forgeable subject/body match;
#   shipped-per-the-subject only -> corroborate with commit-audit before closing
# shipped: false, source: none -> no evidence; keep the ticket open
```

## Best Practices

- ✅ Run `dos commit-audit HEAD` immediately after every agent commit.
- ✅ Treat `source: none` / `CLAIM_UNWITNESSED` as "not done", not as a tool error.
- ✅ C
