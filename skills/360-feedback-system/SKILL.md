---
name: 360-feedback-system
description: 360 feedback register: reviewer, subject, review cycle, visibility, due date and score, as CSV, SQL, JSON Schema or Notion on request. Use for 360 reviews or peer feedback cycles. 
category: Document Processing
source: antigravity
tags: [xlsx, markdown, ai, agent, automation, workflow, template, document, spreadsheet, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/360-feedback-system
---


# 360° Feedback System

**What it is:** Records one feedback response per row, with the field list built only from what the user confirms.

## Overview

Works out the smallest useful 360° feedback setup for the business in front of it, then builds
it only when asked. The default output is a short recommendation, not a spreadsheet. CSV, SQL
DDL, JSON Schema and the Notion mapping are derived from the one Field Reference below, so they
cannot drift apart.

Three conceptual models are kept separate, because merging them is what forces fields to be
invented:

- **Response** - one row per feedback response. The only model with a table in this skill.
- **Scoring Configuration** - scale, weights, missing and not-applicable handling, rounding.
  Configuration, never a column on the response row.
- **Questions** - the question set and its version, held only when questions change between
  cycles. A question ID is a column on Response only once that requirement is confirmed.

Artifacts are empty templates by default. The single illustrative row is a shape placeholder
carrying `Example` / `-EXAMPLE-` values, never business data.

Layer: Layer 4: Manage. Fits: Growth stage. Table code: n/a.

## When to Use This Skill

- 360 feedback
- feedback system
- peer review tool
- 360 degree feedback tracker

Also use it when the user says "holistic feedback", or describes the same process happening in a
spreadsheet, a document or someone's inbox.

Not for payroll, tax, legal, or employment-decision work. This skill does not automate those.

## How It Works

Follow the shared execution contract. The module-specific rules below define only domain fields, decisions, calculations, and safety constraints.

The rules below stand on their own. If the shared execution contract at
`../../references/execution-contract.md` is unavailable, follow this file directly; a missing
reference never blocks basic execution.

### Step 1 - Identify intent

Read the request and pick one intent before asking anything. This is the canonical set, used
here and in the context block with the same spelling:

| Intent | Trigger | Go to |
|---|---|---|
| `advice` | "how do I ...", "what should we" | Answer, offer the build only if it helps |
| `review` | "is this right", "review", "audit" | Check what they share |
| `build` | "set up", "build", "create" | Step 2 |
| `convert` | "move it from our sheet/forms" | Capture their process, then Step 2 |
| `export` | "give me the CSV / SQL / JSON / Notion" for confirmed rules | Step 5 |

One message, one question, no batching. Never ask a question whose answer would not change the
recommendation or the requested artifact.

### Scope boundary

Decline only the specific high-risk action that is out of scope, and continue with the rest of
the request. Example: for a request that mixes feedback capture with payroll, decline the payroll
calculation and proceed with the feedback setup.

### Step 2 - Ask only what is missing

Skip anything already answered in any earlier message. Ask the rest one at a time, and stop as
soon as the remaining answers would not change the output.

Decide fields from the answers, not from habit. The only fields that need no confirmation are the
ones in the minimum core below. Each optional field needs a confirmed requirement behind it:

| Candidate field | Only add when the user confirms |
|---|---|
| `Score` | A scoring mode on a defined scale |
| Additional score fields | Named competency areas, one per confirmed area |
| `Due Date` | Deadlines are part of their process |
| `Reviewer` | Responses are identified or confidential, not anonymous |
| `Review Cycle` | Feedback runs in more than one cycle |
| `Submitted Date` | Submission is timestamped in their process |
| `Question ID` | The question set changes between cycles |
| `Feedback Subject` | A subject is recorded at all |

`Feedback Subject` stays a generic label. The subject may be a person, a project, a customer or
a team, so take the type from the user rather than assuming an employee.

Never invent an answer. Record it as unknown and carry on. `Unknown` is a real value meaning not
yet supplied. Never turn Unknown into zero, and never turn a blank into a zero. Never re-ask an
unknown already recorded.

Answers like `yes`, `no`, `maybe`, `same`, `okay` or `fine` are not an answer to a
multiple-choice question. Re-ask as an explicit choice:

> **Q:** Which do you mean: **identified** or **anonymous** feedback?
>
> **A:** maybe

Keep only the answered part of a partial answer, and leave the rest `Unknown`.

### Step 3 - Hold the internal context

Hold the answers in this shape. It stays internal, is not shown unless asked, and never carries a
value the user did not give.

```yaml
module: 360-feedback-system
intent: null            # advice | review | build | convert | export
scale: null             # only when the answer changes the recommendation
areas:
  "Subject": null
  "Relationships": null
  "Visibility": null
  "Scoring": null
  
