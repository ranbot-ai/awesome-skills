---
name: competency-matrix
description: Competency matrix of expected proficiency by job title and grade, with assessment method and linked skill area. Use for role frameworks and hiring bars. 
category: Document Processing
source: antigravity
tags: [xlsx, markdown, ai, agent, automation, workflow, template, document, spreadsheet, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/competency-matrix
---


# Competency Matrix

**What it is:** Skill levels.

## Overview

Works out the smallest useful **Competency Matrix** setup for the business in front of it, then
builds it only when asked. The default output is a short recommendation, not a
spreadsheet. Artifacts - CSV, SQL DDL, JSON Schema, Notion mapping - are produced on
request, from one field list so they cannot drift apart.

Layer: Layer 5: Develop. Fits: Scale stage. Table code: n/a.

## When to Use This Skill

- competency matrix
- skills framework
- role competency model
- capability matrix

Also use it when the user says "skill levels" for **roles** (what each role must show), or
describes the same process happening in a spreadsheet, a document or someone's inbox.

Do not use it for: payroll calculation, tax filing, or legal advice; assessing named people
against expected levels (that is `skill-gap-analysis`); or certifying competence. This skill
produces empty templates only - it never holds or processes real employee or customer data.

## How It Works

Follow the shared execution contract. The module-specific rules below define only domain fields, decisions, calculations, and safety constraints.

### Step 1 - Identify intent

Read the request and pick the intent before asking anything.

- "set up" or "build" or "create" -> `set up`; go to Step 2.
- "our process is ..." or "it is in a sheet" -> `import`; capture it, then Step 2.
- "is this right" or "review" or "audit" -> `review`; answer from what they share. Do not open an intake question.
- "how do I ..." -> `report`; answer directly and offer the build only if it helps.
- "fix" -> `fix`; correct confirmed defects in the supplied material.

One message, one question, no batching. If intent is `set up` or `import` and the user has
not named the roles, open with:

> **Q:** Which roles need a competency model?

If they already named roles, ask the next missing fact that would change the recommendation
or the requested artifact. Never ask a question whose answer would not change the result.

### Step 2 - Ask only what is missing

Skip anything the user already answered, in any earlier message. Ask the rest one at a
time, and stop as soon as the remaining answers would not change the output.

- **Roles** - Which roles? Skip if already named. This table also stores two different
  "level" facts. Do not ask "How many levels?" until you know which: **Grade Level**
  (job grade) or **Expected Level** (proficiency). First ask which they mean, using those
  two names. After that answer, ask how many and what they are called.
- **Competencies** - Which competencies? / Derived from what?
- **Assessment** - Who assesses? / Self or manager? / How often?
- **Current process** - Is anything documented? / Training linked? / What is missing?
- **Outcome** - What do you need? A matrix, an assessment sheet, or a link to a gap record?
  Do not assume a skill-gap table unless they asked for that link.

Never invent an answer. If the user does not know, record it as unknown and carry on.
Country and software are not required inputs for a country-neutral, tool-neutral
competency-matrix review. Ask for either only when the user supplied country- or
tool-specific requirements that materially change the requested result.

### Step 3 - Hold the internal context

Hold the answers in this shape. It stays internal - it is not shown to the user unless
they ask, and it never carries a value the user did not give.

```yaml
module: competency-matrix
intent: null            # setup | advice | review | fix | build | convert | export
scale: null             # Starter | Growth | Scale, only if the answer changes it
areas:
  "Roles": null
  "Competencies": null
  "Assessment": null
  "Current process": null
  "Outcome": null
requested_outputs: []   # csv | sql | json | notion | xlsx - requested formats only
confirmed_facts: []     # only what the user actually said
open_questions: []      # the unanswered ones, in the order worth asking
```

### Step 4 - Recommend the smallest workflow

Give a short recommendation from confirmed facts only, then ask whether to build it. Do not
build unprompted. Ask: "Want me to build the CSV, SQL DDL, JSON Schema, Notion mapping, or an
Excel workbook from these confirmed rules?"

**Recommended approach:** Define a small set of proficiency levels and attach each competency
to the confirmed roles. Include grades only when the user named them. Mention a gap or
training link only when the user confirmed they need one.

**Why this one:** A matrix that is not attached to roles (and, when confirmed, to a later
assessment or gap record) does not change any decision.

**Workflow:** Roles → Competencies → Level expectations → Assessment. Add a gap and training
link only when that outcome was confirmed.

### Step 5 - Build only on request

Once the user asks for it, emit the artifacts as data only. No preamble, no summary, no
closing line. The Field Reference is the documented starting shape. If the user confir
