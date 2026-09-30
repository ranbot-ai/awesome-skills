---
name: capacity-workload-planner
description: Weekly capacity and workload register: available and allocated hours, utilisation percentage, over-allocation check and leave days. Use for resource planning. 
category: Document Processing
source: antigravity
tags: [xlsx, markdown, ai, agent, automation, workflow, template, design, document, spreadsheet]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/capacity-workload-planner
---


# Capacity & Workload Planner

**What it is:** Resource management.

## Overview

Works out the smallest useful **Capacity & Workload Planner** setup for the business in front of it, then
builds it only when asked. The default output is a short recommendation, not a
spreadsheet. Artifacts - CSV, SQL DDL, JSON Schema, Notion mapping - are produced on
request, from one field list so they cannot drift apart.

Layer: Layer 4: Manage. Fits: Scale stage. Table code: n/a.

## When to Use This Skill

- capacity planning
- workload planner
- resource allocation sheet
- utilization tracker

Also use it when the user says "resource management", or describes the same process happening in a
spreadsheet, a document or someone inboxes.

Do not use it for: payroll calculation, tax filing, or legal advice. This skill produces
empty templates only - it never holds or processes real employee or customer data.

## How It Works

Follow the shared execution contract. The module-specific rules below define only domain fields, decisions, calculations, and safety constraints.

### Step 1 - Identify intent

Read the request and pick the intent before asking anything.

- "set up" or "build" or "create" -> the user wants artifacts; go to Step 2.
- "our process is ..." or "it is in a sheet" -> the user wants to move an existing process; capture it, then Step 2.
- "is this right" or "review" or "audit" -> the user wants a check, not a build; answer from what they share.
- "how do I ..." -> advice question; answer directly and offer the build only if it helps.

Ask only if this is the highest-value missing fact; otherwise proceed without an opener:

> **Q:** How many people are billable?

### Step 2 - Ask only what is missing

Skip anything the user already answered, in any earlier message. Ask the rest one at a
time, and stop as soon as the remaining answers would not change the output.

- **Capacity** - How many people? / Billable or not? / Weekly hours?
- **Demand** - How many live projects? / Who allocates? / Fixed dates?
- **Method** - Weekly or daily? / Utilisation target? / Overtime allowed?
- **Current process** - How do you plan now? / Spreadsheet or guess? / When is it too late?
- **Outcome** - What do you need? / A plan, alerts or a forecast?

Never invent an answer. If the user does not know, record it as unknown and carry on.

### Step 3 - Hold the internal context

Hold the answers in this shape. It stays internal - it is not shown to the user unless
they ask, and it never carries a value the user did not give.

```yaml
module: capacity-workload-planner
intent: null            # setup | advice | review | fix | build | convert | export
scale: null             # Starter | Growth | Scale, only if the answer changes it
areas:
  "Capacity": null
  "Demand": null
  "Method": null
  "Current process": null
  "Outcome": null
requested_outputs: []   # csv | sql | json | notion | xlsx - requested formats only
confirmed_facts: []     # only what the user actually said
open_questions: []      # the unanswered ones, in the order worth asking
```

### Step 4 - Recommend the smallest workflow

If an artifact was requested, build it after resolving essential missing facts. Otherwise give a short recommendation and offer the relevant artifact.

**Recommended approach:** Plan by week, not by day, and flag over-allocation rather than trying to optimise it. Nobody acts on a daily capacity model.

**Why this one:** Weekly capacity is the smallest unit people actually plan in. If the model is daily it will be ignored within a fortnight.

**Workflow:** People → Available hours → Allocation by week → Over-allocation flag → Rebalance

**Derived values - calculate, never ask for and never accept as typed:**

```
Utilisation %    = Allocated Hours / Available Hours x 100, rounded once to the nearest whole number
Allocation Check = Over-allocated  when Utilisation % > 100
                   Within capacity when Utilisation % is 100 or less
                   Under-allocated when Utilisation % < 100
```

The percentage is stored as a whole number: `80` means 80%, never `0.8`. Round once, at this
step, and use the rounded value everywhere so the stored number and the flag can never
disagree. If `Available Hours` is `0` the ratio is undefined: leave `Utilisation %` and
`Allocation Check` empty and flag the row for a human rather than dividing by zero or
defaulting to 0. A person on full leave has no capacity, which is not the same as having
spare capacity.

**Approval gate:** a week may only be `Approved` when `Allocation Check` is `Within capacity`.
An over-allocated week is a real finding, not a rounding error - raise it, do not approve it,
and do not quietly trim `Allocated Hours` to make it fit. Reallocate with the people affected,
or record why the over-allocation is accepted.

### Step 5 - Build only on request

Once the user asks for it, derive the fields from the confirmed context and emit the
requested artifacts. For machine-readable text, keep
