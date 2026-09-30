---
name: advanced-analytics-dashboard
description: Dashboard metric register: metric, source module, formula, period, value, target, trend, owner and last-updated, as CSV, SQL, JSON Schema or Notion on request. Use for KPI dashboards. 
category: Document Processing
source: antigravity
tags: [xlsx, markdown, ai, agent, automation, workflow, template, design, document, spreadsheet]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/advanced-analytics-dashboard
---


# Advanced Analytics Dashboard

**What it is:** A register for analytics metrics and their sources; it does not train or run predictive models.

## Overview

Works out the smallest useful **Advanced Analytics Dashboard** setup for the business in front of it, then
builds it only when asked. The default output is a short recommendation, not a
spreadsheet. Artifacts - CSV, SQL DDL, JSON Schema, Notion mapping - are produced on
request, from one field list so they cannot drift apart.

Layer: Layer 9: Analyze. Fits: Scale stage. Table code: n/a.

## When to Use This Skill

- analytics dashboard
- predictive metrics
- kpi dashboard template
- business metrics dashboard

Also use it when the user says "predictive insights", or describes the same process happening in a
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

> **Q:** Which decision is the dashboard meant to support?

### Step 2 - Ask only what is missing

Skip anything the user already answered, in any earlier message. Ask the rest one at a
time, and stop as soon as the remaining answers would not change the output.

- **Decision** - Which decision? / Who makes it? / How often?
- **Data** - Which sources? / How many rows? / How fresh does it need to be?
- **Measures** - Which metrics? / How many? / Compared against what?
- **Current process** - Do you have a dashboard? / Manual or tool-based? / Is it trusted?
- **Outcome** - What do you need? / A metric set, a layout or both?

Never invent an answer. If the user does not know, record it as unknown and carry on.

### Step 3 - Hold the internal context

Hold the answers in this shape. It stays internal - it is not shown to the user unless
they ask, and it never carries a value the user did not give.

```yaml
module: advanced-analytics-dashboard
intent: null            # setup | advice | review | fix | build | convert | export
scale: null             # Starter | Growth | Scale, only if the answer changes it
areas:
  "Decision": null
  "Data": null
  "Measures": null
  "Current process": null
  "Outcome": null
requested_outputs: []   # csv | sql | json | notion | xlsx - requested formats only
confirmed_facts: []     # only what the user actually said
open_questions: []      # the unanswered ones, in the order worth asking
```

### Step 4 - Recommend the smallest workflow

If an artifact was requested, build it after resolving essential missing facts. Otherwise give a short recommendation and offer the relevant artifact.

**Recommended approach:** Start with the decision, then add one metric per part of it. Layout is a late decision and rarely the problem.

**Why this one:** Dashboards fail from metric sprawl, not from design. Fix the decision and the metric count first, and the layout follows.

**Workflow:** Metric defined → Source data → Calculation → Refresh → Decision review

### Step 5 - Build only on request

Once the user asks for it, derive the fields from the confirmed context and emit the
requested artifacts. For machine-readable text, keep prose outside the data; for files,
provide a usable link. Report material validation failures or limitations separately.

**A selected Notion output is rendered by `notion-manual-import`, so route the
Notion step there.** When the user selects Notion, hand that step to
@notion-manual-import: it holds the CSV, the property
mapping, the import steps and the verification checklist, and it renders the Field
Reference below instead of defining a table of its own. Do not restate the mapping
here and do not improvise the import steps. Manual CSV and mapping outputs need no
connection. For requested workspace changes, follow the shared contract: verify actual
tool access and the target before writing. A user saying "connected" is not tool evidence.
Never ask for a Notion password or token.

For an Excel-compatible CSV, use UTF-8 with a byte order mark so Excel opens the
text correctly. A CSV is not an `.xlsx` workbook; create `.xlsx` only when the user
requests a workbook.
A CSV carries no types, so after it, name the columns
that need a number, date or currency format applied.
