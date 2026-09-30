---
name: data-export-engine
description: Data export log: source module, purpose, format, requester and approver, delivery dates, personal-data flag and status. Use for export audit trails. 
category: Document Processing
source: antigravity
tags: [xlsx, markdown, ai, agent, automation, workflow, template, document, spreadsheet, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/data-export-engine
---


# Data Export Engine

**What it is:** Data extraction.

## Overview

Works out the smallest useful **Data Export Engine** setup for the business in front of it, then
builds it only when asked. The default output is a short recommendation, not a
spreadsheet. Artifacts - CSV, SQL DDL, JSON Schema, Notion mapping - are produced on
request, from one field list so they cannot drift apart.

Layer: Layer 9: Analyze. Fits: Scale stage. Table code: n/a.

## When to Use This Skill

- data export log
- data request tracker
- export register
- data extraction record

Also use it when the user says "data extraction", or describes the same process happening in a
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

> **Q:** Where does the data need to go?

### Step 2 - Ask only what is missing

Skip anything the user already answered, in any earlier message. Ask the rest one at a
time, and stop as soon as the remaining answers would not change the output.

- **Sources** - Which systems? / How many? / What format today?
- **Destination** - Where is it going? / Who consumes it? / How often?
- **Scope** - All records or a subset? / Any sensitive data? / Filtering needed?
- **Current process** - How exported now? / Manual or automated? / What breaks?
- **Outcome** - What do you need? / A one-off export or a repeating feed?

Never invent an answer. If the user does not know, record it as unknown and carry on.

### Step 3 - Hold the internal context

Hold the answers in this shape. It stays internal - it is not shown to the user unless
they ask, and it never carries a value the user did not give.

```yaml
module: data-export-engine
intent: null            # setup | advice | review | fix | build | convert | export
scale: null             # Starter | Growth | Scale, only if the answer changes it
areas:
  "Sources": null
  "Destination": null
  "Scope": null
  "Current process": null
  "Outcome": null
requested_outputs: []   # csv | sql | json | notion | xlsx - requested formats only
confirmed_facts: []     # only what the user actually said
open_questions: []      # the unanswered ones, in the order worth asking
```

### Step 4 - Recommend the smallest workflow

If an artifact was requested, build it after resolving essential missing facts. Otherwise give a short recommendation and offer the relevant artifact.

**Recommended approach:** For a one-off export, use a generated CSV. Only build a repeating feed when the consumer needs it on a schedule.

**Why this one:** Most export requests are one-off. A manual CSV generated from a view solves them; automation is worth it only for a fixed schedule.

**Workflow:** Scope defined → Exported → Delivered → Consumed or archived

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

```csv
Export Name,Source Module,Requested By,Purpose,Format,Date Requested,Date Delivered,Contains Personal Data,Approved By,Status,E
