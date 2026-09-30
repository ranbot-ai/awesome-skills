---
name: alumni-re-hire-tracker
description: Alumni and re-hire register: former role, last working day, re-hire eligibility, current employer and re-engagement date, as CSV, SQL, JSON Schema or Notion on request. Use for alumni outreach. 
category: Document Processing
source: antigravity
tags: [xlsx, markdown, ai, agent, automation, workflow, template, document, spreadsheet, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/alumni-re-hire-tracker
---


# Alumni & Re-hire Tracker

**What it is:** Former employees.

## Overview

Works out the smallest useful **Alumni & Re-hire Tracker** setup for the business in front of it, then
builds it only when asked. The default output is a short recommendation, not a
spreadsheet. Artifacts - CSV, SQL DDL, JSON Schema, Notion mapping - are produced on
request, from one field list so they cannot drift apart.

Layer: Layer 10: Exit. Fits: Scale stage. Table code: n/a.

## When to Use This Skill

- alumni tracker
- rehire tracker
- former employee register
- past employee list

Also use it when the user says "former employees", or describes the same process happening in a
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

> **Q:** How many people have left the company?

### Step 2 - Ask only what is missing

Skip anything the user already answered, in any earlier message. Ask the rest one at a
time, and stop as soon as the remaining answers would not change the output.

- **Alumni** - How many ex-employees? / How long ago? / Any warm contacts?
- **Fit** - Why would you re-hire? / Roles they held? / Skills worth recording?
- **Reach** - How do you stay in touch? / Any consent on file? / How often to check in?
- **Current process** - Is anything recorded? / LinkedIn or a sheet? / What gets missed?
- **Outcome** - What do you need? / An alumni register, a re-hire view or both?

Never invent an answer. If the user does not know, record it as unknown and carry on.

### Step 3 - Hold the internal context

Hold the answers in this shape. It stays internal - it is not shown to the user unless
they ask, and it never carries a value the user did not give.

```yaml
module: alumni-re-hire-tracker
intent: null            # setup | advice | review | fix | build | convert | export
scale: null             # Starter | Growth | Scale, only if the answer changes it
areas:
  "Alumni": null
  "Fit": null
  "Reach": null
  "Current process": null
  "Outcome": null
requested_outputs: []   # csv | sql | json | notion | xlsx - requested formats only
confirmed_facts: []     # only what the user actually said
open_questions: []      # the unanswered ones, in the order worth asking
```

### Step 4 - Recommend the smallest workflow

If an artifact was requested, build it after resolving essential missing facts. Otherwise give a short recommendation and offer the relevant artifact.

**Recommended approach:** Keep a small alumni record with the exit date, the role held and one line on why they left, and revisit it only when a role opens.

**Why this one:** Alumni records are only worth maintaining if something triggers a revisit. Tie it to open roles instead of a standing newsletter.

**Workflow:** Departure recorded → Details kept → Re-hire considered when a role opens → Rejoined or contacted

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
Alumni Name,Former D
