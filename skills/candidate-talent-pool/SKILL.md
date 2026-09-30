---
name: candidate-talent-pool
description: Candidate and prospect pool: contact details, experience, skills, consent status and date, referral source and last contact. Use for talent pipelines and re-engagement. 
category: Document Processing
source: antigravity
tags: [python, xlsx, markdown, ai, agent, automation, workflow, template, document, spreadsheet]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/candidate-talent-pool
---


# Candidate Talent Pool

**What it is:** Prospect database.

## Overview

Works out the smallest useful **Candidate Talent Pool** setup for the business in front of it, then
builds it only when asked. The default output is a short recommendation, not a
spreadsheet. Artifacts - CSV, SQL DDL, JSON Schema, Notion mapping - are produced on
request, from one field list so they cannot drift apart.

Layer: Layer 2: Acquire. Fits: Growth stage. Table code: n/a.

## When to Use This Skill

- talent pool database
- candidate tracker
- recruiter pipeline spreadsheet
- keep candidates warm

Also use it when the user says "prospect database", or describes the same process happening in a
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

> **Q:** Which roles do you hire for?

### Step 2 - Ask only what is missing

Skip anything the user already answered, in any earlier message. Ask the rest one at a
time, and stop as soon as the remaining answers would not change the output.

- **Roles** - Which roles? / How many open? / Any hard-to-fill roles?
- **Pipeline** - How do you find people now? / Referrals or inbound? / Keep rejects warm?
- **Pool** - How long to keep? / Contact allowed? / Consent to re-engage?
- **Current process** - Where do CVs sit now? / Spreadsheet or inbox? / How many in the pool?
- **Outcome** - What do you need? / A pool, a tracker or alerts?

Never invent an answer. If the user does not know, record it as unknown and carry on.

### Step 3 - Hold the internal context

Hold the answers in this shape. It stays internal - it is not shown to the user unless
they ask, and it never carries a value the user did not give.

```yaml
module: candidate-talent-pool
intent: null            # setup | advice | review | fix | build | convert | export
scale: null             # Starter | Growth | Scale, only if the answer changes it
areas:
  "Roles": null
  "Pipeline": null
  "Pool": null
  "Current process": null
  "Outcome": null
requested_outputs: []   # csv | sql | json | notion | xlsx - requested formats only
confirmed_facts: []     # only what the user actually said
open_questions: []      # the unanswered ones, in the order worth asking
```

### Step 4 - Recommend the smallest workflow

If an artifact was requested, build it after resolving essential missing facts. Otherwise give a short recommendation and offer the relevant artifact.

**Recommended approach:** Keep a warm pool with consent and a re-engage date. It is a contact list with a purpose, not a resume archive.

**Why this one:** Rejected candidates are the cheapest hiring source you have, and the most commonly thrown away. Consent and a re-engage date are what make it reusable.

**Workflow:** Candidate added → Consent → Re-engage date → Reminder → Reopen role

**Re-engagement gate:** a candidate may carry a `Re-engage Date` only when `Consent Status` is `Granted`. If consent was never recorded, leave `Re-engage Date` empty, set `Consent Status` to `Not recorded`, and tell the user how many candidates are blocked on it. Do not infer consent from a role being open, from the candidate replying once, or from their CV being on file. `Declined` is final: never re-contact, and never quietly reset it to `Not recorded` to make a re-engagement list longer.

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
connection. For requested workspace changes, follow the shared contract: verify act
