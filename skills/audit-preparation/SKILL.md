---
name: audit-preparation
description: Audit preparation register: required document, period covered, request and receipt dates, preparer and reviewer, auditor queries and adjustments. Use for assembling an audit file. 
category: Document Processing
source: antigravity
tags: [xlsx, markdown, ai, automation, workflow, template, document, spreadsheet, security, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/audit-preparation
---


# Audit Preparation

**What it is:** The audit file checklist, so nothing the auditor asks for has to be hunted for at year end.

## Overview

Works out the smallest useful **Audit Preparation** setup for the business in front of it, then
builds it only when asked. The default output is a short recommendation, not a
spreadsheet. Artifacts - CSV, SQL DDL, JSON Schema, Notion mapping - are produced on
request, from one field list so they cannot drift apart.

Be clear about what this is. It assembles the file. It does not perform the audit, it
does not test anything, and it produces no opinion on the financial statements - only a
qualified auditor can do that, and only after doing work this skill has no part in. What
it does is make sure the ten sections of the audit file exist, that each document is
requested, received, tracked and filed in one place, and that every query and adjustment
raised along the way has a visible answer.

One rule that causes most of the trouble at year end: permanent documents and tax filings
need current originals, not copies of copies. A registration certificate that lapsed, a
licence that was never renewed, a return filed only as a screenshot of a portal - each one
turns into an avoidable exception. Current originals, verified and dated, or the document
is not there.

Layer: Layer 9: Audit. Fits: Growth stage. Table code: n/a.

## When to Use This Skill

- audit file checklist
- audit document request tracker
- audit query log
- year-end document collection
- audit handover register

Also use it when the user says "the audit file checklist, so nothing the auditor asks for has to be hunted for at year end", or describes the same process happening in a
spreadsheet, a document or someone inboxes.

Do not use it for: the audit itself, assurance on the financial statements, or legal advice. This skill produces
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

> **Q:** When did the auditor last ask you for something, and how long did it take to find?

### Step 2 - Ask only what is missing

Treat ambiguous replies as unanswered and ask which explicit option the user means. Record unknown values as `Unknown`; `Unknown` is not zero. A record must not be `Done` when a required check fails.

Skip anything the user already answered, in any earlier message. Ask the rest one at a
time, and stop as soon as the remaining answers would not change the output.

- **Audit** - Internal, statutory or both? / Is an auditor appointed? / First audit or a repeat?
- **Period** - Which financial year? / Year end date? / Single entity or group?
- **File** - What exists today? / Where is it kept? / How is it handed over?
- **Requests** - Requests in writing? / Who tracks them? / How long do they take to close?
- **Outcome** - What do you need? / A checklist, a request tracker or both?

Never invent an answer. If the user does not know, record it as unknown and carry on.

### Step 3 - Hold the internal context

Hold the answers in this shape. It stays internal - it is not shown to the user unless
they ask, and it never carries a value the user did not give.

```yaml
module: audit-preparation
intent: null            # setup | advice | review | fix | build | convert | export
scale: null             # Starter | Growth | Scale, only if the answer changes it
areas:
  "Audit": null
  "Period": null
  "File": null
  "Requests": null
  "Outcome": null
requested_outputs: []   # csv | sql | json | notion | xlsx - requested formats only
confirmed_facts: []     # only what the user actually said
open_questions: []      # the unanswered ones, in the order worth asking
```

### Step 4 - Recommend the smallest workflow

Build an already requested artifact without asking again. For advice-only requests, give a short recommendation and offer the relevant artifact.

**Recommended approach:** One audit file record per document, tagged to the section of the file it belongs to, carrying the request date, the received date, days pending and any query or adjustment, so the file is assembled continuously instead of hunted for in the last week of the year.

**Why this one:** The ten sections of the audit file are fixed from year to year, so a checklist is the whole job - th
