---
name: contract-document-renewal
description: Contract register: counterparty, owner, start and end dates, auto-renewal flag, renewal notice deadline, value and tax basis. Use for renewal tracking and notice deadlines. 
category: Document Processing
source: antigravity
tags: [xlsx, markdown, ai, agent, automation, workflow, template, document, spreadsheet, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/contract-document-renewal
---


# Contract & Document Renewal

**What it is:** Renewal management.

## Overview

Works out the smallest useful **Contract & Document Renewal** setup for the business in front of it, then
builds it only when asked. The default output is a short recommendation, not a
spreadsheet. Artifacts - CSV, SQL DDL, JSON Schema, Notion mapping - are produced on
request, from one field list so they cannot drift apart.

Layer: Layer 7: Protect. Fits: Growth stage. Table code: n/a.

## When to Use This Skill

- contract tracker
- renewal calendar
- contract expiry alerts
- vendor agreement register

Also use it when the user says "renewal management", or describes the same process happening in a
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

> **Q:** When is your next renewal?

### Step 2 - Ask only what is missing

Skip anything the user already answered, in any earlier message. Ask the rest one at a
time, and stop as soon as the remaining answers would not change the output.

- **Documents** - How many contracts? / Which types? / Customers or vendors?
- **Dates** - Renewal date known? / Notice period? / Auto-renew or manual?
- **Ownership** - Who owns each? / Who signs? / Where stored?
- **Current process** - Is it tracked now? / Calendar or reminders? / What gets missed?
- **Outcome** - What do you need? / A renewal calendar, an owner list or both?

Never invent an answer. If the user does not know, record it as unknown and carry on.

### Step 3 - Hold the internal context

Hold the answers in this shape. It stays internal - it is not shown to the user unless
they ask, and it never carries a value the user did not give.

```yaml
module: contract-document-renewal
intent: null            # setup | advice | review | fix | build | convert | export
scale: null             # Starter | Growth | Scale, only if the answer changes it
areas:
  "Documents": null
  "Dates": null
  "Ownership": null
  "Current process": null
  "Outcome": null
requested_outputs: []   # csv | sql | json | notion | xlsx - requested formats only
confirmed_facts: []     # only what the user actually said
open_questions: []      # the unanswered ones, in the order worth asking
```

### Step 4 - Recommend the smallest workflow

If an artifact was requested, build it after resolving essential missing facts. Otherwise give a short recommendation and offer the relevant artifact.

**Recommended approach:** Track the renewal date, the notice deadline and the owner as one record. Set the notice date as the trigger, not the renewal date.

**Why this one:** Renewals are missed because the notice deadline is earlier than the renewal date. Record both and act on the earlier one.

**Workflow:** Contract recorded → Notice window → Reminder → Review → Renewed, amended or ended

**The notice deadline is the trigger, so it has to exist as a date.** This module exists because the notice
deadline falls *before* the renewal date, and `Renewal Notice (Days)` alone cannot be watched - a number of days
never goes red. Store the deadline in `Notice Deadline` and calculate it, never accept it as typed:

```
Notice Deadline = End Date - Renewal Notice (Days)
```

Treat the difference as calendar days, count the deadline day itself as day 1, and store the result as a plain
date in ISO `YYYY-MM-DD`. A notice period is a count of days, not a date, so never accept a date typed into
`Renewal Notice (Days)` and never accept a deadline typed into `Notice Deadline` - the two disagree silently and
the register misses the reminder. If the contract auto-renews and no notice is served, `Notice Deadline` is the
last day the user may still act; after it passes, `Auto-Renew` TRUE means the contract has renewed by operation of
its own terms and `Status` must not still read `In Renewal`.

**Status means one thing at a time.** `Expiring Soon` is the window between the notice deadline and the end date -
action is still possible. `In Renewal` is only correct once a renewal has actually been agreed or served. A
contract whose notice deadline has passed with no action recorded is `Expiring Soon` with the g
