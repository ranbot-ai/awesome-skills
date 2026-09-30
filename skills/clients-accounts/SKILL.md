---
name: clients-accounts
description: Client and account register: contacts, billing address, tax ID and basis, payment terms, invoice totals, amounts paid and outstanding balance. Use for account tracking. 
category: Document Processing
source: antigravity
tags: [xlsx, markdown, ai, agent, automation, workflow, template, design, document, spreadsheet]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/clients-accounts
---


# Clients & Accounts

**What it is:** Every client with contacts, terms and what they owe.

## Overview

Works out the smallest useful **Clients & Accounts** setup for the business in front of it, then
builds it only when asked. The default output is a short recommendation, not a
spreadsheet. Artifacts - CSV, SQL DDL, JSON Schema, Notion mapping - are produced on
request, from one field list so they cannot drift apart.

Layer: Layer 8: Operate. Fits: Starter stage. Table code: n/a.

## When to Use This Skill

- client database
- customer records
- client account tracker
- accounts receivable list

Also use it when the user says "every client with contacts, terms and what they owe", or describes the same process happening in a
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

> **Q:** How many active clients do you have?

### Step 2 - Ask only what is missing

Skip anything the user already answered, in any earlier message. Ask the rest one at a
time, and stop as soon as the remaining answers would not change the output.

- **Clients** - How many active? / Who owns each relationship? / Any churn risk?
- **Details** - Billing details needed? / Contacts per client? / Contract linked?
- **Activity** - How often do you speak? / Meetings logged? / Any health score?
- **Current process** - Where are clients recorded? / CRM or spreadsheet? / What is missing?
- **Outcome** - What do you need? / A client register, a pipeline or reporting?

Never invent an answer. If the user does not know, record it as unknown and carry on.

### Step 3 - Hold the internal context

Hold the answers in this shape. It stays internal - it is not shown to the user unless
they ask, and it never carries a value the user did not give.

```yaml
module: clients-accounts
intent: null            # setup | advice | review | fix | build | convert | export
scale: null             # Starter | Growth | Scale, only if the answer changes it
areas:
  "Clients": null
  "Details": null
  "Activity": null
  "Current process": null
  "Outcome": null
requested_outputs: []   # csv | sql | json | notion | xlsx - requested formats only
confirmed_facts: []     # only what the user actually said
open_questions: []      # the unanswered ones, in the order worth asking
```

### Step 4 - Recommend the smallest workflow

If an artifact was requested, build it after resolving essential missing facts. Otherwise give a short recommendation and offer the relevant artifact.

**Recommended approach:** One record per client with a named owner and next action, and keep activity notes on that record rather than in a separate log.

**Why this one:** Client records go stale when contact details change. A named owner and a next-action date keep the register usable.

**Workflow:** Client recorded → Owner assigned → Activity logged → Next action → Review

**Money basis:** this module does not assume that an amount is tax-inclusive or tax-exclusive. Record the
basis in `Tax Basis` before the money columns mean anything, and if the user has not said, it stays
`Not confirmed` - do not deduce it from the currency, the country, or the size of the number. A registration
number says a business is registered; it never says which tax rate applies or whether the amount includes tax,
so do not add tax rate or tax amount fields to the schema unless the user asks for tax tracking.

**Derived values - calculate, never accept as typed:**

```
Outstanding = Total Invoiced - Total Paid
```

Round once, at the end, to 2 decimal places, and use the rounded figure everywhere. When credits, write-offs
or a part payment mean the two totals do not explain the difference, record why in `Notes` and leave
`Outstanding` as the arithmetic result - do not adjust `Total Paid` to force a tie-out. If the user has
not supplied either total, leave `Outstanding` empty rather than defaulting it to 0.

### Step 5 - Build only on request

Once the user asks for it, derive the fields from the confirmed context and emit the
requested artifacts. For machine-readable text, keep prose outside the data; for files,
provide a usable
