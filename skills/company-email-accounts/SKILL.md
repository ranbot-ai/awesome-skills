---
name: company-email-accounts
description: Mailbox and licence register: employee, account type, aliases, groups, tool, licence cost, 2FA and password policy state, and access-review dates. Use for account provisioning. 
category: Document Processing
source: antigravity
tags: [xlsx, markdown, ai, agent, automation, workflow, template, document, spreadsheet, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/company-email-accounts
---


# Company Email & Accounts

**What it is:** Work email, groups and tool accounts for every person.

## Overview

Works out the smallest useful **Company Email & Accounts** setup for the business in front of it, then
builds it only when asked. The default output is a short recommendation, not a
spreadsheet. Artifacts - CSV, SQL DDL, JSON Schema, Notion mapping - are produced on
request, from one field list so they cannot drift apart.

Layer: Layer 3: Onboard. Fits: Starter stage. Table code: n/a.

## When to Use This Skill

- company email accounts
- work account register
- google workspace account list
- tool account tracker

Also use it when the user says "work email, groups and tool accounts for every person", or describes the same process happening in a
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

> **Q:** Which tools need an account per person?

### Step 2 - Ask only what is missing

Skip anything the user already answered, in any earlier message. Ask the rest one at a
time, and stop as soon as the remaining answers would not change the output.

- **Tools** - Which systems? / Google Workspace? / Any paid tools?
- **Accounts** - Who is admin? / Backup admin? / Per user or per device?
- **Security** - Two-factor required? / Password manager? / Shared logins in use?
- **Current process** - Where is the list now? / Admin console or nothing? / Orphaned accounts?
- **Outcome** - What do you need? / An account register, provisioning or removal?

Never invent an answer. If the user does not know, record it as unknown and carry on.

### Step 3 - Hold the internal context

Hold the answers in this shape. It stays internal - it is not shown to the user unless
they ask, and it never carries a value the user did not give.

```yaml
module: company-email-accounts
intent: null            # setup | advice | review | fix | build | convert | export
scale: null             # Starter | Growth | Scale, only if the answer changes it
areas:
  "Tools": null
  "Accounts": null
  "Security": null
  "Current process": null
  "Outcome": null
requested_outputs: []   # csv | sql | json | notion | xlsx - requested formats only
confirmed_facts: []     # only what the user actually said
open_questions: []      # the unanswered ones, in the order worth asking
```

### Step 4 - Recommend the smallest workflow

If an artifact was requested, build it after resolving essential missing facts. Otherwise give a short recommendation and offer the relevant artifact.

**Recommended approach:** Build an account register tied to people records, then provision and remove from that one list.

**Why this one:** Account sprawl is a security problem, not an admin problem. One register per person, with join and leave dates, is the whole fix.

**Workflow:** Joiner → Create accounts → Assign tools → Leave → Remove access → Log

**The one rule that makes this register mean anything:** `Access Removed Date` is empty for as long as the
account is live, and is set on the day access is actually removed. Never pre-fill it with a planned or
probable leaver date, because a removal date that was only a forecast is indistinguishable from one that
happened, and the register is read to answer "does this person still have access". A record that is `Active`
with a removal date is a contradiction: fix the status or clear the date, never leave both. `Closed` and
`Pending Offboarding` must carry the date, or the offboarding is not finished.

**Security columns are facts, not targets.** `Two Factor On`, `Recovery Email Set` and `Password Policy Met`
record what is true now. They are not a to-do list and must never be pre-set to TRUE to close a ticket. When
one is FALSE, `Status` may be `Active` - the account genuinely exists - and the fix is the review, not a
reclassification. Never disable a control in order to make a record look compliant.

**Recurring review needs a due date.** `Last Access Review` alone cannot go stale, because it always shows the
most recent review and never says the next one is late. `Next Review Due` carries the deadline; a review is
overdue when the du
