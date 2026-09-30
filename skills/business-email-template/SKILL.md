---
name: business-email-template
description: Business email template register: trigger, sender and recipient type, subject pattern, body structure, personalisation tokens and send checks. Use for repeatable outbound email. 
category: Document Processing
source: antigravity
tags: [markdown, ai, automation, workflow, template, design, document, image, security, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/business-email-template
---


# Business Email Templates

**What it is:** the repeatable emails a business actually sends - enquiry reply, quote, invoice, payment reminder, onboarding, complaint, review request, newsletter - with the sendable copy, the authentication records and the accessibility and spam checks each one needs.

## Overview

Works out the smallest useful template set for the business in front of it, then builds it
only when asked. The default output is a short recommendation, not a set of email files.
The template register - CSV, SQL DDL, JSON Schema, Notion mapping - is produced on request,
from one field list so the four cannot drift apart.

Layer: Layer 6: Engage. Fits: Starter stage. Table code: n/a.

**The rule this table exists to enforce:** a template is not the HTML. A template is the
envelope - who it is from, who it is to, what triggers it, what subject pattern it uses, and
whether the domain is allowed to send it - plus the body. `Sender Role` and `Trigger`
exist because most "our email looks unprofessional" complaints are a missing trigger and a
missing signature, not a missing design. And every template needs a plain-text version,
which is a separate field here rather than an afterthought inside the HTML.

## When to Use This Skill

- email templates, email signatures blocks for body copy, cold outreach
- enquiry reply, quotation, invoice email, payment reminder
- welcome email, onboarding, delivery notification
- complaint response, review request, newsletter, offer
- "our emails go to spam", SPF, DKIM, DMARC, deliverability
- email tone and structure standards
- "make our emails look professional"

Do not use it for: the printed signature block on letterhead and cards
(`brand-kit-print-collateral`), the mailbox and account register
(`company-email-accounts` in the operational pack), or marketing campaign automation.

## How It Works

Follow the shared execution contract. The module-specific rules below define only domain fields, decisions, calculations, and safety constraints.

### Step 1 - Identify intent

Read the request and pick the intent before asking anything.

- "set up" / "build" / "we need" -> artifacts wanted; go to Step 2.
- "ours look bad" / "fix" -> something exists; capture what is sent today, then Step 2.
- "they go to spam" / "review" / "audit" -> a deliverability check, not a build.
- "how do I write ..." -> advice question; answer directly, offer the build only if it helps.

Ask only if this is the highest-value missing fact; otherwise proceed without an opener:

> **Q:** What is the business called, and what does one line of it actually do?

### Step 2 - Ask only what is missing

Treat ambiguous replies as unanswered and ask which explicit option the user means. Record unknown values as `Unknown`; `Unknown` is not zero. A record must not be `Done` when a required check fails.

Skip anything already answered. Ask the rest one at a time, and stop as soon as the
remaining answers would not change the template list.

- **Volume** - How many emails a day, and who reads them - one person or a team? / Are
  they sent from a Gmail/Outlook account, a proper domain mailbox, or a platform?
- **Categories** - Which of enquiry, quote, invoice, reminder, welcome, complaint, review
  request, newsletter actually happen? / Which are sent today, in any form?
- **Authentication** - Does the business send from its own domain? / Have SPF, DKIM and
  DMARC been set up? / Is anything sent through a third-party tool?
- **Constraints** - Any legal or regulatory wording that must appear - unsubscribe,
  sender identity, VAT or GST particulars, a claims address? / Any language the business
  must not use?
- **Tone** - Formal or plain-spoken? / Who signs, by title or by name? / Any sector that
  has a required service standard?

Never invent an answer. Domain names, SPF records, DKIM selectors, unsubscribe periods,
legal wording, senders, volumes and metrics the user has not supplied are `Unknown`.

### Step 3 - Hold the internal context

```yaml
module: business-email-template
intent: null            # set up | fix | review | report | import
scale: null             # Starter | Growth | Scale, only if the answer changes it
areas:
  "Volume": null
  "Categories": null
  "Authentication": null
  "Constraints": null
  "Tone": null
requested_outputs: []
confirmed_facts: []
open_questions: []
```

### Step 4 - Recommend the smallest workflow

Build an already requested artifact without asking again. For advice-only requests, give a short recommendation and offer the relevant artifact.

**Recommended approach:** Start with the four that are sent every week and carry the most
risk - enquiry reply, quote, invoice with payment terms, and payment reminder - plus one
plain-text alternative for each. Put the signature block in a single place so it is edited
once. Confirm SPF, DKIM and DMARC before anything is sent from the domain, because no
template quality survives an unauthenticated domain.

**Why this one:** Those four
