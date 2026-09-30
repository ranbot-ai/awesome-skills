---
name: brand-kit-print-collateral
description: Print collateral spec: item, finished and trim size, bleed, colour mode, stock and GSM, finish, safe margin, print method, quantity and unit cost. Use for cards and letterhead. 
category: Document Processing
source: antigravity
tags: [pdf, markdown, ai, workflow, template, design, document, presentation, image, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/brand-kit-print-collateral
---


# Brand Kit & Print Collateral

**What it is:** the printed identity set - letterhead, visiting card, employee ID card, folder, invoice, quotation and the email signature block - specified to the point where any printer can produce it.

## Overview

Works out the smallest useful collateral set for the business in front of it, then builds it
only when asked. The default output is a short recommendation, not a set of layout files.
The collateral register - CSV, SQL DDL, JSON Schema, Notion mapping - is produced on
request, from one field list so the four cannot drift apart.

Layer: Layer 2: Brand & Design. Fits: Starter stage. Table code: n/a.

**The rule this table exists to enforce:** the finished size and the trim size are
different things, and a designer who forgets the difference pays for the reprint. The
finished size is what gets cut; the trim size is finished size plus bleed on every edge.
The table keeps them in separate columns for exactly that reason, and the same logic
separates colour mode, stock weight and finish - three decisions a printer asks about
before a job starts, and three that cannot be changed after it starts.

## When to Use This Skill

- letterhead, visiting card, business card, ID card, employee card, name badge
- compliment slip, folder, envelope, invoice, quotation, statement
- email signature block
- "our print looks wrong"
- prepress, bleed, CMYK, crop marks, stock weight, lamination
- brand guidelines for anything that gets printed

Do not use it for: the digital design system (`design-theme-guide`), the mark itself
(`logo-image-design`), or the email body templates - the signature block is in scope here,
the body is `business-email-template`.

Do not use it before an approved mark exists. Collateral built with no approved logo is a
rewrite later; route to `logo-image-design` first and note the dependency.

## How It Works

Follow the shared execution contract. The module-specific rules below define only domain fields, decisions, calculations, and safety constraints.

### Step 1 - Identify intent

Read the request and pick the intent before asking anything.

- "design" / "make" / "we need" -> artifacts wanted; go to Step 2.
- "we already print these" -> something exists; capture it, then Step 2.
- "print came out wrong" / "fix" -> a prepress or specification problem; capture what went
  wrong, then Step 2.
- "review" / "check" -> a check, not a build.

Ask only if this is the highest-value missing fact; otherwise proceed without an opener:

> **Q:** What is the business called, and what does one line of it actually do?

### Step 2 - Ask only what is missing

Treat ambiguous replies as unanswered and ask which explicit option the user means. Record unknown values as `Unknown`; `Unknown` is not zero. A record must not be `Done` when a required check fails.

Skip anything already answered. Ask the rest one at a time, and stop as soon as the
remaining answers would not change the item list or the specification.

- **Identity** - Exact business name, address and phone as they must print? / Logo file
  available in an editable or vector format? / Anything already printed that must match?
- **Items** - Which items are needed - letterhead, card, employee card, folder, invoice,
  envelope? / Which need to be two-sided? / Is the employee card for access control, or
  purely for identity?
- **Volume** - How many of each, now and over the year? / Who prints it - a local printer,
  a national one, or an online print service?
- **Specification** - Any stock or finish already decided? / Does it need to be writable -
  pen, pencil, thermal printer? / Any wet or outdoor exposure?
- **Employee card detail** - What goes on it - photo, name, role, department, phone, or a
  barcode? / What is the data-protection position on employee photos and role data?

Never invent an answer. Names, addresses, phone numbers, quantities, stock weights, printer
names, prices and barcode schemes the user has not supplied are `Unknown`.

### Step 3 - Hold the internal context

```yaml
module: brand-kit-print-collateral
intent: null            # design | fix | review | import
scale: null             # Starter | Growth | Scale, only if the answer changes it
areas:
  "Identity": null
  "Items": null
  "Volume": null
  "Specification": null
  "Employee Card Detail": null
requested_outputs: []
confirmed_facts: []
open_questions: []
```

### Step 4 - Recommend the smallest workflow

Build an already requested artifact without asking again. For advice-only requests, give a short recommendation and offer the relevant artifact.

**Recommended approach:** Four items that between them cover almost every business - A4
letterhead, a 55x90mm visiting card, an 85.54mm employee card in the same family, and a
single-page email signature. Each specified with trim, bleed, colour mode, stock and
finish stated once, plus a PDF proof and a print-ready export with crop marks. Build the
envelope and folder only when someone asks for them
