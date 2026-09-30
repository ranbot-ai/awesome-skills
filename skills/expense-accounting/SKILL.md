---
name: expense-accounting
description: Expense accounting register: expense number and date, payee with PAN and VAT, bill reference, document type, amount with VAT, ledger account, approver and status. Use for expense bookkeeping. 
category: Document Processing
source: antigravity
tags: [xlsx, markdown, ai, automation, workflow, template, document, spreadsheet, security, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/expense-accounting
---


# Expense Accounting

**What it is:** One row per bill or valid supporting document, carrying the nature of the expense, the document behind it, the applicable tax information and the ledger account together.

## Overview

Works out the smallest useful **Expense Accounting** setup for the business in front of it, then
builds it only when asked. The default output is a short recommendation, not a
spreadsheet. Artifacts - CSV, SQL DDL, JSON Schema, Notion mapping - are produced on
request, from one field list so they cannot drift apart.

Three guardrails shape the whole table.

**Tax is recorded, never assumed.** Being VAT-registered does not tell you the rate, whether
the expense is taxable, whether input tax is recoverable, whether the amount is
tax-inclusive, or whether a reverse charge or another treatment applies. TDS is not part of
an expense entry at all unless the business actually deducts it. Every tax field in the
minimum schema is optional until a rate *and* a treatment have been supplied by the user.

**An expense entry is not a payment.** Payment mode, payment date, payment reference, net
payable, TDS and department are payment-stage facts. They do not appear in an expense-only
setup. If the user asks for payment tracking, that is a deliberate scope change and the
fields are added then, not by default.

**The document must be the real document.** Where no formal invoice exists, an internal
supporting document is defensible only where the transaction would not normally produce
one - purchases from farmers and individual suppliers, wage sheets, rent agreements and
rent records. The absence of an invoice does **not** automatically justify raising a
purchase "Kharche/Kharpai". `Document Type`, `Internal Support Justified` and
`Justification` exist to hold that decision, and a reviewer holds it, not this skill. No
label in the `Document Type` list makes any document legally sufficient.

Layer: Layer 5: Expense & Payroll. Fits: Starter stage. Table code: n/a.

## When to Use This Skill

- expense register
- petty expense sheet
- expense book with tax
- bill and voucher log
- expenses booked to the right account

Also use it when the user describes the same process happening in a spreadsheet, on paper,
or in someone's inbox.

Do not use it for: payroll calculation, tax filing, tax-return preparation, legal advice,
deciding whether a transaction is legally deductible, deciding which tax rate applies,
deciding whether a supporting document is legally sufficient, or processing real employee,
customer, supplier, PAN, VAT or banking data. This skill produces templates only.

## How It Works

Follow the shared execution contract. The module-specific rules below define only domain fields, decisions, calculations, and safety constraints.

### Step 1 - Identify intent

Read the request and pick the intent before asking anything.

- "set up" / "build" / "create" -> a new structure; go to Step 2.
- "our expenses are in a sheet" / "we currently record ..." -> capture the existing
  process first, then Step 2.
- "is this right" / "review this" / "audit this" -> a check, not a build; answer from what
  they share and do not rebuild.
- "how do I ..." -> advice; answer directly and offer a build only if it helps.

### Step 2 - Ask only what is missing

Treat ambiguous replies as unanswered and ask which explicit option the user means. Record unknown values as `Unknown`; `Unknown` is not zero. A record must not be `Done` when a required check fails.

One message, one question, no batching. Skip anything the user already answered, in any
earlier message. Ask only questions whose answer would change the recommended structure or
the requested artifact. Stop as soon as the remaining unknowns would not change the output.
Record `Unknown` and move on when the user does not know, and never ask the same unknown
twice.

The opening question targets the highest-value missing fact. Do not ask for the largest
expense category as a warm-up because it does not change the table structure.

For a new setup the usual first question is:

> **Q:** What do you want to record: expense entries only, payments too, or both?

Then, only as needed:

- **Existing process** - Are you starting from scratch, or replacing an existing sheet or
  book?
- **Categories** - What expense categories do you actually use? If the user does not
  know, keep `Category` configurable. Do not impose a standard category list as though it
  were confirmed.
- **Documents** - Do you normally receive a bill or invoice for each expense? If not,
  what do you keep when there is no formal bill? Record the actual document type.
- **Tax** - Which tax information do you need on each expense? If VAT/GST: do you need the
  rate and the amount recorded separately? If TDS/withholding is not used, TDS fields are
  absent from the schema rather than optional-but-present.
- **Accounting** - Do you assign each expense to a ledger account? Who decides the account?
- **Approval** - Do
