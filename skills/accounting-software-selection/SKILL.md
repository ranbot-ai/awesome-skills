---
name: accounting-software-selection
description: Scores shortlisted accounting packages against 57 evidence-backed fields, emitted as CSV, SQL, JSON Schema or Notion on request. Use for choosing accounting software. 
category: Document Processing
source: antigravity
tags: [xlsx, api, ai, automation, workflow, template, document, spreadsheet, security, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/accounting-software-selection
---


# Accounting Software Selection

**What it is:** The evidence behind a software purchase, recorded so the decision is arguable - and the decision itself still belongs to the business.

## Overview

Works out the smallest useful **Accounting Software Selection** setup for the business in front
of it, then builds it only when asked. The default output is a short recommendation, not a
spreadsheet. Artifacts - CSV, SQL DDL, JSON Schema, Notion mapping - are produced on
request, from one field list so they cannot drift apart.

For a Nepal trading, manufacturing or services business, this is the record that makes the
purchase arguable: requirements ranked, a candidate shortlist, the same demo tests run
against every candidate, the evidence behind every score, cost split so first-year and
three-year totals can be compared, and the evaluation status, selection decision,
rejection reason and deal-breaker flag kept as four separate fields instead of one
opinion. It is an evaluation and decision-support tool, not a bookkeeping, tax-filing,
legal or procurement system.

Four guardrails shape every row.

**Nothing is invented, and nothing is asserted without a source.** Never supply a vendor
capability, a price, a compliance status, a demo result or a stakeholder score that the
user or a named source did not give. What nobody has verified is `Untested` for a
capability and an empty cost cell with `Unknown` in `Notes` for a price. A capability
nobody has looked at is `Untested`; it is not `1 Missing`, and a blank is never filled
with a plausible number so the row looks finished.

**This skill never selects.** It may summarise the evidence, name the requirements a
candidate fails, and state that a Must-have is failed. It must not declare a package the
best option, announce a winner, state a compliance conclusion or record an approval. The
business fills `Selection Decision` itself.

**Fact and opinion stay apart.** The thirty capability fields carry what the vendor
documented or demonstrated. The three `Rating` fields carry the named evaluator's own
judgement. A brochure claim is never copied into a Rating, and an evaluator's impression
is never written into a capability field. An average across evaluators is not objective
truth and a score never becomes a recommendation.

**Nepal tax and statutory claims need cited, current evidence.** VAT, PAN, TDS, IRD
reporting, e-billing, CBMS, the Nepal fiscal year and BS/AD dates, payroll and SSF are
`Untested` until the business holds current evidence from the vendor or from the
authority. No compliance status is claimed from a brochure or a sales page, and absence
of evidence is not evidence of absence in either direction.

Layer: Layer 1: Foundation. Fits: Growth stage. Table code: n/a.

## When to Use This Skill

- accounting software selection
- accounting and erp software comparison
- vendor demo evaluation sheet
- accounting package quotation tracker
- three year software cost comparison

Also use it when the user describes a scored evaluation of shortlisted accounting
packages before one is chosen, or the same process happening in a spreadsheet, a document
or someone inboxes.

Do not use it for: day-to-day bookkeeping once a package is live, tax filing, vendor
contracting or legal advice. This skill produces empty templates only - it never holds or
processes real employee, customer, supplier or vendor data.

## How It Works

Follow the shared execution contract. The module-specific rules below define only domain fields, decisions, calculations, and safety constraints.

### Step 1 - Identify intent

Read the request and pick the intent before asking anything.

- "set up" or "build" or "create" -> the user wants artifacts; go to Step 2.
- "compare" or "which one should we pick" -> the user wants an evaluation; capture the shortlist, then Step 2.
- "our process is ..." or "it is in a sheet" -> the user wants to move an existing evaluation; capture it, then Step 2.
- "is this right" or "review" or "audit" -> the user wants a check, not a build; answer from what they share.
- "report" or "how do I ..." -> advice question; answer directly and offer the build only if it helps.

Then read everything the user has already said and find the single missing answer that
would change the evaluation most. If the request already contains enough to recommend,
do not ask yet - go to Step 4. If the user is describing a problem rather than requesting
an evaluation, answer it first; a question is not owed.

One message, one short question, no batching. Open with:

> **Q:** Which accounting or ERP packages are currently on your shortlist?

Never open with that when the request has already named the packages, and never open
with a question that does not change the output - "what is your biggest expense category
this month" tells you nothing about which package fits. If there is no shortlist, do not
force one: collect the business requirements first and build the candidate shortlist from
them in S
