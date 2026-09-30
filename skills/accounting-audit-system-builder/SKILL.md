---
name: accounting-audit-system-builder
description: Routes an accounting or audit request to the right module skill, from software selection through monthly closing, asking only what is missing. Use for books of accounts or audit files. 
category: Document Processing
source: antigravity
tags: [api, ai, agent, workflow, template, design, document, spreadsheet, presentation, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/accounting-audit-system-builder
---


# Accounting & Audit System Builder

Router for 16 accounting and audit skills, one per stage of the accounting cycle. It
works out where in the cycle the user actually is, then hands off to that one module
skill. It never builds anything itself.

## Overview

A business does not need 100 databases. It needs the two or three it will keep current
for the stage it is at. This skill identifies the stage, asks only what is still missing
one question at a time, stops as soon as the remaining answers stop changing the route,
then recommends two or three modules and waits for the user to pick.

The cycle it routes along:

```
Software selected
  -> Source document filed
    -> Transaction recorded (purchase | sales)
      -> Cash or bank movement recorded (receipt | payment)
        -> Cash counted and day book closed
          -> Ledgers, stock and statutory balances reconciled
            -> Month closed and statements produced
              -> Credit cycle analysed
                -> Audit file assembled
```

Each module skill runs the same contract: context first, a recommendation, and artifacts
only on request. This skill never emits a schema, a CSV or a Notion template.

## When to Use This Skill

- "Set up our accounting system"
- "We need books of accounts for the business"
- "Help us prepare for the auditor"
- "Our accountant asks for things every month and we assemble them manually"
- "Turn our tally process into a proper system"

Do not use it when the user has already named one specific book or report and just wants
the file - go straight to that module skill.

## How It Works

Follow the shared execution contract. The module-specific rules below define only domain fields, decisions, calculations, and safety constraints.

### Step 1 - Identify the stage, not the tool

Read the request and place it on the cycle before asking anything. The stage is the
route.

- "which software", "new system", "migrate" -> Software Selection
- "where do we file invoices", "track documents" -> Source Document & Filing
- "purchases", "supplier bills" -> Purchase Accounting
- "sales", "invoices we raise", "receivables" -> Sales Accounting
- "money received", "collections" -> Receipt Accounting
- "money paid out", "vendor payments" -> Payment Accounting
- "petty cash", "small cash" -> Petty Cash Management
- "daily cash and bank", "day book" -> Day Book
- "party balances differ", "debtor statement mismatch" -> Party / Ledger Reconciliation
- "expenses", "bills without invoices" -> Expense Accounting
- "salary", "wages", "payroll entries" -> Salary & Wage Accounting
- "TDS", "withholding" -> TDS Booking & Payment
- "stock count", "shortage", "inventory match" -> Inventory / Stock Reconciliation
- "month end", "trial balance", "financial statements" -> Monthly Closing & Statements
- "collection period", "who owes us longest" -> Credit-Cycle Analysis
- "audit file", "auditor checklist", "year-end papers" -> Audit Preparation

"how do I ..." is an advice question. Answer it, and offer the build only if it helps.

Ask only if this is the highest-value missing fact; otherwise proceed without an opener:

> **Q:** Where in the accounting cycle is the business right now?

If the user requests an artifact, route to the matching module and continue the build.
A routing step does not require separate permission. Never label a failed check `Done`.

### Step 2 - Ask only what is missing

Skip anything the user already answered, in any earlier message. Ask the rest one at a
time, and stop as soon as the remaining answers would not change the output. Never
invent an answer - if the user does not know, record it as unknown and carry on.

- **Business** - What does the business do? / Trading, service or both? / Approximate
  monthly transaction count?
- **Systems** - Which accounting software today? / Is anything in a spreadsheet? /
  Who does the entries - internal or an accountant?
- **Compliance** - Which taxes are registered? / VAT or GST? / TDS, payroll and
  statutory obligations?
- **Position** - Is anything outstanding or unreconciled? / Any known differences?
- **Outcome** - What do you need? / Ongoing books, a month-end pack or an audit file?

### Step 3 - Recommend the smallest workflow

Match on what the user named, not on what the tier allows. Present two or three modules,
one line of reason each, and ask which to start. A list of 100 is not a recommendation.
Full index: `catalog.md`.

**Starter** - 7 modules, the usual starting set: Sales Accounting, Purchase Accounting,
Receipt Accounting, Payment Accounting, Petty Cash Management, Day Book, Expense
Accounting. Add TDS Booking & Payment once the business is registered and deducting.

**Growth** - Starter plus Accounting Software Selection, Source Document & Filing, Party /
Ledger Reconciliation, Inventory / Stock Reconciliation, Salary & Wage Accounting and
Monthly Closing & Statements.

**Scale** - select additional modules from this 16-module accounting pack only as needed.
