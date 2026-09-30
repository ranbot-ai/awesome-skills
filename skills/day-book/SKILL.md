---
name: day-book
description: Daily cash, bank and digital day book: opening and closing balances per book, in/out movements, debit/credit presentation and reconciliation status. Use for daily bookkeeping. 
category: Document Processing
source: antigravity
tags: [xlsx, markdown, ai, automation, workflow, template, design, document, spreadsheet, presentation]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/day-book
---


# Day Book

**What it is:** The daily cash, bank and digital receipt-and-payment record, with a day-end control row that reconciles the day before it is closed.

## Overview

Works out the smallest useful **Day Book** setup for the business in front of it, then builds it
only when asked. The default output is a short recommendation, not a spreadsheet. Artifacts - CSV,
SQL DDL, JSON Schema, Notion mapping - are produced on request, from one field list so they
cannot drift apart.

Layer: Layer 4: Cash. Fits: Starter stage. Table code: n/a.

**Before anything is generated, the design is checked against itself.** A day book is the easiest
table in the pack to write badly, because the same column can mean two different things on two
different rows and neither reading looks wrong on its own. So before emitting any artifact:

- Look for conflicts in the rules, the examples, the field definitions, the row meanings and the
  output formats. Where the design, the examples or the business's existing sheet disagree with
  each other, do not reproduce them as they stand.
- Name the conflict out loud, then resolve it with the simplest accounting-safe interpretation.
  The simplest safe reading of a disputed field is the one that keeps cash equal to the bank
  position and never invents a movement to make a total look right.
- Derive CSV, SQL DDL, JSON Schema and the Notion mapping from **one** field model afterwards, so
  that no field exists in one artifact and is missing or differently defined in another.

**The rule this table exists to enforce: the debit/credit presentation of a day book depends on
the software's day-book format.** It is not a universal rule that all receipts are debit and all
payments are credit - some books present receipts on the payment side, some carry both columns,
some carry neither. So this table does not hardcode a Debit/Credit pair. `Debit/Credit
Presentation` is a text field that records the presentation **as configured in the business's own
software**, and the six in/out amount columns plus the six balance columns are the part that is
universal. Where a book labels its columns `Dr` and `Cr`, that label is what goes into
`Debit/Credit Presentation`; nothing in this table decides which side a receipt sits on.

**Two row types, and they are not the same kind of thing.** `Row Type` says which one a row is, and
the two are read differently.

| | `Movement` row | `Day Summary` row |
|---|---|---|
| What it is | one receipt or one payment | one per day, written after the day is closed |
| What it books | money, into exactly one book | no money at all - it totals and proves |
| `Book Section` | the one book it was booked to | `All Books` |
| `Mode` | the instrument used | `Mixed` when the day's instruments differ |
| The six In/Out columns | the amount in its own book, and the other two are not applicable | the day's totals for all three books |
| The six balance columns | brought forward, and the running balance **after** this entry | the day's opening and closing balances |
| `Transaction Reference`, `Voucher Number`, `Party` | the entry itself | the day's detail set, not a single voucher |
| `Duplicate Check` | this entry checked against the day's other entries | the whole day's set checked |
| `Balance Difference`, `Reconciliation Status` | not applicable - a single movement is not reconciled on its own | the day's break, and the status of it |

**What each balance field means.** Every one of the six balance fields is a balance, never a
movement. `Opening Cash Balance`, `Opening Bank Balance` and `Opening Digital Balance` are what
was brought into the day. `Cash Closing Balance`, `Bank Closing Balance` and `Digital Closing
Balance` are what was left at the end of it. The identity that connects them, per book, is:

```
opening balance + money in - money out = closing balance
```

On a `Day Summary` row that identity must hold separately for cash, for bank and for digital. On
a `Movement` row, the opening balance is what was brought forward into that entry and the closing
balance is the running balance **after** it, in that entry's own book only.

**The identity that carries the day forward.** A day's opening balance is not a fresh number. It
is the **previous day's closing balance** for the same book. So the check that closes a day is:

```
previous day's closing balance + today's movement = today's closing balance
```

Where it does not hold, the difference goes in `Balance Difference` - signed, and not spread
across the books - and `Reconciliation Status` is set to `Needs Review` or `Unreconciled`. The
component is never edited to make the row tie. A day book whose balances are adjusted until they
agree records nothing about the business.

**`Balance Difference` and `Reconciliation Status`.** `Balance Difference` is the total
unexplained difference across the three books on that row: negative where the book is above the
counted or agreed figure, positive where it is below. Where a differenc
