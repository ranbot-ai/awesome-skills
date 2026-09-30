---
name: credit-cycle-analysis
description: Debtor and creditor credit-cycle analysis: weighted collection or payment days, ageing buckets, credit limit utilisation and gap against benchmark. Use for working-capital review. 
category: Document Processing
source: antigravity
tags: [api, ai, automation, workflow, template, design, document, spreadsheet, security, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/credit-cycle-analysis
---


# Debtor & Creditor Credit-Cycle Analysis

**What it is:** How long the business actually waits to be paid and how long it actually takes to pay, measured per party and per period.

## Overview

Works out the smallest useful **Debtor & Creditor Credit-Cycle Analysis** setup for the business in
front of it, then builds it only when asked. The default output is a short recommendation, not a
spreadsheet. Artifacts - CSV, SQL DDL, JSON Schema, Notion mapping - are produced on request, from
one field list so they cannot drift apart.

Layer: Layer 8: Close & Analyse. Fits: Growth stage. Table code: n/a.

**The SOP rule this skill is built around:** analyse debtors on the average collection period,
outstanding invoices, overdue receivables and the aging of receivables; analyse creditors on the
average payment period, outstanding supplier balances, overdue payables and supplier aging; then
compare the debtor collection cycle with the creditor payment cycle. The comparison is the point.
Two cycles measured the same way can be read against each other, and the day-to-day pressure of
waiting longer than you take is invisible as a line on the balance sheet. That pressure is
measured in **days** here. Turning it into money is a separate calculation with its own basis,
below.

**Six concepts that never stand in for each other.** This table exists to keep them apart, and
most of the wrong answers come from swapping one for another:

| Concept | What it answers | Field that carries it |
|---|---|---|
| Contractual terms | What was agreed | `Contractual Terms Days` |
| Actual cycle | What actually happened | `Actual Collection/Payment Days`, `Weighted Days` |
| Benchmark | What to compare against | `Benchmark Days`, `Gap vs Benchmark` |
| Aging | How old the unpaid items are | bucket amounts, and `Aging Bucket` on the invoice/bill detail |
| Debtor-vs-creditor timing | Which side of the cycle is longer | `Cycle Gap Days` on the comparison record |
| Working-capital funding | What the timing difference costs in money | `Estimated Working-Capital Funding`, `Calculation Basis` |

Conflating them is the defect this module is built to prevent. Contractual terms of 30 days and
an actual collection cycle of 42 days are two facts about the same party, and the 42 is the one
that reaches the bank account. Writing the 30 into `Actual Collection/Payment Days` because it is
the number in the contract is a substituted value, not a measurement.

**Aging lives on the invoice, not on the party.** One party can hold open invoices in several
aging buckets on the same day. So the party-period record carries the bucket **amounts**
(`Current Amount`, `Aging 0-30 Amount`, `Aging 31-60 Amount`, `Aging 61-90 Amount`, `Aging 91-180 Amount`, `Aging Over 180 Amount`)
and the single `Aging Bucket` belongs to one invoice or one bill on the aging-detail record. A
party row carrying one `Aging Bucket` cannot describe a real aging position and is replaced by
the bucket amounts.

**Neutral field names.** The two movement fields are `Credit Movement` and `Settlement`, for
customers and for suppliers alike. `Credit Movement` is the credit-side activity that created the
balance in the period - customer invoices on the debtor side, supplier bills on the creditor
side. `Settlement` is what closed it - customer collections, supplier payments. A name like
`Total Billed` describes only the debtor side and quietly makes the creditor side unreadable.

**The balance identity, and what happens when it fails.**

```
Closing Balance = Opening Balance + Credit Movement - Settlement +/- Adjustments
```

Check it on every row. If it does not hold, the difference is **recorded and marked**, never
repaired by editing a component. A silently balanced row is worse than an unbalanced one,
because the next period inherits it.

**The cycle gap is descriptive, not a verdict.**

```
Cycle Gap Days = Debtor Collection Days - Creditor Payment Days
```

Positive means customers take longer to pay than the business takes to pay suppliers. Zero means
the two measured cycles are equal. Negative means suppliers are paid later than customers are
collected. A positive gap is not automatically bad - it is often the ordinary consequence of
selling on credit to a customer base and buying on shorter terms. The module states the
difference and leaves the judgement to the business.

**Working-capital funding needs a monetary basis, and the basis is always written down.**

```
Estimated Working-Capital Funding = Cycle Gap Days x Relevant Daily Credit Movement
```

This is only computed when the relevant monetary basis exists, and `Calculation Basis` always
records how that basis was built. A plausible daily figure is:

```
Relevant Daily Credit Movement = Relevant annual credit movement / 365
```

and it is only used when the selected annual movement is appropriate for the analysis. Where the
monetary basis is missing, `Estimated Working-Capital Funding` is `Unknown` and the record says so.
Never i
