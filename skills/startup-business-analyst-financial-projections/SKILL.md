---
name: startup-business-analyst-financial-projections
description: Create detailed 3-5 year financial model with revenue, costs, cash flow, and scenarios 
category: Document Processing
source: antigravity
tags: [markdown, claude, ai, workflow, template, design, document, rag, cro, marketing]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/startup-business-analyst-financial-projections
---


# Financial Projections

Create a comprehensive 3-5 year financial model with revenue projections, cost structure, headcount planning, cash flow analysis, and three-scenario modeling (conservative, base, optimistic) for startup financial planning and fundraising.

## Use this skill when

- Working on financial projections tasks or workflows
- Needing guidance, best practices, or checklists for financial projections

## Do not use this skill when

- The task is unrelated to financial projections
- You need a different domain or tool outside this scope

## Instructions

- Clarify goals, constraints, and required inputs.
- Apply relevant best practices and validate outcomes.
- Provide actionable steps and verification.
- If detailed examples are required, open `resources/implementation-playbook.md`.

## What This Command Does

This command builds a complete financial model including:
1. Cohort-based revenue projections
2. Detailed cost structure (COGS, S&M, R&D, G&A)
3. Headcount planning by role
4. Monthly cash flow analysis
5. Key metrics (CAC, LTV, burn rate, runway)
6. Three-scenario analysis

## Instructions for Claude

When this command is invoked, follow these steps:

### Step 1: Gather Model Inputs

Ask the user for essential information:

**Business Model:**
- Revenue model (SaaS, marketplace, transaction, etc.)
- Pricing structure (tiers, average price)
- Target customer segments

**Starting Point:**
- Current MRR/ARR (if any)
- Current customer count
- Current team size
- Current cash balance

**Growth Assumptions:**
- Expected monthly customer acquisition
- Customer retention/churn rate
- Average contract value (ACV)
- Sales cycle length

**Cost Assumptions:**
- Gross margin or COGS %
- S&M budget or CAC target
- Current burn rate (if applicable)

**Funding:**
- Planned fundraising (amount, timing)
- Pre/post-money valuation

### Step 2: Activate startup-financial-modeling Skill

The startup-financial-modeling skill provides frameworks. Reference it for:
- Revenue modeling approaches
- Cost structure templates
- Headcount planning guidance
- Scenario analysis methods

### Step 3: Build Revenue Model

**Use Cohort-Based Approach:**

For each month, track:
1. New customers acquired
2. Existing customers retained (apply churn)
3. Revenue per cohort (customers × ARPU)
4. Expansion revenue (upsells)

**Formula:**
```
MRR (Month N) = Σ across all cohorts:
  (Cohort Size × Retention Rate × ARPU) + Expansion
```

**Project:**
- Monthly detail for Year 1-2
- Quarterly detail for Year 3
- Annual for Years 4-5

### Step 4: Model Cost Structure

Break down operating expenses:

**1. Cost of Goods Sold (COGS)**
- Hosting/infrastructure (% of revenue or fixed)
- Payment processing (% of revenue)
- Variable customer support
- Third-party services

Target gross margin:
- SaaS: 75-85%
- Marketplace: 60-70%
- E-commerce: 40-60%

**2. Sales & Marketing (S&M)**
- Sales team compensation
- Marketing programs
- Tools and software
- Target: 40-60% of revenue (early stage)

**3. Research & Development (R&D)**
- Engineering team
- Product management
- Design
- Target: 30-40% of revenue

**4. General & Administrative (G&A)**
- Executive team
- Finance, legal, HR
- Office and facilities
- Target: 15-25% of revenue

### Step 5: Plan Headcount

Create role-by-role hiring plan:

**Reference team-composition-analysis skill for:**
- Roles by stage
- Compensation benchmarks
- Hiring velocity assumptions

**For each role:**
- Title and department
- Start date (month/quarter)
- Base salary
- Fully-loaded cost (salary × 1.3-1.4)
- Equity grant

**Track departmental ratios:**
- Engineering: 40-50% of team
- Sales & Marketing: 25-35%
- G&A: 10-15%
- Product/CS: 10-15%

### Step 6: Calculate Cash Flow

Monthly cash flow projection:

```
Beginning Cash Balance
+ Cash Collected (revenue, consider payment terms)
- Operating Expenses
- CapEx
= Ending Cash Balance

Monthly Burn = Revenue - Expenses (if negative)
Runway = Cash Balance / Monthly Burn Rate
```

**Include Funding Events:**
- Timing of raises
- Amount raised
- Use of proceeds
- Impact on cash balance

### Step 7: Compute Key Metrics

Calculate monthly/quarterly:

**Unit Economics:**
- CAC (S&M spend / new customers)
- LTV (ARPU × margin% / churn rate)
- LTV:CAC ratio (target > 3.0)
- CAC payback period (target < 18 months)

**Efficiency Metrics:**
- Burn multiple (net burn / net new ARR) - target < 2.0
- Magic number (net new ARR / S&M spend) - target > 0.5
- Rule of 40 (growth% + margin%) - target > 40%

**Cash Metrics:**
- Monthly burn rate
- Runway in months
- Cash efficiency

### Step 8: Create Three Scenarios

Build conservative, base, and optimistic projections:

**Conservative (P10):**
- New customers: -30% vs. base
- Churn: +20% vs. base
- Pricing: -15% vs. base
- CAC: +25% vs. base

**Base (P50):**
- Most likely assumptions
- Primary planning scenario

**Optimistic (P90):**
- New customers: +30% vs. base
- Churn: -20% vs. base
- Pricing: +15% vs. base
- CAC: -25% vs. bas
