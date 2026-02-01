---
name: startup-financial-modeling
description: This skill should be used when the user asks to "create financial projections", "build a financial model", "forecast revenue", "calculate burn rate", "estimate runway", "model cash flow", or requests 
category: Creative & Media
source: antigravity
tags: [api, ai, workflow, template, design, presentation, rag, cro, marketing]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/startup-financial-modeling
---


# Startup Financial Modeling

Build comprehensive 3-5 year financial models with revenue projections, cost structures, cash flow analysis, and scenario planning for early-stage startups.

## Use this skill when

- Working on startup financial modeling tasks or workflows
- Needing guidance, best practices, or checklists for startup financial modeling

## Do not use this skill when

- The task is unrelated to startup financial modeling
- You need a different domain or tool outside this scope

## Instructions

- Clarify goals, constraints, and required inputs.
- Apply relevant best practices and validate outcomes.
- Provide actionable steps and verification.
- If detailed examples are required, open `resources/implementation-playbook.md`.

## Overview

Financial modeling provides the quantitative foundation for startup strategy, fundraising, and operational planning. Create realistic projections using cohort-based revenue modeling, detailed cost structures, and scenario analysis to support decision-making and investor presentations.

## Core Components

### Revenue Model

**Cohort-Based Projections:**
Build revenue from customer acquisition and retention by cohort.

**Formula:**
```
MRR = Σ (Cohort Size × Retention Rate × ARPU)
ARR = MRR × 12
```

**Key Inputs:**
- Monthly new customer acquisitions
- Customer retention rates by month
- Average revenue per user (ARPU)
- Pricing and packaging assumptions
- Expansion revenue (upsells, cross-sells)

### Cost Structure

**Operating Expenses Categories:**

1. **Cost of Goods Sold (COGS)**
   - Hosting and infrastructure
   - Payment processing fees
   - Customer support (variable portion)
   - Third-party services per customer

2. **Sales & Marketing (S&M)**
   - Customer acquisition cost (CAC)
   - Marketing programs and advertising
   - Sales team compensation
   - Marketing tools and software

3. **Research & Development (R&D)**
   - Engineering team compensation
   - Product management
   - Design and UX
   - Development tools and infrastructure

4. **General & Administrative (G&A)**
   - Executive team
   - Finance, legal, HR
   - Office and facilities
   - Insurance and compliance

### Cash Flow Analysis

**Components:**
- Beginning cash balance
- Cash inflows (revenue, fundraising)
- Cash outflows (operating expenses, CapEx)
- Ending cash balance
- Monthly burn rate
- Runway (months of cash remaining)

**Formula:**
```
Runway = Current Cash Balance / Monthly Burn Rate
Monthly Burn = Monthly Revenue - Monthly Expenses
```

### Headcount Planning

**Role-Based Hiring Plan:**
Track headcount by department and role.

**Key Metrics:**
- Fully-loaded cost per employee
- Revenue per employee
- Headcount by department (% of total)

**Typical Ratios (Early-Stage SaaS):**
- Engineering: 40-50%
- Sales & Marketing: 25-35%
- G&A: 10-15%
- Customer Success: 5-10%

## Financial Model Structure

### Three-Scenario Framework

**Conservative Scenario (P10):**
- Slower customer acquisition
- Lower pricing or conversion
- Higher churn rates
- Extended sales cycles
- Used for cash management

**Base Scenario (P50):**
- Most likely outcomes
- Realistic assumptions
- Primary planning scenario
- Used for board reporting

**Optimistic Scenario (P90):**
- Faster growth
- Better unit economics
- Lower churn
- Used for upside planning

### Time Horizon

**Detailed Projections: 3 Years**
- Monthly detail for Year 1
- Monthly detail for Year 2
- Quarterly detail for Year 3

**High-Level Projections: Years 4-5**
- Annual projections
- Key metrics only
- Support long-term planning

## Step-by-Step Process

### Step 1: Define Business Model

Clarify revenue model and pricing.

**SaaS Model:**
- Subscription pricing tiers
- Annual vs. monthly contracts
- Free trial or freemium approach
- Expansion revenue strategy

**Marketplace Model:**
- GMV projections
- Take rate (% of transactions)
- Buyer and seller economics
- Transaction frequency

**Transactional Model:**
- Transaction volume
- Revenue per transaction
- Frequency and seasonality

### Step 2: Build Revenue Projections

Use cohort-based methodology for accuracy.

**Monthly Customer Acquisition:**
Define new customers acquired each month.

**Retention Curve:**
Model customer retention over time.

**Typical SaaS Retention:**
- Month 1: 100%
- Month 3: 90%
- Month 6: 85%
- Month 12: 75%
- Month 24: 70%

**Revenue Calculation:**
For each cohort, calculate retained customers × ARPU for each month.

### Step 3: Model Cost Structure

Break down costs by category and behavior.

**Fixed vs. Variable:**
- Fixed: Salaries, software, rent
- Variable: Hosting, payment processing, support

**Scaling Assumptions:**
- COGS as % of revenue
- S&M as % of revenue (CAC payback)
- R&D growth rate
- G&A as % of total expenses

### Step 4: Create Hiring Plan

Model headcount growth by role and department.

**Inputs:**
- Starting headcount
- Hiring velocity by role
- Fully-loaded compensation by role
- Benefits and taxes (typically 1.3-1.4x salary)

**Examp
