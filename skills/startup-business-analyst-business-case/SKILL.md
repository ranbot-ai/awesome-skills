---
name: startup-business-analyst-business-case
description: Generate comprehensive investor-ready business case document with market, solution, financials, and strategy 
category: Document Processing
source: antigravity
tags: [pdf, markdown, api, claude, ai, workflow, template, document, presentation, marketing]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/startup-business-analyst-business-case
---


# Business Case Generator

Generate a comprehensive, investor-ready business case document covering market opportunity, solution, competitive landscape, financial projections, team, risks, and funding ask for startup fundraising and strategic planning.

## Use this skill when

- Working on business case generator tasks or workflows
- Needing guidance, best practices, or checklists for business case generator

## Do not use this skill when

- The task is unrelated to business case generator
- You need a different domain or tool outside this scope

## Instructions

- Clarify goals, constraints, and required inputs.
- Apply relevant best practices and validate outcomes.
- Provide actionable steps and verification.
- If detailed examples are required, open `resources/implementation-playbook.md`.

## What This Command Does

Create a complete business case including:
1. Executive summary
2. Problem and market opportunity
3. Solution and product
4. Competitive analysis and differentiation
5. Financial projections
6. Go-to-market strategy
7. Team and organization
8. Risks and mitigation
9. Funding ask and use of proceeds

## Instructions for Claude

When this command is invoked, follow these steps:

### Step 1: Gather Context

Ask the user for key information:

**Company Basics:**
- Company name and elevator pitch
- Stage (pre-seed, seed, Series A)
- Problem being solved
- Target customers

**Audience:**
- Who will read this? (VCs, angels, strategic partners)
- What's the primary goal? (fundraising, partnership, internal planning)

**Available Materials:**
- Existing pitch deck or docs?
- Market sizing data?
- Financial model?
- Competitive analysis?

### Step 2: Activate Relevant Skills

Reference skills for comprehensive analysis:
- **market-sizing-analysis** - TAM/SAM/SOM calculations
- **startup-financial-modeling** - Financial projections
- **competitive-landscape** - Competitive analysis frameworks
- **team-composition-analysis** - Organization planning
- **startup-metrics-framework** - Key metrics and benchmarks

### Step 3: Structure the Business Case

Create a comprehensive document with these sections:

---

## Business Case Document Structure

### Section 1: Executive Summary (1-2 pages)

**Company Overview:**
- One-sentence description
- Founded, location, stage
- Team highlights

**Problem Statement:**
- Core problem being solved (2-3 sentences)
- Market pain quantified

**Solution:**
- How the product solves it (2-3 sentences)
- Key differentiation

**Market Opportunity:**
- TAM: $X.XB
- SAM: $X.XM
- SOM (Year 5): $X.XM

**Traction:**
- Current metrics (MRR, customers, growth rate)
- Key milestones achieved

**Financial Snapshot:**
```
| Metric | Current | Year 1 | Year 2 | Year 3 |
|--------|---------|--------|--------|--------|
| ARR | $X | $Y | $Z | $W |
| Customers | X | Y | Z | W |
| Team Size | X | Y | Z | W |
```

**Funding Ask:**
- Amount seeking
- Use of proceeds (top 3-4)
- Expected milestones

### Section 2: Problem & Market Opportunity (2-3 pages)

**The Problem:**
- Detailed problem description
- Who experiences this problem
- Current solutions and their limitations
- Cost of the problem (quantified)

**Market Landscape:**
- Industry overview
- Key trends driving opportunity
- Market growth rate and drivers

**Market Sizing:**
- TAM calculation and methodology
- SAM with filters applied
- SOM with assumptions
- Validation and data sources
- Comparison to public companies

**Target Customer Profile:**
- Primary segments
- Customer characteristics
- Decision-makers and buying process

### Section 3: Solution & Product (2-3 pages)

**Product Overview:**
- What it does (features and capabilities)
- How it works (architecture/approach)
- Key differentiators
- Technology advantages

**Value Proposition:**
- Benefits by customer segment
- ROI or value delivered
- Time to value

**Product Roadmap:**
- Current state
- Near-term (6 months)
- Medium-term (12-18 months)
- Vision (2-3 years)

**Intellectual Property:**
- Patents (filed, pending)
- Proprietary technology
- Data advantages
- Defensibility

### Section 4: Competitive Analysis (2 pages)

**Competitive Landscape:**
- Direct competitors
- Indirect competitors (alternatives)
- Adjacent players (potential entrants)

**Competitive Matrix:**
```
| Feature/Factor | Us | Comp A | Comp B | Comp C |
|----------------|----|---------| -------|--------|
| Feature 1 | ✓ | ✓ | ✗ | ✓ |
| Feature 2 | ✓ | ✗ | ✓ | ✗ |
| Pricing | $X | $Y | $Z | $W |
```

**Differentiation:**
- 3-5 key differentiators
- Why these matter to customers
- Defensibility of advantages

**Competitive Positioning:**
- Positioning map (2-3 dimensions)
- Market positioning statement

**Barriers to Entry:**
- What protects against competition
- Network effects, switching costs, etc.

### Section 5: Business Model & Go-to-Market (2 pages)

**Business Model:**
- Revenue model (subscriptions, transactions, etc.)
- Pricing strategy and tiers
- Customer acquisition approach
- Expansion rev
