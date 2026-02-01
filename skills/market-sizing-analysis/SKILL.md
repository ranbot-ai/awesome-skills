---
name: market-sizing-analysis
description: This skill should be used when the user asks to "calculate TAM", "determine SAM", "estimate SOM", "size the market", "calculate market opportunity", "what's the total addressable market", or requests 
category: Security & Systems
source: antigravity
tags: [ai, automation, workflow, template, document, rag, cro, marketing]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/market-sizing-analysis
---


# Market Sizing Analysis

Comprehensive market sizing methodologies for calculating Total Addressable Market (TAM), Serviceable Available Market (SAM), and Serviceable Obtainable Market (SOM) for startup opportunities.

## Use this skill when

- Working on market sizing analysis tasks or workflows
- Needing guidance, best practices, or checklists for market sizing analysis

## Do not use this skill when

- The task is unrelated to market sizing analysis
- You need a different domain or tool outside this scope

## Instructions

- Clarify goals, constraints, and required inputs.
- Apply relevant best practices and validate outcomes.
- Provide actionable steps and verification.
- If detailed examples are required, open `resources/implementation-playbook.md`.

## Overview

Market sizing provides the foundation for startup strategy, fundraising, and business planning. Calculate market opportunity using three complementary methodologies: top-down (industry reports), bottom-up (customer segment calculations), and value theory (willingness to pay).

## Core Concepts

### The Three-Tier Market Framework

**TAM (Total Addressable Market)**
- Total revenue opportunity if achieving 100% market share
- Defines the universe of potential customers
- Used for long-term vision and market validation
- Example: All email marketing software revenue globally

**SAM (Serviceable Available Market)**
- Portion of TAM targetable with current product/service
- Accounts for geographic, segment, or capability constraints
- Represents realistic addressable opportunity
- Example: AI-powered email marketing for e-commerce in North America

**SOM (Serviceable Obtainable Market)**
- Realistic market share achievable in 3-5 years
- Accounts for competition, resources, and market dynamics
- Used for financial projections and fundraising
- Example: 2-5% of SAM based on competitive landscape

### When to Use Each Methodology

**Top-Down Analysis**
- Use when established market research exists
- Best for mature, well-defined markets
- Validates market existence and growth
- Starts with industry reports and narrows down

**Bottom-Up Analysis**
- Use when targeting specific customer segments
- Best for new or niche markets
- Most credible for investors
- Builds from customer data and pricing

**Value Theory**
- Use when creating new market categories
- Best for disruptive innovations
- Estimates based on value creation
- Calculates willingness to pay for problem solution

## Three-Methodology Framework

### Methodology 1: Top-Down Analysis

Start with total market size and narrow to addressable segments.

**Process:**
1. Identify total market category from research reports
2. Apply geographic filters (target regions)
3. Apply segment filters (target industries/customers)
4. Calculate competitive positioning adjustments

**Formula:**
```
TAM = Total Market Category Size
SAM = TAM × Geographic % × Segment %
SOM = SAM × Realistic Capture Rate (2-5%)
```

**When to use:** Established markets with available research (e.g., SaaS, fintech, e-commerce)

**Strengths:** Quick, uses credible data, validates market existence

**Limitations:** May overestimate for new categories, less granular

### Methodology 2: Bottom-Up Analysis

Build market size from customer segment calculations.

**Process:**
1. Define target customer segments
2. Estimate number of potential customers per segment
3. Determine average revenue per customer
4. Calculate realistic penetration rates

**Formula:**
```
TAM = Σ (Segment Size × Annual Revenue per Customer)
SAM = TAM × (Segments You Can Serve / Total Segments)
SOM = SAM × Realistic Penetration Rate (Year 3-5)
```

**When to use:** B2B, niche markets, specific customer segments

**Strengths:** Most credible for investors, granular, defensible

**Limitations:** Requires detailed customer research, time-intensive

### Methodology 3: Value Theory

Calculate based on value created and willingness to pay.

**Process:**
1. Identify problem being solved
2. Quantify current cost of problem (time, money, inefficiency)
3. Calculate value of solution (savings, gains, efficiency)
4. Estimate willingness to pay (typically 10-30% of value)
5. Multiply by addressable customer base

**Formula:**
```
Value per Customer = Problem Cost × % Solved by Solution
Price per Customer = Value × Willingness to Pay % (10-30%)
TAM = Total Potential Customers × Price per Customer
SAM = TAM × % Meeting Buy Criteria
SOM = SAM × Realistic Adoption Rate
```

**When to use:** New categories, disruptive innovations, unclear existing markets

**Strengths:** Shows value creation, works for new markets

**Limitations:** Requires assumptions, harder to validate

## Step-by-Step Process

### Step 1: Define the Market

Clearly specify what market is being measured.

**Questions to answer:**
- What problem is being solved?
- Who are the target customers?
- What's the product/service category?
- What's the geographic scope?
- What's the time horizon?

**Example:**
- Proble
