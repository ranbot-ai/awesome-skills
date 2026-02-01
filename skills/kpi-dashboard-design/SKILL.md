---
name: kpi-dashboard-design
description: Design effective KPI dashboards with metrics selection, visualization best practices, and real-time monitoring patterns. Use when building business dashboards, selecting metrics, or designing data vis
category: Document Processing
source: antigravity
tags: [python, pdf, api, ai, template, design, document, rag, cro, marketing]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/kpi-dashboard-design
---


# KPI Dashboard Design

Comprehensive patterns for designing effective Key Performance Indicator (KPI) dashboards that drive business decisions.

## Do not use this skill when

- The task is unrelated to kpi dashboard design
- You need a different domain or tool outside this scope

## Instructions

- Clarify goals, constraints, and required inputs.
- Apply relevant best practices and validate outcomes.
- Provide actionable steps and verification.
- If detailed examples are required, open `resources/implementation-playbook.md`.

## Use this skill when

- Designing executive dashboards
- Selecting meaningful KPIs
- Building real-time monitoring displays
- Creating department-specific metrics views
- Improving existing dashboard layouts
- Establishing metric governance

## Core Concepts

### 1. KPI Framework

| Level           | Focus            | Update Frequency  | Audience   |
| --------------- | ---------------- | ----------------- | ---------- |
| **Strategic**   | Long-term goals  | Monthly/Quarterly | Executives |
| **Tactical**    | Department goals | Weekly/Monthly    | Managers   |
| **Operational** | Day-to-day       | Real-time/Daily   | Teams      |

### 2. SMART KPIs

```
Specific: Clear definition
Measurable: Quantifiable
Achievable: Realistic targets
Relevant: Aligned to goals
Time-bound: Defined period
```

### 3. Dashboard Hierarchy

```
├── Executive Summary (1 page)
│   ├── 4-6 headline KPIs
│   ├── Trend indicators
│   └── Key alerts
├── Department Views
│   ├── Sales Dashboard
│   ├── Marketing Dashboard
│   ├── Operations Dashboard
│   └── Finance Dashboard
└── Detailed Drilldowns
    ├── Individual metrics
    └── Root cause analysis
```

## Common KPIs by Department

### Sales KPIs

```yaml
Revenue Metrics:
  - Monthly Recurring Revenue (MRR)
  - Annual Recurring Revenue (ARR)
  - Average Revenue Per User (ARPU)
  - Revenue Growth Rate

Pipeline Metrics:
  - Sales Pipeline Value
  - Win Rate
  - Average Deal Size
  - Sales Cycle Length

Activity Metrics:
  - Calls/Emails per Rep
  - Demos Scheduled
  - Proposals Sent
  - Close Rate
```

### Marketing KPIs

```yaml
Acquisition:
  - Cost Per Acquisition (CPA)
  - Customer Acquisition Cost (CAC)
  - Lead Volume
  - Marketing Qualified Leads (MQL)

Engagement:
  - Website Traffic
  - Conversion Rate
  - Email Open/Click Rate
  - Social Engagement

ROI:
  - Marketing ROI
  - Campaign Performance
  - Channel Attribution
  - CAC Payback Period
```

### Product KPIs

```yaml
Usage:
  - Daily/Monthly Active Users (DAU/MAU)
  - Session Duration
  - Feature Adoption Rate
  - Stickiness (DAU/MAU)

Quality:
  - Net Promoter Score (NPS)
  - Customer Satisfaction (CSAT)
  - Bug/Issue Count
  - Time to Resolution

Growth:
  - User Growth Rate
  - Activation Rate
  - Retention Rate
  - Churn Rate
```

### Finance KPIs

```yaml
Profitability:
  - Gross Margin
  - Net Profit Margin
  - EBITDA
  - Operating Margin

Liquidity:
  - Current Ratio
  - Quick Ratio
  - Cash Flow
  - Working Capital

Efficiency:
  - Revenue per Employee
  - Operating Expense Ratio
  - Days Sales Outstanding
  - Inventory Turnover
```

## Dashboard Layout Patterns

### Pattern 1: Executive Summary

```
┌─────────────────────────────────────────────────────────────┐
│  EXECUTIVE DASHBOARD                        [Date Range ▼]  │
├─────────────┬─────────────┬─────────────┬─────────────────┤
│   REVENUE   │   PROFIT    │  CUSTOMERS  │    NPS SCORE    │
│   $2.4M     │    $450K    │    12,450   │       72        │
│   ▲ 12%     │    ▲ 8%     │    ▲ 15%    │     ▲ 5pts     │
├─────────────┴─────────────┴─────────────┴─────────────────┤
│                                                             │
│  Revenue Trend                    │  Revenue by Product     │
│  ┌───────────────────────┐       │  ┌──────────────────┐   │
│  │    /\    /\          │       │  │ ████████ 45%     │   │
│  │   /  \  /  \    /\   │       │  │ ██████   32%     │   │
│  │  /    \/    \  /  \  │       │  │ ████     18%     │   │
│  │ /            \/    \ │       │  │ ██        5%     │   │
│  └───────────────────────┘       │  └──────────────────┘   │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│  🔴 Alert: Churn rate exceeded threshold (>5%)              │
│  🟡 Warning: Support ticket volume 20% above average        │
└─────────────────────────────────────────────────────────────┘
```

### Pattern 2: SaaS Metrics Dashboard

```
┌─────────────────────────────────────────────────────────────┐
│  SAAS METRICS                     Jan 2024  [Monthly ▼]     │
├──────────────────────┬──────────────────────────────────────┤
│  ┌────────────────┐  │  MRR GROWTH                          │
│  │      MRR       │  │  ┌────────────────────────────────┐  │
│  │    $125,000    │  │  │                          /──   │  │
│  │     ▲ 8%       │  │  │                    /────/      │  │
│  └────────────────┘  │  │              /────/         
