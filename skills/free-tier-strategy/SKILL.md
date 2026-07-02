---
name: free-tier-strategy
description: Design free tiers that convert to paid without creating resentment or abuse. Trigger phrases: free tier design, freemium model, free trial strategy, free tier limits, developer free plan, open source 
category: Document Processing
source: antigravity
tags: [api, ai, workflow, design, document, security, supabase, stripe, rag, marketing]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/free-tier-strategy
---


# Free Tier Strategy
## When to Use

Use this skill when you need design free tiers that convert to paid without creating resentment or abuse. Trigger phrases: free tier design, freemium model, free trial strategy, free tier limits, developer free plan, open source commercial, feature gating, upgrade triggers, free tier conversion.


Design free tiers that let developers build real things, demonstrate value, and convert naturally—without feeling like a trap or creating resentment.

## Overview

Developer tools need free tiers. Developers expect to try before they buy, and they expect the trial to be meaningful—not a 14-day timer or a feature-locked demo. But free tiers also need to sustain your business. Get this wrong in either direction: too restrictive kills adoption, too generous kills revenue.

The best free tiers feel generous to individual developers while naturally scaling into paid tiers as projects grow.

## Before You Start

Review the `/devmarketing-skills/skills/developer-audience-context` skill. Free tier design varies significantly based on whether you're targeting hobbyists, startups, or enterprises. Also understand your unit economics—what does each free user actually cost you?

## Free Tier vs Free Trial vs Freemium

### Definitions

**Free trial:** Time-limited full access (14 or 30 days)
- Best for: High-touch enterprise sales
- Worst for: Developer tools with self-serve motion

**Free tier:** Permanently free with usage/feature limits
- Best for: Developer tools with self-serve adoption
- Requires: Careful limit design

**Freemium:** Free tier plus premium features for payment
- Best for: Tools with clear hobby/pro distinction
- Requires: Obvious value in premium features

**Open core:** Free open source with commercial additions
- Best for: Infrastructure and platforms
- Requires: Active open source community

### Choosing Your Model

| Factor | Free Trial | Free Tier | Freemium | Open Core |
|--------|-----------|-----------|----------|-----------|
| Sales motion | High-touch | Self-serve | Self-serve | Mixed |
| Time to evaluate | Weeks | Months | Months | Unlimited |
| Conversion pressure | High | Low | Medium | None |
| Community building | Low | Medium | Medium | High |
| Support costs | High | Low | Medium | Variable |

**Developer tools almost always need a permanent free tier, not a free trial.** Developers build side projects, evaluate tools for future use, and recommend tools to others—all of which require long-term free access.

## Usage Limits That Make Sense

### Good Limit Dimensions

**API calls/requests**
- Developers understand and can track
- Scales naturally with application growth
- Example: 10,000 requests/month

**Compute resources**
- Clear relationship to cost
- Predictable for developers
- Example: 500 build minutes/month

**Storage**
- Easy to understand
- Natural upgrade trigger as data grows
- Example: 1GB storage

**Seats/users**
- Makes sense for collaboration tools
- Natural upgrade for team growth
- Example: Up to 3 team members

### Bad Limit Dimensions

**Time-based trials disguised as free tiers**
- "Free tier expires after 90 days of inactivity"
- Creates anxiety and resentment

**Arbitrary feature combinations**
- "Free: 3 projects with 2 environments each, max 5 databases per environment, 100MB per database"
- Too complex to evaluate

**Limits that punish success**
- "Free up to 100 monthly active users"
- Your most successful free users hit limits fastest

### The Goldilocks Zone

Free tier limits should:
1. **Allow meaningful usage** - Build and run a real side project
2. **Cover hobbyist use cases** - Personal projects should never require payment
3. **Trigger on growth, not time** - Upgrades happen because projects succeed
4. **Be easy to predict** - Developers should know when they'll hit limits

### Example: Good Limit Structure

**Vercel:**
- Unlimited personal projects
- 100GB bandwidth/month
- Serverless function limits
- Hobby use stays free forever

**Supabase:**
- 500MB database storage
- 2GB bandwidth
- 50,000 monthly active users
- Social auth unlimited

**PlanetScale:**
- 1 database
- 1 billion row reads/month
- 10 million row writes/month
- 5GB storage

## Feature Gating Strategies

### The Free Features Principle

Free tiers should include everything needed to:
1. Evaluate the product thoroughly
2. Build and ship a real project
3. Operate in production at small scale

### Features to Keep Free

- Core functionality
- All integrations and SDKs
- Standard authentication
- Basic monitoring and logs
- Documentation and community support
- Development and testing environments

### Features to Gate Behind Paid Tiers

**Collaboration features:**
- Team members beyond the solo developer
- Access controls and permissions
- Audit logs

**Scale and performance:**
- Higher rate limits
- More compute/storage
- Premium infrastructure (dedicated instances)

**Enterprise requirements:**
- SSO/SAML
- SLAs and uptime guarantees
- Priority support
-
