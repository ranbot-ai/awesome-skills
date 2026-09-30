---
name: business-website-setup
description: Website page register: URL, title, meta description, search intent, NAP block, schema type, canonical, indexability and Core Web Vitals target. Use for site builds and SEO reviews. 
category: Document Processing
source: antigravity
tags: [javascript, markdown, api, ai, workflow, template, design, document, presentation, image]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/business-website-setup
---


# Business Website Setup

**What it is:** the smallest site that ranks and converts - the page list, what each page is
for, which search intent it answers, and the technical and structured-data requirements
that make it findable.

## Overview

Works out the smallest useful site for the business in front of it, then builds the plan
only when asked. The default output is a short recommendation, not a page map. The page
register - CSV, SQL DDL, JSON Schema, Notion mapping - is produced on request, from one
field list so the four cannot drift apart.

Layer: Layer 5: Fulfil. Fits: Growth stage. Table code: n/a.

**The rule this table exists to enforce:** a page with no declared search intent is a page
that ranks for nothing and a page with no declared owner is a page that rots. `Primary
Keyword`, `Search Intent` and `Owner` are therefore required, and the NAP block is a
per-page field rather than a global assumption - a business with one location and one
service area genuinely does repeat the NAP on every page, and a multi-location business
genuinely does not.

## When to Use This Skill

- build a website, set up a website, website plan
- page structure, sitemap, site map, information architecture
- "we have a website but nobody finds us"
- on-page SEO, meta titles, meta descriptions, headings
- structured data, schema, LocalBusiness, Service, FAQ
- Core Web Vitals, page speed, mobile
- NAP on the website, local signals, Google Search Console

Do not use it for: the ranking asset that is not the website - that is
`gbp-local-seo-intent`; the design tokens (`design-theme-guide`); off-site citations
(`seo-directory-backlinks`); or a one-page campaign, which is `linktree-link-hub`.

## How It Works

Follow the shared execution contract. The module-specific rules below define only domain fields, decisions, calculations, and safety constraints.

### Step 1 - Identify intent

Read the request and pick the intent before asking anything.

- "build" / "set up" / "we need" -> artifacts wanted; go to Step 2.
- "we have one already" -> something exists; capture it, then Step 2.
- "not ranking" / "not found" / "fix" -> capture the current state and the queries, then
  Step 2.
- "review" / "audit" / "check" -> a check, not a build.
- "which pages should we have" -> a decision question, not a build.

Ask only if this is the highest-value missing fact; otherwise proceed without an opener:

> **Q:** What is the business called, and what does one line of it actually do?

### Step 2 - Ask only what is missing

Treat ambiguous replies as unanswered and ask which explicit option the user means. Record unknown values as `Unknown`; `Unknown` is not zero. A record must not be `Done` when a required check fails.

Skip anything already answered. Ask the rest one at a time, and stop as soon as the
remaining answers would not change the page list.

- **Business** - Name, address, phone, services, service area? / Do customers visit a
  location, or is it a service-area business? / One location or several?
- **Current** - Is there a site today, and on what - WordPress, Shopify, Wix, Squarespace,
  a builder, or hand-built? / Who can publish a page? / Is there a developer or is it
  self-serve?
- **Customers** - What are the three questions a customer asks before they buy? / What do
  they search for? / Do they compare, or just want the nearest option?
- **Proof** - Any reviews, ratings, certifications, case studies or photos that can be shown?
  / Is there a team, a location, a process worth showing?
- **Outcome** - What is the site's job - calls, enquiries, bookings, direct sales, or just
  credibility? / Is there a phone number or WhatsApp that must be reachable in one tap?

Never invent an answer. Services, keywords, addresses, phone numbers, review counts,
platforms and metrics the user has not supplied are `Unknown`.

### Step 3 - Hold the internal context

```yaml
module: business-website-setup
intent: null            # set up | fix | review | report | import
scale: null             # Starter | Growth | Scale, only if the answer changes it
areas:
  "Business": null
  "Current": null
  "Customers": null
  "Proof": null
  "Outcome": null
requested_outputs: []
confirmed_facts: []
open_questions: []
```

### Step 4 - Recommend the smallest workflow

Build an already requested artifact without asking again. For advice-only requests, give a short recommendation and offer the relevant artifact.

**Recommended approach:** Five to eight pages, one per service and one per place, plus home,
about, contact and a service-area page. Every service gets its own page with its own
intent, its own NAP block and `LocalBusiness` or `Service` structured data. Mobile-first,
fast, one clear call to action per page, and a review widget on the pages that earn trust.
No blog unless someone will actually write it.

**Why this one:** One page per service is what ranks - a single homepage cannot rank for
six different things at once, and a page covering three servi
