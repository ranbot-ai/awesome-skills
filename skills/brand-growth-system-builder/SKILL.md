---
name: brand-growth-system-builder
description: Route requests across 13 brand and growth modules. Use when an SME needs help choosing branding, website, local SEO, content, or cloud-planning workflows. 
category: Document Processing
source: antigravity
tags: [ai, agent, workflow, template, design, document, presentation, image, security, seo]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/brand-growth-system-builder
---


# Brand & Growth System Builder

Router for 13 brand and growth modules: the design theme, the logo and image library, the
print brand kit, the business website, the Google Business Profile, the backlink and
citation directories, the email templates, the presentation deck, the social channels, the
professional code of conduct, the observability and cloud plan, and the free design
resource map.

The 13 modules are published flat, as siblings at `skills/<slug>/`. This pack is a router
and a catalog and holds no modules of its own; it only places a request on the dependency
order and names the module to load.

It works out what the business actually needs, then hands off to the one module skill that
matches. It never builds anything itself.

## Overview

A small business does not need 13 brand systems. It needs the two or three that make
someone pick it: a theme it can build against, a profile Google can rank, and one asset
set it does not re-make every month. This skill identifies the intent, asks only what is
still missing one question at a time, stops as soon as the answers stop changing the
route, then recommends two or three modules and waits for the user to pick.

Each module skill then runs the same contract: context first, a recommendation, and
artifacts only on request. This skill never emits a schema, a CSV, a token file or a
Notion template.

## When to Use This Skill

- "Set up our branding and website"
- "I need a Google Business Profile that ranks"
- "Where do I list my business for backlinks?"
- "Design a logo, letterhead and visiting card"
- "Set up our Facebook, LinkedIn and TikTok"
- "I need a code of conduct and email templates"
- "Plan our cloud spend and monitoring"

Do not use it when the user has already named one specific asset and just wants it - go
straight to that module skill.

## How It Works

Follow the shared execution contract. The module-specific rules below define only domain fields, decisions, calculations, and safety constraints.

### Step 1 - Identify intent

Read the request and pick the intent before asking anything.

- "set up" / "build" / "create" -> artifacts wanted; go to Step 2.
- "review" / "is this right" / "audit" -> a check, not a build; answer from what they share.
- "how do I ..." -> advice question; answer directly, offer the build only if it helps.
- "fix" -> something already exists and is wrong; capture the current state, then Step 2.

### Step 2 - Ask only what is missing

One question per message. Skip anything already answered in any earlier message. The five
groups below are the only intake; take only the ones that change the answer.

- **Business** - What does the business do, in one line? / Who is the customer? / Physical
  address customers can visit, or service-area only? / City, country.
- **Brand** - Name as it must appear everywhere, spelling included? / One primary colour
  already decided? / Any logo, colours or documents in use today?
- **Digital** - Is there a website today, on which platform? / Who writes the copy? / Any
  social accounts already open?
- **Reach** - How many people, and how many locations or staff? / One office or several?
  / B2B, retail, service or mixed?
- **Outcome** - What has to exist in 30 days? / Who signs off on brand decisions?

Never invent a business fact. Names, addresses, phone numbers, colours, domains and
follower counts that the user has not supplied are `Unknown` and stay that way.

### Step 3 - Hold the internal context

```yaml
module: brand-growth-system-builder
intent: null            # set up | fix | review | report | import
scale: null             # Starter | Growth | Scale, only if it changes the answer
areas:
  "Business": null
  "Brand": null
  "Digital": null
  "Reach": null
  "Outcome": null
requested_outputs: []
confirmed_facts: []
open_questions: []
```

### Step 4 - Recommend two or three modules

Pick the smallest set that gets to a live profile and a usable asset set. Rank them by
what unblocks the rest. Then stop and wait for the user to choose. Examples of the shape
of a route:

- Nothing exists: `design-theme-guide` -> `gbp-local-seo-intent` -> `business-website-setup`
- Profile live, no assets: `logo-image-design` -> `brand-kit-print-collateral` -> `linktree-link-hub`
- Website live, not ranking: `gbp-local-seo-intent` -> `seo-directory-backlinks` -> `presentation-deck`
- Team growing: `code-of-conduct` -> `business-email-template` -> `observability-cloud-planning`

### Step 5 - Never build here

This router produces no files. When the user picks a module, read its sibling SKILL.md and continue the requested work. Each module
skill owns its own artifacts and its own field list.

For Notion, read the selected module and then the Notion helper. Manual artifacts need
no connection; live workspace changes follow the shared execution contract.

## Examples

**Prompt**

```
We are launching a local service business. We need a consistent identity, a website,
and a Google Business Profile, but 
