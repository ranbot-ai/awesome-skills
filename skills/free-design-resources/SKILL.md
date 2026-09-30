---
name: free-design-resources
description: Design resource register: resource and provider, licence type, commercial-use and attribution rules, export format, lock-in risk, free tier limit and accessibility notes. Use for tool vetting. 
category: Document Processing
source: antigravity
tags: [pdf, markdown, ai, workflow, template, design, document, image, security, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/free-design-resources
---


# Free Design Resources

**What it is:** the register of free design tools, fonts, icons, images and templates the
business uses, and what each one actually permits.

## Overview

Works out the smallest set of free tools that covers what the business is trying to make,
then builds it only when asked. The default output is a short recommendation, not a
licence review. The resource clearance and adoption register - CSV, SQL, JSON Schema, Notion
mapping - is produced on request, from one field list so the four cannot drift apart.

Layer: Layer 1: Foundation. Fits: Starter stage. Table code: n/a.

**The rule this table exists to enforce:** "free" is not a licence term, so `Licence Type`
and `Commercial Use Allowed` are the fields that matter, and the full map in
`../../references/free-design-resource-map.md` is the evidence base for them. A free tool is safe
to use and unsafe to depend on when it cannot export, when it holds the only copy of the
work, or when its terms forbid the one thing the business needs - commercial use, logo
use, print, or client work. `Export Format` and `Vendor Lock-In Risk` exist to catch
exactly that.

**The second rule:** accessibility and licence are checked at the same time. A font under
14px, a grey-on-grey pair from a template, or an icon set used without its licence
attribution are both defects, and both are cheap to avoid at the point of selection.

## When to Use This Skill

- free design tools, free alternatives, "what can we use for nothing"
- free fonts, free icons, free images, free templates, stock photography
- licensing, licence terms, commercial use, attribution, redistribution
- "can we use this", "is this free to use", "is this allowed for a client"
- tool consolidation, cancelling a subscription, reducing design spend
- design accessibility, contrast checking, free colour palette tools
- brand kit on a zero budget, open source design system

Do not use it for: building the design system itself (`design-theme-guide`), the artwork
(`logo-image-design`), or a legal opinion on a licence agreement.

## How It Works

Follow the shared execution contract. The module-specific rules below define only domain fields, decisions, calculations, and safety constraints.

### Step 1 - Identify intent

Read the request and pick the intent before asking anything.

- "what can we use" / "find" / "we need" -> artifacts wanted; go to Step 2.
- "is this allowed" / "can I use this" -> a licence question, answer it before anything
  else.
- "review" / "audit" / "we are paying too much" -> a review, not a build.
- "we already picked a tool" -> a clearance check on one item; go straight to Step 4.

Ask only if this is the highest-value missing fact; otherwise proceed without an opener:

> **Q:** What are you trying to make, and is it for the business itself or for a client?

### Step 2 - Ask only what is missing

Treat ambiguous replies as unanswered and ask which explicit option the user means. Record unknown values as `Unknown`; `Unknown` is not zero. A record must not be `Done` when a required check fails.

Skip anything already answered. Ask the rest one at a time, and stop as soon as the
remaining answers would not change the shortlist.

- **What is being made** - Logo, brand kit, website, social posts, documents, print, video,
  or a product interface? / Print, screen, or both - and for print, which sizes and which
  process?
- **Who is it for** - The business's own marketing, or work delivered to a client? / Is the
  business itself a registered company, and in which country? / Will anything be sold, or is
  it internal only?
- **Budget reality** - Is zero a hard constraint, or is a small one-off payment acceptable
  to remove a problem? / Is there a card on file for anything that has a free tier?
- **Constraints** - Anyone on the team with specific skills, or accessibility needs? / Any
  existing tool the business has already paid for and should use? / Any file formats the
  client or printer requires?
- **Risk** - Does anything need to be editable by a non-designer in two years? / Is there any
  chance of reselling the output, or licensing it on?

Never invent an answer. Licence terms, prices, feature lists, export formats and
attribution requirements are **not** invented here - they are read from the provider's own
current terms and recorded with the source and the date it was read. Anything not verified
is `Unverified`, which is a different value from `No`.

### Step 3 - Hold the internal context

```yaml
module: free-design-resources
intent: null            # set up | review | report | import
areas:
  "What is being made": null
  "Who is it for": null
  "Budget reality": null
  "Constraints": null
  "Risk": null
requested_outputs: []
confirmed_facts: []
open_questions: []
```

### Step 4 - Recommend the smallest workflow

Build an already requested artifact without asking again. For advice-only requests, give a short recommendation and offer the relevant artifact.

**Recommended 
