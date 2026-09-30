---
name: design-theme-guide
description: Design-token register: colour, typography, spacing and radius tokens with light and dark values, contrast ratio and WCAG level. Use for design system documentation. 
category: Document Processing
source: antigravity
tags: [pdf, xlsx, markdown, ai, workflow, template, design, document, presentation, image]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-theme-guide
---


# Design Theme Guide

**What it is:** the documented value set a business designs against - colour, type, space, radius, motion - with every colour pair contrast-tested and written down.

## Overview

Works out the smallest useful theme for the business in front of it, then builds it only
when asked. The default output is a short recommendation, not a token file. The token
register - CSV, SQL DDL, JSON Schema, Notion mapping - is produced on request, from one
field list so the four cannot drift apart.

Layer: Layer 2: Brand & Design. Fits: Starter stage. Table code: n/a.

**The rule this table exists to enforce:** a theme is a set of *values*, not a set of
screens. If a colour, size or spacing value is not a row in the register, it is not part of
the system, and anything using it is a one-off. `Value` alone is the single source; the
light and dark variants and the type metrics exist on the same row because they are the
same token, and a token split across rows drifts within a month.

## When to Use This Skill

- brand colours, colour palette, theme
- typography, font pairing, type scale
- spacing, grid, layout rules
- "we have no design system"
- dark mode and light mode variants
- accessibility of our own colours
- Figma variables, Style Dictionary, CSS custom properties, `tokens.json`

Do not use it for: designing the logo itself (that is `logo-image-design`), choosing a
typeface's licence (`logo-image-design` covers rights), or a specific component's behaviour.

## How It Works

Follow the shared execution contract. The module-specific rules below define only domain fields, decisions, calculations, and safety constraints.

### Step 1 - Identify intent

Read the request and pick the intent before asking anything.

- "set up" / "build" / "create" -> the user wants the token set; go to Step 2.
- "our colours are a mess" / "fix" -> something exists; capture what is in use, then Step 2.
- "is this accessible" / "review" / "audit" -> a check, not a build; answer from what they share.
- "how do we ..." -> advice question; answer directly and offer the build only if it helps.

Ask only if this is the highest-value missing fact; otherwise proceed without an opener:

> **Q:** What is the business called, and what does one line of it actually do?

### Step 2 - Ask only what is missing

Treat ambiguous replies as unanswered and ask which explicit option the user means. Record unknown values as `Unknown`; `Unknown` is not zero. A record must not be `Done` when a required check fails.

Skip anything the user already answered, in any earlier message. Ask the rest one at a
time, and stop as soon as the remaining answers would not change the token set.

- **Identity** - Business name and what it does? / One colour already decided, and is it
  fixed by a customer, a client or a sign? / Any existing logo, colours or documents?
- **Surface** - Website only, or print and social as well? / Dark mode needed? / Any CMS
  or design tool already in use (Figma, Shopify, WordPress, custom)?
- **Type** - Any typeface already chosen, licensed or not? / Long documents or short
  marketing copy? / Any script other than Latin?
- **Access** - Is there a public-sector, EU-market or accessibility obligation? / Has
  anyone reported low contrast or readability before?
- **Governance** - Who decides a colour change? / Does the theme need to be handed to an
  external developer or agency?

Never invent an answer. Hex codes, brand colours, font names and typeface licences the user
has not supplied are `Unknown`.

### Step 3 - Hold the internal context

```yaml
module: design-theme-guide
intent: null            # set up | fix | review | report | import
scale: null             # Starter | Growth | Scale, only if the answer changes it
areas:
  "Identity": null
  "Surface": null
  "Type": null
  "Access": null
  "Governance": null
requested_outputs: []   # csv | sql | json | notion | xlsx - requested formats only
confirmed_facts: []
open_questions: []
```

### Step 4 - Recommend the smallest workflow

Build an already requested artifact without asking again. For advice-only requests, give a short recommendation and offer the relevant artifact.

**Recommended approach:** One token register with a brand colour as the single source for
accents, a neutral ramp for everything else, one display face and one body face at a fixed
type scale, a 4 or 8 point spacing unit, and light and dark variants. Every colour pair
that carries text gets a measured ratio and a WCAG level in the row itself, so the
accessibility of the theme is auditable rather than remembered.

**Why this one:** A theme that exists as values is the only thing that makes the website,
the deck, the letterhead and the social posts look like one business. Screens cannot do
that, and a theme with no contrast measurement is a theme that fails the first time
someone chooses a pastel.

**Workflow:** Seed colour chosen → Neutral ramp derived → Semantic colour roles assigned →
Every text pair cont
