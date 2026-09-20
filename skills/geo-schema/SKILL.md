---
name: geo-schema
description: Schema.org structured data audit and generation optimized for AI discoverability — detect, validate, and generate JSON-LD markup 
category: AI & Agents
source: antigravity
tags: [python, javascript, pdf, markdown, claude, ai, agent, llm, template, image]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/geo-schema
---


# GEO Schema & Structured Data

## Purpose

Structured data is the primary machine-readable signal that tells AI systems what an entity IS, what it does, and how it connects to other entities. While schema markup has traditionally been about earning Google rich results, its role in GEO is fundamentally different: **structured data is how AI models understand and trust your entity**. A complete entity graph in structured data dramatically increases citation probability across all AI search platforms.

## How to Use This Skill

1. Fetch the target page HTML using `fetch_page.py` (see note below)
2. Detect all existing structured data (JSON-LD, Microdata, RDFa)
3. Validate detected schemas against Schema.org specifications
4. Identify missing recommended schemas based on business type
5. Generate ready-to-use JSON-LD code blocks
6. Output GEO-SCHEMA-REPORT.md

---

## Step 1: Detection

**IMPORTANT:** WebFetch converts HTML to markdown and strips `<head>` content, which removes JSON-LD blocks. Use `fetch_page.py` instead:
```bash
python3 ~/.claude/skills/geo/scripts/fetch_page.py <url> page
```
The output includes a `structured_data` array with all parsed JSON-LD blocks from the page.

### Scan for JSON-LD
Look for `<script type="application/ld+json">` blocks in the HTML. Parse each block as JSON. A page may contain multiple JSON-LD blocks — collect all of them.

### Scan for Microdata
Look for elements with `itemscope`, `itemtype`, and `itemprop` attributes. Map the hierarchy of nested items. Note: Microdata is harder for AI crawlers to parse than JSON-LD. Flag a recommendation to migrate to JSON-LD if Microdata is the only format found.

### Scan for RDFa
Look for elements with `typeof`, `property`, and `vocab` attributes. Similar to Microdata — recommend migration to JSON-LD.

### Priority Order
JSON-LD is the **strongly recommended format** for GEO. Google, Bing, and AI platforms all process JSON-LD most reliably. If the site uses Microdata or RDFa exclusively, flag this as a high-priority migration.

---

## Step 2: Validation

For each detected schema block, validate:

1. **Valid JSON**: Is the JSON-LD syntactically valid? Check for trailing commas, unquoted keys, malformed strings.
2. **Valid @type**: Does the `@type` match a recognized Schema.org type? Check against https://schema.org/docs/full.html.
3. **Required Properties**: Does the schema include all required properties for its type? (See per-type requirements below.)
4. **Recommended Properties**: Does the schema include recommended properties that increase AI discoverability?
5. **sameAs Links**: Does the schema include `sameAs` properties linking to other platform presences?
6. **URL Validity**: Do all URLs in the schema resolve (not 404)?
7. **Nesting**: Is the schema properly nested (e.g., author inside Article, address inside Organization)?
8. **Rendering Method**: Is the JSON-LD in the server-rendered HTML or injected via JavaScript? Per Google's December 2025 guidance, **JavaScript-injected structured data may face delayed processing**. Flag any schema that requires JS execution.

---

## Step 3: Schema Types for GEO

### Organization (CRITICAL — every business site)
Essential for entity recognition across all AI platforms. This is how AI models identify WHAT the business is.

**Required properties:**
- `@type`: "Organization" (or subtype: Corporation, LocalBusiness, etc.)
- `name`: Official business name
- `url`: Official website URL
- `logo`: URL to logo image (ImageObject preferred)

**Recommended properties for GEO:**
- `sameAs`: Array of ALL platform URLs (see sameAs strategy below)
- `description`: 1-2 sentence description of the organization
- `foundingDate`: ISO 8601 date
- `founder`: Person schema
- `address`: PostalAddress schema
- `contactPoint`: ContactPoint with telephone, email, contactType
- `areaServed`: Geographic area
- `numberOfEmployees`: QuantitativeValue
- `industry`: Text or DefinedTerm
- `award`: Array of awards received
- `knowsAbout`: Array of topics the organization is expert in (strong GEO signal)

### LocalBusiness (for businesses with physical locations)
Extends Organization. Critical for local AI search results and Google Gemini.

**Additional required properties:**
- `address`: Full PostalAddress
- `telephone`: Phone number
- `openingHoursSpecification`: Operating hours

**Recommended for GEO:**
- `geo`: GeoCoordinates (latitude, longitude)
- `priceRange`: Price indicator
- `aggregateRating`: AggregateRating schema
- `review`: Array of Review schemas
- `hasMap`: URL to Google Maps

### Article + Author (CRITICAL for publishers)
The Author schema is one of the strongest E-E-A-T signals for AI platforms.

**Article required:**
- `@type`: "Article" (or NewsArticle, BlogPosting, TechArticle)
- `headline`: Article title
- `datePublished`: ISO 8601
- `dateModified`: ISO 8601 (critical for freshness signals)
- `author`: Person or Organization schema
- `publisher`: Organization schema with logo
- `image`: Represent
