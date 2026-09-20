---
name: geo-llmstxt
description: Analyzes and generates llms.txt files -- the emerging standard for helping AI systems understand website structure and content. 
category: AI & Agents
source: antigravity
tags: [react, pdf, markdown, api, claude, ai, agent, llm, template, document]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/geo-llmstxt
---


# llms.txt Standard Analysis and Generation Skill

## Purpose

This skill handles everything related to the `llms.txt` standard -- an emerging convention (proposed by Jeremy Howard in September 2024, gaining adoption through 2025-2026) that allows websites to provide structured guidance to AI systems about their content, structure, and key information. It is analogous to `robots.txt` (which tells crawlers what NOT to access) but instead tells AI systems what IS most useful to understand about the site.

## Why llms.txt Matters

AI language models face a fundamental challenge when processing websites: they must determine which pages are most important, what the site is about, and how content is organized -- typically by crawling many pages and inferring structure. `llms.txt` solves this by providing an explicit, machine-readable (and human-readable) summary.

**Benefits of having a well-crafted llms.txt:**

1. **Faster AI comprehension:** AI systems can understand your site's purpose and structure from a single file rather than crawling dozens of pages.
2. **Controlled narrative:** You choose which pages and facts AI systems see first, shaping how they represent your brand.
3. **Higher citation accuracy:** AI systems that consult llms.txt can cite the correct, authoritative page for each topic.
4. **Reduced misrepresentation:** Key facts (pricing, features, locations) are stated explicitly, reducing AI hallucination about your business.
5. **Early adopter advantage:** As of early 2026, fewer than 5% of websites have an llms.txt file, making it a differentiator.

---

## The llms.txt Specification

### File Location

The file MUST be located at the root of the domain:
```
https://example.com/llms.txt
```

### Format Specification

The file uses Markdown formatting with specific conventions:

```markdown
# [Site Name]

> [One-sentence description of what the site/business does. Keep under 200 characters.]

## Docs

- [Page Title](https://example.com/page-url): Concise description of what this page covers and why it matters.
- [Another Page](https://example.com/another-page): Description of content.

## Optional

- [Less Critical Page](https://example.com/optional-page): Description.
```

### Detailed Format Rules

**1. Title (Required)**
```markdown
# Site Name
```
- Must be the first line of the file.
- Should be the official business/site name.
- Use the H1 heading format (single `#`).

**2. Description (Required)**
```markdown
> Brief description of the site/business
```
- Must appear immediately after the title.
- Use Markdown blockquote format (`>`).
- Keep under 200 characters.
- Should clearly state what the business does and who it serves.
- Avoid marketing fluff -- be factual and specific.

**3. Main Sections (Required -- at least one)**

Use H2 headings (`##`) to organize pages by category. Common section names:

| Section Name | Purpose | Example Content |
|---|---|---|
| `## Docs` | Primary documentation or key pages | Product pages, service descriptions, core content |
| `## Optional` | Secondary pages worth knowing about | Blog posts, supplementary resources |
| `## API` | API documentation | API reference, authentication guides |
| `## Blog` | Blog or news content | Recent/popular articles |
| `## Products` | Product catalog | Product pages, pricing |
| `## Services` | Service offerings | Service descriptions, process pages |
| `## About` | Company information | About page, team, mission |
| `## Resources` | Educational/reference content | Guides, tutorials, whitepapers |
| `## Legal` | Legal documents | Terms of service, privacy policy |
| `## Contact` | Contact information | Contact page, support channels |

**4. Page Entries (Required)**

Each entry follows the format:
```markdown
- [Page Title](https://example.com/): Description of page content
```

Rules for page entries:
- **Title:** Use the actual page title or a clear descriptive title.
- **URL:** Must be a full, absolute URL (not relative paths).
- **Description:** 10-30 words describing what the page covers. Be specific about the information available.
- **Order:** List pages in order of importance within each section.
- **Limit:** Include 10-30 page entries total. Prioritize your most authoritative and useful pages.

**5. Key Facts Section (Recommended)**

```markdown
## Key Facts
- Founded in [year] by [founder(s)]
- Headquarters: [City, Country]
- [X] customers/users in [Y] countries
- Key products: [Product A], [Product B], [Product C]
- Industry: [Industry classification]
```

This section provides quick reference data that AI systems frequently need to answer user queries about your business.

**6. Contact Section (Recommended)**

```markdown
## Contact
- Website: https://example.com
- Email: hello@example.com
- Support: support@example.com
- Phone: +1-555-123-4567
- Address: 123 Main St, City, State, ZIP, Country
```

---

## llms-full.txt (Extended Version)

In addition to `llms.txt`, sites can provide `/llms-full.txt` -- an e
