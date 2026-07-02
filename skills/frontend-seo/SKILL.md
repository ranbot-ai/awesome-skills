---
name: frontend-seo
description: A portable, framework-agnostic SEO system for any React or React Native-for-web frontend. Centralizes site metadata in one constants module, derives canonical URLs from a single base, builds per-route
category: Creative & Media
source: antigravity
tags: [typescript, react, api, claude, ai, agent, template, image, security, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/frontend-seo
---


# Frontend SEO (portable, builder-based)
## When to Use

Use this skill when you need a portable, framework-agnostic SEO system for any React or React Native-for-web frontend. Centralizes site metadata in one constants module, derives canonical URLs from a single base, builds per-route metadata (title, description, canonical, Open Graph, Twitter/X cards), generates...


> Portable skill — readable by Claude Code, OpenCode, Codex, Cursor, Windsurf, and others.
> This skill describes an **SEO system** — a set of pure builder functions plus a thin
> framework adapter — not a component library or a visual style.
> It pairs with the **frontend-architecture** skill: the SEO system lives in a single
> service module (`services/seo/`) and is consumed through one barrel.

The goal: every route ships **correct, consistent, machine-readable metadata** without
anyone copy-pasting `<meta>` tags. Site identity lives in **one** constants module, URLs are
**always absolute and canonical**, and search engines get a **sitemap, robots rules, an RSS
feed, and typed JSON-LD** derived from the same content the app already renders.

---

## 0. The five core ideas

1. **One source of truth for identity.** Site URL, name, description, keywords, author, social handles, OG image, and verification tokens live in a single `constants/seo` module. Nothing about the site's identity is hardcoded anywhere else.
2. **URLs are always absolute and canonical.** A single `canonicalUrl(path)` function turns any path into an absolute, trailing-slash-normalized URL. Every sitemap entry, RSS link, OG URL, and JSON-LD `@id` flows through it.
3. **Builders are pure; the adapter is thin.** Metadata, sitemap, robots, RSS, and JSON-LD are produced by pure functions that take data and return plain objects. Only one small function touches the framework's metadata type. Pure functions are trivially unit-testable.
4. **Structured data is typed and reused.** JSON-LD objects share a `JsonLd` type and a small set of `schema.org` builders (`Person`, `WebSite`, `BlogPosting`, `CreativeWork`, `BreadcrumbList`, `FAQPage`). Entities cross-reference each other by stable `@id`.
5. **Discovery surfaces are generated from content.** `sitemap.xml`, `robots.txt`, and the RSS feed are built from the same content collections the app renders — never maintained by hand, never drifting.

Everything below is the mechanical application of these five ideas.

---

## 1. Directory layout

The SEO system is one service module plus its constants and types. It slots directly into the
`frontend-architecture` shape (`shared/` or `services/`).

```
src/
├── constants/
│   └── seo.ts                  ← SINGLE source of truth for site identity
├── types/
│   └── seo.ts                  ← SchemaType, RouteDescriptor, SitemapEntry,
│                                  RobotsConfig, RssItem, Redirect, JsonLd
├── services/seo/
│   ├── index.ts                ← barrel: canonicalUrl, buildMetadata,
│   │                              sitemapEntries, robots, rssItems,
│   │                              structuredData, redirects
│   └── structured-data.ts      ← per-type JSON-LD builders (Person, WebSite, …)
└── app/ (or routes/)           ← THIN adapter: route files call the builders
    ├── layout.tsx              ← global default metadata (from constants/seo)
    ├── sitemap.ts              ← mounts sitemapEntries()
    ├── robots.ts               ← mounts robots()
    └── feed.xml/route.ts       ← mounts rssItems()
```

Rule of thumb: **builders never import the framework** (except the one `buildMetadata` adapter);
**route files never build SEO data inline** — they call a builder and mount the result.

---

## 2. One source of truth for identity (`constants/seo`)

Everything about the site's identity is a named constant. No bare strings scattered across
route files, no second copy of the description, no hardcoded base URL.

```ts
// constants/seo.ts
export const SITE_URL = "https://example.com"; // no trailing slash
export const SITE_NAME = "Jane Doe";
export const SITE_HANDLE = "@janedoe";
export const SITE_LOCALE = "en_US";

export const SITE_TITLE_DEFAULT = "Jane Doe — Senior Engineer";
export const SITE_TITLE_TEMPLATE = "%s | Jane Doe"; // child pages fill %s

export const SITE_DESCRIPTION =
  "Senior engineer building cross-platform products with React and TypeScript.";

export const SITE_KEYWORDS = ["Jane Doe", "React", "TypeScript", "Engineer"];

export const AUTHOR_NAME = "Jane Doe";
export const AUTHOR_EMAIL = "jane@example.com";
export const AUTHOR_GITHUB = "https://github.com/janedoe";
export const AUTHOR_LINKEDIN = "https://www.linkedin.com/in/janedoe/";

export const OG_IMAGE_PATH = "/og-image.png"; // relative; canonicalized at use
export const OG_IMAGE_WIDTH = 1200;
export const OG_IMAGE_HEIGHT = 630;

export const GOOGLE_SITE_VERIFICATION = "your-search-console-token";
```

Why: changing the description or the OG image touches **one line**. Structured data, OG tags, and
Twitter c
