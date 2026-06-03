---
name: nextjs-seo-indexing
description: Fix SEO indexing issues, crawl budget problems, and Search Console coverage errors for Next.js apps. Covers canonical tags, noindex audits, sitemap health, static rendering, and internal linking. 
category: Business & Marketing
source: antigravity
tags: [nextjs, api, claude, ai, agent, rag, seo, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/nextjs-seo-indexing
---


# Next.js SEO Indexing & Crawl Budget Skill

Fix Google Search Console coverage issues, canonical problems, sitemap errors, and crawl budget waste in Next.js apps.

---

## When to Use

- Use when a Next.js site has Google Search Console coverage issues such as duplicate canonicals, accidental noindex, crawl waste, or discovered-but-not-indexed URLs.
- Use when auditing sitemap, robots.txt, redirect, internal-linking, or static-rendering problems before an SEO release.
- Use when you need framework-specific examples for Next.js App Router metadata, `generateMetadata`, `robots.js`, and sitemap routes.

---

## Understanding Search Console Coverage States

| Status | Meaning | Fix |
|--------|---------|-----|
| Crawled – not indexed | Google crawled but chose not to index | Improve content quality + canonical + internal links |
| Duplicate without canonical | Multiple URLs serve same content, no canonical | Add explicit canonical to the preferred URL |
| Excluded by noindex | `noindex` tag present | Remove noindex if page should be indexed |
| Duplicate, Google chose different canonical | Google prefers a different URL than you specified | Align canonical with the URL Google naturally picks |
| Alternative page with proper canonical | Correct — non-preferred duplicate pointing to canonical | Expected behavior, not a problem |
| Not found 404 | Page deleted or URL changed | Add redirect or restore page |
| Discovered – not indexed | Google knows it exists but hasn't crawled it | Improve internal linking + crawl budget |
| Page with redirect | Redirect chain or redirect to wrong target | Shorten redirect chain, verify destination |

---

## Step 1 — Canonical Audit

### Next.js App Router (metadata export)
```js
// app/blog/my-post/page.js
export const metadata = {
  title: 'My Post Title',
  alternates: {
    canonical: 'https://www.yourdomain.com/blog/my-post',
  },
};
```

### Next.js App Router (generateMetadata)
```js
export async function generateMetadata({ params }) {
  return {
    alternates: {
      canonical: `https://www.yourdomain.com/blog/${params.slug}`,
    },
  };
}
```

### Common canonical mistakes to fix:
```js
// ❌ WRONG — relative URL
canonical: '/blog/my-post'

// ❌ WRONG — missing trailing slash inconsistency  
// (pick one and stick with it sitewide)

// ✓ CORRECT — absolute URL, consistent scheme + subdomain
canonical: 'https://www.yourdomain.com/blog/my-post'
```

---

## Step 2 — Noindex Audit

Find pages that are accidentally noindexed:

```bash
# Search for noindex in metadata
rg -n --glob '*.{js,ts,jsx,tsx}' 'noindex|robots.*noindex' app pages

# Check layout.js — a noindex here affects ALL pages
grep -n "robots" app/layout.js
```

In Next.js App Router, `robots` in the root layout applies globally. Only set it there if you want the whole site affected.

```js
// app/layout.js — only set robots if you need sitewide control
export const metadata = {
  // ✓ Allow indexing
  robots: { index: true, follow: true },
  // ❌ This would noindex the entire site:
  // robots: { index: false }
};
```

---

## Step 3 — Sitemap Health

### Verify sitemap routes return 200 + valid XML
```bash
curl -sI https://www.yourdomain.com/sitemap.xml | grep -i "content-type\|status"
curl -s https://www.yourdomain.com/sitemap.xml | head -20
```

### Next.js App Router sitemap (recommended pattern)
```js
// app/sitemap.js
export default async function sitemap() {
  const baseUrl = 'https://www.yourdomain.com';
  
  // Static pages
  const staticPages = [
    { url: baseUrl, lastModified: new Date(), changeFrequency: 'daily', priority: 1.0 },
    { url: `${baseUrl}/about`, lastModified: new Date(), changeFrequency: 'monthly', priority: 0.8 },
  ];
  
  // Dynamic pages (fetch from DB or CMS)
  const posts = await getPosts(); // your data fetch
  const dynamicPages = posts.map(post => ({
    url: `${baseUrl}/blog/${post.slug}`,
    lastModified: new Date(post.updatedAt),
    changeFrequency: 'weekly',
    priority: 0.7,
  }));
  
  return [...staticPages, ...dynamicPages];
}
```

### Multiple sitemaps (sitemap index)
```js
// app/sitemap-tools/sitemap.js  
// app/sitemap-blog/sitemap.js
// Each returns an array of URL entries
```

---

## Step 4 — Static Rendering Verification

Pages must be statically generated (or SSR with metadata in HTML) for Google to see SEO tags.

```bash
# Check build output — pages should show ● (static) not λ (dynamic)
npm run build 2>&1 | grep -E "○|●|λ|/blog|/tools"
```

```text
○  /about             (static)
●  /blog/[slug]       (SSG)  ← good
λ  /api/data          (serverless) ← expected for APIs
```

If important pages are `λ` (fully dynamic with no static generation), add:

```js
// app/blog/[slug]/page.js
export async function generateStaticParams() {
  const posts = await getPosts();
  return posts.map(post => ({ slug: post.slug }));
}
```

---

## Step 5 — Internal Linking Audit

Pages with zero internal links are rarely indexed. Every important page should be reachable fro
