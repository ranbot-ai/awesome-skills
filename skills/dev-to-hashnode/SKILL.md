---
name: dev-to-hashnode
description: When the user wants to publish on Dev.to, Hashnode, or other developer blogging platforms. Trigger phrases include "Dev.to," "Hashnode," "developer blog," "cross-posting," "technical blogging," "canon
category: Development & Code Tools
source: antigravity
tags: [python, javascript, react, node, markdown, api, ai, agent, workflow, template]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/dev-to-hashnode
---


# Dev.to & Hashnode Publishing
## When to Use

Use this skill when you need when the user wants to publish on Dev.to, Hashnode, or other developer blogging platforms. Trigger phrases include "Dev.to," "Hashnode," "developer blog," "cross-posting," "technical blogging," "canonical URL," or "developer content platform.".


Developer blogging platforms offer built-in audiences of hundreds of thousands of developers. This skill covers cross-posting strategy, platform-specific optimization, and building followers on Dev.to and Hashnode.

---

## Before You Start

1. Read `.agents/developer-audience-context.md` if it exists
2. Decide your canonical URL strategy (important for SEO)
3. Create accounts on both platforms to reserve your username
4. Understand: These platforms reward consistency and engagement

---

## Platform Comparison

### Dev.to vs Hashnode

| Feature | Dev.to | Hashnode |
|---------|--------|----------|
| Monthly visitors | ~10M+ | ~3M+ |
| Custom domain | No (subdomain only) | Yes (free) |
| Canonical URL support | Yes | Yes |
| SEO benefits | High domain authority | Your domain gets SEO |
| Monetization | No native | Sponsors, newsletter |
| Newsletter | No | Built-in |
| Series support | Yes | Yes |
| Code highlighting | Excellent | Excellent |
| Community features | Strong (reactions, comments) | Growing |
| Audience | Broader, more beginners | More senior, focused |

### When to Use Each

| Use Dev.to when | Use Hashnode when |
|-----------------|-------------------|
| Maximum reach is priority | Building your own brand |
| Targeting beginners/mid-level | Want custom domain SEO |
| Community engagement matters | Building email list |
| Quick validation of content | Long-term content strategy |
| Don't have your own blog | Supplementing your main blog |

---

## Cross-Posting Strategy

### The Canonical URL Decision

| Strategy | Pros | Cons |
|----------|------|------|
| **Original on your blog** | SEO to your domain, full control | Platforms may rank lower |
| **Original on Dev.to** | Maximum initial reach | No SEO to your domain |
| **Original on Hashnode (custom domain)** | SEO + platform reach | Smaller initial audience |

### Best Practice: Your Blog + Cross-Post

1. **Publish on your blog first** — This is canonical
2. **Wait 1-2 days** — Let Google index your original
3. **Cross-post to Dev.to** — Set canonical URL to your blog
4. **Cross-post to Hashnode** — Set canonical URL to your blog

### Setting Canonical URLs

**Dev.to** (in frontmatter):
```yaml
---
title: Your Title
canonical_url: https://yourblog.com/your-post
---
```

**Hashnode** (in editor):
- Click "Article settings" gear icon
- Paste original URL in "Canonical URL" field

---

## Dev.to Optimization

### Frontmatter Structure

```yaml
---
title: "Specific, Keyword-Rich Title (Not Clickbait)"
published: true
description: "One compelling sentence that shows up in previews and SEO"
tags: javascript, webdev, tutorial, beginners
cover_image: https://your-cdn.com/image.png
canonical_url: https://yourblog.com/original-post
series: "Building a CLI from Scratch"
---
```

### Tag Strategy

| Tag | Followers | Use for |
|-----|-----------|---------|
| #javascript | 200K+ | JS content |
| #webdev | 150K+ | General web development |
| #beginners | 120K+ | Accessible content |
| #tutorial | 100K+ | Step-by-step guides |
| #react | 80K+ | React specific |
| #programming | 80K+ | General programming |
| #python | 70K+ | Python content |
| #devops | 50K+ | DevOps, CI/CD |
| #opensource | 40K+ | OSS projects |
| #productivity | 40K+ | Dev tools, workflows |

**Rules**:
- Maximum 4 tags per post
- First tag is primary (appears in URL)
- Check tag follower count before using

### What Performs on Dev.to

| Content type | Performance | Notes |
|--------------|-------------|-------|
| Beginner tutorials | High | Largest audience segment |
| Listicles ("10 tools...") | High | Easy to consume |
| Career advice | High | Aspirational content |
| Hot takes | Medium-high | Controversial drives engagement |
| Deep technical | Medium | Niche but engaged audience |
| Project showcases | Medium | Best with story behind it |
| News/updates | Low | Competes with official sources |

### Dev.to Engagement Features

| Feature | How to use |
|---------|------------|
| **Reactions** | Heart, unicorn, saved, fire — different meanings |
| **Comments** | Reply to every comment for algorithm boost |
| **Series** | Group related posts, drives binge reading |
| **Discussion** | Tag #discuss for opinion/question posts |
| **Listings** | Post jobs, events, products |

---

## Hashnode Optimization

### Article Settings

| Setting | Recommendation |
|---------|----------------|
| **Subtitle** | Use for SEO keywords |
| **Cover image** | 1600x840 optimal size |
| **SEO title** | Can differ from article title |
| **SEO description** | 155 characters max |
| **Canonical URL** | Your original if cross-posting |
| **Enable table of contents** | Yes for long posts |
| *
