---
name: community-building
description: When the user wants to build, grow, or improve a developer community on Discord, Slack, or forums. 
category: Document Processing
source: antigravity
tags: [markdown, ai, agent, automation, template, document, security, rag, seo, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/community-building
---


# Community Building
## When to Use

Use this skill when you need when the user wants to build, grow, or improve a developer community on Discord, Slack, or forums. Trigger phrases include "developer community," "Discord server," "Slack community," "community strategy," "community engagement," "community moderation," "community growth," or "community...


This skill helps you build and manage developer communities on Discord, Slack, forums, and other platforms. Covers channel structure, onboarding, engagement programs, handling toxicity, and community-led growth.

---

## Before You Start

**Load your audience context first.** Read `.agents/developer-audience-context.md` to understand:

- Who your developers are (role, seniority, interests)
- Where they already hang out (to avoid competing platforms)
- What problems they discuss (community topic focus)
- How they communicate (formal vs. casual tone)

If the context file doesn't exist, run the `developer-audience-context` skill first.

---

## Platform Selection

### Comparison Matrix

| Platform | Best For | Pros | Cons |
|----------|----------|------|------|
| **Discord** | Developer tools, gaming, OSS | Real-time, rich features, free | Can be chaotic, less enterprise |
| **Slack** | Enterprise, B2B SaaS | Professional, familiar | Expensive at scale, message limits |
| **GitHub Discussions** | OSS projects | Integrated, async, searchable | Less community feel |
| **Discourse** | Long-form, searchable | SEO, threading, ownership | Maintenance, hosting costs |
| **Circle** | Courses, paid communities | Courses integration, clean | Paid, less developer-native |

### Decision Framework

| If your audience is... | Consider |
|------------------------|----------|
| Individual developers, OSS | Discord |
| Enterprise teams | Slack |
| Technical, async-preferred | GitHub Discussions |
| Mixed, need searchability | Discourse |
| Course/education based | Circle |

---

## Channel Structure

### Discord Channel Template

```
📢 INFORMATION
├── #welcome — First landing, rules, links
├── #announcements — Official updates (admin-only posting)
├── #rules — Code of conduct
└── #introductions — New member intros

💬 GENERAL
├── #general — Main discussion
├── #off-topic — Non-project chat
└── #show-what-you-built — Share projects

❓ SUPPORT
├── #help — General questions
├── #troubleshooting — Bug help
└── #feature-requests — Suggestions

🔧 TECHNICAL
├── #backend — Backend discussions
├── #frontend — Frontend discussions
└── #devops — Infrastructure discussions

🤝 COMMUNITY
├── #jobs — Job postings (if allowed)
├── #events — Meetups, conferences
└── #content — Blog posts, videos

📚 RESOURCES
├── #learning — Tutorials, courses
└── #tools — Useful tools and libraries
```

### Slack Channel Template

```
# welcome
# announcements (admin-only)
# general
# help
# random (off-topic)
# jobs (optional)
# introductions
# feedback
```

### Channel Guidelines

| Channel Type | Posting Rules | Moderation Level |
|--------------|---------------|------------------|
| **Announcements** | Admin only | N/A |
| **General** | On-topic discussion | Light |
| **Help** | Questions welcome, be patient | Medium |
| **Off-topic** | Anything goes (within CoC) | Light |
| **Jobs** | Structured format required | Heavy |
| **Introductions** | One post per person | Light |

---

## Onboarding Experience

### New Member Journey

```
Join Server
    ↓
Welcome Message (DM or public)
    ↓
Read Rules / Accept
    ↓
Verify (optional: GitHub, email)
    ↓
Introduce Yourself
    ↓
First Interaction
    ↓
Regular Member
```

### Welcome Message Template

**Discord DM:**
```
Welcome to [Community Name]! 👋

Here's how to get started:

1. Read the rules in #rules
2. Introduce yourself in #introductions
3. Ask questions in #help — we're friendly!

Quick links:
• Documentation: [link]
• Getting started: [link]
• GitHub: [link]

We're glad you're here!
```

**Public #welcome channel:**
```
# Welcome to [Community Name]!

We're [brief description of who you are and what you do].

## Quick Start

1. **Read the rules** → #rules
2. **Introduce yourself** → #introductions
3. **Get help** → #help
4. **Chat with us** → #general

## Useful Links

- [Documentation]
- [GitHub]
- [Website]

## Questions?

Drop a message in #help or mention @moderators
```

### Role Assignment

| Role | How to Get | Permissions |
|------|------------|-------------|
| **New Member** | Auto on join | Limited channels |
| **Member** | Verify or time-based | Full access |
| **Contributor** | PR merged, active helper | Badge, special channel |
| **Moderator** | Invited | Moderation powers |
| **Admin** | Core team | Full access |

---

## Engagement Programs

### Discussion Prompts

Schedule regular engagement:

| Day | Prompt Type | Example |
|-----|-------------|---------|
| Monday | This week's goals | "What are you working on this week?" |
| Wednesday | Technical question | "Controversial: Tabs or spaces?" |
| Friday | Show & Tell | "Share wh
