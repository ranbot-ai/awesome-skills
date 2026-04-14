---
name: blog-writing-guide
description: This skill enforces Sentry's blog writing standards across every post — whether you're helping an engineer write their first blog post or a marketer draft a product announcement. 
category: Creative & Media
source: antigravity
tags: [javascript, ai, rag, cro, marketing]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/blog-writing-guide
---


# Sentry Blog Writing Skill

This skill enforces Sentry's blog writing standards across every post — whether you're helping an engineer write their first blog post or a marketer draft a product announcement.

**The bar:** Every Sentry blog post should be something a senior engineer would share in their team's Slack, or reference in a technical decision.

What follows are the core principles to internalize and apply to every piece of content.

## When to Use
- You need to draft or edit a Sentry blog post.
- The task involves technical storytelling, product announcements, or engineering deep-dives in Sentry's blog voice.
- You want blog content that is opinionated, specific, and technically credible rather than generic marketing copy.

## The Sentry Voice

**We sound like:** A senior developer at a conference afterparty explaining something they're genuinely excited about — smart, specific, a little irreverent, deeply knowledgeable.

**We don't sound like:** A corporate blog, a press release, a sales deck, or an AI-generated summary.

Be technically precise, opinionated, and direct. Humor is welcome but should serve the content, not replace it. Sarcasm works. One good joke per post is plenty.

Use "we" (Sentry) and "you" (the reader). This is a conversation, not a paper.

## Banned Language

Never use these. They are automatic red flags:

- "We're excited/thrilled to announce" — just announce it
- "Best-in-class" / "industry-leading" / "cutting-edge" — show, don't tell
- "Seamless" / "seamlessly" — nothing is seamless
- "Empower" / "leverage" / "unlock" — say what you actually mean
- "Robust" — describe what makes it robust instead
- "At [Company], we believe..." — just state the belief
- "Streamline" — everyone is streamlining, stop
- Filler transitions: "That being said," "It's worth noting that," "At the end of the day," "Without further ado," "As you might know"
- "In this blog post, we will explore..." — be direct, just start

## The Opening (First 2-3 Sentences)

The opening must do one of two things: **state the problem** or **state the conclusion**. Never start with background, company history, or hype.

**Good:** "Two weeks before launch, we killed our entire metrics product. Here's why pre-aggregating time-series metrics breaks down for debugging, and how we rebuilt the system from scratch."

**Bad:** "At Sentry, we're always looking for ways to improve the developer experience. Today, we're thrilled to share some exciting updates to our metrics product that we think you'll love."

## Structure: Follow the Reader's Questions

Structure every post around what the reader is actually wondering, not your internal narrative:

1. **What problem does this solve?** (1-2 paragraphs max)
2. **How does it actually work?** Not buttons-you-click, but underlying technology. (Bulk of the post — be specific)
3. **What were the trade-offs or alternatives?** (This separates good from great)
4. **How do I use/try/implement this?** (Concrete next steps)

For engineering deep-dives, also address:
5. **What did we try that didn't work?** (Builds trust)
6. **What are the known limitations?** (Shows intellectual honesty)

## Section Headings Must Convey Information

**Weak:** "Background," "Architecture," "Results," "Conclusion"

**Strong:** "Why time-series pre-aggregation destroys debugging context," "The scatter-gather approach to distributed GROUP BY," "Where this breaks down: the cardinality wall"

## Technical Quality Standards

**Numbers over adjectives.** If you make a performance claim, include the number.
- Bad: "This significantly reduced our error processing time."
- Good: "This reduced our p99 error processing time from 340ms to 45ms — a 7.5× improvement."

**Code must work.** If a post includes code, test it. Include imports, configuration, and context. Comments should explain *why*, not *what*.

**Diagrams for systems.** If you describe a system with more than two interacting components, include a diagram. Label with real service names, not generic boxes.

**Honesty over hype.** Never overstate what a feature does. Acknowledge limitations. If something is in beta, say so. If a competitor does something well, it's okay to note that. Do not claim AI features are more capable than they are — "Seer suggests a likely root cause" ≠ "Seer finds the root cause."

## Title Guidelines

The title is the highest-leverage sentence in the post. It must stop a developer scrolling through their RSS feed or Twitter.

**Strong titles** make a specific claim, tell a story, or promise a specific payoff:
- "The metrics product we built worked. But we killed it and started over anyway"
- "How we reduced release delays by 5% by fixing Salt"
- "Your JavaScript bundle has 47% dead code. Here's how to find it."

**Weak titles** are vague announcements:
- "Introducing our new metrics product"
- "Performance improvements in Sentry"
- "AI-powered debugging with Seer"

## The Closing

End with something useful — a link to docs, a way to
