---
name: email-marketing-bible
description: Data-backed email marketing for AI agents: automation flows, deliverability triage, copy de-slopping, AI email design, ESP control via MCP with send gates and compliance. 
category: AI & Agents
source: antigravity
tags: [react, api, mcp, claude, ai, agent, llm, gpt, automation, workflow]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/email-marketing-bible
---


# Email Marketing Bible

## Overview

The Email Marketing Bible turns an agent into an email marketing operator. It covers building automation flows, segmenting audiences, writing and de-slopping copy, directing email design, diagnosing deliverability, and operating an ESP through MCP or connectors behind hard pre-send gates. Part A is the operating manual for when the agent acts; Part B is the dense reference (metrics, flows, deliverability, compliance, platforms, benchmarks and 19 industry playbooks).

Adapted from the official skill at [CosmoBlk/email-marketing-bible](https://github.com/CosmoBlk/email-marketing-bible) (v2.7, 8 Sep 2026, MIT) by George Hartley, co-founder of Nitrosend. It is distilled from a 19-chapter guide built on 908 sources ([nitrosend.com/email-marketing-bible](https://nitrosend.com/email-marketing-bible)) and from running SmartrMail (about 12,000 customers, 6 billion emails). Figures are mid-2026; verify anything volatile (inbox rules, ESP features, pricing, model names) before acting.

## When to Use This Skill

- Use when building or editing email automation flows: welcome, abandoned cart, browse abandonment, post-purchase, win-back, sunset.
- Use when an agent drives an ESP through MCP, a connector or an API (Klaviyo, Mailchimp, Resend, Nitrosend and similar) to create segments, flows or campaigns.
- Use when diagnosing deliverability: spam or Promotions placement, bounce or complaint spikes, SPF, DKIM and DMARC problems, warm-up and ESP migrations.
- Use when writing, reviewing or de-slopping email copy, subject lines and CTAs.
- Use when directing AI email design or critiquing a rendered email.
- Use when choosing an ESP, pulling benchmarks, checking compliance (CAN-SPAM, GDPR, CASL, Australian Spam Act), or planning cold email, WhatsApp, SMS or RCS.

## How It Works

### Step 1: Apply the hard gates

Read section 0 before touching a real account. Every segment, draft, campaign, flow or staged send on a live ESP is real, and nothing goes to more than one recipient without explicit human approval in the conversation.

### Step 2: Route the task

Use the task router (section 1) to jump to the right section, and gather the listed inputs before acting.

### Step 3: Read, reason, act, verify

Read account state first (lists, flows, recent campaigns, deliverability, suppressions), change one thing at a time, and verify it against real counts.

### Step 4: Show the pre-send packet and wait

Run the pre-send checklist (section 3), show the packet (preview URL, audience size, suppressions, subject, preview text, send time, sender, unsubscribe, compliance risk) and wait for an explicit "send it".

## Part A: Operating Manual

### 0. AGENT OPERATING RULES

Every segment, draft, campaign, flow or staged send on a real ESP is live. **Hard gates, never skip:**
- **No send or schedule to more than one recipient without explicit human approval in this conversation** ("send it" or equivalent). Single-recipient test sends still need a yes.
- **Preview before asking; show the packet before any send:** preview URL, audience size, exclusions/suppressions applied, subject, preview text, send time, from-name + reply-to, unsubscribe present, compliance risk.
- **Block the send** if authentication is missing, unsubscribe or physical address is absent, complaint rate is at or above 0.1%, consent basis is unclear, or the audience includes suppressed, bounced or complained contacts.
- **Never probe unknown mutating endpoints on a live audience.** `/send`, `/dispatch`, `/trigger`, `/fire`, `/publish` paths can dispatch immediately; if the approve-scheduled path is unclear, ask the human to click it. Test on sandboxes or cloned campaigns with seed lists.
- **Separate the modes.** Transactional, marketing, lifecycle and cold outbound have different rules, domains and consent bases. Never mix them.
- **Log every autonomous action** (segment changed, flow edited, campaign created, send staged) so the human can audit it.

### 1. TASK ROUTER

| Intent | Go to | Gather first |
|---|---|---|
| Audit a programme | §2, then the reference | read access, recent sends |
| Build a flow | §7 + §2 | model, trigger, audience, offer, exclusions |
| Send a campaign | §3 | segment, consent basis, copy, sender, timing |
| Diagnose deliverability | §11 | domain, ESP, bounce + complaint rate, recent changes |
| Write or de-slop copy | §4 | audience, offer, voice, one real proof |
| Design an email | §5 + §16 | brand tokens, archetype, goal |
| Pick a platform | §15 | list size, use case, stack, budget, agent-driven? |
| Pull a benchmark | Appendix | industry, email type |
| Cold outbound | §14 | offer, ICP, domains, volume |
| WhatsApp / SMS / RCS | §Messaging | channel, consent basis, region |

### 2. AI EMAIL AUTOMATION (the operating model)

The marketer moved from operator to director: brief the agent, govern it, own the send button. Most major ESPs now ship a human-gated prompt-to-campaign agent, an MCP server or a Claude
