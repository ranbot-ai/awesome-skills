---
name: developer-advocacy
description: When the user wants to do developer advocacy activities including conference talks, live coding, podcasts, and building in public. Trigger phrases include "developer advocacy," "devrel," "conference t
category: Security & Systems
source: antigravity
tags: [react, markdown, ai, agent, template, security, vulnerability, kubernetes, aws, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/developer-advocacy
---


# Developer Advocacy
## When to Use

Use this skill when you need when the user wants to do developer advocacy activities including conference talks, live coding, podcasts, and building in public. Trigger phrases include "developer advocacy," "devrel," "conference talk," "CFP," "call for papers," "live coding," "podcast," "building in public,"...


This skill helps you with developer advocacy activities: conference talks, live coding demos, podcast appearances, and building in public. Covers talk proposals, demo prep, social presence, and measuring impact.

---

## Before You Start

**Load your audience context first.** Read `.agents/developer-audience-context.md` to understand:

- Who you're trying to reach (conferences they attend, podcasts they listen to)
- What topics resonate (pain points, interests)
- Your product's positioning (what story to tell)
- Voice & tone (how formal/technical to be)

If the context file doesn't exist, run the `developer-audience-context` skill first.

---

## Conference Talks

### Finding the Right Conferences

| Conference Type | Best For | Examples |
|-----------------|----------|----------|
| **Large industry** | Brand awareness, reach | KubeCon, AWS re:Invent, React Summit |
| **Regional** | Local community, accessible | Local meetups, city tech conferences |
| **Niche** | Targeted audience, expertise | GraphQL Conf, RustConf |
| **Company-hosted** | Ecosystem presence | Vercel Ship, GitHub Universe |
| **Unconferences** | Community connection | BarCamps, DevOpsDays |

### Talk Proposal (CFP) Framework

**The winning formula:**
```
Specific Problem + Unique Angle + Clear Takeaways = Accepted Talk
```

**CFP Template:**

```markdown
# Title
[Action verb] + [specific outcome] + [with/using what]
Example: "Building Real-Time Features with Edge Functions and WebSockets"

# Abstract (100-200 words)
[Hook: Problem or curiosity gap]
[What you'll cover]
[What attendees will learn/be able to do]

# Description (detailed, for reviewers)
[Problem context]
[Why this approach]
[Talk structure]
[Your credibility to give this talk]

# Outline
- [Time] Introduction / Problem statement
- [Time] Section 1
- [Time] Section 2
- [Time] Section 3
- [Time] Live demo / walkthrough
- [Time] Key takeaways / Q&A

# Audience
[Who this is for]
[Prerequisite knowledge]
[What they'll learn]

# Bio
[Your relevant experience]
[Why you're qualified]
```

### Title Patterns That Work

| Pattern | Example |
|---------|---------|
| **How I X** | "How I Reduced Deploy Time by 80%" |
| **X in Y Minutes** | "Kubernetes Security in 15 Minutes" |
| **The X of Y** | "The Psychology of Error Messages" |
| **Beyond X** | "Beyond Console.log: Modern Debugging" |
| **X for Y** | "GraphQL for REST Developers" |
| **Lessons from X** | "Lessons from 1000 Production Outages" |

### Talk Types

| Type | Length | Best For |
|------|--------|----------|
| **Lightning** | 5-10 min | Single concept, quick demo |
| **Standard** | 25-45 min | Technical deep-dive |
| **Keynote** | 45-60 min | Big picture, inspiring |
| **Workshop** | 2-4 hours | Hands-on learning |
| **Panel** | 30-60 min | Discussion, multiple perspectives |

### Talk Prep Checklist

| Phase | Tasks |
|-------|-------|
| **2 months before** | Outline, start slides, test demos |
| **1 month before** | Draft complete, first practice run |
| **2 weeks before** | Slides polished, demos solid, practice 3x |
| **1 week before** | Record yourself, get feedback, finalize |
| **Day before** | Test all tech, backup slides, rest |
| **Day of** | Arrive early, test A/V, hydrate |

---

## Live Coding & Demos

### The Demo Danger Zone

| Risk | Mitigation |
|------|------------|
| **Internet fails** | Pre-record backup, local server |
| **Typo freezes you** | Practice typing same code 20x |
| **Error you can't fix** | Have working checkpoints to jump to |
| **Runs over time** | Time yourself, cut ruthlessly |
| **Code too small** | Zoom in, use large font (24pt+) |
| **Dark theme blinding** | Use high-contrast, light-friendly theme |

### Demo Prep Framework

**The 10-3-1 Rule:**
- Run your demo **10 times** in practice
- Have **3 checkpoints** you can jump to if stuck
- **1 backup** (video recording of it working)

**Pre-demo checklist:**
- [ ] Close unnecessary apps
- [ ] Clear browser history/tabs
- [ ] Notifications OFF (Slack, email, calendar)
- [ ] Font size: 24pt+ for terminal, 20pt+ for editor
- [ ] Git stash/branch for clean starting point
- [ ] Environment variables ready
- [ ] Test on the actual projector/screen if possible

### Live Coding Tips

| Tip | Why |
|-----|-----|
| **Type slowly** | Audience needs to follow |
| **Narrate what you type** | "I'm creating a new handler..." |
| **Explain errors** | "This error means X, let me fix it" |
| **Use snippets** | For boilerplate, not core concepts |
| **Show the result** | Always run the code, show output |
| **Checkpoint commits** | `git checkout checkpoint-1` |

---

## Podcast Guesting

### Finding Podcasts

|
