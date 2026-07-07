---
name: effective-agent-skills
description: Author and review high-quality agent skills with triggers, progressive disclosure, and safety notes. 
category: AI & Agents
source: antigravity
tags: [python, pdf, markdown, api, mcp, claude, ai, agent, llm, automation]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/effective-agent-skills
---


# Agent Skills: A Complete Guide

## When to Use

- Use when creating, editing, reviewing, or debugging an agent SKILL.md file.
- Use when you need quality guidance for triggers, examples, limitations, and safety notes.

A consolidated reference on what agent skills are, why they exist, how they work, and how to write effective ones.

---

## 1. What agent skills are

An Agent Skill is a folder containing a `SKILL.md` file (YAML frontmatter + markdown instructions), plus optional subfolders for scripts, references, and assets that the agent loads on demand.

```
my-skill/
├── SKILL.md          # Required: metadata + instructions
├── scripts/          # Optional: executable code (CLIs, validators, helpers)
├── references/       # Optional: detailed docs loaded only when needed
└── assets/           # Optional: templates, fonts, static files
```

Skills are an open standard (agentskills.io), originally created by Anthropic and adopted by OpenAI Codex, Cursor, Gemini CLI, Microsoft Agent Framework, Google ADK, and 40+ other agent products. A skill written once works across all compatible agents.

---

## 2. Why this abstraction exists

Base LLMs are generalists. Real work requires procedural knowledge, organizational context, and repeatable workflows. Every prior alternative had a failure mode:

| Approach | Problem |
|---|---|
| Stuff it into the system prompt | Always loaded → context bloat at scale |
| Re-paste instructions each session | No version control, no consistency |
| Fine-tuning | Slow, expensive, opaque, vendor-locked |
| MCP servers alone | Give the agent tools but no workflows for using them |

Skills solve four problems at once:

- **Context efficiency** — instructions load only when relevant
- **Repeatability** — multi-step procedures become auditable workflows
- **Composability** — multiple skills combine at runtime per task
- **Portability** — same files work across vendors and surfaces

Mental model: skills are to LLMs what man pages, runbooks, and team handbooks are to engineers — reference material loaded into working memory only when the task demands it.

---

## 3. How they work — progressive disclosure

The architectural core. Three-stage loading:

**Level 1 — Discovery (~100 tokens per skill, always in context):**
Only `name` + `description` from frontmatter are injected into the system prompt at startup. Agent knows the skill exists and when it applies. You can install dozens of skills with negligible overhead.

**Level 2 — Activation (<5,000 tokens, loaded on match):**
When the user's request matches a skill's description, the agent reads the full `SKILL.md` body into context.

**Level 3 — Execution (unbounded, on demand):**
The agent reads referenced files (`references/foo.md`) or runs scripts (`scripts/validate.py`) only as needed. Scripts can execute without their source being loaded into context at all.

This is why bundled content has no practical limit. Files don't consume tokens until accessed.

---

## 4. SKILL.md anatomy

```markdown
---
name: skill-name
description: What this skill does AND when to use it. Include trigger phrases the user will say.
---

# Skill Name

## Quick start
[Minimal working example]

## Workflow
[Step-by-step procedure with checklists]

## Output format
[What the user/agent should expect back]

## Advanced
[Link to references/ for rarely-needed detail]
```

Frontmatter constraints:
- `name` is lowercase, hyphens only, 1–64 chars, **exactly matches the parent folder name**
- Avoid `<` and `>` in frontmatter (they can inject into the system prompt)
- Invalid YAML silently prevents loading

Optional standard fields:
- `disable-model-invocation: true` — stops the agent from auto-loading the skill based on the conversation; it can only be triggered manually (e.g. `/skill-name`). Now a standard Agent Skills spec field, so it works across spec-compliant clients (Claude Code, Copilot, etc.), not just Claude. Caveat: it prevents auto-invocation, but some clients (Claude Code, open bug) still inject the `description` into context, so it doesn't always save the discovery-level tokens. Use for manual-only utilities you don't want firing automatically.

---

## 5. Two design philosophies

Skills tend to fall into one of two patterns. Both are valid; they solve different problems.

### Pattern A — Capability primitives (tool wrappers)
The skill is a thin wrapper over a deterministic CLI or script. Logic lives in code. SKILL.md teaches the agent how to invoke it.

- **Adds**: new capabilities (search, email, browser, API access)
- **Reliability via**: shell tools, not prompts
- **Typical length**: 30–80 lines, mostly command examples
- **Use when**: the bottleneck is "the agent can't do X"

### Pattern B — Process primitives (cognitive disciplines)
The skill encodes a methodology the agent should follow. Pure prompt engineering — no scripts needed.

- **Adds**: structured workflows (TDD, code review, design alignment, debugging loops)
- **Reliability via**: exp
