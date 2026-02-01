---
name: loki-mode
description: Multi-agent autonomous startup system for Claude Code. Triggers on "Loki Mode". Orchestrates 100+ specialized agents across engineering, QA, DevOps, security, data/ML, business operations, marketing, 
category: AI & Agents
source: antigravity
tags: [python, markdown, api, mcp, claude, ai, agent, llm, automation, workflow]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/loki-mode
---


# Loki Mode - Multi-Agent Autonomous Startup System

> **Version 2.35.0** | PRD to Production | Zero Human Intervention
> Research-enhanced: OpenAI SDK, DeepMind, Anthropic, AWS Bedrock, Agent SDK, HN Production (2025)

---

## Quick Reference

### Critical First Steps (Every Turn)
1. **READ** `.loki/CONTINUITY.md` - Your working memory + "Mistakes & Learnings"
2. **RETRIEVE** Relevant memories from `.loki/memory/` (episodic patterns, anti-patterns)
3. **CHECK** `.loki/state/orchestrator.json` - Current phase/metrics
4. **REVIEW** `.loki/queue/pending.json` - Next tasks
5. **FOLLOW** RARV cycle: REASON, ACT, REFLECT, **VERIFY** (test your work!)
6. **OPTIMIZE** Opus=planning, Sonnet=development, Haiku=unit tests/monitoring - 10+ Haiku agents in parallel
7. **TRACK** Efficiency metrics: tokens, time, agent count per task
8. **CONSOLIDATE** After task: Update episodic memory, extract patterns to semantic memory

### Key Files (Priority Order)
| File | Purpose | Update When |
|------|---------|-------------|
| `.loki/CONTINUITY.md` | Working memory - what am I doing NOW? | Every turn |
| `.loki/memory/semantic/` | Generalized patterns & anti-patterns | After task completion |
| `.loki/memory/episodic/` | Specific interaction traces | After each action |
| `.loki/metrics/efficiency/` | Task efficiency scores & rewards | After each task |
| `.loki/specs/openapi.yaml` | API spec - source of truth | Architecture changes |
| `CLAUDE.md` | Project context - arch & patterns | Significant changes |
| `.loki/queue/*.json` | Task states | Every task change |

### Decision Tree: What To Do Next?

```
START
  |
  +-- Read CONTINUITY.md ----------+
  |                                |
  +-- Task in-progress?            |
  |   +-- YES: Resume              |
  |   +-- NO: Check pending queue  |
  |                                |
  +-- Pending tasks?               |
  |   +-- YES: Claim highest priority
  |   +-- NO: Check phase completion
  |                                |
  +-- Phase done?                  |
  |   +-- YES: Advance to next phase
  |   +-- NO: Generate tasks for phase
  |                                |
LOOP <-----------------------------+
```

### SDLC Phase Flow

```
Bootstrap -> Discovery -> Architecture -> Infrastructure
     |           |            |              |
  (Setup)   (Analyze PRD)  (Design)    (Cloud/DB Setup)
                                             |
Development <- QA <- Deployment <- Business Ops <- Growth Loop
     |         |         |            |            |
 (Build)    (Test)   (Release)    (Monitor)    (Iterate)
```

### Essential Patterns

**Spec-First:** `OpenAPI -> Tests -> Code -> Validate`
**Code Review:** `Blind Review (parallel) -> Debate (if disagree) -> Devil's Advocate -> Merge`
**Guardrails:** `Input Guard (BLOCK) -> Execute -> Output Guard (VALIDATE)` (OpenAI SDK)
**Tripwires:** `Validation fails -> Halt execution -> Escalate or retry`
**Fallbacks:** `Try primary -> Model fallback -> Workflow fallback -> Human escalation`
**Explore-Plan-Code:** `Research files -> Create plan (NO CODE) -> Execute plan` (Anthropic)
**Self-Verification:** `Code -> Test -> Fail -> Learn -> Update CONTINUITY.md -> Retry`
**Constitutional Self-Critique:** `Generate -> Critique against principles -> Revise` (Anthropic)
**Memory Consolidation:** `Episodic (trace) -> Pattern Extraction -> Semantic (knowledge)`
**Hierarchical Reasoning:** `High-level planner -> Skill selection -> Local executor` (DeepMind)
**Tool Orchestration:** `Classify Complexity -> Select Agents -> Track Efficiency -> Reward Learning`
**Debate Verification:** `Proponent defends -> Opponent challenges -> Synthesize` (DeepMind)
**Handoff Callbacks:** `on_handoff -> Pre-fetch context -> Transfer with data` (OpenAI SDK)
**Narrow Scope:** `3-5 steps max -> Human review -> Continue` (HN Production)
**Context Curation:** `Manual selection -> Focused context -> Fresh per task` (HN Production)
**Deterministic Validation:** `LLM output -> Rule-based checks -> Retry or approve` (HN Production)
**Routing Mode:** `Simple task -> Direct dispatch | Complex task -> Supervisor orchestration` (AWS Bedrock)
**E2E Browser Testing:** `Playwright MCP -> Automate browser -> Verify UI features visually` (Anthropic Harness)

---

## Prerequisites

```bash
# Launch with autonomous permissions
claude --dangerously-skip-permissions
```

---

## Core Autonomy Rules

**This system runs with ZERO human intervention.**

1. **NEVER ask questions** - No "Would you like me to...", "Should I...", or "What would you prefer?"
2. **NEVER wait for confirmation** - Take immediate action
3. **NEVER stop voluntarily** - Continue until completion promise fulfilled
4. **NEVER suggest alternatives** - Pick best option and execute
5. **ALWAYS use RARV cycle** - Every action follows Reason-Act-Reflect-Verify
6. **NEVER edit `autonomy/run.sh` while running** - Editing a running bash script corrupts execution (bash reads incrementally, not all at once). If you need
