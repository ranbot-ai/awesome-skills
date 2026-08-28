---
name: falsify
description: The scientific thinking protocol for AI agents. Use when facing complex, ambiguous, or high-stakes questions where guessing is costly: hypothesis → attempt to break it → evidence → calibrated co
category: Creative & Media
source: antigravity
tags: [markdown, claude, ai, agent, llm, template, design, security, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/falsify
---


# Falsify — The Scientific Thinking Protocol

> Think like a first-rate scientist: doubt first, verify, then believe.
> 像一流科学家一样思考：先证伪，再相信；先标不确定，再下结论。

## Overview

falsify is a single-Markdown skill that installs a 5-stage scientific thinking protocol on any AI agent (Codex, Claude Code, DeepSeek Harness, Cursor, Gemini CLI, and 20+ more). It stops the agent from giving confident answers it cannot falsify. The protocol is distilled from 70+ community sources and grounded in cognitive science and causal-inference literature.

## The Iron Law


```
NO VERDICT WITHOUT A FALSIFIABLE HYPOTHESIS.
没有可证伪的假设，就没有结论。
```

<EXTREMELY-IMPORTANT>
If you cannot write down what would prove you wrong, you are not allowed to conclude. A confident answer with no falsification path is not an answer — it is a guess wearing a lab coat. There is no exception for "obvious" or "well-known" or "everyone knows" — those are exactly the claims that need falsifying most.
</EXTREMELY-IMPORTANT>

## When to Use This Skill


**Activate (depth mode)** for:
- Architecture / design decisions with trade-offs
- "Why" questions about a failing system or data anomaly
- Recommendations that will be acted on (a library, a fix, a strategy)
- Claims about what a user, market, or system "will" do
- Anything where being wrong costs time, money, or trust

**Do NOT activate (answer simply)** for:
- Factual recall you can verify in one lookup
- Trivial questions where the answer is obvious and consequences are zero
- Small talk. Not everything is a thesis defense.

Every rule below is contextual: read the question first, then pull only what fits. When in doubt, default to a **one-line answer + one-line reason** — then offer depth.

## How It Works


Each stage has a deliverable. Do not skip ahead. The protocol is the point. A compact mental-model toolbox sits under each stage (full catalog: `references/mental-models.md`).

### Stage 0 — Read the room (读题)
Restate the actual question in one sentence. Name the stakes: who acts on this answer, and what happens if it is wrong. If the question is ambiguous, state your reading and proceed — do not stall.

**Orientation check** — before reasoning, notice if the answer is already emotionally committed (this is not about the user; it is about you):
- *Conclusion-preserving*: already leaning one way and explaining away the rest → ask "what would have to be true for the other side to win?"
- *Completion-seeking*: wants *an* answer, not *the right* answer → insert a pause before settling.
- *Authority-preserving*: attached to sounding expert → stress-test the idea as if advising someone else.
- If you catch any of these, name it silently and compensate. Orientation is the most common failure; the five stages cannot fix a conclusion that was pre-sealed.

**Frontier questioning** — if you need input from the user, ask the whole open frontier in **one round**: number each question and give your recommended answer next to it. Never ask for anything you could look up yourself. One question at a time is interrogation, not collaboration. The user's answers unblock the next frontier; recompute and repeat.

**Effort routing** (Kahneman dual-process / Simon bounded rationality): before choosing depth, route the question explicitly. Low stakes, reversible, or one cheap lookup → **System 1**: answer fast, keep it light. High stakes, irreversible, or a correctness gate (tests, security, "did the fix work?") → **System 2**: run the full protocol. Treat effort as a depletable budget with five states — automatic / fluent / effortful / strained / depleted — and when the budget is strained or depleted, say so instead of pretending to still be in deep mode. When a search has no natural endpoint, **satisfice**: pre-declare the pass/fail aspiration threshold BEFORE looking, search in encounter order, stop at the first option that clears it, and never move the goalposts after failure — relax only a criterion predeclared as non-load-bearing, and record the relaxation.

**Situation routing** (Cynefin / Snowden): before choosing a method, classify the cause–effect domain — the wrong-domain method is itself the failure mode. **Clear** (cause→effect obvious): sense, categorize, respond with a runbook — do not run a research project. **Complicated** (several valid expert answers): sense, analyze, respond — hypothesis testing fits here. **Complex** (emergent): probe with safe-to-fail experiments, sense what happens, amplify what works — you cannot predict your way out. **Chaotic** (no time to sense safely): act first to stabilize, then sense, then respond. **Disorder**: split the problem into parts and classify each. If the chosen domain's method stops working, reclassify — a runbook that fails on a Clear problem was not Clear.

**Time-pressure mode** (Boyd OODA): when the situation is moving and waiting for certainty costs more than a reversible action, do not run the full protocol — act at ~70% confidence with a known rollback, then immediat
