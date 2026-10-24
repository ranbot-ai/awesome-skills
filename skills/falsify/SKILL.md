---
name: falsify
description: The scientific thinking protocol for AI agents. Use when facing complex, ambiguous, or high-stakes questions where guessing is costly: hypothesis → attempt to break it → evidence → calibrated co
category: Document Processing
source: antigravity
tags: [markdown, claude, ai, agent, llm, template, design, document, security, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/falsify
---


# Falsify — The Scientific Thinking Protocol

> Think like a first-rate scientist: doubt first, verify, then believe.
> 像一流科学家一样思考：先证伪，再相信；先标不确定，再下结论。

## Overview

falsify is a Markdown reasoning framework with bundled references and a ledger template. It can help organize hypotheses and external evidence; it does not guarantee accuracy, calibration or compatibility with every agent. Named concepts are prompts for review, not a validated combined scientific protocol; the complete claimed 70-source derivation is not documented here.

## The Iron Law


```
NO VERDICT WITHOUT A FALSIFIABLE HYPOTHESIS.
没有可证伪的假设，就没有结论。
```

<EXTREMELY-IMPORTANT>
For empirical claims, identify observations that could change the conclusion. Definitions, mathematics, value judgments and underdetermined evidence require a different validation method; do not force a falsification test onto every answer. A confident answer with no falsification path is not an answer — it is a guess wearing a lab coat. There is no exception for "obvious" or "well-known" or "everyone knows" — those are exactly the claims that need falsifying most.
</EXTREMELY-IMPORTANT>

## MODE SELECTION — route BEFORE answering (mandatory)

First decide which mode this question is, then act accordingly. **Do not run the five stages unless you picked Depth.** The wrong mode is itself a protocol failure.

| If the ask is... | Mode | Do |
|---|---|---|
| Live incident / production down / outage / "act now" / degrading | **Incident (OODA)** | **Follow the authorized incident runbook** with the evidence needed for the risk with a known rollback and a time box. Do NOT run the five stages. Stabilize, then falsify the effect. Never demand certainty before a reversible action under time pressure. |
| Trivial / one-lookup fact / small talk / zero consequence | **Simple** | Answer briefly and directly. No protocol, no follow-up questions, no stage labels. |
| Rough estimate / ballpark / "about how much" / "大概" (low-stakes, reversible) | **Nudge** | Give the helpful estimate with its main assumption stated, then 2–3 targeted questions. No five-stage ledger. If being wrong costs time/money/trust, escalate to Depth. |
| Under-specified / unfalsifiable / missing key inputs | **Question** | Ask only the few missing inputs that block a safe answer; provide a default only where justified. Do not conclude, do not fabricate a default justification. |
| High-stakes / correctness gate / "why" about a failing system / will be acted on | **Depth** | Run the five stages below. |

In an incident, the Iron Law means "act reversibly, then falsify the effect" — never "analyze first, act later".

## When to Use This Skill


**Activate (depth mode)** for:
- Architecture / design decisions with trade-offs
- "Why" questions about a failing system or data anomaly
- Recommendations that will be acted on (a library, a fix, a strategy)
- Claims about what a user, market, or system "will" do
- Anything where being wrong costs time, money, or trust


**Default to Nudge (not depth) when the ask is a rough ballpark** — "rough estimate", "ballpark", "about how much", "大概", "粗略": give the helpful estimate directly with its main assumption stated, then 2–3 questions. A rough number is not a correctness gate; forcing a five-stage ledger onto it is protocol theater. **Exception — high-stakes ballparks go to Depth:** if the estimate will be acted on and an error costs time, money, or trust (a rough medication dose, security capacity, production sizing), do NOT nudge: gather the key inputs, state the uncertainty, and falsify before giving the number. The shortcut only pays when the error is cheap.

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
- If you catch any of these, name it sile
