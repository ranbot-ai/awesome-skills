---
name: ai-md
description: Convert human-written CLAUDE.md into AI-native structured-label format. Battle-tested across 4 models. Same rules, fewer tokens, higher compliance. 
category: Document Processing
source: antigravity
tags: [api, claude, ai, llm, gpt, workflow, template, document, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/ai-md
---


# AI.MD v4 — The Complete AI-Native Conversion System

## When to Use This Skill

- Use when your CLAUDE.md is long but AI still ignores your rules
- Use when token usage is too high from verbose system instructions
- Use when you want to optimize any LLM system prompt for compliance
- Use when migrating rules between AI tools (Claude, Codex, Gemini, Grok)

## What Is AI.MD?

AI.MD is a methodology for converting human-written `CLAUDE.md` (or any LLM system instructions)
into a structured-label format that AI models follow more reliably, using fewer tokens.

**The paradox we proved:** Adding more rules in natural language DECREASES compliance.
Converting the same rules to structured format RESTORES and EXCEEDS it.

```
Human prose (6 rules, 1 line)  → AI follows 4 of them
Structured labels (6 rules, 6 lines) → AI follows all 6
Same content. Different format. Different results.
```

---

## Why It Works: How LLMs Actually Process Instructions

LLMs don't "read" — they **attend**. Understanding this changes everything.

### Mechanism 1: Attention Splitting

When multiple rules share one line, the model's attention distributes across all tokens equally.
Each rule gets a fraction of the attention weight. Some rules get lost.

When each rule has its own line, the model processes it as a distinct unit.
Full attention weight on each rule.

```
# ONE LINE = attention splits 5 ways (some rules drop to near-zero weight)
EVIDENCE: no-fabricate no-guess | 禁用詞:應該是/可能是 → 先拿數據 | Read/Grep→行號 curl→數據 | "好像"/"覺得"→自己先跑test | guess=shame-wall

# FIVE LINES = each rule gets full attention
EVIDENCE:
  core: no-fabricate | no-guess | unsure=say-so
  banned: 應該是/可能是/感覺是/推測 → 先拿數據
  proof: all-claims-need(data/line#/source) | Read/Grep→行號 | curl→數據
  hear-doubt: "好像"/"覺得" → self-test(curl/benchmark) → 禁反問user
  violation: guess → shame-wall
```

### Mechanism 2: Zero-Inference Labels

Natural language forces the model to INFER meaning from context.
Labels DECLARE meaning explicitly. No inference needed = no misinterpretation.

```
# AI must infer: what does (防搞混) modify? what does 例外 apply to?
GATE-1: 收到任務→先用一句話複述(防搞混)(長對話中每個新任務都重新觸發) | 例外: signals命中「處理一下」=直接執行

# AI reads labels directly: trigger→action→exception. Zero ambiguity.
GATE-1 複述:
  trigger: new-task
  action: first-sentence="你要我做的是___"
  persist: 長對話中每個新任務都重新觸發
  exception: signal=處理一下 → skip
  yields-to: GATE-3
```

Key insight: Labels like `trigger:` `action:` `exception:` work across ALL languages.
The model doesn't need to parse Chinese/Japanese/English grammar to understand structure.
**Labels are the universal language between humans and AI.**

### Mechanism 3: Semantic Anchoring

Labeled sub-items create **matchable tags**. When a user's input contains a keyword,
the model matches it directly to the corresponding label — like a hash table lookup
instead of a full-text search.

```
# BURIED: AI scans the whole sentence, might miss the connection
加新功能→第一句問schema | 新增API/endpoint=必確認health-check.py覆蓋

# ANCHORED: label "new-api:" directly matches user saying "加個 API"
MOAT:
  new-feature: 第一句問schema/契約/關聯
  new-api: 必確認health-check.py覆蓋(GATE-5)
```

**Real proof:** This specific technique fixed a test case that failed 5 consecutive times
across all models. The label `new-api:` raised Codex T5 from ❌→✅ on first try.

---

## The Conversion Process: What Happens When You Give Me a CLAUDE.md

Here's the exact mental model I use when converting natural language instructions to AI.MD format.

### Phase 1: UNDERSTAND — Read Like a Compiler, Not a Human

I read the CLAUDE.md **as if I'm building a state machine**, not reading a document.

For each sentence, I ask:
1. **Is this a TRIGGER?** (What input activates this behavior?)
2. **Is this an ACTION?** (What should the AI do?)
3. **Is this a CONSTRAINT?** (What should the AI NOT do?)
4. **Is this METADATA?** (Priority, timing, persistence, exceptions?)
5. **Is this a HUMAN EXPLANATION?** (Why the rule exists — delete this)

Example analysis:

```
Input: "收到任務→先用一句話複述(防搞混)(長對話中每個新任務都重新觸發) | 例外: signals命中「處理一下」=直接執行"

Decomposition:
  ├─ TRIGGER:    "收到任務" → new-task
  ├─ ACTION:     "先用一句話複述" → first-sentence="你要我做的是___"
  ├─ DELETE:     "(防搞混)" → human motivation, AI doesn't need this
  ├─ METADATA:   "(長對話中每個新任務都重新觸發)" → persist: every-new-task
  └─ EXCEPTION:  "例外: signals命中「處理一下」=直接執行" → exception: signal=處理一下 → skip
```

### Phase 2: DECOMPOSE — Break Every `|` and `()` Into Atomic Rules

The #1 source of compliance failure is **compound rules**.
A single line with 3 rules separated by `|` looks like 1 instruction to AI.
It needs to be 3 separate instructions.

**The splitter test:** If you can put "AND" between two parts of a sentence,
they are separate rules and MUST be on separate lines.

```
# Input: one sentence hiding 4 rules
禁用詞:應該是/可能是→先拿數據 | "好像"/"覺得"→自己先跑test(不是問user)→有數據才能決定

# Analysis: I find 4 hidden rules
Rule 1: certain words are banned → use data instead
Rule 2: hearing doubt words → run self-test
Rul
