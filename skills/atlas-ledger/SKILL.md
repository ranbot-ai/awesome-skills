---
name: atlas-ledger
description: Companion to atlas-contract. Auto-invoked by its Final Audit on caught drift; also use after Post Reviews or user requests to record a mistake. Distills drift into WHEN/DON'T/INSTEAD clauses, writes t
category: Development & Code Tools
source: antigravity
tags: [api, ai, agent, design, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/atlas-ledger
---


# Atlas Ledger v2.2

Give the Atlas series a memory.

## Contents

1. [Output Language](#1-output-language)
2. [When To Run](#2-when-to-run)
3. [Distillation (the core)](#3-distillation-the-core) — Steps 1–6
4. [Atlas.md format](#4-atlasmd-format)
5. [Clause maintenance](#5-clause-maintenance-keep-the-ledger-alive-not-ossified)
6. [Integration with atlas-contract](#6-integration-with-atlas-contract-the-read-back-half)
7. [Final Principle](#7-final-principle)

## Quick reference

```text
caught drift (auto handoff from Final Audit / Post Review / Phase Check / user request)
 → Step 1  state facts, not motive
 → Step 2  draft WHEN / DON'T / INSTEAD
 → Step 3  four gates: Actionability → Replay → Generalization → Over-reach
 → Step 4  first occurrence = Observation [O#]; repeat or high-severity = Clause [L#]
 → Step 5  propose, ATLAS_STOP, write only after user confirms
 → Step 6  merge-first into Atlas.md; confirmed clauses ≤ 15
```

`atlas-contract` defends the goal **within one conversation**, but it starts from zero every time — it does not know where this project drifted before. `atlas-ledger` closes that gap: when a drift is caught, it distills the lesson into a permanent, project-local **contract clause** and (after the user confirms) writes it to `Atlas.md`. Next time `atlas-contract` builds a Goal Contract, it loads the relevant clauses, so the defense line thickens with each catch. That is the compounding effect.

It is a **low-frequency, lightweight** companion. It runs only after a drift is caught, and it stays small on purpose. Do not turn it into a second heavy governance skill — its only hard job is distillation quality.

## Core idea

The job is **not** to keep a diary. A record of "what went wrong" is a memory; it changes nothing. The job is a translation:

> turn *this caught drift* → into *a clause that can enter a future contract and trigger a stop*.

A diary says "I hid the feature." A ledger clause says "WHEN a backend requirement is blocked, DON'T hide the feature, INSTEAD stop and disclose." Only the second one catches it next time. The entire value of this skill is the quality of that translation — and since it is run by the same model that drifted, the mechanisms below exist to keep it honest rather than trusting it to be careful.

---

# 1. Output Language

Write `Atlas.md` and all user-facing output in the language of the user's current instruction.

**Machine keys stay in English; clause content is localized.** Never translate the keys `WHEN` / `DON'T` / `INSTEAD`, the IDs (`L1`, `O1`), `seen`, `severity`, `Source`, `RETIRED`, or section headers `Confirmed Clauses` / `Provisional Observations` — atlas-contract parses these, and translating them makes the read-back unstable. The text after each key is written in the user's language. (E.g. `WHEN: 硬性 Must-Do 的后端部分受阻` — key English, content Chinese. Do **not** write `当: ...`.)

**Every process label this skill emits to the user must also be localized** (these are not machine keys — they are headings shown to the user, like the four gate names or the candidate-clause header). Only the fixed machine keys above stay English.

Chinese label mapping (process labels — localize these):

- `Atlas Event` → `Atlas 事件`; `Event ID` → `事件编号`; `Type` → `类型`; `Trigger Source` → `触发来源`; `Phase` → `阶段`; `Stop Status` → `停止状态`
- `Candidate Clause` / `Suggested Clause` → `候选条款`; `Proposal` → `提案`; `awaiting confirmation` → `等待确认`
- `Four acceptance gates` → `四道闸自检`; `Actionability` → `可执行性`; `Replay` → `回放`; `Generalization` → `泛化`; `Over-reach` → `误伤`; `Pass` → `通过`; `Fail` → `失败`
- `confirmed on first occurrence` → `首次出现即确认`; `merged` → `已合并`; `retired` → `已退休`; `review: stale` → `待复核：可能失效`

**Pre-output localization self-check:** Before sending any user-facing output, scan for untranslated English process labels (e.g. "Suggested Clause", "Actionability"). If any are found, translate them before sending. Do **not** translate the fixed machine keys (`WHEN`/`DON'T`/`INSTEAD`/IDs/`severity`/`Source`/`seen`/`Confirmed Clauses`/`Provisional Observations`) — those stay English even in a Chinese response.

---

## When to Use

# 2. When To Run

Run distillation only when a drift has been **caught**. Triggers, in order of how they usually arrive:

1. **Automatic handoff from atlas-contract (primary path).** When an `atlas-contract` **Final Audit** records one or more hard deviations (a hard Deviation Notice was raised, or an item is Violation / Partial / Unverified that should have been Complete), the contract skill invokes this distillation **immediately and without asking** — the candidate clause is proposed right after the audit, and the flow stops at the write-confirmation. The user should never have to remember to ask for the recording.
2. an `atlas-contract` **Post Review** (the user said the result was wrong / incomplete / downgraded / mocked);
3. a **Phase Check** catches the same class of error recurring;
4. the user explicitly says "record this so i
