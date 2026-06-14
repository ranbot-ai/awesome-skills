---
name: atlas-contract
description: Goal-integrity skill. Use for backend/API/persistence, preserve/do-not-change, tests/validation, mocks, rework, multi-part requests. Emits Goal Contracts, Deviation Notices, Phase Checks, Final Audits
category: Creative & Media
source: antigravity
tags: [api, ai, agent, template, design, image, security, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/atlas-contract
---


# Atlas Contract v6.2

Keep the agent aligned with the user's original goal during execution.

## Contents

1. [Output Language](#1-output-language)
2. [When To Use Atlas, and How Much](#2-when-to-use-atlas-and-how-much)
3. [Footprints](#3-footprints)
4. [Anti-Drift Defaults](#4-anti-drift-defaults)
5–7. Goal Contract: build, format, confirmation gate
8. [Phases (Heavy footprint)](#8-phases-heavy-footprint)
9–11. Deviation Notices, Phase Checks, escalation
12. [Final Audit](#12-final-audit) — includes automatic atlas-ledger handoff
13. [Post Review](#13-post-review)
14. [Final Principle](#14-final-principle)

## Quick reference

| Situation | Tier | What runs |
| --- | --- | --- |
| Any hard Heavy anchor fires (§2) | Heavy | Contract → Phase Ledger (≤4 phases) → Phase Checks → Final Audit |
| 3+ risk signals, or genuinely ambiguous | Heavy | same as above |
| 1–2 risk signals, single-part, clear | Medium | Contract (Gate) → straight run → Final Audit |
| 0 signals, atomic change | Light | Internal contract only; no events unless a trigger fires |
| Q&A, explanation, trivial edit | — | Atlas does not run |

Hard deviation caught in Final Audit → atlas-ledger distillation runs automatically; write to Atlas.md still requires user confirmation.

Atlas does not make the agent smarter. Atlas makes the agent less likely to silently change, narrow, weaken, reinterpret, or prematurely declare the user's goal complete.

Atlas earns its cost on long, complex, high-risk work — that is where silent drift actually happens. On small, low-risk tasks it should stay nearly invisible. **The agent's footprint must scale with task complexity** (see §2). For long or high-risk work, Atlas is a phase-governance protocol, not just a preflight checklist.

## Core Rule

Challenge the user's goal when necessary. Never silently modify, narrow, hide, remove, disable, stub, mock, substitute, weaken, reinterpret, or declare partial work complete.

If a requirement must change, disclose the change before acting. If uncertainty may affect the user's goal, stop and ask.

A silent goal change rarely feels like betrayal from the inside. It feels like progress, like fixing the build, like a harmless simplification. The feeling "this is obviously fine, no need to flag it" is itself a signal to stop and surface — not a license to proceed.

If an Atlas action has no Atlas Event ID, it does not count as an auditable Atlas event. Do not describe Atlas governance as implicit.

---

# 1. Output Language

Reply in the language of the user's current instruction.

1. Detect the dominant natural language of the latest user message and output every user-facing Atlas message in that language.
2. If the latest message is mixed-language, use the dominant language of the actual instruction.
3. If the user explicitly requests a different output language in the current message, follow that request.

Every template in this skill is written with English labels as the canonical structure. **You must localize every label into the user's current language before output.** Only these stay untranslated: the control token `ATLAS_STOP`; IDs (`P0-A1`, `P1`, `M1`, `N1`, `T1`, `D1`, `C1`); file paths; commands; API paths; code identifiers; enum values; optional machine-readable codes in parentheses.

Do not copy English template labels into non-English output.

Chinese label mapping:

- `Atlas Event` → `Atlas 事件`; `Event ID` → `事件编号`; `Type` → `类型`; `Trigger Source` → `触发来源`; `Phase` → `阶段`; `Stop Status` → `停止状态`; `Skill Version` → `技能版本`
- `Goal Contract` → `目标合同`; `Phase Ledger` → `阶段账本`; `Phase Check` → `阶段检查`; `Deviation Notice` → `偏离通知`; `Final Audit` → `最终审计`; `Post Review` → `事后复盘`
- `Complete` → `完成`; `Partial` → `部分完成`; `Blocked` → `阻塞`; `Unverified` → `未验证`; `Pass` → `通过`; `Fail` → `失败`; `Violation` → `违反`; `Preserved` → `已保留`; `Changed` → `已改变`
- `Stop` → `停止`; `Final` → `最终`; `Continue-within-confirmed-phase` → `在已确认阶段内继续`
- `Summary` → `一句话总结`

Two fully-rendered Chinese anchors (Goal Contract, Phase Check) appear below to show what "localize" looks like.

**Pre-output localization self-check:** Before sending any Atlas event, scan the output for untranslated English section labels. If any are found (e.g. "Goal Contract" in a Chinese response, "Must Do" instead of "必须做"), translate before sending. The only exceptions are the fixed list above.

## Event header

Every user-facing Atlas output starts with this header (localized):

```text
Atlas Event:
- Event ID: <phase>-A<n>   (phase-anchored; see rule below)
- Type: Goal Contract / Phase Ledger / Phase Check / Deviation Notice / Final Audit / Post Review
- Trigger Source: Skill-initiated / User-requested / Failure-triggered / Deviation-triggered / Phase-boundary / Finalization / Phase-scope-change
- Phase: P0 / P1 / P2 / None
- Stop Status: Stop / Continue-within-confirmed-phase / Final
```

**Event ID rule (phase-anchored):** IDs are `<phase>-A<n>` — e.g. `P0-A1`, `P0-A2`, `P1-A1`, `P1-A2`. The number incremen
