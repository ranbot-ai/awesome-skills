---
name: de-ai-writer
description: Chinese AI-smell removal engine: 35 Chinese AI-tell patterns (赋能/闭环), AI-smell scoring, de-AI rewriting, style clone. Use when a Chinese draft reads machine-written or the user asks 去AI味. 
category: Document Processing
source: antigravity
tags: [markdown, claude, ai, llm, design, document, rag, marketing, copywriting]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/de-ai-writer
---


# De-AI Writer — Chinese AI-Smell Removal

## Overview

Chinese AI writing has its own tells, and they are not the English ones. English humanizers hunt `delve`, "it's not just X, it's Y" and em-dash overuse; a Chinese draft reads machine-written because of 赋能 / 闭环 / 抓手 / 底层逻辑 (pattern 15), 首先-其次-最后 scaffolding (pattern 30), 随着…的发展 openers (pattern 25), 拔高意义 endings (pattern 16), and 公文套话 (pattern 22). A translated English humanizer misses all of it.

This skill ships the pattern catalog plus the editing procedure: score a draft for AI smell, rewrite it against the specific patterns it hits, clone a reference style, and review the result. The full 35-pattern catalog lives in `references/ai-patterns-zh.md` and is plain Markdown — usable as a prompt by any assistant.

*Note on the engine: this bundle is documentation only. A zero-dependency local rule engine is published in the source repository (see `source_repo`) as an optional external prerequisite — it is not included here.*

## When to Use This Skill

- Use when a Chinese draft "reads like AI" and needs to sound human-authored.
- Use when the user asks 去AI味, 改得像人写的, or 这段是不是AI写的 (is this AI-written?).
- Use when editing marketing copy, WeChat articles, product listings, or social posts written in Chinese.
- Use when asked to imitate a reference writing style (风格克隆) or to produce A/B variants of the same copy.
- Use when shifting tone: casual / formal / marketing / humor / direct.

## How It Works

### Step 1: Score the draft first (diagnose before editing)

Scan the text, record which patterns hit *and where*, then compute the AI-smell index with the deterministic formula below. Do not rewrite from vibes — the same phrases recur, and you need the hit list to verify the edit afterwards.

#### The AI-smell index (deterministic — the same formula must be used before and after)

1. **Count hits per paragraph.** For each pattern, count one hit per paragraph — repeats inside the same paragraph do not inflate the score.
2. **Weight by evidence strength.** 强模式 = **2 points**; patterns the catalog marks 弱证据 (破折号 / 限定词 / 被动与无主语 / "的"-字堆叠 / 引号不统一) = **1 point**.
3. **Normalize by length.** `D = 加权总分 / max(1, 总字数 / 100)` — weighted hits per 100 characters.
4. **Index.** `AI味指数 = min(100, round(D × 10))`.
5. **Bands.** 0–20 基本像人写 · 21–45 轻度 AI 味 · 46–75 明显 AI 味 · 76–100 一眼假.
6. **Report three numbers, not one:** 命中处数 / 加权总分 / AI味指数. After rewriting, recompute with the same formula so the delta is comparable. If a hit cannot be attributed to a catalogued pattern, report only the observable hit count and say the index is not computed — never invent a number.

Worked example (the sample below): 8 hits in 77 characters, 6 strong (6 × 2 = 12) + 2 weak (2 × 1 = 2) → 加权总分 14 → D = 14 / 0.77 ≈ 18.2 → 指数 = min(100, 182) = **100/100**.

```
AI 味体检报告
总字数 77 ｜ 命中 8 处 ｜ 加权 14 ｜ AI味指数 100/100（一眼假）
机械连接 ×3   官方黑话 ×2   空洞拔高 ×2   夸张词 ×1
```

### Step 2: Rewrite against the specific patterns, not in general

Work through the hit list one pattern at a time. Correct each pattern by its own rule (the catalog gives 识别特征 → 为什么假 → 改前/改后 for all 35). Two rules govern the whole pass:

- **A single hit is not evidence.** The catalog marks certain patterns (em-dash, hedges, passive voice, 的-stacking, quotation marks) as 弱证据 — only act when two or more appear in the same paragraph.
- **Delete, don't decorate.** Most patterns disappear by deleting the sentence that carries them: drop the negation half of 不是 X，而是 Y, drop the significance ending, drop the 开场铺垫, drop the assistant residue (希望对你有帮助).

**The facts come from the source, never from the pattern list.** A rewrite may delete packaging, reorder, and rephrase; it must not introduce a fact the source does not contain. If the rewrite would be clearer with a number or a specification (rotational speed, battery life, materials), and the source has none, ask the user for it — never supply one.

### Step 3: Verify the rewrite

Re-score the rewritten text with the same Step 1 formula. The index should drop and the semantic content must be preserved — report the before/after triple (命中处数 / 加权总分 / 指数), how many patterns were cleared, and confirm that no fact was added or lost. A rewrite that lowers the score by deleting facts is a failed edit; so is one that raises the count of facts in the text.

### Step 4: Optional — style clone, variants, tone, review

- **Style clone**: supply a reference sample (an old article, a novel fragment, a writer you like) and match its sentence rhythm, vocabulary and colloquial ratio.
- **Variants**: produce 2-6 clearly different versions (short and punchy / loose and spoken / vivid) for headline and ad-copy A/B tests.
- **Tone**: re-target the same content to casual, formal, marketing, humor or direct register.
- **Review**: score the finished text on Hook / Pacing / Emotion / AI-Smell / Clarity / Persuasion / Structure / Readability, plus three concrete improvements.

## Examples

### Example 1: Business copy with s
