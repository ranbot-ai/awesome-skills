---
name: clean-code-guard
description: Review generated or changed production code with Clean Code, SOLID, DRY, KISS, YAGNI, and LLM-specific failure-mode checks. 
category: Document Processing
source: antigravity
tags: [react, api, mcp, claude, ai, agent, llm, workflow, document, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/clean-code-guard
---



# clean-code-guard

You are reviewing generated or changed code before it ships. Apply the rules below as a guard pass after the first implementation pass — and once this skill is active, keep applying it to every later code change in the same session, re-running the self-check before delivery after each edit rather than reverting to unguarded output because the skill loaded earlier. If the user explicitly invokes this skill before writing code, use the same rules while writing and still run the self-check before delivery.

## When to Use

Use this skill when reviewing generated or changed code before it ships. Activate it reactively after an agent writes, edits, or refactors production code — especially after a first implementation pass. Re-run the guard pass before delivery after each edit.

## Compatibility

This is a portable instruction skill. It requires no MCP server, network access,
API key, shell command, local executable, or bundled script. It can be used in
any runtime that supports `SKILL.md` plus directly linked [references/](references/)
files; `agents/openai.yaml` is lightweight display metadata.

This skill does not replace project linters, formatters, type checkers, or test
runners. Use the project's own tools for mechanical verification; use this skill
for the judgement layer around code quality and review.

## How to use this skill

This skill has three modes — pick based on the user's request.

**Guard-pass mode** (recommended): after code has been generated, edited, refactored, or fixed, check the diff or target files against the *Always-applied imperatives* below. Fix violations before presenting, committing, or merging the work.

**Live mode** (explicit): when the user invokes this skill before a risky code edit, apply the same imperatives while writing, then run the *Self-check before delivery* checklist. If you violate any rule, fix it before showing the user.

**Review mode** (triggered when the user asks you to review, audit, critique, or rate code): walk [references/review-checklist.md](references/review-checklist.md) against the target file(s) and produce a structured findings report. Do not edit code in review mode unless asked.

Across all three modes, the rule bodies live in [references/](references/). Read the relevant reference file when:
- You hit a rule you don't fully remember the reasoning for.
- The user pushes back on a rule and you need the source citation.
- You're in review mode and need the full checklist.
- The code under review touches a specific principle (e.g., subclassing → [references/solid.md](references/solid.md); deduplication → [references/dry-kiss-yagni.md](references/dry-kiss-yagni.md)).

The reference files are:
- [references/naming-and-functions.md](references/naming-and-functions.md) — names, function size, parameters, command/query separation.
- [references/comments-and-formatting.md](references/comments-and-formatting.md) — when to comment, when to delete, matching neighbor style.
- [references/solid.md](references/solid.md) — SRP, OCP, LSP, ISP, DIP with the modern phrasings and detection smells.
- [references/dry-kiss-yagni.md](references/dry-kiss-yagni.md) — knowledge vs code duplication, Sandi Metz's re-inline rule, McCabe complexity, Fowler's YAGNI cost categories.
- [references/ai-failure-modes.md](references/ai-failure-modes.md) — the 14 systematic ways LLMs produce bad code. **Read this one first if you are an AI agent reading this skill.** It is the highest-leverage file in the skill.
- [references/review-checklist.md](references/review-checklist.md) — structured walk-through for review mode.
- [references/sources.md](references/sources.md) — central bibliography for source URLs. Read it only when you need to verify or cite an external source.

## Examples

- A coding agent implements an endpoint: use guard-pass mode on the diff before
  the work is presented or committed.
- User asks "review this PR" or "should I merge this?": use review mode and
  report findings from [references/review-checklist.md](references/review-checklist.md); do not edit unless
  asked.
- User asks "implement this endpoint using clean-code-guard": use live mode
  while writing, then run the self-check before delivery.
- User asks "refactor this function, same behavior": preserve observable
  behavior exactly and treat any bug fix as a separate change.

## Success criteria

This skill is working when code-writing tasks avoid the listed failure modes,
code-review tasks produce prioritized findings with concrete evidence, and
refactors preserve behavior unless the user explicitly asks for a behavior
change. It should stay silent for conceptual, CI, git workflow, prose, data
analysis, and test-running tasks covered by the frontmatter exclusions.

## Why this skill exists

LLM-generated code has measurable, systematic failure modes that generic "follow clean code" instructions do not catch. Examples backed by published research:

- **Code duplication grew 8x** in tr
