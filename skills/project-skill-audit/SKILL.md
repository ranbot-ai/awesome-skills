---
name: project-skill-audit
description: Audit a project and recommend the highest-value skills to add or update. 
category: AI & Agents
source: antigravity
tags: [ai, agent, workflow, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/project-skill-audit
---


# Project Skill Audit

## Overview

Audit the project's real recurring workflows before recommending skills. Prefer evidence from memory, rollout summaries, existing skill folders, and current repo conventions over generic brainstorming.

Recommend updates before new skills when an existing project skill is already close to the needed behavior.

## When to Use
- When the user asks what skills a project needs or which existing skills should be updated.
- When recommendations should be grounded in project history, memory files, and local conventions.

## Workflow

1. Map the current project surface.
   Identify the repo root and read the most relevant project guidance first, such as `AGENTS.md`, `README.md`, roadmap/ledger files, and local docs that define workflows or validation expectations.

2. Build the memory/session path first.
   Resolve the memory base as `$CODEX_HOME` when set, otherwise default to `~/.codex`.
   Use these locations:
   - memory index: `$CODEX_HOME/memories/MEMORY.md` or `~/.codex/memories/MEMORY.md`
   - rollout summaries: `$CODEX_HOME/memories/rollout_summaries/`
   - raw sessions: `$CODEX_HOME/sessions/` or `~/.codex/sessions/`

3. Read project past sessions in this order.
   If the runtime prompt already includes a memory summary, start there.
   Then search `MEMORY.md` for:
   - repo name
   - repo basename
   - current `cwd`
   - important module or file names
   Open only the 1-3 most relevant rollout summaries first.
   Fall back to raw session JSONL only when the summaries are missing the exact evidence you need.

4. Scan existing project-local skills before suggesting anything new.
   Check these locations relative to the current repo root:
   - `.agents/skills`
   - `.codex/skills`
   - `skills`
   Read both `SKILL.md` and `agents/openai.yaml` when present.

5. Compare project-local skills against recurring work.
   Look for repeated patterns in past sessions:
   - repeated validation sequences
   - repeated failure shields
   - recurring ownership boundaries
   - repeated root-cause categories
   - workflows that repeatedly require the same repo-specific context
   If the pattern appears repeatedly and is not already well captured, it is a candidate skill.

6. Separate `new skill` from `update existing skill`.
   Recommend an update when an existing skill is already the right bucket but has stale triggers, missing guardrails, outdated paths, weak validation instructions, or incomplete scope.
   Recommend a new skill only when the workflow is distinct enough that stretching an existing skill would make it vague or confusing.

7. Check for overlap with global skills only after reviewing project-local skills.
   Use `$CODEX_HOME/skills` and `$CODEX_HOME/skills/public` to avoid proposing project-local skills for workflows already solved well by a generic shared skill.
   Do not reject a project-local skill just because a global skill exists; project-specific guardrails can still justify a local specialization.

## Session Analysis

### 1. Search memory index first

- Search `MEMORY.md` with `rg` using the repo name, basename, and `cwd`.
- Prefer entries that already cite rollout summaries with the same repo path.
- Capture:
  - repeated workflows
  - validation commands
  - failure shields
  - ownership boundaries
  - milestone or roadmap coupling

### 2. Open targeted rollout summaries

- Open the most relevant summary files under `memories/rollout_summaries/`.
- Prefer summaries whose filenames, `cwd`, or `keywords` match the current project.
- Extract:
  - what the user asked for repeatedly
  - what steps kept recurring
  - what broke repeatedly
  - what commands proved correctness
  - what project-specific context had to be rediscovered

### 3. Use raw sessions only as a fallback

- Only search `sessions/` JSONL files if rollout summaries are missing a concrete detail.
- Search by:
  - exact `cwd`
  - repo basename
  - thread ID from a rollout summary
  - specific file paths or commands
- Use raw sessions to recover exact prompts, command sequences, diffs, or failure text, not to replace the summary pass.

### 4. Turn session evidence into skill candidates

- A candidate `new skill` should correspond to a repeated workflow, not just a repeated topic.
- A candidate `skill update` should correspond to a workflow already covered by a local skill whose triggers, guardrails, or validation instructions no longer match the recorded sessions.
- Prefer concrete evidence such as:
  - "this validation sequence appeared in 4 sessions"
  - "this ownership confusion repeated across extractor and runtime fixes"
  - "the same local script and telemetry probes had to be rediscovered repeatedly"

## Recommendation Rules

- Recommend a new skill when:
  - the same repo-specific workflow or failure mode appears multiple times across sessions
  - success depends on project-specific paths, scripts, ownership rules, or validation steps
  - the workflow benefits from strong defaults or failure 
