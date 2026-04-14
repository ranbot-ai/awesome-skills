---
name: analyze-project
description: Forensic root cause analyzer for Antigravity sessions. Classifies scope deltas, rework patterns, root causes, hotspots, and auto-improves prompts/health. 
category: AI & Agents
source: antigravity
tags: [ai, agent, workflow, design, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/analyze-project
---


# /analyze-project — Root Cause Analyst Workflow

Analyze AI-assisted coding sessions in `~/.gemini/antigravity/brain/` and produce a report that explains not just **what happened**, but **why it happened**, **who/what caused it**, and **what should change next time**.

## Goal

For each session, determine:

1. What changed from the initial ask to the final executed work
2. Whether the main cause was:
   - user/spec
   - agent
   - repo/codebase
   - validation/testing
   - legitimate task complexity
3. Whether the opening prompt was sufficient
4. Which files/subsystems repeatedly correlate with struggle
5. What changes would most improve future sessions

## When to Use
- You need a postmortem on AI-assisted coding sessions, especially when scope drift or repeated rework occurred.
- You want root-cause analysis that separates user/spec issues from agent mistakes, repo friction, or validation gaps.
- You need evidence-backed recommendations for improving future prompts, repo health, or delivery workflows.

## Global Rules

- Treat `.resolved.N` counts as **iteration signals**, not proof of failure
- Separate **human-added scope**, **necessary discovered scope**, and **agent-introduced scope**
- Separate **agent error** from **repo friction**
- Every diagnosis must include **evidence** and **confidence**
- Confidence levels:
  - **High** = direct artifact/timestamp evidence
  - **Medium** = multiple supporting signals
  - **Low** = plausible inference, not directly proven
- Evidence precedence:
  - artifact contents > timestamps > metadata summaries > inference
- If evidence is weak, say so

---

## Step 0.5: Session Intent Classification

Classify the primary session intent from objective + artifacts:

- `DELIVERY`
- `DEBUGGING`
- `REFACTOR`
- `RESEARCH`
- `EXPLORATION`
- `AUDIT_ANALYSIS`

Record:
- `session_intent`
- `session_intent_confidence`

Use intent to contextualize severity and rework shape.
Do not judge exploratory or research sessions by the same standards as narrow delivery sessions.

---

## Step 1: Discover Conversations

1. Read available conversation summaries from system context
2. List conversation folders in the user’s Antigravity `brain/` directory
3. Build a conversation index with:
   - `conversation_id`
   - `title`
   - `objective`
   - `created`
   - `last_modified`
4. If the user supplied a keyword/path, filter to matching conversations; otherwise analyze all

Output: indexed list of conversations to analyze.

---

## Step 2: Extract Session Evidence

For each conversation, read if present:

### Core artifacts
- `task.md`
- `implementation_plan.md`
- `walkthrough.md`

### Metadata
- `*.metadata.json`

### Version snapshots
- `task.md.resolved.0 ... N`
- `implementation_plan.md.resolved.0 ... N`
- `walkthrough.md.resolved.0 ... N`

### Additional signals
- other `.md` artifacts
- timestamps across artifact updates
- file/folder/subsystem names mentioned in plans/walkthroughs
- validation/testing language
- explicit acceptance criteria, constraints, non-goals, and file targets

Record per conversation:

#### Lifecycle
- `has_task`
- `has_plan`
- `has_walkthrough`
- `is_completed`
- `is_abandoned_candidate` = task exists but no walkthrough

#### Revision / change volume
- `task_versions`
- `plan_versions`
- `walkthrough_versions`
- `extra_artifacts`

#### Scope
- `task_items_initial`
- `task_items_final`
- `task_completed_pct`
- `scope_delta_raw`
- `scope_creep_pct_raw`

#### Timing
- `created_at`
- `completed_at`
- `duration_minutes`

#### Content / quality
- `objective_text`
- `initial_plan_summary`
- `final_plan_summary`
- `initial_task_excerpt`
- `final_task_excerpt`
- `walkthrough_summary`
- `mentioned_files_or_subsystems`
- `validation_requirements_present`
- `acceptance_criteria_present`
- `non_goals_present`
- `scope_boundaries_present`
- `file_targets_present`
- `constraints_present`

---

## Step 3: Prompt Sufficiency

Score the opening request on a 0–2 scale for:

- **Clarity**
- **Boundedness**
- **Testability**
- **Architectural specificity**
- **Constraint awareness**
- **Dependency awareness**

Create:
- `prompt_sufficiency_score`
- `prompt_sufficiency_band` = High / Medium / Low

Then note which missing prompt ingredients likely contributed to later friction.

Do not punish short prompts by default; a narrow, obvious task can still have high sufficiency.

---

## Step 4: Scope Change Classification

Classify scope change into:

- **Human-added scope** — new asks beyond the original task
- **Necessary discovered scope** — work required to complete the original task correctly
- **Agent-introduced scope** — likely unnecessary work introduced by the agent

Record:
- `scope_change_type_primary`
- `scope_change_type_secondary` (optional)
- `scope_change_confidence`
- evidence

Keep one short example in mind for calibration:
- Human-added: “also refactor nearby code while you’re here”
- Necessary discovered: hidden dependency must be fixed for original task to work
- Agent-in
