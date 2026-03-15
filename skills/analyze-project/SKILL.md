---
name: analyze-project
description: Forensic root cause analyzer for Antigravity sessions. Classifies scope deltas, rework patterns, root causes, hotspots, and auto-improves prompts/health. 
category: AI & Agents
source: antigravity
tags: [ai, agent, workflow, template, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/analyze-project
---


# /analyze-project — Root Cause Analyst Workflow

Analyze AI-assisted coding sessions in `brain/` and produce a diagnostic report that explains not just **what happened**, but **why it happened**, **who/what caused it**, and **what should change next time**.

This workflow is not a simple metrics dashboard.
It is a forensic analysis workflow for AI coding sessions.

---

## Primary Objective

For each session, determine:

1. What changed from the initial ask to the final executed work
2. Whether the change was caused primarily by:
   - the user/spec
   - the agent
   - the codebase/repo
   - testing/verification
   - legitimate task complexity
3. Whether the original prompt was sufficient for the actual job
4. Which subsystems or files repeatedly correlate with struggle
5. What concrete changes would most improve future sessions

---

## Core Principles

- Treat `.resolved.N` counts as **signals of iteration intensity**, not proof of failure
- Do not label struggle based on counts alone; classify the **shape** of rework
- Separate **human-added scope** from **necessary discovered scope**
- Separate **agent error** from **repo friction**
- Every diagnosis must include **evidence**
- Every recommendation must map to a specific observed pattern
- Use confidence levels:
  - **High** = directly supported by artifact contents or timestamps
  - **Medium** = supported by multiple indirect signals
  - **Low** = plausible inference, not directly proven

---

## Step 1: Discovery — Find Relevant Conversations

1. Read the conversation summaries available in the system context.
2. List all subdirectories in:
   `~/.gemini/antigravity/brain/
3. Build a **Conversation Index** by cross-referencing summaries with UUID folders.
4. Record for each conversation:
   - `conversation_id`
   - `title`
   - `objective`
   - `created`
   - `last_modified`
5. If the user supplied a keyword/path, filter on that. Otherwise analyze all workspace conversations.

> Output: indexed list of conversations to analyze.

---

## Step 2: Artifact Extraction — Build Session Evidence

For each conversation, read all structured artifacts that exist.

### 2a. Core Artifacts
- `task.md`
- `implementation_plan.md`
- `walkthrough.md`

### 2b. Metadata
- `*.metadata.json`

### 2c. Version Snapshots
- `task.md.resolved.0 ... N`
- `implementation_plan.md.resolved.0 ... N`
- `walkthrough.md.resolved.0 ... N`

### 2d. Additional Signals
- other `.md` artifacts
- report/evaluation files
- timestamps across artifact updates
- file/folder names mentioned in plans and walkthroughs
- repeated subsystem references
- explicit testing/validation language
- explicit non-goals or constraints, if present

### 2e. Record Per Conversation

#### Presence / Lifecycle
- `has_task`
- `has_plan`
- `has_walkthrough`
- `is_completed`
- `is_abandoned_candidate` = has task but no walkthrough

#### Revision / Change Volume
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

#### Content / Quality Signals
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

## Step 3: Prompt Sufficiency Analysis

For each conversation, score the opening objective/request on a 0–2 scale for each dimension:

- **Clarity** — is the ask understandable?
- **Boundedness** — are scope limits defined?
- **Testability** — are success conditions or acceptance criteria defined?
- **Architectural specificity** — are files/modules/systems identified?
- **Constraint awareness** — are non-goals, constraints, or environment details included?
- **Dependency awareness** — does the prompt acknowledge affected systems or hidden coupling?

Create:
- `prompt_sufficiency_score`
- `prompt_sufficiency_band` = High / Medium / Low

Then note which missing ingredients likely contributed to later friction.

Important:
Do not assume a low-detail prompt is bad by default.
Short prompts can still be good if the task is narrow and the repo context is obvious.

---

## Step 4: Scope Change Classification

Do not treat all scope growth as the same.

For each conversation, classify scope delta into:

### 4a. Human-Added Scope
New items clearly introduced beyond the initial ask.
Examples:
- optional enhancements
- follow-on refactors
- “while we are here” additions
- cosmetic or adjacent work added later

### 4b. Necessary Discovered Scope
Work that was not in the opening ask but appears required to complete it correctly.
Examples:
- dependency fixes
- required validation work
- hidden integration tasks
- migration fallout
- cou
