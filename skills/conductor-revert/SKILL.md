---
name: conductor-revert
description: Git-aware undo by logical work unit (track, phase, or task) 
category: AI & Agents
source: antigravity
tags: [ai, workflow]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/conductor-revert
---


# Revert Track

Revert changes by logical work unit with full git awareness. Supports reverting entire tracks, specific phases, or individual tasks.

## Use this skill when

- Working on revert track tasks or workflows
- Needing guidance, best practices, or checklists for revert track

## Do not use this skill when

- The task is unrelated to revert track
- You need a different domain or tool outside this scope

## Instructions

- Clarify goals, constraints, and required inputs.
- Apply relevant best practices and validate outcomes.
- Provide actionable steps and verification.
- If detailed examples are required, open `resources/implementation-playbook.md`.

## Pre-flight Checks

1. Verify Conductor is initialized:
   - Check `conductor/tracks.md` exists
   - If missing: Display error and suggest running `/conductor:setup` first

2. Verify git repository:
   - Run `git status` to confirm git repo
   - Check for uncommitted changes
   - If uncommitted changes exist:

     ```
     WARNING: Uncommitted changes detected

     Files with changes:
     {list of files}

     Options:
     1. Stash changes and continue
     2. Commit changes first
     3. Cancel revert
     ```

3. Verify git is clean enough to revert:
   - No merge in progress
   - No rebase in progress
   - If issues found: Halt and explain resolution steps

## Target Selection

### If argument provided:

Parse the argument format:

**Full track:** `{trackId}`

- Example: `auth_20250115`
- Reverts all commits for the entire track

**Specific phase:** `{trackId}:phase{N}`

- Example: `auth_20250115:phase2`
- Reverts commits for phase N and all subsequent phases

**Specific task:** `{trackId}:task{X.Y}`

- Example: `auth_20250115:task2.3`
- Reverts commits for task X.Y only

### If no argument:

Display guided selection menu:

```
What would you like to revert?

Currently In Progress:
1. [~] Task 2.3 in dashboard_20250112 (most recent)

Recently Completed:
2. [x] Task 2.2 in dashboard_20250112 (1 hour ago)
3. [x] Phase 1 in dashboard_20250112 (3 hours ago)
4. [x] Full track: auth_20250115 (yesterday)

Options:
5. Enter specific reference (track:phase or track:task)
6. Cancel

Select option:
```

## Commit Discovery

### For Task Revert

1. Search git log for task-specific commits:

   ```bash
   git log --oneline --grep="{trackId}" --grep="Task {X.Y}" --all-match
   ```

2. Also find the plan.md update commit:

   ```bash
   git log --oneline --grep="mark task {X.Y} complete" --grep="{trackId}" --all-match
   ```

3. Collect all matching commit SHAs

### For Phase Revert

1. Determine task range for the phase by reading plan.md
2. Search for all task commits in that phase:

   ```bash
   git log --oneline --grep="{trackId}" | grep -E "Task {N}\.[0-9]"
   ```

3. Find phase verification commit if exists
4. Find all plan.md update commits for phase tasks
5. Collect all matching commit SHAs in chronological order

### For Full Track Revert

1. Find ALL commits mentioning the track:

   ```bash
   git log --oneline --grep="{trackId}"
   ```

2. Find track creation commits:

   ```bash
   git log --oneline -- "conductor/tracks/{trackId}/"
   ```

3. Collect all matching commit SHAs in chronological order

## Execution Plan Display

Before any revert operations, display full plan:

```
================================================================================
                           REVERT EXECUTION PLAN
================================================================================

Target: {description of what's being reverted}

Commits to revert (in reverse chronological order):
  1. abc1234 - feat: add chart rendering (dashboard_20250112)
  2. def5678 - chore: mark task 2.3 complete (dashboard_20250112)
  3. ghi9012 - feat: add data hooks (dashboard_20250112)
  4. jkl3456 - chore: mark task 2.2 complete (dashboard_20250112)

Files that will be affected:
  - src/components/Dashboard.tsx (modified)
  - src/hooks/useData.ts (will be deleted - was created in these commits)
  - conductor/tracks/dashboard_20250112/plan.md (modified)

Plan updates:
  - Task 2.2: [x] -> [ ]
  - Task 2.3: [~] -> [ ]

================================================================================
                              !! WARNING !!
================================================================================

This operation will:
- Create {N} revert commits
- Modify {M} files
- Reset {P} tasks to pending status

This CANNOT be easily undone without manual intervention.

================================================================================

Type 'YES' to proceed, or anything else to cancel:
```

**CRITICAL: Require explicit 'YES' confirmation. Do not proceed on 'y', 'yes', or enter.**

## Revert Execution

Execute reverts in reverse chronological order (newest first):

```
Executing revert plan...

[1/4] Reverting abc1234...
      git revert --no-edit abc1234
      ✓ Success

[2/4] Reverting def5678...
      git revert --no-edit def5678
      
