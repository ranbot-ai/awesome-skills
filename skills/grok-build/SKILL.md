---
name: grok-build
description: Delegate well-specified implementation tasks to xAI's Grok Build CLI running headlessly while the orchestrating agent plans, writes task specs, reviews every diff, and owns the result. 
category: Creative & Media
source: antigravity
tags: [markdown, claude, ai, agent, template, security, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/grok-build
---


# Grok Build Orchestration

## When to Use

- Use when delegating a well-specified implementation task to xAI's Grok Build CLI running headlessly
- Use when executing a Markdown implementation plan task-by-task with a diff review after each task
- Use when the user says "use grok", "grok build", "have grok implement", or "send to grok"

The coding assistant is the orchestrator: it plans, writes self-contained task specs,
dispatches them to Grok Build headlessly, reviews every diff, and owns the final result.
Grok is the fast, cheap executor. Full CLI details and verified behaviors: `references/cli.md`.

## Safety Gate

Before every dispatch, show the user the exact task specification that will be sent to xAI,
the target worktree, and the permission mode. Obtain explicit approval to disclose that text
and to let Grok edit the scoped worktree. Never include secrets, proprietary source, customer
data, or credentials in a task specification. Do not run `grok update`, `--always-approve`,
or a destructive recovery command without separate, explicit approval.

## When to delegate vs keep with the orchestrator

| Delegate to Grok | Keep with the orchestrator |
|---|---|
| Plan tasks with clear acceptance criteria | Ambiguous requirements, architecture decisions |
| Boilerplate, scaffolding, CRUD | Deep cross-file debugging |
| Mechanical refactors | Security-sensitive code |
| Test writing from clear specs | Anything touching production infrastructure |
| UI components from mockups/specs | Tasks where writing the spec ≈ doing the work |

When in doubt, keep it with the orchestrator.

## Session preflight (once, before the first dispatch)

1. `grok update --check --json` — if `updateAvailable` is true, tell the user. Run
   `grok update` only after explicit approval, then confirm with `grok --version`.
2. `grok models` — if it errors or reports logged out, STOP and ask the user to run
   `grok login`.

## Per-task loop (sequential — the default)

1. **Spec.** Write a self-contained task file (template below) to a temp directory
   OUTSIDE the target repo — the harness scratchpad if one is available, else the OS
   temp dir. Never write it inside the target repo. Grok has zero conversation context:
   no one-liner prompts, ever.
   - POSIX: `mkdir -p "${TMPDIR:-/tmp}/grok-specs"`, then write `task.md` there.
   - Windows (PowerShell): `New-Item -ItemType Directory -Force "$env:TEMP\grok-specs"`,
     then write `task.md` there.
2. **Clean state.** No uncommitted *source* changes — commit or stash first, so the
   post-run diff is exactly Grok's work. Ignore build artifacts (`__pycache__`, `dist/`,
   etc.); if they show in `git status`, they're usually just un-gitignored, not your
   concern. Never dispatch on a dirty source tree.
3. **Dispatch.**

   POSIX:

   ```bash
   grok --prompt-file <task-file> \
     --output-format json \
     --always-approve \
     --max-turns 30 \
     --cwd <repo>
   ```

   Windows (PowerShell) — backtick line-continuation:

   ```powershell
   grok --prompt-file <task-file> `
     --output-format json `
     --always-approve `
     --max-turns 30 `
     --cwd <repo>
   ```

   Parse the JSON output and save `sessionId`. (`--always-approve` is required for
   headless runs — `--permission-mode acceptEdits` silently cancels edits with no
   interactive approver. Use it only after the user explicitly approves Grok editing this
   exact scoped worktree. See `references/cli.md`.) For a high-stakes task, add `--check`
   so Grok self-verifies before you review; skip it otherwise (it ~doubles latency).
4. **Review gate — non-negotiable.**
   - Read the diff yourself (`git diff -- <files from the spec>` to skip artifact noise):
     does it do the task, only the task, and match repo conventions?
   - Run the acceptance commands from the spec.
   - **Pass** → commit with a clear message following the repo's convention → next task.
   - **Fail** → ask the user before a fix-up or any reset. Never run `git checkout -- .` or
     `git clean -fd` automatically; preserve the diff for review and use a non-destructive
     recovery plan unless the user explicitly authorizes otherwise.

## Task spec template

```markdown
# Task: <one-line title>

## Context
- Repo: <path> — <one line on what the project is>
- Conventions: <test runner, formatter, a good example file to imitate>

## Files
- Modify: <path>
- Create: <path>

## Task
<precise description of the change>

## Constraints
- Do not modify any files other than those listed above.
- <other constraints>

## Acceptance criteria
- `<exact command>` <expected result>
```

## Executing a Markdown implementation plan

- One plan task per dispatch, in order.
- Check off the plan's task checkboxes (`- [ ]` → `- [x]`) as each task lands and passes
  the review gate.
- If the plan explicitly marks tasks as independent, see Parallel dispatch below;
  otherwise stay sequential.

## Parallel dispatch (opt-in exception, not the default)

Only when a plan exp
