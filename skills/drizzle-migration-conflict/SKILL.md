---
name: drizzle-migration-conflict
description: Diagnose, repair, and prevent Drizzle Kit migration conflicts involving generated SQL, snapshots, journals, merge queues, and team workflows. 
category: Development & Code Tools
source: antigravity
tags: [python, claude, ai, agent, automation, workflow, template, design, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/drizzle-migration-conflict
---


# Drizzle Migration Conflict

Use this skill to help a user diagnose, repair, and prevent Drizzle Kit migration conflicts in a
multi-developer repository. Drizzle migrations encode both SQL and migration snapshots, so the safe
answer depends on the current migration directory shape, the Drizzle Kit version, and the git state.

## When to Use This Skill

- Use when Drizzle migration files, `_journal.json`, or `snapshot.json` conflict after a pull, merge, rebase, or PR update.
- Use when `drizzle-kit check` reports non-commutative migrations or migration folder conflicts.
- Use when a team wants a safe repair flow for generated Drizzle migrations after schema changes converge.
- Use when designing CI or merge-queue policy to prevent repeated Drizzle migration conflicts.

## Safety rules

- Start in read-only diagnosis mode unless the user explicitly asks to fix files.
- Do not run `drizzle-kit migrate`, `drizzle-kit push`, database seed scripts, or any command that
  connects to a live database unless the user explicitly requests it and the target is clear.
- Treat `drizzle-kit check`, project typechecks, and tests as command execution that may load project
  config, environment variables, or scripts. Inspect scripts/config first, and require an explicit
  non-production or disposable target before any DB-backed validation.
- Do not delete migration files, rewrite `_journal.json`, or run `git checkout --ours`,
  `git checkout --theirs`, `git restore`, or `rm` unless the user has confirmed the exact side and
  files to change.
- Do not recommend `drizzle-kit push` as the production solution for migration conflicts; it skips
  the auditable migration history that teams need.
- Treat `--ignore-conflicts` as an exception for a known false positive, not as the normal fix.
- Preserve schema source code changes unless the user explicitly asks to discard them. Conflict
  repair normally discards generated migrations and regenerates them from the merged schema.
- If `ours` and `theirs` could mean different branches depending on merge direction, ask the user to
  identify the parent branch before suggesting checkout commands.

## Required references

- Read `references/sources.md` when the answer depends on current Drizzle behavior, official
  guidance, or one of the preserved external links.
- Read `references/conflict-resolution.md` before recommending a repair flow.
- Read `references/ci-policy.md` before proposing CI, merge queue, or team workflow changes.
- Read `references/report-template.md` before writing a diagnostic report.

## Source references

The full list of official docs, Drizzle GitHub discussions, community scripts, and merge-queue
references lives in `references/sources.md` with trust levels and caveats. Read that file whenever
the answer depends on current Drizzle behavior. Re-verify the official docs and the most relevant
discussion when the project's `drizzle-kit` major version changes, since migration internals
(snapshot format, journal shape, `drizzle-kit check` semantics) have shifted between releases.

## Mode selection

Classify the task first:

1. **Diagnose** - The user has a conflict or failed `drizzle-kit check` and wants to understand it.
2. **Repair** - The user explicitly asks to fix or regenerate migration files.
3. **CI hardening** - The user wants to prevent future conflicts in PRs or merge queues.
4. **Explain** - The user wants a conceptual answer or a team playbook.

When the mode is not explicit, choose Diagnose.

Each mode unlocks a specific set of actions. Do not cross these boundaries without an explicit upgrade:

- **Diagnose** - read-only only. Run `git status`, `git ls-files -u`, the helper script, and file
  inspection. Do not run `drizzle-kit check`, typechecks, tests, or any write command. Report
  findings and the proposed repair path, but do not execute it.
- **Repair** - adds file writes and `drizzle-kit generate`/`check` execution, each gated by the
  Safety rules and explicit confirmation of the exact files and side (`ours`/`theirs`) to change.
- **CI hardening** - adds proposing or editing CI/workflow files. Do not run migration commands
  against the user's database to validate the workflow; validate the workflow syntax and logic only.
- **Explain** - conceptual only. No commands against the repo beyond optional read-only inspection.

## Repository discovery

Collect repo facts before giving commands:

```bash
git status --short
git rev-parse --show-toplevel
git rev-parse --abbrev-ref HEAD
git ls-files -u
rg --files -g 'drizzle.config.*' -g 'package.json' -g 'pnpm-lock.yaml' -g 'yarn.lock' -g 'package-lock.json'
```

Then inspect the relevant files:

- `drizzle.config.*` for `out`, `schema`, dialect, and config shape.
- `package.json` scripts for the project-approved `generate`, `check`, and `migrate` commands.
- `package.json` dependencies or lockfile snippets for `drizzle-kit` and `drizzle-orm` versions.
- The migration output directory, either from config or 
