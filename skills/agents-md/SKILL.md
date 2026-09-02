---
name: agents-md
description: Create, revise, or audit AGENTS.md files from repository evidence, verified commands, and correctly scoped instructions without overwriting maintainer intent. 
category: AI & Agents
source: antigravity
tags: [markdown, api, claude, ai, agent, workflow, template, document, security, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/agents-md
---


# Maintain AGENTS.md from repository evidence

## Overview

Create or improve agent instructions that help a coding agent change the
repository correctly without rediscovering its workflow. Base every
repository-specific command, path, and rule on evidence in the current
checkout.

Prefer a focused diff over a wholesale rewrite. There is no universal line
limit, required section list, symlink layout, or commit-attribution policy;
follow the repository's own needs and maintainer intent.

## When to Use

- The user asks to create, update, shorten, or audit `AGENTS.md`.
- A monorepo needs root instructions plus narrower package-level overrides.
- Existing agent instructions contain stale commands, duplicated policy, or
  unsupported claims.
- The user wants to reconcile `AGENTS.md` with `CLAUDE.md`,
  `.github/copilot-instructions.md`, or other repository instruction files.

Use `@agents-generator` instead when the task specifically calls for its
packaged generation modes, assets, or backup workflow. Use this skill when a
maintainer-readable, evidence-first edit is the primary goal.

## How It Works

### 1. Preserve existing intent

Before writing, read every instruction file that applies to the target path,
including existing `AGENTS.md` files and relevant tool-specific files such as
`CLAUDE.md`, `GEMINI.md`, `.github/copilot-instructions.md`, and
`.github/instructions/*.instructions.md`.

- Improve an existing `AGENTS.md` in place when possible.
- Preserve accurate maintainer-authored rules and repository-specific policy.
- Do not replace another tool's instruction file with a symlink unless the
  user requests it and repository evidence shows identical content is desired.
- Do not silently choose between conflicting instructions. Follow the
  higher-priority applicable rule, or ask when the intended policy cannot be
  established from the repository.

### 2. Build a bounded evidence map

Inspect only enough of the repository to establish how work is actually done:

1. Read the project overview and contribution guidance, such as `README*`,
   `CONTRIBUTING*`, and relevant docs.
2. Read manifests, lockfiles, workspace files, task runners, and build config
   to identify supported tools and exact commands.
3. Read CI workflows to learn required checks. Do not assume every CI or
   deployment job is safe or appropriate to run locally.
4. Inspect representative source and test files for naming, layout, and test
   conventions.
5. Identify generated files, migrations, vendored code, large fixtures,
   secrets boundaries, and production-only operations.

Prefer `rg --files` and `rg` for discovery when available. Track the source of
each non-obvious command or rule so unsupported claims do not enter the final
file.

### 3. Choose the instruction scope

Use the root `AGENTS.md` for repository-wide guidance. Add or revise a nested
`AGENTS.md` only when a subtree has materially different commands,
architecture, conventions, or safety boundaries.

Keep shared rules at the root and only differences in nested files. For tools
that implement the public AGENTS.md convention, the nearest file in the
directory tree controls the working subtree. Do not copy the full root file
into every package.

### 4. Write high-signal guidance

Choose headings that fit the repository instead of forcing a fixed template.
Include the following only when supported by evidence:

- **Repository map:** the few directories and boundaries an agent must know.
- **Setup and commands:** exact install, development, build, lint, type-check,
  and test commands, with the working directory when it is not obvious.
- **Focused validation:** targeted checks for a small change and broader checks
  required before handoff.
- **Change rules:** generated-file ownership, migrations, schemas, APIs,
  dependencies, and cross-package coordination.
- **Safety boundaries:** secrets, production data, destructive commands,
  deployments, and operations that require explicit authorization.
- **Contribution rules:** repository-specific naming, formatting, commit, or
  pull-request requirements that affect implementation or handoff.

Write direct, testable statements. Prefer:

```markdown
- From the repository root, run `npm test -- path/to/file.test.ts` for a focused test.
```

over:

```markdown
- Make sure tests pass and follow best practices.
```

Link to maintained documentation instead of copying it. Distinguish required
checks from optional, slow, privileged, or deployment-only checks.

### 5. Validate before handoff

1. Re-read each changed `AGENTS.md` completely.
2. Remove contradictions, duplicate rules, placeholders, and stale claims.
3. Confirm every mentioned file and directory exists.
4. Cross-check commands against manifests or CI, and run safe, proportionate
   checks when useful.
5. If nested files changed, confirm each contains only subtree-specific rules
   and does not conflict accidentally with the root.
6. Review the diff as a maintainer: every adde
