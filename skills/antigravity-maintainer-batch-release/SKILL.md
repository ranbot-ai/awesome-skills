---
name: antigravity-maintainer-batch-release
description: Run protected AAS maintainer sweeps, PR merge batches, canonical sync, Core preview checks, and scripted releases. Use for repository maintenance, main alignment, CLI/MCP/Workbench changes, or release
category: Document Processing
source: antigravity
tags: [api, mcp, claude, ai, agent, llm, automation, workflow, template, document]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/antigravity-maintainer-batch-release
---


# Antigravity Maintainer Batch Release

## When to Use

Use this skill for repository-wide AAS maintenance, maintainer-side PR repair or merge batches, canonical synchronization, AAS Core or Workbench changes, protected releases, and hosted catalog or legacy redirect infrastructure. Do not use it for ordinary contribution work that does not require maintainer privileges or canonical convergence.

## Protected-Main Contract

Treat the repository root containing this skill as pull-request-only:

- Read `AGENTS.md`, `.github/MAINTENANCE.md`, and current maintainer docs before mutation.
- Never commit or push directly to `main`, even when the user says “push to main.” That phrase names the final target state.
- Preserve unrelated dirty work. Use a clean temporary clone or a topic branch for maintainer changes.
- Use `npm run merge:batch` for accepted source PRs. Do not substitute a raw merge API, generic GitHub skill, or generic push helper.
- Let `automation/canonical-repo-state` own generated artifacts and contributor-credit convergence after the source batch.
- Use `release:prepare` and `release:publish` for releases. They never authorize a direct `main` push.

## Source Checks

Before changing anything:

1. Fetch `origin/main`; prove the clean maintainer checkout is on `main` and equals `origin/main`.
2. Inspect live PRs, issues, discussions in scope, Actions failures, Dependabot, CodeQL, secret scanning, and `npm audit` where relevant.
3. Confirm current scripts from `package.json`; do not rely on remembered release behavior.
4. Capture user worktree status separately and keep those files out of maintainer commits.

## Maintainer Sweep

1. Triage every open PR before editing.
   - Separate valid source changes, repairable PRs, conflicts, generated-only noise, promotional links, and unsupported ownership/license changes.
   - Review semantics, safety, provenance, risk labels, limitations, source credits, and changed-skill evidence.
   - Prefer narrow maintainer repairs on the contributor branch when maintainer edits are enabled.

2. Validate changed skills truthfully.
   - Run `npm run validate`, `npm run validate:references`, `npm run security:docs`, changed-skill evidence, and the relevant tests.
   - Inspect semantics, safety, provenance, declared risk, limitations, and all tracked bundle files directly. Treat inferred risk labels and heuristic quality scores as non-authoritative; do not change a skill merely to satisfy a lexical signal.
   - Inspect the `skill-review` workflow on the exact current head SHA.
   - `review` means Tessl semantic review actually ran or a valid identical-content result was reused.
   - `manual-review-required` means Tessl credentials or credits were unavailable, or Tessl did not produce a passing result. Perform the maintainer semantic review and attest with `--reviewed-head <full-40-character-sha>`.
   - Any non-passing Tessl outcome produces `manual-review-required`; complete the semantic review and bind the judgment to the exact head instead of treating a heuristic score as merge authority.
   - Never report `manual-review-required` as “Tessl passed.”

3. Run checks in parallel where independent.
   - Use the repository validation, test, docs-security, source-credit, reference, warning-budget, and targeted app checks required by the changed files.
   - Fix deterministic policy failures in the source; do not wait for them as if they were flaky CI.

4. Merge accepted source PRs in conflict-aware order.
   - Run a dry classification first when useful.
   - For changed skill content, review the exact head and run:

     ```bash
     npm run merge:batch -- --prs <PR_LIST> --reviewed-head <FULL_HEAD_SHA>
     ```

   - `merge:batch` may normalize the PR body and close/reopen the PR. GitHub creates the replacement workflow runs asynchronously; the command must wait for and approve only post-reopen workflow/check-suite IDs. Older runs on the same SHA cannot satisfy or fail the fresh gate.
   - The routine protected checks are `pr-policy`, `pr-evidence`, `source-validation`, and `artifact-preview`. The retired `aas-v1-baseline` workflow is not a merge prerequisite and must not be awaited or approved during source or canonical-sync batches.
   - If the PR head or base changes, discard stale evidence and rerun from a fresh `origin/main`.

5. Converge canonical state once after the source batch.
   - Wait for the protected `automation/canonical-repo-state` PR.
   - Verify its managed-only diff, required checks, merge result, and the resulting `origin/main`.
   - If an unmanaged repair remains, use a topic PR; never patch `main` directly.

## Hosted Catalog and Legacy Redirect Bridge

Treat the current catalog and the legacy user-site bridge as one public system:

- Current catalog: `sickn33/agentic-awesome-skills` at `https://sickn33.github.io/agentic-awesome-skills/`.
- Legacy bridge: `sickn33/sickn33.github.io` at `https://sickn33.github.io/antigravity-awesome-skills/`.

For SEO, i
