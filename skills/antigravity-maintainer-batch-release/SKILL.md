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
   - Treat the entire tracked `skills/<skill-id>/**` subtree as skill content. Inspect semantics, safety, provenance, declared risk, limitations, and every bundled file directly, including nested examples, scripts, lockfiles, references, and assets. Never reduce evidence or review to `SKILL.md` or a fixed support-directory allowlist.
   - Require changed-skill evidence to cover every Git record in each changed canonical skill subtree. Require the `skill-review` workflow for changes under `skills/**` or `plugins/**/skills/**`; its reusable result must be keyed by the complete nearest skill-directory fingerprint on the exact current head SHA.
   - `review` means Tessl semantic review actually ran or a valid identical-content result was reused.
   - `manual-review-required` means Tessl credentials or credits were unavailable, or Tessl did not produce a passing result. Perform the maintainer semantic review and attest with `--reviewed-head <full-40-character-sha>`.
   - Any non-passing Tessl outcome produces `manual-review-required`; complete the semantic review and bind the judgment to the exact head instead of treating a heuristic score as merge authority.
   - Never report `manual-review-required` as “Tessl passed.”

3. Run checks in parallel where independent.
   - Use the repository validation, test, docs-security, source-credit, reference, warning-budget, and targeted app checks required by the changed files.
   - Fix deterministic policy failures in the source; do not wait for them as if they were flaky CI.
   - Treat `pr-policy` fork classification from the exact protected-base implementation as an unprivileged fail-fast gate before dependent work, never as approval authority. `merge:batch` must still recompute the current trusted decision before approving any fork run or merging.
   - Treat `impact_profile` as shadow-only telemetry. It must not skip, downgrade, or satisfy any required check.
   - For ordinary source PRs, require `source-validation` to generate preview state once and `artifact-preview` to verify the manifest bound to the exact head and run identity. For canonical-sync PRs, rely on `pr-policy` exact-tree reproduction, keep `source-validation` lightweight, require `artifact-preview` to confirm no drift, and retain final CI and CodeQL on the merged `main` commit.
   - Keep timing observational and test sharding opt-in. Required CI must continue to run the full unsharded `npm run test`; deterministic local shards may be used only through `npm run test:local -- --shard-index N --shard-count M`.

4. Merge accepted source PRs in conflict-aware order.
   - Run a dry classification first when useful.
   - For changed skill content, review the exact head and run:

     ```bash
     npm run merge:batch
