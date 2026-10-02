---
name: antigravity-maintainer-batch-release
description: Run protected AAS maintainer sweeps, PR merge batches, canonical sync, Core preview checks, and scripted releases. Use for repository maintenance, main alignment, CLI/MCP/Workbench changes, or release
category: Document Processing
source: antigravity
tags: [python, node, markdown, api, mcp, claude, ai, agent, llm, automation]
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
- Let `automation/canonical-repo-state` own generated artifacts and contributor-credit convergence after the source batch. That lane runs `sync:repo-state`, which now also recomputes the README `## Top Contributors` leaderboards through `sync:top-contributors`: never hand-edit those tables, and treat a stale ranking as a generator or exclusion-list defect instead.
- Use `release:prepare` and `release:publish` for releases. They never authorize a direct `main` push.

## Source Checks

Before changing anything:

1. Fetch `origin/main`; prove the clean maintainer checkout is on `main` and equals `origin/main`.
2. Inspect live PRs, issues, discussions in scope, Actions failures, Dependabot, CodeQL, secret scanning, and `npm audit` where relevant.
3. Confirm current scripts from `package.json` and the workflow files listed in **Current CI workflow**; do not rely on remembered CI or release behavior.
4. Capture user worktree status separately and keep those files out of maintainer commits.

## Current CI workflow

Read `.github/workflows/ci.yml`, `.github/workflows/skill-review.yml`, `.github/workflows/skillspector-advisory.yml`, and their protected-base scripts on the exact task base. Job dependencies define execution order; file order and a green workflow badge do not define merge authority.

### Required PR checks and independent review

| Lane | Actual sequence and evidence |
| --- | --- |
| Intake | `pr-policy` runs first. Ordinary source PRs use the exact protected-base classifier and its dependencies for fork safety and source-only policy. |
| Source validation | After `pr-policy`, `source-validation` checks sources, refreshes ephemeral generated state once, validates applicable references, runs the complete unsharded test suite and documentation security checks, and uploads the exact-head preview manifest. |
| Changed-skill evidence | Also after `pr-policy`, `pr-evidence` runs in parallel with `source-validation`. It publishes changed-skill evidence and a shadow decision manifest, then enforces deterministic regressions. Its advisory semantic-review state does not replace the separate skill-review result. |
| Artifact preview | `artifact-preview` waits for `pr-policy` and `source-validation`, verifies the source-preview manifest and its repository/head/workflow/run-attempt bindings, and does not regenerate ordinary source-PR artifacts. It does not wait for `pr-evidence`. |
| Semantic review | The separate `skill-review.yml` workflow fingerprints the complete changed skill trees. `review` means a passing Tessl result or valid identical-content reuse; `manual-review-required` needs the maintainer's semantic review and exact full-head attestation. It is independent of the required-CI DAG. |
| Static advisory scan | The separate PR-only `skillspector-advisory.yml` workflow runs `evidence-ready`, then `skillspector-advisory`. It waits for the latest GitHub Actions `pr-evidence` check for the same PR and exact head SHA, independently of `source-validation`, `artifact-preview`, and semantic review. |

The four routine protected checks remain `pr-policy`, `pr-evidence`, `source-validation`, and `artifact-preview`. Review skill-content changes truthfully and use `merge:batch` with exact-head attestation where required. SkillSpector, Jev, shadow decisions, and timing telemetry neither satisfy these checks nor authorize a merge. Inspect available advisory findings during semantic review, but do not add an advisory workflow to branch protection, fork-run approval prerequisites, or `merge:batch` without a separately authorized contract change.

For protected canonical-sync PRs, `pr-policy` reproduces the exact managed tree from trusted `main`; `source-validation` and `pr-evidence` record lightweight successful boundaries, while `artifact-preview` regenerates to confirm no drift. Do not describe those boundary jobs as fresh source tests or semantic scans. On merged `main`, `main-validation-and-sync` performs the repository-state sync, reference validation, dependency audit, full tests
