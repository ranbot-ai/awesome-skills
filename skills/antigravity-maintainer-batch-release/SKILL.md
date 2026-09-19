---
name: antigravity-maintainer-batch-release
description: Run protected AAS maintainer sweeps, PR merge batches, canonical sync, Core preview checks, and scripted releases. Use for repository maintenance, main alignment, CLI/MCP/Workbench changes, or release
category: Document Processing
source: antigravity
tags: [python, node, api, mcp, claude, ai, agent, llm, automation, workflow]
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
   - Optional accelerator before editing: run `npm run maintainer:sweep` for repo health, open PR check rollup, advisory download of CI `pr-evidence-*` artifacts (when `pr-evidence` succeeded), optional Jev triage (`TYPESAFE_API_KEY` in `.env.local`), `merge:batch --dry-run` on CI-ready PRs, and a **Next actions** hint list. Prefer CI evidence over re-running `npm run pr:evidence` locally when the artifact head matches. For a single head only, use `npm run maintainer:jev-hints -- --base origin/main --head <head-sha>`. Sweep/Jev/CI summaries are advisory only; `merge:batch` recomputes from trusted `main`, and Tessl plus `--reviewed-head` attestation remain authoritative. See `docs/maintainers/maintainer-sweep.md` and `docs/maintainers/jev-hints.md`.

2. Validate changed skills truthfully.
   - Run `npm run validate`, `npm run validate:references`, `npm run security:docs`, changed-skill evidence, and the relevant tests.
   - Treat the entire tracked `skills/<skill-id>/**` subtree as skill content. Inspect semantics, safety, provenance, declared risk, limitations, and every bundled file directly, including nested examples, scripts, lockfiles, references, and assets. Never reduce evidence or review to `SKILL.md` or a fixed support-directory allowlist.
   - Require changed-skill evidence to cover every Git record in each changed canonical skill subtree. Require the `skill-review` workflow for changes under `skills/**` or `plugins/**/skills/**`; its reusable result must be keyed by the complete nearest skill-directory fingerprint on the exact current head SHA.
   - Keep canonical skill ownership lookup proportional to changed-path depth, not total registry size, and preserve the five-minute trusted evaluator budget so repository-wide evidence completes without weakening fail-closed checks. Parse a legacy executable-mode canonical `SKILL.md` only as private, non-executable snapshot data; keep it reported as unsafe and never materialize symlinks, gitlinks, or other executable files.
   - `review` means Tessl semantic review actually ran or a valid identical-content result was reused.
   - `manual-review-required` means Tessl credentials or credits were unavailable, or Tessl did not produce a passing result. Perform the maintainer semantic review and attest with `--reviewed-head <full-40-character-sha>`.
   - Any non-passing Tessl outcome produces `manual-review-required`; complete the semantic review and bind the judgment to the exact head instead of treating a heuristic score as merge authority.
   - Never report `manual-review-required` as “Tessl passed.”
   - Scoped content-review fingerprints document exact bytes and observed checks, not general reliability. Keep explicit compatibility aliases and their complete local support bundles synchronized; the alias-integrity regression checks equality without affecting selection eligibility. Report remaining corpus debt rather than awarding an
