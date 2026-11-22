---
name: derive-tests
description: 'What should we test' or a coverage map: derive the coverage map and missing tests from docs and code; check mode reports staleness. 
category: Document Processing
source: antigravity
tags: [claude, ai, agent, llm, automation, workflow, document, security, supabase, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/derive-tests
---


# Derive tests -- Turn Intent Into Tests

## Operational boundaries

Keep the scope, sandbox, credentials and approval settings supplied by the user or host. Obtain authorization before delegating, exposing project files to another provider, enabling connectors or hooks, using paid services or deploying. Use synthetic or redacted inputs for examples. Keep security reviews static and defensive, with findings and fixes grounded in source inspection.

## When to Use

'What should we test' or a coverage map: derive the coverage map and missing tests from docs and code; check mode reports staleness.


**Turn documented intent into test cases that keep gaps from reopening.** The docs say what the system should do; an audit finds where the code doesn't. Read that intent and turn each load-bearing rule into a concrete case. Sort cases into automated tests, guarded live runs, and manual checks. Recommend the repo's defined gate, or green-before-merge CI where it defines none.

**Produce a coverage map and concrete cases, not a finished suite.** You or the next agent implement the deterministic cases. If the repo already keeps a test-coverage file, under any name, update that map instead of starting another. Apply the `shipping-artifacts` skill's Locations and names rule.

## Invocation

**Use check-only mode for a leading check or a map-currency question.** A request starting with `check`, or asking only whether the map is current, checks the scope that follows instead of running the workflow.

```
derive-tests                        Claude Code
derive-tests the checkout flow
derive-tests supabase/functions     Codex
derive-tests check
"what should we test here" · "is our coverage map current"   either agent, in plain words
```

## Prerequisite: documented intent

**Write down intent before deriving tests from it.** If system docs are missing or thin, apply the `document-app` skill first. Use the repo's docs location, or `documentation/` by default. This skill reads `flows.md`, `permissions.md`, and `automation.md` most heavily. Where intent is absent, say so rather than inventing rules to test.

## The workflow

### 1. Read the intent — and the tests that already exist

**Read the applicable system docs, treating their claims as unverified.** Read architecture, flows, permissions, variables, and any emails, cron, seo, and automation docs that exist. Apply the `shipping-artifacts` skill for each document's contents. Apply the `intended-vs-implemented` skill for the discipline of treating docs as claims to verify, not proof.

**Inventory existing assertions before claiming any rule is covered.** Read the test files, what they actually assert, and what runs in CI today. Distinguish coverage that exists now from coverage you propose; otherwise, the map can claim rules are pinned when nothing checks them. If there are no tests, say so plainly: that is itself a finding.

### 2. Extract the rules worth testing

**Extract deterministic rules whose violation crosses a consequential boundary.** These are the load-bearing trust, data, money, tenant, or privacy rules:

- authorization allow and deny cases, especially boundary crossings in `flows.md` and the matrix in `permissions.md`;
- input validation and output encoding at each sink;
- idempotency of jobs and dedup keys;
- fail-closed defaults: error, timeout, cache-miss, and flag paths that must deny, not allow;
- side-effect conditions: exactly when an email sends, a write commits, or a paid action fires;
- public-data-only constraints on public or bot routes;
- output-contract and tool-surface limits of any agent in `automation.md`.

**Skip cosmetic behavior; test rules whose failure harms someone other than the actor.**

### 3. Build the coverage map

**Mark coverage existing only when a repository test asserts the rule today.** Build one row per use case:

rule → expected behavior (including the negative case) → evidence source (doc + code) → test type → status (existing / proposed / none).

Use these test types:

- unit — pure and deterministic, no external services;
- integration (deterministic) — real wiring against a dependency the product runs for its tests, such as a local or development database or mocked provider; same pass/fail result every time;
- end-to-end — the running app driven as its user meets it, with a real session for signed-in steps;
- guarded live — a real external service the product does not run for its tests, such as an email provider, LLM, or third party; behind an explicit flag;
- manual — UI/visual or judgment calls; reviewer checklist items, not automated tests.

**Separate a test's dependencies from whether the repo makes it gate.** The repo's gate policy decides the latter (Step 5). A product may gate against its development database and identity provider's development instance, with real browser sessions, as in the `test-harness` skill. Those rows are deterministic there because the product owns the environments.

**Map each flows-doc j
