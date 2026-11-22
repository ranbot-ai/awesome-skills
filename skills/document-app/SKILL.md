---
name: document-app
description: 'Document the app': write or refresh an app's system docs from its code. 'Are the docs right?': check mode, which only reports where docs and code disagree. 
category: Document Processing
source: antigravity
tags: [claude, ai, agent, automation, workflow, template, document, security, supabase, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/document-app
---


# Document the app -- Make the System Reviewable

## Operational boundaries

Keep the scope, sandbox, credentials and approval settings supplied by the user or host. Obtain authorization before delegating, exposing project files to another provider, enabling connectors or hooks, using paid services or deploying. Use synthetic or redacted inputs for examples. Keep security reviews static and defensive, with findings and fixes grounded in source inspection.

## When to Use

'Document the app': write or refresh an app's system docs from its code. 'Are the docs right?': check mode, which only reports where docs and code disagree.


**Document the system honestly so people and agents can review it.** Produce the durable documentation an AI-built app is missing. Map what the system is, who can do what, and where the risk lives. These docs are the foundation every later audit compares the code against.

## Invocation

**Use check-only mode when asked only to check the docs.** A request that starts with `check` also selects that mode, on the scope that follows it.

```
document-app                        Claude Code
document-app supabase/functions
document-app the backend            Codex
document-app check
"document this app" · "check our docs against the code"   either agent, in plain words
```

## Workflow

### Step 1: Scope

**Document the requested scope, or the whole repository when none is given.** If the request starts with `check`, skip to Check-only mode with the rest as the scope. For the whole repository, prioritize backend code, auth, data access, background jobs, and anything that sends, schedules, or exposes data.

### Step 2: Reverse-Engineer the Docs

**Read the code as the source of truth for system docs.** Apply the `shipping-artifacts` skill and produce the applicable documents. Follow its Locations and names rule: use the repo's own docs location and existing equivalents first. Use the names below, in `documentation/` at the repo root, only where the repo has none.

**For large scopes, give parallel subagents one core document each.** Each reads the code slice its doc describes; reconcile the cross-references yourself.

**Always produce the core documents.** They cover:

- `architecture.md` — system overview, stack, auth flow, trust boundaries.
- `flows.md` — the permission-relevant journeys: each protected step's authz check, the trust-boundary crossings, and the side effects each flow causes.
- `permissions.md` — roles, scope derivation, resource × operation × role matrix, RLS vs. code-enforced checks.
- `variables.md` — config & secrets mapped to risk and rotation.

**Produce a conditional document only when its capability exists.** Otherwise, note its absence in one line rather than inventing content.

- `emails.md` — notification path, templates, retry/backoff, failure visibility.
- `cron.md` — scheduled-work inventory, idempotency, internal-call auth.
- `seo.md` — SPA preview approach, route coverage, metadata sanitization.
- `automation.md` — embedded agents/automations: trigger, tool surface, steering vs. hard guardrails, output contract, app-owned side effects, approval gates.

**Describe the current state honestly, without being paranoid.** Skip conditional documents that do not apply and say so. Add a "Related Documents" reference in `architecture.md` for each doc produced. The test-coverage map, `tests.md`, is produced separately by the `derive-tests` skill.

### Step 3: Report

**Report every document's path, what was skipped, and what remains unclear.** Say what was created or updated and whether each path follows the repo's setup or a plugin default. Explain each skip and any gaps where the code was too unclear to document confidently; those are the first things to fix.

### Step 4: Offer Next Steps

**Offer the next steps after reporting the documentation work.** Use these options:

- "Want me to derive a test-coverage map (the `derive-tests` skill) so each documented rule has a verification plan?"
- "Want me to run a security audit now that the intended behavior is documented?"
- "Should I check for performance issues — over-fetching, missing indexes, caching?"
- "Want me to run the ship check (`ship-check`, or `ship-check` in Codex) to wire agent context and produce a full shipping packet?"

## Check-only mode

**Check-only mode reports disagreements and writes no file.** This lets a release check hand-maintained intent against code without overwriting it. Write no doc, report, or draft of a missing doc.

1. **Read existing docs and the code each claim describes.** Find the docs as Step 2 does, with the repo's own location and names first. Apply the `intended-vs-implemented` skill's discipline: cite both the claim and its code path. Report every factual disagreement, not only the ones that cross a boundary; skip wording and style.
2. **Leave the choice of which side is wrong to the owner.** A doc may state intent the code hasn't met, or the code may have moved on.
3. **List a
