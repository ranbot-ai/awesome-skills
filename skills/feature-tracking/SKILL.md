---
name: feature-tracking
description: Maintain durable feature-level memory across AI coding sessions with lightweight Markdown tracks for status, source-of-truth docs, decisions, risks, and changes. 
category: Document Processing
source: antigravity
tags: [markdown, api, claude, ai, agent, automation, workflow, design, document, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/feature-tracking
---


# Feature Tracking

## Overview

Feature Tracking maintains lightweight, repository-native memory for long-lived feature work. It gives AI coding agents a stable place to find the current status, authoritative documents, verified behavior, durable decisions, risks, and recent changes without treating chat history or stale plans as truth.

The workflow uses a global index plus one Markdown track per feature under `docs/features/`. It complements issue trackers, specifications, and source code by linking the evidence that still matters rather than duplicating it.

## When to Use This Skill

- Use when starting or resuming work on a feature after a session, agent, or tool change.
- Use when feature knowledge is scattered across PRDs, API notes, plans, issues, and old commits.
- Use when a long-lived feature needs durable decisions, risks, rollout constraints, or migration notes.
- Use when reviewing or finishing feature work and recording the verified outcome for future agents.
- Use when adopting lightweight project memory in an existing repository without reorganizing all documentation.

Do not use this skill merely to log every code edit or replace an existing issue tracker. Use it when future contributors need a concise, current view of an entire feature.

## How It Works

### Step 1: Discover Existing Feature Memory

Before changing a feature:

1. Read `docs/features/README.md` if it exists.
2. Identify the feature id from the request, code module, route, domain, or existing documentation.
3. Read `docs/features/<feature-id>/README.md` if it exists.
4. Follow its current source-of-truth links before proposing or implementing changes.

Never assume an old plan is authoritative merely because it is detailed. Prefer current code, tests, accepted specifications, and recent verified decisions.

### Step 2: Create the Minimal Structure When Missing

Use lowercase hyphen-case for feature ids:

```text
docs/features/
├── README.md
└── <feature-id>/
    ├── README.md
    ├── prd/
    ├── api/
    ├── plans/
    └── archive/
```

For an existing repository, create only the directories needed now. Link useful documents where they already live before considering a migration.

The global index should remain a compact navigation and status surface:

```markdown
# Feature Tracks

| Feature | Status | Track | Source of Truth | Updated | Notes |
|---|---|---|---|---|---|
| Checkout | active | `checkout/README.md` | `checkout/prd/checkout.md` | 2026-07-13 | Payment retry work in progress |
```

Use project-local status names when the repository already defines them. Otherwise prefer a small vocabulary such as `planned`, `active`, `stable`, `paused`, or `deprecated`.

### Step 3: Maintain the Feature Track

Each `docs/features/<feature-id>/README.md` should summarize current truth and link to detailed evidence:

```markdown
# Checkout Feature Track

## Current Status

Checkout supports one-time card payments. Automatic payment retry is in progress.

## Source of Truth

- Checkout PRD: `prd/checkout.md`
- Payments API: `api/payments.md`
- Current implementation plan: `plans/payment-retry.md`

## Current Behavior

- Customers can complete one-time card payments.
- Failed payments currently require a manual retry.

## Decisions

- Preserve idempotency keys across automatic retries.
- Keep retry policy in the payments service.

## Known Risks

- The provider sandbox does not reproduce every production decline code.

## Changelog

- 2026-07-13: Added the retry plan and recorded idempotency requirements.
```

Update the track when any of these change:

- user-visible or system-visible behavior,
- endpoints, data models, dependencies, or integrations,
- durable decisions and trade-offs,
- rollout constraints, migrations, risks, or follow-ups,
- tests, plans, specifications, or other source-of-truth links.

Keep detailed requirements and designs in their own documents. The feature track should explain what is true now and where to find the proof.

### Step 4: Reconcile the Track Before Completion

Before claiming the feature work is complete:

1. Update the feature track with the actual verified outcome, not only the intended plan.
2. Update the global index when status, date, links, or notes changed.
3. Check that every relative Markdown link resolves.
4. Confirm the track contains current status, source-of-truth links, decisions, risks, and a dated changelog.
5. Record unresolved blockers or follow-ups explicitly.
6. Report validation gaps honestly when a required check could not be run.

## Examples

### Example 1: Resume a Feature Across Sessions

```text
User: Continue the checkout retry feature and make sure the next agent understands what changed.

Agent workflow:
1. Read docs/features/README.md and docs/features/checkout/README.md.
2. Open the linked PRD, API notes, and current implementation plan.
3. Verify the existing behavior in code and tests.
4. Implement and test the requested retry behavior.
5. Update Current Behav
