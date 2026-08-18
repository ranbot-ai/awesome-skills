---
name: cross-platform-contract-propagation-audit
description: Use when auditing whether a field, enum, flag, or API contract propagates consistently across storage, services, clients, analytics, and tests. 
category: Business & Marketing
source: antigravity
tags: [node, api, claude, ai, workflow, design, presentation, security, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/cross-platform-contract-propagation-audit
---


# Cross-Platform Contract Propagation Audit

## Overview

Audit a contract change from its source through every transformation and consumer before release. Treat a field that exists in one schema as incomplete until its meaning, defaults, wire behavior, rollout controls, client handling, analytics, and tests are proven across all relevant paths.

This is a read-only evidence workflow. It reports propagation gaps; it does not implement them.

## When to Use This Skill

- Use when adding or changing a field, enum value, status, capability, or feature flag shared by multiple components.
- Use when database, backend, API, Web, Android, iOS, jobs, events, or analytics may interpret the same value differently.
- Use when a change must preserve existing records, older clients, or a default-off rollout.
- Use when a change looks complete in one endpoint but may be missing from alternate entry points or generated models.

## How It Works

### Step 1: Write the semantic contract

Before tracing files, state the business invariant and define every observable state. Distinguish values that languages and serializers often collapse:

| State | Questions to answer |
|---|---|
| missing | Is the property absent on the wire or in an old record? |
| `null` | Is it unknown, inherited, unsupported, or invalid? |
| `false` or zero | Is this an explicit disabled value or a default? |
| `true` or non-zero | What behavior becomes available? |
| unknown enum | Must old consumers ignore, preserve, or reject it? |

Record compatibility requirements, ownership, rollout condition, and the exact user-visible or system behavior for each state. Do not accept `optional`, `nullable`, and `default false` as equivalent without evidence.

### Step 2: Enumerate the propagation graph

List every relevant node before judging completeness:

```text
source of truth
  -> persistence and migration
  -> domain model and mapper
  -> service or policy computation
  -> every API, event, cache, and job projection
  -> generated or handwritten client model
  -> client state and presentation logic
  -> analytics and operational observability
  -> tests, rollout, and rollback checks
```

Include alternate read/write endpoints, list/detail projections, background consumers, offline caches, admin surfaces, older app versions, and feature-flag evaluation points when they are in scope. Mark a node `not applicable` only with a reason.

### Step 3: Trace evidence edge by edge

For each edge, cite the producer, transformation, consumer, and test using file paths, symbols, schema names, or other inspectable evidence. Assign one status:

| Status | Meaning |
|---|---|
| `proven` | Producer and consumer agree, with direct evidence and relevant test coverage. |
| `partial` | Some paths or states agree, but coverage is incomplete. |
| `missing` | A required propagation edge or consumer is absent. |
| `conflict` | Two layers implement different semantics. |
| `unknown` | Evidence is unavailable or ambiguous. |
| `not_applicable` | The layer is outside scope, with a stated reason. |

Do not upgrade `likely`, convention, type compatibility, or a framework default to `proven`. A declaration proves shape, not runtime mapping or behavior.

### Step 4: Check the high-risk boundaries

Inspect these boundaries explicitly:

- **Migration and existing data:** default, backfill, nullability, rollback, mixed-version reads and writes.
- **Domain mapping:** missing/null coercion, enum fallbacks, validation, derived values, serialization symmetry.
- **Fan-out surfaces:** list and detail DTOs, events, caches, jobs, search indexes, SDKs, and alternate API versions.
- **Client compatibility:** missing and explicit-null decoding, unknown enums, generated-model drift, cached payloads, release or minified builds.
- **Rollout control:** flag default, evaluation location, cohort consistency, kill switch, and behavior when stored data disagrees with the flag.
- **Analytics:** offered, rendered, attempted, succeeded, and failed events carry enough contract and version context to join reliably.

### Step 5: Build a state-by-path test matrix

Cross the semantic states from Step 1 with every material path from Step 2. At minimum, include existing-data defaults, enabled and disabled values, flag on and off, alternate endpoints, current clients, and representative older clients.

For each cell, record the expected result, evidence, and status. A unit test at one layer does not prove an end-to-end cell. Use `unknown` for unexecuted cells.

### Step 6: Decide against explicit release gates

Derive gates from the stated contract, not from intuition. A release is blocked when an edge or compatibility invariant that the contract explicitly requires is `missing`, `conflict`, or `unknown`, or when rollback cannot contain the new behavior. Use `inconclusive` only when the release contract itself is absent or ambiguous, so the audit cannot determine which edges or invariants are required. Do not downgrade a 
