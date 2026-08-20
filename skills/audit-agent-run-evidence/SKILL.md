---
name: audit-agent-run-evidence
description: Use when an agent, harness, gateway, MCP workflow, or multi-step automation claims completion and the available traces, checkpoints, approvals, tool calls, or deployment records must be judged without
category: AI & Agents
source: antigravity
tags: [mcp, ai, agent, automation, workflow, design, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/audit-agent-run-evidence
---


# Audit Agent Run Evidence

## Overview

Turn an end-to-end success statement into independently decidable claims. Reconstruct what happened from available records, grade each claim against the strongest witness, and keep missing evidence distinct from failure.

This is a read-only audit. Do not rerun tools, approve actions, resume workers, deploy artifacts, or modify evidence unless the user separately authorizes those actions.

## When to Use

- Auditing a completed or interrupted agent run from traces and artifacts.
- Checking whether an agent's end-to-end success claim is actually supported.
- Reviewing MCP, gateway, sandbox, checkpoint, retry, memory, approval, or deployment evidence.
- Separating autonomous success from human-assisted or merely requested outcomes.

Do not use this skill to design instrumentation for a future run or to perform the missing actions. It evaluates evidence that already exists.

## Establish the Contract

Record these inputs before judging the run:

- declared goal and terminal success criteria;
- run, workflow, task, and parent identifiers;
- immutable code, configuration, model, prompt, tool-schema, and artifact revisions when available;
- actors and trust boundaries: orchestrator, worker, sandbox, MCP server, gateway, human approver, CI, and deployment platform;
- retry, deadline, token, cost, concurrency, and human-escalation budgets;
- supplied evidence inventory and known collection gaps.

Do not silently strengthen the original success criteria. Do not weaken them to match the evidence that happens to exist.

## Build a Claim Ledger

Split the overall claim into atomic predicates. Give every row a stable claim ID.

| Field | Required content |
|---|---|
| `claim_id` | Stable identifier |
| `predicate` | One falsifiable statement |
| `required_witness` | Source that can independently prove it |
| `evidence_refs` | Exact event, log, artifact, or record IDs |
| `counterevidence_refs` | Conflicting records |
| `coverage` | Required instances versus observed instances |
| `verdict` | `proven`, `partially_proven`, `contradicted`, or `not_proven` |
| `gap` | Missing field, actor, interval, or verification |

Typical predicates include:

- every required step reached its terminal postcondition;
- sandbox isolation held for every executing worker;
- each required MCP/tool call has a correlated response;
- retries respected idempotency and did not duplicate committed effects;
- a checkpoint was durably written, verified, and actually used for resume;
- parallel branches satisfied the declared join policy;
- memory reads cite a versioned source rather than an untracked summary;
- retry, deadline, token, cost, and escalation budgets were respected;
- approval was granted by an authorized human for the exact artifact and target;
- the platform deployed that same artifact and passed the declared health checks.

## Normalize Evidence

Preserve original records and create a normalized event view with:

```json
{
  "run_id": "run-123",
  "event_id": "evt-42",
  "sequence": 42,
  "observed_at": "RFC3339 timestamp",
  "actor": {"type": "worker", "id": "worker-2"},
  "operation": "mcp.search",
  "state_before": "researching",
  "state_after": "researching",
  "attempt": 2,
  "request_id": "req-9",
  "idempotency_key": "task-7:search:2",
  "input_digest": "sha256:...",
  "output_digest": "sha256:...",
  "checkpoint_seq": 3,
  "parent_event_id": "evt-41",
  "status": "succeeded",
  "evidence_ref": "tool-log:991"
}
```

Use `null` or `unknown` for absent values. Never synthesize IDs, timestamps, digests, costs, approvals, or outcomes.

Verify bundle hashes or signatures when supplied. Check duplicate IDs, broken parent links, non-monotonic per-source sequences, impossible state transitions, unaccounted clock skew, and unexplained trace gaps. Treat an integrity failure as counterevidence for claims that depend on the affected records.

## Rank Witnesses

Prefer the witness closest to the effect:

| Claim | Strong witness | Insufficient alone |
|---|---|---|
| Code changed | Commit/tree and diff | Agent narration |
| Test passed | Complete test result bound to revision | Command invocation |
| MCP effect occurred | Server or provider audit record | Client request |
| Checkpoint resumed | Durable checkpoint plus verified load event | Checkpoint file exists |
| Human approved | Authorization-system decision bound to artifact and target | Approval requested |
| Deployment succeeded | Platform record plus required health checks | Deployment started |
| Memory grounded a decision | Versioned memory read and citation | Final answer resembles memory |

An orchestrator and its child worker are not independent witnesses when they repeat the same unverified result. A cryptographic digest proves byte identity, not semantic correctness.

## Reconstruct the Run

1. Order events by causal links and per-source sequence; use timestamps only as supporting evidence.
2. Build the state-transition path and mar
