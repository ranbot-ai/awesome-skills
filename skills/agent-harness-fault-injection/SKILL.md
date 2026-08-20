---
name: agent-harness-fault-injection
description: Use when an agent workflow needs deterministic recovery evidence for sandbox, MCP/tool, worker, checkpoint, memory, or orchestration failures. 
category: AI & Agents
source: antigravity
tags: [mcp, claude, ai, agent, workflow, design, security, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/agent-harness-fault-injection
---


# Agent Harness Fault Injection

## Overview

Use a deterministic, non-production fault schedule to test whether an agent
workflow preserves state, budgets, safety boundaries, and evidence when a
dependency fails. The output is a small fault matrix, an event timeline, and a
verdict that distinguishes recovered, contained, unrecoverable, and
inconclusive runs.

## When to Use This Skill

- Use when a multi-step agent, state machine, loop, or multi-agent workflow has a new recovery path.
- Use when sandbox execution, an MCP/tool call, a worker, a checkpoint store, or memory can time out or disappear.
- Use before claiming retry, resume, deadline, isolation, or partial-failure behavior is production-ready.
- Use when a regression needs reproducible failure evidence instead of a random chaos run.

Do not use this skill against a production target, real user data, live credentials,
or an unbounded external service. Convert those cases to a local simulator or an
authorized staging harness first.

## Safety and Boundary Preconditions

1. Freeze the workflow revision, model/prompt configuration, tool schemas, seed,
   input fixture, timeout, retry budget, deadline, and expected terminal states.
2. Run in a disposable sandbox with synthetic inputs and stubbed tools. Keep
   network disabled unless the test explicitly needs a local test server.
3. Make every injected failure an in-memory or fixture-controlled event. Never
   delete real data, revoke real credentials, kill an unrelated process, or
   mutate a live service to create a failure.
4. Record the test scope and a run identifier before starting. A missing scope,
   fixture, or recovery contract makes the verdict `inconclusive`.

## Recovery Contract

Write the invariant before injecting a fault. A useful contract names the state
that must survive and the side effects that must not repeat:

```text
After recovery, resume from the latest durable checkpoint, preserve the task
identity and safety policy, spend no more than the remaining retry/deadline
budget, and commit each externally visible effect at most once.
```

Model the workflow with explicit states. For example:

```text
created -> running -> checkpointed -> waiting_for_tool
                       |                |
                       v                v
                    failed <--------- recovering -> resumed -> completed
```

For each transition, define the owner, durable fields, allowed retry count,
and terminal behavior. In-memory values are not checkpoints unless the harness
proves they survive the simulated restart.

## Fault Matrix

Select the smallest set of faults that covers the new recovery logic. Do not
randomize the schedule until a deterministic schedule has passed.

| Fault | Injection boundary | Required observation | Expected containment |
|---|---|---|---|
| sandbox denial | before a tool starts | no unsafe side effect; reason is retained | retry only when policy allows |
| MCP/tool timeout | after request id is assigned | timeout is attributed to that request | bounded retry with same idempotency key |
| worker restart | after checkpoint write | worker reloads the same task version | resume from latest checkpoint |
| missing/stale checkpoint | before resume | stale data is rejected or marked | stop safely; never invent progress |
| parallel branch failure | one branch after fan-out | sibling status is preserved | join policy decides retry, degrade, or stop |
| memory loss | clear ephemeral context | durable facts are reconstructed | ask or stop when required facts are absent |
| retry/deadline exhaustion | on the final attempt | no extra call is scheduled | terminal `failed` or `timed_out` |

## Deterministic Injection Schedule

Use event numbers rather than wall-clock randomness. A schedule should be
portable across harnesses:

```json
{
  "seed": "harness-fixture-07",
  "faults": [
    {"event": "tool.call", "ordinal": 2, "kind": "timeout", "tool": "search"},
    {"event": "worker.start", "ordinal": 2, "kind": "restart"},
    {"event": "branch.join", "ordinal": 1, "kind": "partial_failure", "branch": "summarize"}
  ]
}
```

The harness should emit the schedule, not merely the seed. Keep fault identity
separate from the observed error so a wrapper cannot accidentally turn a
timeout into a generic failure. Run the same schedule twice and compare the
normalized timeline before trying a different schedule.

## Recovery Rules by Boundary

### Sandbox and MCP/tool failures

- Assign a request id and idempotency key before the call.
- Distinguish timeout, explicit tool error, invalid output, and policy denial.
- Retry only the declared retryable classes; preserve the original error and
  attempt count in the evidence.
- Do not retry a side effect unless the tool contract says the key is safe to
  replay. A read timeout is not proof that a write did not happen.
- When the deadline or retry budget is exhausted, emit one terminal event and
  stop scheduling work.

### Worker restart an
