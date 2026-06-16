---
name: accint-solve
description: Route agent work through AccInt's MCP memory loop: retrieve prior outcomes, resolve frames, and close commitments with evidence. 
category: AI & Agents
source: antigravity
tags: [mcp, claude, ai, agent, workflow, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/accint-solve
---


# AccInt Solve

## Overview

AccInt is a local-first MCP memory server for coding agents. It keeps a scored
record of retrieved experience, open commitments, continuation frames, and
outcome feedback so the next agent run can build on what actually worked.

Use this skill when AccInt is already configured in the host as an MCP server.
The skill adapts AccInt's public `solve` Claude skill into a host-agnostic
workflow for Claude Code, Codex CLI, Cursor, Gemini CLI, OpenCode, and other
agent runtimes that can call MCP tools.

## When to Use This Skill

- Use when starting non-trivial coding-agent work where prior decisions,
  debugging history, repo-specific habits, or maintainer feedback may matter.
- Use when a task may require multiple attempts and you want an explicit
  commitment ID that can later receive a real outcome.
- Use when AccInt returns a continuation frame and the agent must reason locally
  before submitting a proposal back to the memory loop.
- Use after verification, merge, deployment, maintainer response, or other
  reality signal to close the commitment with an honest outcome.
- Do not use when the host has no AccInt MCP tools configured; first install or
  configure AccInt, then rerun the workflow.

## How It Works

### Step 1: Confirm the AccInt MCP tools exist

Use the host's available MCP/tool list to confirm an AccInt server exposes the
two verbs:

```text
acc_retrieve(query)
acc_act(runtime, input)
```

If the host names the tools with a namespace prefix, use the equivalent
AccInt MCP verbs. If neither verb is available, stop and ask the user to
configure AccInt rather than inventing memory results.

### Step 2: Retrieve before planning

Before a non-trivial step, retrieve relevant prior work:

```json
{"query": "the concrete task or subtask you are about to perform"}
```

Read the returned memories and cite the `[ids]` you actually build on. Treat
retrieved memories as evidence to consider, not as a substitute for inspecting
the current repository, running tests, or checking live external state.

### Step 3: Route the goal through `solve`

Open an AccInt commitment for the concrete goal:

```json
{"runtime": "solve", "input": "the concrete goal to accomplish"}
```

If the response is final, use the answer, commitment ID, and cited memory IDs.
If the response is a `brain_frame`, keep the reasoning in the current session:
inspect the frame, resolve the missing judgment or knowledge from the workspace,
then submit a concise proposal through `continue`.

### Step 4: Resolve continuation frames

For a returned frame, submit only the frame ID and your proposal text unless the
host explicitly manages tokens for you:

```json
{
  "runtime": "continue",
  "input": {
    "frame_id": "bf_...",
    "proposal_text": "reasoned answer, plan, or decision grounded in the current evidence"
  }
}
```

Do not leave a received frame unresolved. If the frame expires, close or rerun
the bound commitment rather than pretending the continuation succeeded.

### Step 5: Execute and verify outside AccInt

Do the actual work in the repository, browser, shell, issue tracker, or other
real environment. Verify with the strongest relevant evidence available: tests,
builds, linters, link checks, PR state, screenshots, maintainer replies, or
production telemetry.

AccInt stores the learning loop; it does not replace the work or the evidence.

### Step 6: Close the commitment with an outcome

When reality answers, record the result:

```json
{
  "runtime": "outcome",
  "input": {
    "ref": "solved:...",
    "good": true,
    "note": "brief evidence: tests passed, PR merged, deploy succeeded, reviewer accepted, or exact failure reason"
  }
}
```

Use `good: false` when the approach failed. Do not tag an outcome as external
or owner-validated unless a real external system or the owner actually supplied
that verdict.

## Examples

### Example 1: Start a repository fix with memory

```text
1. acc_retrieve({"query":"fix failing parser tests in this repo"})
2. Read the returned memories; cite only the relevant [ids].
3. acc_act(runtime="solve", input="Fix the failing parser tests and verify them")
4. Inspect the repo, edit files, run the parser tests.
5. acc_act(runtime="outcome", input={"ref":"solved:...", "good":true, "note":"parser test command passed"})
```

### Example 2: Handle a continuation frame

```text
AccInt returns frame bf_123 asking for a judgment about whether to patch the
schema or the caller.

1. Inspect the schema and caller in the current repo.
2. Decide from code evidence, not memory alone.
3. acc_act(runtime="continue", input={"frame_id":"bf_123", "proposal_text":"Patch the caller because..."})
4. Continue implementation and verification.
```

## Best Practices

- Cite retrieved `[ids]` whenever they shape your plan or answer.
- Keep owner-held facts owner-held: ask instead of fabricating preferences,
  credentials, identity, or history the repository cannot prove.
- Use small, concrete solve goals;
