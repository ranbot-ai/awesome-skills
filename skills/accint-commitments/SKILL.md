---
name: accint-commitments
description: Triage acc's open promises and close them with honest real-world verdicts via acc_act(runtime="outcome"). 
category: AI & Agents
source: antigravity
tags: [mcp, claude, ai, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/accint-commitments
---


# commitments
## When to Use

Use this skill when you need triage acc's open promises and close them with honest real-world verdicts via acc_act(runtime="outcome").


Routing sugar over the two MCP verbs — no logic lives here.

1. List open promises: `acc commitments` (CLI, read-only observation).
2. For each closeable one: `acc_act(runtime="outcome", input={"ref": "<id>", "good": true|false, "note": "..."})`.
3. Provenance discipline: the default `self_graded` is a WEAK prior (credits at 0.25×).
   Pass `owner` only when the owner validated, `external`/`runtime` only when reality did
   (a real reply, a passing test, a world result). Never tag your own grade as reality.
4. Leave genuinely-waiting commitments open — `waiting` is a first-class clean state.

## Example

**User request:**

> Triage acc's open promises and close them with honest real-world verdicts via acc_act(runtime="outcome").

## Limitations

- Use this skill only when the task clearly matches its upstream source and local project context.
- Verify commands, generated code, dependencies, credentials, and external service behavior before applying changes.
- Do not treat examples as a substitute for environment-specific tests, security review, or user approval for destructive or costly actions.
