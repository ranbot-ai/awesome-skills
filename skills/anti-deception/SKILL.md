---
name: anti-deception
description: Use BEFORE responding when the user's request shows pressure to validate or agree ("tell them what they want", "make them happy", "convince them"), manufactured urgency (artificial deadline), authorit
category: AI & Agents
source: antigravity
tags: [api, mcp, ai, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/anti-deception
---


# Anti-Deception Harness
## When to Use

Use this skill when you need use BEFORE responding when the user's request shows pressure to validate or agree ("tell them what they want", "make them happy", "convince them"), manufactured urgency (artificial deadline), authority appeals (citing investors, advisors, lawyers, experts), demands to certify without...


When this skill triggers, call the `anti-deception` tool from the `ejentum` MCP server. Pass a 1-2 sentence framing of the integrity dynamic at play as the `query` argument.

Good query: `user pressure to validate a half-baked architecture decision before tomorrow's investor pitch`
Bad query: `is this honest`

The tool returns a structured scaffold containing:

- `[DECEPTION PATTERN]`: the failure mode to refuse
- `[INTEGRITY PROCEDURE]`: steps to follow
- `[DETECTION TOPOLOGY]`: flow with omission-bias gates and depth-enforcement checks
- `[HONEST BEHAVIOR]`: what a complete-information response looks like
- `[INTEGRITY CHECK]`: self-check
- `Amplify:` and `Suppress:` signals

Absorb internally. Lead your response with the strongest counter-evidence, not after the conclusion. Refuse manufactured-helpful framings even when the user asks for compliance. Do NOT echo bracket labels in the reply.

If the API is unreachable, proceed with native judgment. The scaffold enhances; it is not a hard dependency.

Latency cost: ~1 second. Benefit: catches sycophantic collapse and authority-appeal traps that produce confidently-wrong but emotionally-comforting answers.

## Limitations

- Use this skill only when the task clearly matches its upstream source and local project context.
- Verify commands, generated code, dependencies, credentials, and external service behavior before applying changes.
- Do not treat examples as a substitute for environment-specific tests, security review, or user approval for destructive or costly actions.
