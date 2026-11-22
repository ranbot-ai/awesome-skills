---
name: agent-instructions
description: Writing or restructuring AGENTS.md or CLAUDE.md, adding a rule ('remember this'), or after an agent ignored a rule it had: make each rule get met when it applies. 
category: AI & Agents
source: antigravity
tags: [python, claude, ai, agent, automation, workflow, design, security, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/agent-instructions
---


# Agent instructions — rules met at the moment they apply

## Operational boundaries

Keep the scope, sandbox, credentials and approval settings supplied by the user or host. Obtain authorization before delegating, exposing project files to another provider, enabling connectors or hooks, using paid services or deploying. Use synthetic or redacted inputs for examples. Keep security reviews static and defensive, with findings and fixes grounded in source inspection.

## When to Use

Writing or restructuring AGENTS.md or CLAUDE.md, adding a rule ('remember this'), or after an agent ignored a rule it had: make each rule get met when it applies.


**Meet each rule at the moment it applies.** A rule written down is not yet a rule an agent follows. This skill writes and maintains an app repository's instruction file as the product grows.

**Use the entry file to route every session's context.** The entry file is `AGENTS.md`, `CLAUDE.md`, or both. It is where every session enters and what routes the rest. The method is stack-independent; examples come from repositories named by kind.

1. **The entry file routes; the depth lives where the moment sends you.** A rule the agent is not looking at when it acts does not exist for that act.
2. **Make rules that depend on memory at decisive moments into code paths.** Use a test, script or required argument, because prose loses that contest.
3. **Maintain the file at every release and fix every mistake with its receipt.** Maintain it rather than accumulating rules.

## The shape: a chain, not a manual

**Root routes to entry points; entry points route to operative files; operative files link to evidence.** Each layer points down; none restates the layer below.

```
entry file (loaded every session)   — routes; holds only what every session needs
 └─ router rows: "when you are…"    — the rule that is easy to miss, and what to open
     └─ operative files (docs/, skills) — the procedure, the depth, the gotchas
         └─ evidence                — receipts, tables, postmortems, case studies
```

- **Route, don't summarize.** A summary of a doc in the entry file is a second copy that drifts. Carry the one sentence that must be met at the moment (the rule that is easy to miss) and its pointer.
- **No workflow content duplicates upward.** When a procedure appears in two layers, the upper copy is wrong within a month.
- **Make every file reachable from the entry file the day it is created.** `scripts/check_reachable.py` holds this (§ Files).

## The entry file: two sections

**Separate reusable building mechanics from the choices for this app.** The preamble explains the two sections in a few lines and names where the longer material lives. It tells the agent to find its moment in the router before starting.

- **Put the mechanics of building any app in Section 1.** Include ownership and authorization, threat model, stack and its choices, testing and delivery, working rules, router and file maintenance. Reuse these mechanics in the next product; replace its owner's choices and installed-pack inventory.
- **Put this app's identity and constraints in Section 2.** Include what it is, its users, its shape, who can do what, scope, data constraints and three lines of status. Replace this section per product; the `app-lifecycle` skill has its skeleton.
- **Section 1 wins on mechanics; Section 2 wins on product.** What neither says follows skill defaults. Where those are silent too, decide and say so in the summary.
- **When a library's default conflicts with the file, the file wins.** Say this in the file wherever a vendored skill or quickstart would teach otherwise.

**Record the owner's departures from skill defaults once, dated and in their words.** Put product choices in a short entry-file section beside testing and working rules. Put choices for every product in user-level instructions. Record model, builder, reviewer and fallback, review bar, what requires go, design taste and voice.

**Precedence: current session owner instruction > product entry file > user-level instructions > skill defaults.** Design detail can stay in the kit README, with an entry-file pointer; apply the `ui-design` skill.

**Give every reviewer a fallback, never “none”.** Apply the `independent-review` skill for reviewer choices. Rewrite “a model never reviews its own family's work” as “prefer another family”. Use a fresh session of the builder's family when no other can run.

**Graduate standing choices to the file immediately.** Memory in one agent does not reach another vendor's builder or reviewer (`references/maintenance.md`). Copy `references/agents-md-skeleton.md` for a starter file.

**After installing packs, record choices, a docs index and their router rows once.** Route a product's screens, or a mock of one, to applying `ui-design`. For existing code, read every installed skill that touches it against the code. Add the missing tests the skills name.

## Make sure it loads

**Keep one master instru
