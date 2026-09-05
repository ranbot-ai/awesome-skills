---
name: grilling
description: Interview the user relentlessly about a plan or design. Use when the user wants to stress-test a plan before building, or uses any 'grill' trigger phrases. 
category: AI & Agents
source: antigravity
tags: [api, claude, ai, agent, workflow, design]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/grilling
---


## When to Use

Use when this workflow matches the user request: Interview the user relentlessly about a plan or design. Use when the user wants to stress-test a plan before building, or uses any 'grill' trigger phrases.


_Source: [mattpocock/skills](https://github.com/mattpocock/skills) (MIT)._Interview me relentlessly about every aspect of this plan until we reach a shared understanding. Walk down each branch of the design tree, resolving dependencies between decisions one-by-one. For each question, provide your recommended answer.

Ask the questions one at a time, waiting for feedback on each question before continuing. Asking multiple questions at once is bewildering.

If a question can be answered by exploring the codebase, explore the codebase instead.

## Example

**User request:**

> Use @grilling for this task: Interview the user relentlessly about a plan or design.

## Limitations

- Requires the upstream tool, account, API key, or local setup when the workflow names one.
- Does not authorize destructive, production, paid, or external-message actions without explicit user approval.
- Validate generated artifacts or recommendations against the user's real sources before treating them as final.
