---
name: codebase-onboarding
description: Onboard a developer to a repository using Ontoly graph summaries. Use when asked to explain a new codebase, identify entrypoints, map packages, or suggest first files to inspect. 
category: Document Processing
source: antigravity
tags: [node, mcp, ai, agent, llm, workflow, template, document]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/codebase-onboarding
---

## When to Use
- Use when this upstream workflow matches the user's stated goal.
- Use when the task requires the procedures documented in this skill.

# Codebase Onboarding

Use this skill when the user asks for codebase onboarding using Ontoly evidence.

## Required Workflow

Follow [the shared Ontoly workflow. Also read [graph evidence rules, [MCP usage, [best practices, and [fallback rules when the task requires detail.

## Ontoly Capabilities

Use these capabilities first: `ExplainArchitecture`, `FindEntrypoints`, `GraphStatistics`, `FindFeatureOwner`, `EvidencePack`.

## Output Contract

Return:

- answer or plan
- capabilities invoked
- graph evidence with node ids, edge types, source spans, and graph hash when available
- confidence: high, medium, or low
- fallback reason if repository files were inspected

## Boundaries

Do not implement compiler, query, MCP, SDK, or business logic in the skill. Do not search repository files until Ontoly cannot answer or evidence must be confirmed.

## Resources

- [Examples
- [Prompt template
- [Capability notes

## Learn more

- Documentation: https://ontoly.xyz/docs
- This skill on the web: https://ontoly.xyz/skills#codebase-onboarding
- All Ontoly Agent Skills: https://ontoly.xyz/skills
- Install via skills.sh: https://www.skills.sh/?q=0xsarwagya/ontoly


## Examples

```text
User: Apply this skill to my current task.
Assistant: Follow the workflow in this skill, cite limitations, and ask before risky steps.
```

## Limitations

- Imported upstream skill; verify credentials, permissions, and safety boundaries before execution.
- Does not replace environment-specific validation, testing, or maintainer review.
