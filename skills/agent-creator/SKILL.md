---
name: agent-creator
description: Create custom AI subagents with proper plugin structure, persona generation, and companion routing skills. 
category: AI & Agents
source: antigravity
tags: [python, javascript, markdown, api, claude, ai, agent, automation, workflow, template]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/agent-creator
---


# Agent Creator

A skill for creating custom subagents packaged inside proper plugins. This skill
handles the entire flow: gathering requirements, generating a rich persona from
even a one-line description, scaffolding the correct folder structure, and
optionally creating a companion skill that auto-routes tasks to the new agent.

## When to use

Use this skill whenever you need a dedicated, isolated "brain" to handle a specific repetitive task, or when you find yourself repeatedly pasting the same massive system prompt or constraints into the main chat. Creating a dedicated subagent keeps the main conversation lightweight and focused.

## Why this exists

The contributed example assumes a Windows-style host layout `<appDataDir>\config\plugins\`; it is not a universal Codex/Claude plugin path. For
a subagent to be properly registered and invokable, it needs to be inside a
plugin's `agents/` directory with a valid `plugin.json`. Getting this structure
right manually is tedious and error-prone. This skill automates the entire
process so the user can go from "I want an agent that reviews code" to a reviewable agent package. Activation requires host-specific schema validation and an actual invocation check.

## Target directory

Confirm the user's target host and its supported schema/path first. Codex and Claude distribution remain intentionally blocked in this skill's metadata until compatible packaging is validated. Do not remove these blocks merely because a folder can be created. The legacy example layout is:
```
<appDataDir>\config\plugins\<plugin-name>\
```

If the user wants the agent inside an **existing plugin**, add the agent folder
to that plugin's `agents/` directory. If no plugin is specified, create a new
plugin named `<agent-name>-plugin`.

Before creating any path, validate both `<agent-name>` and `<plugin-name>`:

- accept only lowercase letters, numbers, and single hyphens: `^[a-z0-9]+(-[a-z0-9]+)*$`
- reject `/`, `\`, `.`, `..`, absolute paths, whitespace, shell metacharacters, and YAML metacharacters
- resolve the final target path and verify it stays under `<appDataDir>\config\plugins\`
- stop and ask for a safe replacement instead of sanitizing a suspicious name silently

## Workflow

Use information already supplied, make routine reversible drafting choices, and ask only for material missing host, purpose or placement requirements. Creating a persona does not grant permission to spawn agents or modify global host configuration.

### Step 1: Gather requirements

Ask the user these questions one at a time (use the `ask_question` tool where
appropriate, or ask conversationally if the flow is natural):

1. **Agent name** — What should this agent be called?
   - Guide: short, lowercase, hyphenated (e.g., `code-reviewer`, `sql-expert`, `test-writer`)

2. **Purpose** — What is this agent for? (even a single line is fine)
   - Example: "review code", "write SQL queries", "generate unit tests"

3. **Plugin placement** — Should this go into an existing plugin or a new one?
   - List the user's existing plugins from `<appDataDir>\config\plugins\`
   - Default: create a new plugin named `<agent-name>-plugin`

4. **Companion skill** — Should I also create a routing skill that auto-triggers
   this agent? (Create only when requested)

### Step 2: Generate the persona

This is the most important step. The user might give you a one-liner like
"for reviewing code" — your job is to expand that into a rich, detailed persona
that makes the agent genuinely excellent at its job.

A good persona includes:

- **Identity**: Who the agent is and what it specializes in
- **Expertise areas**: Specific domains, technologies, or methodologies it knows
- **Personality traits**: How it communicates (e.g., direct, thorough, cautious)
- **Working style**: How it approaches problems step by step
- **Output format**: What its responses look like (structured, prose, etc.)
- **Constraints**: What it should NOT do or what it should defer to others
- **Quality standards**: What "good work" looks like for this agent

For example, if the user says "for reviewing code", generate a persona like:

> Act as a careful code reviewer working across multiple
> languages and paradigms. You approach every review with three priorities:
> correctness first, maintainability second, performance third. You never
> approve code you haven't fully understood. You flag security vulnerabilities
> with high urgency. You distinguish between blocking issues (must fix),
> suggestions (should consider), and nitpicks (style preference). You provide
> concrete fix suggestions, not just problem descriptions. You check for edge
> cases, error handling, resource leaks, and race conditions. You respect the
> codebase's existing patterns unless they are actively harmful.

### Step 3: Create the folder structure

Create the following structure:

```
plugins/<plugin-name>/
├── plugin.json
├── agents/
│   └── <agent-name>.md
└── skills/                    (only i
