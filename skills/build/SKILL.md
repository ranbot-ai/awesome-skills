---
name: build
description: name: build This command manages a 4-phase feature development workflow for building major features. Parse `$ARGUMENTS` to determine which subcommand to run. 
category: Document Processing
source: antigravity
tags: [markdown, api, ai, workflow, design, document, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/build
---


---
name: build
description: Feature development pipeline - research, plan, track, and implement major features.
argument-hint: [subcommand] [name]
metadata:
  author: Shpigford
  version: "1.0"
---

Feature development pipeline - research, plan, track, and implement major features.

## When to Use
- You need a structured workflow for building a major feature across research, planning, implementation, and tracking.
- The task involves moving a feature through named phases such as `research`, `implementation`, `progress`, or `phase`.
- You want one command to coordinate status, next steps, and phased delivery for a feature effort.

## Instructions

This command manages a 4-phase feature development workflow for building major features. Parse `$ARGUMENTS` to determine which subcommand to run.

**Arguments provided:** $ARGUMENTS

### Argument Parsing

Parse the first word of $ARGUMENTS to determine the subcommand:

- `research [name]` → Run the Research phase
- `implementation [name]` → Run the Implementation phase
- `progress [name]` → Run the Progress phase
- `phase [n] [name]` → Run Phase n of the implementation
- `status [name]` → Show current status and suggest next step
- (empty or unrecognized) → Show usage help

If the feature name is not provided in arguments, you MUST use AskUserQuestion to prompt for it.

---

## Subcommand: Help (empty args)

If no arguments provided, display this help:

```
/build - Feature Development Pipeline

Subcommands:
  /build research [name]        Deep research on a feature idea
  /build implementation [name]  Create phased implementation plan
  /build progress [name]        Set up progress tracking
  /build phase [n] [name]       Execute implementation phase n
  /build status [name]          Show status and next steps

Example workflow:
  /build research chat-interface
  /build implementation chat-interface
  /build progress chat-interface
  /build phase 1 chat-interface
```

Then use AskUserQuestion to ask what they'd like to do:

- question: "What would you like to do?"
- header: "Action"
- multiSelect: false
- options:
  - label: "Start new feature research"
    description: "Begin deep research on a new feature idea"
  - label: "Continue existing feature"
    description: "Work on a feature already in progress"
  - label: "Check status"
    description: "See what step to do next for a feature"

---

## Subcommand: research

### Step 1: Get Feature Name

If feature name not in arguments, use AskUserQuestion:

- question: "What's a short identifier for this feature? (lowercase, hyphens ok - e.g., 'chat-interface', 'user-auth', 'data-export'). Use 'Other' to type it."
- header: "Feature name"
- multiSelect: false
- options:
  - label: "I'll type the name"
    description: "Enter a short, kebab-case identifier for the feature"

### Step 2: Check for Existing Research

Check if `docs/{name}/RESEARCH.md` already exists.

If it exists, use AskUserQuestion:

- question: "A RESEARCH.md already exists for this feature. What would you like to do?"
- header: "Existing doc"
- multiSelect: false
- options:
  - label: "Overwrite"
    description: "Replace existing research with fresh exploration"
  - label: "Append"
    description: "Add new research below existing content"
  - label: "Skip"
    description: "Keep existing research, suggest next step"

If "Skip" selected, suggest running `/build implementation {name}` and exit.

### Step 3: Gather Feature Context

Use AskUserQuestion to understand the feature:

- question: "Describe the feature you want to build. What problem does it solve? What should it do? (Use 'Other' to describe)"
- header: "Description"
- multiSelect: false
- options:
  - label: "I'll describe it"
    description: "Provide a detailed description of the feature"

### Step 4: Research Scope

Use AskUserQuestion:

- question: "What aspects should the research focus on?"
- header: "Focus areas"
- multiSelect: true
- options:
  - label: "Technical implementation"
    description: "APIs, libraries, architecture patterns"
  - label: "UI/UX design"
    description: "Interface design, user flows, interactions"
  - label: "Data requirements"
    description: "What data to store, schemas, privacy"
  - label: "Platform capabilities"
    description: "OS APIs, system integrations, permissions"

### Step 5: Conduct Deep Research

Now conduct DEEP research on the feature:

1. **Codebase exploration**: Understand existing patterns, similar features, relevant code
2. **Web search**: Research best practices, similar implementations, relevant APIs
3. **Technical deep-dive**: Explore specific technologies, libraries, frameworks
4. **Use AskUserQuestion FREQUENTLY**: Validate assumptions, clarify requirements, get input on decisions

Research should cover:
- Problem definition and user needs
- Technical approaches and trade-offs
- Required data models and storage
- UI/UX considerations
- Integration points with existing code
- Potential challenges and risks
- Recommended approac
