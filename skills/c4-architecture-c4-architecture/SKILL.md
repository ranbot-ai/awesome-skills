---
name: c4-architecture-c4-architecture
description: Generate comprehensive C4 architecture documentation for an existing repository/codebase using a bottom-up analysis approach. 
category: Document Processing
source: antigravity
tags: [python, node, api, ai, agent, workflow, template, design, document, docker]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/c4-architecture-c4-architecture
---


# C4 Architecture Documentation Workflow

Generate comprehensive C4 architecture documentation for an existing repository/codebase using a bottom-up analysis approach.

Use a bottom-up source inventory to support C4 views, while selecting only levels useful to the audience. Specialized agents are optional execution helpers, not bundled tools or evidence that source was reviewed.

## Use this skill when

- Working on c4 architecture documentation workflow tasks or workflows
- Needing guidance, best practices, or checklists for c4 architecture documentation workflow

## Do not use this skill when

- The task is unrelated to c4 architecture documentation workflow
- You need a different domain or tool outside this scope

## Instructions

- Clarify goals, constraints, and required inputs.
- Apply relevant best practices and validate outcomes.
- Provide actionable steps and verification.

## Overview

This workflow creates comprehensive C4 architecture documentation following the [official C4 model](https://c4model.com/diagrams) by:

1. **Code Level**: Analyzing every subdirectory bottom-up to create code-level documentation
2. **Component Level**: Synthesizing code documentation into logical components within containers
3. **Container Level**: Mapping components to C4 applications/data stores with API documentation (shows high-level technology choices)
4. **Context Level**: Creating high-level system context with personas and user journeys (focuses on people and software systems, not technologies)

**Note**: According to the [C4 model](https://c4model.com/diagrams), you don't need to use all 4 levels of diagram - the system context and container diagrams are sufficient for most software development teams. Select useful levels first; code-level diagrams are optional and are not a function catalog for every directory. Preserve a source inventory even when detailed diagrams are omitted.

Use the user’s requested location, otherwise propose a new `C4-Documentation/` directory in the repository root.

Before writing, record repository/head, audience, system boundary and files actually inspected. Protect secrets/internal infrastructure details and follow existing docs conventions. C4 containers are applications or data stores, not synonymous with Docker containers or one deployment replica. Components belong inside one container; code directories do not by themselves establish component boundaries.

## Phase 1: Code-Level Documentation (Bottom-Up Analysis)

### 1.1 Discover All Subdirectories

- Use codebase search to identify all subdirectories in the repository
- Sort directories by depth (deepest first) for bottom-up processing
- Filter out common non-code directories (node_modules, .git, build, dist, etc.)
- Create list of directories to process

### 1.2 Process Each Directory (Bottom-Up)

For each directory, starting from the deepest:

- If an authorized compatible subagent exists, delegate this bounded analysis; otherwise perform it directly. c4-architecture::c4-code is an example role name, not a bundled tool.
- Prompt: |
  Analyze the code in directory: [directory_path]

  Create comprehensive C4 Code-level documentation following this structure:
  1. **Overview Section**:
     - Name: [Descriptive name for this code directory]
     - Description: [Short description of what this code does]
     - Location: [Link to actual directory path relative to repo root]
     - Language: [Primary programming language(s) used]
     - Purpose: [What this code accomplishes]
  2. **Code Elements Section**:
     - Document all functions/methods with complete signatures:
       - Function name, parameters (with types), return type
       - Description of what each function does
       - Location (file path and line numbers)
       - Dependencies (what this function depends on)
     - Document all classes/modules:
       - Class name, description, location
       - Methods and their signatures
       - Dependencies
  3. **Dependencies Section**:
     - Internal dependencies (other code in this repo)
     - External dependencies (libraries, frameworks, services)
  4. **Relationships Section**:
     - Optional Mermaid diagram if relationships are complex

  Save the output as: C4-Documentation/c4-code-[directory-name].md
  Use a stable collision-free path mapping: a/b and a-b must not overwrite each other. Prefer matching output subdirectories or append a short path hash, and record the map.

  Ensure the documentation includes:
  - Complete function signatures with all parameters and types
  - Links to actual source code locations
  - All dependencies (internal and external)
  - Clear, descriptive names and descriptions

- Expected output: c4-code-<directory-name>.md file in C4-Documentation/
- Context: Only files directly owned by this inventory unit; link previously reviewed child inventories instead of repeatedly claiming the same files

**Repeat for every subdirectory** until all directories have corresponding c4-code-\*.md 
