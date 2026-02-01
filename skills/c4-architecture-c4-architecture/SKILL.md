---
name: c4-architecture-c4-architecture
description: Generate comprehensive C4 architecture documentation for an existing repository/codebase using a bottom-up analysis approach. 
category: Document Processing
source: antigravity
tags: [python, node, api, ai, agent, workflow, design, document, docker, kubernetes]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/c4-architecture-c4-architecture
---


# C4 Architecture Documentation Workflow

Generate comprehensive C4 architecture documentation for an existing repository/codebase using a bottom-up analysis approach.

[Extended thinking: This workflow implements a complete C4 architecture documentation process following the C4 model (Context, Container, Component, Code). It uses a bottom-up approach, starting from the deepest code directories and working upward, ensuring every code element is documented before synthesizing into higher-level abstractions. The workflow coordinates four specialized C4 agents (Code, Component, Container, Context) to create a complete architectural documentation set that serves both technical and non-technical stakeholders.]

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
- If detailed examples are required, open `resources/implementation-playbook.md`.

## Overview

This workflow creates comprehensive C4 architecture documentation following the [official C4 model](https://c4model.com/diagrams) by:

1. **Code Level**: Analyzing every subdirectory bottom-up to create code-level documentation
2. **Component Level**: Synthesizing code documentation into logical components within containers
3. **Container Level**: Mapping components to deployment containers with API documentation (shows high-level technology choices)
4. **Context Level**: Creating high-level system context with personas and user journeys (focuses on people and software systems, not technologies)

**Note**: According to the [C4 model](https://c4model.com/diagrams), you don't need to use all 4 levels of diagram - the system context and container diagrams are sufficient for most software development teams. This workflow generates all levels for completeness, but teams can choose which levels to use.

All documentation is written to a new `C4-Documentation/` directory in the repository root.

## Phase 1: Code-Level Documentation (Bottom-Up Analysis)

### 1.1 Discover All Subdirectories

- Use codebase search to identify all subdirectories in the repository
- Sort directories by depth (deepest first) for bottom-up processing
- Filter out common non-code directories (node_modules, .git, build, dist, etc.)
- Create list of directories to process

### 1.2 Process Each Directory (Bottom-Up)

For each directory, starting from the deepest:

- Use Task tool with subagent_type="c4-architecture::c4-code"
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
  Use a sanitized directory name (replace / with -, remove special chars) for the filename.

  Ensure the documentation includes:
  - Complete function signatures with all parameters and types
  - Links to actual source code locations
  - All dependencies (internal and external)
  - Clear, descriptive names and descriptions

- Expected output: c4-code-<directory-name>.md file in C4-Documentation/
- Context: All files in the directory and its subdirectories

**Repeat for every subdirectory** until all directories have corresponding c4-code-\*.md files.

## Phase 2: Component-Level Synthesis

### 2.1 Analyze All Code-Level Documentation

- Collect all c4-code-\*.md files created in Phase 1
- Analyze code structure, dependencies, and relationships
- Identify logical component boundaries based on:
  - Domain boundaries (related business functionality)
  - Technical boundaries (shared frameworks, libraries)
  - Organizational boundarie
