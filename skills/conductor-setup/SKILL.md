---
name: conductor-setup
description: Initialize project with Conductor artifacts (product definition, tech stack, workflow, style guides) 
category: Document Processing
source: antigravity
tags: [python, javascript, typescript, react, markdown, api, claude, ai, workflow, template]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/conductor-setup
---


# Conductor Setup

Initialize or resume Conductor project setup. This command creates foundational project documentation through interactive Q&A.

## Use this skill when

- Working on conductor setup tasks or workflows
- Needing guidance, best practices, or checklists for conductor setup

## Do not use this skill when

- The task is unrelated to conductor setup
- You need a different domain or tool outside this scope

## Instructions

- Clarify goals, constraints, and required inputs.
- Apply relevant best practices and validate outcomes.
- Provide actionable steps and verification.
- If detailed examples are required, open `resources/implementation-playbook.md`.

## Pre-flight Checks

1. Check if `conductor/` directory already exists in the project root:
   - If `conductor/product.md` exists: Ask user whether to resume setup or reinitialize
   - If `conductor/setup_state.json` exists with incomplete status: Offer to resume from last step

2. Detect project type by checking for existing indicators:
   - **Greenfield (new project)**: No .git, no package.json, no requirements.txt, no go.mod, no src/ directory
   - **Brownfield (existing project)**: Any of the above exist

3. Load or create `conductor/setup_state.json`:
   ```json
   {
     "status": "in_progress",
     "project_type": "greenfield|brownfield",
     "current_section": "product|guidelines|tech_stack|workflow|styleguides",
     "current_question": 1,
     "completed_sections": [],
     "answers": {},
     "files_created": [],
     "started_at": "ISO_TIMESTAMP",
     "last_updated": "ISO_TIMESTAMP"
   }
   ```

## Interactive Q&A Protocol

**CRITICAL RULES:**

- Ask ONE question per turn
- Wait for user response before proceeding
- Offer 2-3 suggested answers plus "Type your own" option
- Maximum 5 questions per section
- Update `setup_state.json` after each successful step
- Validate file writes succeeded before continuing

### Section 1: Product Definition (max 5 questions)

**Q1: Project Name**

```
What is your project name?

Suggested:
1. [Infer from directory name]
2. [Infer from package.json/go.mod if brownfield]
3. Type your own
```

**Q2: Project Description**

```
Describe your project in one sentence.

Suggested:
1. A web application that [does X]
2. A CLI tool for [doing Y]
3. Type your own
```

**Q3: Problem Statement**

```
What problem does this project solve?

Suggested:
1. Users struggle to [pain point]
2. There's no good way to [need]
3. Type your own
```

**Q4: Target Users**

```
Who are the primary users?

Suggested:
1. Developers building [X]
2. End users who need [Y]
3. Internal teams managing [Z]
4. Type your own
```

**Q5: Key Goals (optional)**

```
What are 2-3 key goals for this project? (Press enter to skip)
```

### Section 2: Product Guidelines (max 3 questions)

**Q1: Voice and Tone**

```
What voice/tone should documentation and UI text use?

Suggested:
1. Professional and technical
2. Friendly and approachable
3. Concise and direct
4. Type your own
```

**Q2: Design Principles**

```
What design principles guide this project?

Suggested:
1. Simplicity over features
2. Performance first
3. Developer experience focused
4. User safety and reliability
5. Type your own (comma-separated)
```

### Section 3: Tech Stack (max 5 questions)

For **brownfield projects**, first analyze existing code:

- Run `Glob` to find package.json, requirements.txt, go.mod, Cargo.toml, etc.
- Parse detected files to pre-populate tech stack
- Present findings and ask for confirmation/additions

**Q1: Primary Language(s)**

```
What primary language(s) does this project use?

[For brownfield: "I detected: Python 3.11, JavaScript. Is this correct?"]

Suggested:
1. TypeScript
2. Python
3. Go
4. Rust
5. Type your own (comma-separated)
```

**Q2: Frontend Framework (if applicable)**

```
What frontend framework (if any)?

Suggested:
1. React
2. Vue
3. Next.js
4. None / CLI only
5. Type your own
```

**Q3: Backend Framework (if applicable)**

```
What backend framework (if any)?

Suggested:
1. Express / Fastify
2. Django / FastAPI
3. Go standard library
4. None / Frontend only
5. Type your own
```

**Q4: Database (if applicable)**

```
What database (if any)?

Suggested:
1. PostgreSQL
2. MongoDB
3. SQLite
4. None / Stateless
5. Type your own
```

**Q5: Infrastructure**

```
Where will this be deployed?

Suggested:
1. AWS (Lambda, ECS, etc.)
2. Vercel / Netlify
3. Self-hosted / Docker
4. Not decided yet
5. Type your own
```

### Section 4: Workflow Preferences (max 4 questions)

**Q1: TDD Strictness**

```
How strictly should TDD be enforced?

Suggested:
1. Strict - tests required before implementation
2. Moderate - tests encouraged, not blocked
3. Flexible - tests recommended for complex logic
```

**Q2: Commit Strategy**

```
What commit strategy should be followed?

Suggested:
1. Conventional Commits (feat:, fix:, etc.)
2. Descriptive messages, no format required
3. Squash commits per task
```

**Q3: Code Review Requirements**

```
What code r
