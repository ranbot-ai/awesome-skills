---
name: linear-claude-skill
description: Manage Linear issues, projects, and teams 
category: Security & Systems
source: antigravity
tags: [javascript, typescript, node, api, mcp, claude, ai, agent, automation, workflow]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/linear-claude-skill
---


## When to Use This Skill

Manage Linear issues, projects, and teams

Use this skill when working with manage linear issues, projects, and teams.
# Linear

Tools and workflows for managing issues, projects, and teams in Linear.

---

## ⚠️ Tool Availability (READ FIRST)

**This skill supports multiple tool backends. Use whichever is available:**

1. **MCP Tools (mcp__linear)** - Use if available in your tool set
2. **Linear CLI (`linear` command)** - Always available via Bash
3. **Helper Scripts** - For complex operations

**If MCP tools are NOT available**, use the Linear CLI via Bash:

```bash
# View an issue
linear issues view ENG-123

# Create an issue
linear issues create --title "Issue title" --description "Description"

# Update issue status (get state IDs first)
linear issues update ENG-123 -s "STATE_ID"

# Add a comment
linear issues comment add ENG-123 -m "Comment text"

# List issues
linear issues list
```

**Do NOT report "MCP tools not available" as a blocker** - use CLI instead.

---


## When to Use This Skill

Manage Linear issues, projects, and teams

Use this skill when working with manage linear issues, projects, and teams.
## 🔐 Security: Varlock Integration

**CRITICAL**: Never expose API keys in terminal output or Claude's context.

### Safe Commands (Always Use)

```bash
# Validate LINEAR_API_KEY is set (masked output)
varlock load 2>&1 | grep LINEAR

# Run commands with secrets injected
varlock run -- npx tsx scripts/query.ts "query { viewer { name } }"

# Check schema (safe - no values)
cat .env.schema | grep LINEAR
```

### Unsafe Commands (NEVER Use)

```bash
# ❌ NEVER - exposes key to Claude's context
linear config show
echo $LINEAR_API_KEY
printenv | grep LINEAR
cat .env
```

### Setup for New Projects

1. Create `.env.schema` with `@sensitive` annotation:
   ```bash
   # @type=string(startsWith=lin_api_) @required @sensitive
   LINEAR_API_KEY=
   ```

2. Add `LINEAR_API_KEY` to `.env` (never commit this file)

3. Configure MCP to use environment variable:
   ```json
   {
     "mcpServers": {
       "linear": {
         "env": { "LINEAR_API_KEY": "${LINEAR_API_KEY}" }
       }
     }
   }
   ```

4. Use `varlock load` to validate before operations

---

## Quick Start (First-Time Users)

### 1. Check Your Setup

Run the setup check to verify your configuration:

```bash
npx tsx ~/.claude/skills/linear/scripts/setup.ts
```

This will check:
- LINEAR_API_KEY is set and valid
- @linear/sdk is installed
- Linear CLI availability (optional)
- MCP configuration (optional)

### 2. Get API Key (If Needed)

If setup reports a missing API key:

1. Open [Linear](https://linear.app) in your browser
2. Go to **Settings** (gear icon) -> **Security & access** -> **Personal API keys**
3. Click **Create key** and copy the key (starts with `lin_api_`)
4. Add to your environment:

```bash
# Option A: Add to shell profile (~/.zshrc or ~/.bashrc)
export LINEAR_API_KEY="lin_api_your_key_here"

# Option B: Add to Claude Code environment
echo 'LINEAR_API_KEY=lin_api_your_key_here' >> ~/.claude/.env

# Then reload your shell or restart Claude Code
```

### 3. Test Connection

Verify everything works:

```bash
npx tsx ~/.claude/skills/linear/scripts/query.ts "query { viewer { name } }"
```

You should see your name from Linear.

### 4. Common Operations

```bash
# Create issue in a project
npx tsx scripts/linear-ops.ts create-issue "Project" "Title" "Description"

# Update issue status
npx tsx scripts/linear-ops.ts status Done ENG-123 ENG-124

# Create sub-issue
npx tsx scripts/linear-ops.ts create-sub-issue ENG-100 "Sub-task" "Details"

# Update project status
npx tsx scripts/linear-ops.ts project-status "Phase 1" completed

# Show all commands
npx tsx scripts/linear-ops.ts help
```

See [Project Management Commands](#project-management-commands) for full reference.

---


## When to Use This Skill

Manage Linear issues, projects, and teams

Use this skill when working with manage linear issues, projects, and teams.
## Project Planning Workflow

### Create Issues in the Correct Project from the Start

**Best Practice**: When planning a new phase or initiative, create the project and its issues together in a single planning session. Avoid creating issues in a catch-all project and moving them later.

#### Recommended Workflow

1. **Create the project first**:
   ```bash
   npx tsx scripts/linear-ops.ts create-project "Phase X: Feature Name" "My Initiative"
   ```

2. **Set project state to Planned**:
   ```bash
   npx tsx scripts/linear-ops.ts project-status "Phase X: Feature Name" planned
   ```

3. **Create issues directly in the project**:
   ```bash
   npx tsx scripts/linear-ops.ts create-issue "Phase X: Feature Name" "Parent task" "Description"
   npx tsx scripts/linear-ops.ts create-sub-issue ENG-XXX "Sub-task 1" "Description"
   npx tsx scripts/linear-ops.ts create-sub-issue ENG-XXX "Sub-task 2" "Description"
   ```

4. **Update project state when work begins**:
   ```bash
   npx tsx scripts/line
