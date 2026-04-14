---
name: claude-settings-audit
description: Analyze a repository to generate recommended Claude Code settings.json permissions. Use when setting up a new project, auditing existing settings, or determining which read-only bash commands to allow
category: AI & Agents
source: antigravity
tags: [python, typescript, react, node, nextjs, markdown, api, mcp, claude, ai]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/claude-settings-audit
---


# Claude Settings Audit

Analyze this repository and generate recommended Claude Code `settings.json` permissions for read-only commands.

## When to Use
- You are setting up or auditing Claude Code `settings.json` permissions for a repository.
- You need to infer a safe read-only allow list from the repo's tech stack, tooling, and monorepo structure.
- You want to review or replace an existing Claude permissions baseline with something evidence-based.

## Phase 1: Detect Tech Stack

Run these commands to detect the repository structure:

```bash
ls -la
find . -maxdepth 2 \( -name "*.toml" -o -name "*.json" -o -name "*.lock" -o -name "*.yaml" -o -name "*.yml" -o -name "Makefile" -o -name "Dockerfile" -o -name "*.tf" \) 2>/dev/null | head -50
```

Check for these indicator files:

| Category     | Files to Check                                                                        |
| ------------ | ------------------------------------------------------------------------------------- |
| **Python**   | `pyproject.toml`, `setup.py`, `requirements.txt`, `Pipfile`, `poetry.lock`, `uv.lock` |
| **Node.js**  | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`                    |
| **Go**       | `go.mod`, `go.sum`                                                                    |
| **Rust**     | `Cargo.toml`, `Cargo.lock`                                                            |
| **Ruby**     | `Gemfile`, `Gemfile.lock`                                                             |
| **Java**     | `pom.xml`, `build.gradle`, `build.gradle.kts`                                         |
| **Build**    | `Makefile`, `Dockerfile`, `docker-compose.yml`                                        |
| **Infra**    | `*.tf` files, `kubernetes/`, `helm/`                                                  |
| **Monorepo** | `lerna.json`, `nx.json`, `turbo.json`, `pnpm-workspace.yaml`                          |

## Phase 2: Detect Services

Check for service integrations:

| Service    | Detection                                                                       |
| ---------- | ------------------------------------------------------------------------------- |
| **Sentry** | `sentry-sdk` in deps, `@sentry/*` packages, `.sentryclirc`, `sentry.properties` |
| **Linear** | Linear config files, `.linear/` directory                                       |

Read dependency files to identify frameworks:

- `package.json` → check `dependencies` and `devDependencies`
- `pyproject.toml` → check `[project.dependencies]` or `[tool.poetry.dependencies]`
- `Gemfile` → check gem names
- `Cargo.toml` → check `[dependencies]`

## Phase 3: Check Existing Settings

```bash
cat .claude/settings.json 2>/dev/null || echo "No existing settings"
```

## Phase 4: Generate Recommendations

Build the allow list by combining:

### Baseline Commands (Always Include)

```json
[
  "Bash(ls:*)",
  "Bash(pwd:*)",
  "Bash(find:*)",
  "Bash(file:*)",
  "Bash(stat:*)",
  "Bash(wc:*)",
  "Bash(head:*)",
  "Bash(tail:*)",
  "Bash(cat:*)",
  "Bash(tree:*)",
  "Bash(git status:*)",
  "Bash(git log:*)",
  "Bash(git diff:*)",
  "Bash(git show:*)",
  "Bash(git branch:*)",
  "Bash(git remote:*)",
  "Bash(git tag:*)",
  "Bash(git stash list:*)",
  "Bash(git rev-parse:*)",
  "Bash(gh pr view:*)",
  "Bash(gh pr list:*)",
  "Bash(gh pr checks:*)",
  "Bash(gh pr diff:*)",
  "Bash(gh issue view:*)",
  "Bash(gh issue list:*)",
  "Bash(gh run view:*)",
  "Bash(gh run list:*)",
  "Bash(gh run logs:*)",
  "Bash(gh repo view:*)",
  "Bash(gh api:*)"
]
```

### Stack-Specific Commands

Only include commands for tools actually detected in the project.

#### Python (if any Python files or config detected)

| If Detected                        | Add These Commands                      |
| ---------------------------------- | --------------------------------------- |
| Any Python                         | `python --version`, `python3 --version` |
| `poetry.lock`                      | `poetry show`, `poetry env info`        |
| `uv.lock`                          | `uv pip list`, `uv tree`                |
| `Pipfile.lock`                     | `pipenv graph`                          |
| `requirements.txt` (no other lock) | `pip list`, `pip show`, `pip freeze`    |

#### Node.js (if package.json detected)

| If Detected                  | Add These Commands                     |
| ---------------------------- | -------------------------------------- |
| Any Node.js                  | `node --version`                       |
| `pnpm-lock.yaml`             | `pnpm list`, `pnpm why`                |
| `yarn.lock`                  | `yarn list`, `yarn info`, `yarn why`   |
| `package-lock.json`          | `npm list`, `npm view`, `npm outdated` |
| TypeScript (`tsconfig.json`) | `tsc --version`                        |

#### Other Languages

| If Detected    | Add These Commands                                                   |
| -------------- | -------------------
