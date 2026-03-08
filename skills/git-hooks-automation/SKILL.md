---
name: git-hooks-automation
description: Master Git hooks setup with Husky, lint-staged, pre-commit framework, and commitlint. Automate code quality gates, formatting, linting, and commit message enforcement before code reaches CI. 
category: Development & Code Tools
source: antigravity
tags: [python, javascript, typescript, node, ai, automation, workflow, template]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/git-hooks-automation
---


# Git Hooks Automation

Automate code quality enforcement at the Git level. Set up hooks that lint, format, test, and validate before commits and pushes ever reach your CI pipeline — catching issues in seconds instead of minutes.

## When to Use This Skill

- User asks to "set up git hooks" or "add pre-commit hooks"
- Configuring Husky, lint-staged, or the pre-commit framework
- Enforcing commit message conventions (Conventional Commits, commitlint)
- Automating linting, formatting, or type-checking before commits
- Setting up pre-push hooks for test runners
- Migrating from Husky v4 to v9+ or adopting hooks from scratch
- User mentions "pre-commit", "commit-msg", "pre-push", "lint-staged", or "githooks"

## Git Hooks Fundamentals

Git hooks are scripts that run automatically at specific points in the Git workflow. They live in `.git/hooks/` and are not version-controlled by default — which is why tools like Husky exist.

### Hook Types & When They Fire

| Hook | Fires When | Common Use |
|---|---|---|
| `pre-commit` | Before commit is created | Lint, format, type-check staged files |
| `prepare-commit-msg` | After default msg, before editor | Auto-populate commit templates |
| `commit-msg` | After user writes commit message | Enforce commit message format |
| `post-commit` | After commit is created | Notifications, logging |
| `pre-push` | Before push to remote | Run tests, check branch policies |
| `pre-rebase` | Before rebase starts | Prevent rebase on protected branches |
| `post-merge` | After merge completes | Install deps, run migrations |
| `post-checkout` | After checkout/switch | Install deps, rebuild assets |

### Native Git Hooks (No Framework)

```bash
# Create a pre-commit hook manually
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/sh
set -e

# Run linter on staged files only
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(js|ts|jsx|tsx)$' || true)

if [ -n "$STAGED_FILES" ]; then
  echo "🔍 Linting staged files..."
  echo "$STAGED_FILES" | xargs npx eslint --fix
  echo "$STAGED_FILES" | xargs git add  # Re-stage after fixes
fi
EOF
chmod +x .git/hooks/pre-commit
```

**Problem**: `.git/hooks/` is local-only and not shared with the team. Use a framework instead.

## Husky + lint-staged (Node.js Projects)

The modern standard for JavaScript/TypeScript projects. Husky manages Git hooks; lint-staged runs commands only on staged files for speed.

### Quick Setup (Husky v9+)

```bash
# Install
npm install --save-dev husky lint-staged

# Initialize Husky (creates .husky/ directory)
npx husky init

# The init command creates a pre-commit hook — edit it:
echo "npx lint-staged" > .husky/pre-commit
```

### Configure lint-staged in `package.json`

```json
{
  "lint-staged": {
    "*.{js,jsx,ts,tsx}": [
      "eslint --fix --max-warnings=0",
      "prettier --write"
    ],
    "*.{css,scss}": [
      "prettier --write",
      "stylelint --fix"
    ],
    "*.{json,md,yml,yaml}": [
      "prettier --write"
    ]
  }
}
```

### Add Commit Message Linting

```bash
# Install commitlint
npm install --save-dev @commitlint/cli @commitlint/config-conventional

# Create commitlint config
cat > commitlint.config.js << 'EOF'
module.exports = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'type-enum': [2, 'always', [
      'feat', 'fix', 'docs', 'style', 'refactor',
      'perf', 'test', 'build', 'ci', 'chore', 'revert'
    ]],
    'subject-max-length': [2, 'always', 72],
    'body-max-line-length': [2, 'always', 100]
  }
};
EOF

# Add commit-msg hook
echo "npx --no -- commitlint --edit \$1" > .husky/commit-msg
```

### Add Pre-Push Hook

```bash
# Run tests before pushing
echo "npm test" > .husky/pre-push
```

### Complete Husky Directory Structure

```
project/
├── .husky/
│   ├── pre-commit        # npx lint-staged
│   ├── commit-msg        # npx --no -- commitlint --edit $1
│   └── pre-push          # npm test
├── commitlint.config.js
├── package.json          # lint-staged config here
└── ...
```

## pre-commit Framework (Python / Polyglot)

Language-agnostic framework that works with any project. Hooks are defined in YAML and run in isolated environments.

### Setup

```bash
# Install (Python required)
pip install pre-commit

# Create config
cat > .pre-commit-config.yaml << 'EOF'
repos:
  # Built-in checks
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-json
      - id: check-added-large-files
        args: ['--maxkb=500']
      - id: check-merge-conflict
      - id: detect-private-key

  # Python formatting
  - repo: https://github.com/psf/black
    rev: 24.4.2
    hooks:
      - id: black

  # Python linting
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.4.4
    hooks:
      - id: ruff
        args: ['--fix']
      - id: ruff-format

  # Shell script linting
  - repo: https://github.com/shellcheck-py/shellche
