---
name: ai-coding-agent-guardrails
description: Secure AI coding agents (Claude Code, Cursor, Codex, Copilot) with permission boundaries, secret protection, code review gates, and safe sandbox configurations for team environments. 
category: AI & Agents
source: antigravity
tags: [python, node, markdown, api, claude, ai, agent, workflow, template, design]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/ai-coding-agent-guardrails
---


# AI Coding Agent Guardrails

Secure the use of AI coding agents across engineering teams. This skill covers permission boundaries, secret protection, sandbox isolation, code review gates, and audit trails for Claude Code, Cursor, Copilot, and Codex.

---

## Permission Boundaries

### CLAUDE.md Configuration

A `CLAUDE.md` supplies behavioral guidance, not an OS sandbox. Merge compatible rules into existing instructions without overwriting them; tool permissions and isolation enforce boundaries independently.

```markdown
# CLAUDE.md

## Restrictions

- NEVER read or output contents of .env, .env.*, secrets.yaml, or any file matching *.pem, *.key
- NEVER execute `rm -rf`, `DROP TABLE`, `kubectl delete`, or `terraform destroy` commands
- NEVER push directly to main or master branches
- NEVER modify files in the infrastructure/, terraform/, or .github/workflows/ directories without explicit user approval
- NEVER install new dependencies without listing them first for review
- NEVER access or display API keys, tokens, passwords, or connection strings

## Allowed Operations

- Read and modify application source code in src/, lib/, and tests/
- Run test suites with `npm test`, `pytest`, `go test`
- Run linters with `eslint`, `ruff`, `golangci-lint`
- Create new branches with prefix `ai/` or `agent/`
- Create and modify files in docs/ directory

## Code Standards

- All new functions must include docstrings or JSDoc comments
- All new code must have corresponding unit tests
- Follow existing code style and patterns in the repository
- Maximum file length: 500 lines. Suggest splitting if exceeded.
```

### Command Allowlists

For agents that execute shell commands, define an explicit allowlist:

```yaml
# .agent-permissions.yaml — conceptual schema, not consumed automatically by these clients
agent_permissions:
  allowed_commands:
    - "npm test"
    - "npm run lint"
    - "npm run build"
    - "pytest"
    - "ruff check"
    - "go test ./..."
    - "git status"
    - "git diff"
    - "git log"
    - "git checkout -b"
    - "git add"
    - "git commit"
    - "ls"
    - "cat"
    - "head"
    - "tail"

  blocked_commands:
    - "rm -rf"
    - "curl"
    - "wget"
    - "ssh"
    - "scp"
    - "kubectl"
    - "terraform"
    - "aws"
    - "gcloud"
    - "az"
    - "docker push"
    - "npm publish"

  blocked_paths:
    - ".env*"
    - "**/*.pem"
    - "**/*.key"
    - "**/secrets/**"
    - "infrastructure/**"
    - ".github/workflows/**"

  allowed_paths:
    - "src/**"
    - "lib/**"
    - "tests/**"
    - "docs/**"
    - "package.json"
    - "pyproject.toml"
```

### File System Access Controls

Linux-only administrator sketch for a disposable checkout; do not recursively change ownership/modes on a live developer repository. The script below grants named ACL entries but does not grant traversal on the repository/parent directories or default ACLs for new files. Design and verify both explicitly; prevent symlink escapes and keep credentials outside the sandbox. Recursive chmod 750 also marks source files executable.

Use filesystem permissions to enforce boundaries at the OS level:

```bash
#!/bin/bash
# setup-agent-workspace.sh
# Create a restricted workspace for agent execution

AGENT_USER="ai-agent"
REPO_DIR="/workspace/repo"

# Create agent user with limited permissions
useradd --system --shell /bin/bash --no-create-home "$AGENT_USER"

# Set ownership: developers own everything, agent gets read on most
chown -R root:developers "$REPO_DIR"
chmod -R 750 "$REPO_DIR"

# Grant agent write access only to safe directories
setfacl -R -m u:${AGENT_USER}:rwx "${REPO_DIR}/src"
setfacl -R -m u:${AGENT_USER}:rwx "${REPO_DIR}/tests"
setfacl -R -m u:${AGENT_USER}:rwx "${REPO_DIR}/docs"

# Deny agent access to sensitive files
setfacl -m u:${AGENT_USER}:--- "${REPO_DIR}/.env"
setfacl -R -m u:${AGENT_USER}:--- "${REPO_DIR}/infrastructure"
setfacl -R -m u:${AGENT_USER}:--- "${REPO_DIR}/.github/workflows"

echo "Agent workspace permissions configured."
```

---

## Secret Protection

### Pre-commit Hooks with git-secrets

```bash
#!/bin/bash
# install-secret-scanning.sh

# Install git-secrets
git clone https://github.com/awslabs/git-secrets.git /tmp/git-secrets
cd /tmp/git-secrets && make install

# Initialize in repository
cd /path/to/repo
git secrets --install

# Register common secret patterns
git secrets --register-aws

# Add custom patterns for common credential formats
git secrets --add '-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----'
git secrets --add 'AKIA[0-9A-Z]{16}'
git secrets --add 'ghp_[a-zA-Z0-9]{36}'
git secrets --add 'sk-[a-zA-Z0-9]{48}'
git secrets --add 'xox[baprs]-[0-9a-zA-Z-]{10,}'
git secrets --add 'password\s*[:=]\s*["\x27][^\s]{8,}'
git secrets --add 'api[_-]?key\s*[:=]\s*["\x27][^\s]{8,}'

# Add allowed patterns (false positive exclusions)
git secrets --add --allowed 'EXAMPLE_KEY'
git secrets --add --allowed 'your-api-key-here'
```

### Agent Output Scanning

Scan agent-generated output before it reaches v
