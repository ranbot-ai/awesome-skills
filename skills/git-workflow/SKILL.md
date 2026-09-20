---
name: git-workflow
description: Implement Git branching strategies, PR workflows, and release management patterns. 
category: Document Processing
source: antigravity
tags: [javascript, markdown, api, ai, agent, automation, workflow, template, document, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/git-workflow
---


# Git Workflow

Implement effective branching strategies and pull request workflows for team collaboration.

## When to Use This Skill

Use this skill when:
- Establishing team Git workflows
- Implementing branching strategies
- Configuring pull request processes
- Setting up release management
- Improving code review practices

## Prerequisites

- Git installed
- Repository hosting (GitHub, GitLab, Bitbucket)
- Basic Git knowledge

## Branching Strategies

### Trunk-Based Development

Best for: Continuous deployment, small teams, mature CI/CD

```
main ─────●─────●─────●─────●─────●─────●─────●
          │     │     │     │     │     │
          └─●   └─●   └─●   └─●   └─●   └─●
         feature branches (short-lived)
```

```bash
# Create short-lived feature branch
git checkout main
git pull origin main
git checkout -b feature/add-login

# Work and commit frequently
git add .
git commit -m "feat: add login form"

# Keep branch updated
git fetch origin
git rebase origin/main

# Merge quickly (same day ideally)
git checkout main
git pull origin main
git merge feature/add-login
git push origin main
git branch -d feature/add-login
```

### GitHub Flow

Best for: Continuous delivery, web applications

```
main ─────●─────●───────────●─────────────●─────●
          │           ↑           ↑       ↑
          └───●───●───┘           │       │
              feature/login       │       │
                                  │       │
          └───●───●───●───●───────┘       │
              feature/dashboard           │
                                          │
          └───●─────────────────────────┘
              hotfix/security-patch
```

```bash
# Create feature branch from main
git checkout main
git pull origin main
git checkout -b feature/user-dashboard

# Push and create PR
git push -u origin feature/user-dashboard

# After review, merge via PR (squash recommended)
# Delete branch after merge
```

### GitFlow

Best for: Scheduled releases, versioned products

```
main     ────────●────────────────●──────────────●
                 ↑                ↑              ↑
release  ────────┼────●───●──────┼──────────────┼
                 │    │   │      │              │
develop  ───●────●────┼───●──●───●───●───●───●──┼
            │         │      │       │   │      │
feature  ───┴─────────┘      │       │   │      │
                             │       │   │      │
hotfix   ────────────────────┴───────┼───┼──────┘
                                     │   │
feature  ────────────────────────────┴───┘
```

```bash
# Initialize GitFlow
git flow init

# Start feature
git flow feature start user-auth

# Finish feature (merges to develop)
git flow feature finish user-auth

# Start release
git flow release start 1.0.0

# Finish release (merges to main and develop)
git flow release finish 1.0.0

# Hotfix
git flow hotfix start security-fix
git flow hotfix finish security-fix
```

## Commit Conventions

### Conventional Commits

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting
- `refactor`: Code restructuring
- `test`: Adding tests
- `chore`: Maintenance

Examples:
```bash
git commit -m "feat(auth): add OAuth2 login support"
git commit -m "fix(api): handle null response from payment service"
git commit -m "docs: update API documentation for v2 endpoints"
git commit -m "refactor(db): optimize user query performance"

# Breaking change
git commit -m "feat(api)!: change response format for user endpoint

BREAKING CHANGE: The user endpoint now returns an object instead of array"
```

### Commit Message Template

```bash
# Create template file ~/.gitmessage
# Subject line (50 chars max)

# Body (72 chars per line max)
# - What changed
# - Why it changed
# - Any side effects

# Footer
# Fixes #123
# Co-authored-by: Name <email>

# Configure Git to use template
git config --global commit.template ~/.gitmessage
```

## Pull Request Workflow

### PR Template

```markdown
<!-- .github/pull_request_template.md -->
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix (non-breaking change)
- [ ] New feature (non-breaking change)
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing performed

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review performed
- [ ] Documentation updated
- [ ] No new warnings introduced

## Related Issues
Closes #

## Screenshots (if applicable)
```

### Branch Protection Rules

```yaml
# GitHub branch protection
branch_protection:
  branch: main
  required_pull_request_reviews:
    required_approving_review_count: 1
    dismiss_stale_reviews: true
    require_code_owner_reviews: true
  required_status_checks:
    strict: true
    contexts:
      - "ci/tests"
      - "ci/lint"
  restrictions:
    users: []
    teams: ["maintainers"]
  enforce_admins:
