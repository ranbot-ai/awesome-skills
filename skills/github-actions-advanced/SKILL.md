---
name: github-actions-advanced
description: Design, debug, and harden GitHub Actions CI/CD workflows, including reusable workflows, matrix builds, self-hosted runners, OIDC authentication, caching, environments, secrets, and release automation.
category: AI & Agents
source: antigravity
tags: [python, javascript, typescript, node, api, ai, automation, workflow, template, design]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/github-actions-advanced
---


# GitHub Actions Advanced Skill

Expert guidance for designing, writing, debugging, and securing **production-grade** GitHub Actions workflows.

---

## When to Use This Skill

- User mentions GitHub Actions, `.github/workflows`, CI/CD pipelines, runners, jobs, steps, or actions
- User wants to automate builds, tests, deployments, or releases via GitHub
- User asks about matrix builds, reusable workflows, composite actions, or self-hosted runners
- User needs help with OIDC authentication, caching strategies, or secrets management
- User says "my GitHub pipeline is failing" or "set up CI for my repo"
- User asks about workflow security, hardening, or environment protection rules

## When NOT to Use This Skill

- The user is working with GitLab CI/CD → recommend `gitlab-ci-patterns`
- The user is working with CircleCI, Jenkins, or other CI platforms
- The task is purely about Docker image building without GitHub context → recommend `docker-expert`
- The task is about Kubernetes deployment configuration → recommend `kubernetes-architect`

---

## Step 1: Understand Context Before Responding

When invoked, first gather context:

```bash
# Discover existing workflows in the repo
find .github/workflows -name "*.yml" -o -name "*.yaml" 2>/dev/null | head -20

# Check for composite actions
find .github/actions -name "action.yml" 2>/dev/null

# Detect tech stack (influences runner OS, language setup actions)
ls package.json requirements.txt Gemfile go.mod Cargo.toml pom.xml 2>/dev/null
```

Then adapt recommendations to:
- Existing workflow patterns in the repo
- The tech stack and language runtime
- Whether this is a monorepo or single-project repo
- Whether self-hosted or GitHub-hosted runners are in use

---

## Workflow Structure Reference

```yaml
name: Workflow Name

on:                          # Triggers (see Triggers section)
  push:
    branches: [main]

permissions:                 # Always declare — principle of least privilege
  contents: read

env:                         # Workflow-level env vars
  NODE_VERSION: '20'

concurrency:                 # Prevent duplicate runs
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true   # Cancel older runs for same branch

jobs:
  job-id:
    name: Human-readable name
    runs-on: ubuntu-24.04    # Pin OS version — never use -latest in prod
    timeout-minutes: 15      # Always set — prevents runaway jobs
    environment: production  # Links to GitHub Environment (approvals/secrets)

    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
      - name: Step name
        run: echo "hello"
```

---

## Triggers (`on:`)

### Common Patterns

```yaml
on:
  push:
    branches: [main, 'release/**']
    paths-ignore: ['**.md', 'docs/**']   # Skip docs-only changes

  pull_request:
    types: [opened, synchronize, reopened]
    branches: [main]

  workflow_dispatch:                      # Manual trigger with inputs
    inputs:
      environment:
        description: 'Deploy target'
        required: true
        type: choice
        options: [staging, production]
      dry-run:
        description: 'Dry run only?'
        type: boolean
        default: false

  schedule:
    - cron: '0 2 * * 1'                 # Monday 2am UTC

  workflow_call:                          # Called by other workflows (reusable)
    inputs:
      image-tag:
        type: string
        required: true
    secrets:
      deploy-token:
        required: true

  release:
    types: [published]                   # Trigger only on published releases

  pull_request_target:                   # Runs with repo secrets — use with care!
    types: [labeled]                     # Gate with label + author_association check
```

> **Security Warning:** `pull_request_target` runs with repo secrets. Only use after a maintainer labels the PR. Never check out fork code without explicit sandboxing.

---

## Reusable Workflows

Split large pipelines into composable units stored in `.github/workflows/`.

**Convention:** Prefix internal/reusable workflows with `_` (e.g., `_build.yml`).

### Caller (`.github/workflows/deploy.yml`)

```yaml
jobs:
  call-build:
    uses: ./.github/workflows/_build.yml        # Same-repo reusable
    # uses: org/repo/.github/workflows/build.yml@main  # Cross-repo
    with:
      image-tag: ${{ github.sha }}
    secrets: inherit                             # Pass all caller secrets down
  
  call-test:
    uses: ./.github/workflows/_test.yml
    with:
      node-version: '20'
    secrets:
      NPM_TOKEN: ${{ secrets.NPM_TOKEN }}       # Explicit secret passing
```

### Reusable Workflow (`.github/workflows/_build.yml`)

```yaml
on:
  workflow_call:
    inputs:
      image-tag:
        type: string
        required: true
      push:
        type: boolean
        default: false
    secrets:
      registry-token:
        required: false
    outputs:
      digest:
        description: "Image digest"
        value: ${{ jobs.buil
